import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MockAgent } from "undici";

import { Permit0Client } from "../src/Permit0Client.js";
import type { Decision } from "../src/types.js";

/**
 * Integration tests for the FailOpenBuffer ↔ Permit0Client wiring:
 *   - failed check + fail-open → event lands in buffer + synthetic allow
 *     returned to the caller
 *   - drainFailedOpenBuffer() POSTs to /api/v1/audit/replay
 *   - server 207 partial → rejected events stay in buffer
 *   - server 5xx → all events stay
 *   - close() drops buffered events
 */

const BASE_URL = "http://localhost:9090";

function makeAllow(): Decision {
  return {
    permission: "allow",
    action_type: "process.shell",
    channel: "shell",
    norm_hash: "aa",
    source: "engine",
  };
}

function setup() {
  const agent = new MockAgent();
  agent.disableNetConnect();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dispatcher = agent as any;
  const pool = agent.get(BASE_URL);
  return { agent, dispatcher, pool };
}

function refusedError(): Error & { code: string } {
  return Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" });
}

describe("Permit0Client + FailOpenBuffer — fail-open enqueue", () => {
  let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    env = { ...process.env };
    delete process.env["PERMIT0_FAIL_OPEN"];
  });
  afterEach(() => {
    process.env = env;
  });

  it("enqueues a buffered event when daemon refused + fail-open active", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0, // disable idle poller — we drive drains explicitly
    });

    const decision = await client.check(
      "Bash",
      { command: "ls" },
      { session_id: "conv-1" },
    );
    expect(decision.source).toBe("failed_open");

    const status = client.failedOpenBufferStatus();
    expect(status.count).toBe(1);
    expect(status.windowStart).toBeDefined();
    expect(status.windowEnd).toBeDefined();
    expect(status.dropped).toBe(0);
    await client.close();
  });

  it("does NOT enqueue when fail-open is off (fail-closed throws as before)", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: false,
      drainPollMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
    });
    expect(client.failedOpenBufferStatus().count).toBe(0);
    await client.close();
  });

  it("captures fail_reason_code from the underlying transport error", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
    });

    await client.check("Bash", { command: "ls" });

    // Drain into a captured body to inspect the event we buffered.
    let captured: { events: Array<Record<string, unknown>> } | undefined;
    pool
      .intercept({ path: "/api/v1/audit/replay", method: "POST" })
      .reply(200, (opts) => {
        captured = JSON.parse(String(opts.body));
        return { accepted: 1, rejected: [] };
      });
    await client.drainFailedOpenBuffer();

    expect(captured?.events.length).toBe(1);
    const event = captured!.events[0]!;
    expect(event["tool_name"]).toBe("Bash");
    expect(event["fail_reason_code"]).toBe("refused");
    expect(event["fail_open_source"]).toBe("config_flag"); // failOpen=true
    expect(event["outcome"]).toBe("executed");
    expect(typeof event["event_id"]).toBe("string");
    await client.close();
  });
});

describe("Permit0Client + FailOpenBuffer — drain", () => {
  it("drainFailedOpenBuffer POSTs the right batch shape and clears on success", async () => {
    const { dispatcher, pool } = setup();
    // 3 fail-open calls during the outage.
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(6); // 3 calls × 2 attempts (1 + 1 retry)

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
    });

    await client.check("Bash", { command: "ls" });
    await client.check("Bash", { command: "pwd" });
    await client.check("Write", { path: "/tmp/x", content: "hi" });

    expect(client.failedOpenBufferStatus().count).toBe(3);

    let body: { events: Array<{ event_id: string }>; client_window_start: string; dropped_count: number } | undefined;
    pool
      .intercept({ path: "/api/v1/audit/replay", method: "POST" })
      .reply(200, (opts) => {
        body = JSON.parse(String(opts.body));
        return { accepted: 3, rejected: [] };
      });

    const result = await client.drainFailedOpenBuffer();
    expect(result.flushed).toBe(3);
    expect(result.remaining).toBe(0);
    expect(body?.events.length).toBe(3);
    expect(body?.client_window_start).toBeDefined();
    expect(body?.dropped_count).toBe(0);
    expect(client.failedOpenBufferStatus().count).toBe(0);
    await client.close();
  });

  it("partial rejection keeps rejected events buffered for retry", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(4);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
    });

    await client.check("Bash", { command: "ls" });
    await client.check("Bash", { command: "pwd" });

    // Capture the event_ids the client generated, then have the server
    // reject one of them by event_id.
    let firstId: string | undefined;
    pool
      .intercept({ path: "/api/v1/audit/replay", method: "POST" })
      .reply(207, (opts) => {
        const body = JSON.parse(String(opts.body)) as {
          events: Array<{ event_id: string }>;
        };
        firstId = body.events[0]!.event_id;
        return {
          accepted: 1,
          rejected: [{ event_id: firstId, error: "shape mismatch" }],
        };
      });

    const result = await client.drainFailedOpenBuffer();
    expect(result.flushed).toBe(1);
    expect(result.remaining).toBe(1);
    expect(result.rejected[0]?.event_id).toBe(firstId);
    expect(client.failedOpenBufferStatus().count).toBe(1);
    await client.close();
  });

  it("server 5xx keeps every event buffered for the next attempt", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
    });
    await client.check("Bash", { command: "ls" });

    pool
      .intercept({ path: "/api/v1/audit/replay", method: "POST" })
      .reply(500, "boom");

    const result = await client.drainFailedOpenBuffer();
    expect(result.flushed).toBe(0);
    expect(result.remaining).toBe(1);
    expect(result.error).toBeDefined();
    expect(client.failedOpenBufferStatus().count).toBe(1);
    await client.close();
  });
});

describe("Permit0Client + FailOpenBuffer — lazy drain trigger", () => {
  it("a successful check after a buffered window kicks off the drain", async () => {
    const { dispatcher, pool } = setup();

    // First two calls fail (fail-open).
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
    });

    await client.check("Bash", { command: "ls" });
    expect(client.failedOpenBufferStatus().count).toBe(1);

    // Daemon is back. Set up a successful /check + the replay POST.
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    let replayCalled = false;
    pool
      .intercept({ path: "/api/v1/audit/replay", method: "POST" })
      .reply(200, () => {
        replayCalled = true;
        return { accepted: 1, rejected: [] };
      });

    // Live check — fire-and-forget lazy drain runs in background.
    await client.check("Bash", { command: "echo ok" });

    // Wait for the lazy drain to complete: drainFailedOpenBuffer is
    // single-flight; once the in-flight one finishes, this returns
    // immediately with remaining=0 (or it runs another drain that also
    // finds buffer empty).
    await new Promise<void>((resolve) => setTimeout(resolve, 25));

    expect(replayCalled).toBe(true);
    expect(client.failedOpenBufferStatus().count).toBe(0);
    await client.close();
  });
});

describe("Permit0Client + FailOpenBuffer — overflow", () => {
  it("respects custom bufferCapacity and reports dropped count", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(8); // 4 calls × 2 attempts

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
      bufferCapacity: 2,
    });

    await client.check("Bash", { command: "1" });
    await client.check("Bash", { command: "2" });
    await client.check("Bash", { command: "3" });
    await client.check("Bash", { command: "4" });

    const status = client.failedOpenBufferStatus();
    expect(status.count).toBe(2);
    expect(status.dropped).toBe(2);
    await client.close();
  });

  it("drain reports dropped_count to the server", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(6);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
      bufferCapacity: 1,
    });

    await client.check("Bash", { command: "1" });
    await client.check("Bash", { command: "2" });
    await client.check("Bash", { command: "3" });

    let captured: { dropped_count: number } | undefined;
    pool
      .intercept({ path: "/api/v1/audit/replay", method: "POST" })
      .reply(200, (opts) => {
        captured = JSON.parse(String(opts.body));
        return { accepted: 1, rejected: [] };
      });
    await client.drainFailedOpenBuffer();
    expect(captured?.dropped_count).toBe(2);
    await client.close();
  });
});

describe("Permit0Client + FailOpenBuffer — close()", () => {
  it("close() clears the buffer", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(refusedError())
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      drainPollMs: 0,
    });
    await client.check("Bash", { command: "ls" });
    expect(client.failedOpenBufferStatus().count).toBe(1);
    await client.close();
    expect(client.failedOpenBufferStatus().count).toBe(0);
  });
});
