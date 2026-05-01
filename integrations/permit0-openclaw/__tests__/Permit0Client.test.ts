import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MockAgent } from "undici";

import { Permit0Error } from "../src/errors.js";
import { Permit0Client } from "../src/Permit0Client.js";
import type { Decision, Logger } from "../src/types.js";

// ── helpers ────────────────────────────────────────────────────────────

const BASE_URL = "http://localhost:9090";

function makeAllowDecision(overrides: Partial<Decision> = {}): Decision {
  return {
    permission: "allow",
    action_type: "process.shell",
    channel: "shell",
    norm_hash: "abcdef1234567890",
    source: "engine",
    score: 12,
    tier: "LOW",
    blocked: false,
    ...overrides,
  };
}

function setup() {
  const agent = new MockAgent();
  agent.disableNetConnect();
  // The dispatcher passed to Permit0Client is what undici.fetch uses.
  // We cast to any only to bridge the dispatcher type — undici's MockAgent
  // is a valid dispatcher at runtime.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dispatcher = agent as any;
  const pool = agent.get(BASE_URL);
  return { agent, dispatcher, pool };
}

function captureLogger(): Logger & { records: Array<{ level: string; msg: string }> } {
  const records: Array<{ level: string; msg: string }> = [];
  return {
    records,
    warn: (msg) => records.push({ level: "warn", msg }),
    error: (msg) => records.push({ level: "error", msg }),
    debug: (msg) => records.push({ level: "debug", msg }),
  };
}

// ── tests ──────────────────────────────────────────────────────────────

describe("Permit0Client.check — happy paths", () => {
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    env = { ...process.env };
    delete process.env["PERMIT0_FAIL_OPEN"];
  });
  afterEach(() => {
    process.env = env;
  });

  it("returns Decision on 200 allow", async () => {
    const { dispatcher, pool } = setup();
    const decision = makeAllowDecision();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, decision);

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    const got = await client.check("Bash", { command: "ls" });

    expect(got).toEqual(decision);
    await client.close();
  });

  it("returns Decision on 200 deny with block_reason", async () => {
    const { dispatcher, pool } = setup();
    const decision: Decision = {
      permission: "deny",
      action_type: "process.shell",
      channel: "shell",
      norm_hash: "ff00",
      source: "engine",
      score: 100,
      tier: "CRITICAL",
      blocked: true,
      block_reason: "destructive-root-removal",
    };
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, decision);

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    const got = await client.check("Bash", { command: "rm -rf /" });

    expect(got.permission).toBe("deny");
    expect(got.block_reason).toBe("destructive-root-removal");
    await client.close();
  });

  it("returns Decision on 200 human", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision({ permission: "human", tier: "MEDIUM" }));

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    const got = await client.check("WebFetch", { url: "http://x" });

    expect(got.permission).toBe("human");
    await client.close();
  });
});

describe("Permit0Client.check — request shape", () => {
  it("threads session_id and task_goal into metadata", async () => {
    const { dispatcher, pool } = setup();
    let captured: unknown;
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, (opts) => {
        captured = JSON.parse(String(opts.body));
        return makeAllowDecision();
      });

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    await client.check(
      "Bash",
      { command: "ls" },
      { session_id: "conv-123", task_goal: "list files" },
    );

    expect(captured).toMatchObject({
      tool_name: "Bash",
      parameters: { command: "ls" },
      metadata: {
        session_id: "conv-123",
        task_goal: "list files",
        client: "@permit0/openclaw",
      },
    });
    expect((captured as { metadata: { client_version: string } }).metadata.client_version).toMatch(/^\d+\.\d+\.\d+$/);
    await client.close();
  });

  it("merges extra metadata after named fields", async () => {
    const { dispatcher, pool } = setup();
    let captured: { metadata: Record<string, unknown> } | undefined;
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, (opts) => {
        captured = JSON.parse(String(opts.body));
        return makeAllowDecision();
      });

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    await client.check(
      "Bash",
      { command: "ls" },
      { session_id: "s1", extra: { trace_id: "trace-9" } },
    );

    expect(captured?.metadata).toMatchObject({
      session_id: "s1",
      trace_id: "trace-9",
    });
    await client.close();
  });

  it("sets client_kind to openclaw so the daemon strips mcporter's <server>.<tool> shape", async () => {
    const { dispatcher, pool } = setup();
    let captured: { client_kind?: string } | undefined;
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, (opts) => {
        captured = JSON.parse(String(opts.body));
        return makeAllowDecision();
      });

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    await client.check("gmail.create_label", { name: "TestLabel" });
    expect(captured?.client_kind).toBe("openclaw");
    await client.close();
  });
});

describe("Permit0Client.check — retry semantics", () => {
  let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    env = { ...process.env };
    delete process.env["PERMIT0_FAIL_OPEN"];
  });
  afterEach(() => {
    process.env = env;
  });

  it("does not retry on 4xx", async () => {
    const { agent, dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(400, "bad request");

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "http_error",
      status: 400,
    });
    // If retry had fired, this assertNoPendingInterceptors would fail because
    // we only set up one interceptor.
    agent.assertNoPendingInterceptors();
    await client.close();
  });

  it("retries once on 5xx then fails closed if also 5xx", async () => {
    const { agent, dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(500, "boom")
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "http_error",
      status: 500,
    });
    agent.assertNoPendingInterceptors();
    await client.close();
  });

  it("retries once on 5xx and recovers if second attempt succeeds", async () => {
    const { agent, dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(503, "unavailable");
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision());

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    const got = await client.check("Bash", { command: "ls" });
    expect(got.permission).toBe("allow");
    agent.assertNoPendingInterceptors();
    await client.close();
  });

  it("logs a warning when retrying", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(503, "unavailable");
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision());

    const logger = captureLogger();
    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      logger,
    });

    await client.check("Bash", { command: "ls" });
    expect(logger.records.some((r) => r.level === "warn")).toBe(true);
    await client.close();
  });
});

describe("Permit0Client.check — fail-closed default", () => {
  let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    env = { ...process.env };
    delete process.env["PERMIT0_FAIL_OPEN"];
  });
  afterEach(() => {
    process.env = env;
  });

  it("throws Permit0Error on connection refused (fail-closed)", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toBeInstanceOf(
      Permit0Error,
    );
    await client.close();
  });

  it("throws Permit0Error{malformed_response} on non-Decision body", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, { permission: "maybe", action_type: "x", channel: "y", norm_hash: "z", source: "engine" });

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "malformed_response",
    });
    await client.close();
  });

  it("throws Permit0Error{malformed_response} on non-JSON body", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, "not json", { headers: { "content-type": "text/plain" } });

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "malformed_response",
    });
    await client.close();
  });

  it("rejects responses where 'score' is not a number", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, {
        permission: "allow",
        action_type: "x",
        channel: "y",
        norm_hash: "z",
        source: "engine",
        score: "not a number",
      });

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "malformed_response",
      message: expect.stringContaining("score"),
    });
    await client.close();
  });

  it("rejects responses where 'tier' is not in the enum", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, {
        permission: "allow",
        action_type: "x",
        channel: "y",
        norm_hash: "z",
        source: "engine",
        tier: "Spicy",
      });

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "malformed_response",
      message: expect.stringContaining("tier"),
    });
    await client.close();
  });

  it("rejects responses where 'blocked' is not a boolean", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, {
        permission: "allow",
        action_type: "x",
        channel: "y",
        norm_hash: "z",
        source: "engine",
        blocked: "yes",
      });

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "malformed_response",
      message: expect.stringContaining("blocked"),
    });
    await client.close();
  });
});

describe("Permit0Client.check — fail-open path", () => {
  let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    env = { ...process.env };
    delete process.env["PERMIT0_FAIL_OPEN"];
  });
  afterEach(() => {
    process.env = env;
  });

  it("returns synthetic allow when failOpen=true and daemon refused", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    const logger = captureLogger();
    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
      logger,
    });

    const got = await client.check("Bash", { command: "ls" });
    expect(got.permission).toBe("allow");
    expect(got.source).toBe("failed_open");
    expect(got.action_type).toBe("unknown");
    // block_reason is reserved for the deny path; synthetic allow must not
    // overload it with a fail-open reason that consumers would misread.
    expect(got.block_reason).toBeUndefined();
    expect(logger.records.some((r) => r.level === "warn" && /PERMIT0_FAIL_OPEN/.test(r.msg))).toBe(true);
    await client.close();
  });

  it("respects PERMIT0_FAIL_OPEN env var when failOpen='env'", async () => {
    process.env["PERMIT0_FAIL_OPEN"] = "1";
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: "env",
    });

    const got = await client.check("Bash", { command: "ls" });
    expect(got.source).toBe("failed_open");
    await client.close();
  });

  it("re-reads env var on every call (toggle without recreating client)", async () => {
    delete process.env["PERMIT0_FAIL_OPEN"];
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(4);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: "env",
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toBeInstanceOf(
      Permit0Error,
    );

    process.env["PERMIT0_FAIL_OPEN"] = "1";
    const got = await client.check("Bash", { command: "ls" });
    expect(got.source).toBe("failed_open");
    await client.close();
  });
});

describe("Permit0Client.check — timeout", () => {
  it("throws Permit0Error{timeout} when fetch aborts", async () => {
    const { dispatcher, pool } = setup();
    // Reply with a delay longer than the timeout.
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision())
      .delay(200)
      .times(2);

    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      timeoutMs: 30,
      retryBackoffMs: 0,
    });

    await expect(client.check("Bash", { command: "ls" })).rejects.toMatchObject({
      name: "Permit0Error",
      code: "timeout",
    });
    await client.close();
  }, 5_000);
});

describe("Permit0Client.health", () => {
  it("returns true on /api/v1/health 200", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/health", method: "GET" })
      .reply(200, "ok");

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    expect(await client.health()).toBe(true);
    await client.close();
  });

  it("returns false on connection failure (never throws)", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/health", method: "GET" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }));

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    expect(await client.health()).toBe(false);
    await client.close();
  });

  it("returns false on non-2xx", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/health", method: "GET" })
      .reply(503, "down");

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    expect(await client.health()).toBe(false);
    await client.close();
  });
});

describe("Permit0Client construction", () => {
  it("honors custom baseUrl", async () => {
    const { dispatcher, agent } = setup();
    const otherPool = agent.get("http://example.test:8080");
    otherPool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision());

    const client = new Permit0Client({
      baseUrl: "http://example.test:8080",
      dispatcher,
    });
    const got = await client.check("Bash", { command: "ls" });
    expect(got.permission).toBe("allow");
    await client.close();
  });

  it("close() does not close a user-supplied dispatcher", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision());

    const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    await client.check("Bash", { command: "ls" });
    await client.close();

    // The dispatcher must still be usable after close() — we don't own it.
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllowDecision());
    const client2 = new Permit0Client({ baseUrl: BASE_URL, dispatcher });
    const got = await client2.check("Bash", { command: "ls" });
    expect(got.permission).toBe("allow");
    await client2.close();
  });

  it("close() does close a self-created dispatcher (idempotent)", async () => {
    // No mock — just verify close() resolves without error twice in a row
    // when the client owns its dispatcher. This catches regressions where
    // ownsDispatcher logic flips wrong.
    const client = new Permit0Client({ baseUrl: BASE_URL });
    await client.close();
    // Second close should also resolve cleanly (already-closed Agent is a no-op).
    await expect(client.close()).resolves.toBeUndefined();
  });

  it("uses NOOP_LOGGER by default (no console output)", async () => {
    const { dispatcher, pool } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(503, "boom")
      .times(2);

    const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
    });
    await expect(client.check("Bash", { command: "ls" })).rejects.toBeInstanceOf(
      Permit0Error,
    );
    expect(consoleWarn).not.toHaveBeenCalled();
    consoleWarn.mockRestore();
    await client.close();
  });
});

describe("Permit0Client.isFailOpenActive", () => {
  let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    env = { ...process.env };
  });
  afterEach(() => {
    process.env = env;
  });

  it("returns true when failOpen=true", () => {
    const client = new Permit0Client({ failOpen: true });
    expect(client.isFailOpenActive()).toBe(true);
    void client.close();
  });

  it("returns false when failOpen=false", () => {
    process.env["PERMIT0_FAIL_OPEN"] = "1";
    const client = new Permit0Client({ failOpen: false });
    expect(client.isFailOpenActive()).toBe(false);
    void client.close();
  });

  it("reads env var when failOpen='env'", () => {
    delete process.env["PERMIT0_FAIL_OPEN"];
    const client = new Permit0Client({ failOpen: "env" });
    expect(client.isFailOpenActive()).toBe(false);
    process.env["PERMIT0_FAIL_OPEN"] = "1";
    expect(client.isFailOpenActive()).toBe(true);
    void client.close();
  });
});
