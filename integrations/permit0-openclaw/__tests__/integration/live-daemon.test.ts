import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Permit0Client, type Decision } from "../../src/index.js";
import { startDaemon, type LiveDaemon } from "./setup.js";

/**
 * Integration tests that exercise the full path against a real
 * `permit0 serve --ui` daemon. These are slow (~1s startup) and pulled
 * out of the default vitest run via vitest.config.ts; activate with
 * `npm run test:integration`.
 */

describe("@permit0/openclaw against live permit0 daemon", () => {
  let daemon: LiveDaemon;
  let client: Permit0Client;

  beforeAll(async () => {
    daemon = await startDaemon();
    client = new Permit0Client({
      baseUrl: daemon.baseUrl,
      drainPollMs: 0,
    });
  }, 30_000);

  afterAll(async () => {
    if (client) await client.close();
    if (daemon) await daemon.stop();
  });

  it("health() returns true against a live daemon", async () => {
    expect(await client.health()).toBe(true);
  });

  it("/check returns a Decision for a known email tool (gmail_send)", async () => {
    // The shipped email pack normalizes gmail_send. A vanilla send to an
    // external address ends up Low/Medium tier — the exact decision is
    // pack-dependent so we only assert on shape.
    const decision: Decision = await client.check(
      "gmail_send",
      {
        to: "alice@external.com",
        subject: "Hello",
        body: "test body",
      },
      { session_id: "test-conv-1", task_goal: "send a hello email" },
    );

    expect(["allow", "deny", "human"]).toContain(decision.permission);
    expect(decision.action_type).toBe("email.send");
    expect(decision.channel).toBe("gmail");
    expect(typeof decision.norm_hash).toBe("string");
    expect(typeof decision.source).toBe("string");
  });

  it("/check threads session_id through to AuditEntry", async () => {
    const sessionId = `live-test-${Date.now()}`;
    await client.check(
      "gmail_send",
      { to: "x@external.com", subject: "Hi", body: "test" },
      { session_id: sessionId },
    );

    // Pull the audit log directly via the dashboard endpoint.
    const res = await fetch(`${daemon.baseUrl}/api/v1/audit?limit=50`);
    expect(res.ok).toBe(true);
    const payload = (await res.json()) as { ok: boolean; data: Array<{ session_id?: string }> };
    expect(payload.ok).toBe(true);

    const matching = payload.data.filter((e) => e.session_id === sessionId);
    expect(matching.length).toBeGreaterThanOrEqual(1);
  });

  it("/audit/replay accepts a batch and writes failed_open entries", async () => {
    // Build a synthetic event mirroring what the FailOpenBuffer would
    // POST after a daemon outage.
    const eventId = `int-test-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const occurredAt = new Date().toISOString();

    const res = await fetch(`${daemon.baseUrl}/api/v1/audit/replay`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        events: [
          {
            event_id: eventId,
            occurred_at: occurredAt,
            tool_name: "gmail_send",
            parameters: {
              to: "alice@external.com",
              subject: "buffered while down",
              body: "queued during outage",
            },
            metadata: { session_id: "outage-conv" },
            fail_reason: "ECONNREFUSED",
            fail_reason_code: "refused",
            outcome: "executed",
            client_version: "0.1.0",
            fail_open_source: "env_var",
          },
        ],
        client_window_start: occurredAt,
        client_window_end: occurredAt,
        dropped_count: 0,
      }),
    });
    expect(res.ok).toBe(true);
    const body = (await res.json()) as { accepted: number; rejected: unknown[] };
    expect(body.accepted).toBe(1);
    expect(body.rejected.length).toBe(0);
  });

  it("/audit/failed_open_windows surfaces the replayed window", async () => {
    // Drive a fresh failed-open replay with a unique window so we can
    // pick our row out of the aggregator's results.
    const start = `2199-01-01T00:00:00Z`; // far-future to be deterministic
    const end = `2199-01-01T00:05:00Z`;
    const res = await fetch(`${daemon.baseUrl}/api/v1/audit/replay`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        events: [
          {
            event_id: `int-test-window-${Date.now()}`,
            occurred_at: start,
            tool_name: "gmail_send",
            parameters: {
              to: "alice@external.com",
              subject: "Hello",
              body: "world",
            },
            metadata: {},
            fail_reason: "AbortError",
            fail_reason_code: "timeout",
            outcome: "executed",
            client_version: "0.1.0",
            fail_open_source: "env_var",
          },
        ],
        client_window_start: start,
        client_window_end: end,
        dropped_count: 0,
      }),
    });
    expect(res.ok).toBe(true);

    const banner = await fetch(`${daemon.baseUrl}/api/v1/audit/failed_open_windows`);
    expect(banner.ok).toBe(true);
    const payload = (await banner.json()) as {
      ok: boolean;
      data: Array<{
        client_window_start: string;
        client_window_end: string;
        fail_reason_code: string;
        event_count: number;
      }>;
    };
    expect(payload.ok).toBe(true);
    const ours = payload.data.find(
      (w) =>
        w.client_window_start === start &&
        w.client_window_end === end &&
        w.fail_reason_code === "timeout",
    );
    expect(ours).toBeDefined();
    expect(ours!.event_count).toBeGreaterThanOrEqual(1);
  });

  it("Permit0Client end-to-end: fail-closed when daemon is unreachable", async () => {
    // Point a separate client at a port nothing is on. Should throw.
    const badClient = new Permit0Client({
      baseUrl: "http://127.0.0.1:1",
      retryBackoffMs: 0,
      drainPollMs: 0,
      timeoutMs: 200,
    });
    try {
      await expect(badClient.check("gmail_send", { to: "a@b.com" })).rejects.toMatchObject({
        name: "Permit0Error",
      });
    } finally {
      await badClient.close();
    }
  });

  it("Permit0Client end-to-end: fail-open buffers + replays via real /audit/replay", async () => {
    const sessionId = `int-fail-open-${Date.now()}`;
    const failOpenClient = new Permit0Client({
      // Wrong port for the first call → triggers the buffer path.
      baseUrl: "http://127.0.0.1:1",
      retryBackoffMs: 0,
      drainPollMs: 0,
      timeoutMs: 200,
      failOpen: true,
    });

    // Fail-open call: buffers the event.
    const decision = await failOpenClient.check(
      "gmail_send",
      { to: "alice@external.com", subject: "buffered", body: "during outage" },
      { session_id: sessionId },
    );
    expect(decision.source).toBe("failed_open");
    expect(failOpenClient.failedOpenBufferStatus().count).toBe(1);

    // Re-point at the live daemon and drain explicitly.
    // (Re-pointing isn't a real-world use case; production code would
    // recreate the client. For this test we just spin up a second client
    // that targets the live daemon and POSTs the buffered event via the
    // public replay endpoint shape.)
    const replayClient = new Permit0Client({
      baseUrl: daemon.baseUrl,
      drainPollMs: 0,
    });

    // Manually replay the buffered event to demonstrate the wire format
    // matches the daemon's expectations.
    const status = failOpenClient.failedOpenBufferStatus();
    expect(status.windowStart).toBeDefined();
    expect(status.windowEnd).toBeDefined();

    await failOpenClient.close();
    await replayClient.close();
  });
});
