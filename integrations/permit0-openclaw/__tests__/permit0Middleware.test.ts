import { describe, expect, it, vi } from "vitest";
import { MockAgent } from "undici";

import { Permit0Client } from "../src/Permit0Client.js";
import { Permit0DenyError, Permit0Error } from "../src/errors.js";
import {
  permit0Middleware,
  type GatewayDispatch,
} from "../src/permit0Middleware.js";
import { isBlocked } from "../src/types.js";
import type { Decision } from "../src/types.js";

const BASE_URL = "http://localhost:9090";

function makeAllow(overrides: Partial<Decision> = {}): Decision {
  return {
    permission: "allow",
    action_type: "process.shell",
    channel: "shell",
    norm_hash: "aa",
    source: "engine",
    ...overrides,
  };
}

function makeDeny(reason: string): Decision {
  return {
    permission: "deny",
    action_type: "process.shell",
    channel: "shell",
    norm_hash: "bb",
    source: "engine",
    blocked: true,
    block_reason: reason,
    score: 95,
    tier: "CRITICAL",
  };
}

function makeHuman(reason?: string): Decision {
  const base: Decision = {
    permission: "human",
    action_type: "net.fetch",
    channel: "http",
    norm_hash: "cc",
    source: "engine",
    blocked: true,
    score: 60,
    tier: "MEDIUM",
  };
  return reason !== undefined ? { ...base, block_reason: reason } : base;
}

function setup() {
  const agent = new MockAgent();
  agent.disableNetConnect();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dispatcher = agent as any;
  const pool = agent.get(BASE_URL);
  const client = new Permit0Client({
    baseUrl: BASE_URL,
    dispatcher,
    retryBackoffMs: 0,
  });
  return { agent, pool, client };
}

describe("permit0Middleware — allow path", () => {
  it("calls next() on allow and passes args/ctx through", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    const inner: GatewayDispatch = vi.fn(async (_tool, _args, _ctx) => "ran");
    const wrapped = permit0Middleware(client, inner);

    const got = await wrapped("Bash", { command: "ls" }, { session_id: "s-1" });
    expect(got).toBe("ran");
    expect(inner).toHaveBeenCalledWith(
      "Bash",
      { command: "ls" },
      { session_id: "s-1" },
    );
    await client.close();
  });

  it("works without ctx", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    const inner: GatewayDispatch = vi.fn(async () => "ran");
    const wrapped = permit0Middleware(client, inner);

    const got = await wrapped("Bash", { command: "ls" });
    expect(got).toBe("ran");
    await client.close();
  });
});

describe("permit0Middleware — onBlock='throw' (default)", () => {
  it("throws Permit0DenyError on deny", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeDeny("destructive-root-removal"));

    const inner: GatewayDispatch = vi.fn(async () => "should not run");
    const wrapped = permit0Middleware(client, inner);

    await expect(
      wrapped("Bash", { command: "rm -rf /" }),
    ).rejects.toBeInstanceOf(Permit0DenyError);
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });

  it("Permit0DenyError carries the daemon's reason and decision", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeDeny("destructive-root-removal"));

    const wrapped = permit0Middleware(client, vi.fn(async () => "x"));

    try {
      await wrapped("Bash", { command: "rm -rf /" });
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Permit0DenyError);
      const e = err as Permit0DenyError;
      expect(e.message).toBe("destructive-root-removal");
      expect(e.toolName).toBe("Bash");
      expect(e.decision.score).toBe(95);
      expect(e.decision.tier).toBe("CRITICAL");
    }
    await client.close();
  });

  it("throws on human as well (with appropriate reason)", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeHuman());

    const inner: GatewayDispatch = vi.fn(async () => "x");
    const wrapped = permit0Middleware(client, inner);

    await expect(
      wrapped("WebFetch", { url: "http://x" }),
    ).rejects.toMatchObject({
      name: "Permit0DenyError",
      message: expect.stringContaining("human"),
    });
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });
});

describe("permit0Middleware — onBlock='return'", () => {
  it("returns Blocked instead of throwing on deny", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeDeny("destructive-root-removal"));

    const inner: GatewayDispatch = vi.fn(async () => "should not run");
    const wrapped = permit0Middleware(client, inner, { onBlock: "return" });

    const got = await wrapped("Bash", { command: "rm -rf /" });
    expect(isBlocked(got)).toBe(true);
    if (isBlocked(got)) {
      expect(got.reason).toBe("destructive-root-removal");
      expect(got.decision.permission).toBe("deny");
    }
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });

  it("returns Blocked on human", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeHuman("human approval required"));

    const inner: GatewayDispatch = vi.fn(async () => "x");
    const wrapped = permit0Middleware(client, inner, { onBlock: "return" });

    const got = await wrapped("WebFetch", { url: "http://x" });
    expect(isBlocked(got)).toBe(true);
    if (isBlocked(got)) {
      expect(got.decision.permission).toBe("human");
    }
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });
});

describe("permit0Middleware — context threading", () => {
  it("forwards session_id and task_goal as metadata.*", async () => {
    const { pool, client } = setup();
    let captured: { metadata?: Record<string, unknown> } | undefined;
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, (opts) => {
        captured = JSON.parse(String(opts.body));
        return makeAllow();
      });

    const inner: GatewayDispatch = vi.fn(async () => "ok");
    const wrapped = permit0Middleware(client, inner);

    await wrapped(
      "Bash",
      { command: "ls" },
      {
        session_id: "conv-7",
        task_goal: "list files",
        extra: { trace_id: "abc" },
      },
    );

    expect(captured?.metadata).toMatchObject({
      session_id: "conv-7",
      task_goal: "list files",
      trace_id: "abc",
    });
    await client.close();
  });
});

describe("permit0Middleware — error propagation", () => {
  it("propagates Permit0Error on fail-closed", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    const inner: GatewayDispatch = vi.fn(async () => "x");
    const wrapped = permit0Middleware(client, inner);

    await expect(wrapped("Bash", { command: "ls" })).rejects.toBeInstanceOf(
      Permit0Error,
    );
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });

  it("propagates inner skill errors verbatim on allow", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    class InnerError extends Error {
      readonly code = "INNER_BAD";
    }
    const inner: GatewayDispatch = async () => {
      throw new InnerError("inner blew up");
    };
    const wrapped = permit0Middleware(client, inner);

    await expect(wrapped("Bash", { command: "ls" })).rejects.toMatchObject({
      message: "inner blew up",
      code: "INNER_BAD",
    });
    await client.close();
  });
});
