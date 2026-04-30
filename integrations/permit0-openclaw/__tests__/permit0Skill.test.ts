import { describe, expect, it, vi } from "vitest";
import { MockAgent } from "undici";

import { Permit0Client } from "../src/Permit0Client.js";
import { Permit0Error } from "../src/errors.js";
import { permit0Skill } from "../src/permit0Skill.js";
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
  const client = new Permit0Client({ baseUrl: BASE_URL, dispatcher, retryBackoffMs: 0 });
  return { agent, pool, client };
}

describe("permit0Skill — allow path", () => {
  it("runs the inner skill and returns its result on allow", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    const inner = vi.fn(async ({ command }: { command: string }) => `ran: ${command}`);
    const safe = permit0Skill("Bash", client, inner);

    const got = await safe({ command: "ls" });
    expect(got).toBe("ran: ls");
    expect(inner).toHaveBeenCalledOnce();
    expect(inner).toHaveBeenCalledWith({ command: "ls" });
    await client.close();
  });

  it("treats fail-open synthetic allow the same as a real allow", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    // Re-create client with fail-open enabled.
    await client.close();
    const agent = new MockAgent();
    agent.disableNetConnect();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dispatcher = agent as any;
    const pool2 = agent.get(BASE_URL);
    pool2
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    const failOpenClient = new Permit0Client({
      baseUrl: BASE_URL,
      dispatcher,
      retryBackoffMs: 0,
      failOpen: true,
    });
    const inner = vi.fn(async () => "ran");
    const safe = permit0Skill("Bash", failOpenClient, inner);

    const got = await safe({ command: "ls" });
    expect(got).toBe("ran");
    expect(inner).toHaveBeenCalledOnce();
    await failOpenClient.close();
  });
});

describe("permit0Skill — deny path", () => {
  it("returns Blocked with the daemon's block_reason on deny", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeDeny("destructive-root-removal"));

    const inner = vi.fn(async () => "should not run");
    const safe = permit0Skill("Bash", client, inner);

    const got = await safe({ command: "rm -rf /" });
    expect(isBlocked(got)).toBe(true);
    if (isBlocked(got)) {
      expect(got.reason).toBe("destructive-root-removal");
      expect(got.decision.permission).toBe("deny");
      expect(got.decision.score).toBe(95);
    }
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });

  it("falls back to a generated reason when block_reason is absent", async () => {
    const { pool, client } = setup();
    const decision = makeDeny("anything");
    delete decision.block_reason;
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, decision);

    const inner = vi.fn(async () => "should not run");
    const safe = permit0Skill("Bash", client, inner);

    const got = await safe({ command: "rm -rf /" });
    expect(isBlocked(got)).toBe(true);
    if (isBlocked(got)) {
      expect(got.reason).toMatch(/policy denied/i);
      expect(got.reason).toContain("Bash");
    }
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });
});

describe("permit0Skill — human path", () => {
  it("returns Blocked with the daemon's reason on human", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeHuman("human approval required"));

    const inner = vi.fn(async () => "should not run");
    const safe = permit0Skill("WebFetch", client, inner);

    const got = await safe({ url: "http://example.com" });
    expect(isBlocked(got)).toBe(true);
    if (isBlocked(got)) {
      expect(got.reason).toBe("human approval required");
      expect(got.decision.permission).toBe("human");
    }
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });

  it("provides a default reason when human decision has no block_reason", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeHuman());

    const inner = vi.fn(async () => "should not run");
    const safe = permit0Skill("WebFetch", client, inner);

    const got = await safe({ url: "http://example.com" });
    expect(isBlocked(got)).toBe(true);
    if (isBlocked(got)) {
      expect(got.reason).toMatch(/human approval/i);
    }
    await client.close();
  });
});

describe("permit0Skill — error propagation", () => {
  it("rethrows Permit0Error when daemon unreachable and fail-closed", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .replyWithError(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }))
      .times(2);

    const inner = vi.fn(async () => "should not run");
    const safe = permit0Skill("Bash", client, inner);

    await expect(safe({ command: "ls" })).rejects.toBeInstanceOf(Permit0Error);
    expect(inner).not.toHaveBeenCalled();
    await client.close();
  });

  it("rethrows the inner skill's exception verbatim (does not wrap)", async () => {
    const { pool, client } = setup();
    // Two intercepts because we call safe() twice — once for shape, once for instance check.
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow())
      .times(2);

    class CustomError extends Error {
      readonly code = "MY_CODE";
    }
    const inner = vi.fn(async () => {
      throw new CustomError("inner blew up");
    });
    const safe = permit0Skill("Bash", client, inner);

    await expect(safe({ command: "ls" })).rejects.toMatchObject({
      message: "inner blew up",
      code: "MY_CODE",
    });
    await expect(safe({ command: "ls" })).rejects.toBeInstanceOf(CustomError);
    await client.close();
  });
});

describe("permit0Skill — context threading", () => {
  it("passes ctx through to Permit0Client.check", async () => {
    const { pool, client } = setup();
    let capturedBody: { metadata?: Record<string, unknown> } | undefined;
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, (opts) => {
        capturedBody = JSON.parse(String(opts.body));
        return makeAllow();
      });

    const inner = vi.fn(async () => "ok");
    const safe = permit0Skill("Bash", client, inner);

    await safe({ command: "ls" }, { ctx: { session_id: "conv-42", task_goal: "list" } });

    expect(capturedBody?.metadata).toMatchObject({
      session_id: "conv-42",
      task_goal: "list",
    });
    await client.close();
  });

  it("works without ctx (defaults to empty)", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    const inner = vi.fn(async () => "ok");
    const safe = permit0Skill("Bash", client, inner);

    const got = await safe({ command: "ls" });
    expect(got).toBe("ok");
    await client.close();
  });
});

describe("permit0Skill — type preservation", () => {
  it("preserves Args and Result types end-to-end", async () => {
    const { pool, client } = setup();
    pool
      .intercept({ path: "/api/v1/check", method: "POST" })
      .reply(200, makeAllow());

    interface FooArgs {
      n: number;
      tag: string;
    }
    interface FooResult {
      doubled: number;
      tagWas: string;
    }

    const inner = async ({ n, tag }: FooArgs): Promise<FooResult> => ({
      doubled: n * 2,
      tagWas: tag,
    });

    const safe = permit0Skill<FooArgs, FooResult>("Foo", client, inner);
    const got = await safe({ n: 21, tag: "x" });
    if (!isBlocked(got)) {
      expect(got.doubled).toBe(42);
      expect(got.tagWas).toBe("x");
    } else {
      throw new Error("unexpected block");
    }
    await client.close();
  });
});
