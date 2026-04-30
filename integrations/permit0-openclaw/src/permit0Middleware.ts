import { Permit0DenyError } from "./errors.js";
import { blockedFromDecision } from "./permit0Skill.js";
import type { Permit0Client } from "./Permit0Client.js";
import type { Blocked, CheckContext, Decision } from "./types.js";

/**
 * Per-call gateway context the middleware reads to thread session id and
 * task goal into permit0's audit trail. OpenClaw populates this at the
 * dispatch boundary; any other gateway with the same shape works too.
 *
 * All fields are optional so callers can attach what they have.
 */
export interface GatewayCtx {
  session_id?: string;
  task_goal?: string;
  /** Free-form additional metadata, lands under metadata.* in audit. */
  extra?: Record<string, unknown>;
}

/**
 * Generic gateway dispatch signature.
 *
 * `next(args)` runs the original skill registered under `toolName`. The
 * middleware composes by replacing the gateway's dispatch with a wrapper
 * that calls permit0 first and only invokes `next` on allow.
 *
 * Result is `unknown` because the gateway's skill registry holds skills
 * with heterogeneous return types — type narrowing happens at the caller.
 */
export type GatewayDispatch = (
  toolName: string,
  args: unknown,
  ctx?: GatewayCtx,
) => Promise<unknown>;

/**
 * Behavior on non-allow decisions.
 *
 * - `"throw"` (default) — raise Permit0DenyError so the gateway's normal
 *   exception handling surfaces it. Best for gateways that already have a
 *   structured error path back to the LLM.
 *
 * - `"return"` — return a Blocked sentinel as the dispatch result. Best
 *   for gateways without exception machinery, or when the gateway wants
 *   to render block reasons inline without unwinding the call stack.
 */
export type OnBlock = "throw" | "return";

export interface Permit0MiddlewareOptions {
  /** What to do on deny / human. Defaults to "throw". */
  onBlock?: OnBlock;
}

/**
 * Compose permit0 in front of a gateway's dispatch function.
 *
 * Returns a wrapped dispatch with the same signature. Plug it in where
 * the gateway hands tool calls to skills:
 *
 * @example
 * ```ts
 * import { permit0Middleware, Permit0Client } from "@permit0/openclaw";
 *
 * const client = new Permit0Client();
 * gateway.dispatch = permit0Middleware(client, gateway.dispatch);
 * // Or, with options:
 * // gateway.dispatch = permit0Middleware(client, gateway.dispatch, { onBlock: "return" });
 * ```
 *
 * Concurrency: stateless. Multiple in-flight calls don't share state
 * inside the middleware itself — each goes through Permit0Client.check()
 * independently and undici handles connection multiplexing.
 */
export function permit0Middleware(
  client: Permit0Client,
  next: GatewayDispatch,
  options: Permit0MiddlewareOptions = {},
): GatewayDispatch {
  const onBlock: OnBlock = options.onBlock ?? "throw";

  return async (toolName, args, ctx) => {
    const checkCtx: CheckContext = toCheckContext(ctx);
    const decision: Decision = await client.check(toolName, args, checkCtx);

    if (decision.permission === "allow") {
      return next(toolName, args, ctx);
    }

    if (onBlock === "return") {
      const blocked: Blocked = blockedFromDecision(toolName, decision);
      return blocked;
    }

    // onBlock === "throw"
    const reason =
      decision.block_reason ??
      (decision.permission === "human"
        ? "human approval required"
        : `policy denied call to ${toolName}`);
    throw new Permit0DenyError(toolName, reason, decision);
  };
}

function toCheckContext(ctx: GatewayCtx | undefined): CheckContext {
  if (!ctx) return {};
  const out: CheckContext = {};
  if (ctx.session_id !== undefined) out.session_id = ctx.session_id;
  if (ctx.task_goal !== undefined) out.task_goal = ctx.task_goal;
  if (ctx.extra) out.extra = ctx.extra;
  return out;
}
