import type { Permit0Client } from "./Permit0Client.js";
import type { Blocked, CheckContext, Decision } from "./types.js";

/**
 * Per-call options for a wrapped skill. Threads context that the OpenClaw
 * gateway has but the inner skill doesn't directly know about (session id,
 * task goal, etc.) into permit0's audit trail.
 */
export interface SkillCallOptions {
  ctx?: CheckContext;
}

/**
 * Wrap an OpenClaw-style skill function so every invocation goes through
 * permit0 first.
 *
 * On `allow` (or fail-open synthetic allow), the inner skill runs and its
 * return value is passed through untouched.
 *
 * On `deny` or `human`, the wrapped function returns a `Blocked` value
 * carrying the reason and the full Decision — the gateway can render it
 * back to the LLM, log it, or surface it as an approval prompt.
 *
 * Throws Permit0Error only when fail-closed fires (daemon unreachable +
 * PERMIT0_FAIL_OPEN unset). Inner skill exceptions are rethrown verbatim.
 *
 * @example
 * ```ts
 * const safeShell = permit0Skill("Bash", client, async ({ command }) => {
 *   return execSync(command).toString();
 * });
 * const result = await safeShell({ command: "ls" });
 * if (isBlocked(result)) { ... } else { ... }
 * ```
 */
export function permit0Skill<Args, Result>(
  toolName: string,
  client: Permit0Client,
  skill: (args: Args) => Promise<Result>,
): (args: Args, opts?: SkillCallOptions) => Promise<Result | Blocked> {
  return async (args, opts) => {
    const decision: Decision = await client.check(
      toolName,
      args as unknown,
      opts?.ctx ?? {},
    );

    if (decision.permission === "allow") {
      return skill(args);
    }

    return blockedFromDecision(toolName, decision);
  };
}

/**
 * Build a uniform Blocked sentinel from a non-allow Decision.
 * Centralized so HOF and middleware produce identical messages for
 * identical decisions (auditors expect consistent reason text).
 */
export function blockedFromDecision(
  toolName: string,
  decision: Decision,
): Blocked {
  let reason: string;
  if (decision.permission === "human") {
    reason = decision.block_reason ?? "human approval required";
  } else {
    // permission === "deny"
    reason = decision.block_reason ?? `policy denied call to ${toolName}`;
  }
  return { blocked: true, reason, decision };
}
