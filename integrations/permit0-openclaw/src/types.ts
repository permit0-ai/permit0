/**
 * Hand-written TypeScript types for the permit0 HTTP API surface used by
 * @permit0/openclaw. These mirror crates/permit0-cli/src/cmd/serve.rs::CheckResponse
 * exactly. Drift is caught by the JSON fixture test in __tests__/types.fixture.test.ts.
 *
 * If you change a field here, capture a fresh fixture from `permit0 serve` and
 * pin it under __tests__/fixtures/ so the alignment regression is self-evident.
 */

/** Final policy decision permit0 returned for a tool call. */
export type Permission = "allow" | "deny" | "human";

/**
 * Risk tier from the scoring pipeline. Display-only on the client side.
 *
 * NOTE: the Rust daemon serializes Tier via its `Display` impl, which
 * produces UPPER_SNAKE_CASE values ("MINIMAL", "LOW", etc.). Keep this
 * union in lockstep with `permit0-types/src/risk.rs::Tier::fmt`.
 */
export type Tier = "MINIMAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * Decision source. Mirrors `PermissionResult.source` in the engine.
 *
 * Common values today: `"engine"`, `"denylist"`, `"allowlist"`, `"policy_cache"`,
 * `"human_review"`. New values may appear over time, so consumers should not
 * exhaustively switch on this — treat as informational.
 */
export type DecisionSource = string;

/**
 * Response body for POST /api/v1/check.
 *
 * Field-for-field mirror of `CheckResponse` in serve.rs. Optional fields here
 * are exactly the ones marked `Option<_>` server-side.
 */
export interface Decision {
  permission: Permission;
  action_type: string;
  channel: string;
  norm_hash: string;
  source: DecisionSource;
  score?: number;
  tier?: Tier;
  blocked?: boolean;
  block_reason?: string;
}

/**
 * Request body for POST /api/v1/check.
 *
 * `metadata` is reserved for caller-supplied context (e.g. `session_id`,
 * `task_goal`). It is currently dropped server-side; Lane A step 1 wires it
 * into the audit entry. Sending it now is forward-compatible.
 */
export interface CheckRequest {
  tool_name: string;
  parameters: unknown;
  metadata?: Record<string, unknown>;
}

/**
 * Per-call context the caller threads through `Permit0Client.check()`.
 * All fields land in `metadata` on the outgoing request.
 */
export interface CheckContext {
  /** OpenClaw conversation/session id, surfaces on the audit entry once Lane A lands. */
  session_id?: string;
  /** What the agent was asked to do (high-level), helps audit triage. */
  task_goal?: string;
  /** Free-form additional metadata, merged after session_id/task_goal. */
  extra?: Record<string, unknown>;
}

/** Sentinel returned by wrappers when permit0 blocked the call. */
export interface Blocked {
  blocked: true;
  reason: string;
  decision: Decision;
}

export function isBlocked(value: unknown): value is Blocked {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { blocked?: unknown }).blocked === true
  );
}

/** Logger surface used by Permit0Client. Default impl is a no-op. */
export interface Logger {
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  debug(message: string, fields?: Record<string, unknown>): void;
}

export const NOOP_LOGGER: Logger = {
  warn: () => {},
  error: () => {},
  debug: () => {},
};
