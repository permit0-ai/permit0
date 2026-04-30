import type { Decision } from "./types.js";

/**
 * Reason codes for non-decision failures (transport, daemon-unreachable).
 * `decision` failures use Permit0DenyError instead.
 */
export type Permit0FailureCode =
  | "timeout"
  | "refused"
  | "http_error"
  | "malformed_response"
  | "fail_closed";

/**
 * Thrown when permit0 could not reach a decision (transport failure,
 * malformed response, or fail-closed default with no daemon answer).
 *
 * Distinct from a deny — this means we did not get policy adjudication at
 * all. Callers should treat it as fail-closed unless PERMIT0_FAIL_OPEN=1.
 */
export class Permit0Error extends Error {
  override readonly name = "Permit0Error";
  readonly code: Permit0FailureCode;
  readonly toolName: string;
  readonly status: number | undefined;
  readonly cause: unknown;

  constructor(
    message: string,
    opts: {
      code: Permit0FailureCode;
      toolName: string;
      status?: number;
      cause?: unknown;
    },
  ) {
    super(message);
    this.code = opts.code;
    this.toolName = opts.toolName;
    this.status = opts.status;
    this.cause = opts.cause;
  }

  override toString(): string {
    const parts = [`Permit0Error[${this.code}]`, this.toolName, this.message];
    if (this.status !== undefined) parts.push(`status=${this.status}`);
    return parts.join(" — ");
  }
}

/**
 * Thrown by middleware when permit0 returned a deny or human-in-the-loop
 * decision. Carries the full decision so the gateway can render a useful
 * message back to the LLM.
 *
 * Per-skill HOF callers receive a `Blocked` value instead of this error
 * (they can keep their own control flow).
 */
export class Permit0DenyError extends Error {
  override readonly name = "Permit0DenyError";
  readonly toolName: string;
  readonly decision: Decision;

  constructor(toolName: string, reason: string, decision: Decision) {
    super(reason);
    this.toolName = toolName;
    this.decision = decision;
  }

  override toString(): string {
    const tier = this.decision.tier ?? "?";
    const score = this.decision.score ?? "?";
    return `Permit0DenyError — ${this.toolName} — ${this.message} (tier=${tier} score=${score})`;
  }
}
