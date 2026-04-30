import { createRequire } from "node:module";

import { Agent, fetch as undiciFetch } from "undici";

import { Permit0Error, type Permit0FailureCode } from "./errors.js";
import {
  FailOpenBuffer,
  type BufferStatus,
  type BufferedEvent,
  type DrainResult,
} from "./FailOpenBuffer.js";
import {
  NOOP_LOGGER,
  type CheckContext,
  type CheckRequest,
  type Decision,
  type Logger,
  type Tier,
} from "./types.js";

const DEFAULT_BASE_URL = "http://localhost:9090";
const DEFAULT_TIMEOUT_MS = 1_000;
const DEFAULT_RETRY_BACKOFF_MS = 50;

/**
 * Read package.json's version at runtime so it can never drift from the
 * shipped artifact. Wrapped in a try/catch because some bundlers may
 * relocate package.json relative to the compiled file; the metadata field
 * is informational, not load-bearing.
 */
const PACKAGE_VERSION: string = (() => {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json") as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
})();

/**
 * Mode for the fail-open escape hatch. The default reads
 * `process.env.PERMIT0_FAIL_OPEN === "1"` on every call so flipping the env
 * var doesn't require recreating the client.
 *
 * Production deployments should leave this on `"env"` (default fail-closed
 * unless the operator opts in). Tests pass a literal boolean.
 */
export type FailOpenMode = "env" | boolean;

export interface Permit0ClientOptions {
  /** Base URL of the permit0 daemon. Defaults to http://localhost:9090. */
  baseUrl?: string;
  /** Per-attempt timeout in ms. Defaults to 1000. */
  timeoutMs?: number;
  /** How many extra attempts after the first failure. Defaults to 1 (1 retry). */
  maxRetries?: number;
  /** Delay before retry in ms. Defaults to 50. */
  retryBackoffMs?: number;
  /** Fail-open behavior. Defaults to reading `PERMIT0_FAIL_OPEN` env var. */
  failOpen?: FailOpenMode;
  /** Pluggable logger. Defaults to a no-op (no console output). */
  logger?: Logger;
  /** Pre-built undici Agent (for tests). Defaults to a keep-alive Agent. */
  dispatcher?: Agent;
  /** Failed-open ring buffer capacity. Defaults to 10000. */
  bufferCapacity?: number;
  /**
   * Idle reconnect poller interval, ms. While the buffer is non-empty
   * AND no live `check()` is firing the lazy drain, the client tries to
   * deliver buffered events every `drainPollMs`. Defaults to 30000.
   * Set to 0 to disable.
   */
  drainPollMs?: number;
}

/**
 * HTTP transport for the permit0 daemon's `/api/v1/check` and
 * `/api/v1/health` endpoints.
 *
 * Behavior matrix locked in the plan:
 *   - 1s per-attempt timeout (configurable)
 *   - 1 retry on transport failure or 5xx (configurable)
 *   - No retry on 4xx (caller error)
 *   - Keep-alive connection reuse via undici Agent
 *   - Fail-closed by default; PERMIT0_FAIL_OPEN=1 enables synthetic-allow
 *   - Pluggable logger, no-op default (no console.log in package code)
 *
 * NOTE: slice 1 returns a synthetic allow Decision when fail-open triggers.
 * Slice 3 (FailOpenBuffer) will additionally enqueue the event for replay.
 */
export class Permit0Client {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly maxRetries: number;
  readonly retryBackoffMs: number;
  readonly failOpen: FailOpenMode;
  readonly logger: Logger;
  readonly drainPollMs: number;
  private readonly dispatcher: Agent;
  /** True if we created the dispatcher; close() only closes when true. */
  private readonly ownsDispatcher: boolean;
  /** Tracks whether close() has already run, to make it idempotent. */
  private closed = false;
  private readonly buffer: FailOpenBuffer;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(options: Permit0ClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? 1;
    this.retryBackoffMs = options.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
    this.failOpen = options.failOpen ?? "env";
    this.logger = options.logger ?? NOOP_LOGGER;
    this.drainPollMs = options.drainPollMs ?? 30_000;
    this.buffer = new FailOpenBuffer(options.bufferCapacity ?? 10_000);
    if (options.dispatcher) {
      this.dispatcher = options.dispatcher;
      this.ownsDispatcher = false;
    } else {
      this.dispatcher = new Agent({
        keepAliveTimeout: 30_000,
        keepAliveMaxTimeout: 60_000,
      });
      this.ownsDispatcher = true;
    }
  }

  /**
   * Whether fail-open is currently active.
   *
   * `failOpen: true`  → always.
   * `failOpen: false` → never.
   * `failOpen: "env"` → reads PERMIT0_FAIL_OPEN === "1" right now.
   */
  isFailOpenActive(): boolean {
    if (this.failOpen === true) return true;
    if (this.failOpen === false) return false;
    return process.env["PERMIT0_FAIL_OPEN"] === "1";
  }

  /**
   * Ask permit0 to adjudicate a tool call.
   *
   * Returns a Decision on success. On transport failure with fail-open
   * disabled, throws `Permit0Error`. On transport failure with fail-open
   * enabled, returns a synthetic `allow` Decision tagged
   * `source: "failed_open"`.
   */
  async check(
    toolName: string,
    parameters: unknown,
    ctx: CheckContext = {},
  ): Promise<Decision> {
    const body: CheckRequest = {
      tool_name: toolName,
      parameters,
      metadata: buildMetadata(ctx),
    };

    let lastError: Permit0Error | undefined;
    const totalAttempts = this.maxRetries + 1;

    for (let attempt = 1; attempt <= totalAttempts; attempt++) {
      try {
        const decision = await this.attemptCheck(toolName, body);
        // Successful check is the lazy-drain trigger. If we have buffered
        // events from a prior outage, drain in the background — we don't
        // block the live caller on it.
        this.maybeLazyDrain();
        return decision;
      } catch (err) {
        if (!(err instanceof Permit0Error)) throw err;
        lastError = err;

        if (!isRetryable(err)) {
          break;
        }
        if (attempt < totalAttempts) {
          this.logger.warn("permit0.check attempt failed, retrying", {
            tool: toolName,
            attempt,
            code: err.code,
            status: err.status,
          });
          await sleep(this.retryBackoffMs);
          continue;
        }
      }
    }

    // All attempts exhausted.
    const finalError =
      lastError ??
      new Permit0Error("unknown failure with no captured error", {
        code: "fail_closed",
        toolName,
      });

    if (this.isFailOpenActive()) {
      this.logger.warn(
        "permit0 unreachable; PERMIT0_FAIL_OPEN active — running tool without policy review",
        {
          tool: toolName,
          code: finalError.code,
          status: finalError.status,
        },
      );
      // Buffer the event so the daemon can replay it once it's back.
      // This is what closes the audit gap — the action is about to run
      // on the client; we capture enough to write a `failed_open` audit
      // entry on the server side later.
      this.buffer.enqueue({
        tool_name: toolName,
        parameters,
        metadata: body.metadata ?? {},
        fail_reason: finalError.message,
        fail_reason_code: finalError.code,
        outcome: "executed",
        client_version: PACKAGE_VERSION,
        fail_open_source: this.failOpen === "env" ? "env_var" : "config_flag",
      });
      this.scheduleIdlePoll();
      return syntheticFailOpenDecision(finalError);
    }

    throw finalError;
  }

  /**
   * Snapshot of the failed-open buffer state.
   *
   * Surfaces window bounds, count, drop count, and whether a drain is
   * in flight. Use for ops dashboards or to assert post-outage that
   * everything was replayed.
   */
  failedOpenBufferStatus(): BufferStatus {
    return this.buffer.status();
  }

  /**
   * Force a drain attempt now. Useful for shutdown sequences ("flush
   * before exit") or for tests that want to skip the lazy/idle triggers.
   *
   * Returns the same `DrainResult` shape the lazy drain produces: how
   * many events were flushed, how many remain, server rejections, and
   * any transport error. Single-flight: if a drain is already running
   * this returns immediately with `flushed: 0` and the current size.
   */
  async drainFailedOpenBuffer(): Promise<DrainResult> {
    return this.buffer.drain((events, ctx) => this.postReplay(events, ctx));
  }

  // ── internals: replay & drain orchestration ───────────────────────────

  /**
   * Fire-and-forget lazy drain. Runs after every successful `check()`
   * when the buffer has events. Never throws — buffer.drain captures
   * errors as part of its DrainResult; we just log on partial failures.
   */
  private maybeLazyDrain(): void {
    if (this.buffer.isEmpty() || this.closed) return;
    this.buffer
      .drain((events, ctx) => this.postReplay(events, ctx))
      .then((result) => {
        if (result.error) {
          this.logger.warn("permit0 replay drain failed; will retry", {
            remaining: result.remaining,
            error: result.error.message,
          });
        } else if (result.rejected.length > 0) {
          this.logger.warn("permit0 replay partial reject; rejected events kept", {
            flushed: result.flushed,
            rejected: result.rejected.length,
          });
        }
        // If buffer is now empty, no need to keep the idle poller alive.
        if (this.buffer.isEmpty()) {
          this.cancelIdlePoll();
        }
      })
      .catch((err) => {
        // buffer.drain swallows errors into DrainResult.error, so this
        // path should be unreachable. Defensive log if it ever fires.
        this.logger.error("permit0 replay drain threw unexpectedly", {
          error: err instanceof Error ? err.message : String(err),
        });
      });
  }

  /**
   * Schedule the idle reconnect poller. While the buffer is non-empty
   * and there's no live `check()` activity, this fires every
   * `drainPollMs` to attempt delivery. On success the buffer empties
   * and the poller stops itself.
   */
  private scheduleIdlePoll(): void {
    if (this.drainPollMs <= 0) return;
    if (this.idleTimer !== undefined) return;
    if (this.closed) return;

    this.idleTimer = setTimeout(() => {
      this.idleTimer = undefined;
      if (this.closed || this.buffer.isEmpty()) return;
      this.maybeLazyDrain();
      // If still non-empty after the attempt, reschedule.
      if (!this.buffer.isEmpty()) {
        this.scheduleIdlePoll();
      }
    }, this.drainPollMs);
    // Don't keep the Node event loop alive just for the poller.
    if (typeof this.idleTimer.unref === "function") {
      this.idleTimer.unref();
    }
  }

  private cancelIdlePoll(): void {
    if (this.idleTimer !== undefined) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
  }

  /**
   * POST a batch of buffered events to /api/v1/audit/replay. Translates
   * the server response back into the shape `FailOpenBuffer.drain`
   * expects (Set of accepted event_ids + list of rejections).
   */
  private async postReplay(
    events: BufferedEvent[],
    ctx: {
      client_window_start: string;
      client_window_end: string;
      dropped_count: number;
    },
  ): Promise<{
    acceptedIds: Set<string>;
    rejected: Array<{ event_id: string; error: string }>;
  }> {
    const ac = new AbortController();
    // Replay POSTs can carry up to 500 events; give them a longer
    // timeout than a single /check (10× the per-attempt budget).
    const replayTimeoutMs = Math.max(this.timeoutMs * 10, 10_000);
    const t = setTimeout(() => ac.abort(), replayTimeoutMs);
    try {
      const res = await undiciFetch(`${this.baseUrl}/api/v1/audit/replay`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ events, ...ctx }),
        signal: ac.signal,
        dispatcher: this.dispatcher,
      });

      if (!res.ok) {
        // 4xx/5xx — keep everything in the buffer for retry.
        const body = await res.text().catch(() => "");
        throw new Error(
          `permit0 /audit/replay returned HTTP ${res.status}${body ? ` — ${truncate(body, 200)}` : ""}`,
        );
      }

      const payload = (await res.json()) as {
        accepted?: number;
        rejected?: Array<{ event_id: string; error: string }>;
      };

      const rejected = Array.isArray(payload.rejected) ? payload.rejected : [];
      const rejectedIds = new Set(rejected.map((r) => r.event_id));
      const acceptedIds = new Set<string>();
      for (const e of events) {
        if (!rejectedIds.has(e.event_id)) acceptedIds.add(e.event_id);
      }
      return { acceptedIds, rejected };
    } finally {
      clearTimeout(t);
    }
  }

  /**
   * Liveness probe for the permit0 daemon.
   *
   * Hits `GET /api/v1/health` (does not pollute the audit log, unlike a
   * dummy `/check` call). Returns false on any failure, never throws.
   */
  async health(): Promise<boolean> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      const res = await undiciFetch(`${this.baseUrl}/api/v1/health`, {
        method: "GET",
        signal: ac.signal,
        dispatcher: this.dispatcher,
      });
      return res.ok;
    } catch {
      return false;
    } finally {
      clearTimeout(t);
    }
  }

  /**
   * Close the underlying connection pool if this client created it.
   *
   * - Idempotent: calling twice is a no-op (matters when shutdown logic
   *   double-fires from a finally block during error handling).
   * - If the caller passed a `dispatcher` to the constructor, the
   *   dispatcher is left alone — they own its lifecycle.
   * - Cancels the idle reconnect timer and clears the failed-open
   *   buffer so the Node event loop can exit cleanly. **Buffered
   *   events that haven't been replayed are dropped on close** — call
   *   `drainFailedOpenBuffer()` first if you care about them.
   *
   * Tests must call this to avoid keeping the Node event loop alive
   * when the constructor created the default Agent.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.cancelIdlePoll();
    this.buffer.clear();
    if (this.ownsDispatcher) {
      await this.dispatcher.close();
    }
  }

  // ── internals ─────────────────────────────────────────────────────────

  private async attemptCheck(
    toolName: string,
    body: CheckRequest,
  ): Promise<Decision> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);

    try {
      const res = await undiciFetch(`${this.baseUrl}/api/v1/check`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: ac.signal,
        dispatcher: this.dispatcher,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Permit0Error(
          `permit0 /check returned HTTP ${res.status}${text ? ` — ${truncate(text, 200)}` : ""}`,
          { code: "http_error", toolName, status: res.status },
        );
      }

      let payload: unknown;
      try {
        payload = await res.json();
      } catch (cause) {
        throw new Permit0Error("permit0 /check returned non-JSON body", {
          code: "malformed_response",
          toolName,
          cause,
        });
      }

      assertDecisionShape(payload, toolName);
      return payload;
    } catch (err) {
      if (err instanceof Permit0Error) throw err;

      // AbortError surfaces as DOMException name "AbortError" or {name:"AbortError"}.
      const name = (err as { name?: string }).name;
      if (name === "AbortError") {
        throw new Permit0Error(
          `permit0 /check timed out after ${this.timeoutMs}ms`,
          { code: "timeout", toolName, cause: err },
        );
      }

      // undici surfaces ECONNREFUSED with code on the inner cause.
      const code = extractErrorCode(err);
      if (code === "ECONNREFUSED" || code === "UND_ERR_CONNECT_TIMEOUT") {
        throw new Permit0Error(
          `permit0 daemon unreachable at ${this.baseUrl} (${code})`,
          { code: "refused", toolName, cause: err },
        );
      }

      throw new Permit0Error(
        `permit0 /check transport error: ${stringifyError(err)}`,
        { code: "refused", toolName, cause: err },
      );
    } finally {
      clearTimeout(t);
    }
  }
}

// ── helpers ────────────────────────────────────────────────────────────

function buildMetadata(ctx: CheckContext): Record<string, unknown> {
  const meta: Record<string, unknown> = {
    client: "@permit0/openclaw",
    client_version: PACKAGE_VERSION,
  };
  if (ctx.session_id !== undefined) meta["session_id"] = ctx.session_id;
  if (ctx.task_goal !== undefined) meta["task_goal"] = ctx.task_goal;
  if (ctx.extra) Object.assign(meta, ctx.extra);
  return meta;
}

function isClientError(status: number | undefined): boolean {
  return typeof status === "number" && status >= 400 && status < 500;
}

/**
 * Whether a failure is worth retrying. Transient transport errors yes;
 * shape mismatches and 4xx caller errors no (re-asking won't fix them).
 */
function isRetryable(err: Permit0Error): boolean {
  switch (err.code) {
    case "malformed_response":
      return false;
    case "http_error":
      return !isClientError(err.status);
    case "timeout":
    case "refused":
    case "fail_closed":
      return true;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}

function extractErrorCode(err: unknown): string | undefined {
  if (typeof err !== "object" || err === null) return undefined;
  const direct = (err as { code?: unknown }).code;
  if (typeof direct === "string") return direct;
  const cause = (err as { cause?: unknown }).cause;
  if (typeof cause === "object" && cause !== null) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === "string") return code;
  }
  return undefined;
}

function stringifyError(err: unknown): string {
  if (err instanceof Error) return err.message;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

const VALID_TIERS: ReadonlySet<Tier> = new Set([
  "MINIMAL",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]);

/**
 * Validate the response payload matches the Decision shape we expect.
 * Validates required fields AND optional fields (when present) so a flaky
 * daemon returning, say, `score: "abc"` is caught at the boundary instead
 * of poisoning consumer code with a string-where-number-was-promised.
 *
 * Throws Permit0Error{malformed_response} on any mismatch.
 */
function assertDecisionShape(
  value: unknown,
  toolName: string,
): asserts value is Decision {
  const fail = (msg: string): never => {
    throw new Permit0Error(msg, { code: "malformed_response", toolName });
  };

  if (typeof value !== "object" || value === null) {
    fail("permit0 /check returned non-object body");
  }
  const o = value as Record<string, unknown>;

  if (
    o["permission"] !== "allow" &&
    o["permission"] !== "deny" &&
    o["permission"] !== "human"
  ) {
    fail(
      `permit0 /check returned invalid permission: ${JSON.stringify(o["permission"])}`,
    );
  }
  for (const required of ["action_type", "channel", "norm_hash", "source"]) {
    if (typeof o[required] !== "string") {
      fail(`permit0 /check missing required string field: ${required}`);
    }
  }

  // Optional fields — validate types only when the field is present.
  if (o["score"] !== undefined && typeof o["score"] !== "number") {
    fail(`permit0 /check optional field 'score' has non-number type`);
  }
  if (o["blocked"] !== undefined && typeof o["blocked"] !== "boolean") {
    fail(`permit0 /check optional field 'blocked' has non-boolean type`);
  }
  if (o["block_reason"] !== undefined && typeof o["block_reason"] !== "string") {
    fail(`permit0 /check optional field 'block_reason' has non-string type`);
  }
  if (o["tier"] !== undefined) {
    if (typeof o["tier"] !== "string" || !VALID_TIERS.has(o["tier"] as Tier)) {
      fail(
        `permit0 /check optional field 'tier' has invalid value: ${JSON.stringify(o["tier"])}`,
      );
    }
  }
}

/**
 * Synthetic Decision returned when fail-open fires.
 *
 * The `source` field is the canonical signal — consumers should switch on
 * `decision.source === "failed_open"` to distinguish from a real allow.
 * The reason for the fail-open lives in the logger output and (slice 3)
 * the buffered event, not on this struct, because `block_reason` is
 * semantically reserved for the deny/human path and overloading it would
 * mislead consumers reading telemetry.
 */
function syntheticFailOpenDecision(_err: Permit0Error): Decision {
  return {
    permission: "allow",
    action_type: "unknown",
    channel: "unknown",
    norm_hash: "",
    source: "failed_open",
  };
}

// Re-export Permit0FailureCode for convenience to package consumers.
export type { Permit0FailureCode };
