import { ulid } from "ulid";

import type { Permit0FailureCode } from "./errors.js";

/**
 * One buffered tool call that ran on the client during a daemon outage.
 * Mirrors the server-side `FailedOpenEvent` struct in
 * crates/permit0-cli/src/cmd/serve.rs — keep field names byte-identical
 * so the JSON body deserializes cleanly without serde aliases.
 */
export interface BufferedEvent {
  event_id: string;
  occurred_at: string;
  tool_name: string;
  parameters: unknown;
  metadata: Record<string, unknown>;
  fail_reason: string;
  fail_reason_code: Permit0FailureCode;
  outcome: "executed" | "skill_threw";
  client_version: string;
  fail_open_source: "env_var" | "config_flag";
}

/** Snapshot of the buffer state, returned by `status()`. */
export interface BufferStatus {
  count: number;
  dropped: number;
  capacity: number;
  windowStart: string | undefined;
  windowEnd: string | undefined;
  draining: boolean;
}

/** Outcome of a single drain attempt. */
export interface DrainResult {
  flushed: number;
  remaining: number;
  rejected: Array<{ event_id: string; error: string }>;
  /** Set when the post function itself threw (network down, etc.). */
  error?: Error;
}

/**
 * Function the buffer calls to actually deliver events. Lives on
 * `Permit0Client` so the buffer is decoupled from any specific transport.
 *
 * Returning a list of `event_ids` that the server accepted lets the
 * buffer drop exactly those — partial drains keep rejected events
 * around for the next attempt.
 */
export type DrainPoster = (
  events: BufferedEvent[],
  context: {
    client_window_start: string;
    client_window_end: string;
    dropped_count: number;
  },
) => Promise<{
  /** event_ids the server wrote to the audit log. */
  acceptedIds: Set<string>;
  /** event_ids the server rejected (will be retried). */
  rejected: Array<{ event_id: string; error: string }>;
}>;

const DEFAULT_CAPACITY = 10_000;

/**
 * In-memory ring buffer of failed-open events with single-flight drain.
 *
 * Cap defaults to 10,000 (~10 MB worst case for typical tool params).
 * On overflow the oldest event is dropped and `dropped` is incremented;
 * the dashboard banner surfaces the dropped count so auditors know the
 * window may be incomplete.
 *
 * v1 limitations called out in the failed-open design:
 *   - In-memory only. A Node process restart loses the unflushed window.
 *     v2 may add disk-backed persistence; for now the daemon's audit
 *     summary marks restart-truncated windows as incomplete.
 *   - No idempotency dedup on the server side. Each event has a ULID
 *     event_id; the daemon writes them as-is. Auditors can dedupe at
 *     query time. Single-flight drain on the client side prevents
 *     concurrent batch posts within a single process.
 */
export class FailOpenBuffer {
  private events: BufferedEvent[] = [];
  private dropped = 0;
  private windowStart: string | undefined;
  private windowEnd: string | undefined;
  private draining = false;
  private readonly capacity: number;

  constructor(capacity: number = DEFAULT_CAPACITY) {
    if (capacity <= 0) {
      throw new RangeError(`FailOpenBuffer capacity must be > 0, got ${capacity}`);
    }
    this.capacity = capacity;
  }

  /**
   * Enqueue an event. Caller supplies everything except `event_id` and
   * `occurred_at`, which the buffer fills. Returns the event_id so the
   * caller can correlate (e.g. for log lines).
   */
  enqueue(
    event: Omit<BufferedEvent, "event_id" | "occurred_at"> & {
      event_id?: string;
      occurred_at?: string;
    },
  ): string {
    const event_id = event.event_id ?? ulid();
    const occurred_at = event.occurred_at ?? new Date().toISOString();

    const stored: BufferedEvent = {
      event_id,
      occurred_at,
      tool_name: event.tool_name,
      parameters: event.parameters,
      metadata: event.metadata,
      fail_reason: event.fail_reason,
      fail_reason_code: event.fail_reason_code,
      outcome: event.outcome,
      client_version: event.client_version,
      fail_open_source: event.fail_open_source,
    };

    if (this.events.length >= this.capacity) {
      this.events.shift();
      this.dropped += 1;
    }
    this.events.push(stored);

    if (this.windowStart === undefined) this.windowStart = occurred_at;
    this.windowEnd = occurred_at;

    return event_id;
  }

  status(): BufferStatus {
    return {
      count: this.events.length,
      dropped: this.dropped,
      capacity: this.capacity,
      windowStart: this.windowStart,
      windowEnd: this.windowEnd,
      draining: this.draining,
    };
  }

  isEmpty(): boolean {
    return this.events.length === 0;
  }

  /** Number of events currently buffered (for tests / status reporters). */
  size(): number {
    return this.events.length;
  }

  /**
   * Atomically attempt to flush all buffered events to the supplied
   * poster. Single-flight: if a drain is already running, returns a
   * "skipped" result without taking action.
   *
   * Behavior matrix:
   *   - Poster succeeds, all events accepted → buffer cleared, window reset.
   *   - Poster succeeds, partial accept → only accepted events removed;
   *     rejected events remain for the next drain.
   *   - Poster throws → no events removed, error returned, lock released.
   *
   * dropped_count is reported once per drain attempt; on success it
   * resets so we don't double-count across drains.
   */
  async drain(post: DrainPoster): Promise<DrainResult> {
    if (this.draining) {
      return {
        flushed: 0,
        remaining: this.events.length,
        rejected: [],
      };
    }
    if (this.events.length === 0) {
      return { flushed: 0, remaining: 0, rejected: [] };
    }

    this.draining = true;

    // Snapshot what we're about to send. If new events arrive during
    // the post, they'll be in this.events but not in `snapshot`.
    const snapshot = this.events.slice();
    const droppedThisDrain = this.dropped;
    const winStart = this.windowStart ?? snapshot[0]!.occurred_at;
    const winEnd = this.windowEnd ?? snapshot[snapshot.length - 1]!.occurred_at;

    try {
      const result = await post(snapshot, {
        client_window_start: winStart,
        client_window_end: winEnd,
        dropped_count: droppedThisDrain,
      });

      // Remove accepted events by event_id.
      const accepted = result.acceptedIds;
      this.events = this.events.filter((e) => !accepted.has(e.event_id));

      // Only zero `dropped` after success — if poster fails we don't
      // want to lose track of past overflows.
      this.dropped -= droppedThisDrain;
      if (this.dropped < 0) this.dropped = 0;

      // Window markers: if buffer empty, reset; otherwise keep as-is so
      // the next drain still reports the encompassing window.
      if (this.events.length === 0) {
        this.windowStart = undefined;
        this.windowEnd = undefined;
      }

      return {
        flushed: snapshot.length - result.rejected.length,
        remaining: this.events.length,
        rejected: result.rejected,
      };
    } catch (err) {
      return {
        flushed: 0,
        remaining: this.events.length,
        rejected: [],
        error: err instanceof Error ? err : new Error(String(err)),
      };
    } finally {
      this.draining = false;
    }
  }

  /** Wipe all state. Tests and `Permit0Client.close()`. */
  clear(): void {
    this.events = [];
    this.dropped = 0;
    this.windowStart = undefined;
    this.windowEnd = undefined;
    this.draining = false;
  }
}
