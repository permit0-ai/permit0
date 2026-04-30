import { describe, expect, it, vi } from "vitest";

import { FailOpenBuffer, type BufferedEvent } from "../src/FailOpenBuffer.js";

function partialEvent(
  overrides: Partial<BufferedEvent> = {},
): Omit<BufferedEvent, "event_id" | "occurred_at"> & {
  event_id?: string;
  occurred_at?: string;
} {
  return {
    tool_name: "Bash",
    parameters: { command: "ls" },
    metadata: {},
    fail_reason: "ECONNREFUSED",
    fail_reason_code: "refused",
    outcome: "executed",
    client_version: "0.1.0",
    fail_open_source: "env_var",
    ...overrides,
  };
}

describe("FailOpenBuffer.enqueue", () => {
  it("auto-fills event_id (ULID-shaped) and occurred_at", () => {
    const buf = new FailOpenBuffer();
    const id = buf.enqueue(partialEvent());
    // ULID is 26 chars Crockford base32.
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(buf.size()).toBe(1);
    const status = buf.status();
    expect(status.windowStart).toBeDefined();
    expect(status.windowEnd).toBeDefined();
  });

  it("preserves caller-supplied event_id and occurred_at", () => {
    const buf = new FailOpenBuffer();
    const id = buf.enqueue(
      partialEvent({
        event_id: "01JX-CUSTOM",
        occurred_at: "2026-04-30T10:00:00Z",
      }),
    );
    expect(id).toBe("01JX-CUSTOM");
    expect(buf.status().windowStart).toBe("2026-04-30T10:00:00Z");
    expect(buf.status().windowEnd).toBe("2026-04-30T10:00:00Z");
  });

  it("tracks window from first to last enqueue", () => {
    const buf = new FailOpenBuffer();
    buf.enqueue(partialEvent({ occurred_at: "2026-04-30T10:00:00Z" }));
    buf.enqueue(partialEvent({ occurred_at: "2026-04-30T10:01:00Z" }));
    buf.enqueue(partialEvent({ occurred_at: "2026-04-30T10:02:00Z" }));
    expect(buf.status().windowStart).toBe("2026-04-30T10:00:00Z");
    expect(buf.status().windowEnd).toBe("2026-04-30T10:02:00Z");
  });

  it("drops oldest on overflow and increments dropped counter", () => {
    const buf = new FailOpenBuffer(3);
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));
    buf.enqueue(partialEvent({ event_id: "c" }));
    buf.enqueue(partialEvent({ event_id: "d" }));
    buf.enqueue(partialEvent({ event_id: "e" }));
    expect(buf.size()).toBe(3);
    expect(buf.status().dropped).toBe(2);
  });

  it("rejects non-positive capacity at construction", () => {
    expect(() => new FailOpenBuffer(0)).toThrow(RangeError);
    expect(() => new FailOpenBuffer(-1)).toThrow(RangeError);
  });
});

describe("FailOpenBuffer.drain", () => {
  it("happy path: all accepted, buffer cleared, dropped reset", async () => {
    const buf = new FailOpenBuffer();
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));
    buf.enqueue(partialEvent({ event_id: "c" }));

    const result = await buf.drain(async (events, ctx) => {
      expect(events.length).toBe(3);
      expect(ctx.client_window_start).toBeDefined();
      expect(ctx.client_window_end).toBeDefined();
      expect(ctx.dropped_count).toBe(0);
      return {
        acceptedIds: new Set(["a", "b", "c"]),
        rejected: [],
      };
    });

    expect(result.flushed).toBe(3);
    expect(result.remaining).toBe(0);
    expect(result.rejected).toEqual([]);
    expect(result.error).toBeUndefined();
    expect(buf.size()).toBe(0);
    expect(buf.status().windowStart).toBeUndefined();
  });

  it("partial reject: keeps rejected events, removes accepted only", async () => {
    const buf = new FailOpenBuffer();
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));
    buf.enqueue(partialEvent({ event_id: "c" }));

    const result = await buf.drain(async (_events) => ({
      acceptedIds: new Set(["a", "c"]),
      rejected: [{ event_id: "b", error: "shape mismatch" }],
    }));

    expect(result.flushed).toBe(2);
    expect(result.remaining).toBe(1);
    expect(result.rejected).toEqual([
      { event_id: "b", error: "shape mismatch" },
    ]);
    expect(buf.size()).toBe(1);
  });

  it("preserves dropped count when poster throws (does not double-count)", async () => {
    const buf = new FailOpenBuffer(2);
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));
    buf.enqueue(partialEvent({ event_id: "c" })); // overflow → dropped=1

    expect(buf.status().dropped).toBe(1);

    const result = await buf.drain(async () => {
      throw new Error("network down");
    });

    expect(result.flushed).toBe(0);
    expect(result.remaining).toBe(2);
    expect(result.error?.message).toBe("network down");
    // Drop count stays — next drain attempt will report it.
    expect(buf.status().dropped).toBe(1);
  });

  it("clears dropped count on successful drain", async () => {
    const buf = new FailOpenBuffer(2);
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));
    buf.enqueue(partialEvent({ event_id: "c" })); // overflow

    expect(buf.status().dropped).toBe(1);

    await buf.drain(async (events) => ({
      acceptedIds: new Set(events.map((e) => e.event_id)),
      rejected: [],
    }));

    expect(buf.status().dropped).toBe(0);
  });

  it("single-flight: second drain returns immediately while first runs", async () => {
    const buf = new FailOpenBuffer();
    buf.enqueue(partialEvent({ event_id: "a" }));

    let resolveFirst!: () => void;
    const firstPromise = buf.drain(async (events) => {
      await new Promise<void>((r) => {
        resolveFirst = r;
      });
      return {
        acceptedIds: new Set(events.map((e) => e.event_id)),
        rejected: [],
      };
    });

    // Second drain while first is mid-flight: skipped, returns 0/0.
    const secondPromise = buf.drain(async () => {
      throw new Error("should not be called");
    });
    const second = await secondPromise;
    expect(second.flushed).toBe(0);
    expect(second.rejected).toEqual([]);

    // Now finish the first drain.
    resolveFirst();
    const first = await firstPromise;
    expect(first.flushed).toBe(1);
    expect(buf.size()).toBe(0);
  });

  it("drain on empty buffer is a no-op", async () => {
    const buf = new FailOpenBuffer();
    const post = vi.fn();
    const result = await buf.drain(post);
    expect(post).not.toHaveBeenCalled();
    expect(result.flushed).toBe(0);
    expect(result.remaining).toBe(0);
  });

  it("releases drain lock even when poster throws", async () => {
    const buf = new FailOpenBuffer();
    buf.enqueue(partialEvent({ event_id: "a" }));

    await buf.drain(async () => {
      throw new Error("first attempt failed");
    });

    expect(buf.status().draining).toBe(false);

    // A subsequent drain should be allowed (lock released).
    const result = await buf.drain(async (events) => ({
      acceptedIds: new Set(events.map((e) => e.event_id)),
      rejected: [],
    }));
    expect(result.flushed).toBe(1);
  });

  it("events arriving during drain are not lost (snapshot semantics)", async () => {
    const buf = new FailOpenBuffer();
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));

    let resolveDrain!: () => void;
    const drainPromise = buf.drain(async (events) => {
      // Mid-drain, a new event arrives.
      buf.enqueue(partialEvent({ event_id: "c" }));
      await new Promise<void>((r) => {
        resolveDrain = r;
      });
      return {
        acceptedIds: new Set(events.map((e) => e.event_id)),
        rejected: [],
      };
    });

    resolveDrain();
    const result = await drainPromise;
    expect(result.flushed).toBe(2); // a + b
    // c is still buffered — it arrived during the drain, was not part of snapshot.
    expect(buf.size()).toBe(1);
  });
});

describe("FailOpenBuffer.clear", () => {
  it("wipes events, dropped, window, and lock", () => {
    const buf = new FailOpenBuffer(2);
    buf.enqueue(partialEvent({ event_id: "a" }));
    buf.enqueue(partialEvent({ event_id: "b" }));
    buf.enqueue(partialEvent({ event_id: "c" })); // overflow
    buf.clear();
    const s = buf.status();
    expect(s.count).toBe(0);
    expect(s.dropped).toBe(0);
    expect(s.windowStart).toBeUndefined();
    expect(s.windowEnd).toBeUndefined();
    expect(s.draining).toBe(false);
  });
});
