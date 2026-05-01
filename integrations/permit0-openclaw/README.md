# @permit0/openclaw

**One line of code to put a deterministic policy gate in front of every OpenClaw skill.**

```ts
import { permit0Skill, Permit0Client, isBlocked } from "@permit0/openclaw";
import { execSync } from "node:child_process";

const client = new Permit0Client();

const safeShell = permit0Skill(
  "Bash",
  client,
  async ({ command }: { command: string }) => execSync(command).toString(),
);

const result = await safeShell({ command: "ls /tmp" });
if (isBlocked(result)) {
  // result.reason — string the LLM should see
  // result.decision.tier / .score — for your logger
} else {
  // result is the inner skill's return value, untouched
}
```

Every call to `safeShell` first hits the local permit0 daemon. Allow → the inner skill runs. Deny / human-in-the-loop → the inner skill is short-circuited and you get a structured `Blocked` value back.

## What is OpenClaw

[OpenClaw](https://github.com/openclaw/openclaw) is a TypeScript agent gateway. Capabilities are exposed as **skills** — plain `async (args) => result` functions registered into the gateway's dispatch table. The gateway hands tool calls from the LLM to those skills.

This package wraps any OpenClaw skill so policy adjudication happens *before* side effects. You don't fork OpenClaw, change its types, or run anything in-process — everything goes over HTTP to a local permit0 daemon.

## What you get

Before each call, permit0 normalizes the tool invocation into a `NormAction`, scores it against the active pack's risk rules, and returns one of three verdicts. What happens next depends on the integration shape and (for middleware) the `onBlock` setting:

| permit0 verdict | `permit0Skill` (HOF) | `permit0Middleware` default | `permit0Middleware` `{ onBlock: "return" }` |
|---|---|---|---|
| ✅ allow | inner skill runs, result returned | inner dispatch runs, result returned | inner dispatch runs, result returned |
| ❌ deny | returns `Blocked` sentinel | throws `Permit0DenyError` | returns `Blocked` sentinel |
| 🟡 human | returns `Blocked` sentinel | throws `Permit0DenyError` | returns `Blocked` sentinel |

What surfaces to your gateway / LLM:

- **HOF / `onBlock: "return"`** — `result.reason` is the LLM-facing string (e.g. `policy: destructive-root-removal`). `result.decision.tier` and `result.decision.score` are available for your logger.
- **Middleware throw (default)** — `Permit0DenyError`. `error.message` is the same reason string. `error.toString()` adds tier/score:

  ```
  Permit0DenyError — Bash — policy: destructive-root-removal (tier=CRITICAL score=100)
  ```

  `error.decision` carries the full payload.

## Why this package exists — the audit gap

You can write a 30-line wrapper that POSTs to `/api/v1/check` yourself. The reason this package is what it is comes down to one specific class of audit gap:

> Operator sets `PERMIT0_FAIL_OPEN=1`. Daemon goes down. OpenClaw runs N tool calls. The dashboard shows nothing. Compliance review can't see what happened.

End-to-end, what this package does to close that gap:

```
@permit0/openclaw                       permit0 daemon
─────────────────────                  ─────────────────────
check() fails              ──────►
fail-open active                       (down)
event → FailOpenBuffer
inner skill runs anyway

   ... daemon comes back ...

check() succeeds           ──────►     200 OK with Decision
buffer non-empty
  → fire-and-forget drain
  POST /audit/replay       ──────►     for each event:
                                         retro-score current pack
                                         AuditEntry {
                                           decision_source: "failed_open"
                                           decision: Allow (it ran)
                                           retroactive_decision: Allow|Deny|Human
                                           failed_open_context: {window, reason}
                                         }
                                       chained, ed25519-signed
                           ◄──────     { accepted: N, rejected: [...] }

                                       GET /audit/failed_open_windows
                                       (operator opens dashboard)
                                       → banner: "N events during
                                          10:00–10:05. M would have
                                          been blocked under current
                                          policy."
```

Without this package: silent gap during outages. With it: every call buffered, replayed, retro-scored, and surfaced on the dashboard.

## Install

You need two things running: the permit0 daemon (HTTP server on `:9090`) and your OpenClaw process with this package.

**1. Build and run the daemon** (once per machine):

```bash
git clone https://github.com/AnissL93/permit0-core
cd permit0-core
cargo build --release
./target/release/permit0 serve --ui --port 9090
```

**2. Add the package** to your OpenClaw project:

```bash
npm install @permit0/openclaw
```

**3. Verify the daemon is reachable:**

```ts
import { Permit0Client } from "@permit0/openclaw";

const client = new Permit0Client();
console.log(await client.health()); // → true
await client.close();
```

If `health()` returns `false`, the daemon isn't listening on the configured `baseUrl` (default `http://localhost:9090`).

For local development against this repo, point your project at the workspace copy:

```json
{
  "dependencies": {
    "@permit0/openclaw": "file:../../integrations/permit0-openclaw"
  }
}
```

## Two integration shapes

Pick one. They're not mutually exclusive but you usually want one or the other.

### (a) Per-skill HOF — explicit, opt-in

Wrap each skill at registration time. Best when you want different gating for different skills, or when you want to roll out gradually.

```ts
import { permit0Skill, Permit0Client, isBlocked } from "@permit0/openclaw";
import { execSync } from "node:child_process";

const client = new Permit0Client();

const safeShell = permit0Skill(
  "Bash",
  client,
  async ({ command }: { command: string }) => execSync(command).toString(),
);

gateway.register("Bash", safeShell);
```

Threading session/task context for the audit trail (per call):

```ts
const result = await safeShell(
  { command: "ls /tmp" },
  { ctx: { session_id: "agent-run-7f3a", task_goal: "list temp files" } },
);
```

### (b) Gateway middleware — uniform coverage

Compose permit0 in front of the gateway's dispatch function. One change, every skill is gated.

```ts
import { permit0Middleware, Permit0Client } from "@permit0/openclaw";

const client = new Permit0Client();
gateway.dispatch = permit0Middleware(client, gateway.dispatch);
```

The middleware reads `session_id` and `task_goal` off the gateway's per-call `ctx` automatically. If your gateway already passes a context object through `dispatch(toolName, args, ctx)`, those fields land on the audit entry without any extra work.

Switch the deny behavior if your gateway prefers value-returns over exceptions:

```ts
gateway.dispatch = permit0Middleware(client, gateway.dispatch, { onBlock: "return" });
```

### When to pick which

- **HOF** if you're rolling out gradually, want different gating per skill, or your gateway doesn't have a clean middleware seam.
- **Middleware** if you want one place to enforce policy and you want to forget about it. This is the production default.

## API reference

### `Permit0Client`

```ts
const client = new Permit0Client({
  baseUrl: "http://localhost:9090",   // default
  timeoutMs: 1000,                    // per-attempt timeout
  maxRetries: 1,                      // 1 retry on 5xx / timeout / refused
  retryBackoffMs: 50,
  failOpen: "env",                    // "env" reads PERMIT0_FAIL_OPEN; true | false override
  drainPollMs: 30_000,                // idle reconnect poller; 0 disables
  bufferCapacity: 10_000,             // failed-open ring buffer
  logger: NOOP_LOGGER,                // pluggable; default is silent
});
```

| method | when to call |
|---|---|
| `check(toolName, args, ctx?)` | Manually adjudicate one call. The HOF/middleware do this for you. |
| `health()` | Liveness probe at startup or on a hot path. Uses `GET /api/v1/health` (no audit pollution, unlike a dummy `/check`). |
| `failedOpenBufferStatus()` | Snapshot of the ring buffer (count, dropped, window bounds, draining). For ops dashboards. |
| `drainFailedOpenBuffer()` | Force a replay POST now. Use during graceful shutdown. |
| `close()` | Idempotent. Releases the connection pool and cancels the idle poller. **Drops any unflushed buffered events** — call `drainFailedOpenBuffer()` first if you care. |

Required for clean process exit: when the client created its own HTTP dispatcher (the default), the keep-alive Agent and idle poller hold the Node event loop open. Always `await client.close()` on shutdown.

### `permit0Skill(toolName, client, skill)`

Higher-order wrap. Same args/return shape as your skill, plus a `Blocked` branch:

```ts
function permit0Skill<Args, Result>(
  toolName: string,
  client: Permit0Client,
  skill: (args: Args) => Promise<Result>,
): (args: Args, opts?: { ctx?: CheckContext }) => Promise<Result | Blocked>;
```

- Returns the inner skill's value verbatim on allow (or fail-open synthetic-allow).
- Returns `Blocked = { blocked: true, reason, decision }` on deny / human.
- Throws `Permit0Error` only on fail-closed transport failure.
- Rethrows the inner skill's exception verbatim — permit0 never wraps user errors.

### `permit0Middleware(client, next, options?)`

Compose into the gateway's dispatch chain.

```ts
function permit0Middleware(
  client: Permit0Client,
  next: GatewayDispatch,
  options?: { onBlock?: "throw" | "return" },
): GatewayDispatch;

type GatewayDispatch = (
  toolName: string,
  args: unknown,
  ctx?: { session_id?: string; task_goal?: string; extra?: Record<string, unknown> },
) => Promise<unknown>;
```

- `onBlock: "throw"` (default) — raises `Permit0DenyError` on deny / human.
- `onBlock: "return"` — returns a `Blocked` sentinel as the dispatch result.

### `Decision`

What permit0's `/check` endpoint returns. Mirrors the Rust daemon's `CheckResponse`:

```ts
interface Decision {
  permission: "allow" | "deny" | "human";
  action_type: string;
  channel: string;
  norm_hash: string;
  source: string;          // "engine" | "denylist" | "failed_open" | …
  score?: number;
  tier?: "MINIMAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  blocked?: boolean;
  block_reason?: string;
}
```

`source: "failed_open"` is the canonical signal that the synthetic-allow path fired (and the call was buffered for replay).

### `Blocked`

```ts
interface Blocked {
  blocked: true;
  reason: string;     // string the LLM should see
  decision: Decision; // full payload for logging / audit
}

function isBlocked(value: unknown): value is Blocked;
```

## Failure modes

### Daemon unreachable — fail-closed (default)

`Permit0Client.check()` throws `Permit0Error` after `1 + maxRetries` attempts. The HOF and middleware both surface this as a thrown error. No call runs without policy review.

### Daemon unreachable — fail-open + replay

Set `PERMIT0_FAIL_OPEN=1` (or pass `failOpen: true`) to switch to fail-open:

1. The transport failure is caught.
2. The event is buffered in an in-memory ring (default capacity 10,000, oldest dropped on overflow).
3. `check()` returns a synthetic allow Decision tagged `source: "failed_open"` so the inner skill runs.
4. On the next successful `check()`, the buffer drains to `POST /api/v1/audit/replay` in the background.
5. While the buffer is non-empty *and* there's no live traffic, an **idle reconnect poller** retries delivery every `drainPollMs` (default 30s; set to `0` to disable). The poller is `unref()`'d so it never keeps the Node event loop alive on its own.
6. The daemon retro-scores each event with the current pack and writes one audit entry per event with `decision_source: "failed_open"` and `retroactive_decision: <what current policy would say>`.
7. The dashboard banner surfaces "N events during 10:00–10:05. M would have been blocked under current policy" so an operator can review.

Inspect the buffer at any time:

```ts
const status = client.failedOpenBufferStatus();
// { count, dropped, capacity, windowStart, windowEnd, draining }
```

Force a drain (graceful shutdown):

```ts
const drain = await client.drainFailedOpenBuffer();
// { flushed, remaining, rejected: [{event_id, error}], error?: Error }
```

**v1 limits worth knowing:**

- The buffer is in-memory only. A Node restart drops the unflushed window.
- No server-side dedup. Each event has a ULID; if a partial replay batch is retried, the daemon may write duplicates. Auditors can dedupe by `event_id` (visible under `raw_tool_call.metadata.event_id`).

### Inner skill throws

The HOF rethrows the inner skill's exception verbatim. The middleware does the same on the dispatch path. permit0 never wraps user-thrown errors.

### Malformed daemon response

`Permit0Client` validates required and optional field types on every `/check` response. A daemon-side schema drift surfaces as `Permit0Error{ code: "malformed_response" }` rather than corrupting downstream code with mistyped fields.

## Development

```bash
cd integrations/permit0-openclaw
npm install
npm run build       # tsc to dist/
npm test            # vitest run (unit + fixture, mocked transport)
npm run typecheck   # tsc --noEmit
```

Integration tests run against a live daemon and are excluded from the default `npm test`. Spin up the daemon and run:

```bash
cargo run -p permit0-cli -- serve --port 9090   # in one terminal
npm run test:integration                         # in another
```

## Related

- [`docs/dsl.md`](../../docs/dsl.md) — pack and risk-rule authoring (what determines allow/deny/human).
- [`docs/permit.md`](../../docs/permit.md) — the audit log format.
- [`integrations/README.md`](../README.md) — index of all framework integrations.
- [`examples/openclaw-governed/`](../../examples/openclaw-governed/) — a single-file demo if you want to read the wrapper pattern in <100 lines.

## Appendix: migrating from `examples/openclaw-governed`

If you have code importing from the demo file:

```ts
// Before
import { Permit0Client, permit0Skill, isBlocked } from "openclaw-permit0-demo";
// After
import { Permit0Client, permit0Skill, isBlocked } from "@permit0/openclaw";
```

The HOF signature is unchanged. New behavior available in this package:

| Demo file | This package |
|---|---|
| `permit0Skill(name, client, fn)` | same, plus optional `(args, { ctx }) => …` per-call context |
| no middleware | `permit0Middleware(client, dispatch)` for gateway-wide enforcement |
| no fail-open buffer | `PERMIT0_FAIL_OPEN=1` activates the replay path |
| `client.health()` POSTs `/check` | `client.health()` GETs `/health` (no audit pollution) |
| `console.log` everywhere | pluggable `logger`, no-op default |
| no retries | 1s timeout + 1 retry + keep-alive |
| no type validation | runtime shape check on every `/check` response |

## License

Apache-2.0 — same as the rest of the workspace.
