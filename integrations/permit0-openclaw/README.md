# @permit0/openclaw

**Policy-gate every OpenClaw skill through permit0 with a single line of code.**

Two integration shapes, same package:

```ts
import { permit0Skill, permit0Middleware, Permit0Client } from "@permit0/openclaw";

const client = new Permit0Client();

// (a) Wrap one skill at a time — explicit, opt-in.
gateway.register("Bash", permit0Skill("Bash", client, async ({ command }) => {
  return execSync(command).toString();
}));

// (b) Or insert one middleware in front of the gateway dispatch — uniform coverage.
gateway.dispatch = permit0Middleware(client, gateway.dispatch);
```

Either way, every tool call goes through permit0's deterministic policy engine first. Allow → the skill runs. Deny / human-in-the-loop → the skill is short-circuited and the gateway tells the LLM why.

## What you get

Before each call, permit0 normalizes the tool invocation into a `NormAction`, applies the pack's risk rules, and returns one of three outcomes:

| permit0 verdict | HOF behavior | Middleware behavior (default) |
|---|---|---|
| ✅ allow | inner skill runs, result returned | inner dispatch runs, result returned |
| ❌ deny | returns `Blocked` sentinel | throws `Permit0DenyError` |
| 🟡 human | returns `Blocked` sentinel | throws `Permit0DenyError` |

Switch the middleware's deny behavior with `permit0Middleware(client, dispatch, { onBlock: "return" })` if your gateway prefers value-returns over exception-driven control flow.

## Install

```bash
# Daemon (any platform with Rust toolchain)
cd permit0-core
cargo build --release
./target/release/permit0 serve --ui --port 9090

# Package
npm install @permit0/openclaw
```

For local development against this repo, point the demo at the workspace copy:

```json
{
  "dependencies": {
    "@permit0/openclaw": "file:../../integrations/permit0-openclaw"
  }
}
```

## Quick reference

### `Permit0Client`

```ts
const client = new Permit0Client({
  baseUrl: "http://localhost:9090",   // default
  timeoutMs: 1000,                    // per-attempt timeout
  maxRetries: 1,                      // 1 retry on 5xx / timeout / refused
  retryBackoffMs: 50,
  failOpen: "env",                    // "env" reads PERMIT0_FAIL_OPEN; true | false override
  drainPollMs: 30_000,                // idle reconnect poll for the failed-open buffer; 0 disables
  bufferCapacity: 10_000,             // failed-open ring buffer
  logger: NOOP_LOGGER,                // pluggable; default is silent
});
```

Methods: `check()`, `health()`, `failedOpenBufferStatus()`, `drainFailedOpenBuffer()`, `close()`.

### `permit0Skill(toolName, client, skill)`

Higher-order wrap. Same args/return shape as your skill, plus the deny/human branch returns a `Blocked` value:

```ts
const result = await safeShell({ command: "ls" });
if (isBlocked(result)) {
  // result.reason — string the LLM should see
  // result.decision — full Decision payload
} else {
  // result is the inner skill's return value, untouched
}
```

### `permit0Middleware(client, next, options?)`

Compose into the gateway's dispatch chain. Returns a wrapper with the same `(toolName, args, ctx?) => Promise<unknown>` shape. Threads `ctx.session_id` and `ctx.task_goal` into permit0's audit metadata.

## Failure modes

### Daemon unreachable

Default behavior is **fail-closed** — `Permit0Client.check()` throws `Permit0Error` after `1 + maxRetries` attempts. The HOF surfaces this as a thrown error; the middleware re-throws.

Set `PERMIT0_FAIL_OPEN=1` (or pass `failOpen: true`) to enable the **fail-open + replay** path:

1. The transport failure is caught.
2. The event is buffered in an in-memory ring (default capacity 10,000, oldest dropped on overflow).
3. `check()` returns a synthetic Decision tagged `source: "failed_open"` so the inner skill runs anyway.
4. On the next successful `check()`, the buffer is drained to `POST /api/v1/audit/replay` in the background.
5. The daemon retro-scores each event with the current pack, writes one audit entry per event with `decision_source: "failed_open"` and `retroactive_decision: <what current policy would say>`.
6. The dashboard banner surfaces "N events during 10:00–10:05. M would have been blocked under current policy" so an operator can review.

You can inspect the buffer state any time:

```ts
const status = client.failedOpenBufferStatus();
// { count, dropped, capacity, windowStart, windowEnd, draining }
```

Force a drain (useful for graceful shutdown):

```ts
const drain = await client.drainFailedOpenBuffer();
// { flushed, remaining, rejected: [{event_id, error}], error?: Error }
```

**v1 limits**:
- Buffer is in-memory only — a Node restart drops the unflushed window.
- No server-side dedup. Each event has a ULID; if a partial replay batch is retried, the daemon may write duplicates. Auditors can dedupe by `event_id` (visible under `raw_tool_call.metadata.event_id`).

### Inner skill throws

The HOF rethrows the inner skill's exception verbatim — permit0 doesn't wrap user-thrown errors. The middleware does the same on the dispatch path.

### Malformed daemon response

`Permit0Client.assertDecisionShape` validates the `/check` JSON shape (required + optional field types). A drift in the daemon's response shape surfaces as `Permit0Error{code: "malformed_response"}` rather than silent garbage in downstream code.

## Audit gap closure

Most of the work in this package exists to close one specific class of audit gap:

> Operator sets `PERMIT0_FAIL_OPEN=1`. Daemon goes down. OpenClaw runs N tool calls. The dashboard shows nothing. Compliance review can't see what happened.

End-to-end flow:

```
@permit0/openclaw                       permit0 daemon
─────────────────────                  ─────────────────────
check() fails              ──────►
fail-open active                       (down)
event → FailOpenBuffer

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

## Migrating from the demo file

If your code currently imports from `examples/openclaw-governed/index.ts`:

```ts
// Before
import { Permit0Client, permit0Skill, isBlocked } from "openclaw-permit0-demo";

// After
import { Permit0Client, permit0Skill, isBlocked } from "@permit0/openclaw";
```

The HOF signature is unchanged. Optional new behavior you can opt into:

| Demo file | This package |
|---|---|
| `permit0Skill(name, client, fn)` | same — plus an optional `(args, { ctx }) => …` second arg for session/task threading |
| no middleware | new `permit0Middleware(client, dispatch)` for gateway-wide enforcement |
| no fail-open buffer | `PERMIT0_FAIL_OPEN=1` activates the replay path |
| `client.health()` POSTs `/api/v1/check` | `client.health()` GETs `/api/v1/health` (no audit pollution) |
| `console.log` everywhere | pluggable `logger`, no-op default |
| no retries | 1s timeout + 1 retry + keep-alive |
| no type validation | runtime shape check on `/check` responses |

## Development

```bash
cd integrations/permit0-openclaw
npm install
npm run build       # tsc to dist/
npm test            # vitest run (unit + fixture, mocked transport)
npm run typecheck   # tsc --noEmit
```

Integration tests against a live daemon live under `__tests__/integration/` and are excluded from the default `npm test` run; spin up the daemon (`cargo run -p permit0-cli -- serve --port 9090`) and run `npm run test:integration` to exercise them.

## License

Apache-2.0 — same as the rest of the workspace.
