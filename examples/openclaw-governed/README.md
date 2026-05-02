# OpenClaw + permit0 — single-file demo

A self-contained TypeScript file demonstrating how to wrap [OpenClaw](https://github.com/openclaw/openclaw) skills with a [permit0](https://github.com/permit0-ai/permit0) policy check.

Read this if you want to see the wrapper pattern in one place. **For production use, the same surface plus a failed-open replay buffer ships as a published package** — see [`integrations/permit0-openclaw/`](../../integrations/permit0-openclaw/).

## How to run

1. **Start the permit0 server** from the repo root:

   ```bash
   cargo run -p permit0-cli -- serve --port 9090
   ```

2. **Install deps:**

   ```bash
   cd examples/openclaw-governed
   npm install
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

The demo prints a labeled run of benign and dangerous tool invocations and the verdict permit0 returns for each. Exact scores and reasons depend on the loaded policy pack.

## What this demo is, and isn't

This file is a **teaching artifact**: one HOF wrapper, one client class, a few mock skills, and a scripted run. It's intentionally small so you can read the entire wrapper pattern in one sitting.

For shipping to production, use [`@permit0/openclaw`](../../integrations/permit0-openclaw/) instead. That package adds, on top of what's shown here:

- Gateway middleware (one-line uniform coverage in addition to the per-skill HOF)
- Failed-open replay buffer + idle reconnect poller (closes the audit gap when the daemon is down)
- Runtime shape validation on `/check` responses
- Pluggable logger (no `console.log` in package code)
- Retries, timeouts, keep-alive, graceful shutdown

## Files

- `index.ts` — `Permit0Client`, `permit0Skill()` wrapper, mock skills, and a scripted demo.
- `package.json` — single dev dependency (`tsx`).
