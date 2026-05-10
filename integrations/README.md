# permit0 Integrations

Reusable, framework-native packages that integrate permit0 with specific agent frameworks. Each is a real package you can depend on — proper manifest, public API surface, unit tests, versioned release line — not a single-file copy-and-tweak demo.

## Packages

| Package | Framework | Language | Install | Pattern |
|---------|-----------|----------|---------|---------|
| [`permit0-openclaw/`](./permit0-openclaw/) | [OpenClaw](https://github.com/openclaw/openclaw) | TypeScript | `npm install @permit0/openclaw` | `permit0Middleware(...)` over the gateway dispatch (recommended); `permit0Skill(...)` HOF for advanced cases |

### CLI-hook integrations (no separate library; config + docs only)

These frameworks expose a tool-invocation hook of their own. permit0 plugs
in via the same `permit0 hook` CLI subcommand with a `--client` flag — no
library to publish, just a copy-paste config block.

| Folder | Framework | Hook config lives in |
|---|---|---|
| [`permit0-codex/`](./permit0-codex/) | [OpenAI Codex CLI](https://developers.openai.com/codex) | `~/.codex/config.toml` `[hooks]` or `~/.codex/hooks.json` |
| — (no folder yet) | [Claude Code](https://docs.claude.com/en/docs/claude-code/overview) | `~/.claude/settings.json` `PreToolUse` |

## The wrapper pattern in one sentence

Every integration follows the same three-step pattern, regardless of language:

1. **Intercept** — hook into the framework's tool-invocation path (decorator, base class, middleware, or proxy).
2. **Check** — call permit0 with the normalized tool name + parameters (in-process via SDK, or over HTTP to the daemon).
3. **Route** — on **Allow**, run the original tool; on **Deny**, short-circuit with a reason; on **Human**, route to an approval queue (or, in LLM-agent contexts, treat as Deny so the LLM can work around it).

What changes between integrations is *how* you hook in:

- **OpenClaw (TypeScript)** → compose `permit0Middleware(...)` over the gateway dispatch — OpenClaw routes every skill through that chain, so one composition gates all of them. The per-skill `permit0Skill(...)` HOF is the underlying primitive, available for advanced cases. See [`permit0-openclaw/`](./permit0-openclaw/).
- **OpenAI Codex CLI** → wire `permit0 hook --client codex` as a `PreToolUse` hook in `~/.codex/config.toml`; gates every Bash, `apply_patch`, and MCP tool call before Codex runs it. See [`permit0-codex/`](./permit0-codex/).
- **Claude Code (CLI)** → wire `permit0 hook` as a `PreToolUse` hook in `~/.claude/settings.json`; the hook adjudicates every built-in and MCP tool call before Claude Code runs it.
- **CrewAI** → subclass `crewai.tools.BaseTool` and override `_run`.
- **OpenAI Agents SDK** → wrap around the `@function_tool` decorator.
- **MCP** → sit as a JSON-RPC proxy in front of the upstream MCP server.

## Quick start

### TypeScript (OpenClaw)

```bash
# 1. Build and start the permit0 daemon (once per machine)
cargo build --release
./target/release/permit0 serve --ui --port 9090

# 2. Install the integration in your OpenClaw project
npm install @permit0/openclaw
```

```ts
import { permit0Skill, Permit0Client, isBlocked } from "@permit0/openclaw";
import { execSync } from "node:child_process";

const client = new Permit0Client();

const safeShell = permit0Skill(
  "Bash",
  client,
  async ({ command }: { command: string }) => execSync(command).toString(),
);

const ok = await safeShell({ command: "ls" });
const bad = await safeShell({ command: "sudo rm -rf /" });
console.log(isBlocked(bad) ? `BLOCKED: ${bad.reason}` : bad);
```

## Design notes

**In-process SDK vs HTTP daemon?**
Both are first-class:

- The Python bindings give sub-millisecond, in-process permission checks with no network hop. Best for single-process Python agents.
- The HTTP daemon (`permit0 serve --ui`) gives one policy engine for many processes / languages, plus the dashboard and audit replay. `permit0-openclaw` uses HTTP because OpenClaw is Node and the policy engine is Rust.

For multi-tenant or multi-process deployments, HTTP is the right answer regardless of language. For a single-process Python agent, in-process is faster and simpler.

**Why not just publish to PyPI / npm?**
We will. For now integrations are installed from this repo to make iteration on the core + integration simultaneous; the npm package ships from this same tree.

## Contributing a new integration

1. Pick a framework with clear tool-invocation semantics (decorator, class, hook, dispatch).
2. Scaffold `integrations/permit0-<framework>/` mirroring [`permit0-openclaw/`](./permit0-openclaw/) (TypeScript + HOF/middleware wrap).
3. Required surface:
   - Manifest (`pyproject.toml` or `package.json`) declaring permit0 + framework as deps.
   - Public API kept small (one decorator, one HOF, one class).
   - Tests covering Allow / Deny / Human / a framework-invocation smoke test.
   - `README.md` — install, one example in 10 lines, API ref.
   - Optional: runnable example agent (scripted, no API keys required).
4. Open a PR — `permit0-openclaw` is a good shape to match.

## Related docs

- [`../README.md`](../README.md) — what permit0 is
- [`../docs/taxonomy.md`](../docs/taxonomy.md) — the taxonomy of governed action types
