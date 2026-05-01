# permit0 Integrations

Reusable, framework-native packages that integrate permit0 with specific agent frameworks. Each is a real package you can depend on — proper manifest, public API surface, unit tests, versioned release line — not a single-file copy-and-tweak demo.

(Demos live one level up under [`examples/`](../examples/) — that's where to look if you want to read a pattern in <100 lines or copy it into your own project.)

## Packages

| Package | Framework | Language | Install | Pattern |
|---------|-----------|----------|---------|---------|
| [`permit0-langgraph/`](./permit0-langgraph/) | [LangGraph](https://langchain-ai.github.io/langgraph/) + [LangChain](https://python.langchain.com/) | Python | `pip install -e integrations/permit0-langgraph` | `@permit0_tool(...)` decorator returns a `StructuredTool` LangGraph consumes natively |
| [`permit0-openclaw/`](./permit0-openclaw/) | [OpenClaw](https://github.com/openclaw/openclaw) | TypeScript | `npm install @permit0/openclaw` | `permit0Skill(...)` HOF or `permit0Middleware(...)` over the gateway dispatch |

## The wrapper pattern in one sentence

Every integration follows the same three-step pattern, regardless of language:

1. **Intercept** — hook into the framework's tool-invocation path (decorator, base class, middleware, or proxy).
2. **Check** — call permit0 with the normalized tool name + parameters (in-process via SDK, or over HTTP to the daemon).
3. **Route** — on **Allow**, run the original tool; on **Deny**, short-circuit with a reason; on **Human**, route to an approval queue (or, in LLM-agent contexts, treat as Deny so the LLM can work around it).

What changes between integrations is *how* you hook in:

- **LangGraph / LangChain (Python)** → wrap with `@tool` after the permit0 check. See [`permit0-langgraph/`](./permit0-langgraph/).
- **OpenClaw (TypeScript)** → wrap each skill with `permit0Skill(...)`, or compose `permit0Middleware(...)` over the gateway dispatch. See [`permit0-openclaw/`](./permit0-openclaw/).
- **CrewAI** → subclass `crewai.tools.BaseTool` and override `_run`.
- **OpenAI Agents SDK** → wrap around the `@function_tool` decorator.
- **MCP** → sit as a JSON-RPC proxy in front of the upstream MCP server.

## Quick starts

### Python (LangGraph)

```bash
# 1. Build the permit0 Rust core + Python bindings (once)
cd crates/permit0-py && maturin develop --release

# 2. Install the integration
cd ../../integrations/permit0-langgraph && pip install -e .

# 3. Use it
python -c "
from permit0_langgraph import configure, permit0_tool
configure('packs', profile='fintech')

@permit0_tool('Bash')
def execute_shell(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

print(execute_shell.invoke({'command': 'ls'}))             # allowed
print(execute_shell.invoke({'command': 'sudo rm -rf /'}))  # blocked
"
```

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

## Planning

Additional integrations on the roadmap (with matching demos in [`examples/`](../examples/)):

- `permit0-crewai` — package version of `examples/crewai-governed`
- `permit0-openai-agents` — package version of `examples/openai-agents-governed`
- `permit0-mcp` — packaged MCP proxy (vs the single-file demo)

If you need one of these now, copy the relevant file from `examples/` into your project — it's intentionally kept at a single-file size so lifting the pattern is easy.

## Design notes

**Why a separate `integrations/` tree instead of just more `examples/`?**
Agents in production need a dependency they can pin, upgrade, and audit — not a file they copied once and forgot. `integrations/` has versioned packages; `examples/` has teaching material.

**In-process SDK vs HTTP daemon?**
Both are first-class:

- The Python bindings (used by `permit0-langgraph`) give sub-millisecond, in-process permission checks with no network hop. Best for single-process Python agents.
- The HTTP daemon (`permit0 serve --ui`) gives one policy engine for many processes / languages, plus the dashboard and audit replay. `permit0-openclaw` uses HTTP because OpenClaw is Node and the policy engine is Rust.

For multi-tenant or multi-process deployments, HTTP is the right answer regardless of language. For a single-process Python agent, in-process is faster and simpler.

**Why not just publish to PyPI / npm?**
We will. For now Python integrations are `pip install -e .` from this repo to make iteration on the core + integration simultaneous; the npm package ships from this same tree.

## Contributing a new integration

1. Pick a framework with clear tool-invocation semantics (decorator, class, hook, dispatch).
2. Scaffold `integrations/permit0-<framework>/` mirroring an existing reference:
   - `permit0-langgraph/` for Python + decorator wrap.
   - `permit0-openclaw/` for TypeScript + HOF/middleware wrap.
3. Required surface:
   - Manifest (`pyproject.toml` or `package.json`) declaring permit0 + framework as deps.
   - Public API kept small (one decorator, one HOF, one class).
   - Tests covering Allow / Deny / Human / a framework-invocation smoke test.
   - `README.md` — install, one example in 10 lines, API ref.
   - Optional: runnable example agent (scripted, no API keys required).
4. Open a PR — both reference packages are good shapes to match.

## Related docs

- [`../README.md`](../README.md) — what permit0 is
- [`../docs/permit.md`](../docs/permit.md) — the audit log format
- [`../docs/dsl.md`](../docs/dsl.md) — pack / risk-rule authoring
- [`../examples/`](../examples/) — single-file integration demos
