# permit0 Integrations

Reusable, pip-installable packages that integrate permit0 with specific agent frameworks.

Unlike [`examples/`](../examples/) — which contains single-file demos showing integration patterns — everything under `integrations/` is structured as a real package you can depend on: proper `pyproject.toml`, public API surface, unit tests, and a versioned release line.

## Packages

| Package | Framework | Install | Pattern |
|---------|-----------|---------|---------|
| [`permit0-langgraph/`](./permit0-langgraph/) | [LangGraph](https://langchain-ai.github.io/langgraph/) + [LangChain](https://python.langchain.com/) | `pip install -e integrations/permit0-langgraph` | `@permit0_tool(...)` decorator returns a `StructuredTool` LangGraph consumes natively |

## Quick start

```bash
# 1. Build the permit0 Rust core + Python bindings (once)
cd crates/permit0-py && maturin develop --release

# 2. Install an integration
cd ../../integrations/permit0-langgraph && pip install -e .

# 3. Use it
python -c "
from permit0_langgraph import configure, permit0_tool
configure('packs', profile='fintech')

@permit0_tool('Bash')
def execute_shell(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

print(execute_shell.invoke({'command': 'ls'}))        # allowed
print(execute_shell.invoke({'command': 'sudo rm -rf /'}))  # blocked
"
```

## The wrapper pattern in one sentence

Every integration follows the same three-step pattern:

1. **Intercept** — hook into the framework's tool-invocation path (decorator, base class, middleware, or proxy).
2. **Check** — call `engine.get_permission(...)` (or `check_with_session(...)`) with the normalized tool name + parameters.
3. **Route** — on **Allow**, run the original tool; on **Deny**, short-circuit with a reason; on **Human**, route to an approval queue (or, in LLM-agent contexts, treat as Deny and let the LLM work around it).

What changes between integrations is *how* you hook in — every framework has its own conventions:

- **LangGraph / LangChain** → wrap with `@tool` after the permit0 check (what `permit0-langgraph` does).
- **CrewAI** → subclass `crewai.tools.BaseTool` and override `_run`.
- **OpenAI Agents SDK** → wrap around the `@function_tool` decorator.
- **MCP** → sit as a JSON-RPC proxy in front of the upstream MCP server.

## Planning

Additional integrations on the roadmap (see matching demos in [`examples/`](../examples/)):

- `permit0-crewai` — package-ified version of `examples/crewai-governed`
- `permit0-openai-agents` — package-ified version of `examples/openai-agents-governed`
- `permit0-mcp` — packaged MCP proxy (vs the single-file demo)

If you need one of these now, copy the relevant file from `examples/` into your project — it's intentionally kept at a single-file size so lifting the pattern is easy.

## Design notes

**Why a separate `integrations/` tree instead of just more `examples/`?**
Agents in production need a dependency they can pin, upgrade, and be audited — not a file they copied once and forgot. `integrations/` has versioned packages; `examples/` has teaching material.

**Why in-process SDK over HTTP?**
The Python / Node bindings give sub-millisecond permission checks with no network hop. For multi-tenant / multi-process deployments, the HTTP server (`permit0 serve --ui`) is still the right answer — and those clients belong in `integrations/` too once they're written.

**Why not just publish to PyPI?**
We will. For now everything is `pip install -e .` from this repo to make iteration on the core + integration simultaneous.

## Contributing a new integration

1. Pick a framework with clear tool-invocation semantics (decorator, class, hook).
2. Scaffold `integrations/permit0-<framework>/` mirroring `permit0-langgraph/`:
   - `pyproject.toml` — declare `permit0` + framework as deps.
   - `permit0_<framework>/` — keep the public surface small (usually one decorator or one class).
   - `tests/` — at least Allow / Deny / Session and a framework-invocation smoke test.
   - `README.md` — install, one example in 10 lines, API ref.
   - `example_agent.py` — runnable without API keys (scripted), optional `--with-llm` mode.
3. Open a PR — the `permit0-langgraph` package is the reference shape.

## Related docs

- [`../README.md`](../README.md) — what permit0 is
- [`../docs/taxonomy.md`](../docs/taxonomy.md) — the taxonomy of governed action types
- [`../docs/dsl.md`](../docs/dsl.md) — pack / risk-rule authoring
- [`../examples/`](../examples/) — single-file integration demos
