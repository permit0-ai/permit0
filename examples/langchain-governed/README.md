# LangChain + permit0 — Governed Tool Execution

This demo shows how to wrap arbitrary LangChain `BaseTool` instances with
permit0 permission checks so that every tool call an agent makes is vetted
against the project's policy packs before execution. It runs entirely offline
— no LLM API keys required — by driving a scripted sequence of tool calls
that stand in for an LLM's decisions.

## Architecture

```
LangChain Agent
     |
     v  calls tool
Permit0ProtectedTool (wrapper)
     |
     v  engine.check_with_session()
permit0 Engine  <-- packs/*.yaml
     |
     v  Allow / Human / Deny
Inner Tool (executed or blocked)
```

Two integration patterns are shown:

- `Permit0ProtectedTool` — a `BaseTool` subclass that wraps any inner tool
  and delegates only after permit0 returns `Allow` (or `Human` plus human
  approval).
- `@permit0_protected(engine, tool_name=...)` — a decorator that gates a
  plain function before it is registered as a LangChain `StructuredTool`.

## Run it

```bash
# 1. Install permit0 into a venv (built from the workspace)
cd ../../crates/permit0-py
maturin develop

# 2. Install LangChain (no LLM provider SDK required)
pip install "langchain-core>=0.3.0"

# 3. Run the demo
cd ../../examples/langchain-governed
python3 main.py
```

The demo resolves `packs/` relative to the script's location, so it can be
invoked from anywhere.

## Expected output (abridged)

```
=== LangChain + permit0 — Governed Tool Execution ===

[step 1/6] Bash — list project files (safe)
  permit0 verdict=ALLOW tier=minimal score=10/100 flags=['EXECUTION']
  tool returned: (stub) shell executed: 'ls -la'

[step 2/6] Write — write a benign scratch file (safe)
  permit0 verdict=ALLOW tier=minimal score=3/100 flags=['MUTATION']
  tool returned: (stub) wrote 2 bytes to '/tmp/hello.txt'

[step 3/6] Write — tamper with ssh authorized_keys (attack)
  permit0 verdict=DENY tier=critical score=100/100
  reason ssh_directory_write
  tool returned: BLOCKED by permit0: ssh_directory_write

[step 4/6] Bash — catastrophic recursive delete (attack)
  permit0 verdict=DENY tier=critical score=100/100
  flags=['PRIVILEGE', 'DESTRUCTION', 'EXECUTION']
  reason catastrophic_recursive_delete
  tool returned: BLOCKED by permit0: catastrophic_recursive_delete

[step 5/6] Read — read /etc/passwd (sensitive)
  permit0 verdict=DENY tier=critical score=100/100 flags=['EXPOSURE', ...]
  reason system_credential_access
  tool returned: BLOCKED by permit0: system_credential_access

[step 6/6] WebFetch — fetch a URL (safe)
  permit0 verdict=ALLOW tier=minimal score=3/100 flags=['OUTBOUND']
  tool returned: (stub) fetched 'https://api.github.com/zen'
```

Decisions are color-coded on real terminals: green `ALLOW`, red `DENY`,
yellow `HUMAN`.

## Integration patterns

### Wrapper class (recommended for existing tool inventories)

Use `Permit0ProtectedTool` when you already have a set of `BaseTool`
instances and want to retrofit governance without touching their code.
The wrapper preserves the inner tool's `name`/`description`, so the agent
sees the same tool signature — only the execution path differs.

```python
governed = Permit0ProtectedTool(inner=my_shell_tool, engine=engine, session=session)
```

### Decorator (recommended for new function-based tools)

Use `@permit0_protected` for tools defined as plain functions that you
register via `StructuredTool.from_function`:

```python
@permit0_protected(engine, tool_name="Bash", session=session)
def run_shell(command: str) -> str:
    ...
```

## Production notes

- **Real LLM agents**: swap the scripted loop for LangChain's
  `create_tool_calling_agent` (or LangGraph). The governed tools plug in
  unchanged — they are still `BaseTool`s.
- **Session tracking**: use `engine.check_with_session(session, ...)` to
  get rate-limit and streak detection across conversation turns. Create one
  `permit0.Session` per agent run (or per user conversation).
- **Human-in-the-loop**: the demo's `ask_human` auto-denies. In production,
  publish the `DecisionResult` to your approvals queue (e.g.
  `POST /api/v1/approvals`) and block until a human responds.
- **Policy sourcing**: `Engine.from_packs("packs")` loads every YAML pack in
  the directory. Point it at a shared path (mounted volume, git submodule,
  S3-synced directory) so every agent runs against the same policy.
- **HTTP API alternative**: if you prefer to keep permit0 out of the agent
  process, run `permit0 serve` and call it over HTTP — the wrapper class's
  single `get_permission` call becomes a single HTTP request.
