# permit0-langgraph

**Turn any Python function into a permission-governed LangGraph tool with a single decorator.**

```python
from permit0_langgraph import configure, permit0_tool

configure("packs", profile="fintech")

@permit0_tool("Bash")
def execute_shell(command: str) -> str:
    """Execute a shell command."""
    import subprocess
    return subprocess.check_output(command, shell=True).decode()
```

Pass `execute_shell` directly to `create_react_agent(tools=[...])` or `ToolNode([...])` — it's a real LangChain `StructuredTool` under the hood, just with a permit0 check wrapped around every invocation.

## What you get

Before each call, permit0 normalizes the tool invocation into a `NormAction`, applies the pack's risk rules, and produces one of three outcomes:

| permit0 verdict | default behavior | tunable via |
|---|---|---|
| ✅ Allow | function runs normally | — |
| ❌ Deny | returns `"[BLOCKED by permit0] …"` string to the LLM | `on_deny=` |
| 🟡 Human-in-the-loop | treated as Deny (conservative) | `on_human=` |

The default `on_deny="return"` is the best UX for LLM agents — the blocked reason becomes a regular tool result that the model can read and react to (usually by trying a safer alternative or giving up with an explanation to the user). Flip to `on_deny="raise"` if you want a hard stop.

## Install

```bash
# 1. Build the Rust core + Python bindings
cd ../../crates/permit0-py
maturin develop --release

# 2. Install this package
cd ../../integrations/permit0-langgraph
pip install -e .

# 3. Optional: LangGraph for the example agent
pip install langgraph
```

## Usage patterns

### Basic: module-level config + decorator

The 80% case. One engine for the whole process.

```python
from permit0_langgraph import configure, permit0_tool

configure(packs_dir="packs", profile="fintech")

@permit0_tool("Bash")
def execute_shell(command: str) -> str:
    """Execute a shell command."""
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

@permit0_tool("Write")
def write_file(file_path: str, content: str) -> str:
    """Write content to a file."""
    with open(file_path, "w") as f:
        f.write(content)
    return f"wrote {len(content)} bytes to {file_path}"
```

### Session-aware (cumulative risk across calls)

Pass a `permit0.Session` to thread cross-call context (attack-chain detection, rate limits, cumulative amounts):

```python
import permit0
from permit0_langgraph import configure, permit0_tool

configure("packs")

session = permit0.Session("agent-run-7f3a")

@permit0_tool("Bash", session=session)
def execute_shell(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

@permit0_tool("Write", session=session)
def write_file(file_path: str, content: str) -> str:
    with open(file_path, "w") as f:
        f.write(content)
    return f"wrote {file_path}"
```

Every call now flows through `engine.check_with_session(session, ...)`, and the session accumulates action history. A previously-CRITICAL block in the same session can trigger session-level gates on later outbound calls (see `packs/claude_code/risk_rules/network.yaml` for examples).

### LangGraph ReAct agent

```python
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from permit0_langgraph import configure, permit0_tool

configure("packs", profile="fintech")

@permit0_tool("Bash")
def execute_shell(command: str) -> str:
    """Execute a shell command and return its output."""
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

@permit0_tool("WebFetch")
def fetch_url(url: str) -> str:
    """Fetch a URL over HTTP GET."""
    import urllib.request
    with urllib.request.urlopen(url) as r:
        return r.read(10_000).decode("utf-8", errors="replace")

agent = create_react_agent(
    model=ChatOpenAI(model="gpt-4o-mini"),
    tools=[execute_shell, fetch_url],
)

result = agent.invoke({
    "messages": [("user", "list the files in /tmp and fetch example.com")],
})
```

Each tool call the agent makes gets gated by permit0 — safe calls like `ls /tmp` flow through; `sudo rm -rf /` gets blocked with a reason the LLM can read.

### Mapping function args to normalizer param names

Your function's parameter names won't always match what the permit0 normalizer reads. The shipped `Write` normalizer reads `file_path`; if your function takes `path`, pass a rename map:

```python
@permit0_tool("Write", param_map={"path": "file_path"})
def write_file(path: str, content: str) -> str:
    """Create or overwrite a file."""
    with open(path, "w") as f:
        f.write(content)
    return f"wrote {path}"
```

The inner function still receives `path=...` (its original signature); only the dict passed to permit0's permission check is renamed. Keys in `param_map` that aren't in the call's kwargs are silently skipped, so `Optional[...]` parameters stay safe.

For anything beyond a key rename — injecting constants, flattening nested objects, building a shape the normalizer expects — use `param_transform`:

```python
@permit0_tool(
    "http",  # Stripe normalizer matches method + URL + body
    param_transform=lambda kw: {
        "method": "POST",
        "url": "https://api.stripe.com/v1/charges",
        "body": {"amount": kw["amount"], "currency": "usd"},
    },
)
def charge_customer(amount: int) -> str:
    """Charge a customer `amount` cents via Stripe."""
    ...
```

`param_map` and `param_transform` are mutually exclusive — pass at most one. The inner function always runs with the *original* kwargs; the transform only affects the permission-check dict.

### Custom `on_deny` / `on_human` behavior

```python
from permit0_langgraph import permit0_tool, Permit0BlockedError

# Raise on deny (hard stop — LangGraph will propagate the error)
@permit0_tool("Bash", on_deny="raise")
def run_cmd(command: str) -> str: ...

# Structured dict result (for non-LLM consumers / middlewares)
@permit0_tool("Bash", on_deny="message")
def run_cmd(command: str) -> str: ...
# -> returns {"blocked": True, "tool": "Bash", "reason": "...", "score": 100, "tier": "CRITICAL", "norm_hash": "..."}

# Allow human-tier actions to proceed (testing only)
@permit0_tool("WebFetch", on_human="allow")
def fetch_url(url: str) -> str: ...
```

### Pre-built engine (audit trail, agent reviewer, etc.)

When you need `EngineBuilder` features (signed audit log, LLM reviewer for Medium tier):

```python
import permit0
from permit0_langgraph import permit0_tool, set_default_engine

audit = permit0.AuditBundle()
builder = permit0.EngineBuilder()
# ... install normalizers, risk rules, wire reviewer, etc.
builder.with_audit(audit)
engine = builder.build()

set_default_engine(engine)

@permit0_tool("Bash")
def execute_shell(command: str) -> str: ...

# Later: audit.export_jsonl("run.jsonl")
```

Or pass `engine=` per decorator if you need multiple engines in one process:

```python
@permit0_tool("Bash", engine=engine_strict)
def execute_shell_strict(command: str) -> str: ...

@permit0_tool("Bash", engine=engine_lax)
def execute_shell_lax(command: str) -> str: ...
```

## API reference

### `permit0_tool(name=None, *, engine=None, session=None, org_domain="default.org", on_deny="return", on_human="deny", wrap_as_tool=True, param_map=None, param_transform=None)`

Decorator that wraps a function as a permit0-governed LangGraph tool.

| param | default | meaning |
|---|---|---|
| `name` | `None` → `func.__name__` | permit0 action name (must match normalizer's `match: tool:` field) |
| `engine` | default engine | `permit0.Engine` instance |
| `session` | `None` | `permit0.Session` for cumulative risk; uses `check_with_session` |
| `org_domain` | `"default.org"` | org context for normalization helpers |
| `on_deny` | `"return"` | `"return"` \| `"raise"` \| `"message"` |
| `on_human` | `"deny"` | `"deny"` \| `"allow"` \| `"return"` \| `"raise"` \| `"message"` |
| `wrap_as_tool` | `True` | wrap result with LangChain `@tool`; set `False` for raw callable |
| `param_map` | `None` | `{func_arg: permit0_arg}` rename for the permission-check dict. Inner function still receives original arg names. |
| `param_transform` | `None` | `(dict) -> dict` full shape transform. Use for injecting constants / nesting. Mutually exclusive with `param_map`. |

### `configure(packs_dir="packs", *, profile=None, profile_path=None) -> Engine`

Build a default engine from disk and install it process-wide.

### `set_default_engine(engine)`, `get_default_engine()`, `reset_default_engine()`

Manage the module-level default engine directly (useful for tests and advanced setups).

### Exceptions

- `Permit0Error` — base class
- `Permit0BlockedError` — raised when `on_deny="raise"` fires. Attributes: `tool_name`, `reason`, `score`, `tier`, `norm_hash`.
- `Permit0HumanRequired` — raised when `on_human="raise"` fires.
- `Permit0NotConfigured` — raised at call time when no engine is available.

## How it integrates with LangGraph

`permit0_tool` returns a LangChain `StructuredTool` by default (`wrap_as_tool=True`). That type is what `create_react_agent(tools=[...])`, `ToolNode([...])`, and any other LangChain-compatible consumer expects — so there's no glue code. The function's signature, docstring, and type hints are preserved, so the LLM still sees the right JSON schema.

On a Deny verdict with `on_deny="return"` (the default), your tool returns a string like `"[BLOCKED by permit0] Bash: catastrophic_recursive_delete (score=100, tier=CRITICAL). Try a safer alternative or request human approval."`. LangGraph treats this as a normal tool result and passes it back to the LLM, which typically explains the constraint to the user and stops trying. This is almost always what you want for production agents.

For security-critical deployments where you want to hard-stop the graph on a deny, use `on_deny="raise"` and configure LangGraph's `ToolNode(..., handle_tool_errors=False)` so the exception propagates.

## Comparison with the `examples/langchain-governed` demo

| aspect | `examples/langchain-governed/` | `integrations/permit0-langgraph/` (this package) |
|---|---|---|
| **purpose** | Single-file demo of the wrapper pattern | Reusable, pip-installable package |
| **target framework** | Plain LangChain | LangGraph + LangChain |
| **wrapper style** | `Permit0ProtectedTool` class | `@permit0_tool` decorator |
| **imports** | Manual setup per script | `from permit0_langgraph import ...` |
| **use when** | Learning / prototyping | Shipping agents to prod |

## Testing

```bash
cd integrations/permit0-langgraph
pip install -e '.[test]'
pytest
```

## License

Apache-2.0, same as permit0.
