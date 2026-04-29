"""
LangChain + permit0 — Governed Tool Execution Demo.

Demonstrates two integration patterns for wrapping LangChain Tools with
permit0 permission checks:

    1. Permit0ProtectedTool  — a wrapper class around any BaseTool
    2. @permit0_protected     — a decorator for function-based tools

The demo uses a scripted agent loop (no LLM API keys required) that attempts
six tool calls, printing the permit0 verdict for each one.

Run:
    python3 main.py
"""

from __future__ import annotations

from typing import Any, Callable, Optional

import permit0
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import PrivateAttr


# ---------------------------------------------------------------------------
# Terminal colors (ANSI escape codes) — no external deps.
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"


def _color_permission(perm: permit0.Permission) -> str:
    """Color-code a permit0 Permission verdict for terminal display."""
    s = str(perm).upper()
    if s == "ALLOW":
        return f"{GREEN}{BOLD}ALLOW{RESET}"
    if s == "DENY":
        return f"{RED}{BOLD}DENY{RESET}"
    if s == "HUMAN":
        return f"{YELLOW}{BOLD}HUMAN{RESET}"
    return s


# ---------------------------------------------------------------------------
# Integration pattern 1 — wrapper class around any BaseTool.
# ---------------------------------------------------------------------------


class Permit0ProtectedTool(BaseTool):
    """Wraps a LangChain BaseTool, enforcing a permit0 permission check
    before delegating to the inner tool's ``_run``.

    The wrapper preserves the inner tool's name and description so the
    agent sees the same tool signature — only the execution path differs.
    """

    name: str
    description: str
    _inner: BaseTool = PrivateAttr()
    _engine: permit0.Engine = PrivateAttr()
    _session: Optional[permit0.Session] = PrivateAttr(default=None)
    _org_domain: str = PrivateAttr(default="example.com")

    def __init__(
        self,
        inner: BaseTool,
        engine: permit0.Engine,
        session: Optional[permit0.Session] = None,
        org_domain: str = "example.com",
    ) -> None:
        super().__init__(name=inner.name, description=inner.description)
        self._inner = inner
        self._engine = engine
        self._session = session
        self._org_domain = org_domain

    def _run(self, **kwargs: Any) -> str:
        """Check permit0 first; only invoke the inner tool on Allow
        (or on Human after approval)."""
        if self._session is not None:
            result = self._engine.check_with_session(
                self._session, self._inner.name, kwargs
            )
        else:
            result = self._engine.get_permission(
                self._inner.name, kwargs, self._org_domain
            )

        _print_decision(self._inner.name, kwargs, result)

        perm = str(result.permission).upper()
        if perm == "DENY":
            reason = result.risk_score.block_reason or result.risk_score.reason
            return f"BLOCKED by permit0: {reason}"
        if perm == "HUMAN":
            if not ask_human(result):
                return "BLOCKED: human approver declined"
        # Use invoke() to stay compatible with StructuredTool's runtime
        # contract (which requires a RunnableConfig when calling _run directly).
        return self._inner.invoke(kwargs)

    async def _arun(self, **kwargs: Any) -> str:  # pragma: no cover - demo
        return self._run(**kwargs)


# ---------------------------------------------------------------------------
# Integration pattern 2 — decorator for function-based tools.
# ---------------------------------------------------------------------------


def permit0_protected(
    engine: permit0.Engine,
    tool_name: str,
    session: Optional[permit0.Session] = None,
    org_domain: str = "example.com",
) -> Callable[[Callable[..., str]], Callable[..., str]]:
    """Decorator that gates a plain Python function behind a permit0 check.

    The decorated function can then be registered as a LangChain StructuredTool.
    """

    def decorator(fn: Callable[..., str]) -> Callable[..., str]:
        def wrapped(**kwargs: Any) -> str:
            if session is not None:
                result = engine.check_with_session(session, tool_name, kwargs)
            else:
                result = engine.get_permission(tool_name, kwargs, org_domain)
            _print_decision(tool_name, kwargs, result)
            perm = str(result.permission).upper()
            if perm == "DENY":
                reason = result.risk_score.block_reason or result.risk_score.reason
                return f"BLOCKED by permit0: {reason}"
            if perm == "HUMAN" and not ask_human(result):
                return "BLOCKED: human approver declined"
            return fn(**kwargs)

        wrapped.__name__ = fn.__name__
        wrapped.__doc__ = fn.__doc__
        return wrapped

    return decorator


# ---------------------------------------------------------------------------
# Human-in-the-loop stub.
# ---------------------------------------------------------------------------


def ask_human(result: permit0.DecisionResult) -> bool:
    """In production, publish to a review queue (e.g. POST /api/v1/approvals)
    and block until a human responds. For this demo, we auto-deny and print
    a note — no interactive prompt keeps the demo reproducible in CI."""
    rs = result.risk_score
    print(
        f"  {YELLOW}[HUMAN APPROVAL REQUESTED]{RESET} "
        f"tier={rs.tier} score={rs.score} flags={rs.flags}"
    )
    print(
        f"  {DIM}(demo) auto-denying; in production route to "
        f"POST /api/v1/approvals and await the decision{RESET}"
    )
    return False


# ---------------------------------------------------------------------------
# Sample inner tools (the "real" tools an agent might call).
#
# These are intentionally stubbed — a real integration would invoke a shell,
# write to disk, make an HTTP request, etc. The whole point of this demo is
# that permit0 gates the execution, so the stubs simply echo back.
# ---------------------------------------------------------------------------


def _shell_impl(command: str) -> str:
    return f"(stub) shell executed: {command!r}"


def _write_impl(file_path: str, content: str) -> str:
    return f"(stub) wrote {len(content)} bytes to {file_path!r}"


def _read_impl(file_path: str) -> str:
    return f"(stub) read contents of {file_path!r}"


def _fetch_impl(url: str) -> str:
    return f"(stub) fetched {url!r}"


def build_raw_tools() -> dict[str, BaseTool]:
    """Build LangChain StructuredTools with no permit0 gating."""
    return {
        "Bash": StructuredTool.from_function(
            func=_shell_impl,
            name="Bash",
            description="Run a shell command on the host machine.",
        ),
        "Write": StructuredTool.from_function(
            func=_write_impl,
            name="Write",
            description="Write content to a file at the given path.",
        ),
        "Read": StructuredTool.from_function(
            func=_read_impl,
            name="Read",
            description="Read the contents of a file at the given path.",
        ),
        "WebFetch": StructuredTool.from_function(
            func=_fetch_impl,
            name="WebFetch",
            description="Perform an HTTP GET against the given URL.",
        ),
    }


# ---------------------------------------------------------------------------
# Pretty-printing helpers.
# ---------------------------------------------------------------------------


def _print_decision(
    tool_name: str, params: dict[str, Any], result: permit0.DecisionResult
) -> None:
    """Render a single permit0 decision as a colored block."""
    rs = result.risk_score
    tier = str(rs.tier)
    perm = _color_permission(result.permission)

    print(f"  {DIM}permit0{RESET} "
          f"verdict={perm} "
          f"tier={CYAN}{tier}{RESET} "
          f"score={BOLD}{rs.score}{RESET}/100 "
          f"flags={rs.flags or '[]'}")
    print(f"  {DIM}norm   action={result.norm_action.action_type} "
          f"channel={result.norm_action.channel}{RESET}")
    if rs.block_reason:
        print(f"  {DIM}reason {RESET}{RED}{rs.block_reason}{RESET}")
    elif rs.reason:
        # Trim the noisy scoring breakdown for readability.
        print(f"  {DIM}reason {rs.reason}{RESET}")


# ---------------------------------------------------------------------------
# Scripted agent loop — stands in for the LLM's tool-calling decisions.
# ---------------------------------------------------------------------------


SCENARIOS: list[tuple[str, str, dict[str, Any], str]] = [
    (
        "Bash",
        "list project files (safe)",
        {"command": "ls -la"},
        "expect ALLOW — read-only, minimal tier",
    ),
    (
        "Write",
        "write a benign scratch file (safe)",
        {"file_path": "/tmp/hello.txt", "content": "hi"},
        "expect ALLOW — tmp is non-sensitive",
    ),
    (
        "Write",
        "tamper with ssh authorized_keys (attack)",
        {"file_path": "/root/.ssh/authorized_keys", "content": "ssh-rsa AAAA attacker"},
        "expect DENY — credential-exposure guard",
    ),
    (
        "Bash",
        "catastrophic recursive delete (attack)",
        {"command": "sudo rm -rf /"},
        "expect DENY — destruction + privilege guard",
    ),
    (
        "Read",
        "read /etc/passwd (sensitive)",
        {"file_path": "/etc/passwd"},
        "expect DENY — system credential access",
    ),
    (
        "WebFetch",
        "fetch a URL (safe)",
        {"url": "https://api.github.com/zen"},
        "expect ALLOW — benign outbound",
    ),
]


def run_demo() -> None:
    """Run the scripted agent loop against a governed tool set."""
    print(f"{BOLD}{MAGENTA}=== LangChain + permit0 — Governed Tool Execution ==={RESET}")
    print(f"{DIM}loading packs from ../../packs (relative to this file){RESET}")

    # Resolve packs dir relative to this file so the demo runs from anywhere.
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    packs_dir = os.path.abspath(os.path.join(here, "..", "..", "packs"))

    engine = permit0.Engine.from_packs(packs_dir, None)
    session = permit0.Session("demo-agent-1")

    raw_tools = build_raw_tools()
    governed_tools = {
        name: Permit0ProtectedTool(inner=tool, engine=engine, session=session)
        for name, tool in raw_tools.items()
    }

    print(f"\n{DIM}registered {len(governed_tools)} governed tools: "
          f"{list(governed_tools)}{RESET}\n")

    for i, (tool_name, label, params, note) in enumerate(SCENARIOS, 1):
        print(f"{BOLD}[step {i}/{len(SCENARIOS)}]{RESET} "
              f"{CYAN}{tool_name}{RESET} — {label}")
        print(f"  {DIM}params={params}{RESET}")
        print(f"  {DIM}note:  {note}{RESET}")

        tool = governed_tools[tool_name]
        output = tool._run(**params)

        if output.startswith("BLOCKED"):
            print(f"  {RED}tool returned:{RESET} {output}")
        else:
            print(f"  {GREEN}tool returned:{RESET} {output}")
        print()

    # Demonstrate the decorator pattern on a single call, for the README.
    print(f"{BOLD}{MAGENTA}--- decorator pattern ---{RESET}")

    @permit0_protected(engine, "Bash", session=session)
    def guarded_echo(command: str) -> str:
        """A plain function gated by the @permit0_protected decorator."""
        return f"(stub) decorator-wrapped shell: {command!r}"

    print(f"{BOLD}[bonus]{RESET} {CYAN}guarded_echo{RESET}(command='whoami')")
    print(f"  {DIM}params={{'command': 'whoami'}}{RESET}")
    print(f"  {GREEN}returned:{RESET} {guarded_echo(command='whoami')}")


if __name__ == "__main__":
    run_demo()
