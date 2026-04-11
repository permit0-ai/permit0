"""
LangGraph agent loop with permit0 integration.

Two modes:
  - Unprotected: all tool calls execute immediately (no permit0).
  - Protected:   every tool call passes through permit0 engine;
                 HUMAN_IN_THE_LOOP triggers an interrupt for GUI approval.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from langchain_core.tools import tool as langchain_tool
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt

import permit0  # type: ignore

from .scenarios import Scenario
from .tools import ALL_TOOLS, TOOLS_BY_NAME, get_tool_call_params

# Typing
from typing import Annotated, TypedDict


# ── State ──────────────────────────────────────────────────────

class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    # Track permit0 decisions for the UI
    decisions: list[dict]
    # Whether this run is protected
    protected: bool
    # Scenario metadata
    scenario_id: str
    org_domain: str


# ── Event callback protocol ────────────────────────────────────

@dataclass
class AgentEvent:
    """Events emitted by the agent loop for the WebSocket UI."""
    kind: str  # "thinking", "tool_call", "tool_result", "permit0_decision", "blocked", "done", "error"
    data: dict = field(default_factory=dict)


EventCallback = Any  # Callable[[AgentEvent], Awaitable[None]]


# ── Engine singleton ───────────────────────────────────────────

_engine: permit0.Engine | None = None
_audit: permit0.AuditBundle | None = None

PACKS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "packs")


def get_engine() -> permit0.Engine:
    global _engine, _audit
    if _engine is None:
        _audit = permit0.AuditBundle()
        builder = permit0.EngineBuilder()

        for pack_name in sorted(os.listdir(PACKS_DIR)):
            pack_dir = os.path.join(PACKS_DIR, pack_name)
            if not os.path.isdir(pack_dir):
                continue
            norm_dir = os.path.join(pack_dir, "normalizers")
            rule_dir = os.path.join(pack_dir, "risk_rules")
            if os.path.isdir(norm_dir):
                for fname in sorted(os.listdir(norm_dir)):
                    if fname.endswith(".yaml"):
                        with open(os.path.join(norm_dir, fname)) as f:
                            builder.install_normalizer_yaml(f.read())
            if os.path.isdir(rule_dir):
                for fname in sorted(os.listdir(rule_dir)):
                    if fname.endswith(".yaml"):
                        with open(os.path.join(rule_dir, fname)) as f:
                            builder.install_risk_rule_yaml(f.read())

        # Agent reviewer: LLM-based review for MEDIUM-tier calls
        if os.environ.get("PERMIT0_REVIEWER_ENABLED", "true").lower() == "true":
            try:
                from .reviewer import anthropic_review
                builder.with_reviewer(anthropic_review)
            except Exception as e:
                print(f"[permit0] Agent reviewer disabled: {e}")

        builder.with_audit(_audit)
        _engine = builder.build()
    return _engine


def get_audit() -> permit0.AuditBundle | None:
    return _audit


def reset_engine() -> None:
    """Force re-creation of engine + audit for a fresh demo run."""
    global _engine, _audit
    _engine = None
    _audit = None


# ── Agent runner ───────────────────────────────────────────────

class DemoAgent:
    """
    Runs one demo scenario through the LangGraph agent loop.

    Emits AgentEvent objects via the callback for real-time UI updates.
    """

    def __init__(
        self,
        scenario: Scenario,
        protected: bool,
        callback: EventCallback,
        model_name: str = "claude-sonnet-4-20250514",
    ):
        self.scenario = scenario
        self.protected = protected
        self.callback = callback
        self.model = ChatAnthropic(
            model=model_name,
            temperature=0,
            max_tokens=4096,
        ).bind_tools(scenario.tools)
        self.session = permit0.Session(f"demo-{scenario.id}-{'protected' if protected else 'unprotected'}")
        self.engine = get_engine()
        self._pending_approval: dict | None = None
        self._approval_event: asyncio.Event | None = None
        self._approval_result: str | None = None

    async def emit(self, kind: str, **data: Any) -> None:
        await self.callback(AgentEvent(kind=kind, data=data))

    async def run(self) -> list[dict]:
        """Execute the full agent loop. Returns list of decisions."""
        decisions: list[dict] = []

        messages: list[BaseMessage] = [
            SystemMessage(content=self.scenario.system_prompt),
            HumanMessage(content=self.scenario.user_message),
        ]

        await self.emit("start", scenario=self.scenario.id, protected=self.protected)

        # Show the prompts to the UI before the agent starts thinking
        await self.emit("system_prompt", text=self.scenario.system_prompt)
        await self.emit("user_prompt", text=self.scenario.user_message)

        max_turns = 20  # safety limit
        for turn in range(max_turns):
            # ── LLM call ──
            await self.emit("thinking")
            response: AIMessage = await asyncio.to_thread(
                self.model.invoke, messages
            )
            messages.append(response)

            # If LLM produced text content (no tool calls), emit and check if done
            if response.content and not response.tool_calls:
                text = response.content if isinstance(response.content, str) else str(response.content)
                await self.emit("assistant_message", text=text)

            # No tool calls → agent is done
            if not response.tool_calls:
                break

            # ── Process each tool call ──
            all_blocked = True
            for tc in response.tool_calls:
                tool_name = tc["name"]
                tool_input = tc["args"]
                tool_call_id = tc["id"]

                await self.emit(
                    "tool_call",
                    tool_name=tool_name,
                    tool_input=tool_input,
                    tool_call_id=tool_call_id,
                )

                if self.protected:
                    # ── permit0 check ──
                    p0_tool, p0_params = get_tool_call_params(tool_name, tool_input)
                    result = self.engine.check_with_session(
                        self.session, p0_tool, p0_params, self.scenario.org_domain
                    )

                    decision_data = {
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                        "permission": str(result.permission),
                        "source": result.source,
                        "risk_score": None,
                        "blocked": False,
                    }
                    if result.risk_score:
                        decision_data["risk_score"] = {
                            "raw": result.risk_score.raw,
                            "score": result.risk_score.score,
                            "tier": str(result.risk_score.tier),
                            "flags": result.risk_score.flags,
                            "blocked": result.risk_score.blocked,
                            "block_reason": result.risk_score.block_reason,
                        }
                        decision_data["blocked"] = result.risk_score.blocked

                    decisions.append(decision_data)
                    await self.emit("permit0_decision", **decision_data)

                    if result.permission == permit0.Permission.Deny:
                        # BLOCKED
                        await self.emit(
                            "blocked",
                            tool_name=tool_name,
                            reason=result.risk_score.block_reason if result.risk_score else "denied",
                        )
                        tool_result = (
                            f"[BLOCKED by permit0] This action was denied. "
                            f"Reason: {result.risk_score.block_reason if result.risk_score and result.risk_score.block_reason else 'policy violation'}. "
                            f"Do not retry this action."
                        )
                        messages.append(ToolMessage(
                            content=tool_result,
                            tool_call_id=tool_call_id,
                        ))
                        continue

                    if result.permission == permit0.Permission.Human:
                        # HUMAN-IN-THE-LOOP — wait for GUI approval
                        await self.emit(
                            "approval_required",
                            tool_name=tool_name,
                            tool_input=tool_input,
                            risk_score=decision_data.get("risk_score"),
                        )

                        # Block until the UI sends approve/reject
                        self._approval_event = asyncio.Event()
                        self._pending_approval = {
                            "tool_name": tool_name,
                            "tool_input": tool_input,
                            "tool_call_id": tool_call_id,
                        }
                        await self._approval_event.wait()
                        approved = self._approval_result == "approve"
                        self._pending_approval = None

                        if not approved:
                            await self.emit("blocked", tool_name=tool_name, reason="rejected by human reviewer")
                            tool_result = "[REJECTED by human reviewer] This action was not approved. Do not retry."
                            messages.append(ToolMessage(
                                content=tool_result,
                                tool_call_id=tool_call_id,
                            ))
                            continue

                        await self.emit("approved", tool_name=tool_name)

                # ── Execute tool ──
                all_blocked = False
                tool_fn = TOOLS_BY_NAME.get(tool_name)
                if tool_fn:
                    tool_result = await asyncio.to_thread(tool_fn.invoke, tool_input)
                else:
                    tool_result = f"Unknown tool: {tool_name}"

                await self.emit(
                    "tool_result",
                    tool_name=tool_name,
                    result=str(tool_result),
                )
                messages.append(ToolMessage(
                    content=str(tool_result),
                    tool_call_id=tool_call_id,
                ))

        await self.emit("done", decisions=decisions)
        return decisions

    def resolve_approval(self, decision: str) -> None:
        """Called by the WebSocket handler when the user clicks approve/reject."""
        self._approval_result = decision
        if self._approval_event:
            self._approval_event.set()

    @property
    def has_pending_approval(self) -> bool:
        return self._pending_approval is not None

    @property
    def pending_approval(self) -> dict | None:
        return self._pending_approval
