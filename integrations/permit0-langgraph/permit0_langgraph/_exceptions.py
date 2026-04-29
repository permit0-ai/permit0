"""Exceptions raised by permit0-langgraph."""
from __future__ import annotations

from typing import Optional


class Permit0Error(Exception):
    """Base class for permit0-langgraph errors."""


class Permit0NotConfigured(Permit0Error):
    """Raised when `@permit0_tool` is invoked without a configured engine.

    Call :func:`permit0_langgraph.configure` once at startup, or pass an
    explicit `engine=` argument to the decorator.
    """


class Permit0BlockedError(Permit0Error):
    """Raised when permit0 denies a tool invocation and `on_deny="raise"`.

    Carries the full decision context so callers can route / log / alert on
    specific block reasons.

    Attributes:
        tool_name: The permit0 action name that was blocked (e.g. ``"Bash"``).
        reason: Human-readable block reason from the risk score.
        score: Numeric risk score (0-100).
        tier: Risk tier string (``"CRITICAL"``, ``"HIGH"``, etc.).
        norm_hash: Normalized action hash for allow/denylist management.
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
        score: int,
        tier: str,
        norm_hash: Optional[str] = None,
    ) -> None:
        self.tool_name = tool_name
        self.reason = reason
        self.score = score
        self.tier = tier
        self.norm_hash = norm_hash
        super().__init__(
            f"permit0 blocked {tool_name}: {reason} "
            f"(score={score}, tier={tier})"
        )


class Permit0HumanRequired(Permit0Error):
    """Raised when permit0 requires human approval and `on_human="raise"`.

    Unlike :class:`Permit0BlockedError`, this is recoverable — a supervisor
    process can inspect the approval queue and resume the tool call.

    Attributes match :class:`Permit0BlockedError` plus ``approval_id`` when
    the engine was built with an approval manager (not the common path for
    in-process SDK use).
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
        score: int,
        tier: str,
        approval_id: Optional[str] = None,
    ) -> None:
        self.tool_name = tool_name
        self.reason = reason
        self.score = score
        self.tier = tier
        self.approval_id = approval_id
        super().__init__(
            f"permit0 requires human approval for {tool_name}: {reason} "
            f"(score={score}, tier={tier})"
        )
