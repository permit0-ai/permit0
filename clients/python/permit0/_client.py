"""HTTP client + decorator implementation."""
from __future__ import annotations

import functools
import inspect
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import httpx

DEFAULT_URL = "http://localhost:9090"
# Default HTTP timeout. Long enough to cover the daemon's calibration
# approval window (5-min default in ApprovalManager). Override via
# the PERMIT0_TIMEOUT env var (seconds).
DEFAULT_TIMEOUT = float(os.environ.get("PERMIT0_TIMEOUT", "310"))


@dataclass(frozen=True)
class Decision:
    """Result of a permit0 check."""

    permission: str  # "allow" | "deny" | "human"
    action_type: str
    source: str
    norm_hash: str
    decision_source: str
    score: int | None = None
    tier: str | None = None
    blocked: bool | None = None
    block_reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.permission == "allow"


class Denied(Exception):
    """Raised when permit0 returns a non-``allow`` decision on a guarded call."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        msg = (
            f"permit0 {decision.permission}: {decision.action_type} "
            f"(tier={decision.tier} score={decision.score} decision_source={decision.decision_source})"
        )
        if decision.block_reason:
            msg += f" — {decision.block_reason}"
        super().__init__(msg)


def _server_url() -> str:
    return os.environ.get("PERMIT0_URL", DEFAULT_URL).rstrip("/")


def check_action(
    action_type: str,
    parameters: Mapping[str, Any] | None = None,
    *,
    source: str = "app",
    timeout: float = DEFAULT_TIMEOUT,
) -> Decision:
    """Call ``POST /api/v1/check_action`` and return a parsed ``Decision``.

    Lower-level than ``guard``: lets you check an action without decorating a
    function. Useful for one-off checks or middleware-style integration.
    """
    body = {
        "action_type": action_type,
        "source": source,
        "parameters": dict(parameters) if parameters else {},
    }
    r = httpx.post(f"{_server_url()}/api/v1/check_action", json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return Decision(
        permission=data["permission"],
        action_type=data["action_type"],
        source=data["source"],
        norm_hash=data["norm_hash"],
        decision_source=data["decision_source"],
        score=data.get("score"),
        tier=data.get("tier"),
        blocked=data.get("blocked"),
        block_reason=data.get("block_reason"),
    )


def _derive_action_type(fn: Callable[..., Any]) -> str:
    """Map a function name like ``email_send`` → ``email.send``.

    Splits on the first underscore: domain = before, verb = after (kept intact).
    """
    name = fn.__name__
    if "_" not in name:
        raise ValueError(
            f"cannot derive action_type from function name {name!r}: "
            f"name must follow '<domain>_<verb>' convention. "
            f"Pass an explicit action_type: @permit0.guard(\"domain.verb\")"
        )
    domain, verb = name.split("_", 1)
    return f"{domain}.{verb}"


def _bind_parameters(fn: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
    """Map the function's call-site arguments to parameter names (kwargs by name)."""
    sig = inspect.signature(fn)
    bound = sig.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    return {k: v for k, v in bound.arguments.items() if k not in ("self", "cls")}


def guard(
    action_type: str | None = None,
    *,
    source: str = "app",
    parameters: Callable[..., Mapping[str, Any]] | None = None,
):
    """Decorator: gate a function on a permit0 norm action.

    By default, the function name is mapped to a ``domain.verb`` action type
    (e.g. ``email_send`` → ``email.send``) and the function's bound arguments
    become permit0 parameters.

    Args:
        action_type: Norm action like ``"email.send"``. If omitted, derived
            from the function name.
        source: Vendor-surface string sent to permit0 (default ``"app"``).
        parameters: Optional callable ``(args, kwargs) -> dict`` to override the
            default mapping if your function's argument names don't match the
            risk rule's expected parameter names.

    Raises:
        Denied: if permit0 returns ``deny`` or ``human``.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        action = action_type or _derive_action_type(fn)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            ents = parameters(*args, **kwargs) if parameters else _bind_parameters(fn, args, kwargs)
            decision = check_action(action, ents, source=source)
            if not decision.allowed:
                raise Denied(decision)
            return fn(*args, **kwargs)

        wrapper.__permit0_action__ = action  # type: ignore[attr-defined]
        return wrapper

    return decorator
