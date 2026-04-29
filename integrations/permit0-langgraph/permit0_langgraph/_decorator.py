"""The ``@permit0_tool`` decorator.

Turns any Python callable into a LangChain/LangGraph-compatible tool whose
invocations are gated by permit0. The decorator:

1. Calls ``engine.get_permission(...)`` (or ``check_with_session(...)``) before
   the wrapped function runs.
2. On **Allow**: invokes the function normally.
3. On **Deny**: routes via ``on_deny`` — raise, return-as-string, or return a
   structured blocked dict.
4. On **Human-in-the-loop**: routes via ``on_human`` — same options, plus
   "treat as allow" for testing.
5. Wraps the result with LangChain's ``@tool`` so LangGraph / ``create_react_agent``
   / ``ToolNode`` can consume it directly.

Design notes:
- Sync wrap only — LangGraph happily uses sync tools. Async can be added later.
- The decorator preserves ``__name__``, ``__doc__``, and function signature so
  LangChain can infer the JSON schema the LLM sees.
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Literal, Mapping, Optional, Union

import permit0

from ._engine import get_default_engine
from ._exceptions import Permit0BlockedError, Permit0HumanRequired, Permit0NotConfigured


# Valid values for ``on_deny`` and ``on_human``.
OnDenyMode = Literal["raise", "return", "message"]
OnHumanMode = Literal["raise", "return", "message", "deny", "allow"]

# A callable that takes the function's bound kwargs and returns the dict of
# parameters passed to permit0's permission check. Used for `param_transform`.
ParamTransform = Callable[[Dict[str, Any]], Dict[str, Any]]


def permit0_tool(
    name: Optional[str] = None,
    *,
    engine: Optional[permit0.Engine] = None,
    session: Optional[permit0.Session] = None,
    org_domain: str = "default.org",
    on_deny: OnDenyMode = "return",
    on_human: OnHumanMode = "deny",
    wrap_as_tool: bool = True,
    param_map: Optional[Mapping[str, str]] = None,
    param_transform: Optional[ParamTransform] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a function as a permit0-governed LangGraph tool.

    Usage — common case::

        from permit0_langgraph import configure, permit0_tool

        configure("packs", profile="fintech")

        @permit0_tool("Bash")
        def execute_shell(command: str) -> str:
            \"\"\"Run a shell command.\"\"\"
            import subprocess
            return subprocess.check_output(command, shell=True).decode()

        # Pass to LangGraph:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model=..., tools=[execute_shell])

    Args:
        name: The permit0 action / tool name used for normalizer lookup (must
            match the ``match: tool: <name>`` in a normalizer YAML). Defaults
            to the function's ``__name__``.
        engine: Engine to use for permission checks. Defaults to the engine
            installed via :func:`configure`. Passing ``engine=`` always wins
            over the default.
        session: Optional :class:`permit0.Session` for cumulative risk across
            calls. If provided, uses :meth:`Engine.check_with_session` (so
            session history is auto-updated).
        org_domain: Organization domain passed into the normalization context
            (used by helpers like ``recipient_scope``).
        on_deny: What to do when permit0 returns ``Deny``:

            * ``"return"`` (default): return a ``"[BLOCKED by permit0] …"``
              string. The agent sees the block reason as a normal tool result
              and can react — usually the best UX for LLM agents.
            * ``"raise"``: raise :class:`Permit0BlockedError`. LangGraph will
              catch or re-raise depending on its ``on_tool_error`` config.
            * ``"message"``: return a structured ``dict`` (same keys as the
              error) — useful when you want to pattern-match on the result.
        on_human: What to do when permit0 returns human-in-the-loop
            (Medium-tier ambiguous actions):

            * ``"deny"`` (default): treat as Deny — conservative.
            * ``"allow"``: treat as Allow. Only for dev / testing.
            * ``"raise"``: raise :class:`Permit0HumanRequired`.
            * ``"return"`` / ``"message"``: same semantics as ``on_deny``.
        wrap_as_tool: If ``True`` (default), wraps the governed callable with
            LangChain's ``@tool`` decorator to produce a ``StructuredTool``
            that LangGraph consumes natively. Set to ``False`` to get back the
            plain governed function (useful for unit tests or non-LangGraph
            orchestrators).
        param_map: Simple key-rename from function-signature argument names to
            the parameter names the permit0 normalizer expects. Use when your
            function's signature doesn't line up with the normalizer's
            ``from:`` fields — e.g. your function takes ``path`` but the
            normalizer's ``write.yaml`` reads ``file_path``::

                @permit0_tool("Write", param_map={"path": "file_path"})
                def write_file(path: str, content: str) -> str: ...

            The inner function always receives the original (un-renamed)
            kwargs; only the dict passed into permit0's permission check is
            transformed. Unknown keys in ``param_map`` are silently ignored
            so optional arguments stay safe.
        param_transform: Full callable that takes the function's bound kwargs
            and returns the dict of parameters to pass to permit0. Use this
            when a simple rename isn't enough — e.g. you need to inject
            constants (HTTP method / URL) or flatten nested objects::

                @permit0_tool("http", param_transform=lambda kw: {
                    "method": "POST",
                    "url": "https://api.stripe.com/v1/charges",
                    "body": {"amount": kw["amount"], "currency": "usd"},
                })
                def charge_customer(amount: int) -> str: ...

            ``param_map`` and ``param_transform`` are mutually exclusive —
            passing both raises ``ValueError`` at decorator-apply time.

    Returns:
        A decorator that takes the user function and returns either a
        LangChain ``BaseTool`` (when ``wrap_as_tool=True``) or the raw
        governed callable.

    Raises:
        Permit0NotConfigured: at call time, when neither ``engine=`` nor
            :func:`configure` has established an engine.
    """
    if param_map is not None and param_transform is not None:
        raise ValueError(
            "permit0_tool: pass at most one of `param_map` or `param_transform`"
        )
    # Freeze the rename mapping so mutations to the caller's dict can't affect
    # the decorator after application.
    _param_map: Optional[Dict[str, str]] = (
        dict(param_map) if param_map is not None else None
    )

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or func.__name__

        @functools.wraps(func)
        def governed(*args: Any, **kwargs: Any) -> Any:
            eng = engine or get_default_engine()
            if eng is None:
                raise Permit0NotConfigured(
                    "No permit0 engine configured. Call "
                    "`permit0_langgraph.configure('packs', profile=...)` "
                    "at startup, or pass `engine=` to @permit0_tool."
                )

            # LangGraph always calls tools with kwargs — but support positional
            # for direct invocation in tests. Map positional → kwargs by signature.
            if args:
                try:
                    sig = inspect.signature(func)
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    params = dict(bound.arguments)
                except TypeError:
                    # Fall back to raw kwargs if the signature can't be bound.
                    params = dict(kwargs)
            else:
                params = dict(kwargs)

            # Apply param_map / param_transform to build the dict that goes
            # into permit0. The inner function still runs with the ORIGINAL
            # kwargs — the transform only affects what permit0 sees.
            permit0_params = _build_permit0_params(
                params, _param_map, param_transform, tool_name
            )

            # Permit0 requires plain JSON-serializable values for parameter inspection.
            # Reject non-serializable arguments upfront so the failure is clear.
            try:
                import json
                json.dumps(permit0_params, default=str)
            except (TypeError, ValueError) as e:
                raise TypeError(
                    f"@permit0_tool({tool_name!r}) received non-JSON-serializable "
                    f"parameters: {e}"
                ) from e

            if session is not None:
                result = eng.check_with_session(session, tool_name, permit0_params, org_domain)
            else:
                result = eng.get_permission(tool_name, permit0_params, org_domain)

            perm = result.permission

            if perm == permit0.Permission.Deny:
                return _handle_deny(tool_name, result, on_deny)

            if perm == permit0.Permission.Human:
                outcome = _handle_human(tool_name, result, on_human)
                if outcome == "allow":
                    pass  # fall through to invocation
                elif outcome == "deny":
                    return _handle_deny(tool_name, result, on_deny)
                else:
                    # _handle_human already returned a string/dict or raised.
                    return outcome

            # Allow — invoke the wrapped function.
            return func(*args, **kwargs)

        # Preserve the signature annotations so LangChain's tool-schema
        # inference sees the user's function, not the `*args, **kwargs` shim.
        try:
            governed.__signature__ = inspect.signature(func)  # type: ignore[attr-defined]
        except (ValueError, TypeError):
            pass

        if not wrap_as_tool:
            return governed

        # Lazy import: users who install this package without langchain should
        # still be able to use `wrap_as_tool=False` for tests.
        try:
            from langchain_core.tools import tool as langchain_tool
        except ImportError as e:
            raise ImportError(
                "langchain-core is required when wrap_as_tool=True. "
                "Install with: pip install langchain-core"
            ) from e

        return langchain_tool(governed)

    return decorator


def _build_permit0_params(
    original_kwargs: Dict[str, Any],
    param_map: Optional[Dict[str, str]],
    param_transform: Optional[ParamTransform],
    tool_name: str,
) -> Dict[str, Any]:
    """Compute the parameter dict passed to permit0's permission check.

    Precedence:
    - ``param_transform`` (if set) fully replaces the dict — we call it with a
      *copy* of the kwargs so the callback can't mutate the caller's state.
    - ``param_map`` (if set) renames keys from the function's argument names
      to the permit0 normalizer's expected names. Unknown source keys are
      silently skipped so optional-argument absences don't break mapping.
    - Otherwise the kwargs flow through unchanged.

    Args:
        original_kwargs: The function's bound kwargs (already normalized from
            args via ``inspect.signature``).
        param_map: The frozen rename dict, or ``None``.
        param_transform: The transform callable, or ``None``.
        tool_name: Used only for error context.
    """
    if param_transform is not None:
        try:
            result = param_transform(dict(original_kwargs))
        except Exception as e:  # noqa: BLE001  — caller controls callback
            raise RuntimeError(
                f"@permit0_tool({tool_name!r}) param_transform raised: {e}"
            ) from e
        if not isinstance(result, dict):
            raise TypeError(
                f"@permit0_tool({tool_name!r}) param_transform must return a dict, "
                f"got {type(result).__name__}"
            )
        return result

    if param_map is not None:
        renamed: Dict[str, Any] = {}
        for k, v in original_kwargs.items():
            if k in param_map:
                renamed[param_map[k]] = v
            else:
                renamed[k] = v
        return renamed

    return dict(original_kwargs)


def _handle_deny(
    tool_name: str,
    result: "permit0.DecisionResult",
    mode: OnDenyMode,
) -> Any:
    rs = result.risk_score
    reason = (rs.block_reason or rs.reason) if rs else "policy block"
    score = rs.score if rs else 0
    tier = str(rs.tier) if rs else "UNKNOWN"
    norm_hash = result.norm_action.norm_hash if result.norm_action else None

    if mode == "raise":
        raise Permit0BlockedError(tool_name, reason, score, tier, norm_hash)
    if mode == "message":
        return {
            "blocked": True,
            "tool": tool_name,
            "reason": reason,
            "score": score,
            "tier": tier,
            "norm_hash": norm_hash,
        }
    # default: "return" — string the LLM can read
    return (
        f"[BLOCKED by permit0] {tool_name}: {reason} "
        f"(score={score}, tier={tier}). "
        f"Try a safer alternative or request human approval."
    )


def _handle_human(
    tool_name: str,
    result: "permit0.DecisionResult",
    mode: OnHumanMode,
) -> Union[str, dict, Any]:
    rs = result.risk_score
    reason = rs.reason if rs else "human review required"
    score = rs.score if rs else 0
    tier = str(rs.tier) if rs else "MEDIUM"

    if mode == "allow":
        return "allow"
    if mode == "deny":
        return "deny"
    if mode == "raise":
        raise Permit0HumanRequired(tool_name, reason, score, tier)
    if mode == "message":
        return {
            "blocked": True,
            "tool": tool_name,
            "reason": reason,
            "score": score,
            "tier": tier,
            "needs_human_approval": True,
        }
    # "return"
    return (
        f"[permit0 requires human approval] {tool_name}: {reason} "
        f"(score={score}, tier={tier}). Queued for review."
    )
