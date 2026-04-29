"""Process-wide default engine registry.

Agents typically want to configure permit0 once at startup and not thread the
Engine through every tool decorator. This module holds an optional global
reference that :func:`permit0_tool` falls back to.

Per-tool `engine=` overrides are supported and always win over the default.
"""
from __future__ import annotations

from typing import Optional

import permit0


_default_engine: Optional[permit0.Engine] = None


def configure(
    packs_dir: str = "packs",
    *,
    profile: Optional[str] = None,
    profile_path: Optional[str] = None,
) -> permit0.Engine:
    """Load permit0 packs and install them as the default engine.

    After calling this, any ``@permit0_tool(...)``-decorated function that
    doesn't pass an explicit ``engine=`` will use the engine built here.

    Args:
        packs_dir: Directory containing pack subdirectories. Relative paths
            are resolved against the current working directory.
        profile: Optional profile name. Loads ``profiles/<profile>.profile.yaml``
            if present.
        profile_path: Explicit profile YAML path, overrides ``profile``.

    Returns:
        The newly-built :class:`permit0.Engine`.
    """
    global _default_engine
    kwargs = {}
    if profile is not None:
        kwargs["profile"] = profile
    if profile_path is not None:
        kwargs["profile_path"] = profile_path
    _default_engine = permit0.Engine.from_packs(packs_dir, **kwargs)
    return _default_engine


def set_default_engine(engine: permit0.Engine) -> None:
    """Install an already-built engine as the default.

    Use this when you want to build the engine with :class:`permit0.EngineBuilder`
    (e.g. to attach an audit bundle or agent reviewer) instead of the simpler
    :func:`configure` path.
    """
    global _default_engine
    _default_engine = engine


def get_default_engine() -> Optional[permit0.Engine]:
    """Return the currently-installed default engine, or ``None``."""
    return _default_engine


def reset_default_engine() -> None:
    """Clear the default engine. Primarily useful for tests."""
    global _default_engine
    _default_engine = None
