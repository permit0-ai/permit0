"""permit0-langgraph: LangGraph integration for permit0.

Usage::

    from permit0_langgraph import configure, permit0_tool

    configure("packs", profile="fintech")

    @permit0_tool("Bash")
    def execute_shell(command: str) -> str:
        \"\"\"Run a shell command.\"\"\"
        import subprocess
        return subprocess.check_output(command, shell=True).decode()

    # Pass to LangGraph
    from langgraph.prebuilt import create_react_agent
    agent = create_react_agent(model=..., tools=[execute_shell])

See :func:`permit0_tool` for full option documentation.
"""
from ._decorator import permit0_tool
from ._engine import (
    configure,
    get_default_engine,
    reset_default_engine,
    set_default_engine,
)
from ._exceptions import (
    Permit0BlockedError,
    Permit0Error,
    Permit0HumanRequired,
    Permit0NotConfigured,
)

__version__ = "0.1.0"

__all__ = [
    # Decorator (the main user-facing API)
    "permit0_tool",
    # Engine configuration
    "configure",
    "set_default_engine",
    "get_default_engine",
    "reset_default_engine",
    # Exceptions
    "Permit0Error",
    "Permit0BlockedError",
    "Permit0HumanRequired",
    "Permit0NotConfigured",
]
