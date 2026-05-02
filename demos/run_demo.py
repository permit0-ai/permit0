#!/usr/bin/env python3
"""
Launch the permit0 demo server.

Usage:
    cd /path/to/permit0
    source .venv/bin/activate
    export ANTHROPIC_API_KEY=sk-ant-...
    python demos/run_demo.py

Then open http://localhost:8000 in your browser.
"""
import os
import sys

# Ensure demos/ is on sys.path for the demo_app package
DEMOS_DIR = os.path.dirname(os.path.abspath(__file__))
if DEMOS_DIR not in sys.path:
    sys.path.insert(0, DEMOS_DIR)


def main():
    # Verify API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable not set.")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    # Verify permit0 is importable
    try:
        import permit0  # type: ignore
    except ImportError:
        print("ERROR: permit0 not installed. Build it first:")
        print("  cd crates/permit0-py && maturin develop --release")
        sys.exit(1)

    import uvicorn
    from demo_app.server import app  # noqa: E402

    port = int(os.environ.get("PORT", "8000"))
    print(f"\n🛡  permit0 Demo Server")
    print(f"   http://localhost:{port}")
    print(f"   Press Ctrl+C to stop\n")

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
