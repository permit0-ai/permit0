"""
Renderer for the `watch` script. Reads events.log lines on stdin and
prints one colored row per invocation. Kept in its own file so the
parent shell script doesn't have to escape Python quoting.
"""

import json
import os
import sys


def main() -> None:
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def c(code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if use_color else text

    styles = {
        "EMPTY_STDOUT": ("32", "ALLOW/DEFER"),
        "deny": ("31", "DENY       "),
        "<missing>": ("33", "<missing>  "),
    }

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = event.get("ts", "?")
        tool = event.get("tool_name", "?")
        dec = event.get("decision", "?")
        dur = event.get("duration_ms", "?")
        color, label = styles.get(dec, ("0", str(dec).ljust(11)))
        print(
            f"  {c('90', ts)}  {c(color, label)}  tool={c('36', tool)}  dur={dur}ms",
            flush=True,
        )


if __name__ == "__main__":
    main()
