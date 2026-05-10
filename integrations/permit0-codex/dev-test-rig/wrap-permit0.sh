#!/usr/bin/env bash
#
# wrap-permit0.sh — instrumented permit0 hook wrapper for Codex.
#
# Codex's `[hooks.PreToolUse.hooks].command` points at this script. On
# every PreToolUse fire it:
#   1. Generates a unique invocation id (`inv-<ts>-<pid>`).
#   2. Captures Codex's full stdin to `$TRACE_DIR/inv-<id>/stdin.json`.
#   3. Invokes the permit0 binary with the Codex client kind and the
#      repo's pack directory.
#   4. Captures permit0's stdout (the deny envelope, or 0 bytes) to
#      `inv-<id>/stdout` and stderr to `inv-<id>/stderr`.
#   5. Appends one structured JSONL row per invocation to
#      `$TRACE_DIR/events.log`.
#   6. Forwards permit0's stdout + stderr to Codex with the original
#      exit code.
#
# Default mode is enforcement (permit0 actually blocks risky tool calls).
# Set PERMIT0_SHADOW=1 in the environment to flip to observe-only mode.
#
# All ephemeral trace state goes under TRACE_DIR (=/tmp/permit0-codex-test
# by default) so it is never committed to the repo.

set -uo pipefail

# ── Locate ourselves and the repo root ─────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# dev-test-rig/ → permit0-codex/ → integrations/ → repo root
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TRACE_DIR="${PERMIT0_TRACE_DIR:-/tmp/permit0-codex-test}"
PERMIT0="$REPO_ROOT/target/release/permit0"
PACKS_DIR="$REPO_ROOT/packs"

if [[ ! -x "$PERMIT0" ]]; then
    echo "wrap-permit0: $PERMIT0 missing or not executable — run \`cargo build --release\` first" >&2
    exit 2
fi

HOOK_ARGS=(hook --client codex --packs-dir "$PACKS_DIR" --unknown defer)
if [[ -n "${PERMIT0_SHADOW:-}" && "${PERMIT0_SHADOW}" != "0" ]]; then
    HOOK_ARGS+=(--shadow)
fi

mkdir -p "$TRACE_DIR"

INV_ID="$(python3 -c 'import time; print(f"{int(time.time()*1000):013d}")')-$$"
INV_DIR="$TRACE_DIR/inv-$INV_ID"
mkdir -p "$INV_DIR"

{
    echo "PPID=$PPID"
    echo "PID=$$"
    echo "CODEX_THREAD_ID=${CODEX_THREAD_ID:-}"
    echo "CODEX_HOME=${CODEX_HOME:-}"
    echo "PERMIT0_SHADOW=${PERMIT0_SHADOW:-}"
    echo "SCRIPT_DIR=$SCRIPT_DIR"
    echo "REPO_ROOT=$REPO_ROOT"
    echo "TRACE_DIR=$TRACE_DIR"
    echo "CWD=$(pwd)"
    echo "ARGS=${HOOK_ARGS[*]}"
} > "$INV_DIR/env"

START_MS="$(python3 -c 'import time; print(int(time.time()*1000))')"
cat > "$INV_DIR/stdin.json"

"$PERMIT0" "${HOOK_ARGS[@]}" \
    < "$INV_DIR/stdin.json" \
    > "$INV_DIR/stdout" \
    2> "$INV_DIR/stderr"
EXIT=$?

END_MS="$(python3 -c 'import time; print(int(time.time()*1000))')"
DURATION_MS=$((END_MS - START_MS))

STDIN_BYTES="$(wc -c < "$INV_DIR/stdin.json" | tr -d ' ')"
STDOUT_BYTES="$(wc -c < "$INV_DIR/stdout" | tr -d ' ')"
STDERR_BYTES="$(wc -c < "$INV_DIR/stderr" | tr -d ' ')"

TOOL_NAME="$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("tool_name", "<none>"))
except Exception as e:
    print(f"<parse-error: {e}>")
' "$INV_DIR/stdin.json" 2>/dev/null)"

DECISION="$(python3 -c '
import json, sys
b = open(sys.argv[1]).read()
if not b.strip():
    print("EMPTY_STDOUT")
else:
    try:
        d = json.loads(b)
        print(d.get("hookSpecificOutput", {}).get("permissionDecision", "<missing>"))
    except Exception as e:
        print(f"<parse-error: {e}>")
' "$INV_DIR/stdout" 2>/dev/null)"

python3 - "$INV_ID" "$EXIT" "$DURATION_MS" "$STDIN_BYTES" "$STDOUT_BYTES" "$STDERR_BYTES" "$TOOL_NAME" "$DECISION" <<'PY' >> "$TRACE_DIR/events.log"
import json
import sys
import time

(
    inv_id,
    exit_code,
    duration_ms,
    stdin_bytes,
    stdout_bytes,
    stderr_bytes,
    tool_name,
    decision,
) = sys.argv[1:]

event = {
    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "kind": "hook_invocation",
    "inv_id": inv_id,
    "exit_code": int(exit_code),
    "duration_ms": int(duration_ms),
    "stdin_bytes": int(stdin_bytes),
    "stdout_bytes": int(stdout_bytes),
    "stderr_bytes": int(stderr_bytes),
    "tool_name": tool_name,
    "decision": decision,
}
print(json.dumps(event))
PY

cat "$INV_DIR/stdout"
cat "$INV_DIR/stderr" >&2
exit "$EXIT"
