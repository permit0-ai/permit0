#!/usr/bin/env bash
#
# test-managed-prefs-roundtrip.sh — integration test for
# integrations/permit0-codex/examples/install-managed-prefs.sh.
#
# Mutates the real macOS user defaults under
# `com.openai.codex/requirements_toml_base64`, so the test snapshots the
# live value at startup and restores it on EXIT (success or failure)
# via a trap. Never destroys developer state.
#
# Test phases:
#   A. Without --force, refuse to clobber an unstamped existing value.
#   B. With --force, back up the prior value and install permit0's.
#   C. --uninstall restores the most recent backup.
#   D. --uninstall on an unstamped value refuses without --force.
#
# Skips gracefully on non-macOS (CI on Linux).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$REPO_ROOT/integrations/permit0-codex/examples/install-managed-prefs.sh"

DOMAIN=com.openai.codex
KEY=requirements_toml_base64
BACKUP_DIR="$HOME/.permit0"
STAMP="# permit0-managed: installed by integrations/permit0-codex"

PASS=0
FAIL=0

# ── Skip on non-macOS ───────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "test-managed-prefs-roundtrip: skipped (requires macOS \`defaults\`)"
    exit 0
fi
if [[ ! -x "$INSTALLER" ]]; then
    echo "test-managed-prefs-roundtrip: skipped (installer missing or not executable: $INSTALLER)"
    exit 0
fi

# ── Snapshot + restore-on-exit ──────────────────────────────────────
PRESERVED_PATH="/tmp/permit0-mp-test-preserved-$$.b64"
PRESERVED_BACKUPS_DIR="/tmp/permit0-mp-test-preserved-backups-$$"
HAD_VALUE=0
HAD_BACKUPS=0

if defaults read "$DOMAIN" "$KEY" >/dev/null 2>&1; then
    defaults read "$DOMAIN" "$KEY" > "$PRESERVED_PATH"
    HAD_VALUE=1
fi
if compgen -G "$BACKUP_DIR/managed-prefs-backup-*.toml" >/dev/null 2>&1; then
    mkdir -p "$PRESERVED_BACKUPS_DIR"
    mv "$BACKUP_DIR"/managed-prefs-backup-*.toml "$PRESERVED_BACKUPS_DIR/"
    HAD_BACKUPS=1
fi

restore_state() {
    # Always remove anything the test left behind first.
    defaults delete "$DOMAIN" "$KEY" >/dev/null 2>&1 || true
    rm -f "$BACKUP_DIR"/managed-prefs-backup-*.toml 2>/dev/null || true
    # Put the developer's pre-test state back.
    if [[ "$HAD_VALUE" == "1" && -f "$PRESERVED_PATH" ]]; then
        defaults write "$DOMAIN" "$KEY" -string "$(cat "$PRESERVED_PATH")" \
            >/dev/null 2>&1 || true
    fi
    rm -f "$PRESERVED_PATH" 2>/dev/null
    if [[ "$HAD_BACKUPS" == "1" && -d "$PRESERVED_BACKUPS_DIR" ]]; then
        mv "$PRESERVED_BACKUPS_DIR"/managed-prefs-backup-*.toml \
            "$BACKUP_DIR/" 2>/dev/null || true
        rmdir "$PRESERVED_BACKUPS_DIR" 2>/dev/null || true
    fi
}
trap restore_state EXIT

# ── Test helpers ────────────────────────────────────────────────────
say() { printf '%s\n' "$*"; }

assert_pass() {
    PASS=$((PASS + 1))
    say "  ✓ $1"
}

assert_fail() {
    FAIL=$((FAIL + 1))
    say "  ✗ $1"
}

assert_exit_neq_zero() {
    local label="$1"
    local code="$2"
    if [[ "$code" != "0" ]]; then
        assert_pass "$label (exit=$code)"
    else
        assert_fail "$label (expected non-zero exit, got 0)"
    fi
}

assert_exit_zero() {
    local label="$1"
    local code="$2"
    if [[ "$code" == "0" ]]; then
        assert_pass "$label (exit=0)"
    else
        assert_fail "$label (expected exit 0, got $code)"
    fi
}

current_value_decoded() {
    if defaults read "$DOMAIN" "$KEY" >/dev/null 2>&1; then
        defaults read "$DOMAIN" "$KEY" | base64 -d
    fi
}

plant_sentinel() {
    local sentinel="# fake-mdm-sentinel-do-not-overwrite
[features]
hooks = false
"
    defaults write "$DOMAIN" "$KEY" -string "$(printf '%s' "$sentinel" | base64)"
    printf '%s' "$sentinel"
}

# ── Fresh-start the test state ──────────────────────────────────────
defaults delete "$DOMAIN" "$KEY" >/dev/null 2>&1 || true
rm -f "$BACKUP_DIR"/managed-prefs-backup-*.toml 2>/dev/null || true

# ──────────────────────────────────────────────────────────────────
#   Phase A: refuse to clobber an unstamped existing value
# ──────────────────────────────────────────────────────────────────
say
say "Phase A: refuse to clobber unstamped existing value"
SENTINEL="$(plant_sentinel)"

set +e
INSTALL_OUTPUT="$("$INSTALLER" 2>&1)"
CODE=$?
set -e
assert_exit_neq_zero "installer without --force exits non-zero" "$CODE"

if grep -qiE "(unstamped|stamp|--force)" <<<"$INSTALL_OUTPUT"; then
    assert_pass "warning mentions stamp/--force"
else
    assert_fail "warning should mention stamp/--force; got: $(head -3 <<<"$INSTALL_OUTPUT")"
fi

if [[ "$(current_value_decoded)" == "$SENTINEL" ]]; then
    assert_pass "sentinel value unchanged after failed install"
else
    assert_fail "sentinel value was modified by failed install"
fi

# ──────────────────────────────────────────────────────────────────
#   Phase B: --force backs up + overwrites
# ──────────────────────────────────────────────────────────────────
say
say "Phase B: --force backs up and overwrites"
set +e
FORCE_OUTPUT="$("$INSTALLER" --force 2>&1)"
CODE=$?
set -e
assert_exit_zero "installer --force succeeds" "$CODE"

# Find the new backup.
LATEST_BACKUP="$(ls -1t "$BACKUP_DIR"/managed-prefs-backup-*.toml 2>/dev/null | head -1)"
if [[ -n "$LATEST_BACKUP" && -f "$LATEST_BACKUP" ]]; then
    assert_pass "backup file created at $(basename "$LATEST_BACKUP")"
    if [[ "$(cat "$LATEST_BACKUP")" == "$SENTINEL" ]]; then
        assert_pass "backup content matches the pre-install sentinel"
    else
        assert_fail "backup content does not match sentinel"
    fi
else
    assert_fail "no backup file found in $BACKUP_DIR"
fi

NEW_VAL="$(current_value_decoded)"
if grep -qF "$STAMP" <<<"$NEW_VAL"; then
    assert_pass "new value contains permit0 stamp"
else
    assert_fail "new value missing permit0 stamp marker"
fi

# ──────────────────────────────────────────────────────────────────
#   Phase C: --uninstall restores backup
# ──────────────────────────────────────────────────────────────────
say
say "Phase C: --uninstall restores the most recent backup"
set +e
UNINSTALL_OUTPUT="$("$INSTALLER" --uninstall 2>&1)"
CODE=$?
set -e
assert_exit_zero "installer --uninstall succeeds" "$CODE"

RESTORED="$(current_value_decoded)"
if [[ "$RESTORED" == "$SENTINEL" ]]; then
    assert_pass "current value matches the sentinel after restore"
else
    assert_fail "restore did not match sentinel"
fi

# ──────────────────────────────────────────────────────────────────
#   Phase D: --uninstall on unstamped value refuses
# ──────────────────────────────────────────────────────────────────
say
say "Phase D: --uninstall on unstamped value refuses without --force"

# Sentinel is still in place from Phase C. Remove the backup we left
# behind so --uninstall can't quietly restore it after a refuse.
rm -f "$BACKUP_DIR"/managed-prefs-backup-*.toml 2>/dev/null || true

set +e
REFUSE_OUTPUT="$("$INSTALLER" --uninstall 2>&1)"
CODE=$?
set -e
assert_exit_neq_zero "--uninstall on unstamped value exits non-zero" "$CODE"

if [[ "$(current_value_decoded)" == "$SENTINEL" ]]; then
    assert_pass "sentinel value preserved after refused --uninstall"
else
    assert_fail "sentinel value was modified by refused --uninstall"
fi

# ──────────────────────────────────────────────────────────────────
#   Summary
# ──────────────────────────────────────────────────────────────────
say
say "═══ Summary ═══"
say "  passed: $PASS"
say "  failed: $FAIL"
[[ "$FAIL" == "0" ]]
