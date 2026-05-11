#!/usr/bin/env bash
#
# install-managed-prefs.sh — install (or remove) the permit0+Codex hook
# in macOS managed preferences so Codex auto-trusts it.
#
# Codex's hook trust taxonomy treats values written to user defaults
# under `com.openai.codex/requirements_toml_base64` as
# `legacy_managed_config_mdm` — always trusted, no /hooks review needed.
# This is the only unattended path on macOS that works without launching
# Codex's TUI first.
#
# Usage:
#   install-managed-prefs.sh [--force]       install a daemon-backed hook
#                                            (refuses if an unstamped value
#                                            is already present)
#   install-managed-prefs.sh --uninstall     remove permit0's value; if a
#                                            backup exists, restore the
#                                            most recent one
#   install-managed-prefs.sh --help          show this help
#
# Safety model:
#   • Before writing, we check whether `requirements_toml_base64` is
#     already set.
#   • If it's set and lacks our permit0 stamp comment, we refuse to
#     overwrite without --force (an enterprise MDM may legitimately own
#     that slot — we must not nuke it silently).
#   • Every overwrite saves the prior decoded TOML to
#     ~/.permit0/managed-prefs-backup-<YYYYMMDD-HHMMSS>.toml so recovery
#     is always possible.
#   • --uninstall restores the most recent backup by mtime.
#
# The stamp comment lives at the top of our written TOML:
#   # permit0-managed: installed by integrations/permit0-codex
# It survives because permit0's scripts round-trip the value via
# `defaults read | base64 -d`, not through Codex's TOML parser. Codex's
# parser strips it on load but never writes the value back to defaults,
# so the stamp lives in our managed-preferences blob indefinitely.
# DO NOT remove this stamp thinking it's dead — it is the ownership
# marker.

set -euo pipefail

# ── Constants ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PERMIT0_BIN="$REPO_ROOT/target/release/permit0"
PERMIT0_URL="${PERMIT0_URL:-http://127.0.0.1:9090}"

DEFAULTS_DOMAIN="com.openai.codex"
DEFAULTS_KEY="requirements_toml_base64"
STAMP="# permit0-managed: installed by integrations/permit0-codex"
BACKUP_DIR="$HOME/.permit0"

# ── Help ────────────────────────────────────────────────────────────
print_help() {
    cat <<'EOF'
install-managed-prefs.sh — install the permit0+Codex managed-prefs hook.

USAGE:
  install-managed-prefs.sh                    # install daemon-backed hook
  install-managed-prefs.sh --force            # overwrite (backs up first)
  install-managed-prefs.sh --uninstall        # remove permit0 value; restore last backup
  install-managed-prefs.sh --uninstall --force  # remove any value (no stamp check)
  install-managed-prefs.sh --help             # this message

CONFIG:
  PERMIT0_URL=http://127.0.0.1:9090           # daemon used by the hook

  The installed hook uses remote daemon mode so enforcement decisions land
  in the same permit0 server and dashboard. Start it with:
    cargo run -p permit0-cli -- serve --ui --port 9090

SAFETY:
  This script writes to macOS user defaults at
    com.openai.codex/requirements_toml_base64
  which is the same slot enterprise MDMs use for Codex policy. By
  default we REFUSE to overwrite a value we didn't install. Use
  --force to override (a timestamped backup is always written first to
  ~/.permit0/managed-prefs-backup-<TIMESTAMP>.toml).

VERIFY:
  defaults read com.openai.codex requirements_toml_base64 | base64 -d
EOF
}

# ── Arg parsing ─────────────────────────────────────────────────────
MODE=install
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --uninstall)  MODE=uninstall ;;
        --force)      FORCE=1 ;;
        -h|--help)    print_help; exit 0 ;;
        *)
            echo "error: unknown flag: $arg" >&2
            print_help
            exit 2
            ;;
    esac
done

# ── Helpers ─────────────────────────────────────────────────────────
read_current_decoded() {
    if defaults read "$DEFAULTS_DOMAIN" "$DEFAULTS_KEY" >/dev/null 2>&1; then
        defaults read "$DEFAULTS_DOMAIN" "$DEFAULTS_KEY" | base64 -d
        return 0
    fi
    return 1
}

is_stamped() {
    grep -qF "$STAMP" <<<"$1"
}

write_backup() {
    local body="$1"
    mkdir -p "$BACKUP_DIR"
    local ts="$(date +%Y%m%d-%H%M%S)"
    local path="$BACKUP_DIR/managed-prefs-backup-$ts.toml"
    # Avoid stomping if two backups happen in the same second.
    while [[ -e "$path" ]]; do
        sleep 1
        ts="$(date +%Y%m%d-%H%M%S)"
        path="$BACKUP_DIR/managed-prefs-backup-$ts.toml"
    done
    printf '%s' "$body" > "$path"
    echo "$path"
}

most_recent_backup() {
    local match
    match=$(ls -1t "$BACKUP_DIR"/managed-prefs-backup-*.toml 2>/dev/null | head -1)
    [[ -n "$match" ]] && echo "$match"
}

permit0_toml_body() {
    cat <<EOF
$STAMP
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "$PERMIT0_BIN hook --client codex --remote $PERMIT0_URL --unknown deny"
timeout = 30
statusMessage = "permit0 safety check"
EOF
}

# ── Install path ────────────────────────────────────────────────────
do_install() {
    if [[ ! -x "$PERMIT0_BIN" ]]; then
        echo "error: $PERMIT0_BIN not found or not executable" >&2
        echo "       run: cd $REPO_ROOT && cargo build --release" >&2
        exit 2
    fi

    local existing=""
    if existing=$(read_current_decoded); then
        if is_stamped "$existing"; then
            echo "permit0 managed-prefs value already installed — re-installing."
            local backup
            backup=$(write_backup "$existing")
            echo "  prior value backed up to: $backup"
        else
            if [[ "$FORCE" != "1" ]]; then
                echo "error: an UNSTAMPED managed-prefs value is already set under" >&2
                echo "       $DEFAULTS_DOMAIN/$DEFAULTS_KEY." >&2
                echo "       Refusing to overwrite — this may be your enterprise MDM's" >&2
                echo "       Codex policy. Re-run with --force to back it up and replace." >&2
                echo "       First 5 lines of the existing value:" >&2
                printf '%s\n' "$existing" | head -5 | sed 's/^/         | /' >&2
                exit 2
            fi
            echo "WARNING: overwriting unstamped existing value (--force given)."
            local backup
            backup=$(write_backup "$existing")
            echo "  prior value backed up to: $backup"
        fi
    fi

    local body
    body=$(permit0_toml_body)
    defaults write "$DEFAULTS_DOMAIN" "$DEFAULTS_KEY" -string "$(printf '%s' "$body" | base64)"

    echo "✓ permit0 managed-prefs installed."
    echo "  daemon URL: $PERMIT0_URL"
    echo
    cat <<EOF
Verify:
  defaults read $DEFAULTS_DOMAIN $DEFAULTS_KEY | base64 -d

Run the daemon before starting Codex:
  cd $REPO_ROOT && cargo run -p permit0-cli -- serve --ui --port 9090

Uninstall (and restore the most recent backup if any):
  $0 --uninstall
EOF
}

# ── Uninstall path ──────────────────────────────────────────────────
do_uninstall() {
    local existing=""
    if ! existing=$(read_current_decoded); then
        echo "(already absent — nothing to do)"
        exit 0
    fi

    if ! is_stamped "$existing"; then
        if [[ "$FORCE" != "1" ]]; then
            echo "error: managed-prefs value present but NOT stamped by permit0." >&2
            echo "       Refusing to delete. Re-run with --force to remove anyway." >&2
            echo "       First 5 lines:" >&2
            printf '%s\n' "$existing" | head -5 | sed 's/^/         | /' >&2
            exit 2
        fi
        echo "WARNING: deleting unstamped value (--force given)."
    fi

    defaults delete "$DEFAULTS_DOMAIN" "$DEFAULTS_KEY"
    echo "✓ removed managed-prefs value."

    local restore
    if restore=$(most_recent_backup); then
        local restored_body
        restored_body=$(cat "$restore")
        defaults write "$DEFAULTS_DOMAIN" "$DEFAULTS_KEY" \
            -string "$(printf '%s' "$restored_body" | base64)"
        echo "✓ restored most recent backup: $restore"
    else
        echo "  (no backup found in $BACKUP_DIR — nothing to restore)"
    fi
}

case "$MODE" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
esac
