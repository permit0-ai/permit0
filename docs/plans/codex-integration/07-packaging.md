# 07 — Packaging: Hardening and Reconciliation

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** 02-implementation, 06-real-codex-testing
**Blocks:** None

## Goal

The Codex integration's demo tooling, configuration examples, and
developer test rig are **already committed** at
`integrations/permit0-codex/`. The `integrations/README.md` already lists
Codex in the CLI-hook integrations table. The original-plan
configuration-doc link is also already in place at the top of
`docs/plans/codex-integration/03-configuration.md`.

What's left is **hardening** — making the two scripts that mutate global
macOS state (`install-managed-prefs.sh` and `dev-test-rig/cleanup`) safe
on a Mac where someone else (e.g. an enterprise MDM) already owns
`com.openai.codex/requirements_toml_base64`. Today they would silently
clobber any pre-existing value, which is a real correctness/safety bug.

This is NOT a file-creation or file-move plan. The layout is done.

## Current state (verified 2026-05-10)

```
integrations/permit0-codex/
├── README.md                          ✓ exists
├── examples/
│   ├── config.toml.example            ✓ exists
│   ├── hooks.json.example             ✓ exists
│   └── install-managed-prefs.sh       ✗ unsafe clobber (Change 1)
└── dev-test-rig/
    ├── README.md                      ✓ exists
    ├── codex-demo                     ✗ hard-coded codex path (Change 3)
    ├── watch                          ✓ exists
    ├── cleanup                        ✗ unsafe clobber (Change 2)
    ├── wrap-permit0.sh                ✓ exists
    ├── mock-gmail-mcp.py              ✓ exists
    └── _watch_render.py               ✓ exists

integrations/README.md                 ✓ Codex in CLI-hook table
docs/plans/codex-integration/03-configuration.md
                                       ✓ already links to examples/
scripts/test-codex-hook.sh             ✓ 9-case synthetic smoke test
scripts/test-managed-prefs-roundtrip.sh  ✗ doesn't exist yet (Change 5)
```

## Changes

### Change 1: Safe managed-preferences installer (P0 — blocker)

**File:** `integrations/permit0-codex/examples/install-managed-prefs.sh`

#### Why

`requirements_toml_base64` is the real macOS managed-config slot that
enterprise MDMs use to ship hardened Codex policy. The current installer
overwrites it unconditionally. On a managed Mac this would silently
destroy the org's policy and replace it with permit0's demo hook. That's
unacceptable behavior for a script shipped in the repo.

#### Requirements

1. **Detect existing value.** Before writing, check whether the key is
   already set via
   `defaults read com.openai.codex requirements_toml_base64 2>/dev/null`.

2. **Stamp permit0 ownership.** When the script does install, the TOML
   body MUST begin with the marker line

       # permit0-managed: installed by integrations/permit0-codex

   Detection elsewhere checks for this comment to distinguish "ours"
   from "someone else's."

   *Why this works:* the comment survives because permit0's scripts
   round-trip the value through `defaults read | base64 -d`, not through
   Codex's TOML parser. Codex's parser will strip the comment when it
   loads the requirements, but it never writes the value back to
   defaults, so the stamp lives in our managed-preferences blob
   indefinitely. Do not "clean up" the comment thinking it's dead — it
   is the ownership marker.

3. **Refuse without `--force`.** If a value exists AND lacks the
   permit0 stamp, the installer prints a warning (showing the first 5
   lines of the decoded TOML) and exits with status 2. Passing
   `--force` proceeds anyway after writing a backup.

4. **Backup before overwrite.** On `--force` (or when the existing
   value IS already permit0-stamped, since a re-install also overwrites),
   save the prior decoded TOML to

       ~/.permit0/managed-prefs-backup-<YYYYMMDD-HHMMSS>.toml

   The timestamp goes in the **filename** so successive `--force` runs
   create distinct backups instead of overwriting each other.

5. **`--uninstall` flag.** When passed:
   - If the current value bears the permit0 stamp → delete the key.
   - Then if any `~/.permit0/managed-prefs-backup-*.toml` files exist,
     restore the **most recent** one (by mtime) via
     `defaults write ... -string "$(cat ... | base64)"`. Tell the user
     which backup was restored.
   - If the current value lacks the permit0 stamp → print
     "managed-prefs value present but not stamped by permit0; refusing
     to delete. Use `--force` if you really want to remove it." and exit
     non-zero.
   - If the key is absent → print "(already absent)" and exit 0.

6. **Help text.** Add a `--help` flag that prints usage including
   `--force` and `--uninstall`.

### Change 2: Safe cleanup in dev-test-rig (P0 — blocker)

**File:** `integrations/permit0-codex/dev-test-rig/cleanup`

#### Why

Same root cause as Change 1. The current cleanup does an unconditional
`defaults delete com.openai.codex requirements_toml_base64`, which would
also wipe an org's MDM-installed policy if the demo was run on a managed
Mac.

#### Requirements

1. Read the existing value (if any) and decode it.
2. **If the value bears the permit0 stamp** → delete the key.
3. **If the value exists but lacks the stamp** → print a warning showing
   the first 5 lines of the decoded TOML, refuse to delete, and exit
   non-zero. Document that `--force` overrides this guard.
4. **If `--force` is passed** → delete the key unconditionally (this is
   the only way to recover from a stale unstamped value).
5. **If the key is absent** → print "(already absent)" as today.
6. After deletion, if `~/.permit0/managed-prefs-backup-*.toml` exists,
   inform the user with the same "restore via install-managed-prefs.sh
   --uninstall" path so they have one canonical way to recover backups.

### Change 3: Codex binary path fallback in codex-demo (P2 — UX)

**File:** `integrations/permit0-codex/dev-test-rig/codex-demo`

The current script hard-codes `/Applications/Codex.app/Contents/Resources/codex`.
This is the verified path for the macOS desktop app, but users who
installed Codex via `npm install -g @openai/codex` (or on Linux) hit a
silent failure.

Revised resolution order (most portable first):

```bash
CODEX="${CODEX:-}"
if [[ -z "$CODEX" ]]; then
    if command -v codex >/dev/null 2>&1; then
        CODEX="$(command -v codex)"
    elif [[ -x /Applications/Codex.app/Contents/Resources/codex ]]; then
        CODEX=/Applications/Codex.app/Contents/Resources/codex
    else
        echo "error: Codex binary not found." >&2
        echo "  Set CODEX=/path/to/codex or install Codex." >&2
        exit 2
    fi
fi
```

`$CODEX` env override remains the highest-priority option. PATH lookup
comes before the bundle path because it's portable beyond macOS; on
macOS both typically resolve to the same binary anyway.

### Change 4: Round-trip integration test (P1 — test)

**File:** `scripts/test-managed-prefs-roundtrip.sh` (new)

A script that mutates global system state needs an integration test.
The test must:

1. **Save the live value before starting** so the test never destroys
   the developer's real config. Stash it in
   `/tmp/permit0-mp-test-preserved-<pid>.b64` and restore on EXIT trap
   (success or failure).

2. **Phase A — refuse to clobber:**
   - Plant a sentinel value (e.g.
     `# fake-mdm\nfeatures.hooks = false\n` base64'd) via `defaults write`.
   - Run `install-managed-prefs.sh` without `--force`; assert exit
     status ≠ 0 and stderr mentions "stamp".
   - Assert the sentinel value is unchanged after the failed install.

3. **Phase B — `--force` backs up and overwrites:**
   - With the sentinel still in place, run with `--force`.
   - Assert exit status = 0.
   - Assert `~/.permit0/managed-prefs-backup-*.toml` now exists and its
     content matches the sentinel.
   - Assert the new value contains the permit0 stamp marker.

4. **Phase C — `--uninstall` restores backup:**
   - Run `install-managed-prefs.sh --uninstall`.
   - Assert the live value matches the sentinel again (backup
     restored).
   - Assert exit status = 0.

5. **Phase D — uninstall on unstamped value refuses:**
   - With the sentinel in place (no permit0 stamp), run `--uninstall`.
   - Assert exit status ≠ 0 and the value is preserved.

6. Cleanup runs via EXIT trap regardless of outcome.

The script gates on macOS (`uname -s` = Darwin); otherwise prints
"skipped on non-macOS" and exits 0 so CI on Linux is unaffected.

## Dropped from the plan

- **Original Change 4 (link from `03-configuration.md` to examples/):**
  Already present at the top of `03-configuration.md` since the
  integrations folder was created. Verified 2026-05-10. No further
  change needed.

- **README.md table update:** Already done. Codex is in the CLI-hook
  table at `integrations/README.md`. No further change needed.

- **File creation/move:** Already done.

- **`.gitignore` comment for `/tmp/permit0-codex-test/`:** Adds no value;
  the dir is outside the repo tree.

## Acceptance criteria

- [ ] `install-managed-prefs.sh` refuses to overwrite an unstamped
      existing `requirements_toml_base64` value without `--force` (exit
      ≠ 0, warning shown)
- [ ] `install-managed-prefs.sh` stamps its TOML body with
      `# permit0-managed: installed by integrations/permit0-codex`
- [ ] `install-managed-prefs.sh` with `--force` creates a timestamped
      backup at `~/.permit0/managed-prefs-backup-<YYYYMMDD-HHMMSS>.toml`
- [ ] `install-managed-prefs.sh --uninstall` deletes only permit0-stamped
      values and restores the most-recent backup (by mtime)
- [ ] `install-managed-prefs.sh --help` documents `--force` and
      `--uninstall`
- [ ] `dev-test-rig/cleanup` refuses to delete unstamped values, accepts
      `--force` to override
- [ ] `dev-test-rig/codex-demo` discovers Codex via `$CODEX`, then
      PATH, then the macOS app-bundle path; exits 2 with a helpful
      message if none found
- [ ] `scripts/test-managed-prefs-roundtrip.sh` exists and passes on
      macOS (gracefully skips on Linux)
- [ ] `scripts/test-codex-hook.sh` still passes (unchanged)
- [ ] `cargo test --all-targets` still passes (no Rust changes)

## Deferred

- Codex plugin manifest (`plugin.toml`) for `codex plugin install permit0` (v3)
- Codex Cloud sidecar packaging (v3, see `05-limitations.md`)
- Adding `[mcp_servers]` to managed requirements (schema unresolved in
  Codex 0.130)
- npm/pip package publication (shape #2 doesn't need one)
