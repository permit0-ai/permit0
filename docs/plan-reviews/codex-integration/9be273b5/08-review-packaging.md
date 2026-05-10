# Review: 07 - Packaging: Repo Layout and Reusable Artifacts

**Reviewer:** Cursor Agent (9be273b5)
**Plan doc:** `docs/plans/codex-integration/07-packaging.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The proposed repository shape is sensible: a non-publishable `integrations/permit0-codex/` folder for docs, examples, and a dev rig matches the current CLI-hook integration model. The plan is now partly stale against the working tree, and it misses a serious safety requirement around overwriting and deleting Codex's managed requirements preference.

## Detailed Findings

### Finding 1: Managed-preferences install/uninstall can clobber unrelated Codex requirements

**Severity:** Critical
**Location:** Change 2, Change 3, Acceptance criteria
**Claim:** `install-managed-prefs.sh` should install `requirements_toml_base64`, and `cleanup` or `--uninstall` should undo it.
**Reality:** The current installer writes `com.openai.codex requirements_toml_base64` directly in `integrations/permit0-codex/examples/install-managed-prefs.sh:56-57`. The demo launcher also overwrites the same key in `integrations/permit0-codex/dev-test-rig/codex-demo:74-75`. The cleanup script deletes the key if present in `integrations/permit0-codex/dev-test-rig/cleanup:11-17`. None of these paths checks whether the user already had managed requirements installed, backs up the prior value, or restores only if permit0 installed it. For users with existing enterprise-managed hooks or requirements, this can silently remove other governance controls.
**Recommendation:** Add a plan requirement to detect an existing `requirements_toml_base64`, store a backup or refuse without `--force`, stamp permit0-installed state, and restore the previous value on uninstall/cleanup. Do not delete the key blindly.

### Finding 2: The plan is stale because the integration folder already exists

**Severity:** Major
**Location:** Goal, Layout, Changes 1-3
**Claim:** Move the Codex integration tooling from `/tmp/permit0-codex-test/` into version control at `integrations/permit0-codex/`.
**Reality:** `integrations/permit0-codex/` already exists with `README.md`, the three example files, and the seven dev-test-rig files. The actual file list matches the intended layout from `docs/plans/codex-integration/07-packaging.md:21-41`, as confirmed by `integrations/permit0-codex/README.md:153-168` and the filesystem. `/tmp/permit0-codex-test/` also still exists, but now contains runtime state such as `events.log`, `inv-*`, SQLite files, Codex auth/cache links, and session data.
**Recommendation:** Rewrite the plan as a verification/follow-up plan instead of a creation/move plan. Make clear which artifacts are already committed and which `/tmp` files must remain runtime-only.

### Finding 3: The proposed integrations README update conflicts with current README taxonomy

**Severity:** Major
**Location:** Change 4
**Claim:** Add Codex to the main `Package | Framework | Language | Install | Pattern` table.
**Reality:** The current `integrations/README.md` says integrations are "real package[s] you can depend on" in `integrations/README.md:1-3`, then has a separate "CLI-hook integrations" section for integrations with no separate library in `integrations/README.md:11-20`. Codex is already listed there at `integrations/README.md:17-20` and described in the framework list at `integrations/README.md:30-34`. Putting Codex into the package table with no language/package would undermine the distinction the README now makes.
**Recommendation:** Update the plan to preserve the current two-section README structure. If the goal is discoverability, improve the existing CLI-hook table rather than moving Codex into the package table.

### Finding 4: The requested `--uninstall` flag is not present in the installer

**Severity:** Major
**Location:** Change 2
**Claim:** `install-managed-prefs.sh` includes a `--uninstall` flag to undo.
**Reality:** The current installer documents only the install command and a manual `defaults delete` uninstall in `integrations/permit0-codex/examples/install-managed-prefs.sh:11-17` and `integrations/permit0-codex/examples/install-managed-prefs.sh:61-78`. A separate dev-test-rig cleanup script exists, but it is not the user-facing example installer and it deletes the global preference unconditionally.
**Recommendation:** Either implement and document `install-managed-prefs.sh --uninstall` with safe restore semantics, or change the plan to say uninstall is handled by a separate cleanup path.

### Finding 5: `03-configuration.md` does not yet point to the examples directory

**Severity:** Minor
**Location:** Change 5
**Claim:** Add a note at the top of `03-configuration.md` pointing users to `integrations/permit0-codex/examples/`.
**Reality:** The current `docs/plans/codex-integration/03-configuration.md` starts with prerequisites and hook configuration, but contains no pointer to `integrations/permit0-codex/examples/`. The examples themselves exist at `integrations/permit0-codex/examples/config.toml.example`, `integrations/permit0-codex/examples/hooks.json.example`, and `integrations/permit0-codex/examples/install-managed-prefs.sh`.
**Recommendation:** Keep this change in the plan and make it part of acceptance, since it is one of the main discoverability benefits of packaging the examples.

### Finding 6: The no-op `.gitignore` comment is not useful acceptance work

**Severity:** Minor
**Location:** Change 6
**Claim:** Add a `.gitignore` comment documenting that runtime data stays under `/tmp/permit0-codex-test/`.
**Reality:** The current `.gitignore` has no Codex section in `.gitignore:1-46`, and the existing scripts already default runtime state to `/tmp/permit0-codex-test/` through `TRACE_DIR` in `integrations/permit0-codex/dev-test-rig/codex-demo:25-27`, `integrations/permit0-codex/dev-test-rig/wrap-permit0.sh:31-33`, and `integrations/permit0-codex/dev-test-rig/watch:11-13`. A comment-only `.gitignore` change does not enforce anything and can become stale.
**Recommendation:** Drop this change or replace it with actual safeguards in scripts/tests that fail if runtime artifacts are written under `integrations/permit0-codex/`.

### Finding 7: The demo launcher has a hard-coded Codex binary path

**Severity:** Minor
**Location:** Acceptance criteria
**Claim:** `bash integrations/permit0-codex/dev-test-rig/codex-demo` launches Codex with the hook active.
**Reality:** The current launcher requires `/Applications/Codex.app/Contents/Resources/codex` in `integrations/permit0-codex/dev-test-rig/codex-demo:25`. That matches the verified macOS app setup, but it will fail for users who installed Codex via `npm install -g @openai/codex`, which the earlier configuration guide still mentions in `docs/plans/codex-integration/03-configuration.md:16-20`.
**Recommendation:** Add acceptance language requiring either PATH discovery/fallback (`command -v codex`) or explicit documentation that the dev-test-rig supports only the macOS app binary path unless `CODEX` is edited.

## Verified Claims

- `integrations/permit0-codex/` exists with `README.md`, `examples/`, and `dev-test-rig/`, matching the intended high-level layout.
- The examples directory contains `config.toml.example`, `hooks.json.example`, and `install-managed-prefs.sh`.
- The dev-test-rig contains `README.md`, `codex-demo`, `watch`, `cleanup`, `wrap-permit0.sh`, `mock-gmail-mcp.py`, and `_watch_render.py`.
- Dev-test-rig runtime state is directed to `/tmp/permit0-codex-test/` by default via `TRACE_DIR` in the shell/Python scripts.
- `codex-demo` and `wrap-permit0.sh` derive `REPO_ROOT` relative to their own location, matching the plan's requirement to avoid hard-coded repo paths.
- `wrap-permit0.sh` invokes `$REPO_ROOT/target/release/permit0` with `hook --client codex --packs-dir "$REPO_ROOT/packs" --unknown defer`.
- `mock-gmail-mcp.py` exposes a fake `gmail_send` MCP tool and writes logs under `PERMIT0_TRACE_DIR`.
- `scripts/test-codex-hook.sh` exists and contains nine synthetic smoke cases for `permit0 hook --client codex`.
- `crates/permit0-cli/src/cmd/hook.rs` already contains `ClientKind::Codex`, `OutputFormat::Codex`, Codex empty-stdout emission, and a fail-closed Codex wrapper.
- `crates/permit0-cli/tests/cli_tests.rs` already contains Codex process-level tests for unknown defer/deny, malformed stdin, empty stdin, remote daemon down, shadow mode, minimal payloads, and forbidden allow output.
- The current `integrations/README.md` already links to `permit0-codex/` in a dedicated CLI-hook integrations table.

## Questions for the Author

1. Is `07-packaging.md` intended to describe future work, or should it be updated to reflect the already-committed `integrations/permit0-codex/` tree?
2. Should the managed-preferences installer refuse to run when an existing `requirements_toml_base64` value is present, or should it merge/backup/restore that value?
3. Should Codex remain in the README's CLI-hook integrations section, or do you want to redefine the main package table to include non-package integrations?
4. Should the dev-test-rig support PATH-based Codex installs, or is the macOS app binary path the only supported live-demo environment?
