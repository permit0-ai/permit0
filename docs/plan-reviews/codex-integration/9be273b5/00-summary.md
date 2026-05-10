# Plan Review Summary: codex-integration packaging

**Reviewer:** Cursor Agent (9be273b5)
**Review date:** 2026-05-10
**Plan location:** `docs/plans/codex-integration/`

## Overall Verdict

REQUEST CHANGES

## Key Findings

- Critical: The managed-preferences packaging plan does not require preserving an existing `com.openai.codex/requirements_toml_base64` value before overwriting or uninstalling it. The existing scripts write and delete that global user preference directly, which can remove unrelated managed requirements and silently disable other trusted hooks.
- Major: The plan is partially stale: `integrations/permit0-codex/` and the proposed files already exist, while the plan still describes creating/moving them from `/tmp/permit0-codex-test/`.
- Major: The plan's `integrations/README.md` change conflicts with the current README structure, which deliberately separates publishable packages from CLI-hook integrations. Adding Codex to the package table would contradict the README's own "real package" definition.
- Major: The required `install-managed-prefs.sh --uninstall` flow is not present in the existing installer; uninstall is documented as a separate `defaults delete` command or dev-test-rig `cleanup` script.
- Minor: The plan asks for a ready-to-use examples pointer in `03-configuration.md`, but that pointer is not present in the current plan doc.

## Statistics

| Metric | Count |
|--------|-------|
| Plan docs reviewed | 1 |
| Critical findings | 1 |
| Major findings | 4 |
| Minor findings | 3 |
| Nits | 0 |
| Verified claims | 11 |
| Open questions | 4 |

## Recommendation

Do not proceed with this packaging plan as written. Convert it from a "create these files" plan into a reconciliation plan against the already-present `integrations/permit0-codex/` tree, and add explicit managed-preferences backup/restore requirements before promoting the unattended install path.

The file layout itself is sensible and mostly already implemented. The remaining work is to tighten safety semantics for installer cleanup, align the plan with the current integration README taxonomy, and update cross-links from the configuration docs.
