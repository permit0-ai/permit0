# Review: 03 - Configuration Guide

**Reviewer:** Cursor Agent (600f2a13)
**Plan doc:** `docs/plans/codex-integration/03-configuration.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The Codex hook configuration examples mostly match the current Codex docs, including the feature flag, JSON/TOML shapes, matcher behavior, timeout, and project-local hook loading. The guide is misleading around remote session-aware behavior and around what `--unknown defer` does for uncovered tools.

## Detailed Findings

### Finding 1: Remote session-aware guidance is inaccurate

**Severity:** Major
**Location:** Step 3: Start the permit0 Daemon, Session-Aware Mode
**Claim:** In remote mode, the Codex hook passes `session_id` from stdin through to the daemon, and the daemon manages its own sessions.
**Reality:** The current hook remote body contains only `tool_name` and `parameters` in `crates/permit0-cli/src/cmd/hook.rs:435-443`. The daemon accepts `metadata.session_id`, but only uses it to create an empty `SessionContext` in `crates/permit0-cli/src/cmd/serve.rs:130-134`.
**Recommendation:** Change the guide to say remote mode does not currently provide cross-call session-history scoring, or add the missing metadata forwarding and daemon session persistence to v1.

### Finding 2: `--unknown defer` should be described as delegation, not governance

**Severity:** Minor
**Location:** Configure the PreToolUse Hook, Matcher Examples
**Claim:** Omitting the matcher catches all tool calls, and `--unknown defer` is a recommended setup.
**Reality:** Omitting the matcher does run the hook broadly, but unknown actions under `--unknown defer` are deliberately allowed to fall through to Codex's native behavior. The current pack surface is email-focused in `packs/permit0/email/pack.yaml:31-62`, so Bash and other built-ins will not be pack-scored unless additional packs are added.
**Recommendation:** Keep `--unknown defer` as a low-friction default, but call it delegation for uncovered tools. Recommend `--unknown deny` only for users who have packs/allowlists for all governed actions.

### Finding 3: Remote daemon-down behavior is stricter in the guide than current hook behavior

**Severity:** Minor
**Location:** Verification, Configuration Variants
**Claim:** The guide implies remote mode centrally enforces all decisions when the daemon is configured.
**Reality:** The current Claude remote transport error path maps daemon-unreachable to `HookOutput::ask`, not deny, in `crates/permit0-cli/src/cmd/hook.rs:417-428`. Codex does not support `ask` in `PreToolUse`, so the implementation must intentionally choose a Codex-specific block behavior for daemon-down cases.
**Recommendation:** Add a configuration warning: Codex remote mode must be tested with the daemon unavailable, and Codex implementation should fail closed with deny/exit 2 rather than inheriting Claude's ask-shaped transport error.

## Verified Claims

- Codex hooks are behind `[features] codex_hooks = true`, matching the public Codex hooks docs.
- Codex supports both `hooks.json` and inline `config.toml` hook definitions.
- Codex hook matchers are regex strings, and omitting matcher or using a wildcard matches supported events.
- Codex docs confirm `timeout` is in seconds and defaults to 600.
- Codex docs confirm `statusMessage` is optional.
- The plan's JSON and TOML hook nesting matches public Codex examples.
- `PERMIT0_REMOTE`, `PERMIT0_UNKNOWN`, `PERMIT0_SHADOW`, and `PERMIT0_CLIENT` are already read by the CLI path in `crates/permit0-cli/src/main.rs:239-264` and `crates/permit0-cli/src/cmd/hook.rs:491`.
- The `--remote` CLI help correctly says profile, packs dir, and db are ignored when the daemon governs evaluation in `crates/permit0-cli/src/main.rs:65-76`.

## Questions for the Author

1. Should the recommended Codex setup be local mode until remote session semantics are fixed?
2. Should the guide include an explicit fail-open warning for Codex hook crashes, malformed output, and timeouts?
