# Review: 03 — Configuration Guide

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/03-configuration.md`
**Review date:** 2026-05-10

## Verdict

APPROVE WITH COMMENTS

## Summary

The configuration guide is comprehensive and well-organized: covers
both JSON and TOML formats, lists local/remote/shadow/calibration
variants, and documents the env-var overrides. The major issue is the
session-aware-mode subsection contradicts the implementation plan and
limitations doc. There are also a handful of unverified version
claims, an absolute-path warning that's missing for one example, and
the "Verification" steps would be hard for a user to actually carry
out without more guidance.

## Detailed Findings

### Finding 1: Session-aware-remote claim contradicts implementation reality

**Severity:** Major
**Location:** "Session-Aware Mode" subsection, last paragraph
**Claim:** "Note: `--db` is ignored when `--remote` is set (the daemon
manages its own sessions). For session-aware remote mode, the Codex
hook passes the `session_id` from the stdin payload through to the
daemon."
**Reality:** The hook does NOT pass `session_id` to the daemon today
(`crates/permit0-cli/src/cmd/hook.rs:440-444` POSTs only `tool_name`
and `parameters`), and the implementation plan
(`02-implementation.md`) does not introduce metadata-forwarding for
the remote POST. `05-limitations.md` Section 7 explicitly defers
this to v2. So the configuration doc's promise is false today. A
user following this doc and starting Codex with `--remote` would
see no session-aware behavior at all — every call would be evaluated
against a stateless daemon (or worse, against whatever ambient state
the daemon happens to have for an unrelated request).
**Recommendation:** Replace the second sentence with: "v1 limitation:
when `--remote` is set, the Codex hook does NOT forward
`session_id`. Cross-call session pattern detection is therefore
unavailable in remote mode. Use local mode (omit `--remote`) for
session-aware Codex governance. See `05-limitations.md` §7."

### Finding 2: Network-access guidance is contradictory

**Severity:** Major
**Location:** "Network Access Requirement" subsection
**Claim:** Two options offered: (1) enable `network_access = true`
in `[sandbox_workspace_write]`, (2) "the hook binary itself is not
sandboxed (only tool commands are), so localhost access should
work without this setting in most configurations. Test with
`--shadow` first to verify."
**Reality:** Without access to Codex's source, I can't verify which
of these is correct. But these two options are stated as alternatives
when in fact only one will be true for any given Codex version. If
hooks ARE sandboxed in `workspace-write` mode, option 2 fails closed
and option 1 is required; if they ARE NOT sandboxed, option 1 is
unnecessary. Telling the user "test with --shadow first to verify"
is operationally hostile — shadow mode for Codex hasn't been
validated either, per Finding 2 of `02-review-implementation.md`.
**Recommendation:** Either (a) cite the Codex docs that document
hook sandboxing semantics, then state which option is actually
needed, or (b) instruct the user to use option 1 unconditionally
("Enabling `network_access = true` in
`[sandbox_workspace_write]` is the safe default; the alternative
relies on hook subprocesses being unsandboxed, which the Codex docs
do not guarantee").

### Finding 3: "Codex 0.110+" version claim is not citation-backed

**Severity:** Minor
**Location:** "Prerequisites" item 3
**Claim:** "Verify Codex hooks are supported (requires Codex 0.110+)"
**Reality:** I cannot verify this against any source available in
this codebase. If the version is wrong, users will install a Codex
that doesn't have hook support, hook config will be silently
ignored, and they'll think permit0 is broken.
**Recommendation:** Cite the Codex release notes or PR that added
hook support, e.g. "(see [openai/codex#NNNN](https://github.com/openai/codex/pull/NNNN))".
If unverified, either remove the version pin or mark it "TBD —
confirm Codex version once hooks docs are public."

### Finding 4: `--shadow` example uses absolute path inconsistently

**Severity:** Minor
**Location:** "Shadow Mode" JSON snippet, line `"command": "/abs/path/to/permit0 hook --client codex --remote http://127.0.0.1:9090 --shadow"`
**Claim:** Use absolute paths.
**Reality:** All other examples include `--unknown defer`. This one
omits it. With no `--unknown` set, the hook defaults to
`UnknownMode::Defer` (`hook.rs:138`). For Codex, defer means "exit
0 with empty stdout" per Change 6 — so the behavior is the same as
explicit `--unknown defer`, but the inconsistency makes the user
wonder if shadow mode requires a different unknown policy.
**Recommendation:** Either add `--unknown defer` for consistency or
add a one-line note: "(`--unknown` is omitted here; defaults to
`defer`)."

### Finding 5: Calibration mode requires extra hop the docs don't show

**Severity:** Minor
**Location:** "Calibration Mode" subsection
**Claim:** Hook config is the same `--remote` setup; calls block
until a human decides in the dashboard.
**Reality:** `crates/permit0-cli/src/cmd/serve.rs:408-508` shows
calibration mode requires the request to wait on an
`ApprovalManager` channel; if the timeout (default not specified
here) expires, the request returns HTTP 408 and the hook would
treat that as `RemoteError::HttpStatus` (deny). For Codex, this
manifests as a deny envelope with "permit0 daemon error (HTTP 408)"
rather than "your call was held for review and timed out." Users
won't understand the failure mode.
**Recommendation:** Add: "Calibration timeout: the daemon's
ApprovalManager has a default timeout; if no human acts within
that window, the hook receives HTTP 408 and emits a deny envelope.
Set the timeout via the daemon's config (see ApprovalManager docs)
or have an operator standing by."

### Finding 6: Verification steps are not actionable

**Severity:** Minor
**Location:** "Verification" section
**Claim:** "Start Codex … Ask it to do something … Check stderr or
the dashboard."
**Reality:** Codex's stderr is not the hook's stderr in the
default invocation — the hook subprocess's stderr is captured by
Codex and may or may not surface to the user. The plan doesn't
explain where to look. Without concrete log path or
"check the file at X", users can't verify.
**Recommendation:** Either link to a Codex doc explaining where
hook stderr goes, or describe the dashboard verification step in
detail (e.g. "Open `http://localhost:9090/ui/` and click the
'Recent Decisions' tab; the gmail_send call should appear within
2 seconds with permit0's verdict.").

### Finding 7: Per-project-hook ergonomics example is misleading

**Severity:** Nit
**Location:** "Project-Local Hooks" subsection
**Claim:** Use `--unknown deny` for project-local hooks for
"whitelist-only governance: every tool without a pack is blocked."
**Reality:** This is correct, but the example doesn't show the
trade-off: every Codex built-in tool (Bash, apply_patch, etc.)
without a permit0 pack will be blocked, including read-only
operations the user expects to "just work." Without knowing which
permit0 packs are installed, a developer enabling this in
their repo will likely be unable to do basic tasks. This needs
a warning.
**Recommendation:** Add: "Warning: `--unknown deny` blocks every
tool without a permit0 pack. Verify your installed packs cover
the tools your project uses (e.g. `Bash`, `apply_patch`,
`WebSearch`) before enabling this in a daily-driver project."

### Finding 8: MCP server config example uses placeholder paths

**Severity:** Nit
**Location:** "MCP Server Configuration" subsection
**Claim:** `command = "/abs/path/to/permit0-gmail-mcp"`.
**Reality:** This is a placeholder that the user must replace.
The doc could show a more realistic example, e.g. how to find
the binary in a typical install.
**Recommendation:** Add a sentence: "After `cargo build --release`,
the gmail/outlook MCP binaries are at
`./target/release/permit0-gmail-mcp` and `./target/release/permit0-outlook-mcp`."
(Verify the binary names against the workspace before merging.)

## Verified Claims

- The hook command pattern `permit0 hook --client codex --remote
  http://127.0.0.1:9090 --unknown defer` is syntactically correct
  given the proposed `Codex` ClientKind variant. The dispatcher at
  `crates/permit0-cli/src/main.rs:229-277` handles `--client`,
  `--remote`, `--unknown` flags with env-var fallback.
- The dashboard mounts at `/ui/` when `serve --ui` is set; verified
  at `crates/permit0-cli/src/cmd/serve.rs:672-675`.
- Environment variable overrides table (`PERMIT0_REMOTE`,
  `PERMIT0_UNKNOWN`, `PERMIT0_SHADOW`, `PERMIT0_CLIENT`) accurately
  reflect the dispatcher logic at `main.rs:241-265` and
  `hook.rs:491` (for `PERMIT0_SHADOW`).
- `--db` is correctly described as ignored when `--remote` is set
  — verified at `hook.rs:512-516` which prints a warning to stderr.
- Calibration mode does require `--ui` (verified at
  `crates/permit0-cli/src/main.rs:288`: `ui || calibrate`), so the
  example `serve --ui --calibrate --port 9090` is correct (the
  `--ui` is redundant but doesn't hurt).
- The matcher regex examples are syntactically valid for Rust regex
  (typical, no plan-introduced features).

## Questions for the Author

1. What's the verified minimum Codex version with hook support? See
   Finding 3.
2. Are Codex hook subprocesses sandboxed in `workspace-write` mode?
   Resolving Finding 2 requires this answer.
3. Should the configuration doc include an "Uninstall / disable"
   section for users who want to remove permit0 from Codex without
   manually editing the JSON/TOML? Many users don't know that
   removing the hook config restores default Codex behavior.
4. The MCP server configuration assumes the user wants Gmail/Outlook
   MCP servers. Should the doc say "skip this section if you only
   care about governing Bash/apply_patch"?
