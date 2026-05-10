# Review: 02 — Implementation Plan

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/02-implementation.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

Changes 1–5 (ClientKind, OutputFormat, HookInput expansion, codex_output,
session ID derivation) are well-specified and would compile largely as
written. Change 6 ("Update run() function") is the load-bearing change
and the plan is hand-wavy about it — particularly for the remote-mode
output path, where `result.permission` is referenced but doesn't exist
in scope. Several integration points (shadow mode, --unknown ask, error
fail-safes) need explicit code sketches.

## Detailed Findings

### Finding 1: Remote-mode `codex_output(result.permission, ...)` cannot work as written

**Severity:** Critical
**Location:** Change 6, "Update `run()` function" snippet, the
`OutputFormat::Codex` arm
**Claim:**
```rust
OutputFormat::Codex => {
    match codex_output(result.permission, &reason) {
        Some(json) => println!("{json}"),
        None => { /* exit 0, empty stdout = allow */ }
    }
}
```
**Reality:** `result` and `reason` are constructed in the local-mode
block (`crates/permit0-cli/src/cmd/hook.rs:583, 615-638`). In remote
mode (lines 511-542), the existing code returns `(HookOutput, bool)`
from `evaluate_remote_with_meta` — there is no `result.permission`,
no `result.norm_action`, and `reason` is embedded inside the
`HookOutput`. The proposed snippet would not compile.

The plan's "Remote mode" subsection further confuses this:
> The remote path (`evaluate_remote_with_meta`) returns a `HookOutput`
> today. For Codex, the same remote response is translated through
> `codex_output` instead of `remote_response_to_hook_output`. The HTTP
> call itself is unchanged.

But `codex_output` takes a `Permission`, not a `RemoteCheckResponse`.
There's no specified function that converts the remote response to a
`Permission` for Codex.
**Recommendation:** Add Change 4a: a sibling helper
```rust
fn codex_output_from_remote(resp: &RemoteCheckResponse) -> Option<String>
```
that mirrors `remote_response_to_hook_output` but produces a Codex
envelope or `None`. Show the actual run() block for both local and
remote paths. Without this, an implementer will either (a) get the
compiler error, or (b) reach for `match output.hook_specific_output.permission_decision`,
which round-trips Permission → string → string and is fragile.

### Finding 2: Shadow mode for Codex is described in prose but not in code

**Severity:** Major
**Location:** Change 6, "Shadow mode" subsection
**Claim:** "For Codex, 'always allow' means exit 0 with empty stdout
(instead of printing the Claude allow envelope)."
**Reality:** The existing shadow path emits `HookOutput::allow()` and
unconditionally `println!("{}", serde_json::to_string(&final_output)?)`.
For Codex, that JSON envelope contains
`"permissionDecision":"allow"`, which `01-protocol.md` warns is
explicitly rejected by Codex. So shadow + Codex would emit exactly the
forbidden output. The plan's prose says "exit 0 with empty stdout" but
the snippet in Change 6 doesn't show the conditional skip. This will
silently break shadow mode for Codex unless an implementer remembers
the prose.
**Recommendation:** Show the actual updated shadow code, e.g.:
```rust
if shadow {
    let (decision, reason) = hook_output_summary(&output);
    if decision != "allow" {
        eprintln!("[permit0 shadow] WOULD {} ...", decision.to_uppercase());
    }
    match format {
        OutputFormat::ClaudeCode => {
            println!("{}", serde_json::to_string(&HookOutput::allow())?);
        }
        OutputFormat::Codex => { /* skip stdout entirely */ }
    }
    return Ok(());
}
```
Or refactor to compute "the value to print" once and only branch on
whether to print.

### Finding 3: `apply_unknown_policy` is not Codex-aware

**Severity:** Major
**Location:** Change 6, "Unknown mode" subsection
**Claim:** `UnknownMode::Ask` → "deny envelope with reason (Codex has
no 'ask')"; `UnknownMode::Defer` → exit 0 with empty stdout.
**Reality:** `apply_unknown_policy` (`hook.rs:359-374`) operates on
`HookOutput`, not on `Permission` or format. It currently does:
- Ask + Ask mode → keep as `HookOutput::ask(...)` (Claude envelope)
- Ask + Defer mode → `HookOutput::defer()` (Claude envelope, no
  permissionDecision)
- Ask + Deny mode → `HookOutput::deny(...)` (Claude envelope)
- Ask + Allow mode → `HookOutput::allow(...)` (Claude envelope —
  forbidden under Codex)

These rewrites all produce Claude-shaped envelopes. For Codex, the
function needs to either (a) take an OutputFormat argument and rewrite
to Codex-shaped outputs, or (b) be called BEFORE the OutputFormat
branch and the Codex serializer needs to round-trip a HookOutput back
into Codex shape. The plan doesn't choose. Either way, Defer + Codex
must explicitly skip stdout (no envelope at all), and Allow + Codex
must NOT produce `permissionDecision: "allow"`.
**Recommendation:** Add a Change 5a — refactor `apply_unknown_policy`
to take `format: OutputFormat` and produce `Option<String>` (the JSON
to write, or None for "don't write"). Show the four-arm match for
Codex explicitly.

### Finding 4: Stdin parser does not gracefully handle Codex's `null` `transcript_path`

**Severity:** Minor
**Location:** Change 3, "Codex input deserialization"
**Claim:** All new fields are `#[serde(default)] Option<...>`.
**Reality:** `Option<String>` accepts `null` and absent keys, so
basic deserialization works. But if Codex sends `"transcript_path":
""` (empty string), the field becomes `Some("")` — and then the
session-ID derivation logic must treat empty strings the same as
None. The proposed `derive_session_id_for_format` correctly does
`stdin_session_id.filter(|s| !s.is_empty())` for `session_id`, but
the plan should call out empty-string handling as a deliberate
contract for ALL Codex string fields, not just session_id.
**Recommendation:** Add a brief note in Change 3: "Empty-string
values from Codex are treated equivalent to absent fields. The
HookInput struct stores `Option<String>`; downstream consumers
filter `.filter(|s| !s.is_empty())`."

### Finding 5: Help text update misses `openclaw`

**Severity:** Minor
**Location:** Change 7, updated `--client` help text
**Claim:** Help reads "Supported: claude-code (default), claude-
desktop, openclaw, codex, raw."
**Reality:** The current help text in
`crates/permit0-cli/src/main.rs:62` reads "Supported: claude-code
(default), claude-desktop, raw" — `openclaw` is missing today, and
the Codex plan correctly fixes that. Good. But the plan should call
out that this is a pre-existing inconsistency the plan happens to
fix, rather than an additive change. Otherwise a reviewer will think
"openclaw" is new.
**Recommendation:** Add to Change 7: "(Note: `openclaw` is missing
from current help text — this is a pre-existing inconsistency. This
PR fixes it incidentally.)"

### Finding 6: "Files NOT changed" claim about `serve.rs` is incomplete

**Severity:** Minor
**Location:** "Files NOT Changed" table row "crates/permit0-cli/src/cmd/serve.rs"
**Claim:** "Daemon API is unchanged"
**Reality:** True for the wire endpoint shape. But the daemon's
`ClientKind` enum (imported from hook.rs at
`crates/permit0-cli/src/cmd/serve.rs:35`) gains a new variant. That
variant becomes silently parseable from the JSON `client_kind` field
(`serve.rs:114-118`). So the daemon does observably change behavior
for `{"client_kind": "codex"}` requests, even though no source line
in `serve.rs` is edited. This is fine but should be honest about the
transitive effect.
**Recommendation:** Add a row note: "(transitively gains
`client_kind: \"codex\"` support via the shared ClientKind import)".

### Finding 7: `PERMIT0_CLIENT` env var precedence is undocumented for new variant

**Severity:** Nit
**Location:** Change 1, FromStr impl
**Claim:** `"codex" | "codex-cli" | "codex_cli"` parse to
`ClientKind::Codex`.
**Reality:** Looks correct. But the env var path (`main.rs:241`) does
`std::env::var("PERMIT0_CLIENT").ok()`. If a user sets
`PERMIT0_CLIENT=Codex` (capitalized), the parser would error rather
than fall back. The existing parser is case-sensitive
(`hook.rs:97-108`). This is consistent behavior, but `04-testing.md`
should test it.
**Recommendation:** Add a test (or note in the existing test plan):
`"Codex".parse::<ClientKind>().is_err()` to lock down the
case-sensitivity contract.

### Finding 8: Risk Assessment underplays the silent-bypass mode

**Severity:** Nit
**Location:** "Risk Assessment" bullet 3 ("Fail-safe")
**Claim:** "Any bug in Codex output serialization results in Codex
treating the hook as a no-op (fail-open), which is safe for a new
integration but means bugs silently disable governance."
**Reality:** Correct, but the plan should distinguish two failure
modes: (a) hook crashes/exits 1 — Codex logs an error; users may
notice, (b) hook outputs an unparseable but non-empty stdout — Codex
logs a "warning" that's easy to miss in real-world usage. The risk of
(b) is higher because it requires no fatal error. The
`codex_output_never_contains_allow` test covers one such case but not
all malformed-JSON paths.
**Recommendation:** Add a fuzzing or property test idea: serialize
arbitrary Permission/Reason combinations and assert the output is
either empty OR a parseable JSON envelope of the expected shape.

## Verified Claims

- The proposed `OutputFormat::from_client` with `_ => Self::ClaudeCode`
  is consistent with the project's defaulting style elsewhere.
- The new `Codex` ClientKind reusing the same `mcp__<server>__<tool>`
  stripping is correct: the strip logic at `hook.rs:77-80` is purely
  string-based and the OR in the match arm is sound.
- Adding `Codex` as the first new variant after `OpenClaw` (alphabetical
  insertion not required) is non-breaking; the existing tests don't
  enumerate variants exhaustively beyond the parser tests at
  `hook.rs:1043-1072`.
- Local-mode `result.permission` is real and accessible — it comes from
  `engine.get_permission(&tool_call, &ctx)?` at `hook.rs:583`. The
  problem is only in the remote-mode arm.
- `evaluate_remote_with_meta` returning `(HookOutput, bool)` is verified
  at `hook.rs:435-469`; the `bool` is `is_unknown` for the unknown-mode
  policy.
- `derive_session_id` (existing) takes `Option<String>` and returns
  `String`, so the proposed `derive_session_id_for_format` signature
  is consistent with the existing helper.
- The CLI dispatcher's env-var precedence pattern (`main.rs:241-265`)
  generalizes cleanly to a Codex variant — no main.rs changes needed
  beyond the help text update.

## Questions for the Author

1. Show the full `run()` function after Change 6, including BOTH the
   local and remote arms, in a single snippet. The current "either
   ClaudeCode or Codex" branch is sketched, but the interaction with
   the remote arm and the shadow guard isn't clear.
2. Should `apply_unknown_policy` be called before or after the
   OutputFormat branch? Either choice has implications — call before
   means the policy operates on Claude-shaped HookOutput and the Codex
   serializer must round-trip it; call after means the policy logic
   has to be format-aware. Pick one and show the code.
3. For the remote path, is the intent to keep `evaluate_remote_with_meta`
   returning `(HookOutput, bool)` and write a HookOutput→Codex shim,
   or refactor the function to return `(Permission, ResponseMeta, bool)`
   and let each format build its own envelope? The latter is a bigger
   change but avoids the round-trip awkwardness.
4. Will the implementation also fix the existing `"humanintheloop"` vs
   `"human"` matcher bug in `remote_response_to_hook_output`? The
   Codex path inherits the bug; fixing it now (with regression tests)
   keeps blast radius small.
