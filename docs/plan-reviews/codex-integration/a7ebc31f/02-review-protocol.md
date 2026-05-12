# Review: 01 — Codex Hook Wire Protocol

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/01-protocol.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The protocol doc is detailed and the schema and verdict-mapping tables
are mostly correct. The biggest issue is that the plan does not address
a pre-existing wire-format mismatch in the Claude Code remote path that
the Codex remote path will inherit verbatim: the daemon emits
`permission: "human"` for HumanInTheLoop, but the hook's parser expects
`"humanintheloop"`. The "session ID extraction" Rust snippet is also
inconsistent with the implementation plan's signature.

## Detailed Findings

### Finding 1: HITL wire-format mismatch will manifest in Codex remote mode

**Severity:** Critical
**Location:** "Verdict Mapping Table" row "HumanInTheLoop"
**Claim:** Codex remote mode produces `hookSpecificOutput.permissionDecision: "deny"` with the standard
"requires human review" reason string.
**Reality:** In remote mode, the hook reads the daemon's
`CheckResponse.permission` field. The daemon serializes it via
`result.permission.to_string().to_lowercase()`
(`crates/permit0-cli/src/cmd/serve.rs:578`). `Permission::Display` for
`HumanInTheLoop` writes `"HUMAN"`
(`crates/permit0-types/src/permission.rs:17`), so the daemon emits
`"human"`. The hook's existing matcher only knows `"allow"`, `"deny"`,
and `"humanintheloop"` (`crates/permit0-cli/src/cmd/hook.rs:317-336`),
so the daemon's `"human"` falls into the `other` branch and produces
`HookOutput::ask("permit0 remote: unknown permission value 'human'")`.
The OpenClaw TypeScript client correctly aligns with the daemon at
`integrations/permit0-openclaw/src/Permit0Client.ts:594-601` and
`integrations/permit0-openclaw/src/types.ts:11`: `Permission = "allow" |
"deny" | "human"`. Once Codex remote mode reuses this path through
`codex_output`, the user will see "permit0 remote: unknown permission
value 'human'" as the deny reason on every HITL verdict — confusing and
defeats the goal of "informative reason strings."
**Recommendation:** Either (a) add a fix to `remote_response_to_hook_output`
to also match `"human"` (and update tests at `hook.rs:1183, 1231` which
use the wrong fixture), then call out in the protocol doc that Codex
fixes this latent bug; or (b) add a translator
`remote_response_to_codex_output` that handles the canonical daemon
spelling. Either way, the protocol doc must specify which spelling the
daemon emits and which the parser accepts.

### Finding 2: `derive_session_id_codex` snippet diverges from implementation plan signature

**Severity:** Major
**Location:** "Session ID Extraction" Rust snippet (function
`derive_session_id_codex`)
**Claim:** Function signature is
`fn derive_session_id_codex(stdin_session_id: Option<String>, explicit_flag: Option<String>) -> String`.
**Reality:** `02-implementation.md` Change 5 names the function
`derive_session_id_for_format` and adds a `format: OutputFormat` arg.
The two snippets disagree on both the name and the parameter list,
making it unclear which is canonical. The protocol doc's snippet also
shows the priority as: explicit flag, stdin, env var, fallback — but
the implementation snippet branches on `format` first, then applies
the same priority within the Codex branch. These should match.
**Recommendation:** Pick one signature (the implementation plan's
`derive_session_id_for_format` seems strictly better because it lets
ClaudeCode bypass Codex-specific logic), and use the same name in both
docs. Replace this snippet with a reference to the
`02-implementation.md` snippet to keep one source of truth.

### Finding 3: `transcript_path` is "always present" but described as "string or null"

**Severity:** Minor
**Location:** "Field Reference" table, row `transcript_path`
**Claim:** Type "string or null", "Always present: Yes".
**Reality:** "Always present" and "or null" are inconsistent — if the
key is always present but may be null, the type should be `string |
null` and the deserializer must accept `null`. The proposed
`HookInput` struct uses `Option<String>` with `#[serde(default)]`,
which works for both `null` and absent keys, so the runtime is fine.
But the plan's contract is ambiguous — if a future Codex version stops
emitting the key, does that violate the contract?
**Recommendation:** Change "Always present" to "Always present (may be
null)" and clarify that the implementation tolerates absence as well.

### Finding 4: "Codex also accepts the legacy block format" claim is unverified

**Severity:** Minor
**Location:** "Verdict: Deny (block)" subsection
**Claim:** Codex accepts both `hookSpecificOutput.permissionDecision`
and the legacy `{decision: "block", reason: "..."}` shape.
**Reality:** This is plausible (Claude Code historically supported
both shapes) but the plan does not cite a Codex source. If the Codex
team has standardized on the new shape and silently ignores the legacy
shape, the doc would be misleading.
**Recommendation:** Cite the Codex docs/PR confirming legacy support,
or remove the claim.

### Finding 5: Empty stdout for Allow has no test for Bash-style buffering

**Severity:** Minor
**Location:** "Verdict: Allow (no objection)" subsection
**Claim:** Exit code 0 with empty stdout = no objection.
**Reality:** The plan asserts "zero bytes" but the proposed
implementation in `02-implementation.md` Change 6 uses
`/* exit 0, empty stdout = allow */` as a comment with no actual code.
The current Claude path always calls `println!()`, which adds a
trailing newline. The Codex branch must NOT call println!() — that
emits a one-byte (newline) stdout, which Codex may or may not
interpret as "non-empty." The protocol must specify whether Codex
considers a single newline as empty (likely does) or non-empty
(possible parser bug).
**Recommendation:** Add a sentence: "Implementations must skip the
stdout write entirely (no trailing newline). A `print!()` or `println!()`
of an empty string is non-equivalent and may trigger Codex's invalid-
JSON warning path." Add a test that asserts exact zero bytes on
stdout via `Command::output()`.

### Finding 6: PermissionRequest example uses `decision.behavior` but PreToolUse uses `permissionDecision`

**Severity:** Nit
**Location:** "PermissionRequest Hook (v2, Future)" subsection
**Claim:** PermissionRequest output is
`{hookSpecificOutput: {decision: {behavior: "allow"}}}`.
**Reality:** This is a different envelope shape than PreToolUse
(`permissionDecision: "deny"`). If Codex really uses both shapes, the
plan should highlight this divergence so future v2 implementers don't
copy the PreToolUse shape into PermissionRequest by mistake.
**Recommendation:** Add a comparison line: "Note: PermissionRequest
uses `decision.behavior`, NOT `permissionDecision` — different from
PreToolUse."

### Finding 7: MCP name sanitization claim is not actionable

**Severity:** Nit
**Location:** "MCP Tool Name Format" subsection (last paragraph)
**Claim:** "Codex sanitizes MCP tool names for the Responses API:
hyphens are replaced with underscores… The permit0 hook receives the
**pre-sanitized** name from hooks."
**Reality:** This is reassuring but unverified. If a future Codex
release passes the post-sanitized name to hooks, normalizers that
currently match `mcp__permit0-gmail__gmail_send` would silently miss
`mcp__permit0_gmail__gmail_send`. The plan should state how it would
detect this regression.
**Recommendation:** Add a unit test (in `04-testing.md`) that
explicitly tests the post-sanitized form (e.g.
`mcp__permit0_gmail__gmail_send`) and asserts current behavior. That
way a Codex-side change shows up as a test diff.

## Verified Claims

- `HookInput` extending with `#[serde(default)]` Option fields is
  backward-compatible (verified by the existing
  `parse_hook_input` test at `hook.rs:682-687` which only sets
  `tool_name` and `tool_input`).
- The MCP `mcp__<server>__<tool>` stripping is a single first-double-
  underscore split, working correctly with single-underscore tool
  names like `outlook_create_mailbox`
  (`hook.rs:991-994`).
- Codex's `tool_input` mapping to `RawToolCall.parameters` aligns with
  the existing struct (`crates/permit0-types/src/tool_call.rs:12`).
- The verdict mapping table for non-HITL verdicts (Allow → empty
  stdout, Deny → envelope) is internally consistent and matches
  `02-implementation.md`'s `codex_output` function.

## Questions for the Author

1. Is "Codex 0.110+" verifiable? `03-configuration.md:21` makes the
   same claim. Please cite the release notes or the PR that introduced
   `[features] codex_hooks`.
2. Does PermissionRequest exist today in Codex, or is it speculative?
   `00-overview.md` Finding 4 raised this; the protocol doc would be
   the right place to either confirm with a citation or label as
   "speculative future schema."
3. The "System Message" subsection says `additionalContext` "is parsed
   by Codex but not fully supported yet." If it's not supported, why
   document it? Either remove or note "future use."
4. For the legacy block format `{decision: "block", reason: ...}`,
   should the permit0 hook ever emit this? The recommendation says
   "prefer the envelope" but a strict reading of the protocol could
   suggest fallback behavior. Be explicit: "permit0 always emits the
   envelope; the legacy form is documented only because Codex still
   parses it from third-party hooks."
