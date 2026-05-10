#![forbid(unsafe_code)]

//! PreToolUse hook adapter for multiple agent runtimes.
//!
//! Reads a JSON tool-call payload on stdin and emits a verdict to
//! stdout. The exact wire format depends on which agent runtime
//! invoked the hook (see [`ClientKind`] for prefix stripping and
//! [`OutputFormat`] for output serialization):
//!
//! - **Claude Code, Claude Desktop, OpenClaw, Raw**: emit a
//!   `hookSpecificOutput` envelope with
//!   `permissionDecision: "allow" | "deny" | "ask"` (or no
//!   `permissionDecision` for "defer to native flow").
//! - **OpenAI Codex CLI**: emit **empty stdout** for "no objection"
//!   (Codex explicitly rejects an `allow` envelope and would fail
//!   open with a warning if we sent one) or a deny envelope for
//!   blocks. Codex `PreToolUse` has no `ask` verdict; HITL maps to
//!   deny with a "requires human review" marker so users can
//!   distinguish it from a hard block.
//!
//! ## Fail-closed semantics
//!
//! Codex treats a non-zero exit, malformed stdout, or any output
//! containing `permissionDecision: "allow"` as **fail-open** — the
//! tool runs anyway. The Codex path of [`run`] catches every
//! recoverable error from the inner pipeline and converts it to a
//! structured deny envelope so an internal permit0 failure never
//! silently allows a governed action.
//!
//! ## Session-Aware Mode
//!
//! When `--db` is provided, the hook persists session context to
//! SQLite, enabling cross-invocation pattern detection (velocity,
//! attack chains). The session ID is derived from the explicit
//! `--session-id` flag, then the client-specific source
//! (`CLAUDE_SESSION_ID` for Claude Code; stdin payload `session_id` →
//! `CODEX_THREAD_ID` env for Codex), then the PPID fallback. Remote
//! mode (`--remote`) is stateless for session history in v1 — the
//! daemon is the source of truth for evaluation.
//!
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [{
//!       "command": "permit0 hook --profile fintech --db ~/.permit0/sessions.db",
//!       "description": "permit0 agent safety check (session-aware)"
//!     }]
//!   }
//! }
//! ```

use std::io::Read;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use permit0_engine::PermissionCtx;
use permit0_normalize::NormalizeCtx;
use permit0_types::{Domain, Permission, RawToolCall};

use crate::engine_factory;

/// Which MCP host (agent) is calling this hook. Different hosts namespace
/// MCP tool names differently; the hook strips the host-specific prefix
/// before normalizing so YAML normalizers can match the bare tool name
/// (e.g. `outlook_send`).
///
/// **Adding a new client**: confirm the exact prefix shape an actual
/// install passes to the PreToolUse hook (echo a tool call, look at the
/// `tool_name` field), then add a variant + handler. Don't guess —
/// false-positive stripping silently breaks normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientKind {
    /// Claude Code (CLI, terminal). Prefixes MCP tools as
    /// `mcp__<server>__<tool>` (double underscore separator). This is the
    /// default since it's the most common deployment.
    #[default]
    ClaudeCode,
    /// Claude Desktop (macOS/Windows GUI app). Passes MCP tool names
    /// as-is, no prefix.
    ClaudeDesktop,
    /// OpenClaw. MCP tools resolved by `mcporter` arrive as
    /// `<server>.<tool>` (single dot separator) at the gateway dispatch
    /// boundary. Strip the leading `<server>.` so normalizers can match
    /// the bare tool name.
    OpenClaw,
    /// OpenAI Codex CLI. Uses the same `mcp__<server>__<tool>` prefixing
    /// as Claude Code. Selecting this client also switches verdict
    /// serialization to Codex's `PreToolUse` envelope (see
    /// [`OutputFormat`]).
    Codex,
    /// No prefix stripping at all. Use this when you're calling the hook
    /// directly (e.g. from tests or a custom integration that already
    /// hands you the bare tool name).
    Raw,
}

impl ClientKind {
    /// Strip the host-specific prefix from a tool name, leaving the bare
    /// name normalizers expect.
    pub fn strip_prefix(self, tool_name: &str) -> &str {
        match self {
            // Claude Code and Codex share the MCP convention:
            // "mcp__<server>__<tool>" — first "__" after "mcp__"
            // separates server from tool.
            Self::ClaudeCode | Self::Codex => tool_name
                .strip_prefix("mcp__")
                .and_then(|rest| rest.split_once("__").map(|(_, tool)| tool))
                .unwrap_or(tool_name),
            // OpenClaw via mcporter: "<server>.<tool>". Strip everything
            // up to and including the first dot. Names without a dot pass
            // through (built-in tools like "exec" or plugin tools that
            // register bare names).
            Self::OpenClaw => tool_name
                .split_once('.')
                .map(|(_, tool)| tool)
                .unwrap_or(tool_name),
            // Claude Desktop and Raw: passthrough.
            Self::ClaudeDesktop | Self::Raw => tool_name,
        }
    }
}

impl FromStr for ClientKind {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "claude-code" | "claude_code" => Ok(Self::ClaudeCode),
            "claude-desktop" | "claude_desktop" => Ok(Self::ClaudeDesktop),
            "openclaw" | "open-claw" | "open_claw" => Ok(Self::OpenClaw),
            "codex" | "codex-cli" | "codex_cli" => Ok(Self::Codex),
            "raw" | "none" => Ok(Self::Raw),
            other => Err(format!(
                "unknown client '{other}' (supported: claude-code, claude-desktop, \
                 openclaw, codex, raw)"
            )),
        }
    }
}

/// Wire format used to serialize the hook's verdict to stdout.
///
/// Different agent runtimes interpret hook responses differently:
/// - Claude Code expects a `hookSpecificOutput` envelope with
///   `permissionDecision: "allow" | "deny" | "ask"`, or no
///   `permissionDecision` for "defer to native flow".
/// - Codex expects **empty stdout** for "allow" / "no objection"
///   (an `allow` envelope is explicitly rejected and causes Codex to
///   fail open with a warning), and a `hookSpecificOutput` envelope
///   with `permissionDecision: "deny"` for blocks. Codex has no `ask`
///   verdict in `PreToolUse`; HITL is mapped to `deny` with an
///   informative reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Claude Code envelope. Used by Claude Code, Claude Desktop,
    /// OpenClaw, and the `Raw` client (which all consume the same
    /// `hookSpecificOutput` schema).
    ClaudeCode,
    /// OpenAI Codex `PreToolUse` envelope. Empty stdout = no objection;
    /// any other stdout must be a deny envelope.
    Codex,
}

impl OutputFormat {
    /// Pick the wire output format for a given client. Adding a new
    /// `ClientKind` requires a deliberate decision here — exhaustive
    /// matching makes that mandatory.
    pub fn from_client(client: ClientKind) -> Self {
        match client {
            ClientKind::Codex => Self::Codex,
            ClientKind::ClaudeCode
            | ClientKind::ClaudeDesktop
            | ClientKind::OpenClaw
            | ClientKind::Raw => Self::ClaudeCode,
        }
    }
}

/// What to do when permit0 has no opinion about a tool call (i.e. the action
/// normalized to `unknown.unclassified` AND the engine's verdict is the
/// fallback "ask"). Selectable per‑hook so security‑heavy setups can keep
/// the conservative prompt while everyday Claude Code use can fall through
/// to Claude Code's own permission system for built‑in tools.
///
/// The override fires **only** when both of these hold:
/// 1. The normalized action is in the `unknown` domain.
/// 2. The current verdict is `ask` (the fallback HITL path).
///
/// Allowlist / denylist hits on unknown tool names continue to apply — those
/// are explicit operator decisions and aren't rewritten by `--unknown`.
///
/// The wire shape each variant produces depends on [`OutputFormat`]:
/// - Claude Code emits the standard `hookSpecificOutput` envelope.
/// - Codex emits empty stdout for "no objection" (Allow / Defer) and a
///   deny envelope for blocking verdicts (Ask is mapped to deny since
///   Codex `PreToolUse` has no `ask`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownMode {
    /// Prompt the user with permit0's reasoning before the tool runs.
    /// On Claude Code this is `permissionDecision: "ask"` (native ask
    /// UI); on Codex this becomes a deny envelope with the
    /// "requires human review" marker since Codex `PreToolUse` has no
    /// `ask` verdict.
    Ask,
    /// Let the tool run unprompted. On Claude Code this is
    /// `permissionDecision: "allow"`; on Codex this is empty stdout
    /// (Codex explicitly rejects an `allow` envelope). Sharp edge:
    /// blanket‑allows anything permit0 doesn't recognize.
    Allow,
    /// Block the tool. Deny envelope on every client. Use for
    /// whitelist‑only setups where every governed action must be
    /// packaged.
    Deny,
    /// Fall through to the client's native flow. On Claude Code this is
    /// an envelope with no `permissionDecision` (so Claude's own
    /// allowlists / ask UI take over); on Codex this is empty stdout
    /// (no objection — Codex continues with its default flow). Default
    /// — permit0 only intervenes for tools it has packs for.
    #[default]
    Defer,
}

impl FromStr for UnknownMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ask" => Ok(Self::Ask),
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "defer" => Ok(Self::Defer),
            other => Err(format!(
                "unknown unknown-mode '{other}' (supported: ask, allow, deny, defer)"
            )),
        }
    }
}

/// PreToolUse hook input format.
///
/// Accepts the union of:
/// - Claude Code's minimal payload (`tool_name` + `tool_input`)
/// - Codex's extended payload (adds `session_id`, `turn_id`, `cwd`,
///   `hook_event_name`, `model`, `tool_use_id`, `transcript_path`)
///
/// All Codex-specific fields are optional with `#[serde(default)]`, so
/// the same struct deserializes both formats. Empty-string values from
/// Codex are treated as equivalent to missing fields: downstream
/// consumers must apply `.filter(|s| !s.is_empty())` before acting on
/// any optional string field.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// The tool name (e.g. "Bash", "Write", "Edit", or an MCP-prefixed
    /// name like `mcp__permit0-gmail__gmail_send`).
    pub tool_name: String,
    /// The tool input parameters.
    pub tool_input: serde_json::Value,
    /// Codex thread/session UUID. Primary automatic source for the
    /// permit0 session ID when `--client codex` is set.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Codex turn identifier within a thread. Captured for forward-compat;
    /// not currently consumed by permit0.
    #[serde(default)]
    pub turn_id: Option<String>,
    /// Codex working directory at the time of the tool call. Captured for
    /// forward-compat; not currently consumed by permit0.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Codex hook event name (always `"PreToolUse"` for this hook). Captured
    /// for forward-compat; not currently consumed by permit0.
    #[serde(default)]
    pub hook_event_name: Option<String>,
    /// Codex model slug. Captured for forward-compat; not currently
    /// consumed by permit0.
    #[serde(default)]
    pub model: Option<String>,
    /// Codex per-call invocation ID. Captured for forward-compat; not
    /// currently consumed by permit0.
    #[serde(default)]
    pub tool_use_id: Option<String>,
    /// Codex JSONL transcript path. Captured for forward-compat; not
    /// currently consumed by permit0.
    #[serde(default)]
    pub transcript_path: Option<String>,
}

/// Claude Code PreToolUse hook output. Schema per
/// <https://code.claude.com/docs/en/hooks>:
///
/// ```json
/// {
///   "hookSpecificOutput": {
///     "hookEventName": "PreToolUse",
///     "permissionDecision": "allow" | "deny" | "ask" | "defer",
///     "permissionDecisionReason": "..."
///   }
/// }
/// ```
///
/// Anything else is silently ignored by Claude Code (which is exactly the
/// trap that hid this bug — the legacy `{"decision":"allow"}` shape just
/// passed through as a no-op).
#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,
    /// Optional so we can emit a "no opinion" envelope for `--unknown defer`:
    /// when omitted, Claude Code falls back to its own permission flow.
    #[serde(rename = "permissionDecision")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<&'static str>,
    #[serde(rename = "permissionDecisionReason")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
}

impl HookOutput {
    pub fn allow() -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some("allow"),
                permission_decision_reason: None,
            },
        }
    }
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some("deny"),
                permission_decision_reason: Some(reason.into()),
            },
        }
    }
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some("ask"),
                permission_decision_reason: Some(reason.into()),
            },
        }
    }
    /// Emit an envelope with no `permissionDecision`. Claude Code interprets
    /// this as "no opinion" and falls back to its own permission flow
    /// (settings.local.json allowlists, then its native ask UI). Used by
    /// `--unknown defer` for tools permit0 has no packs for.
    pub fn defer() -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: None,
                permission_decision_reason: None,
            },
        }
    }
}

/// Serialize a Codex `PreToolUse` deny envelope with the given reason.
///
/// Codex `PreToolUse` accepts only `permissionDecision: "deny"` (or no
/// objection via empty stdout). All Codex hook outputs that are not
/// "no objection" must be emitted through this helper.
fn codex_deny_envelope(reason: &str) -> String {
    // Static string keys + a single string value never hit any
    // serde_json failure path, so the expect is structurally
    // guaranteed. We still go through serde_json (rather than format!)
    // to get correct JSON escaping of the reason text.
    serde_json::to_string(&serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    .expect("serializing a static-keyed JSON object cannot fail")
}

/// Test-only helper: convert a `Permission` directly into Codex stdout
/// output.
///
/// Production code never has a bare `Permission` at the emit boundary;
/// it always has a [`HookOutput`] (after unknown-policy and shadow
/// rewrites), so it uses [`hook_output_to_codex`] instead. This helper
/// exists so the per-`Permission` mapping table is testable in isolation
/// and must stay consistent with `hook_output_to_codex`'s mapping —
/// both apply [`CODEX_HITL_MARKER`] for `HumanInTheLoop`.
///
/// Returns `None` for `Permission::Allow` (Codex requires empty stdout
/// for "no objection"; an `allow` envelope is explicitly rejected).
/// Returns `Some(envelope)` for `Deny` and `HumanInTheLoop` (HITL maps
/// to deny with the marker because Codex `PreToolUse` has no `ask`).
#[cfg(test)]
fn codex_output(perm: Permission, reason: &str) -> Option<String> {
    match perm {
        Permission::Allow => None,
        Permission::Deny => Some(codex_deny_envelope(reason)),
        Permission::HumanInTheLoop => {
            Some(codex_deny_envelope(&format!("{reason}{CODEX_HITL_MARKER}")))
        }
    }
}

/// Marker appended to HITL→deny reasons under Codex so users can tell
/// "blocked because Codex has no `ask`" apart from "blocked because the
/// action is Critical / on a denylist". Without this, every Codex deny
/// envelope looks the same shape and operators have no signal about
/// what to do (e.g. add to allowlist vs. abort the task).
const CODEX_HITL_MARKER: &str = " — requires human review";

/// Convert a finalized [`HookOutput`] into Codex stdout output.
///
/// This is the runtime counterpart to [`codex_output`]: it operates on
/// the same `HookOutput` shape used by every other code path (unknown
/// policy rewrites, remote response mapping, remote error mapping,
/// shadow mode), so converting at the very end of the pipeline avoids
/// duplicating the rewrite logic.
///
/// Returns `None` when Codex should see empty stdout:
/// - `Some("allow")` → no objection, empty stdout (Codex rejects the
///   `allow` envelope).
/// - `None` (deferred) → no objection, empty stdout (Codex falls through
///   to its native flow naturally).
///
/// Returns `Some(envelope)` for any blocking verdict:
/// - `Some("deny")` → deny envelope with the existing reason (or a
///   generic fallback).
/// - `Some("ask")` → deny envelope with [`CODEX_HITL_MARKER`] appended
///   (Codex has no `ask`; the marker tells users this would have been
///   a HITL prompt under Claude Code, not a hard block).
/// - Any other `Some(...)` value (defensive against future Claude Code
///   verdict additions) → deny envelope flagging the unexpected value.
fn hook_output_to_codex(output: &HookOutput) -> Option<String> {
    match output.hook_specific_output.permission_decision {
        Some("allow") | None => None,
        Some("deny") => Some(codex_deny_envelope(
            output
                .hook_specific_output
                .permission_decision_reason
                .as_deref()
                .unwrap_or("permit0 denied"),
        )),
        Some("ask") => {
            // Always end the reason with the HITL marker so Codex users
            // can distinguish "would have been a Claude Code approval
            // prompt" from "Critical-tier hard block".
            let reason = match output
                .hook_specific_output
                .permission_decision_reason
                .as_deref()
            {
                Some(r) => format!("{r}{CODEX_HITL_MARKER}"),
                // Without an existing reason, emit the marker as the
                // full message without the leading separator.
                None => "permit0: requires human review".to_string(),
            };
            Some(codex_deny_envelope(&reason))
        }
        Some(other) => Some(codex_deny_envelope(&format!(
            "permit0: unexpected decision '{other}'"
        ))),
    }
}

/// Write a finalized [`HookOutput`] to stdout in the requested format.
///
/// For `ClaudeCode`, serializes the full envelope. For `Codex`, emits
/// either the deny envelope (for blocking verdicts) or zero bytes (for
/// allow / defer). The Codex empty-stdout case must NOT call
/// `println!("")` — that would write a trailing newline byte and may
/// trigger Codex's invalid-JSON warning path. We skip the write entirely.
fn emit_hook_output(format: OutputFormat, output: &HookOutput) -> Result<()> {
    match format {
        OutputFormat::ClaudeCode => {
            println!("{}", serde_json::to_string(output)?);
        }
        OutputFormat::Codex => {
            if let Some(json) = hook_output_to_codex(output) {
                println!("{json}");
            }
        }
    }
    Ok(())
}

/// PPID / cwd hash fallback for session ID derivation. Common to every
/// `ClientKind` and used as the last resort when no explicit flag, no
/// stdin payload field, and no client-specific env var has supplied an
/// ID. Stable within a single agent conversation under Unix; on
/// Windows we fall back to a cwd hash since PPID isn't portable here.
fn ppid_fallback() -> String {
    #[cfg(unix)]
    {
        let ppid = std::os::unix::process::parent_id();
        format!("ppid-{ppid}")
    }
    #[cfg(not(unix))]
    {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".into());
        format!("cwd-{:x}", fxhash(&cwd))
    }
}

/// Derive session ID for the Claude Code path: explicit flag, then
/// `CLAUDE_SESSION_ID` env var, then PPID/cwd fallback.
fn derive_session_id(explicit: Option<String>) -> String {
    if let Some(id) = explicit {
        return id;
    }
    if let Ok(id) = std::env::var("CLAUDE_SESSION_ID") {
        if !id.is_empty() {
            return id;
        }
    }
    ppid_fallback()
}

#[cfg(not(unix))]
fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u64);
    }
    h
}

/// Forward the Codex stdin context fields into `RawToolCall.metadata`.
///
/// permit0's audit pipeline serializes every `RawToolCall` (including
/// `metadata`) into its audit records and dashboard view, so forwarding
/// the Codex thread / turn / model identity makes decisions correlatable
/// with the originating Codex session after the fact. Empty-string
/// values from Codex are dropped so a payload like `"transcript_path":
/// ""` does not pollute the audit record. Claude Code's minimal payload
/// produces an empty map (no behavior change vs. the legacy default).
///
/// **Local mode only**: `evaluate_remote_with_meta` POSTs only
/// `tool_name` and `parameters` to the daemon, so this metadata
/// surfaces in audit records only when `--remote` is unset.
/// `docs/plans/codex-integration/05-limitations.md` Section 7 scopes
/// remote-mode metadata forwarding as v2.
fn build_tool_call_metadata(input: &HookInput) -> serde_json::Map<String, serde_json::Value> {
    let mut metadata = serde_json::Map::new();
    let pairs: [(&str, &Option<String>); 7] = [
        ("session_id", &input.session_id),
        ("turn_id", &input.turn_id),
        ("cwd", &input.cwd),
        ("hook_event_name", &input.hook_event_name),
        ("model", &input.model),
        ("tool_use_id", &input.tool_use_id),
        ("transcript_path", &input.transcript_path),
    ];
    for (key, value) in pairs {
        if let Some(v) = value.as_deref().filter(|s| !s.is_empty()) {
            metadata.insert(key.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    metadata
}

/// Derive a session ID using format-specific sources.
///
/// Priority for Codex:
/// 1. Explicit `--session-id` flag (operator override).
/// 2. `session_id` from the stdin payload (thread UUID, most reliable
///    automatic source).
/// 3. `CODEX_THREAD_ID` environment variable (Codex injects this into
///    shell tool processes).
/// 4. PPID / cwd hash fallback ([`ppid_fallback`]).
///
/// Priority for Claude Code:
/// 1. Explicit `--session-id` flag.
/// 2. `CLAUDE_SESSION_ID` environment variable.
/// 3. PPID / cwd hash fallback.
///
/// **The Codex branch deliberately does not consult `CLAUDE_SESSION_ID`.**
/// In a developer environment where both Claude Code and Codex are
/// configured side-by-side, a stale `CLAUDE_SESSION_ID` exported from a
/// prior shell wrapper could otherwise cross-contaminate Codex's
/// session ID and fragment cross-call pattern detection. Empty strings
/// from the stdin payload or env vars are treated as absent so a Codex
/// payload with `"session_id": ""` does not poison the session store.
fn derive_session_id_for_format(
    format: OutputFormat,
    stdin_session_id: Option<String>,
    explicit_flag: Option<String>,
) -> String {
    if let Some(id) = explicit_flag.filter(|s| !s.is_empty()) {
        return id;
    }
    match format {
        OutputFormat::Codex => {
            if let Some(id) = stdin_session_id.filter(|s| !s.is_empty()) {
                return id;
            }
            if let Ok(id) = std::env::var("CODEX_THREAD_ID") {
                if !id.is_empty() {
                    return id;
                }
            }
            // Skip CLAUDE_SESSION_ID — see function-level docstring.
            ppid_fallback()
        }
        OutputFormat::ClaudeCode => derive_session_id(None),
    }
}

/// Subset of `serve.rs::CheckResponse` we care about when delegating
/// evaluation to a remote daemon. Extra fields are ignored so this stays
/// forward-compatible if the server response grows.
#[derive(Debug, Deserialize)]
struct RemoteCheckResponse {
    /// Lowercase Permission Display: "allow" | "deny" | "humanintheloop".
    permission: String,
    #[serde(default)]
    action_type: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    score: Option<u32>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    block_reason: Option<String>,
}

/// Build the full check endpoint URL from a user-supplied --remote value.
/// Accept either a base URL (`http://host:port`) or the full path; tolerate
/// trailing slashes either way.
fn build_check_endpoint(remote: &str) -> String {
    let trimmed = remote.trim().trim_end_matches('/');
    if trimmed.contains("/api/") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api/v1/check")
    }
}

/// Translate a remote `CheckResponse` into the Claude Code hook envelope.
///
/// Wire-format note: the daemon's `serve.rs::CheckResponse` serializes
/// `Permission::HumanInTheLoop` as `"human"` (via `Display` → `"HUMAN"` →
/// `to_lowercase()`), not `"humanintheloop"`. We accept both for safety
/// against an older daemon that may have been deployed with a stricter
/// mapping, but `"human"` is the canonical value.
fn remote_response_to_hook_output(resp: &RemoteCheckResponse) -> HookOutput {
    match resp.permission.as_str() {
        "allow" => HookOutput::allow(),
        "deny" => HookOutput::deny(
            resp.block_reason
                .clone()
                .unwrap_or_else(|| "permit0 denied (remote)".into()),
        ),
        "human" | "humanintheloop" => HookOutput::ask(format!(
            "permit0: {} ({}) — risk {}/100 {}",
            resp.action_type.as_deref().unwrap_or("?"),
            resp.channel.as_deref().unwrap_or("?"),
            resp.score.unwrap_or(0),
            resp.tier.as_deref().unwrap_or(""),
        )),
        // Unknown permission value → fail-safe to "ask" so the human is
        // alerted rather than silently allowing the call.
        other => HookOutput::ask(format!(
            "permit0 remote: unknown permission value '{other}'"
        )),
    }
}

/// Convert a HookOutput to (decision_label, reason) for shadow logging.
/// Mirrors the local-path tuple shape so shadow mode prints uniformly.
/// `defer` (no permissionDecision) is reported as `"defer"` for the log.
fn hook_output_summary(out: &HookOutput) -> (&'static str, String) {
    let d = out
        .hook_specific_output
        .permission_decision
        .unwrap_or("defer");
    let reason = out
        .hook_specific_output
        .permission_decision_reason
        .clone()
        .unwrap_or_default();
    (d, reason)
}

/// Apply the configured `--unknown` policy. Only rewrites the output when
/// (a) the action is in the unknown domain AND (b) the current decision is
/// `ask`. All other cases pass through unchanged so denylist/allowlist hits
/// and pack‑backed verdicts keep their semantics.
fn apply_unknown_policy(output: HookOutput, is_unknown: bool, mode: UnknownMode) -> HookOutput {
    if !is_unknown {
        return output;
    }
    if output.hook_specific_output.permission_decision != Some("ask") {
        return output;
    }
    match mode {
        UnknownMode::Ask => output,
        UnknownMode::Allow => HookOutput::allow(),
        UnknownMode::Deny => {
            HookOutput::deny("permit0: unknown action denied by --unknown deny policy".to_string())
        }
        UnknownMode::Defer => HookOutput::defer(),
    }
}

/// Did the daemon classify this call as the unknown fallback action?
/// Used by `apply_unknown_policy` to decide whether `--unknown` overrides
/// the verdict. Compared against the canonical `unknown.unclassified`
/// string from the action catalog.
fn remote_is_unknown(resp: &RemoteCheckResponse) -> bool {
    resp.action_type
        .as_deref()
        .is_some_and(|s| s == permit0_types::ActionType::UNKNOWN.as_action_str())
}

/// What went wrong while talking to the remote daemon. Distinguishing
/// these matters because they map to very different hook outputs:
///
/// - `Transport` (daemon unreachable, DNS failure, timeout, …) — the
///   right call is the existing "ask" fail-safe so the human is alerted.
/// - `HttpStatus` (daemon responded but with non‑2xx) — surface the
///   daemon's own error message in a `deny`. The daemon refused to
///   evaluate; treating that as "unavailable" hides the real reason.
#[derive(Debug)]
enum RemoteError {
    Transport(String),
    HttpStatus { status: u16, body: String },
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport: {msg}"),
            Self::HttpStatus { status, body } => write!(f, "HTTP {status}: {body}"),
        }
    }
}

/// Translate a RemoteError into the hook output the user actually sees.
/// Pure (no I/O, no eprintln) so it's directly unit‑testable; the calling
/// run() loop is responsible for the stderr breadcrumb.
///
/// `is_unknown` is intentionally always `false` here — fail-safes shouldn't
/// be silently rewritten by `--unknown`. If the daemon was unreachable
/// permit0 has no opinion at all, but rewriting that into `defer`/`allow`
/// would let outages quietly nullify governance.
fn remote_error_to_hook_output(err: &RemoteError) -> (HookOutput, bool) {
    match err {
        RemoteError::Transport(msg) => (
            HookOutput::ask(format!("permit0 remote unavailable: {msg}")),
            false,
        ),
        RemoteError::HttpStatus { status, body } => (
            HookOutput::deny(format!("permit0 daemon error (HTTP {status}): {body}")),
            false,
        ),
    }
}

/// POST the tool call to a remote `permit0 serve` daemon and translate
/// the response into a HookOutput plus an `is_unknown` flag for the
/// `--unknown` policy. The error variant tells the caller whether the
/// daemon was unreachable (Transport) or responded with an error
/// (HttpStatus) so the fail-safe path can pick the right hook output.
fn evaluate_remote_with_meta(
    remote: &str,
    tool_call: &RawToolCall,
) -> std::result::Result<(HookOutput, bool), RemoteError> {
    let endpoint = build_check_endpoint(remote);
    let body = serde_json::json!({
        "tool_name": tool_call.tool_name,
        "parameters": tool_call.parameters,
    });

    let response = match ureq::post(&endpoint)
        .set("content-type", "application/json")
        .send_json(body)
    {
        Ok(resp) => resp,
        Err(ureq::Error::Status(status, resp)) => {
            // Daemon responded but refused — surface the body so the
            // human sees the real reason (e.g. normalizer mismatch).
            let body = resp
                .into_string()
                .unwrap_or_else(|_| "<unreadable response body>".to_string());
            return Err(RemoteError::HttpStatus { status, body });
        }
        Err(ureq::Error::Transport(t)) => {
            return Err(RemoteError::Transport(format!("POST {endpoint}: {t}")));
        }
    };

    let parsed: RemoteCheckResponse = response
        .into_json()
        .map_err(|e| RemoteError::Transport(format!("parsing /api/v1/check JSON: {e}")))?;

    let is_unknown = remote_is_unknown(&parsed);
    Ok((remote_response_to_hook_output(&parsed), is_unknown))
}

/// Run the PreToolUse hook adapter.
///
/// `client` selects which MCP host calls us, controlling both how
/// tool-name prefixes are stripped before normalization (see
/// [`ClientKind`]) and how verdicts are serialized to stdout (see
/// [`OutputFormat`]).
///
/// `remote` (if `Some`) delegates evaluation to a running `permit0 serve
/// --ui` daemon at that URL; in that mode the local engine is never built
/// and `profile` / `packs_dir` / `db_path` / `session_id` are ignored.
///
/// ## Codex fail-closed semantics
///
/// In Codex mode, a non-zero exit, malformed stdout, or missing deny
/// envelope causes the tool to **fail open** (Codex executes the tool
/// anyway with a warning). This wrapper catches any error from the
/// inner pipeline and converts it into a structured Codex deny envelope
/// so an internal permit0 failure never silently allows a governed
/// action.
#[allow(clippy::too_many_arguments)]
pub fn run(
    profile: Option<String>,
    org_domain: &str,
    db_path: Option<String>,
    session_id: Option<String>,
    packs_dir: Option<String>,
    shadow: bool,
    client: ClientKind,
    remote: Option<String>,
    unknown: UnknownMode,
) -> Result<()> {
    let format = OutputFormat::from_client(client);
    let result = run_inner(
        profile, org_domain, db_path, session_id, packs_dir, shadow, client, format, remote,
        unknown,
    );
    match (format, result) {
        (_, Ok(())) => Ok(()),
        // Claude Code treats a non-zero exit as "hook failed" and prompts
        // the user. That's the existing behavior — propagate the error.
        (OutputFormat::ClaudeCode, Err(e)) => Err(e),
        // Codex treats a non-zero exit as "hook failed → tool runs". We
        // must never bubble Err out in that mode. Convert the error into
        // a structured deny envelope so Codex blocks the tool.
        (OutputFormat::Codex, Err(e)) => {
            eprintln!("permit0 codex hook error: {e}");
            println!(
                "{}",
                codex_deny_envelope(&format!("permit0 internal error: {e}"))
            );
            Ok(())
        }
    }
}

/// Inner pipeline: read stdin, evaluate, emit. Returns `Err` on any
/// recoverable failure; the outer [`run`] wraps the Codex path so those
/// errors cannot fail open.
#[allow(clippy::too_many_arguments)]
fn run_inner(
    profile: Option<String>,
    org_domain: &str,
    db_path: Option<String>,
    session_id: Option<String>,
    packs_dir: Option<String>,
    shadow: bool,
    client: ClientKind,
    format: OutputFormat,
    remote: Option<String>,
    unknown: UnknownMode,
) -> Result<()> {
    let shadow = shadow || std::env::var("PERMIT0_SHADOW").is_ok_and(|v| !v.is_empty() && v != "0");
    // Read hook input from stdin
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading hook input from stdin")?;

    let hook_input: HookInput = serde_json::from_str(&buf).context("parsing hook input JSON")?;

    // Strip the host-specific MCP prefix (if any) so YAML normalizers can
    // match the bare tool name. See `ClientKind::strip_prefix`. We pull
    // `session_id` out and build the audit metadata before the partial
    // move into RawToolCall so the local-mode session derivation and
    // metadata helper can both still read `hook_input` by reference.
    let stdin_session_id = hook_input.session_id.clone();
    let metadata = build_tool_call_metadata(&hook_input);
    let tool_call = RawToolCall {
        tool_name: client.strip_prefix(&hook_input.tool_name).to_string(),
        parameters: hook_input.tool_input,
        metadata,
    };

    // Remote mode short-circuits the local pipeline. Profile / packs_dir /
    // db_path / session_id are intentionally ignored — the daemon's own
    // configuration governs evaluation.
    if let Some(remote_url) = remote {
        if db_path.is_some() || session_id.is_some() {
            eprintln!(
                "permit0: --remote set; ignoring --db / --session-id (remote daemon governs sessions)"
            );
        }
        let (output, is_unknown) = match evaluate_remote_with_meta(&remote_url, &tool_call) {
            Ok(pair) => pair,
            Err(err) => {
                // stderr breadcrumb — kept in run() so the helper stays
                // pure and unit‑testable.
                eprintln!("permit0: remote evaluation failed: {err}");
                remote_error_to_hook_output(&err)
            }
        };
        let output = apply_unknown_policy(output, is_unknown, unknown);
        let final_output = if shadow {
            let (decision, reason) = hook_output_summary(&output);
            if decision != "allow" {
                eprintln!(
                    "[permit0 shadow] WOULD {} (remote): {}",
                    decision.to_uppercase(),
                    reason,
                );
            }
            HookOutput::allow()
        } else {
            output
        };
        emit_hook_output(format, &final_output)?;
        return Ok(());
    }

    // Build engine
    let engine = engine_factory::build_engine_from_packs(profile.as_deref(), packs_dir.as_deref())?;

    // Session-aware context
    let session_store = db_path.as_ref().map(|path| {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        permit0_session::SqliteSessionStore::open(path)
    });

    let session_store = match session_store {
        Some(Ok(store)) => Some(store),
        Some(Err(e)) => {
            // Log but don't fail — fall back to stateless mode
            eprintln!("permit0: session DB open failed ({e}), running stateless");
            None
        }
        None => None,
    };

    let session_id_str = session_store.as_ref().map(|_| {
        derive_session_id_for_format(format, stdin_session_id.clone(), session_id.clone())
    });
    let session_ctx = session_id_str.as_ref().and_then(|sid| {
        session_store
            .as_ref()
            .and_then(|store| store.get_session(sid))
    });

    // Build context with optional session
    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain));
    let ctx = match session_ctx {
        Some(session) => ctx.with_session(session),
        None => ctx,
    };

    // Evaluate
    let result = engine.get_permission(&tool_call, &ctx)?;

    // Record action to session store (after evaluation)
    if let (Some(store), Some(sid)) = (&session_store, &session_id_str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let record = permit0_session::ActionRecord {
            action_type: result.norm_action.action_type.as_action_str(),
            tier: result
                .risk_score
                .as_ref()
                .map(|s| s.tier)
                .unwrap_or(permit0_types::Tier::Medium),
            flags: result
                .risk_score
                .as_ref()
                .map(|s| s.flags.clone())
                .unwrap_or_default(),
            timestamp: now,
            entities: result.norm_action.entities.clone(),
        };
        store.record_action(sid, &record);
    }

    // Build the base hook output from permit0's verdict directly. We
    // match exhaustively on `result.permission` (rather than going
    // through an intermediate string label) so the compiler enforces
    // every variant is handled. A wildcard `_ => HookOutput::allow()`
    // arm here would silently fail open under Codex (where empty stdout
    // means "no objection") if a future `Permission` variant ever
    // reached this site.
    //
    // The `--unknown` policy fires only for unknown→ask and rewrites
    // `output` accordingly. Shadow mode observes the post-policy
    // decision so logs reflect what the user would see if shadow were
    // removed.
    let base_output = match result.permission {
        Permission::Allow => HookOutput::allow(),
        Permission::Deny => HookOutput::deny(
            result
                .risk_score
                .as_ref()
                .and_then(|s| s.block_reason.clone())
                .unwrap_or_else(|| format!("permit0 denied: {:?}", result.source)),
        ),
        Permission::HumanInTheLoop => HookOutput::ask(format!(
            "permit0: {} ({}) — risk {}/100 {:?}",
            result.norm_action.action_type.as_action_str(),
            result.norm_action.channel,
            result.risk_score.as_ref().map_or(0, |s| s.score),
            result
                .risk_score
                .as_ref()
                .map_or(permit0_types::Tier::Medium, |s| s.tier),
        )),
    };
    let is_unknown = result.norm_action.domain() == Domain::Unknown;
    let output = apply_unknown_policy(base_output, is_unknown, unknown);

    // Shadow mode: log the would-be decision and always allow. The
    // format-aware emitter turns `HookOutput::allow()` into either the
    // Claude allow envelope or empty stdout (Codex), so shadow + Codex
    // is correctly silent without a separate code path.
    let final_output = if shadow {
        let (logged_decision, logged_reason) = hook_output_summary(&output);
        if logged_decision != "allow" {
            eprintln!(
                "[permit0 shadow] WOULD {}: {} ({}) score={}/100  {}",
                logged_decision.to_uppercase(),
                result.norm_action.action_type.as_action_str(),
                result.norm_action.channel,
                result.risk_score.as_ref().map_or(0, |s| s.score),
                logged_reason,
            );
        }
        HookOutput::allow()
    } else {
        output
    };

    emit_hook_output(format, &final_output)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hook_input() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "rm -rf /");
    }

    // Tests assert the exact schema Claude Code expects: a top-level
    // `hookSpecificOutput` envelope with `hookEventName=PreToolUse` and a
    // `permissionDecision` of allow|deny|ask|defer.

    #[test]
    fn hook_output_allow_serialization() {
        let json = serde_json::to_string(&HookOutput::allow()).unwrap();
        assert!(json.contains(r#""hookSpecificOutput""#), "got: {json}");
        assert!(
            json.contains(r#""hookEventName":"PreToolUse""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""permissionDecision":"allow""#),
            "got: {json}"
        );
        // No reason on plain allow.
        assert!(!json.contains("permissionDecisionReason"));
    }

    #[test]
    fn hook_output_deny_serialization() {
        let json = serde_json::to_string(&HookOutput::deny("dangerous command")).unwrap();
        assert!(
            json.contains(r#""permissionDecision":"deny""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""permissionDecisionReason":"dangerous command""#),
            "got: {json}"
        );
    }

    #[test]
    fn hook_output_ask_serialization() {
        let json = serde_json::to_string(&HookOutput::ask("Allow this?")).unwrap();
        assert!(
            json.contains(r#""permissionDecision":"ask""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""permissionDecisionReason":"Allow this?""#),
            "got: {json}"
        );
    }

    #[test]
    fn hook_output_defer_omits_permission_decision() {
        // Critical contract: a deferred output must serialize WITHOUT
        // `permissionDecision` so Claude Code falls back to its native
        // permission flow (allowlists, then ask UI). If this key is
        // present — even as null — Claude Code will treat the response
        // as authoritative.
        let json = serde_json::to_string(&HookOutput::defer()).unwrap();
        assert!(
            json.contains(r#""hookEventName":"PreToolUse""#),
            "got: {json}"
        );
        assert!(!json.contains("permissionDecision"), "got: {json}");
        assert!(!json.contains("permissionDecisionReason"), "got: {json}");
    }

    #[test]
    fn unknown_mode_default_is_defer() {
        // Documents the user-visible default: tools without packs fall
        // through to Claude Code's own permission flow rather than being
        // forced through permit0's "ask" UI on every call.
        assert_eq!(UnknownMode::default(), UnknownMode::Defer);
    }

    #[test]
    fn unknown_mode_parses_each_variant() {
        assert_eq!("ask".parse::<UnknownMode>().unwrap(), UnknownMode::Ask);
        assert_eq!("allow".parse::<UnknownMode>().unwrap(), UnknownMode::Allow);
        assert_eq!("deny".parse::<UnknownMode>().unwrap(), UnknownMode::Deny);
        assert_eq!("defer".parse::<UnknownMode>().unwrap(), UnknownMode::Defer);
        assert!("HITL".parse::<UnknownMode>().is_err());
    }

    #[test]
    fn apply_unknown_policy_passes_known_actions_unchanged() {
        // Pack-backed verdicts must not be touched, even on Defer mode.
        let out = HookOutput::ask("permit0: payment.charge — risk 70/100 High");
        let result = apply_unknown_policy(out, false, UnknownMode::Defer);
        assert_eq!(result.hook_specific_output.permission_decision, Some("ask"),);
    }

    #[test]
    fn apply_unknown_policy_only_rewrites_ask() {
        // An unknown action that somehow matched an allowlist must keep
        // its allow verdict — operator allowlists win over --unknown.
        let out = HookOutput::allow();
        let result = apply_unknown_policy(out, true, UnknownMode::Deny);
        assert_eq!(
            result.hook_specific_output.permission_decision,
            Some("allow"),
        );

        // Same for denylist hits on unknown tool names.
        let out = HookOutput::deny("operator denylist");
        let result = apply_unknown_policy(out, true, UnknownMode::Defer);
        assert_eq!(
            result.hook_specific_output.permission_decision,
            Some("deny"),
        );
    }

    #[test]
    fn apply_unknown_policy_ask_mode_keeps_ask() {
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let result = apply_unknown_policy(out, true, UnknownMode::Ask);
        assert_eq!(result.hook_specific_output.permission_decision, Some("ask"),);
    }

    #[test]
    fn apply_unknown_policy_allow_mode_rewrites_to_allow() {
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let result = apply_unknown_policy(out, true, UnknownMode::Allow);
        assert_eq!(
            result.hook_specific_output.permission_decision,
            Some("allow"),
        );
        assert!(
            result
                .hook_specific_output
                .permission_decision_reason
                .is_none()
        );
    }

    #[test]
    fn apply_unknown_policy_deny_mode_rewrites_to_deny_with_reason() {
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let result = apply_unknown_policy(out, true, UnknownMode::Deny);
        assert_eq!(
            result.hook_specific_output.permission_decision,
            Some("deny"),
        );
        let reason = result
            .hook_specific_output
            .permission_decision_reason
            .as_deref()
            .unwrap_or_default();
        assert!(!reason.is_empty(), "deny mode must surface a reason");
    }

    #[test]
    fn apply_unknown_policy_defer_mode_drops_permission_decision() {
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let result = apply_unknown_policy(out, true, UnknownMode::Defer);
        assert!(result.hook_specific_output.permission_decision.is_none());
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("permissionDecision"), "got: {json}");
    }

    #[test]
    fn remote_transport_error_maps_to_ask_with_unavailable_reason() {
        // Daemon unreachable (DNS, connection refused, timeout). The
        // human must be alerted — silent allow would nullify governance
        // every time the daemon flaps.
        let err = RemoteError::Transport(
            "POST http://127.0.0.1:9090/api/v1/check: Connection refused".to_string(),
        );
        let (output, is_unknown) = remote_error_to_hook_output(&err);
        assert!(
            !is_unknown,
            "transport errors must not flow through --unknown"
        );
        assert_eq!(output.hook_specific_output.permission_decision, Some("ask"),);
        let reason = output
            .hook_specific_output
            .permission_decision_reason
            .as_deref()
            .unwrap_or_default();
        assert!(
            reason.contains("permit0 remote unavailable"),
            "reason should advertise unavailability, got: {reason}",
        );
        assert!(
            reason.contains("Connection refused"),
            "reason should preserve the underlying transport message, got: {reason}",
        );
    }

    #[test]
    fn remote_http_status_error_maps_to_deny_with_daemon_body() {
        // Daemon responded with a non‑2xx — typically a normalizer /
        // config bug surfaced by the engine. The daemon's own message
        // tells the operator exactly what to fix; "unavailable" would be
        // misleading because the network leg actually worked.
        let err = RemoteError::HttpStatus {
            status: 500,
            body: "engine error: normalization failed: missing required field 'message_id' in tool call 'gmail_read'".to_string(),
        };
        let (output, is_unknown) = remote_error_to_hook_output(&err);
        assert!(!is_unknown, "HTTP errors must not flow through --unknown");
        assert_eq!(
            output.hook_specific_output.permission_decision,
            Some("deny"),
        );
        let reason = output
            .hook_specific_output
            .permission_decision_reason
            .as_deref()
            .unwrap_or_default();
        assert!(
            reason.contains("HTTP 500"),
            "reason should announce status code, got: {reason}",
        );
        assert!(
            reason.contains("missing required field 'message_id'"),
            "reason should preserve the daemon's body so operators can debug, got: {reason}",
        );
    }

    #[test]
    fn remote_http_status_other_codes_still_deny() {
        // Any non‑2xx — not just 500 — should deny. We don't try to
        // interpret 4xx vs 5xx differently because the daemon's body
        // is what the operator needs to read either way.
        let err = RemoteError::HttpStatus {
            status: 422,
            body: "validation: tool_name missing".to_string(),
        };
        let (output, _) = remote_error_to_hook_output(&err);
        assert_eq!(
            output.hook_specific_output.permission_decision,
            Some("deny"),
        );
        assert!(
            output
                .hook_specific_output
                .permission_decision_reason
                .as_deref()
                .unwrap_or_default()
                .contains("HTTP 422"),
        );
    }

    #[test]
    fn remote_error_display_is_distinct_per_variant() {
        // Display impl is what flows into the run()‑loop's eprintln; if
        // the two variants formatted identically we'd lose the signal
        // that helped operators tell "daemon down" from "daemon angry"
        // in shadow logs and CI output.
        let transport = RemoteError::Transport("connection refused".into()).to_string();
        let http = RemoteError::HttpStatus {
            status: 503,
            body: "overloaded".into(),
        }
        .to_string();
        assert!(transport.starts_with("transport:"), "got: {transport}");
        assert!(http.starts_with("HTTP 503:"), "got: {http}");
        assert_ne!(transport, http);
    }

    #[test]
    fn remote_is_unknown_detects_canonical_action_type() {
        let resp = RemoteCheckResponse {
            permission: "humanintheloop".into(),
            action_type: Some("unknown.unclassified".into()),
            channel: Some("local".into()),
            score: Some(0),
            tier: Some("Medium".into()),
            block_reason: None,
        };
        assert!(remote_is_unknown(&resp));

        let resp = RemoteCheckResponse {
            permission: "humanintheloop".into(),
            action_type: Some("payment.charge".into()),
            channel: None,
            score: None,
            tier: None,
            block_reason: None,
        };
        assert!(!remote_is_unknown(&resp));

        let resp = RemoteCheckResponse {
            permission: "allow".into(),
            action_type: None,
            channel: None,
            score: None,
            tier: None,
            block_reason: None,
        };
        assert!(!remote_is_unknown(&resp));
    }

    #[test]
    fn claude_code_strips_mcp_double_underscore_prefix() {
        let c = ClientKind::ClaudeCode;
        assert_eq!(
            c.strip_prefix("mcp__permit0-outlook__outlook_send"),
            "outlook_send"
        );
        assert_eq!(
            c.strip_prefix("mcp__permit0-gmail__gmail_archive"),
            "gmail_archive"
        );
        // Tool names with single underscores survive (only the "__"
        // delimiter is consumed once).
        assert_eq!(
            c.strip_prefix("mcp__permit0-outlook__outlook_create_mailbox"),
            "outlook_create_mailbox"
        );
    }

    #[test]
    fn claude_code_passes_through_non_mcp_names() {
        let c = ClientKind::ClaudeCode;
        assert_eq!(c.strip_prefix("Bash"), "Bash");
        assert_eq!(c.strip_prefix("outlook_send"), "outlook_send");
        // Edge: starts with mcp__ but no second separator → no rewrite.
        assert_eq!(c.strip_prefix("mcp__weird"), "mcp__weird");
    }

    #[test]
    fn claude_desktop_passes_through_unchanged() {
        let c = ClientKind::ClaudeDesktop;
        assert_eq!(c.strip_prefix("outlook_send"), "outlook_send");
        // Even if a Claude-Code-style prefix accidentally arrives at a
        // claude-desktop hook, we DO NOT strip — the user said this client
        // doesn't prefix, so respect that.
        assert_eq!(
            c.strip_prefix("mcp__permit0-outlook__outlook_send"),
            "mcp__permit0-outlook__outlook_send"
        );
    }

    #[test]
    fn raw_passes_through_everything() {
        let c = ClientKind::Raw;
        assert_eq!(c.strip_prefix("anything_at_all"), "anything_at_all");
        assert_eq!(c.strip_prefix("mcp__a__b"), "mcp__a__b");
    }

    #[test]
    fn openclaw_strips_dot_prefix() {
        let c = ClientKind::OpenClaw;
        // mcporter shape: "<server>.<tool>"
        assert_eq!(c.strip_prefix("gmail.create_label"), "create_label");
        assert_eq!(c.strip_prefix("gmail.search_threads"), "search_threads");
        assert_eq!(c.strip_prefix("linear.list_issues"), "list_issues");
        // Bare names (built-in tools, plugin tools) pass through.
        assert_eq!(c.strip_prefix("exec"), "exec");
        assert_eq!(c.strip_prefix("Bash"), "Bash");
        // Only the FIRST dot is consumed. Tool names containing dots
        // after the server segment survive.
        assert_eq!(c.strip_prefix("server.tool.with.dots"), "tool.with.dots");
        // Edge: starts with "." → empty server, tool is the rest.
        assert_eq!(c.strip_prefix(".tool"), "tool");
    }

    #[test]
    fn client_kind_parses_from_string() {
        assert_eq!(
            "claude-code".parse::<ClientKind>().unwrap(),
            ClientKind::ClaudeCode
        );
        assert_eq!(
            "claude_code".parse::<ClientKind>().unwrap(),
            ClientKind::ClaudeCode
        );
        assert_eq!(
            "claude-desktop".parse::<ClientKind>().unwrap(),
            ClientKind::ClaudeDesktop
        );
        assert_eq!(
            "openclaw".parse::<ClientKind>().unwrap(),
            ClientKind::OpenClaw
        );
        assert_eq!(
            "open-claw".parse::<ClientKind>().unwrap(),
            ClientKind::OpenClaw
        );
        assert_eq!(
            "open_claw".parse::<ClientKind>().unwrap(),
            ClientKind::OpenClaw
        );
        assert_eq!("raw".parse::<ClientKind>().unwrap(), ClientKind::Raw);
        assert_eq!("none".parse::<ClientKind>().unwrap(), ClientKind::Raw);
        assert!("cursor".parse::<ClientKind>().is_err());
    }

    #[test]
    fn derive_session_id_explicit() {
        let id = derive_session_id(Some("my-session".into()));
        assert_eq!(id, "my-session");
    }

    #[test]
    fn derive_session_id_ppid_fallback() {
        let id = derive_session_id(None);
        // On Unix, should start with "ppid-". On Windows, the fallback
        // path uses a different scheme — we just assert non-empty so the
        // test compiles on both platforms.
        #[cfg(unix)]
        assert!(id.starts_with("ppid-"));
        #[cfg(not(unix))]
        assert!(!id.is_empty());
    }

    #[test]
    fn build_check_endpoint_appends_default_path() {
        assert_eq!(
            build_check_endpoint("http://127.0.0.1:9090"),
            "http://127.0.0.1:9090/api/v1/check"
        );
        assert_eq!(
            build_check_endpoint("http://127.0.0.1:9090/"),
            "http://127.0.0.1:9090/api/v1/check"
        );
    }

    #[test]
    fn build_check_endpoint_respects_explicit_path() {
        // If the user passes a URL that already includes `/api/`, leave
        // the path alone so they can point at custom mounts (e.g. behind
        // a reverse proxy).
        assert_eq!(
            build_check_endpoint("http://example.com/permit0/api/v1/check"),
            "http://example.com/permit0/api/v1/check"
        );
        assert_eq!(
            build_check_endpoint("http://example.com/api/v1/check/"),
            "http://example.com/api/v1/check"
        );
    }

    #[test]
    fn remote_response_allow_maps_to_allow() {
        let resp = RemoteCheckResponse {
            permission: "allow".into(),
            action_type: Some("file.read".into()),
            channel: Some("local".into()),
            score: Some(5),
            tier: Some("Minimal".into()),
            block_reason: None,
        };
        let out = remote_response_to_hook_output(&resp);
        assert_eq!(out.hook_specific_output.permission_decision, Some("allow"));
        assert!(
            out.hook_specific_output
                .permission_decision_reason
                .is_none()
        );
    }

    #[test]
    fn remote_response_deny_uses_block_reason() {
        let resp = RemoteCheckResponse {
            permission: "deny".into(),
            action_type: Some("shell.exec".into()),
            channel: Some("bash".into()),
            score: Some(95),
            tier: Some("Critical".into()),
            block_reason: Some("rm -rf /".into()),
        };
        let out = remote_response_to_hook_output(&resp);
        assert_eq!(out.hook_specific_output.permission_decision, Some("deny"));
        assert_eq!(
            out.hook_specific_output
                .permission_decision_reason
                .as_deref(),
            Some("rm -rf /")
        );
    }

    #[test]
    fn remote_response_deny_falls_back_when_no_block_reason() {
        let resp = RemoteCheckResponse {
            permission: "deny".into(),
            action_type: None,
            channel: None,
            score: None,
            tier: None,
            block_reason: None,
        };
        let out = remote_response_to_hook_output(&resp);
        assert_eq!(out.hook_specific_output.permission_decision, Some("deny"));
        // Make sure we still surface *some* reason — Claude Code shows it
        // to the user, and an empty deny reason is confusing.
        let reason = out
            .hook_specific_output
            .permission_decision_reason
            .as_deref()
            .unwrap_or_default();
        assert!(!reason.is_empty());
    }

    #[test]
    fn remote_response_humanintheloop_maps_to_ask() {
        let resp = RemoteCheckResponse {
            permission: "humanintheloop".into(),
            action_type: Some("email.send".into()),
            channel: Some("gmail".into()),
            score: Some(62),
            tier: Some("High".into()),
            block_reason: None,
        };
        let out = remote_response_to_hook_output(&resp);
        assert_eq!(out.hook_specific_output.permission_decision, Some("ask"));
        let reason = out
            .hook_specific_output
            .permission_decision_reason
            .clone()
            .unwrap_or_default();
        assert!(reason.contains("email.send"), "got: {reason}");
        assert!(reason.contains("gmail"), "got: {reason}");
        assert!(reason.contains("62/100"), "got: {reason}");
        assert!(reason.contains("High"), "got: {reason}");
    }

    #[test]
    fn remote_response_human_maps_to_ask() {
        // The daemon serializes Permission::HumanInTheLoop as "human"
        // (Display → "HUMAN" → to_lowercase()), not "humanintheloop".
        // Pin the canonical daemon value here so a server-side rename
        // would surface as a test failure instead of a silent
        // "unknown permission value 'human'" reason at runtime.
        let resp = RemoteCheckResponse {
            permission: "human".into(),
            action_type: Some("email.send".into()),
            channel: Some("gmail".into()),
            score: Some(62),
            tier: Some("High".into()),
            block_reason: None,
        };
        let out = remote_response_to_hook_output(&resp);
        assert_eq!(out.hook_specific_output.permission_decision, Some("ask"));
        let reason = out
            .hook_specific_output
            .permission_decision_reason
            .clone()
            .unwrap_or_default();
        assert!(reason.contains("email.send"), "got: {reason}");
        assert!(reason.contains("gmail"), "got: {reason}");
        assert!(
            !reason.contains("unknown permission value"),
            "must NOT show 'unknown permission' for the canonical \
             daemon value 'human', got: {reason}",
        );
    }

    #[test]
    fn remote_response_unknown_permission_fails_safe_to_ask() {
        // If the daemon ever adds a new Permission variant we don't know
        // about, prefer surfacing it to the human over silent allow.
        let resp = RemoteCheckResponse {
            permission: "quarantine".into(),
            action_type: None,
            channel: None,
            score: None,
            tier: None,
            block_reason: None,
        };
        let out = remote_response_to_hook_output(&resp);
        assert_eq!(out.hook_specific_output.permission_decision, Some("ask"));
        assert!(
            out.hook_specific_output
                .permission_decision_reason
                .as_deref()
                .unwrap_or_default()
                .contains("quarantine"),
        );
    }

    #[test]
    fn remote_response_parses_real_check_response_shape() {
        // Lock the deserialization to the actual `serve.rs::CheckResponse`
        // shape so a server-side rename doesn't silently break the hook.
        let json = r#"{
            "permission": "humanintheloop",
            "action_type": "email.send",
            "channel": "gmail",
            "norm_hash": "deadbeef",
            "score": 62,
            "tier": "High",
            "blocked": false,
            "block_reason": null,
            "source": "Scorer"
        }"#;
        let parsed: RemoteCheckResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.permission, "humanintheloop");
        assert_eq!(parsed.action_type.as_deref(), Some("email.send"));
        assert_eq!(parsed.score, Some(62));
    }

    #[test]
    fn remote_response_parses_actual_daemon_human_shape() {
        // The daemon's CheckResponse actually emits "human" (verified
        // via Permission::Display → "HUMAN" → to_lowercase() in
        // serve.rs). This pins the canonical wire shape so a future
        // server-side change would surface here.
        let json = r#"{
            "permission": "human",
            "action_type": "email.send",
            "channel": "gmail",
            "norm_hash": "deadbeef",
            "score": 62,
            "tier": "High",
            "blocked": false,
            "block_reason": null,
            "source": "Scorer"
        }"#;
        let parsed: RemoteCheckResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.permission, "human");
        let out = remote_response_to_hook_output(&parsed);
        assert_eq!(out.hook_specific_output.permission_decision, Some("ask"));
    }

    // ── Codex client / output format ──────────────────────────────────

    #[test]
    fn codex_client_kind_parses() {
        assert_eq!("codex".parse::<ClientKind>().unwrap(), ClientKind::Codex);
        assert_eq!(
            "codex-cli".parse::<ClientKind>().unwrap(),
            ClientKind::Codex
        );
        assert_eq!(
            "codex_cli".parse::<ClientKind>().unwrap(),
            ClientKind::Codex
        );
    }

    #[test]
    fn codex_client_kind_parser_is_case_sensitive() {
        // The existing parser is case-sensitive (e.g. "claude-code"
        // works but "Claude-Code" doesn't). Pin the same contract for
        // the new "codex" alias so behavior is consistent.
        assert!("Codex".parse::<ClientKind>().is_err());
        assert!("CODEX".parse::<ClientKind>().is_err());
    }

    #[test]
    fn codex_strips_mcp_double_underscore_prefix() {
        // Codex shares the Claude Code MCP convention; the strip rule
        // is identical (split on the first `__` after `mcp__`).
        let c = ClientKind::Codex;
        assert_eq!(
            c.strip_prefix("mcp__permit0-gmail__gmail_send"),
            "gmail_send"
        );
        assert_eq!(
            c.strip_prefix("mcp__permit0-outlook__outlook_archive"),
            "outlook_archive"
        );
        // Non-MCP names pass through.
        assert_eq!(c.strip_prefix("Bash"), "Bash");
        assert_eq!(c.strip_prefix("apply_patch"), "apply_patch");
        // Codex sanitizes hyphens to underscores in some contexts; the
        // splitter only consumes `__` so post-sanitization names still
        // work.
        assert_eq!(
            c.strip_prefix("mcp__permit0_gmail__gmail_send"),
            "gmail_send"
        );
    }

    #[test]
    fn output_format_from_client() {
        assert_eq!(
            OutputFormat::from_client(ClientKind::Codex),
            OutputFormat::Codex
        );
        assert_eq!(
            OutputFormat::from_client(ClientKind::ClaudeCode),
            OutputFormat::ClaudeCode
        );
        assert_eq!(
            OutputFormat::from_client(ClientKind::ClaudeDesktop),
            OutputFormat::ClaudeCode
        );
        assert_eq!(
            OutputFormat::from_client(ClientKind::OpenClaw),
            OutputFormat::ClaudeCode
        );
        assert_eq!(
            OutputFormat::from_client(ClientKind::Raw),
            OutputFormat::ClaudeCode
        );
    }

    // ── Codex hook input deserialization ─────────────────────────────

    #[test]
    fn codex_hook_input_full_payload() {
        // A full Codex PreToolUse payload must deserialize cleanly and
        // every captured field must be readable. Reading every field
        // here also keeps the dead_code lint happy without
        // `#[allow(dead_code)]` on the struct.
        let json = r#"{
            "session_id": "019dba93-8214-7d50-a089-9690b4ce6b9e",
            "transcript_path": "/home/user/.codex/history/019dba93.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.4",
            "turn_id": "turn-7",
            "tool_name": "mcp__permit0-gmail__gmail_send",
            "tool_use_id": "call_abc123",
            "tool_input": { "to": "alice@example.com", "subject": "Hi" }
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "mcp__permit0-gmail__gmail_send");
        assert_eq!(
            input.session_id.as_deref(),
            Some("019dba93-8214-7d50-a089-9690b4ce6b9e"),
        );
        assert_eq!(input.turn_id.as_deref(), Some("turn-7"));
        assert_eq!(input.cwd.as_deref(), Some("/home/user/project"));
        assert_eq!(input.hook_event_name.as_deref(), Some("PreToolUse"));
        assert_eq!(input.model.as_deref(), Some("gpt-5.4"));
        assert_eq!(input.tool_use_id.as_deref(), Some("call_abc123"));
        assert_eq!(
            input.transcript_path.as_deref(),
            Some("/home/user/.codex/history/019dba93.jsonl"),
        );
        assert_eq!(input.tool_input["to"], "alice@example.com");
    }

    #[test]
    fn hook_input_claude_code_compat() {
        // The Claude Code minimal payload must continue to deserialize
        // without errors after HookInput gained Codex-specific optional
        // fields. None of the Codex fields are populated.
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "ls"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "ls");
        assert!(input.session_id.is_none());
        assert!(input.turn_id.is_none());
        assert!(input.cwd.is_none());
        assert!(input.hook_event_name.is_none());
        assert!(input.model.is_none());
        assert!(input.tool_use_id.is_none());
        assert!(input.transcript_path.is_none());
    }

    #[test]
    fn build_tool_call_metadata_codex_payload() {
        // Codex stdin context fields flow into `RawToolCall.metadata`
        // so audit records show the originating thread / turn / model.
        let json = r#"{
            "session_id": "019dba93-8214",
            "transcript_path": "/tmp/x.jsonl",
            "cwd": "/home/u",
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.4",
            "turn_id": "turn-7",
            "tool_name": "Bash",
            "tool_use_id": "call_abc",
            "tool_input": {"command": "ls"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let metadata = build_tool_call_metadata(&input);
        assert_eq!(
            metadata.get("session_id").and_then(|v| v.as_str()),
            Some("019dba93-8214")
        );
        assert_eq!(
            metadata.get("turn_id").and_then(|v| v.as_str()),
            Some("turn-7")
        );
        assert_eq!(
            metadata.get("cwd").and_then(|v| v.as_str()),
            Some("/home/u")
        );
        assert_eq!(
            metadata.get("hook_event_name").and_then(|v| v.as_str()),
            Some("PreToolUse"),
        );
        assert_eq!(
            metadata.get("model").and_then(|v| v.as_str()),
            Some("gpt-5.4")
        );
        assert_eq!(
            metadata.get("tool_use_id").and_then(|v| v.as_str()),
            Some("call_abc"),
        );
        assert_eq!(
            metadata.get("transcript_path").and_then(|v| v.as_str()),
            Some("/tmp/x.jsonl"),
        );
    }

    #[test]
    fn build_tool_call_metadata_claude_payload_is_empty() {
        // Claude Code's minimal payload populates none of the optional
        // fields, so the metadata map remains empty — preserving the
        // pre-Codex behavior for non-Codex hooks.
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "ls"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let metadata = build_tool_call_metadata(&input);
        assert!(
            metadata.is_empty(),
            "Claude Code payload must yield empty metadata, got: {metadata:?}"
        );
    }

    #[test]
    fn build_tool_call_metadata_drops_empty_strings() {
        // Codex sometimes sends `""` for fields it cannot populate
        // (e.g. transcript_path on first turn). Empty strings must NOT
        // appear in metadata — they're forensically useless and would
        // confuse audit queries that filter by presence.
        let json = r#"{
            "session_id": "real",
            "transcript_path": "",
            "cwd": "",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let metadata = build_tool_call_metadata(&input);
        assert_eq!(
            metadata.get("session_id").and_then(|v| v.as_str()),
            Some("real")
        );
        assert!(!metadata.contains_key("transcript_path"));
        assert!(!metadata.contains_key("cwd"));
    }

    #[test]
    fn hook_input_codex_null_transcript_path() {
        // Codex may send `null` for transcript_path; Option<String>
        // handles this naturally via `#[serde(default)]`.
        let json = r#"{
            "session_id": "s1",
            "transcript_path": null,
            "tool_name": "Bash",
            "tool_input": {"command": "ls"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert!(input.transcript_path.is_none());
        assert_eq!(input.session_id.as_deref(), Some("s1"));
    }

    // ── Codex output serialization ───────────────────────────────────

    #[test]
    fn codex_output_allow_is_none() {
        // Allow MUST produce zero stdout bytes for Codex. Codex
        // explicitly rejects `permissionDecision: "allow"` and would
        // fail open if we sent it.
        let output = codex_output(Permission::Allow, "");
        assert!(
            output.is_none(),
            "Allow must produce no stdout for Codex, got: {output:?}",
        );
    }

    #[test]
    fn codex_output_deny_produces_envelope() {
        let output = codex_output(Permission::Deny, "destructive command blocked").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse",);
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny",);
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "destructive command blocked",
        );
    }

    #[test]
    fn codex_output_hitl_maps_to_deny_with_marker() {
        // Codex PreToolUse has no "ask" verdict. HITL maps to deny BUT
        // with the HITL marker appended so users can tell "would have
        // been an approval prompt" from "Critical-tier hard block".
        let output =
            codex_output(Permission::HumanInTheLoop, "permit0: email.send — High").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("permit0: email.send"),
            "original reason preserved, got: {reason}"
        );
        assert!(
            reason.contains("requires human review"),
            "HITL marker present, got: {reason}"
        );
    }

    #[test]
    fn codex_deny_envelope_escapes_reason_text() {
        // The reason is user-visible; if the operator's pack pushes a
        // reason containing quotes / newlines, the envelope must remain
        // valid JSON. We go through serde_json (not format!) precisely
        // to get this for free.
        let envelope = codex_deny_envelope("contains \"quotes\" and \n newlines");
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "contains \"quotes\" and \n newlines",
        );
    }

    #[test]
    fn hook_output_to_codex_allow_is_none() {
        // Allow envelope (Claude shape) → Codex must skip stdout.
        assert!(hook_output_to_codex(&HookOutput::allow()).is_none());
    }

    #[test]
    fn hook_output_to_codex_defer_is_none() {
        // Defer envelope (no permissionDecision) → Codex must skip
        // stdout. There's nothing to translate; Codex naturally falls
        // through to its default behavior for empty stdout.
        assert!(hook_output_to_codex(&HookOutput::defer()).is_none());
    }

    #[test]
    fn hook_output_to_codex_deny_uses_existing_reason() {
        let json = hook_output_to_codex(&HookOutput::deny("payment.charge — risk 95/100")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            parsed["hookSpecificOutput"]["permissionDecisionReason"],
            "payment.charge — risk 95/100",
        );
    }

    #[test]
    fn hook_output_to_codex_ask_maps_to_deny_with_marker() {
        let json = hook_output_to_codex(&HookOutput::ask("email.send — High")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("email.send — High"),
            "original reason preserved, got: {reason}"
        );
        assert!(
            reason.contains("requires human review"),
            "HITL marker appended for Codex, got: {reason}"
        );
    }

    #[test]
    fn hook_output_to_codex_ask_with_no_reason_uses_marker_text() {
        // If somehow a HookOutput::ask with no reason reaches the Codex
        // emitter (defensive — the constructor always sets one), we
        // still emit a non-empty deny envelope so Codex never sees
        // empty stdout for an ask verdict.
        let custom = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some("ask"),
                permission_decision_reason: None,
            },
        };
        let json = hook_output_to_codex(&custom).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("requires human review"),
            "HITL marker present even without source reason, got: {reason}"
        );
    }

    #[test]
    fn hook_output_to_codex_never_emits_allow_decision() {
        // Critical Codex invariant: stdout must never contain
        // `permissionDecision: "allow"`. Codex explicitly rejects that
        // form and the tool would fail open with a warning. Use a
        // structural JSON check (not substring matching) so a deny
        // reason that happens to contain the literal text "allow" does
        // not falsely fail.
        for hook_out in [
            HookOutput::allow(),
            HookOutput::deny("test"),
            HookOutput::ask("test"),
            HookOutput::defer(),
        ] {
            if let Some(json) = hook_output_to_codex(&hook_out) {
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_ne!(
                    parsed["hookSpecificOutput"]["permissionDecision"], "allow",
                    "Codex must never produce permissionDecision: allow, got: {json}",
                );
            }
        }
    }

    #[test]
    fn hook_output_to_codex_unknown_decision_label_fails_closed() {
        // Defensive: if a future Claude Code verdict added a new label
        // (e.g. "quarantine") and somehow flowed into the Codex emit
        // path, we must block the tool rather than fail open.
        let custom = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some("quarantine"),
                permission_decision_reason: Some("speculative".into()),
            },
        };
        let json = hook_output_to_codex(&custom).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("quarantine"),
            "must surface the unexpected label, got: {reason}",
        );
    }

    #[test]
    fn codex_unknown_defer_yields_empty_stdout() {
        // Combining `apply_unknown_policy(.., Defer)` with the Codex
        // emitter must produce zero bytes — defer means "no opinion"
        // and Codex interprets empty stdout as "let the tool run".
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let policy_result = apply_unknown_policy(out, true, UnknownMode::Defer);
        assert!(
            hook_output_to_codex(&policy_result).is_none(),
            "Defer + Codex must skip stdout entirely",
        );
    }

    #[test]
    fn codex_unknown_deny_yields_deny_envelope() {
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let policy_result = apply_unknown_policy(out, true, UnknownMode::Deny);
        let json = hook_output_to_codex(&policy_result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn codex_unknown_ask_yields_deny_envelope_with_marker() {
        // `--unknown ask` is the one mode whose output type is
        // unchanged by `apply_unknown_policy` (it keeps the `ask`
        // verdict). The Codex emit then converts ask → deny + HITL
        // marker, which is the most behaviorally distinct combination
        // and the one the other three (Allow/Deny/Defer) composition
        // tests don't exercise.
        let original = HookOutput::ask("permit0: unknown.unclassified");
        let policy_result = apply_unknown_policy(original, true, UnknownMode::Ask);
        // Sanity: Ask mode preserves the ask verdict.
        assert_eq!(
            policy_result.hook_specific_output.permission_decision,
            Some("ask"),
        );
        let json = hook_output_to_codex(&policy_result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("permit0: unknown.unclassified"),
            "original ask reason preserved, got: {reason}"
        );
        assert!(
            reason.contains("requires human review"),
            "HITL marker appended, got: {reason}"
        );
    }

    #[test]
    fn codex_unknown_allow_yields_empty_stdout() {
        // `--unknown allow` rewrites to HookOutput::allow(), which the
        // Codex emitter correctly turns into zero bytes — Codex would
        // reject the literal `permissionDecision: "allow"` form.
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let policy_result = apply_unknown_policy(out, true, UnknownMode::Allow);
        assert!(
            hook_output_to_codex(&policy_result).is_none(),
            "Unknown::Allow + Codex must skip stdout entirely",
        );
    }

    // ── Codex remote daemon mapping ──────────────────────────────────

    #[test]
    fn codex_remote_human_response_maps_to_deny() {
        // Pins the end-to-end remote → Codex behavior for HITL using
        // the canonical daemon value `"human"` (not "humanintheloop").
        // After the prerequisite fix, the deny envelope must include
        // the full risk reason — NOT "unknown permission value 'human'".
        let resp = RemoteCheckResponse {
            permission: "human".into(),
            action_type: Some("email.send".into()),
            channel: Some("gmail".into()),
            score: Some(62),
            tier: Some("High".into()),
            block_reason: None,
        };
        let hook_out = remote_response_to_hook_output(&resp);
        let codex = hook_output_to_codex(&hook_out).expect("HITL must produce a deny envelope");
        let parsed: serde_json::Value = serde_json::from_str(&codex).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("email.send"),
            "reason must include action type, got: {reason}",
        );
        assert!(
            !reason.contains("unknown permission value"),
            "must NOT show 'unknown permission' for canonical daemon value, got: {reason}",
        );
    }

    #[test]
    fn codex_remote_transport_error_maps_to_deny() {
        // Remote daemon down → Codex must fail closed (deny). This is
        // stricter than the Claude path (which prompts the user via
        // ask), and is the correct Codex behavior since Codex has no
        // ask verdict in PreToolUse.
        let err = RemoteError::Transport(
            "POST http://127.0.0.1:9999/api/v1/check: Connection refused".to_string(),
        );
        let (hook_out, _) = remote_error_to_hook_output(&err);
        let codex = hook_output_to_codex(&hook_out).expect("transport error must produce a deny");
        let parsed: serde_json::Value = serde_json::from_str(&codex).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(
            reason.contains("permit0 remote unavailable"),
            "deny reason must explain transport failure, got: {reason}",
        );
    }

    // ── Codex session ID derivation ──────────────────────────────────

    #[test]
    fn codex_session_id_from_stdin() {
        let id =
            derive_session_id_for_format(OutputFormat::Codex, Some("019dba93-8214".into()), None);
        assert_eq!(id, "019dba93-8214");
    }

    #[test]
    fn codex_session_id_explicit_overrides_stdin() {
        let id = derive_session_id_for_format(
            OutputFormat::Codex,
            Some("stdin-id".into()),
            Some("explicit-id".into()),
        );
        assert_eq!(id, "explicit-id");
    }

    #[test]
    fn codex_session_id_empty_stdin_falls_through() {
        // An empty-string `session_id` from Codex must be treated as
        // absent — falling through to env var / PPID. Otherwise an
        // empty payload field would poison the session store.
        let id = derive_session_id_for_format(OutputFormat::Codex, Some(String::new()), None);
        // Should NOT be the empty string; falls through to ppid_fallback.
        assert!(!id.is_empty(), "empty stdin must not pin to empty id");
    }

    #[cfg(unix)]
    #[test]
    fn codex_session_id_falls_through_to_ppid_not_claude_env() {
        // Codex must NEVER consult CLAUDE_SESSION_ID — a stale Claude
        // env var in a side-by-side Claude+Codex workstation would
        // otherwise cross-contaminate the Codex session.
        //
        // We don't manipulate env vars here (would race with parallel
        // tests under cargo test). Instead we rely on the structural
        // contract: when stdin is absent and CODEX_THREAD_ID is unset
        // (the default test environment), the result must be the
        // PPID fallback shape `ppid-<n>` regardless of whether
        // CLAUDE_SESSION_ID happens to be set in the test process.
        // If CODEX_THREAD_ID is set in the environment for some
        // reason, this assertion's failure mode is informative
        // enough — it will print the unexpected ID.
        let id = derive_session_id_for_format(OutputFormat::Codex, None, None);
        if std::env::var_os("CODEX_THREAD_ID").is_none() {
            assert!(
                id.starts_with("ppid-"),
                "Codex must use PPID fallback (not CLAUDE_SESSION_ID), got: {id}",
            );
        }
    }

    #[test]
    fn claude_session_id_ignores_stdin() {
        // Under Claude Code format, stdin session_id is not consulted
        // (Claude doesn't put it in stdin payloads). The function
        // should fall through to the existing derive_session_id path.
        // To assert this without env-var contamination, give an
        // explicit flag — that wins regardless of format.
        let id = derive_session_id_for_format(
            OutputFormat::ClaudeCode,
            Some("ignored-stdin".into()),
            Some("explicit".into()),
        );
        assert_eq!(id, "explicit");
    }

    // ── Codex emit_hook_output ───────────────────────────────────────

    #[test]
    fn emit_hook_output_codex_allow_writes_nothing_visible() {
        // Compile-only sanity check: `emit_hook_output` does I/O so we
        // can't capture stdout from a unit test trivially, but we can
        // verify the helper compiles for both formats and that
        // hook_output_to_codex agrees with the contract for allow.
        // (The end-to-end "empty stdout" behavior is verified in the
        // integration test suite.)
        let allow = HookOutput::allow();
        assert!(hook_output_to_codex(&allow).is_none());
    }
}
