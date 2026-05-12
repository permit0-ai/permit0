#![forbid(unsafe_code)]

//! Claude Code PreToolUse hook adapter.
//!
//! Claude Code invokes hooks with a JSON payload on stdin describing
//! the tool call. The hook responds with a JSON object:
//!
//! - `{ "decision": "allow" }` — permit the tool call
//! - `{ "decision": "block", "reason": "..." }` — deny the tool call
//! - `{ "decision": "ask_user", "message": "..." }` — human-in-the-loop
//!
//! ## Session-Aware Mode
//!
//! When `--db` is provided, the hook persists session context to SQLite,
//! enabling cross-invocation pattern detection (velocity, attack chains).
//!
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [{
//!       "command": "permit0 hook --profile my-profile --db ~/.permit0/sessions.db",
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
            // Claude Code: "mcp__<server>__<tool>" — first "__" after
            // "mcp__" separates server from tool.
            Self::ClaudeCode => tool_name
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
            "raw" | "none" => Ok(Self::Raw),
            other => Err(format!(
                "unknown client '{other}' (supported: claude-code, claude-desktop, openclaw, raw)"
            )),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownMode {
    /// Emit `permissionDecision: "ask"` with permit0's reasoning. The user
    /// is prompted via Claude Code's UI before the tool runs.
    Ask,
    /// Emit `permissionDecision: "allow"` — the tool runs unprompted.
    /// Sharp edge: blanket‑allows anything permit0 doesn't recognize.
    Allow,
    /// Emit `permissionDecision: "deny"` with a generic reason — the tool
    /// is blocked. Use for whitelist‑only setups where every governed action
    /// must be packaged.
    Deny,
    /// Emit a hook output with **no** `permissionDecision`, letting Claude
    /// Code's own permission flow take over (settings allowlists, then its
    /// native ask UI). Default — permit0 only intervenes for tools it has
    /// packs for.
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

/// Claude Code hook input format.
///
/// Claude Code passes the tool name and input as JSON.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// The tool name (e.g. "Bash", "Write", "Edit").
    pub tool_name: String,
    /// The tool input parameters.
    pub tool_input: serde_json::Value,
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

/// Derive session ID from available sources.
fn derive_session_id(explicit: Option<String>) -> String {
    // 1. Explicit --session-id flag
    if let Some(id) = explicit {
        return id;
    }
    // 2. CLAUDE_SESSION_ID environment variable
    if let Ok(id) = std::env::var("CLAUDE_SESSION_ID") {
        if !id.is_empty() {
            return id;
        }
    }
    // 3. PPID (parent process ID — stable within a Claude Code conversation)
    #[cfg(unix)]
    {
        let ppid = std::os::unix::process::parent_id();
        format!("ppid-{ppid}")
    }
    #[cfg(not(unix))]
    {
        // 4. Fallback: hash of current working directory
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".into());
        format!("cwd-{:x}", fxhash(&cwd))
    }
}

#[cfg(not(unix))]
fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u64);
    }
    h
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
fn remote_response_to_hook_output(resp: &RemoteCheckResponse) -> HookOutput {
    match resp.permission.as_str() {
        "allow" => HookOutput::allow(),
        "deny" => HookOutput::deny(
            resp.block_reason
                .clone()
                .unwrap_or_else(|| "permit0 denied (remote)".into()),
        ),
        "humanintheloop" => HookOutput::ask(format!(
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
/// `client` selects which MCP host calls us, controlling how tool-name
/// prefixes are stripped before normalization. See [`ClientKind`].
///
/// `remote` (if `Some`) delegates evaluation to a running `permit0 serve
/// --ui` daemon at that URL; in that mode the local engine is never built
/// and `profile` / `packs_dir` / `db_path` / `session_id` are ignored.
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
    let shadow = shadow || std::env::var("PERMIT0_SHADOW").is_ok_and(|v| !v.is_empty() && v != "0");
    // Read hook input from stdin
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading hook input from stdin")?;

    let hook_input: HookInput = serde_json::from_str(&buf).context("parsing hook input JSON")?;

    // Strip the host-specific MCP prefix (if any) so YAML normalizers can
    // match the bare tool name. See `ClientKind::strip_prefix`.
    let tool_call = RawToolCall {
        tool_name: client.strip_prefix(&hook_input.tool_name).to_string(),
        parameters: hook_input.tool_input,
        metadata: Default::default(),
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
        println!("{}", serde_json::to_string(&final_output)?);
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

    let session_id_str = session_store
        .as_ref()
        .map(|_| derive_session_id(session_id));
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

    // Resolve to Claude Code's permissionDecision values:
    //   allow  → tool runs unprompted
    //   deny   → tool blocked, reason shown to user/agent
    //   ask    → user prompted; their choice routes the call
    //   defer  → fall through to next hook / default behavior
    let (decision_label, reason): (&'static str, String) = match result.permission {
        Permission::Allow => ("allow", String::new()),
        Permission::Deny => (
            "deny",
            result
                .risk_score
                .as_ref()
                .and_then(|s| s.block_reason.clone())
                .unwrap_or_else(|| format!("permit0 denied: {:?}", result.source)),
        ),
        Permission::HumanInTheLoop => (
            "ask",
            format!(
                "permit0: {} ({}) — risk {}/100 {:?}",
                result.norm_action.action_type.as_action_str(),
                result.norm_action.channel,
                result.risk_score.as_ref().map_or(0, |s| s.score),
                result
                    .risk_score
                    .as_ref()
                    .map_or(permit0_types::Tier::Medium, |s| s.tier),
            ),
        ),
    };

    // Build the base hook output from permit0's verdict, then apply the
    // --unknown policy (which only fires for unknown→ask). Shadow mode
    // observes the post-policy decision so logs reflect what the user
    // would actually see when shadow is removed.
    let base_output = match decision_label {
        "allow" => HookOutput::allow(),
        "deny" => HookOutput::deny(reason),
        "ask" => HookOutput::ask(reason),
        _ => HookOutput::allow(), // unreachable, but defensible
    };
    let is_unknown = result.norm_action.domain() == Domain::Unknown;
    let output = apply_unknown_policy(base_output, is_unknown, unknown);

    // Shadow mode: log the would-be decision and always allow.
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

    // Write JSON response to stdout
    println!("{}", serde_json::to_string(&final_output)?);

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
}
