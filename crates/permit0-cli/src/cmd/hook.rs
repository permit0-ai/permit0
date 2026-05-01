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
use permit0_types::{Permission, RawToolCall};

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
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
}

impl HookOutput {
    pub fn allow() -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "allow",
                permission_decision_reason: None,
            },
        }
    }
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: Some(reason.into()),
            },
        }
    }
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "ask",
                permission_decision_reason: Some(reason.into()),
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

/// Run the PreToolUse hook adapter.
///
/// `client` selects which MCP host calls us, controlling how tool-name
/// prefixes are stripped before normalization. See [`ClientKind`].
pub fn run(
    profile: Option<String>,
    org_domain: &str,
    db_path: Option<String>,
    session_id: Option<String>,
    packs_dir: Option<String>,
    shadow: bool,
    client: ClientKind,
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

    // Shadow mode: log the would-be decision and always allow.
    let output = if shadow {
        if decision_label != "allow" {
            eprintln!(
                "[permit0 shadow] WOULD {}: {} ({}) score={}/100  {}",
                decision_label.to_uppercase(),
                result.norm_action.action_type.as_action_str(),
                result.norm_action.channel,
                result.risk_score.as_ref().map_or(0, |s| s.score),
                reason,
            );
        }
        HookOutput::allow()
    } else {
        match decision_label {
            "allow" => HookOutput::allow(),
            "deny" => HookOutput::deny(reason),
            "ask" => HookOutput::ask(reason),
            _ => HookOutput::allow(), // unreachable, but defensible
        }
    };

    // Write JSON response to stdout
    println!("{}", serde_json::to_string(&output)?);

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
}
