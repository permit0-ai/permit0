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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// Claude Code (CLI, terminal). Prefixes MCP tools as
    /// `mcp__<server>__<tool>` (double underscore separator). This is the
    /// default since it's the most common deployment.
    ClaudeCode,
    /// Claude Desktop (macOS/Windows GUI app). Passes MCP tool names
    /// as-is, no prefix.
    ClaudeDesktop,
    /// No prefix stripping at all. Use this when you're calling the hook
    /// directly (e.g. from tests or a custom integration that already
    /// hands you the bare tool name).
    Raw,
}

impl ClientKind {
    /// Strip the host-specific prefix from a tool name, leaving the bare
    /// name normalizers expect.
    pub fn strip_prefix<'a>(self, tool_name: &'a str) -> &'a str {
        match self {
            // Claude Code: "mcp__<server>__<tool>" — first "__" after
            // "mcp__" separates server from tool.
            Self::ClaudeCode => tool_name
                .strip_prefix("mcp__")
                .and_then(|rest| rest.split_once("__").map(|(_, tool)| tool))
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
            "raw" | "none" => Ok(Self::Raw),
            other => Err(format!(
                "unknown client '{other}' (supported: claude-code, claude-desktop, raw)"
            )),
        }
    }
}

impl Default for ClientKind {
    fn default() -> Self {
        Self::ClaudeCode
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

/// Claude Code hook output format.
#[derive(Debug, Serialize)]
pub struct HookOutput {
    /// One of: "allow", "block", "ask_user".
    pub decision: String,
    /// Reason (for "block" or "ask_user").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Message to show the user (for "ask_user").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
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
        return format!("ppid-{ppid}");
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

    let hook_input: HookInput =
        serde_json::from_str(&buf).context("parsing hook input JSON")?;

    // Strip the host-specific MCP prefix (if any) so YAML normalizers can
    // match the bare tool name. See `ClientKind::strip_prefix`.
    let tool_call = RawToolCall {
        tool_name: client.strip_prefix(&hook_input.tool_name).to_string(),
        parameters: hook_input.tool_input,
        metadata: Default::default(),
    };

    // Build engine
    let engine = engine_factory::build_engine_from_packs(
        profile.as_deref(),
        packs_dir.as_deref(),
    )?;

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

    let session_id_str = session_store.as_ref().map(|_| derive_session_id(session_id));
    let session_ctx = session_id_str.as_ref().and_then(|sid| {
        session_store.as_ref().and_then(|store| store.get_session(sid))
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

    // Map to hook output
    let real_output = match result.permission {
        Permission::Allow => HookOutput {
            decision: "allow".into(),
            reason: None,
            message: None,
        },
        Permission::Deny => {
            let reason = result
                .risk_score
                .as_ref()
                .and_then(|s| s.block_reason.clone())
                .unwrap_or_else(|| format!("denied: {:?}", result.source));
            HookOutput {
                decision: "block".into(),
                reason: Some(reason),
                message: None,
            }
        }
        Permission::HumanInTheLoop => {
            let msg = format!(
                "permit0: {} ({}) — risk {}/100 {:?}. Allow this action?",
                result.norm_action.action_type.as_action_str(),
                result.norm_action.channel,
                result.risk_score.as_ref().map_or(0, |s| s.score),
                result.risk_score.as_ref().map_or(
                    permit0_types::Tier::Medium,
                    |s| s.tier
                ),
            );
            HookOutput {
                decision: "ask_user".into(),
                reason: None,
                message: Some(msg),
            }
        }
    };

    // Shadow mode: log the would-be decision and always allow.
    let output = if shadow {
        if real_output.decision != "allow" {
            let action = result.norm_action.action_type.as_action_str();
            let channel = &result.norm_action.channel;
            let score = result.risk_score.as_ref().map_or(0, |s| s.score);
            let detail = real_output.reason.as_deref()
                .or(real_output.message.as_deref())
                .unwrap_or("");
            eprintln!(
                "[permit0 shadow] WOULD {}: {} ({}) score={}/100  {}",
                real_output.decision.to_uppercase(),
                action,
                channel,
                score,
                detail,
            );
        }
        HookOutput {
            decision: "allow".into(),
            reason: None,
            message: None,
        }
    } else {
        real_output
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

    #[test]
    fn hook_output_allow_serialization() {
        let output = HookOutput {
            decision: "allow".into(),
            reason: None,
            message: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains(r#""decision":"allow""#));
        assert!(!json.contains("reason"));
        assert!(!json.contains("message"));
    }

    #[test]
    fn hook_output_block_serialization() {
        let output = HookOutput {
            decision: "block".into(),
            reason: Some("dangerous command".into()),
            message: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains(r#""decision":"block""#));
        assert!(json.contains(r#""reason":"dangerous command""#));
    }

    #[test]
    fn hook_output_ask_user_serialization() {
        let output = HookOutput {
            decision: "ask_user".into(),
            reason: None,
            message: Some("Allow this?".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains(r#""decision":"ask_user""#));
        assert!(json.contains(r#""message":"Allow this?""#));
    }

    #[test]
    fn claude_code_strips_mcp_double_underscore_prefix() {
        let c = ClientKind::ClaudeCode;
        assert_eq!(c.strip_prefix("mcp__permit0-outlook__outlook_send"), "outlook_send");
        assert_eq!(c.strip_prefix("mcp__permit0-gmail__gmail_archive"), "gmail_archive");
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
    fn client_kind_parses_from_string() {
        assert_eq!("claude-code".parse::<ClientKind>().unwrap(), ClientKind::ClaudeCode);
        assert_eq!("claude_code".parse::<ClientKind>().unwrap(), ClientKind::ClaudeCode);
        assert_eq!("claude-desktop".parse::<ClientKind>().unwrap(), ClientKind::ClaudeDesktop);
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
        // On Unix, should start with "ppid-"
        #[cfg(unix)]
        assert!(id.starts_with("ppid-"));
    }
}
