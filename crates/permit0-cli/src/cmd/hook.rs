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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use permit0_engine::PermissionCtx;
use permit0_normalize::NormalizeCtx;
use permit0_types::{Permission, RawToolCall};

use crate::engine_factory;

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

/// Run the Claude Code hook adapter.
pub fn run(
    profile: Option<String>,
    org_domain: &str,
    db_path: Option<String>,
    session_id: Option<String>,
    packs_dir: Option<String>,
) -> Result<()> {
    // Read hook input from stdin
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading hook input from stdin")?;

    let hook_input: HookInput =
        serde_json::from_str(&buf).context("parsing hook input JSON")?;

    // Convert to RawToolCall
    let tool_call = RawToolCall {
        tool_name: hook_input.tool_name,
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
    let output = match result.permission {
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
