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
//! Usage as a Claude Code hook:
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [{
//!       "command": "permit0 hook --profile fintech",
//!       "description": "permit0 agent safety check"
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

/// Run the Claude Code hook adapter.
pub fn run(profile: Option<String>, org_domain: &str) -> Result<()> {
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
    let engine = engine_factory::build_engine_from_packs(profile.as_deref())?;

    // Build context
    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain));

    // Evaluate
    let result = engine.get_permission(&tool_call, &ctx)?;

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
}
