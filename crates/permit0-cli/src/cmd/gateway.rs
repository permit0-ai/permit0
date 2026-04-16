#![forbid(unsafe_code)]

//! Generic stdin/stdout JSON gateway.
//!
//! Reads JSON tool calls from stdin (one per line, JSONL format),
//! evaluates each through the permit0 engine, and writes a JSON
//! decision to stdout for each.
//!
//! Usage:
//! ```sh
//! cat tool_calls.jsonl | permit0 gateway --profile fintech
//! ```
//!
//! Input format (one per line):
//! ```json
//! {"tool": "Bash", "input": {"command": "ls"}}
//! ```
//!
//! Output format (one per line):
//! ```json
//! {"permission": "allow", "action_type": "system.exec", "channel": "bash", "score": 12, "tier": "Minimal"}
//! ```

use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use permit0_engine::PermissionCtx;
use permit0_normalize::NormalizeCtx;
use permit0_types::RawToolCall;

/// Gateway input — same as RawToolCall but we accept either field naming.
#[derive(Debug, Deserialize)]
struct GatewayInput {
    #[serde(alias = "tool")]
    tool_name: String,
    #[serde(alias = "input")]
    parameters: serde_json::Value,
}

use crate::engine_factory;

/// Gateway output format.
#[derive(Debug, Serialize)]
pub struct GatewayDecision {
    pub permission: String,
    pub action_type: String,
    pub channel: String,
    pub norm_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_reason: Option<String>,
    pub source: String,
}

/// Gateway error output.
#[derive(Debug, Serialize)]
pub struct GatewayError {
    pub error: String,
    pub line: usize,
}

/// Run the JSON gateway.
pub fn run(profile: Option<String>, org_domain: &str) -> Result<()> {
    let engine = engine_factory::build_engine_from_packs(profile.as_deref(), None)?;
    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain));

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for (i, line) in stdin.lock().lines().enumerate() {
        let line = line.context("reading stdin line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match process_line(trimmed, &engine, &ctx) {
            Ok(decision) => {
                serde_json::to_writer(&mut out, &decision)?;
                writeln!(out)?;
            }
            Err(e) => {
                let err = GatewayError {
                    error: e.to_string(),
                    line: i + 1,
                };
                serde_json::to_writer(&mut out, &err)?;
                writeln!(out)?;
            }
        }
        out.flush()?;
    }

    Ok(())
}

fn process_line(
    json_str: &str,
    engine: &permit0_engine::Engine,
    ctx: &PermissionCtx,
) -> Result<GatewayDecision> {
    let input: GatewayInput =
        serde_json::from_str(json_str).context("parsing tool call JSON")?;
    let tool_call = RawToolCall {
        tool_name: input.tool_name,
        parameters: input.parameters,
        metadata: Default::default(),
    };

    let result = engine.get_permission(&tool_call, ctx)?;

    Ok(GatewayDecision {
        permission: result.permission.to_string().to_lowercase(),
        action_type: result.norm_action.action_type.as_action_str().to_string(),
        channel: result.norm_action.channel.clone(),
        norm_hash: result.norm_action.norm_hash_hex(),
        score: result.risk_score.as_ref().map(|s| s.score),
        tier: result.risk_score.as_ref().map(|s| s.tier.to_string()),
        blocked: result.risk_score.as_ref().map(|s| s.blocked),
        block_reason: result
            .risk_score
            .as_ref()
            .and_then(|s| s.block_reason.clone()),
        source: format!("{:?}", result.source),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_decision_serialization() {
        let decision = GatewayDecision {
            permission: "allow".into(),
            action_type: "system.exec".into(),
            channel: "bash".into(),
            norm_hash: "abc123".into(),
            score: Some(12),
            tier: Some("Minimal".into()),
            blocked: Some(false),
            block_reason: None,
            source: "Scoring".into(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains(r#""permission":"allow""#));
        assert!(json.contains(r#""action_type":"system.exec""#));
        assert!(!json.contains("block_reason"));
    }

    #[test]
    fn gateway_error_serialization() {
        let err = GatewayError {
            error: "parse error".into(),
            line: 3,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains(r#""error":"parse error""#));
        assert!(json.contains(r#""line":3"#));
    }
}
