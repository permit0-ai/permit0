#![forbid(unsafe_code)]

use std::io::Read;

use anyhow::{Context, Result};
use permit0_engine::PermissionCtx;
use permit0_normalize::NormalizeCtx;
use permit0_types::RawToolCall;

use crate::engine_factory;

pub fn run(input: Option<String>, profile: Option<String>, org_domain: &str) -> Result<()> {
    // Read input
    let json_str = match input {
        Some(s) => s,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };

    let tool_call: RawToolCall =
        serde_json::from_str(&json_str).context("parsing tool call JSON")?;

    // Build engine
    let engine = engine_factory::build_engine_from_packs(profile.as_deref())?;

    // Build context
    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain));

    // Evaluate
    let result = engine.get_permission(&tool_call, &ctx)?;

    // Output
    println!("┌─ permit0 decision ─────────────────────────");
    println!("│ Permission:  {}", result.permission);
    println!("│ Source:      {:?}", result.source);
    println!(
        "│ Action:      {}",
        result.norm_action.action_type.as_action_str()
    );
    println!("│ Channel:     {}", result.norm_action.channel);
    println!(
        "│ NormHash:    {}",
        result.norm_action.norm_hash_hex()
    );

    if let Some(ref score) = result.risk_score {
        println!("├─ risk score ───────────────────────────────");
        println!("│ Raw:         {:.4}", score.raw);
        println!("│ Score:       {}/100", score.score);
        println!("│ Tier:        {}", score.tier);
        println!("│ Blocked:     {}", score.blocked);
        if !score.flags.is_empty() {
            println!("│ Flags:       {}", score.flags.join(", "));
        }
        if let Some(ref reason) = score.block_reason {
            println!("│ Block:       {reason}");
        }
        println!("│ Reason:      {}", score.reason);
    }

    println!("└────────────────────────────────────────────");

    // Exit code: 0 = allow, 1 = HITL, 2 = deny
    let code = match result.permission {
        permit0_types::Permission::Allow => 0,
        permit0_types::Permission::HumanInTheLoop => 1,
        permit0_types::Permission::Deny => 2,
    };
    std::process::exit(code);
}
