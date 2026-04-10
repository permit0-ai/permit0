#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context, Result};
use permit0_engine::PermissionCtx;
use permit0_normalize::NormalizeCtx;
use permit0_types::RawToolCall;

use crate::engine_factory;

/// Run golden calibration corpus: each case specifies a tool call and expected tier.
pub fn test_corpus(corpus_path: &str) -> Result<()> {
    let corpus_dir = Path::new(corpus_path);
    if !corpus_dir.exists() {
        anyhow::bail!("corpus directory not found: {corpus_path}");
    }

    // Build engine with all packs (no profile — base config)
    let engine = engine_factory::build_engine_from_packs(None)?;
    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("calibration.test"));

    let mut passed = 0;
    let mut failed = 0;
    let mut errors = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(corpus_dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            continue;
        }
        let yaml = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let case: CorpusCase = serde_yaml::from_str(&yaml)
            .with_context(|| format!("parsing {}", path.display()))?;

        let tool_call = RawToolCall {
            tool_name: case.tool_name,
            parameters: case.parameters,
            metadata: Default::default(),
        };

        match engine.get_permission(&tool_call, &ctx) {
            Ok(result) => {
                let actual_tier = result
                    .risk_score
                    .as_ref()
                    .map(|s| s.tier.to_string())
                    .unwrap_or_else(|| "NONE".to_string());
                let actual_perm = format!("{}", result.permission);

                let tier_ok = case.expected_tier.is_none()
                    || case
                        .expected_tier
                        .as_ref()
                        .is_some_and(|t| t.to_uppercase() == actual_tier);
                let perm_ok = case.expected_permission.is_none()
                    || case
                        .expected_permission
                        .as_ref()
                        .is_some_and(|p| p.to_uppercase() == actual_perm);

                if tier_ok && perm_ok {
                    println!("  ✓ {}: tier={actual_tier} perm={actual_perm}", case.name);
                    passed += 1;
                } else {
                    let msg = format!(
                        "{}: expected tier={} perm={}, got tier={actual_tier} perm={actual_perm}",
                        case.name,
                        case.expected_tier.as_deref().unwrap_or("any"),
                        case.expected_permission.as_deref().unwrap_or("any"),
                    );
                    println!("  ✗ {msg}");
                    errors.push(msg);
                    failed += 1;
                }
            }
            Err(e) => {
                let msg = format!("{}: error: {e}", case.name);
                println!("  ✗ {msg}");
                errors.push(msg);
                failed += 1;
            }
        }
    }

    println!("\n── Calibration Results ──");
    println!("{passed} passed, {failed} failed, {} total", passed + failed);

    if failed > 0 {
        println!("\nFailures:");
        for e in &errors {
            println!("  - {e}");
        }
        anyhow::bail!("{failed} calibration case(s) failed")
    } else {
        println!("All calibration cases passed.");
        Ok(())
    }
}

/// Validate a profile against guardrails.
pub fn validate_profile(profile_name: &str) -> Result<()> {
    println!("── Validating profile: {profile_name} ──");
    let _config = engine_factory::load_scoring_config(Some(profile_name))?;
    println!("  ✓ Profile {profile_name} passes all guardrails");
    Ok(())
}

/// Show diff between base config and a profile.
pub fn diff_profile(profile_name: &str) -> Result<()> {
    let base = permit0_scoring::ScoringConfig::default();
    let with_profile = engine_factory::load_scoring_config(Some(profile_name))?;

    println!("── Profile diff: base → {profile_name} ──\n");

    // Risk weight diffs
    println!("Risk Weights:");
    let mut keys: Vec<_> = base.risk_weights.keys().collect();
    keys.sort();
    for key in &keys {
        let base_val = base.risk_weights.get(*key).copied().unwrap_or(0.0);
        let prof_val = with_profile.risk_weights.get(*key).copied().unwrap_or(0.0);
        if (base_val - prof_val).abs() > 1e-6 {
            let arrow = if prof_val > base_val { "↑" } else { "↓" };
            println!(
                "  {key:20} {base_val:.4} → {prof_val:.4}  {arrow} ({:+.1}%)",
                ((prof_val / base_val) - 1.0) * 100.0
            );
        }
    }

    // Amp weight diffs
    println!("\nAmplifier Weights:");
    let mut keys: Vec<_> = base.amp_weights.keys().collect();
    keys.sort();
    for key in &keys {
        let base_val = base.amp_weights.get(*key).copied().unwrap_or(0.0);
        let prof_val = with_profile.amp_weights.get(*key).copied().unwrap_or(0.0);
        if (base_val - prof_val).abs() > 1e-6 {
            let arrow = if prof_val > base_val { "↑" } else { "↓" };
            println!(
                "  {key:20} {base_val:.4} → {prof_val:.4}  {arrow} ({:+.1}%)",
                ((prof_val / base_val) - 1.0) * 100.0
            );
        }
    }

    // Action type floors
    if !with_profile.action_type_floors.is_empty() {
        println!("\nAction Type Floors:");
        let mut floors: Vec<_> = with_profile.action_type_floors.iter().collect();
        floors.sort_by_key(|(at, _)| at.as_action_str());
        for (at, tier) in floors {
            println!("  {:30} → {tier}", at.as_action_str());
        }
    }

    // Block rules
    let extra_rules = with_profile.block_rules.len() - base.block_rules.len();
    if extra_rules > 0 {
        println!("\nAdditional Block Rules: +{extra_rules}");
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct CorpusCase {
    name: String,
    tool_name: String,
    parameters: serde_json::Value,
    expected_tier: Option<String>,
    expected_permission: Option<String>,
}
