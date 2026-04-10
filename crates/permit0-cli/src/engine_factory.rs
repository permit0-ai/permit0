#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context, Result};
use permit0_engine::EngineBuilder;
use permit0_scoring::{ProfileOverrides, ScoringConfig, Guardrails};

/// Load all packs from the packs/ directory and build an engine.
pub fn build_engine_from_packs(profile: Option<&str>) -> Result<permit0_engine::Engine> {
    let config = load_scoring_config(profile)?;
    let mut builder = EngineBuilder::new().with_config(config);

    // Discover and install all pack normalizers and risk rules
    let packs_dir = Path::new("packs");
    if packs_dir.exists() {
        for entry in std::fs::read_dir(packs_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                builder = install_pack(builder, &entry.path())?;
            }
        }
    }

    builder.build().map_err(Into::into)
}

/// Load scoring config with optional profile overlay.
pub fn load_scoring_config(profile: Option<&str>) -> Result<ScoringConfig> {
    let profile_overrides = match profile {
        Some(name) => {
            let path = format!("profiles/{name}.profile.yaml");
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read profile: {path}"))?;
            let overrides: ProfileYaml = serde_yaml::from_str(&yaml)
                .with_context(|| format!("failed to parse profile: {path}"))?;
            Some(overrides.into_overrides()?)
        }
        None => None,
    };

    let guardrails = Guardrails::default();
    ScoringConfig::from_layers(profile_overrides.as_ref(), None, &guardrails)
        .map_err(|e| anyhow::anyhow!("guardrail violation: {e}"))
}

/// Install all normalizers and risk rules from a single pack directory.
fn install_pack(
    mut builder: EngineBuilder,
    pack_dir: &Path,
) -> Result<EngineBuilder> {
    let normalizers_dir = pack_dir.join("normalizers");
    if normalizers_dir.exists() {
        for entry in std::fs::read_dir(&normalizers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                let yaml = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                builder = builder
                    .install_normalizer_yaml(&yaml)
                    .with_context(|| format!("installing normalizer {}", path.display()))?;
            }
        }
    }

    let rules_dir = pack_dir.join("risk_rules");
    if rules_dir.exists() {
        for entry in std::fs::read_dir(&rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                let yaml = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                builder = builder
                    .install_risk_rule_yaml(&yaml)
                    .with_context(|| format!("installing risk rule {}", path.display()))?;
            }
        }
    }

    Ok(builder)
}

/// Intermediate type for parsing profile YAML (which has extra fields we ignore).
#[derive(serde::Deserialize)]
struct ProfileYaml {
    #[serde(default)]
    risk_weight_adjustments: std::collections::HashMap<String, f64>,
    #[serde(default)]
    amp_weight_adjustments: std::collections::HashMap<String, f64>,
    #[serde(default)]
    action_type_floors: std::collections::HashMap<String, String>,
    #[allow(dead_code)]
    #[serde(default)]
    additional_block_rules: Vec<serde_yaml::Value>,
    // Ignored fields
    #[allow(dead_code)]
    #[serde(default)]
    tier_threshold_shifts: std::collections::HashMap<String, f64>,
}

impl ProfileYaml {
    fn into_overrides(self) -> Result<ProfileOverrides> {
        let mut floors = std::collections::HashMap::new();
        for (action_str, tier_str) in &self.action_type_floors {
            let at = permit0_types::ActionType::parse(action_str)
                .map_err(|e| anyhow::anyhow!("invalid action type {action_str}: {e}"))?;
            let tier = match tier_str.to_uppercase().as_str() {
                "MINIMAL" => permit0_types::Tier::Minimal,
                "LOW" => permit0_types::Tier::Low,
                "MEDIUM" => permit0_types::Tier::Medium,
                "HIGH" => permit0_types::Tier::High,
                "CRITICAL" => permit0_types::Tier::Critical,
                _ => anyhow::bail!("unknown tier: {tier_str}"),
            };
            floors.insert(at, tier);
        }

        Ok(ProfileOverrides {
            risk_weight_adjustments: self.risk_weight_adjustments,
            amp_weight_adjustments: self.amp_weight_adjustments,
            action_type_floors: floors,
            ..Default::default()
        })
    }
}
