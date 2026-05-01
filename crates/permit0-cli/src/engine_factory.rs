#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context, Result};
use permit0_dsl::discover_packs;
use permit0_engine::EngineBuilder;
use permit0_scoring::{Guardrails, ProfileOverrides, ScoringConfig};

/// Load all packs into an `EngineBuilder` without finalizing it. Lets
/// callers stack additional configuration (e.g. audit sink + signer)
/// before calling `.build()`.
///
/// Search order for packs is the same as `build_engine_from_packs`.
pub fn build_engine_builder_from_packs(
    profile: Option<&str>,
    packs_dir: Option<&str>,
) -> Result<EngineBuilder> {
    let config = load_scoring_config(profile)?;
    let mut builder = EngineBuilder::new().with_config(config);

    let resolved_dir = resolve_packs_dir(packs_dir);
    if let Some(dir) = &resolved_dir {
        let pack_dirs = discover_packs(dir)
            .with_context(|| format!("discovering packs in {}", dir.display()))?;
        for pack_dir in pack_dirs {
            builder = install_pack(builder, &pack_dir)?;
        }
    }

    Ok(builder)
}

/// Load all packs from the packs/ directory and build an engine.
///
/// Search order for packs:
/// 1. Explicit `packs_dir` if provided
/// 2. `./packs/` relative to CWD
/// 3. `~/.permit0/packs/`
pub fn build_engine_from_packs(
    profile: Option<&str>,
    packs_dir: Option<&str>,
) -> Result<permit0_engine::Engine> {
    build_engine_builder_from_packs(profile, packs_dir)?
        .build()
        .map_err(Into::into)
}

/// Resolve the packs directory from explicit path, CWD, or ~/.permit0/packs/.
pub fn resolve_packs_dir(explicit: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(dir) = explicit {
        let p = Path::new(dir);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // CWD/packs/
    let cwd_packs = Path::new("packs");
    if cwd_packs.exists() {
        return Some(cwd_packs.to_path_buf());
    }
    // ~/.permit0/packs/
    if let Some(home) = dirs_home() {
        let home_packs = home.join(".permit0").join("packs");
        if home_packs.exists() {
            return Some(home_packs);
        }
    }
    None
}

pub fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
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
fn install_pack(mut builder: EngineBuilder, pack_dir: &Path) -> Result<EngineBuilder> {
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

    // Optional aliases file at the pack root. Lets foreign tool names
    // (e.g. Google's official Gmail MCP) be rewritten to the canonical
    // names the pack's normalizers match. Single file rather than a
    // directory because aliases naturally form one table per pack.
    let aliases_path = pack_dir.join("aliases.yaml");
    if aliases_path.exists() {
        let yaml = std::fs::read_to_string(&aliases_path)
            .with_context(|| format!("reading {}", aliases_path.display()))?;
        builder = builder
            .install_aliases_yaml(&yaml)
            .with_context(|| format!("installing aliases {}", aliases_path.display()))?;
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
    /// Named sets for DSL `in_set` / `not_in_set` predicates. Each key is a
    /// dotted identifier (e.g., `org.trusted_domains`); each value is a list
    /// of strings. Later layers replace whole sets under the same key.
    #[serde(default)]
    named_sets: std::collections::HashMap<String, Vec<String>>,
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

        let named_sets: std::collections::HashMap<String, std::collections::HashSet<String>> = self
            .named_sets
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        Ok(ProfileOverrides {
            risk_weight_adjustments: self.risk_weight_adjustments,
            amp_weight_adjustments: self.amp_weight_adjustments,
            action_type_floors: floors,
            named_sets,
            ..Default::default()
        })
    }
}
