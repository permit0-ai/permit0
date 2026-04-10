#![forbid(unsafe_code)]

use std::collections::HashMap;

use permit0_types::{ActionType, Tier};
use serde::{Deserialize, Serialize};

use crate::block_rules::{BlockRule, immutable_block_rules};
use crate::constants::{
    BASE_AMP_WEIGHTS, BASE_RISK_WEIGHTS, CATEGORIES, CategoryConfig, DEFAULT_TANH_K,
};

/// Direction constraint for block rule modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    OnlyStricter,
}

/// Compiled limits that prevent calibration from creating unsafe configurations.
/// These are built into the engine and cannot be overridden by YAML.
#[derive(Debug, Clone)]
pub struct Guardrails {
    /// No flag weight can be adjusted below this fraction of its base (default: 0.5).
    pub min_weight_ratio: f64,
    /// No flag weight can be adjusted above this fraction of its base (default: 2.0).
    pub max_weight_ratio: f64,
    /// Tier thresholds cannot shift more than this (default: 0.10).
    pub max_threshold_shift: f64,
    /// Block rules can only be made stricter, never weaker.
    pub block_rules_direction: Direction,
    /// The tanh constant range (default: 1.0–2.5).
    pub tanh_k_range: (f64, f64),
    /// Flags that can NEVER be removed or zeroed.
    pub immutable_flags: Vec<String>,
    /// Block rules that can NEVER be disabled.
    pub immutable_block_rules: Vec<String>,
    /// Minimum tier floor per domain.
    pub min_tier_by_domain: HashMap<String, Tier>,
}

impl Default for Guardrails {
    fn default() -> Self {
        Self {
            min_weight_ratio: 0.5,
            max_weight_ratio: 2.0,
            max_threshold_shift: 0.10,
            block_rules_direction: Direction::OnlyStricter,
            tanh_k_range: (1.0, 2.5),
            immutable_flags: vec![
                "DESTRUCTION".into(),
                "PHYSICAL".into(),
                "EXECUTION".into(),
            ],
            immutable_block_rules: immutable_block_rules()
                .iter()
                .map(|r| r.name.clone())
                .collect(),
            min_tier_by_domain: HashMap::new(),
        }
    }
}

/// Resolved scoring configuration — the result of composing base + profile + org policy.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    pub risk_weights: HashMap<String, f64>,
    pub amp_weights: HashMap<String, f64>,
    pub categories: Vec<CategoryConfig>,
    pub block_rules: Vec<BlockRule>,
    pub tanh_k: f64,
    pub action_type_floors: HashMap<ActionType, Tier>,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            risk_weights: BASE_RISK_WEIGHTS
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            amp_weights: BASE_AMP_WEIGHTS
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            categories: CATEGORIES.to_vec(),
            block_rules: immutable_block_rules(),
            tanh_k: DEFAULT_TANH_K,
            action_type_floors: HashMap::new(),
        }
    }
}

impl ScoringConfig {
    /// Look up risk weight for a flag, defaulting to 0.0 for unknown flags.
    pub fn risk_weight(&self, flag: &str) -> f64 {
        self.risk_weights.get(flag).copied().unwrap_or(0.0)
    }

    /// Look up amplifier weight for a dimension, defaulting to 0.0.
    pub fn amp_weight(&self, dim: &str) -> f64 {
        self.amp_weights.get(dim).copied().unwrap_or(0.0)
    }

    /// Look up action-type tier floor, if configured.
    pub fn action_type_floor(&self, action_type: &ActionType) -> Option<Tier> {
        self.action_type_floors.get(action_type).copied()
    }

    /// Compose base + optional profile + optional org policy into a ScoringConfig.
    /// Validates against guardrails; returns error if any check fails.
    pub fn from_layers(
        profile: Option<&ProfileOverrides>,
        org: Option<&OrgOverrides>,
        guardrails: &Guardrails,
    ) -> Result<Self, GuardrailViolation> {
        let mut config = Self::default();

        // Apply profile overrides
        if let Some(profile) = profile {
            config.apply_overrides(&profile.risk_weight_adjustments, &profile.amp_weight_adjustments);
            if let Some(k) = profile.tanh_k {
                config.tanh_k = k;
            }
            for rule in &profile.additional_block_rules {
                config.block_rules.push(rule.clone());
            }
            for (at, tier) in &profile.action_type_floors {
                config.action_type_floors.insert(*at, *tier);
            }
        }

        check_guardrails(&config, guardrails)?;

        // Apply org overrides
        if let Some(org) = org {
            config.apply_overrides(&org.risk_weight_adjustments, &org.amp_weight_adjustments);
            if let Some(k) = org.tanh_k {
                config.tanh_k = k;
            }
            for rule in &org.additional_block_rules {
                config.block_rules.push(rule.clone());
            }
            for (at, tier) in &org.action_type_floors {
                config.action_type_floors.insert(*at, *tier);
            }
        }

        check_guardrails(&config, guardrails)?;

        Ok(config)
    }

    fn apply_overrides(
        &mut self,
        risk_adj: &HashMap<String, f64>,
        amp_adj: &HashMap<String, f64>,
    ) {
        for (flag, factor) in risk_adj {
            if let Some(w) = self.risk_weights.get_mut(flag) {
                *w *= factor;
            }
        }
        for (dim, factor) in amp_adj {
            if let Some(w) = self.amp_weights.get_mut(dim) {
                *w *= factor;
            }
        }
    }
}

/// Profile-layer overrides (from YAML domain profiles).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileOverrides {
    #[serde(default)]
    pub risk_weight_adjustments: HashMap<String, f64>,
    #[serde(default)]
    pub amp_weight_adjustments: HashMap<String, f64>,
    #[serde(default)]
    pub tanh_k: Option<f64>,
    #[serde(default)]
    pub additional_block_rules: Vec<BlockRule>,
    #[serde(default)]
    pub action_type_floors: HashMap<ActionType, Tier>,
}

/// Org-policy-layer overrides (from YAML org policies).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgOverrides {
    #[serde(default)]
    pub risk_weight_adjustments: HashMap<String, f64>,
    #[serde(default)]
    pub amp_weight_adjustments: HashMap<String, f64>,
    #[serde(default)]
    pub tanh_k: Option<f64>,
    #[serde(default)]
    pub additional_block_rules: Vec<BlockRule>,
    #[serde(default)]
    pub action_type_floors: HashMap<ActionType, Tier>,
}

/// Error returned when a configuration violates guardrails.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GuardrailViolation {
    #[error("flag weight for '{flag}' ratio {ratio:.2} outside [{min:.2}, {max:.2}]")]
    WeightOutOfBounds {
        flag: String,
        ratio: f64,
        min: f64,
        max: f64,
    },
    #[error("tanh_k={value:.2} outside allowed range [{min:.2}, {max:.2}]")]
    TanhKOutOfRange { value: f64, min: f64, max: f64 },
    #[error("immutable flag '{flag}' has been zeroed or removed")]
    ImmutableFlagRemoved { flag: String },
    #[error("immutable block rule '{rule}' has been removed")]
    ImmutableBlockRuleRemoved { rule: String },
}

/// Validate a ScoringConfig against guardrails. Returns error on first violation.
pub fn check_guardrails(
    config: &ScoringConfig,
    guardrails: &Guardrails,
) -> Result<(), GuardrailViolation> {
    // Check tanh_k range
    let (min_k, max_k) = guardrails.tanh_k_range;
    if config.tanh_k < min_k || config.tanh_k > max_k {
        return Err(GuardrailViolation::TanhKOutOfRange {
            value: config.tanh_k,
            min: min_k,
            max: max_k,
        });
    }

    // Check flag weight bounds
    for &(flag, base_w) in BASE_RISK_WEIGHTS {
        let current = config.risk_weights.get(flag).copied().unwrap_or(0.0);
        if base_w > 0.0 {
            let ratio = current / base_w;
            if ratio < guardrails.min_weight_ratio || ratio > guardrails.max_weight_ratio {
                return Err(GuardrailViolation::WeightOutOfBounds {
                    flag: flag.to_string(),
                    ratio,
                    min: guardrails.min_weight_ratio,
                    max: guardrails.max_weight_ratio,
                });
            }
        }
    }

    // Check immutable flags not zeroed
    for flag in &guardrails.immutable_flags {
        let w = config.risk_weights.get(flag.as_str()).copied().unwrap_or(0.0);
        if w <= 0.0 {
            return Err(GuardrailViolation::ImmutableFlagRemoved {
                flag: flag.clone(),
            });
        }
    }

    // Check immutable block rules still present
    for rule_name in &guardrails.immutable_block_rules {
        if !config.block_rules.iter().any(|r| r.name == *rule_name) {
            return Err(GuardrailViolation::ImmutableBlockRuleRemoved {
                rule: rule_name.clone(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_passes_guardrails() {
        let config = ScoringConfig::default();
        let guardrails = Guardrails::default();
        assert!(check_guardrails(&config, &guardrails).is_ok());
    }

    #[test]
    fn weight_too_low_rejected() {
        let mut config = ScoringConfig::default();
        // Set DESTRUCTION weight to 10% of base (0.28 * 0.1 = 0.028), below 0.5 ratio
        config
            .risk_weights
            .insert("DESTRUCTION".into(), 0.28 * 0.1);
        let guardrails = Guardrails::default();
        let err = check_guardrails(&config, &guardrails).unwrap_err();
        assert!(matches!(err, GuardrailViolation::WeightOutOfBounds { .. }));
    }

    #[test]
    fn weight_too_high_rejected() {
        let mut config = ScoringConfig::default();
        config
            .risk_weights
            .insert("DESTRUCTION".into(), 0.28 * 3.0);
        let guardrails = Guardrails::default();
        let err = check_guardrails(&config, &guardrails).unwrap_err();
        assert!(matches!(err, GuardrailViolation::WeightOutOfBounds { .. }));
    }

    #[test]
    fn tanh_k_out_of_range_rejected() {
        let config = ScoringConfig {
            tanh_k: 5.0,
            ..ScoringConfig::default()
        };
        let guardrails = Guardrails::default();
        let err = check_guardrails(&config, &guardrails).unwrap_err();
        assert!(matches!(err, GuardrailViolation::TanhKOutOfRange { .. }));
    }

    #[test]
    fn immutable_flag_zeroed_rejected() {
        let mut config = ScoringConfig::default();
        config.risk_weights.insert("DESTRUCTION".into(), 0.0);
        let guardrails = Guardrails::default();
        // Zeroing triggers WeightOutOfBounds first (ratio=0 < min 0.5),
        // but the intent is still caught. Verify it's rejected.
        assert!(check_guardrails(&config, &guardrails).is_err());
    }

    #[test]
    fn immutable_flag_removed_rejected() {
        let mut config = ScoringConfig::default();
        // Remove the flag entirely so it won't hit WeightOutOfBounds but will hit ImmutableFlagRemoved
        config.risk_weights.remove("DESTRUCTION");
        let guardrails = Guardrails {
            min_weight_ratio: 0.0,
            max_weight_ratio: f64::MAX,
            ..Guardrails::default()
        };
        let err = check_guardrails(&config, &guardrails).unwrap_err();
        assert!(matches!(
            err,
            GuardrailViolation::ImmutableFlagRemoved { .. }
        ));
    }

    #[test]
    fn from_layers_with_valid_profile() {
        let profile = ProfileOverrides {
            risk_weight_adjustments: {
                let mut m = HashMap::new();
                m.insert("FINANCIAL".into(), 1.5); // 50% increase, within 2x guardrail
                m
            },
            ..Default::default()
        };
        let guardrails = Guardrails::default();
        let config = ScoringConfig::from_layers(Some(&profile), None, &guardrails);
        assert!(config.is_ok());
        let config = config.unwrap();
        let expected = 0.20 * 1.5;
        assert!((config.risk_weights["FINANCIAL"] - expected).abs() < 1e-10);
    }

    #[test]
    fn from_layers_rejects_excessive_profile() {
        let profile = ProfileOverrides {
            risk_weight_adjustments: {
                let mut m = HashMap::new();
                m.insert("DESTRUCTION".into(), 5.0); // 5x, exceeds 2x guardrail
                m
            },
            ..Default::default()
        };
        let guardrails = Guardrails::default();
        let result = ScoringConfig::from_layers(Some(&profile), None, &guardrails);
        assert!(result.is_err());
    }
}
