#![forbid(unsafe_code)]

use std::collections::HashSet;

use permit0_types::ActionType;

use crate::helpers::build_helper_registry;
use crate::schema::normalizer::NormalizerDef;
use crate::schema::risk_rule::RiskRuleDef;

/// Validation error for DSL pack files.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid action_type format: {0}")]
    InvalidActionType(String),
    #[error("unknown helper: {0}")]
    UnknownHelper(String),
    #[error("wrong argument count for helper `{helper}`: expected {expected}, got {got}")]
    WrongArgCount {
        helper: String,
        expected: usize,
        got: usize,
    },
    #[error("unknown parameter type: {0} (valid: string, int, bool, float, list)")]
    UnknownParameterType(String),
    #[error("conflicting field requirements: `{0}` has both required=true and optional=true")]
    ConflictingRequirements(String),
    #[error("required field `{0}` cannot have a default value")]
    RequiredWithDefault(String),
    #[error("amplifier out of range: `{dim}` = {value} (must be 0..=30)")]
    AmplifierOutOfRange { dim: String, value: i32 },
    #[error("invalid flag role: {0} (must be 'primary' or 'secondary')")]
    InvalidFlagRole(String),
    #[error("empty gate reason")]
    EmptyGateReason,
    #[error("duplicate normalizer ID: {0}")]
    DuplicateNormalizerId(String),
    #[error("{0}")]
    TierInvariant(String),
}

const VALID_PARAMETER_TYPES: &[&str] = &[
    "string", "int", "integer", "bool", "boolean", "float", "number", "list",
];

/// Validate a normalizer definition.
pub fn validate_normalizer(def: &NormalizerDef) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let helpers = build_helper_registry();

    // Check action_type format
    if ActionType::parse(&def.normalize.action_type).is_err() {
        errors.push(ValidationError::InvalidActionType(
            def.normalize.action_type.clone(),
        ));
    }

    // Check parameters
    for (name, param) in &def.normalize.parameters {
        // Check parameter type
        if let Some(ref t) = param.value_type {
            if !VALID_PARAMETER_TYPES.contains(&t.as_str()) {
                errors.push(ValidationError::UnknownParameterType(t.clone()));
            }
        }

        // Check compute helper exists and arity
        if let Some(ref helper_name) = param.compute {
            match helpers.get(helper_name.as_str()) {
                Some((_, expected_arity)) => {
                    let got = param.args.as_ref().map_or(0, |a| a.len());
                    if got != *expected_arity {
                        errors.push(ValidationError::WrongArgCount {
                            helper: helper_name.clone(),
                            expected: *expected_arity,
                            got,
                        });
                    }
                }
                None => {
                    errors.push(ValidationError::UnknownHelper(helper_name.clone()));
                }
            }
        }

        // Check conflicting requirements
        if param.required == Some(true) && param.optional == Some(true) {
            errors.push(ValidationError::ConflictingRequirements(name.clone()));
        }

        // Check required with default
        if param.required == Some(true) && param.default.is_some() {
            errors.push(ValidationError::RequiredWithDefault(name.clone()));
        }
    }

    errors
}

/// Validate a risk rule's fixed-tier / scored-rule invariants only. Not a complete rule
/// validator — see validate_risk_rule_def.
pub(crate) fn validate_tier_invariants(rule: &RiskRuleDef) -> Result<(), String> {
    use crate::schema::risk_rule::MutationDef;

    match &rule.tier {
        Some(tier_str) => {
            let tier = crate::risk_executor::parse_tier(tier_str)
                .ok_or_else(|| format!("invalid tier: {tier_str}"))?;
            if tier == permit0_types::Tier::Critical {
                return Err(
                    "tier: critical is not allowed — use a gate: mutation to force CRITICAL"
                        .to_string(),
                );
            }
            if let Some(base) = &rule.base {
                if !base.amplifiers.is_empty() {
                    return Err(
                        "amplifiers are ignored when tier: is set — remove them".to_string()
                    );
                }
            }
            let all_then = rule
                .rules
                .iter()
                .flat_map(|r| &r.then)
                .chain(rule.session_rules.iter().flat_map(|r| &r.then));
            for m in all_then {
                if !matches!(m, MutationDef::Gate { .. }) {
                    return Err("fixed-tier rules may only use gate: mutations \
                         (no add_flag/upgrade/etc.)"
                        .to_string());
                }
            }
        }
        None => {
            if rule.base.is_none() {
                return Err("a scored rule must declare a base: section".to_string());
            }
        }
    }
    Ok(())
}

/// Validate a risk rule definition, returning all errors found.
pub fn validate_risk_rule_def(def: &RiskRuleDef) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    // Check tier invariants first
    if let Err(msg) = validate_tier_invariants(def) {
        errors.push(ValidationError::TierInvariant(msg));
    }

    // Check action_type
    if ActionType::parse(&def.action_type).is_err() {
        errors.push(ValidationError::InvalidActionType(def.action_type.clone()));
    }

    // Check base amplifiers and flag roles (base is optional for fixed-tier rules)
    if let Some(base) = &def.base {
        for (dim, value) in &base.amplifiers {
            if *value < 0 || *value > 30 {
                errors.push(ValidationError::AmplifierOutOfRange {
                    dim: dim.clone(),
                    value: *value,
                });
            }
        }

        for role in base.flags.values() {
            if role != "primary" && role != "secondary" {
                errors.push(ValidationError::InvalidFlagRole(role.clone()));
            }
        }
    }

    // Check mutations in rules — only for scored rules (fixed-tier rules may only use gate:
    // mutations, which is enforced by validate_tier_invariants; running validate_mutations
    // for them would double-report the same violation).
    if def.tier.is_none() {
        for rule in &def.rules {
            validate_mutations(&rule.then, &mut errors);
        }

        for rule in &def.session_rules {
            validate_mutations(&rule.then, &mut errors);
        }
    }

    errors
}

fn validate_mutations(
    mutations: &[crate::schema::risk_rule::MutationDef],
    errors: &mut Vec<ValidationError>,
) {
    use crate::schema::risk_rule::MutationDef;
    for m in mutations {
        match m {
            MutationDef::Gate { gate } if gate.is_empty() => {
                errors.push(ValidationError::EmptyGateReason);
            }
            MutationDef::AddFlag { add_flag }
                if add_flag.role != "primary" && add_flag.role != "secondary" =>
            {
                errors.push(ValidationError::InvalidFlagRole(add_flag.role.clone()));
            }
            MutationDef::Split { split } => {
                for (dim, value) in &split.amplifiers {
                    if *value < 0 {
                        errors.push(ValidationError::AmplifierOutOfRange {
                            dim: dim.clone(),
                            value: *value,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Check for duplicate normalizer IDs across a set.
pub fn check_duplicate_ids(normalizers: &[NormalizerDef]) -> Vec<ValidationError> {
    let mut seen = HashSet::new();
    let mut errors = Vec::new();
    for n in normalizers {
        if !seen.insert(&n.id) {
            errors.push(ValidationError::DuplicateNormalizerId(n.id.clone()));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::normalizer::{NormalizeDef, NormalizerDef, ParameterDef};
    use crate::schema::risk_rule::RiskRuleDef;
    use std::collections::HashMap;

    fn rule(yaml: &str) -> RiskRuleDef {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn fixed_tier_rule_is_valid() {
        let r = rule(
            r#"
permit0_pack: "p/x"
action_type: "email.delete"
tier: high
base: { flags: { MUTATION: primary } }
session_rules:
  - when: { record_count: { gt: 10 } }
    then: [ { gate: "bulk" } ]
"#,
        );
        assert!(validate_tier_invariants(&r).is_ok());
    }

    #[test]
    fn rejects_tier_critical() {
        let r = rule("permit0_pack: p/x\naction_type: a.b\ntier: critical\n");
        let err = validate_tier_invariants(&r).unwrap_err();
        assert!(err.contains("critical is not allowed"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_tier() {
        let r = rule("permit0_pack: p/x\naction_type: a.b\ntier: spicy\n");
        assert!(validate_tier_invariants(&r).is_err());
    }

    #[test]
    fn rejects_amplifiers_with_fixed_tier() {
        let r = rule(
            r#"
permit0_pack: "p/x"
action_type: "a.b"
tier: high
base: { flags: { MUTATION: primary }, amplifiers: { scope: 10 } }
"#,
        );
        assert!(validate_tier_invariants(&r).is_err());
    }

    #[test]
    fn rejects_non_gate_mutation_with_fixed_tier() {
        let r = rule(
            r#"
permit0_pack: "p/x"
action_type: "a.b"
tier: high
rules:
  - when: { x: { gt: 1 } }
    then: [ { upgrade: { dim: scope, delta: 5 } } ]
"#,
        );
        let err = validate_tier_invariants(&r).unwrap_err();
        assert!(err.contains("only use gate"), "got: {err}");
    }

    #[test]
    fn fixed_tier_rule_without_base_is_valid() {
        let r = rule("permit0_pack: p/x\naction_type: a.b\ntier: low\n");
        assert!(validate_tier_invariants(&r).is_ok());
    }

    #[test]
    fn rejects_scored_rule_without_base() {
        let r = rule("permit0_pack: p/x\naction_type: a.b\n");
        assert!(validate_tier_invariants(&r).is_err());
    }

    fn minimal_normalizer(action_type: &str) -> NormalizerDef {
        NormalizerDef {
            permit0_pack: "v1".into(),
            id: "test:norm".into(),
            priority: 100,
            extends: None,
            api_version: None,
            match_expr: serde_yaml::from_str("tool: http").unwrap(),
            normalize: NormalizeDef {
                action_type: action_type.into(),
                domain: "payment".into(),
                verb: "charge".into(),
                source: "test".into(),
                parameters: HashMap::new(),
            },
        }
    }

    #[test]
    fn valid_normalizer_passes() {
        let def = minimal_normalizer("payment.charge");
        let errors = validate_normalizer(&def);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn invalid_action_type() {
        let def = minimal_normalizer("invalid_action");
        let errors = validate_normalizer(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidActionType(_)))
        );
    }

    #[test]
    fn unknown_helper() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.parameters.insert(
            "test".into(),
            ParameterDef {
                from: None,
                from_any: None,
                value_type: None,
                required: None,
                optional: None,
                default: None,
                lowercase: None,
                uppercase: None,
                trim: None,
                compute: Some("nonexistent_helper".into()),
                args: Some(vec!["x".into()]),
            },
        );
        let errors = validate_normalizer(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::UnknownHelper(_)))
        );
    }

    #[test]
    fn wrong_arity() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.parameters.insert(
            "test".into(),
            ParameterDef {
                from: None,
                from_any: None,
                value_type: None,
                required: None,
                optional: None,
                default: None,
                lowercase: None,
                uppercase: None,
                trim: None,
                compute: Some("url_host".into()),
                args: Some(vec!["a".into(), "b".into()]), // expects 1
            },
        );
        let errors = validate_normalizer(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::WrongArgCount { .. }))
        );
    }

    #[test]
    fn unknown_parameter_type() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.parameters.insert(
            "test".into(),
            ParameterDef {
                from: Some("field".into()),
                from_any: None,
                value_type: Some("invalid_type".into()),
                required: None,
                optional: None,
                default: None,
                lowercase: None,
                uppercase: None,
                trim: None,
                compute: None,
                args: None,
            },
        );
        let errors = validate_normalizer(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::UnknownParameterType(_)))
        );
    }

    #[test]
    fn conflicting_required_optional() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.parameters.insert(
            "test".into(),
            ParameterDef {
                from: Some("field".into()),
                from_any: None,
                value_type: None,
                required: Some(true),
                optional: Some(true),
                default: None,
                lowercase: None,
                uppercase: None,
                trim: None,
                compute: None,
                args: None,
            },
        );
        let errors = validate_normalizer(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ConflictingRequirements(_)))
        );
    }

    #[test]
    fn required_with_default() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.parameters.insert(
            "test".into(),
            ParameterDef {
                from: Some("field".into()),
                from_any: None,
                value_type: None,
                required: Some(true),
                optional: None,
                default: Some(serde_json::json!("fallback")),
                lowercase: None,
                uppercase: None,
                trim: None,
                compute: None,
                args: None,
            },
        );
        let errors = validate_normalizer(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::RequiredWithDefault(_)))
        );
    }

    #[test]
    fn risk_rule_amplifier_out_of_range() {
        let def: RiskRuleDef = serde_yaml::from_str(
            r#"
permit0_pack: "v1"
action_type: "payment.charge"
base:
  flags:
    financial_write: primary
  amplifiers:
    amount: 50
rules: []
session_rules: []
"#,
        )
        .unwrap();
        let errors = validate_risk_rule_def(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::AmplifierOutOfRange { .. }))
        );
    }

    #[test]
    fn risk_rule_invalid_flag_role() {
        let def: RiskRuleDef = serde_yaml::from_str(
            r#"
permit0_pack: "v1"
action_type: "payment.charge"
base:
  flags:
    financial_write: invalid_role
  amplifiers:
    amount: 5
rules: []
session_rules: []
"#,
        )
        .unwrap();
        let errors = validate_risk_rule_def(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidFlagRole(_)))
        );
    }

    #[test]
    fn valid_risk_rule_passes() {
        let yaml =
            permit0_test_utils::load_test_fixture("packs/permit0/email/risk_rules/send.yaml");
        let def: RiskRuleDef = serde_yaml::from_str(&yaml).unwrap();
        let errors = validate_risk_rule_def(&def);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn duplicate_normalizer_ids() {
        let n1 = minimal_normalizer("payment.charge");
        let n2 = minimal_normalizer("payment.charge");
        let errors = check_duplicate_ids(&[n1, n2]);
        assert_eq!(errors.len(), 1);
        assert!(
            matches!(&errors[0], ValidationError::DuplicateNormalizerId(id) if id == "test:norm")
        );
    }
}
