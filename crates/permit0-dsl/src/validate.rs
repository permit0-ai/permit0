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
    #[error("unknown entity type: {0} (valid: string, int, bool, float, list)")]
    UnknownEntityType(String),
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
}

const VALID_ENTITY_TYPES: &[&str] = &[
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

    // Check entities
    for (name, entity) in &def.normalize.entities {
        // Check entity type
        if let Some(ref t) = entity.value_type {
            if !VALID_ENTITY_TYPES.contains(&t.as_str()) {
                errors.push(ValidationError::UnknownEntityType(t.clone()));
            }
        }

        // Check compute helper exists and arity
        if let Some(ref helper_name) = entity.compute {
            match helpers.get(helper_name.as_str()) {
                Some((_, expected_arity)) => {
                    let got = entity.args.as_ref().map_or(0, |a| a.len());
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
        if entity.required == Some(true) && entity.optional == Some(true) {
            errors.push(ValidationError::ConflictingRequirements(name.clone()));
        }

        // Check required with default
        if entity.required == Some(true) && entity.default.is_some() {
            errors.push(ValidationError::RequiredWithDefault(name.clone()));
        }
    }

    errors
}

/// Validate a risk rule definition.
pub fn validate_risk_rule(def: &RiskRuleDef) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    // Check action_type
    if ActionType::parse(&def.action_type).is_err() {
        errors.push(ValidationError::InvalidActionType(def.action_type.clone()));
    }

    // Check base amplifiers: 0..=30
    for (dim, value) in &def.base.amplifiers {
        if *value < 0 || *value > 30 {
            errors.push(ValidationError::AmplifierOutOfRange {
                dim: dim.clone(),
                value: *value,
            });
        }
    }

    // Check base flag roles
    for role in def.base.flags.values() {
        if role != "primary" && role != "secondary" {
            errors.push(ValidationError::InvalidFlagRole(role.clone()));
        }
    }

    // Check mutations in rules
    for rule in &def.rules {
        validate_mutations(&rule.then, &mut errors);
    }

    // Check mutations in session rules
    for rule in &def.session_rules {
        validate_mutations(&rule.then, &mut errors);
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
    use crate::schema::normalizer::{EntityDef, NormalizeDef, NormalizerDef};
    use std::collections::HashMap;

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
                channel: "test".into(),
                entities: HashMap::new(),
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
        def.normalize.entities.insert(
            "test".into(),
            EntityDef {
                from: None,
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
        def.normalize.entities.insert(
            "test".into(),
            EntityDef {
                from: None,
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
    fn unknown_entity_type() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.entities.insert(
            "test".into(),
            EntityDef {
                from: Some("field".into()),
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
                .any(|e| matches!(e, ValidationError::UnknownEntityType(_)))
        );
    }

    #[test]
    fn conflicting_required_optional() {
        let mut def = minimal_normalizer("payment.charge");
        def.normalize.entities.insert(
            "test".into(),
            EntityDef {
                from: Some("field".into()),
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
        def.normalize.entities.insert(
            "test".into(),
            EntityDef {
                from: Some("field".into()),
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
        let errors = validate_risk_rule(&def);
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
        let errors = validate_risk_rule(&def);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidFlagRole(_)))
        );
    }

    #[test]
    fn valid_risk_rule_passes() {
        let yaml = permit0_test_utils::load_test_fixture("packs/email/risk_rules/send.yaml");
        let def: RiskRuleDef = serde_yaml::from_str(&yaml).unwrap();
        let errors = validate_risk_rule(&def);
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
