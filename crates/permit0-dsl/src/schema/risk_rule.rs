#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::Deserialize;

use crate::schema::condition::ConditionExpr;

/// A risk rule YAML file — defines how an action_type is scored.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskRuleDef {
    pub permit0_pack: String,
    pub action_type: String,
    /// Pack-declared fixed tier (`minimal|low|medium|high`). When set, the
    /// scoring path is bypassed; see `risk_executor`. Validated in `validate.rs`.
    #[serde(default)]
    pub tier: Option<String>,
    /// Base flags + amplifiers. Required for scored rules; optional for
    /// fixed-tier rules (where `flags` are kept only as audit labels).
    #[serde(default)]
    pub base: Option<RiskBaseDef>,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub session_rules: Vec<SessionRuleDef>,
}

/// Base risk template definition.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskBaseDef {
    #[serde(default)]
    pub flags: HashMap<String, String>,
    #[serde(default)]
    pub amplifiers: HashMap<String, i32>,
}

/// A single rule: when condition → then mutations.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub when: ConditionExpr,
    pub then: Vec<MutationDef>,
}

/// A session rule: when session-condition → then mutations.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionRuleDef {
    pub when: ConditionExpr,
    pub then: Vec<MutationDef>,
}

/// A mutation action applied to a RiskTemplate.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MutationDef {
    Gate {
        gate: String,
    },
    AddFlag {
        add_flag: AddFlagDef,
    },
    RemoveFlag {
        remove_flag: String,
    },
    PromoteFlag {
        promote_flag: String,
    },
    Upgrade {
        upgrade: DimDeltaDef,
    },
    Downgrade {
        downgrade: DimDeltaDef,
    },
    Override {
        #[serde(rename = "override")]
        override_amp: DimValueDef,
    },
    Split {
        split: SplitDef,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddFlagDef {
    pub flag: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DimDeltaDef {
    pub dim: String,
    pub delta: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DimValueDef {
    pub dim: String,
    pub value: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SplitDef {
    #[serde(default)]
    pub flags: HashMap<String, String>,
    #[serde(default)]
    pub amplifiers: HashMap<String, i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_tier_rule_without_amplifiers() {
        let yaml = r#"
permit0_pack: "permit0/email"
action_type: "email.delete"
tier: high
base:
  flags:
    MUTATION: primary
session_rules:
  - when: { record_count: { gt: 10 } }
    then:
      - gate: "bulk delete"
"#;
        let rule: RiskRuleDef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.tier.as_deref(), Some("high"));
        let base = rule.base.expect("base present");
        assert_eq!(
            base.flags.get("MUTATION").map(String::as_str),
            Some("primary")
        );
        assert!(base.amplifiers.is_empty());
    }

    #[test]
    fn parses_scored_rule_still() {
        let yaml = r#"
permit0_pack: "permit0/email"
action_type: "email.send"
base:
  flags: { OUTBOUND: primary }
  amplifiers: { scope: 18 }
"#;
        let rule: RiskRuleDef = serde_yaml::from_str(yaml).unwrap();
        assert!(rule.tier.is_none());
        assert!(rule.base.is_some());
    }
}
