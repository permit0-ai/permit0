#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::Deserialize;

use crate::schema::condition::ConditionExpr;

/// A risk rule YAML file — defines how an action_type is scored.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskRuleDef {
    pub permit0_pack: String,
    pub action_type: String,
    pub base: RiskBaseDef,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub session_rules: Vec<SessionRuleDef>,
}

/// Base risk template definition.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskBaseDef {
    pub flags: HashMap<String, String>,
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
