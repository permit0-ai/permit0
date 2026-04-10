#![forbid(unsafe_code)]
#![doc = "Shared types for the permit0 agent permission framework."]

mod catalog;
mod decision;
mod norm_action;
mod permission;
mod risk;
mod tool_call;

pub use catalog::{
    ActionType, CatalogError, Domain, Verb, ALL_DOMAINS, all_action_types,
};
pub use decision::{DecisionFilter, DecisionRecord};
pub use norm_action::{Entities, ExecutionMeta, NormAction, NormHash};
pub use permission::Permission;
pub use risk::{FlagRole, RiskScore, Tier, TIER_THRESHOLDS, to_risk_score};
pub use tool_call::RawToolCall;
