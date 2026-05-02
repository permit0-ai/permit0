#![forbid(unsafe_code)]
#![doc = "Shared types for the permit0 agent permission framework."]

mod decision;
mod norm_action;
mod permission;
mod risk;
mod taxonomy;
mod tool_call;

pub use decision::{DecisionFilter, DecisionRecord};
pub use norm_action::{Entities, ExecutionMeta, NormAction, NormHash};
pub use permission::Permission;
pub use risk::{FlagRole, RiskScore, TIER_THRESHOLDS, Tier, to_risk_score};
pub use taxonomy::{ALL_DOMAINS, ActionType, Domain, TaxonomyError, Verb, all_action_types};
pub use tool_call::RawToolCall;
