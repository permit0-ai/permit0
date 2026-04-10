#![forbid(unsafe_code)]
#![doc = "Risk scoring math for the permit0 agent permission framework."]

pub mod block_rules;
pub mod config;
pub mod constants;
pub mod scorer;
pub mod template;

pub use block_rules::BlockRule;
pub use config::{
    Direction, GuardrailViolation, Guardrails, OrgOverrides, ProfileOverrides, ScoringConfig,
    check_guardrails,
};
pub use constants::{
    AMP_MAXES, BASE_AMP_WEIGHTS, BASE_RISK_WEIGHTS, CATEGORIES, CategoryConfig,
    DEFAULT_TANH_K, MULTIPLICATIVE_DIMS,
};
pub use scorer::{compute_hybrid, normalise_amps};
pub use template::RiskTemplate;
