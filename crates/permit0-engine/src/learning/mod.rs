#![forbid(unsafe_code)]

pub mod analyzer;
pub mod override_store;
pub mod types;

pub use analyzer::{
    ALLOWLIST_MAX_OVERRIDE_RATE, ALLOWLIST_MIN_APPROVALS, AUTO_APPROVE_MAX_OVERRIDE_RATE,
    AUTO_APPROVE_MIN_APPROVALS, LearningAnalyzer, record_human_decision,
};
pub use override_store::{InMemoryOverrideStore, OverrideStore};
pub use types::{ActionStats, HumanOverride, LearningSuggestion, TrainingFeatures};
