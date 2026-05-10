#![forbid(unsafe_code)]

use permit0_normalize::NormalizeError;
use permit0_store::StateError;

/// Errors returned by the permission engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("normalization failed: {0}")]
    Normalize(#[from] NormalizeError),

    #[error("policy state error: {0}")]
    State(#[from] StateError),

    #[error("no risk rule found for action type: {0}")]
    NoRiskRule(String),

    #[error("engine build error: {0}")]
    Build(String),

    #[error("audit failure: {0}")]
    AuditFailure(String),
}
