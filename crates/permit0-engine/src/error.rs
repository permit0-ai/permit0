#![forbid(unsafe_code)]

use permit0_normalize::NormalizeError;
use permit0_store::StoreError;

/// Errors returned by the permission engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("normalization failed: {0}")]
    Normalize(#[from] NormalizeError),

    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("no risk rule found for action type: {0}")]
    NoRiskRule(String),

    #[error("engine build error: {0}")]
    Build(String),
}
