#![forbid(unsafe_code)]

/// Errors from token operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token has expired")]
    Expired,

    #[error("invalid token signature")]
    InvalidSignature,

    #[error("token verification failed: {0}")]
    VerificationFailed(String),

    #[error("scope violation: {0}")]
    ScopeViolation(String),

    #[error("action type mismatch: expected {expected}, got {actual}")]
    ActionTypeMismatch { expected: String, actual: String },

    #[error("attenuation error: {0}")]
    AttenuationFailed(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("keypair error: {0}")]
    KeyError(String),
}
