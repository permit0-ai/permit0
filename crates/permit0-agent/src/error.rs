#![forbid(unsafe_code)]

/// Errors from LLM client operations.
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("LLM request failed: {0}")]
    RequestFailed(String),
    #[error("LLM response parse error: {0}")]
    ParseError(String),
    #[error("LLM client not configured")]
    NotConfigured,
}
