#![forbid(unsafe_code)]

use crate::error::LlmError;

/// Pluggable LLM client trait for the agent reviewer.
///
/// Implementations behind cargo features: `ollama`, `openai`, `mock`.
pub trait LlmClient: Send + Sync {
    /// Send a prompt to the LLM and get a raw text response.
    fn review(&self, prompt: &str) -> Result<String, LlmError>;
}

/// Mock LLM client for testing. Returns a configurable response.
pub struct MockLlmClient {
    response: String,
}

impl MockLlmClient {
    pub fn new(response: impl Into<String>) -> Self {
        Self {
            response: response.into(),
        }
    }

    /// Create a mock that returns a valid HUMAN verdict.
    pub fn human(reason: &str) -> Self {
        Self::new(format!(
            r#"{{"verdict":"HumanInTheLoop","reason":"{}","confidence":0.65,"escalate_reason":"Needs human judgment"}}"#,
            reason
        ))
    }

    /// Create a mock that returns a valid DENY verdict with high confidence.
    pub fn deny(reason: &str) -> Self {
        Self::new(format!(
            r#"{{"verdict":"Deny","reason":"{}","confidence":0.95,"escalate_reason":null}}"#,
            reason
        ))
    }

    /// Create a mock that returns a DENY with low confidence (should be downgraded to HUMAN).
    pub fn deny_low_confidence(reason: &str) -> Self {
        Self::new(format!(
            r#"{{"verdict":"Deny","reason":"{}","confidence":0.75,"escalate_reason":null}}"#,
            reason
        ))
    }

    /// Create a mock that returns unparseable garbage.
    pub fn garbage() -> Self {
        Self::new("this is not valid json at all {{{{")
    }
}

impl LlmClient for MockLlmClient {
    fn review(&self, _prompt: &str) -> Result<String, LlmError> {
        Ok(self.response.clone())
    }
}
