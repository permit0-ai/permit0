#![forbid(unsafe_code)]
#![doc = "LLM-based agent reviewer for permit0 (agent-in-the-loop)."]

pub mod client;
pub mod error;
pub mod reviewer;
pub mod types;

pub use client::{CallbackLlmClient, LlmClient, MockLlmClient};
pub use error::LlmError;
pub use reviewer::AgentReviewer;
pub use types::{
    AgentReviewResponse, ReviewInput, ReviewVerdict, ALWAYS_HUMAN_TYPES,
    DENY_CONFIDENCE_THRESHOLD, MEDIUM_SCORE_SKIP_THRESHOLD,
};
