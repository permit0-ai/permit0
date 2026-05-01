#![forbid(unsafe_code)]

use thiserror::Error;

/// Errors that can occur during normalization.
#[derive(Debug, Error)]
pub enum NormalizeError {
    #[error("no normalizer matched the tool call '{tool_name}'")]
    NoMatch { tool_name: String },

    #[error("missing required field '{field}' in tool call '{tool_name}'")]
    MissingRequiredField { tool_name: String, field: String },

    #[error("type cast failed for field '{field}': expected {expected}, got {actual}")]
    TypeCastFailed {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("helper '{helper}' failed: {reason}")]
    HelperFailed { helper: String, reason: String },
}

/// Errors that can occur during normalizer registration.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("priority conflict: normalizers '{a}' and '{b}' both have priority {priority}")]
    PriorityConflict { a: String, b: String, priority: i32 },

    #[error(
        "alias conflict: tool '{tool}' is aliased twice (existing: '{existing}', new: '{new}')"
    )]
    AliasConflict {
        tool: String,
        existing: String,
        new: String,
    },

    #[error("alias parse error: {0}")]
    AliasParse(String),
}
