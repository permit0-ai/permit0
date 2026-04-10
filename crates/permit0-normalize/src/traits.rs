#![forbid(unsafe_code)]

use permit0_types::{NormAction, RawToolCall};

use crate::context::NormalizeCtx;
use crate::error::NormalizeError;

/// A normalizer converts raw tool calls into structured NormActions.
///
/// Implementations may be YAML-driven (DslNormalizer) or hand-coded for special cases.
pub trait Normalizer: Send + Sync {
    /// Unique identifier for this normalizer (e.g. "stripe:charges.create").
    fn id(&self) -> &str;

    /// Priority for dispatch ordering. Higher = checked earlier.
    /// Two normalizers at the same priority that could match the same input
    /// is a registration-time error.
    fn priority(&self) -> i32;

    /// Quick check: could this normalizer handle this tool call?
    fn matches(&self, raw: &RawToolCall) -> bool;

    /// Perform the full normalization: extract entities, compute derived fields,
    /// and produce a NormAction.
    fn normalize(
        &self,
        raw: &RawToolCall,
        ctx: &NormalizeCtx,
    ) -> Result<NormAction, NormalizeError>;
}
