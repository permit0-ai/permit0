#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::{NormHash, Permission, Tier};

/// A persisted record of a permission decision — the audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Unique decision ID (ULID).
    pub id: String,
    /// SHA-256 hash of the canonical NormAction.
    pub norm_hash: NormHash,
    /// The action type string, e.g. "payments.charge".
    pub action_type: String,
    /// Channel, e.g. "stripe", "gmail".
    pub channel: String,
    /// The final permission decision.
    pub permission: Permission,
    /// How the decision was reached.
    pub source: String,
    /// Risk tier (if scoring was performed).
    pub tier: Option<Tier>,
    /// Raw risk score 0.0–1.0 (if scoring was performed).
    pub risk_raw: Option<f64>,
    /// Whether a gate/block rule fired.
    pub blocked: bool,
    /// Flags that fired during risk assessment.
    pub flags: Vec<String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Surface tool name for audit.
    pub surface_tool: String,
    /// Surface command for audit.
    pub surface_command: String,
}

/// Filter criteria for querying decision records.
#[derive(Debug, Default, Clone)]
pub struct DecisionFilter {
    /// Filter by action type prefix, e.g. "payments" matches "payments.charge".
    pub action_type: Option<String>,
    /// Filter by permission outcome.
    pub permission: Option<Permission>,
    /// Filter by channel.
    pub channel: Option<String>,
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// ISO 8601 lower bound (inclusive).
    pub since: Option<String>,
}
