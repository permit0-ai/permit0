#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use permit0_types::Tier;

/// Safeguards required before execution, based on risk tier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Safeguard {
    /// Log extracted entities for audit.
    LogEntities,
    /// Log the full request body for audit.
    LogBody,
    /// Require explicit confirmation before execution.
    ConfirmBeforeExecute,
}

/// Scope constraints encoded in a capability token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenScope {
    /// If set, the recipient must match exactly.
    pub recipient: Option<String>,
    /// If set, the file path must be under this prefix.
    pub path_prefix: Option<String>,
    /// If set, the amount must not exceed this ceiling.
    pub amount_ceiling: Option<f64>,
    /// If set, the environment must match (e.g. "production", "staging").
    pub environment: Option<String>,
}

/// Claims embedded in a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Action type, e.g. "payments.charge".
    pub action_type: String,
    /// Scope constraints.
    pub scope: TokenScope,
    /// Who issued: "scorer" or "human".
    pub issued_by: IssuedBy,
    /// Risk score 0–100 at time of approval.
    pub risk_score: u32,
    /// Risk tier at time of approval.
    pub risk_tier: Tier,
    /// Session ID this token belongs to.
    pub session_id: String,
    /// Required safeguards before execution.
    pub safeguards: Vec<Safeguard>,
    /// Unix timestamp of issuance.
    pub issued_at: i64,
    /// Unix timestamp of hard expiry.
    pub expires_at: i64,
}

/// Who issued the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssuedBy {
    /// Auto-approved by scorer (MINIMAL/LOW risk).
    Scorer,
    /// Approved by a human reviewer.
    Human,
}

/// TTL constants by issuing authority.
pub const SCORER_TTL_SECS: i64 = 300; // 5 minutes
pub const HUMAN_TTL_SECS: i64 = 3600; // 1 hour

/// Get safeguards for a given tier per §11.
pub fn safeguards_for_tier(tier: Tier) -> Vec<Safeguard> {
    match tier {
        Tier::Minimal | Tier::Low => vec![],
        Tier::Medium => vec![Safeguard::LogEntities],
        Tier::High => vec![
            Safeguard::LogEntities,
            Safeguard::LogBody,
            Safeguard::ConfirmBeforeExecute,
        ],
        Tier::Critical => vec![], // Critical is DENY — no token issued
    }
}

/// The result of token verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// The claims extracted from the token.
    pub claims: TokenClaims,
    /// Whether the token is still valid (not expired).
    pub valid: bool,
}
