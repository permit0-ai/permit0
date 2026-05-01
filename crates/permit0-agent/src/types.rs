#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use permit0_types::{NormAction, RawToolCall, RiskScore};

/// The reviewer's verdict. Only two options — no Allow, no token issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewVerdict {
    /// Route to a human for final decision.
    HumanInTheLoop,
    /// Block the action.
    Deny,
}

impl std::fmt::Display for ReviewVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HumanInTheLoop => write!(f, "HUMAN"),
            Self::Deny => write!(f, "DENY"),
        }
    }
}

/// The structured response from the agent reviewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReviewResponse {
    /// The verdict: Human or Deny only.
    pub verdict: ReviewVerdict,
    /// Reason for the verdict (logged; shown to human if verdict is Human).
    pub reason: String,
    /// Confidence in the verdict (0.0–1.0).
    pub confidence: f64,
    /// Why human review is needed (if verdict is Human).
    pub escalate_reason: Option<String>,
}

/// Input context provided to the reviewer.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewInput {
    /// The normalized action.
    pub norm_action: NormAction,
    /// Risk score from the scorer.
    pub risk_score: RiskScore,
    /// Original raw tool call.
    pub raw_tool_call: RawToolCall,
    /// What the agent was asked to do.
    pub task_goal: Option<String>,
    /// Session summary (lightweight text).
    pub session_summary: Option<String>,
    /// Plain-text organizational policy for this action type.
    pub org_policy: Option<String>,
}

/// Confidence threshold — deny requires at least this confidence.
pub const DENY_CONFIDENCE_THRESHOLD: f64 = 0.90;

/// Score threshold — MEDIUM calls at or above this go straight to HUMAN.
pub const MEDIUM_SCORE_SKIP_THRESHOLD: u32 = 52;

/// Action types that always skip the reviewer and go straight to HUMAN.
///
/// Strings here must match the canonical `Domain.Verb` form from
/// permit0-types/taxonomy.rs (singular domain). `secret.get` covers the
/// retrieval path since the Secret domain does not expose a dedicated
/// "read" verb.
pub const ALWAYS_HUMAN_TYPES: &[&str] = &[
    "payment.charge",
    "payment.transfer",
    "iam.assign_role",
    "iam.generate_api_key",
    "secret.get",
    "legal.sign_document",
];
