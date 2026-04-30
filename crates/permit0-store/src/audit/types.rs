#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use permit0_types::{NormAction, NormHash, Permission, RiskScore, Tier};

/// Every decision is logged as an immutable audit entry with cryptographic integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    // ── Identity ─────────────────────────────────────────
    /// Unique entry ID (ULID string).
    pub entry_id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Monotonic sequence number. Gaps indicate tampering.
    pub sequence: u64,

    // ── Decision ─────────────────────────────────────────
    /// The final permission decision.
    pub decision: Permission,
    /// How the decision was reached.
    pub decision_source: String,

    // ── What was decided ─────────────────────────────────
    /// The normalized action.
    pub norm_action: NormAction,
    /// SHA-256 of the canonical NormAction.
    pub norm_hash: NormHash,
    /// The raw tool call JSON (redacted).
    pub raw_tool_call: serde_json::Value,

    // ── How it was scored ────────────────────────────────
    /// Risk score (if scoring was performed).
    pub risk_score: Option<RiskScore>,
    /// Full scoring breakdown for independent reproducibility.
    pub scoring_detail: Option<ScoringDetail>,

    // ── Who / where / why ────────────────────────────────
    /// Agent identifier.
    pub agent_id: String,
    /// Session identifier.
    pub session_id: Option<String>,
    /// What the agent was asked to do.
    pub task_goal: Option<String>,
    /// Organization identifier.
    pub org_id: String,
    /// Deployment environment (e.g. "production", "staging").
    pub environment: String,

    // ── Provenance ───────────────────────────────────────
    /// Engine version.
    pub engine_version: String,
    /// Rule pack identifier.
    pub pack_id: String,
    /// Rule pack version.
    pub pack_version: String,
    /// DSL version.
    pub dsl_version: String,

    // ── Human review chain ───────────────────────────────
    /// Human review data, if applicable.
    pub human_review: Option<HumanReview>,

    // ── Token ────────────────────────────────────────────
    /// Token ID if a scoped token was issued.
    pub token_id: Option<String>,

    // ── Integrity ────────────────────────────────────────
    /// SHA-256 of the previous entry (hash chain).
    pub prev_hash: String,
    /// SHA-256 of this entry's content (excluding entry_hash and signature).
    pub entry_hash: String,
    /// ed25519 signature over entry_hash.
    pub signature: String,

    // ── Corrections ──────────────────────────────────────
    /// If this entry overrides a prior decision, the original entry_id.
    pub correction_of: Option<String>,

    // ── Failed-open replay (Lane A step 1b) ──────────────
    /// Set when this entry was reconstructed from a client-side
    /// `FailOpenBuffer` after the daemon was unreachable. Carries the
    /// reason the client failed open and the window the action falls in.
    /// `None` for normal entries.
    pub failed_open_context: Option<FailedOpenContext>,
    /// What the *current* pack would have decided, computed at replay
    /// time. Distinct from `decision`, which records what actually ran
    /// (always `Allow` for failed-open entries because the action did
    /// execute). Auditors compare the two to find "should not have run"
    /// cases. `None` for normal entries.
    pub retroactive_decision: Option<Permission>,
}

/// Forensic context attached to an audit entry that was replayed from a
/// client-side fail-open buffer. Lets auditors see why the client could
/// not reach the daemon and the wall-clock window of the outage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedOpenContext {
    /// Coarse error class: "timeout" | "refused" | "http_error" | "other".
    pub fail_reason_code: String,
    /// Verbose error string from the client. Redact before storage if it
    /// might contain sensitive data — for the official @permit0/openclaw
    /// client this is just an undici code or AbortError.
    pub fail_reason: String,
    /// ISO 8601, the start of the failed-open window the client observed.
    pub client_window_start: String,
    /// ISO 8601, the end of the failed-open window the client observed.
    pub client_window_end: String,
    /// Version of the client library that buffered the event.
    pub client_version: String,
    /// How the client's fail-open switch got flipped: "env_var" | "config_flag".
    pub fail_open_source: String,
}

/// Full scoring breakdown, making every decision independently reproducible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringDetail {
    /// Risk flags that were active.
    pub active_flags: Vec<String>,
    /// Raw amplifier values before normalization.
    pub amplifiers_raw: HashMap<String, i32>,
    /// Normalized amplifier values (0.0–1.0).
    pub amplifiers_norm: HashMap<String, f64>,
    /// Per-category scores.
    pub category_scores: HashMap<String, f64>,
    /// Base score before amplifiers.
    pub base: f64,
    /// Compound amplifier contribution.
    pub compound: f64,
    /// Additive boost.
    pub add_boost: f64,
    /// Intermediate score (base + compound + add_boost).
    pub intermediate: f64,
    /// Final raw score (0.0–1.0).
    pub raw_score: f64,
    /// Resolved tier.
    pub tier: Tier,
    /// Block rules that fired (if any).
    pub block_rules_fired: Vec<String>,
}

/// Human review metadata attached to an audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanReview {
    /// Who reviewed (email, username, etc.).
    pub reviewer: String,
    /// The human's decision.
    pub decision: Permission,
    /// Reason for the decision.
    pub reason: String,
    /// ISO 8601 timestamp of the review.
    pub reviewed_at: String,
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Whether the chain is valid.
    pub valid: bool,
    /// Number of entries verified.
    pub entries_checked: u64,
    /// First broken sequence number (if invalid).
    pub first_broken_at: Option<u64>,
    /// Description of the failure.
    pub failure_reason: Option<String>,
}

/// Filter for querying audit entries.
#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    /// Filter by action type prefix.
    pub action_type: Option<String>,
    /// Filter by decision (permission).
    pub decision: Option<Permission>,
    /// Filter by tier.
    pub tier: Option<Tier>,
    /// Filter by session ID.
    pub session_id: Option<String>,
    /// ISO 8601 lower bound (inclusive).
    pub since: Option<String>,
    /// ISO 8601 upper bound (inclusive).
    pub until: Option<String>,
    /// Maximum number of results.
    pub limit: Option<u32>,
}

/// Audit policy: how to handle sink failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuditPolicy {
    /// Block decisions if any sink fails. Required for fintech.
    Strict,
    /// Log failure, continue, buffer and retry.
    #[default]
    BestEffort,
}
