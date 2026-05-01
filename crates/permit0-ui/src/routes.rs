#![forbid(unsafe_code)]

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use permit0_store::AuditFilter;
use permit0_store::audit::AuditEntry;
use permit0_types::{DecisionFilter, Permission};

use crate::approval::HumanDecision;
use crate::state::AppState;

// ── Audit Routes ──

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub action_type: Option<String>,
    pub decision: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub session_id: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

fn ok_response<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        ok: true,
        data: Some(data),
        error: None,
    })
}

fn err_response<T: Serialize>(status: StatusCode, msg: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        status,
        Json(ApiResponse {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }),
    )
}

/// GET /api/v1/audit — list audit entries.
pub async fn list_audit(
    State(state): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> Result<
    Json<ApiResponse<Vec<serde_json::Value>>>,
    (StatusCode, Json<ApiResponse<Vec<serde_json::Value>>>),
> {
    if let Some(ref sink) = state.audit_sink {
        let filter = AuditFilter {
            action_type: q.action_type,
            decision: q.decision.as_deref().and_then(parse_permission),
            session_id: q.session_id,
            since: q.since,
            until: q.until,
            limit: q.limit,
            ..Default::default()
        };
        match sink.query(&filter) {
            Ok(entries) => {
                // The frontend's audit table and dashboard "Recent Decisions"
                // both read flat fields (action_type, permission, tier,
                // risk_raw, ...) shaped like DecisionRecord. AuditEntry has a
                // nested shape (norm_action.action_type, decision,
                // risk_score.tier). Project to the flat shape so both views
                // render correctly without reaching into nested objects.
                let json_entries: Vec<serde_json::Value> = entries
                    .iter()
                    .map(flatten_audit_entry)
                    .collect();
                Ok(ok_response(json_entries))
            }
            Err(e) => Err(err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("audit query failed: {e}"),
            )),
        }
    } else {
        // Fall back to simple decision records from store
        let filter = DecisionFilter {
            action_type: q.action_type,
            permission: q.decision.as_deref().and_then(parse_permission),
            since: q.since,
            limit: q.limit,
            ..Default::default()
        };
        match state.store.query_decisions(&filter) {
            Ok(records) => {
                let json_records: Vec<serde_json::Value> = records
                    .iter()
                    .filter_map(|r| serde_json::to_value(r).ok())
                    .collect();
                Ok(ok_response(json_records))
            }
            Err(e) => Err(err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("decision query failed: {e}"),
            )),
        }
    }
}

// ── Approval Routes ──

/// GET /api/v1/approvals — list pending approvals.
pub async fn list_approvals(
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<crate::approval::PendingApprovalSummary>>> {
    let pending = state.approval_manager.list_pending();
    ok_response(pending)
}

#[derive(Debug, Deserialize)]
pub struct SubmitDecisionRequest {
    pub approval_id: String,
    pub permission: String,
    pub reason: String,
    pub reviewer: String,
}

/// POST /api/v1/approvals/decide — submit a human decision.
pub async fn submit_approval(
    State(state): State<AppState>,
    Json(req): Json<SubmitDecisionRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let permission = match parse_permission(&req.permission) {
        Some(p) => p,
        None => {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "invalid permission: expected 'allow', 'deny', or 'human'",
            ));
        }
    };

    let decision = HumanDecision {
        permission,
        reason: req.reason,
        reviewer: req.reviewer,
    };

    if state
        .approval_manager
        .submit_decision(&req.approval_id, decision)
    {
        Ok(ok_response("decision submitted".to_string()))
    } else {
        Err(err_response(
            StatusCode::NOT_FOUND,
            "approval not found or already resolved",
        ))
    }
}

// ── List Routes ──

#[derive(Debug, Deserialize)]
pub struct ListAddRequest {
    pub norm_hash_hex: String,
    pub reason: String,
}

/// POST /api/v1/lists/denylist — add to denylist.
pub async fn denylist_add(
    State(state): State<AppState>,
    Json(req): Json<ListAddRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let hash = match hex_to_norm_hash(&req.norm_hash_hex) {
        Some(h) => h,
        None => {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "invalid norm_hash hex",
            ));
        }
    };
    state.store.denylist_add(hash, req.reason).map_err(|e| {
        err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        )
    })?;
    Ok(ok_response("added to denylist".to_string()))
}

/// POST /api/v1/lists/allowlist — add to allowlist.
pub async fn allowlist_add(
    State(state): State<AppState>,
    Json(req): Json<ListAddRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let hash = match hex_to_norm_hash(&req.norm_hash_hex) {
        Some(h) => h,
        None => {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "invalid norm_hash hex",
            ));
        }
    };
    state.store.allowlist_add(hash, req.reason).map_err(|e| {
        err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        )
    })?;
    Ok(ok_response("added to allowlist".to_string()))
}

// ── Health Route ──

/// GET /api/v1/health
pub async fn health() -> Json<ApiResponse<String>> {
    ok_response("ok".to_string())
}

// ── Helpers ──

fn parse_permission(s: &str) -> Option<Permission> {
    match s.to_lowercase().as_str() {
        "allow" => Some(Permission::Allow),
        "deny" => Some(Permission::Deny),
        "human" | "humanintheloop" => Some(Permission::HumanInTheLoop),
        _ => None,
    }
}

/// Project an `AuditEntry` to the flat JSON shape the frontend reads.
///
/// Mirrors `DecisionRecord` field names so the audit-log table and
/// dashboard "Recent Decisions" can render without nested-field
/// destructuring. Audit-only fields (entry_id, sequence, prev_hash,
/// human_review, failed_open_context) are preserved alongside, so detail
/// expansion still has the chain metadata to show.
fn flatten_audit_entry(e: &AuditEntry) -> serde_json::Value {
    let risk_raw = e.risk_score.as_ref().map(|s| s.raw);
    let risk_score = e.risk_score.as_ref().map(|s| s.score);
    let tier = e.risk_score.as_ref().map(|s| s.tier.to_string());
    let blocked = e.risk_score.as_ref().map(|s| s.blocked);
    let flags: Vec<String> = e
        .risk_score
        .as_ref()
        .map(|s| s.flags.clone())
        .unwrap_or_default();
    let reviewer = e.human_review.as_ref().map(|hr| hr.reviewer.clone());
    let reason = e.human_review.as_ref().map(|hr| hr.reason.clone());

    serde_json::json!({
        "id": e.entry_id,
        "timestamp": e.timestamp,
        "action_type": e.norm_action.action_type.as_action_str(),
        "channel": e.norm_action.channel,
        "permission": e.decision,
        "source": e.decision_source,
        "tier": tier,
        "risk_raw": risk_raw,
        "score": risk_score,
        "blocked": blocked,
        "flags": flags,
        "surface_tool": e.norm_action.execution.surface_tool,
        "surface_command": e.norm_action.execution.surface_command,
        "reviewer": reviewer,
        "reason": reason,
        "engine_permission": e.engine_decision,
        "norm_hash": hex::encode(e.norm_hash),
        "session_id": e.session_id,
        "task_goal": e.task_goal,
        "sequence": e.sequence,
        "entry_id": e.entry_id,
        "prev_hash": e.prev_hash,
        "human_review": e.human_review,
        "failed_open_context": e.failed_open_context,
        "retroactive_decision": e.retroactive_decision,
    })
}

fn hex_to_norm_hash(hex_str: &str) -> Option<permit0_types::NormHash> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_permission_variants() {
        assert_eq!(parse_permission("allow"), Some(Permission::Allow));
        assert_eq!(parse_permission("deny"), Some(Permission::Deny));
        assert_eq!(parse_permission("human"), Some(Permission::HumanInTheLoop));
        assert_eq!(parse_permission("ALLOW"), Some(Permission::Allow));
        assert!(parse_permission("invalid").is_none());
    }

    #[test]
    fn hex_to_norm_hash_valid() {
        let hex = "00".repeat(32);
        let hash = hex_to_norm_hash(&hex).unwrap();
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn hex_to_norm_hash_invalid() {
        assert!(hex_to_norm_hash("not_hex").is_none());
        assert!(hex_to_norm_hash("00").is_none()); // too short
    }
}
