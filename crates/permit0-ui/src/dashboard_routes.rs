#![forbid(unsafe_code)]

use std::collections::HashMap;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use permit0_store::audit::AuditFilter;
use permit0_types::{DecisionFilter, Permission};

use crate::state::AppState;

// ── Response Envelope ──

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

// ── Response Types ──

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_decisions: usize,
    pub allow_count: usize,
    pub deny_count: usize,
    pub human_count: usize,
    pub tier_distribution: HashMap<String, usize>,
    pub pending_approvals: usize,
}

#[derive(Debug, Serialize)]
pub struct ListEntry {
    pub norm_hash_hex: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub filename: String,
}

// ── Request Types ──

#[derive(Debug, Deserialize)]
pub struct RemoveEntryRequest {
    pub norm_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>,
}

// ── Helpers ──

fn hex_to_norm_hash(hex_str: &str) -> Option<permit0_types::NormHash> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

fn sanitize_profile_name(name: &str) -> Result<&str, String> {
    if name.is_empty() {
        return Err("profile name must not be empty".into());
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(format!("invalid profile name: {name}"));
    }
    let valid = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err(format!("invalid profile name: {name}"));
    }
    Ok(name)
}

// ── Route Handlers ──

/// GET /api/v1/stats
pub async fn stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<StatsResponse>>, (StatusCode, Json<ApiResponse<StatsResponse>>)> {
    let filter = DecisionFilter {
        limit: Some(10_000),
        ..Default::default()
    };

    let records = state.store.query_decisions(&filter).map_err(|e| {
        err_response::<StatsResponse>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to query decisions: {e}"),
        )
    })?;

    let total_decisions = records.len();
    let mut allow_count = 0usize;
    let mut deny_count = 0usize;
    let mut human_count = 0usize;
    let mut tier_distribution: HashMap<String, usize> = HashMap::new();

    for record in &records {
        match record.permission {
            Permission::Allow => allow_count += 1,
            Permission::Deny => deny_count += 1,
            Permission::HumanInTheLoop => human_count += 1,
        }
        if let Some(ref tier) = record.tier {
            *tier_distribution.entry(tier.to_string()).or_insert(0) += 1;
        }
    }

    let pending_approvals = state.approval_manager.list_pending().len();

    Ok(ok_response(StatsResponse {
        total_decisions,
        allow_count,
        deny_count,
        human_count,
        tier_distribution,
        pending_approvals,
    }))
}

/// GET /api/v1/lists/denylist
pub async fn list_denylist(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<ListEntry>>>, (StatusCode, Json<ApiResponse<Vec<ListEntry>>>)> {
    let entries = state.store.denylist_list().map_err(|e| {
        err_response::<Vec<ListEntry>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to list denylist: {e}"),
        )
    })?;

    let list: Vec<ListEntry> = entries
        .into_iter()
        .map(|(hash, reason)| ListEntry {
            norm_hash_hex: hex::encode(hash),
            reason,
        })
        .collect();

    Ok(ok_response(list))
}

/// GET /api/v1/lists/allowlist
pub async fn list_allowlist(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<ListEntry>>>, (StatusCode, Json<ApiResponse<Vec<ListEntry>>>)> {
    let entries = state.store.allowlist_list().map_err(|e| {
        err_response::<Vec<ListEntry>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to list allowlist: {e}"),
        )
    })?;

    let list: Vec<ListEntry> = entries
        .into_iter()
        .map(|(hash, justification)| ListEntry {
            norm_hash_hex: hex::encode(hash),
            reason: justification,
        })
        .collect();

    Ok(ok_response(list))
}

/// DELETE /api/v1/lists/denylist
pub async fn denylist_remove_entry(
    State(state): State<AppState>,
    Json(req): Json<RemoveEntryRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let hash = hex_to_norm_hash(&req.norm_hash_hex)
        .ok_or_else(|| err_response::<String>(StatusCode::BAD_REQUEST, "invalid norm_hash hex"))?;

    state.store.denylist_remove(&hash).map_err(|e| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        )
    })?;

    Ok(ok_response("removed from denylist".to_string()))
}

/// DELETE /api/v1/lists/allowlist
pub async fn allowlist_remove_entry(
    State(state): State<AppState>,
    Json(req): Json<RemoveEntryRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let hash = hex_to_norm_hash(&req.norm_hash_hex)
        .ok_or_else(|| err_response::<String>(StatusCode::BAD_REQUEST, "invalid norm_hash hex"))?;

    state.store.allowlist_remove(&hash).map_err(|e| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        )
    })?;

    Ok(ok_response("removed from allowlist".to_string()))
}

/// GET /api/v1/audit/export?format=jsonl|csv
pub async fn audit_export(
    State(state): State<AppState>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, (StatusCode, Json<ApiResponse<String>>)> {
    let format = q.format.unwrap_or_else(|| "jsonl".to_string());

    let filter = DecisionFilter {
        limit: Some(100_000),
        ..Default::default()
    };

    let records = state.store.query_decisions(&filter).map_err(|e| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to query decisions: {e}"),
        )
    })?;

    match format.as_str() {
        "jsonl" => {
            let mut body = String::new();
            for record in &records {
                if let Ok(line) = serde_json::to_string(record) {
                    body.push_str(&line);
                    body.push('\n');
                }
            }
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/x-ndjson"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit_export.jsonl\"",
                    ),
                ],
                body,
            )
                .into_response())
        }
        "csv" => {
            let mut body = String::new();
            body.push_str(
                "id,norm_hash,action_type,channel,permission,source,tier,risk_raw,blocked,flags,timestamp,surface_tool,surface_command\n",
            );
            for record in &records {
                let tier_str = record
                    .tier
                    .as_ref()
                    .map(|t| t.to_string())
                    .unwrap_or_default();
                let risk_str = record.risk_raw.map(|r| r.to_string()).unwrap_or_default();
                let flags_str = record.flags.join(";");
                body.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    record.id,
                    hex::encode(record.norm_hash),
                    record.action_type,
                    record.channel,
                    record.permission,
                    record.source,
                    tier_str,
                    risk_str,
                    record.blocked,
                    flags_str,
                    record.timestamp,
                    record.surface_tool,
                    record.surface_command,
                ));
            }
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit_export.csv\"",
                    ),
                ],
                body,
            )
                .into_response())
        }
        other => Err(err_response::<String>(
            StatusCode::BAD_REQUEST,
            &format!("unsupported format: {other} (expected 'jsonl' or 'csv')"),
        )),
    }
}

/// GET /api/v1/profiles
pub async fn list_profiles(
    State(state): State<AppState>,
) -> Result<
    Json<ApiResponse<Vec<ProfileSummary>>>,
    (StatusCode, Json<ApiResponse<Vec<ProfileSummary>>>),
> {
    let profiles_dir = state.profiles_dir.as_ref().ok_or_else(|| {
        err_response::<Vec<ProfileSummary>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "profiles_dir is not configured",
        )
    })?;

    let entries = std::fs::read_dir(profiles_dir).map_err(|e| {
        err_response::<Vec<ProfileSummary>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to read profiles directory: {e}"),
        )
    })?;

    let mut summaries: Vec<ProfileSummary> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !filename.ends_with(".profile.yaml") {
            continue;
        }
        let name = filename.trim_end_matches(".profile.yaml").to_string();
        summaries.push(ProfileSummary { name, filename });
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ok_response(summaries))
}

/// GET /api/v1/profiles/{name}
pub async fn get_profile(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let name = sanitize_profile_name(&name)
        .map_err(|e| err_response::<String>(StatusCode::BAD_REQUEST, &e))?;

    let profiles_dir = state.profiles_dir.as_ref().ok_or_else(|| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "profiles_dir is not configured",
        )
    })?;

    let file_path = profiles_dir.join(format!("{name}.profile.yaml"));

    let content = std::fs::read_to_string(&file_path).map_err(|e| {
        err_response::<String>(StatusCode::NOT_FOUND, &format!("profile not found: {e}"))
    })?;

    Ok(ok_response(content))
}

// ── Calibration ──

#[derive(Debug, Serialize)]
pub struct CalibrationStats {
    /// Total calibration records (records with a reviewer set).
    pub total: usize,
    /// Records where engine and human agreed.
    pub matched: usize,
    /// Records where the human overrode permit0.
    pub overridden: usize,
    /// matched / total (0.0–1.0). Null if total = 0.
    pub agreement_rate: Option<f64>,
    /// Top reviewers by count: list of (reviewer, count).
    pub by_reviewer: Vec<ReviewerCount>,
    /// Most-overridden action types.
    pub most_overridden_actions: Vec<ActionOverrideCount>,
}

#[derive(Debug, Serialize)]
pub struct ReviewerCount {
    pub reviewer: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ActionOverrideCount {
    pub action_type: String,
    pub count: usize,
}

/// GET /api/v1/calibration/stats — aggregate stats over calibration records.
pub async fn calibration_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<CalibrationStats>>, (StatusCode, Json<ApiResponse<CalibrationStats>>)>
{
    let records = state
        .store
        .query_decisions(&DecisionFilter {
            limit: Some(10000),
            ..Default::default()
        })
        .map_err(|e| {
            err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("query failed: {e}"),
            )
        })?;

    // Calibration records = those with a reviewer set.
    let calib: Vec<_> = records.iter().filter(|r| r.reviewer.is_some()).collect();
    let total = calib.len();

    let mut matched = 0;
    let mut overridden = 0;
    for r in &calib {
        if let Some(eng) = r.engine_permission {
            if eng == r.permission {
                matched += 1;
            } else {
                overridden += 1;
            }
        }
    }

    let mut by_reviewer_map: HashMap<String, usize> = HashMap::new();
    for r in &calib {
        if let Some(rev) = &r.reviewer {
            *by_reviewer_map.entry(rev.clone()).or_insert(0) += 1;
        }
    }
    let mut by_reviewer: Vec<ReviewerCount> = by_reviewer_map
        .into_iter()
        .map(|(reviewer, count)| ReviewerCount { reviewer, count })
        .collect();
    by_reviewer.sort_by_key(|x| std::cmp::Reverse(x.count));
    by_reviewer.truncate(10);

    let mut overridden_action_map: HashMap<String, usize> = HashMap::new();
    for r in &calib {
        if let Some(eng) = r.engine_permission {
            if eng != r.permission {
                *overridden_action_map
                    .entry(r.action_type.clone())
                    .or_insert(0) += 1;
            }
        }
    }
    let mut most_overridden_actions: Vec<ActionOverrideCount> = overridden_action_map
        .into_iter()
        .map(|(action_type, count)| ActionOverrideCount { action_type, count })
        .collect();
    most_overridden_actions.sort_by_key(|x| std::cmp::Reverse(x.count));
    most_overridden_actions.truncate(10);

    let agreement_rate = if total > 0 {
        Some(matched as f64 / total as f64)
    } else {
        None
    };

    Ok(ok_response(CalibrationStats {
        total,
        matched,
        overridden,
        agreement_rate,
        by_reviewer,
        most_overridden_actions,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CalibrationListQuery {
    /// "matched" → only agreement; "overridden" → only mismatch; default → all
    pub agreement: Option<String>,
    /// Filter by reviewer name (exact match)
    pub reviewer: Option<String>,
    /// Max records to return
    pub limit: Option<u32>,
}

/// GET /api/v1/calibration/records — calibration-only audit subset.
pub async fn calibration_records(
    State(state): State<AppState>,
    Query(q): Query<CalibrationListQuery>,
) -> Result<
    Json<ApiResponse<Vec<serde_json::Value>>>,
    (StatusCode, Json<ApiResponse<Vec<serde_json::Value>>>),
> {
    let records = state
        .store
        .query_decisions(&DecisionFilter {
            limit: Some(q.limit.unwrap_or(500)),
            ..Default::default()
        })
        .map_err(|e| {
            err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("query failed: {e}"),
            )
        })?;

    let filtered: Vec<serde_json::Value> = records
        .into_iter()
        .filter(|r| r.reviewer.is_some())
        .filter(|r| match q.reviewer.as_deref() {
            Some(rev) => r.reviewer.as_deref() == Some(rev),
            None => true,
        })
        .filter(|r| match q.agreement.as_deref() {
            Some("matched") => {
                r.engine_permission.is_some() && r.engine_permission == Some(r.permission)
            }
            Some("overridden") => {
                r.engine_permission.is_some() && r.engine_permission != Some(r.permission)
            }
            _ => true,
        })
        .filter_map(|r| serde_json::to_value(&r).ok())
        .collect();

    Ok(ok_response(filtered))
}

// ── Failed-open windows banner (Lane A step 1c) ──────────────────────

/// One row in the dashboard banner: a single failed-open window the
/// client buffered, replayed, and the daemon retro-scored. Operators
/// review entries where `would_have_blocked > 0` first.
#[derive(Debug, Serialize)]
pub struct FailedOpenWindow {
    pub client_window_start: String,
    pub client_window_end: String,
    pub fail_reason_code: String,
    pub event_count: u64,
    pub would_have_allowed: u64,
    pub would_have_denied: u64,
    pub would_have_human: u64,
    /// Convenience for the UI: events with retroactive_decision != Allow.
    pub would_have_blocked: u64,
}

/// GET /api/v1/audit/failed_open_windows
///
/// Aggregates audit entries with `decision_source == "failed_open"` by
/// the `(client_window_start, client_window_end, fail_reason_code)`
/// triple, returning one row per distinct window. Sorted most-recent-end
/// first so the UI banner shows the freshest incident at the top.
pub async fn failed_open_windows(
    State(state): State<AppState>,
) -> Result<
    Json<ApiResponse<Vec<FailedOpenWindow>>>,
    (StatusCode, Json<ApiResponse<Vec<FailedOpenWindow>>>),
> {
    let sink = match state.audit_sink {
        Some(ref s) => s,
        None => {
            // No audit sink wired — banner has nothing to show. Return
            // an empty list so the frontend can render "no incidents".
            return Ok(ok_response(Vec::new()));
        }
    };

    // Pull a generous batch of recent audit entries. The query path uses
    // an AuditFilter that doesn't currently support filter-by-source, so
    // we filter client-side.
    let filter = AuditFilter {
        limit: Some(10_000),
        ..Default::default()
    };
    let entries = sink.query(&filter).map_err(|e| {
        err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("audit query failed: {e}"),
        )
    })?;

    let rows = aggregate_failed_open_windows(&entries);
    Ok(ok_response(rows))
}

/// Aggregate audit entries into one row per `(window_start, window_end,
/// reason_code)`. Pulled out as a pure function so it can be unit-tested
/// without spinning up an AppState + AuditSink.
///
/// Result is sorted most-recent-end first (ISO 8601 lexical sort).
fn aggregate_failed_open_windows(
    entries: &[permit0_store::audit::AuditEntry],
) -> Vec<FailedOpenWindow> {
    let mut windows: HashMap<(String, String, String), FailedOpenWindow> = HashMap::new();
    for entry in entries {
        if entry.decision_source != "failed_open" {
            continue;
        }
        let foc = match &entry.failed_open_context {
            Some(c) => c,
            None => continue, // legacy or malformed; skip
        };
        let key = (
            foc.client_window_start.clone(),
            foc.client_window_end.clone(),
            foc.fail_reason_code.clone(),
        );
        let row = windows.entry(key).or_insert_with(|| FailedOpenWindow {
            client_window_start: foc.client_window_start.clone(),
            client_window_end: foc.client_window_end.clone(),
            fail_reason_code: foc.fail_reason_code.clone(),
            event_count: 0,
            would_have_allowed: 0,
            would_have_denied: 0,
            would_have_human: 0,
            would_have_blocked: 0,
        });
        row.event_count += 1;
        match entry.retroactive_decision {
            Some(Permission::Allow) => row.would_have_allowed += 1,
            Some(Permission::Deny) => {
                row.would_have_denied += 1;
                row.would_have_blocked += 1;
            }
            Some(Permission::HumanInTheLoop) => {
                row.would_have_human += 1;
                row.would_have_blocked += 1;
            }
            None => {} // engine retro-score didn't run; leave counts alone
        }
    }

    let mut rows: Vec<FailedOpenWindow> = windows.into_values().collect();
    rows.sort_by(|a, b| b.client_window_end.cmp(&a.client_window_end));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── hex_to_norm_hash tests ──

    #[test]
    fn hex_to_norm_hash_valid() {
        let hex = "00".repeat(32);
        let hash = hex_to_norm_hash(&hex).unwrap();
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn hex_to_norm_hash_all_ff() {
        let hex = "ff".repeat(32);
        let hash = hex_to_norm_hash(&hex).unwrap();
        assert_eq!(hash, [0xffu8; 32]);
    }

    #[test]
    fn hex_to_norm_hash_invalid_hex() {
        assert!(hex_to_norm_hash("not_valid_hex").is_none());
    }

    #[test]
    fn hex_to_norm_hash_wrong_length() {
        assert!(hex_to_norm_hash("00").is_none()); // 1 byte, not 32
        assert!(hex_to_norm_hash(&"00".repeat(16)).is_none()); // 16 bytes
        assert!(hex_to_norm_hash(&"00".repeat(33)).is_none()); // 33 bytes
    }

    // ── sanitize_profile_name tests ──

    #[test]
    fn sanitize_profile_name_accepts_valid() {
        assert_eq!(sanitize_profile_name("default"), Ok("default"));
        assert_eq!(sanitize_profile_name("my-profile"), Ok("my-profile"));
        assert_eq!(sanitize_profile_name("test_123"), Ok("test_123"));
    }

    #[test]
    fn sanitize_profile_name_rejects_empty() {
        assert!(sanitize_profile_name("").is_err());
    }

    #[test]
    fn sanitize_profile_name_rejects_traversal() {
        assert!(sanitize_profile_name("..").is_err());
        assert!(sanitize_profile_name("../evil").is_err());
        assert!(sanitize_profile_name("foo/../bar").is_err());
    }

    #[test]
    fn sanitize_profile_name_rejects_slash() {
        assert!(sanitize_profile_name("foo/bar").is_err());
    }

    #[test]
    fn sanitize_profile_name_rejects_backslash() {
        assert!(sanitize_profile_name("foo\\bar").is_err());
    }

    #[test]
    fn sanitize_profile_name_rejects_special_chars() {
        assert!(sanitize_profile_name("foo.bar").is_err());
        assert!(sanitize_profile_name("foo bar").is_err());
    }

    // ── list_profiles filesystem test ──

    #[test]
    fn profile_filename_suffix_detection() {
        let filename = "staging.profile.yaml";
        assert!(filename.ends_with(".profile.yaml"));
        let name = filename.trim_end_matches(".profile.yaml");
        assert_eq!(name, "staging");
    }

    // ── aggregate_failed_open_windows tests ──

    use permit0_store::audit::{AuditEntry, FailedOpenContext};
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_failed_open_entry(
        window_start: &str,
        window_end: &str,
        reason_code: &str,
        retroactive: Option<Permission>,
    ) -> AuditEntry {
        AuditEntry {
            entry_id: format!("e-{window_start}-{reason_code}"),
            timestamp: window_end.into(),
            sequence: 0,
            decision: Permission::Allow,
            decision_source: "failed_open".into(),
            norm_action: NormAction {
                action_type: ActionType::parse("email.send").unwrap(),
                channel: "test".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "test".into(),
                    surface_command: "".into(),
                },
            },
            norm_hash: [0u8; 32],
            raw_tool_call: json!({}),
            risk_score: None,
            scoring_detail: None,
            agent_id: String::new(),
            session_id: None,
            task_goal: None,
            org_id: String::new(),
            environment: String::new(),
            engine_version: "test".into(),
            pack_id: String::new(),
            pack_version: String::new(),
            dsl_version: "1.0".into(),
            human_review: None,
            token_id: None,
            prev_hash: String::new(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: Some(FailedOpenContext {
                fail_reason_code: reason_code.into(),
                fail_reason: "test".into(),
                client_window_start: window_start.into(),
                client_window_end: window_end.into(),
                client_version: "0.1.0".into(),
                fail_open_source: "env_var".into(),
            }),
            retroactive_decision: retroactive,
        }
    }

    fn make_normal_entry(decision_source: &str) -> AuditEntry {
        let mut e = make_failed_open_entry("a", "b", "refused", Some(Permission::Allow));
        e.decision_source = decision_source.into();
        e.failed_open_context = None;
        e.retroactive_decision = None;
        e
    }

    #[test]
    fn aggregate_groups_by_window_and_reason() {
        let entries = vec![
            make_failed_open_entry(
                "2026-04-30T10:00:00Z",
                "2026-04-30T10:05:00Z",
                "refused",
                Some(Permission::Allow),
            ),
            make_failed_open_entry(
                "2026-04-30T10:00:00Z",
                "2026-04-30T10:05:00Z",
                "refused",
                Some(Permission::Deny),
            ),
            make_failed_open_entry(
                "2026-04-30T10:00:00Z",
                "2026-04-30T10:05:00Z",
                "refused",
                Some(Permission::HumanInTheLoop),
            ),
            make_failed_open_entry(
                "2026-04-30T11:00:00Z",
                "2026-04-30T11:02:00Z",
                "timeout",
                Some(Permission::Allow),
            ),
        ];
        let rows = aggregate_failed_open_windows(&entries);
        assert_eq!(rows.len(), 2);

        // Sorted by window_end DESC: 11:02 first, then 10:05.
        assert_eq!(rows[0].client_window_end, "2026-04-30T11:02:00Z");
        assert_eq!(rows[0].event_count, 1);
        assert_eq!(rows[0].would_have_allowed, 1);
        assert_eq!(rows[0].would_have_blocked, 0);

        assert_eq!(rows[1].client_window_end, "2026-04-30T10:05:00Z");
        assert_eq!(rows[1].event_count, 3);
        assert_eq!(rows[1].would_have_allowed, 1);
        assert_eq!(rows[1].would_have_denied, 1);
        assert_eq!(rows[1].would_have_human, 1);
        assert_eq!(rows[1].would_have_blocked, 2);
    }

    #[test]
    fn aggregate_skips_non_failed_open_entries() {
        let entries = vec![
            make_normal_entry("scorer"),
            make_normal_entry("policy_cache"),
            make_failed_open_entry("a", "b", "refused", Some(Permission::Deny)),
        ];
        let rows = aggregate_failed_open_windows(&entries);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_count, 1);
    }

    #[test]
    fn aggregate_skips_failed_open_without_context() {
        // Defensive: a tampered or legacy entry with decision_source ==
        // "failed_open" but no failed_open_context should not crash the
        // aggregator. It just gets skipped.
        let mut bad = make_failed_open_entry("a", "b", "refused", Some(Permission::Deny));
        bad.failed_open_context = None;
        let entries = vec![bad];
        let rows = aggregate_failed_open_windows(&entries);
        assert!(rows.is_empty());
    }

    #[test]
    fn aggregate_handles_missing_retroactive_decision() {
        // If retro-scoring failed for an entry, retroactive_decision is
        // None — the row still counts the event but doesn't increment any
        // bucket. Operators see "event_count: N, but breakdown is 0/0/0"
        // which signals "retro-score didn't run, look at raw entries".
        let entries = vec![make_failed_open_entry("a", "b", "refused", None)];
        let rows = aggregate_failed_open_windows(&entries);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_count, 1);
        assert_eq!(rows[0].would_have_allowed, 0);
        assert_eq!(rows[0].would_have_denied, 0);
        assert_eq!(rows[0].would_have_human, 0);
        assert_eq!(rows[0].would_have_blocked, 0);
    }

    #[test]
    fn aggregate_separates_windows_with_different_reason_codes() {
        // Same time window but two different reason_codes (operator
        // hit a flapping daemon: timeout, then refused) → two rows.
        let entries = vec![
            make_failed_open_entry("a", "b", "timeout", Some(Permission::Allow)),
            make_failed_open_entry("a", "b", "refused", Some(Permission::Allow)),
        ];
        let rows = aggregate_failed_open_windows(&entries);
        assert_eq!(rows.len(), 2);
    }
}
