#![forbid(unsafe_code)]

use std::collections::HashMap;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

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
            *tier_distribution
                .entry(tier.to_string())
                .or_insert(0) += 1;
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
                let risk_str = record
                    .risk_raw
                    .map(|r| r.to_string())
                    .unwrap_or_default();
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
    let name = sanitize_profile_name(&name).map_err(|e| {
        err_response::<String>(StatusCode::BAD_REQUEST, &e)
    })?;

    let profiles_dir = state.profiles_dir.as_ref().ok_or_else(|| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "profiles_dir is not configured",
        )
    })?;

    let file_path = profiles_dir.join(format!("{name}.profile.yaml"));

    let content = std::fs::read_to_string(&file_path).map_err(|e| {
        err_response::<String>(
            StatusCode::NOT_FOUND,
            &format!("profile not found: {e}"),
        )
    })?;

    Ok(ok_response(content))
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
}
