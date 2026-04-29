#![forbid(unsafe_code)]

//! HTTP server mode: `permit0 serve --port 9090`.
//!
//! Exposes a REST API for remote agents:
//!
//! - `POST /api/v1/check` — evaluate a tool call, return decision JSON
//! - `GET  /api/v1/health` — health check
//!
//! Also mounts the full approval UI API if `--ui` is passed.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};

use permit0_engine::{DecisionSource, Engine, PermissionCtx, PermissionResult};
use permit0_normalize::NormalizeCtx;
use permit0_store::{InMemoryStore, SqliteStore, Store};
use permit0_types::{
    ActionType, DecisionRecord, Entities, ExecutionMeta, NormAction, RawToolCall, RiskScore,
    Tier,
};
use permit0_ui::{AppState, ApprovalManager, TokenStore};
use tower_http::services::ServeDir;

use crate::engine_factory;

/// Shared state for the server.
#[derive(Clone)]
struct ServerState {
    engine: Arc<Engine>,
    org_domain: String,
    store: Option<Arc<dyn Store>>,
    /// Calibration mode: every fresh decision is escalated to human approval.
    calibrate: bool,
    /// Approval manager for the calibration synchronous wait. Shared with
    /// AppState so the dashboard's /api/v1/approvals/decide endpoint
    /// resolves the same channel.
    approval_manager: Option<Arc<permit0_ui::ApprovalManager>>,
}

/// Request body for POST /api/v1/check.
#[derive(Debug, Deserialize)]
struct CheckRequest {
    #[serde(alias = "tool")]
    tool_name: String,
    #[serde(alias = "input")]
    parameters: serde_json::Value,
}

/// Response for POST /api/v1/check.
#[derive(Debug, Serialize)]
struct CheckResponse {
    permission: String,
    action_type: String,
    channel: String,
    norm_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_reason: Option<String>,
    source: String,
}

/// POST /api/v1/check handler.
async fn check_handler(
    State(state): State<ServerState>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let tool_call = RawToolCall {
        tool_name: req.tool_name,
        parameters: req.parameters,
        metadata: Default::default(),
    };

    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&state.org_domain))
        .with_skip_audit(state.calibrate);

    let result = state
        .engine
        .get_permission(&tool_call, &ctx)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("engine error: {e}")))?;

    let (result, meta) = apply_calibration(&state, result).await?;

    let surface_command = tool_call
        .parameters
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    record_and_respond(&state, &result, tool_call.tool_name.clone(), surface_command, meta)
}

/// Request body for POST /api/v1/check_action.
#[derive(Debug, Deserialize)]
struct CheckActionRequest {
    action_type: String,
    #[serde(default = "default_channel")]
    channel: String,
    #[serde(default)]
    entities: Entities,
}

fn default_channel() -> String {
    "app".to_string()
}

/// POST /api/v1/check_action handler — evaluate a pre-normalized action.
///
/// Used by language SDKs (e.g. `@permit0.guard("email.send")` in Python)
/// where the caller already knows the norm action and doesn't need
/// YAML normalizer translation.
async fn check_action_handler(
    State(state): State<ServerState>,
    Json(req): Json<CheckActionRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let action_type = ActionType::parse(&req.action_type)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid action_type: {e}")))?;

    let surface_tool = format!("__action:{}", req.action_type);
    let norm = NormAction {
        action_type,
        channel: req.channel,
        entities: req.entities,
        execution: ExecutionMeta {
            surface_tool: surface_tool.clone(),
            surface_command: String::new(),
        },
    };

    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&state.org_domain))
        .with_skip_audit(state.calibrate);

    let result = state
        .engine
        .check_norm_action(norm, &ctx)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("engine error: {e}")))?;

    let (result, meta) = apply_calibration(&state, result).await?;

    record_and_respond(&state, &result, surface_tool, String::new(), meta)
}

/// In calibration mode, escalate every fresh decision (Scorer or AgentReviewer
/// source — i.e. not from list/cache) to a human-in-the-loop approval. The
/// HTTP request blocks until the human submits a decision via the dashboard,
/// or until the approval timeout expires.
///
/// Cache is updated with the human's decision so subsequent identical calls
/// reflect the calibrated answer.
async fn apply_calibration(
    state: &ServerState,
    result: PermissionResult,
) -> Result<(PermissionResult, CalibrationMeta), (StatusCode, String)> {
    if !state.calibrate {
        return Ok((result, CalibrationMeta::default()));
    }
    // Skip when the decision came from a place where the human already had
    // a say (allowlist/denylist) or we're replaying a previous decision.
    match result.source {
        DecisionSource::Allowlist
        | DecisionSource::Denylist
        | DecisionSource::PolicyCache => return Ok((result, CalibrationMeta::default())),
        DecisionSource::Scorer | DecisionSource::AgentReviewer => {}
    }

    let manager = match &state.approval_manager {
        Some(m) => m.clone(),
        None => return Ok((result, CalibrationMeta::default())),
    };

    // Construct a RiskScore for the dashboard display (synthesize a Minimal
    // entry if the engine didn't produce one — rare, but possible).
    let risk_score = result.risk_score.clone().unwrap_or_else(|| RiskScore {
        raw: 0.0,
        score: 0,
        tier: Tier::Minimal,
        blocked: false,
        flags: Vec::new(),
        block_reason: None,
        reason: "no risk score (cache or fast-path)".into(),
    });

    let original_permission = result.permission;
    let norm_hash = result.norm_action.norm_hash();

    let (approval_id, rx) =
        manager.create_pending(result.norm_action.clone(), risk_score);
    let timeout = manager.timeout();

    eprintln!(
        "[calibrate] awaiting human decision for {} ({}) — engine says {:?}, approval_id={}",
        result.norm_action.action_type.as_action_str(),
        result.norm_action.channel,
        original_permission,
        approval_id,
    );

    // Block until the human decides or the approval times out.
    let decision = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(d)) => d,
        Ok(Err(_)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "approval channel closed unexpectedly".into(),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                format!("calibration timeout after {}s; no human decision", timeout.as_secs()),
            ));
        }
    };

    eprintln!(
        "[calibrate] human → {:?} (engine had → {:?}) reviewer={} reason={}",
        decision.permission, original_permission, decision.reviewer, decision.reason,
    );

    // Persist the human's decision in the cache so future identical calls
    // reflect the calibrated answer (overwriting the engine's recommendation).
    let _ = state
        .engine
        .store()
        .policy_cache_set(norm_hash, decision.permission);

    let meta = CalibrationMeta {
        engine_permission: Some(original_permission),
        reviewer: Some(decision.reviewer),
        reason: Some(decision.reason),
    };
    let new_result = PermissionResult {
        permission: decision.permission,
        norm_action: result.norm_action,
        risk_score: result.risk_score,
        source: DecisionSource::AgentReviewer,
    };
    Ok((new_result, meta))
}

/// Calibration metadata attached to a decision when a human reviewer
/// approved/denied. None for non-calibration calls.
#[derive(Default)]
struct CalibrationMeta {
    engine_permission: Option<permit0_types::Permission>,
    reviewer: Option<String>,
    reason: Option<String>,
}

/// Persist the decision (if a shared store is configured) and serialize the response.
fn record_and_respond(
    state: &ServerState,
    result: &permit0_engine::PermissionResult,
    surface_tool: String,
    surface_command: String,
    calibration: CalibrationMeta,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    if let Some(ref store) = state.store {
        let record = DecisionRecord {
            id: ulid::Ulid::new().to_string(),
            norm_hash: result.norm_action.norm_hash(),
            action_type: result.norm_action.action_type.as_action_str().to_string(),
            channel: result.norm_action.channel.clone(),
            permission: result.permission,
            source: format!("{:?}", result.source),
            tier: result.risk_score.as_ref().map(|s| s.tier),
            risk_raw: result.risk_score.as_ref().map(|s| s.raw),
            blocked: result.risk_score.as_ref().map_or(false, |s| s.blocked),
            flags: result
                .risk_score
                .as_ref()
                .map_or_else(Vec::new, |s| s.flags.clone()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            surface_tool,
            surface_command,
            engine_permission: calibration.engine_permission,
            reviewer: calibration.reviewer,
            reason: calibration.reason,
        };
        let _ = store.save_decision(record);
    }

    Ok(Json(CheckResponse {
        permission: result.permission.to_string().to_lowercase(),
        action_type: result.norm_action.action_type.as_action_str().to_string(),
        channel: result.norm_action.channel.clone(),
        norm_hash: result.norm_action.norm_hash_hex(),
        score: result.risk_score.as_ref().map(|s| s.score),
        tier: result.risk_score.as_ref().map(|s| s.tier.to_string()),
        blocked: result.risk_score.as_ref().map(|s| s.blocked),
        block_reason: result
            .risk_score
            .as_ref()
            .and_then(|s| s.block_reason.clone()),
        source: format!("{:?}", result.source),
    }))
}

/// GET /api/v1/health handler.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "permit0" }))
}

/// Run the HTTP server.
pub fn run(
    port: u16,
    profile: Option<String>,
    org_domain: &str,
    with_ui: bool,
    calibrate: bool,
) -> Result<()> {
    let engine = engine_factory::build_engine_from_packs(profile.as_deref(), None)?;

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async move {
        let app = if with_ui {
            let packs_dir = engine_factory::resolve_packs_dir(None);
            let db_dir = engine_factory::dirs_home()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".permit0");
            std::fs::create_dir_all(&db_dir).ok();
            let db_path = db_dir.join("permit0.db");
            eprintln!("  database at {}", db_path.display());
            let shared_store: Arc<dyn Store> = match SqliteStore::open(&db_path) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    eprintln!("  warning: failed to open SQLite store ({e}), falling back to in-memory");
                    Arc::new(InMemoryStore::new())
                }
            };

            // Shared approval manager so the daemon's calibration handler and
            // the dashboard's /api/v1/approvals/decide endpoint resolve the
            // same oneshot channels.
            let approval_manager = Arc::new(ApprovalManager::new());

            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
                store: Some(shared_store.clone()),
                calibrate,
                approval_manager: Some(approval_manager.clone()),
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
                .route("/check_action", post(check_action_handler))
                .with_state(server_state);

            let ui_state = AppState {
                store: shared_store,
                audit_sink: None,
                token_store: Arc::new(TokenStore::new()),
                approval_manager,
                packs_dir: packs_dir.clone(),
                profiles_dir: Some(std::path::PathBuf::from("profiles")),
            };
            let ui_router = permit0_ui::build_router(ui_state);

            let mut app = Router::new()
                .nest("/api/v1", check_api)
                .merge(ui_router);

            let cwd_static = std::path::Path::new("crates/permit0-ui/static");
            if cwd_static.exists() {
                app = app.nest_service("/ui", ServeDir::new(cwd_static));
            }

            app
        } else {
            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
                store: None,
                calibrate: false,
                approval_manager: None,
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
                .route("/check_action", post(check_action_handler))
                .route("/health", get(health))
                .with_state(server_state);
            Router::new().nest("/api/v1", check_api)
        };

        let addr = format!("0.0.0.0:{port}");
        eprintln!("permit0 server listening on {addr}");
        if with_ui {
            eprintln!("  API mounted at /api/v1/");
            eprintln!("  admin dashboard at http://0.0.0.0:{port}/ui/");
        }

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .context("binding listener")?;
        axum::serve(listener, app)
            .await
            .context("running server")?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_response_serialization() {
        let resp = CheckResponse {
            permission: "allow".into(),
            action_type: "system.exec".into(),
            channel: "bash".into(),
            norm_hash: "abc123".into(),
            score: Some(12),
            tier: Some("Minimal".into()),
            blocked: Some(false),
            block_reason: None,
            source: "Scoring".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""permission":"allow""#));
        assert!(!json.contains("block_reason"));
    }

    #[test]
    fn check_request_deserialization() {
        let json = r#"{"tool": "Bash", "input": {"command": "ls"}}"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tool_name, "Bash");
        assert_eq!(req.parameters["command"], "ls");
    }
}
