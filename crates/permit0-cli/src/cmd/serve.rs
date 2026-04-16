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

use permit0_engine::{Engine, PermissionCtx};
use permit0_normalize::NormalizeCtx;
use permit0_store::{InMemoryStore, SqliteStore, Store};
use permit0_types::{DecisionRecord, RawToolCall};
use permit0_ui::{AppState, ApprovalManager, TokenStore};
use tower_http::services::ServeDir;

use crate::engine_factory;

/// Shared state for the server.
#[derive(Clone)]
struct ServerState {
    engine: Arc<Engine>,
    org_domain: String,
    store: Option<Arc<dyn Store>>,
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

    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&state.org_domain));

    let result = state
        .engine
        .get_permission(&tool_call, &ctx)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("engine error: {e}")))?;

    // Save decision to store for dashboard visibility
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
            surface_tool: tool_call.tool_name.clone(),
            surface_command: tool_call
                .parameters
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(200)
                .collect(),
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
pub fn run(port: u16, profile: Option<String>, org_domain: &str, with_ui: bool) -> Result<()> {
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

            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
                store: Some(shared_store.clone()),
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
                .with_state(server_state);

            let ui_state = AppState {
                store: shared_store,
                audit_sink: None,
                token_store: Arc::new(TokenStore::new()),
                approval_manager: Arc::new(ApprovalManager::new()),
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
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
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
