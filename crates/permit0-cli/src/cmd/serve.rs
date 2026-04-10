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
use permit0_store::InMemoryStore;
use permit0_types::RawToolCall;
use permit0_ui::{AppState, ApprovalManager, TokenStore};

use crate::engine_factory;

/// Shared state for the server.
#[derive(Clone)]
struct ServerState {
    engine: Arc<Engine>,
    org_domain: String,
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
    let engine = engine_factory::build_engine_from_packs(profile.as_deref())?;

    let server_state = ServerState {
        engine: Arc::new(engine),
        org_domain: org_domain.into(),
    };

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async move {
        let check_api = Router::new()
            .route("/check", post(check_handler))
            .route("/health", get(health))
            .with_state(server_state);

        let app = if with_ui {
            let ui_state = AppState {
                store: Arc::new(InMemoryStore::new()),
                audit_sink: None,
                token_store: Arc::new(TokenStore::new()),
                approval_manager: Arc::new(ApprovalManager::new()),
            };
            let ui_router = permit0_ui::build_router(ui_state);
            // Merge: /api/v1/check + /api/v1/* (UI routes)
            Router::new()
                .nest("/api/v1", check_api)
                .merge(ui_router)
        } else {
            Router::new().nest("/api/v1", check_api)
        };

        let addr = format!("0.0.0.0:{port}");
        eprintln!("permit0 server listening on {addr}");
        if with_ui {
            eprintln!("  approval UI API mounted at /api/v1/");
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
