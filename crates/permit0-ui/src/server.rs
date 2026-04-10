#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use permit0_store::{AuditSink, Store};

use crate::approval::ApprovalManager;
use crate::auth::TokenStore;
use crate::routes;
use crate::state::AppState;

/// Build the axum router with all API routes.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(routes::health))
        .route("/audit", get(routes::list_audit))
        .route("/approvals", get(routes::list_approvals))
        .route("/approvals/decide", post(routes::submit_approval))
        .route("/lists/denylist", post(routes::denylist_add))
        .route("/lists/allowlist", post(routes::allowlist_add));

    Router::new()
        .nest("/api/v1", api)
        .with_state(state)
}

/// Build the router with auth middleware.
pub fn build_router_with_auth(state: AppState) -> Router {
    let public_api = Router::new()
        .route("/health", get(routes::health));

    let protected_api = Router::new()
        .route("/audit", get(routes::list_audit))
        .route("/approvals", get(routes::list_approvals))
        .route("/approvals/decide", post(routes::submit_approval))
        .route("/lists/denylist", post(routes::denylist_add))
        .route("/lists/allowlist", post(routes::allowlist_add))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .nest("/api/v1", public_api.merge(protected_api))
        .with_state(state)
}

/// Auth middleware: checks Bearer token in Authorization header.
async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
        stripped.trim()
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    match state.token_store.verify(token) {
        Some(_api_token) => Ok(next.run(request).await),
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Configuration for the UI server.
pub struct ServerConfig {
    pub port: u16,
    pub store: Arc<dyn Store>,
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    pub require_auth: bool,
}

/// Create default AppState from ServerConfig.
pub fn create_app_state(config: &ServerConfig) -> AppState {
    AppState {
        store: config.store.clone(),
        audit_sink: config.audit_sink.clone(),
        token_store: Arc::new(TokenStore::new()),
        approval_manager: Arc::new(ApprovalManager::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use axum::body::Body;
    use axum::http::Request;
    use permit0_store::InMemoryStore;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            store: Arc::new(InMemoryStore::new()),
            audit_sink: None,
            token_store: Arc::new(TokenStore::new()),
            approval_manager: Arc::new(ApprovalManager::new()),
        }
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn audit_endpoint_returns_empty() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn approvals_endpoint_returns_empty() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_middleware_rejects_no_token() {
        let app = build_router_with_auth(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_accepts_valid_token() {
        let state = test_state();
        let token = state.token_store.create_token("Test", Role::Admin);

        let app = build_router_with_auth(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_bypasses_auth() {
        let app = build_router_with_auth(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
