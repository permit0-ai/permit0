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
use crate::dashboard_routes;
use crate::oidc;
use crate::pack_routes;
use crate::routes;
use crate::state::AppState;

/// Build the axum router with all API routes.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(routes::health))
        .route("/audit", get(routes::list_audit))
        .route("/audit/export", get(dashboard_routes::audit_export))
        .route("/stats", get(dashboard_routes::stats))
        .route("/approvals", get(routes::list_approvals))
        .route("/approvals/decide", post(routes::submit_approval))
        .route(
            "/lists/denylist",
            get(dashboard_routes::list_denylist)
                .post(routes::denylist_add)
                .delete(dashboard_routes::denylist_remove_entry),
        )
        .route(
            "/lists/allowlist",
            get(dashboard_routes::list_allowlist)
                .post(routes::allowlist_add)
                .delete(dashboard_routes::allowlist_remove_entry),
        )
        .route("/profiles", get(dashboard_routes::list_profiles))
        .route("/profiles/{name}", get(dashboard_routes::get_profile))
        .route("/packs", get(pack_routes::list_packs))
        .route("/packs/validate", post(pack_routes::validate_yaml))
        .route("/packs/{pack_name}", get(pack_routes::get_pack))
        .route(
            "/packs/{pack_name}/normalizers/{filename}",
            get(pack_routes::get_normalizer).put(pack_routes::update_normalizer),
        )
        .route(
            "/packs/{pack_name}/risk_rules/{filename}",
            get(pack_routes::get_risk_rule).put(pack_routes::update_risk_rule),
        );

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
        .route("/audit/export", get(dashboard_routes::audit_export))
        .route("/stats", get(dashboard_routes::stats))
        .route("/approvals", get(routes::list_approvals))
        .route("/approvals/decide", post(routes::submit_approval))
        .route(
            "/lists/denylist",
            get(dashboard_routes::list_denylist)
                .post(routes::denylist_add)
                .delete(dashboard_routes::denylist_remove_entry),
        )
        .route(
            "/lists/allowlist",
            get(dashboard_routes::list_allowlist)
                .post(routes::allowlist_add)
                .delete(dashboard_routes::allowlist_remove_entry),
        )
        .route("/profiles", get(dashboard_routes::list_profiles))
        .route("/profiles/{name}", get(dashboard_routes::get_profile))
        .route("/packs", get(pack_routes::list_packs))
        .route("/packs/validate", post(pack_routes::validate_yaml))
        .route("/packs/{pack_name}", get(pack_routes::get_pack))
        .route(
            "/packs/{pack_name}/normalizers/{filename}",
            get(pack_routes::get_normalizer).put(pack_routes::update_normalizer),
        )
        .route(
            "/packs/{pack_name}/risk_rules/{filename}",
            get(pack_routes::get_risk_rule).put(pack_routes::update_risk_rule),
        )
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

/// Build the router with OIDC authentication.
pub fn build_router_with_oidc(state: AppState, oidc_state: oidc::OidcState) -> Router {
    let public_api = Router::new()
        .route("/health", get(routes::health));

    // OIDC routes (public — handle login/callback flow)
    let oidc_routes = Router::new()
        .route("/oidc/login", get(oidc::routes::oidc_login))
        .route("/oidc/callback", get(oidc::routes::oidc_callback))
        .route("/oidc/logout", get(oidc::routes::oidc_logout))
        .route("/oidc/me", get(oidc::routes::oidc_me))
        .with_state(oidc_state.clone());

    let protected_api = Router::new()
        .route("/audit", get(routes::list_audit))
        .route("/audit/export", get(dashboard_routes::audit_export))
        .route("/stats", get(dashboard_routes::stats))
        .route("/approvals", get(routes::list_approvals))
        .route("/approvals/decide", post(routes::submit_approval))
        .route(
            "/lists/denylist",
            get(dashboard_routes::list_denylist)
                .post(routes::denylist_add)
                .delete(dashboard_routes::denylist_remove_entry),
        )
        .route(
            "/lists/allowlist",
            get(dashboard_routes::list_allowlist)
                .post(routes::allowlist_add)
                .delete(dashboard_routes::allowlist_remove_entry),
        )
        .route("/profiles", get(dashboard_routes::list_profiles))
        .route("/profiles/{name}", get(dashboard_routes::get_profile))
        .route("/packs", get(pack_routes::list_packs))
        .route("/packs/validate", post(pack_routes::validate_yaml))
        .route("/packs/{pack_name}", get(pack_routes::get_pack))
        .route(
            "/packs/{pack_name}/normalizers/{filename}",
            get(pack_routes::get_normalizer).put(pack_routes::update_normalizer),
        )
        .route(
            "/packs/{pack_name}/risk_rules/{filename}",
            get(pack_routes::get_risk_rule).put(pack_routes::update_risk_rule),
        )
        .layer(middleware::from_fn_with_state(
            oidc_state,
            oidc::routes::oidc_auth_middleware,
        ))
        .with_state(state.clone());

    Router::new()
        .nest("/api/v1", public_api.merge(oidc_routes).merge(protected_api))
        .with_state(state)
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
        packs_dir: None,
        profiles_dir: None,
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
            packs_dir: None,
            profiles_dir: None,
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
