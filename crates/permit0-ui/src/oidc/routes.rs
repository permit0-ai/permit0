#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Json, Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};

use crate::auth::Role;
use crate::routes::ApiResponse;

use super::client::OidcClient;
use super::role_mapper::RoleMapper;
use super::session::{OidcSession, SessionStore};

/// Shared OIDC state (separate from AppState to keep separation clean).
#[derive(Clone)]
pub struct OidcState {
    pub client: std::sync::Arc<OidcClient>,
    pub role_mapper: std::sync::Arc<RoleMapper>,
    pub session_store: std::sync::Arc<SessionStore>,
    pub cookie_name: String,
    /// In-flight PKCE verifiers and state nonces.
    /// Key: state nonce, Value: (pkce_verifier, created_at).
    pub pending_flows: std::sync::Arc<Mutex<HashMap<String, PendingOidcFlow>>>,
}

/// A pending OIDC authorization flow.
#[derive(Debug, Clone)]
pub struct PendingOidcFlow {
    pub pkce_verifier: String,
    pub created_at: String,
}

/// GET /api/v1/oidc/login — Redirect to OIDC provider.
pub async fn oidc_login(
    State(state): State<OidcState>,
) -> Result<Redirect, (StatusCode, Json<ApiResponse<String>>)> {
    let (auth_url, verifier, nonce) = state.client.build_auth_url().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                ok: false,
                data: None,
                error: Some(format!("OIDC error: {e}")),
            }),
        )
    })?;

    // Store PKCE verifier keyed by state nonce
    state.pending_flows.lock().unwrap().insert(
        nonce,
        PendingOidcFlow {
            pkce_verifier: verifier,
            created_at: chrono::Utc::now().to_rfc3339(),
        },
    );

    Ok(Redirect::temporary(&auth_url))
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// GET /api/v1/oidc/callback — Handle OIDC provider callback.
pub async fn oidc_callback(
    State(state): State<OidcState>,
    Query(q): Query<CallbackQuery>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), (StatusCode, Json<ApiResponse<String>>)> {
    // Retrieve and remove PKCE verifier
    let flow = state
        .pending_flows
        .lock()
        .unwrap()
        .remove(&q.state)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    ok: false,
                    data: None,
                    error: Some("invalid or expired state parameter".into()),
                }),
            )
        })?;

    // Exchange code for tokens
    let tokens = state
        .client
        .exchange_code(&q.code, &flow.pkce_verifier)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ApiResponse {
                    ok: false,
                    data: None,
                    error: Some(format!("token exchange failed: {e}")),
                }),
            )
        })?;

    // Fetch user info
    let user_info = state
        .client
        .fetch_userinfo(&tokens.access_token)
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ApiResponse {
                    ok: false,
                    data: None,
                    error: Some(format!("userinfo fetch failed: {e}")),
                }),
            )
        })?;

    // Check domain allowlist
    if let Some(ref email) = user_info.email {
        if !state.role_mapper.is_domain_allowed(email) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiResponse {
                    ok: false,
                    data: None,
                    error: Some("email domain not allowed".into()),
                }),
            ));
        }
    }

    // Resolve role
    let role = state.role_mapper.resolve_role(&user_info);

    // Create session
    let session_id = SessionStore::generate_session_id();
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(tokens.expires_in as i64);

    let session = OidcSession {
        session_id: session_id.clone(),
        sub: user_info.sub,
        email: user_info.email.unwrap_or_default(),
        name: user_info.name.unwrap_or_default(),
        role,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };

    state.session_store.create(session);

    // Set HTTP-only cookie (Cookie requires 'static ownership)
    let cookie = Cookie::build((state.cookie_name.clone(), session_id))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .build();

    Ok((jar.add(cookie), Redirect::temporary("/")))
}

/// GET /api/v1/oidc/logout — Destroy session and clear cookie.
pub async fn oidc_logout(
    State(state): State<OidcState>,
    jar: CookieJar,
) -> (CookieJar, Json<ApiResponse<String>>) {
    if let Some(cookie) = jar.get(&state.cookie_name) {
        state.session_store.remove(cookie.value());
    }

    let removal = Cookie::from(state.cookie_name.clone());

    (
        jar.remove(removal),
        Json(ApiResponse {
            ok: true,
            data: Some("logged out".into()),
            error: None,
        }),
    )
}

/// Response for GET /api/v1/oidc/me.
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub role: Role,
}

/// GET /api/v1/oidc/me — Return current user info from session.
pub async fn oidc_me(
    State(state): State<OidcState>,
    jar: CookieJar,
) -> Result<Json<ApiResponse<MeResponse>>, (StatusCode, Json<ApiResponse<MeResponse>>)> {
    let session_id = jar
        .get(&state.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    ok: false,
                    data: None,
                    error: Some("not authenticated".into()),
                }),
            )
        })?;

    let session = state.session_store.get(&session_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse {
                ok: false,
                data: None,
                error: Some("session expired or invalid".into()),
            }),
        )
    })?;

    Ok(Json(ApiResponse {
        ok: true,
        data: Some(MeResponse {
            sub: session.sub,
            email: session.email,
            name: session.name,
            role: session.role,
        }),
        error: None,
    }))
}

/// OIDC session middleware: checks for valid session cookie.
/// Used to protect routes when OIDC auth mode is enabled.
pub async fn oidc_auth_middleware(
    State(state): State<OidcState>,
    jar: CookieJar,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let session_id = jar
        .get(&state.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    state
        .session_store
        .get(&session_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::super::client::{OidcError, OidcHttpClient};
    use super::super::config::*;
    use super::*;

    struct MockHttpClient;

    impl OidcHttpClient for MockHttpClient {
        fn fetch_discovery(&self, _issuer: &str) -> Result<OidcDiscovery, OidcError> {
            Ok(OidcDiscovery {
                issuer: "https://login.test.com".into(),
                authorization_endpoint: "https://login.test.com/authorize".into(),
                token_endpoint: "https://login.test.com/oauth/token".into(),
                userinfo_endpoint: "https://login.test.com/userinfo".into(),
                end_session_endpoint: None,
            })
        }

        fn exchange_code(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<TokenResponse, OidcError> {
            Ok(TokenResponse {
                access_token: "at-mock".into(),
                id_token: Some("idt-mock".into()),
                refresh_token: Some("rt-mock".into()),
                token_type: "Bearer".into(),
                expires_in: 3600,
            })
        }

        fn fetch_userinfo(&self, _: &str, _: &str) -> Result<UserInfo, OidcError> {
            Ok(UserInfo {
                sub: "user-1".into(),
                email: Some("alice@acme.com".into()),
                name: Some("Alice".into()),
                groups: vec!["security-team@acme.com".into()],
            })
        }

        fn refresh_token(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<TokenResponse, OidcError> {
            Ok(TokenResponse {
                access_token: "at-refreshed".into(),
                id_token: None,
                refresh_token: Some("rt-refreshed".into()),
                token_type: "Bearer".into(),
                expires_in: 3600,
            })
        }
    }

    fn test_oidc_state() -> OidcState {
        let config = OidcConfig {
            issuer: "https://login.test.com".into(),
            client_id: "test-client".into(),
            client_secret_env: "TEST_SECRET".into(),
            allowed_domains: vec!["acme.com".into()],
            role_mapping: HashMap::from([
                ("admin".into(), vec!["security-team@acme.com".into()]),
                ("approver".into(), vec!["engineering@acme.com".into()]),
            ]),
            redirect_uri: "http://localhost:9091/api/v1/oidc/callback".into(),
            cookie_name: "permit0_session".into(),
            session_ttl_secs: 3600,
        };

        let client = OidcClient::new_with_secret(
            config.clone(),
            Box::new(MockHttpClient),
            "test-secret".into(),
        );

        let role_mapper =
            RoleMapper::new(config.role_mapping.clone(), config.allowed_domains.clone());

        OidcState {
            client: std::sync::Arc::new(client),
            role_mapper: std::sync::Arc::new(role_mapper),
            session_store: std::sync::Arc::new(SessionStore::new(config.session_ttl_secs)),
            cookie_name: config.cookie_name.clone(),
            pending_flows: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    use super::super::client::OidcClient;

    #[test]
    fn pending_flow_stored_and_retrieved() {
        let state = test_oidc_state();
        state.pending_flows.lock().unwrap().insert(
            "nonce-1".into(),
            PendingOidcFlow {
                pkce_verifier: "verifier-1".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
        );

        let flow = state
            .pending_flows
            .lock()
            .unwrap()
            .remove("nonce-1")
            .unwrap();
        assert_eq!(flow.pkce_verifier, "verifier-1");
    }

    #[test]
    fn session_created_from_oidc_flow() {
        let state = test_oidc_state();
        let session_id = SessionStore::generate_session_id();
        let session = OidcSession {
            session_id: session_id.clone(),
            sub: "user-1".into(),
            email: "alice@acme.com".into(),
            name: "Alice".into(),
            role: Role::Admin,
            access_token: "at-123".into(),
            refresh_token: Some("rt-123".into()),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        };
        state.session_store.create(session);

        let retrieved = state.session_store.get(&session_id).unwrap();
        assert_eq!(retrieved.email, "alice@acme.com");
        assert_eq!(retrieved.role, Role::Admin);
    }

    #[test]
    fn logout_removes_session() {
        let state = test_oidc_state();
        let session_id = SessionStore::generate_session_id();
        let session = OidcSession {
            session_id: session_id.clone(),
            sub: "user-1".into(),
            email: "alice@acme.com".into(),
            name: "Alice".into(),
            role: Role::Admin,
            access_token: "at-123".into(),
            refresh_token: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        };
        state.session_store.create(session);
        assert!(state.session_store.remove(&session_id));
        assert!(state.session_store.get(&session_id).is_none());
    }
}
