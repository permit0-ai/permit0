#![forbid(unsafe_code)]

use std::sync::RwLock;

use base64::Engine;
use sha2::Digest;

use super::config::{OidcConfig, OidcDiscovery, TokenResponse, UserInfo};

/// Errors from the OIDC client.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("discovery failed: {0}")]
    DiscoveryFailed(String),
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),
    #[error("userinfo failed: {0}")]
    UserInfoFailed(String),
    #[error("not configured")]
    NotConfigured,
}

/// HTTP client abstraction for OIDC operations.
/// Allows mocking in tests without requiring a real OIDC provider.
pub trait OidcHttpClient: Send + Sync {
    /// Fetch the OIDC discovery document.
    fn fetch_discovery(&self, issuer: &str) -> Result<OidcDiscovery, OidcError>;
    /// Exchange authorization code for tokens.
    fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, OidcError>;
    /// Fetch user info using an access token.
    fn fetch_userinfo(
        &self,
        userinfo_endpoint: &str,
        access_token: &str,
    ) -> Result<UserInfo, OidcError>;
    /// Refresh an access token.
    fn refresh_token(
        &self,
        token_endpoint: &str,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, OidcError>;
}

/// PKCE challenge pair.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The verifier (random string, stored server-side).
    pub verifier: String,
    /// The challenge (SHA-256 hash of verifier, sent to provider).
    pub challenge: String,
}

/// Generate a PKCE code verifier and challenge (S256).
pub fn generate_pkce() -> PkceChallenge {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut verifier_bytes = [0u8; 32];
    rng.fill(&mut verifier_bytes);

    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = sha2::Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

    PkceChallenge {
        verifier,
        challenge,
    }
}

/// OIDC client that manages discovery, auth URLs, and token exchange.
pub struct OidcClient {
    config: OidcConfig,
    http_client: Box<dyn OidcHttpClient>,
    discovery: RwLock<Option<OidcDiscovery>>,
    client_secret: String,
}

impl OidcClient {
    /// Create a new OIDC client.
    ///
    /// The client secret is resolved from the environment variable
    /// specified in `config.client_secret_env`.
    pub fn new(
        config: OidcConfig,
        http_client: Box<dyn OidcHttpClient>,
    ) -> Result<Self, OidcError> {
        let client_secret = std::env::var(&config.client_secret_env).unwrap_or_default();
        Ok(Self {
            config,
            http_client,
            discovery: RwLock::new(None),
            client_secret,
        })
    }

    /// Create with an explicit secret (for testing).
    pub fn new_with_secret(
        config: OidcConfig,
        http_client: Box<dyn OidcHttpClient>,
        client_secret: String,
    ) -> Self {
        Self {
            config,
            http_client,
            discovery: RwLock::new(None),
            client_secret,
        }
    }

    /// Ensure discovery document is loaded.
    pub fn ensure_discovery(&self) -> Result<OidcDiscovery, OidcError> {
        {
            let guard = self.discovery.read().unwrap();
            if let Some(ref disc) = *guard {
                return Ok(disc.clone());
            }
        }

        let disc = self.http_client.fetch_discovery(&self.config.issuer)?;
        {
            let mut guard = self.discovery.write().unwrap();
            *guard = Some(disc.clone());
        }
        Ok(disc)
    }

    /// Build the authorization URL with PKCE.
    ///
    /// Returns (auth_url, pkce_verifier, state_nonce).
    pub fn build_auth_url(&self) -> Result<(String, String, String), OidcError> {
        let disc = self.ensure_discovery()?;
        let pkce = generate_pkce();

        // Generate state nonce for CSRF protection
        let state = ulid::Ulid::new().to_string();

        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid+email+profile+groups&code_challenge={}&code_challenge_method=S256&state={}",
            disc.authorization_endpoint,
            urlencoded(&self.config.client_id),
            urlencoded(&self.config.redirect_uri),
            urlencoded(&pkce.challenge),
            urlencoded(&state),
        );

        Ok((url, pkce.verifier, state))
    }

    /// Exchange an authorization code for tokens.
    pub fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, OidcError> {
        let disc = self.ensure_discovery()?;
        self.http_client.exchange_code(
            &disc.token_endpoint,
            code,
            &self.config.redirect_uri,
            &self.config.client_id,
            &self.client_secret,
            code_verifier,
        )
    }

    /// Fetch user info using an access token.
    pub fn fetch_userinfo(&self, access_token: &str) -> Result<UserInfo, OidcError> {
        let disc = self.ensure_discovery()?;
        self.http_client
            .fetch_userinfo(&disc.userinfo_endpoint, access_token)
    }

    /// Refresh an access token.
    pub fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, OidcError> {
        let disc = self.ensure_discovery()?;
        self.http_client.refresh_token(
            &disc.token_endpoint,
            refresh_token,
            &self.config.client_id,
            &self.client_secret,
        )
    }

    /// Get the OIDC config.
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }
}

/// Minimal URL encoding for query parameters.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('+', "%2B")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('?', "%3F")
        .replace('#', "%23")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockHttpClient {
        discovery: OidcDiscovery,
        token_response: TokenResponse,
        userinfo: UserInfo,
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                discovery: OidcDiscovery {
                    issuer: "https://login.test.com".into(),
                    authorization_endpoint: "https://login.test.com/authorize".into(),
                    token_endpoint: "https://login.test.com/oauth/token".into(),
                    userinfo_endpoint: "https://login.test.com/userinfo".into(),
                    end_session_endpoint: None,
                },
                token_response: TokenResponse {
                    access_token: "at-123".into(),
                    id_token: Some("idt-123".into()),
                    refresh_token: Some("rt-123".into()),
                    token_type: "Bearer".into(),
                    expires_in: 3600,
                },
                userinfo: UserInfo {
                    sub: "user-1".into(),
                    email: Some("alice@acme.com".into()),
                    name: Some("Alice".into()),
                    groups: vec!["engineering@acme.com".into()],
                },
            }
        }
    }

    impl OidcHttpClient for MockHttpClient {
        fn fetch_discovery(&self, _issuer: &str) -> Result<OidcDiscovery, OidcError> {
            Ok(self.discovery.clone())
        }

        fn exchange_code(
            &self,
            _token_endpoint: &str,
            _code: &str,
            _redirect_uri: &str,
            _client_id: &str,
            _client_secret: &str,
            _code_verifier: &str,
        ) -> Result<TokenResponse, OidcError> {
            Ok(self.token_response.clone())
        }

        fn fetch_userinfo(
            &self,
            _userinfo_endpoint: &str,
            _access_token: &str,
        ) -> Result<UserInfo, OidcError> {
            Ok(self.userinfo.clone())
        }

        fn refresh_token(
            &self,
            _token_endpoint: &str,
            _refresh_token: &str,
            _client_id: &str,
            _client_secret: &str,
        ) -> Result<TokenResponse, OidcError> {
            Ok(self.token_response.clone())
        }
    }

    fn test_config() -> OidcConfig {
        OidcConfig {
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
        }
    }

    #[test]
    fn pkce_challenge_generation() {
        let pkce = generate_pkce();
        assert!(!pkce.verifier.is_empty());
        assert!(!pkce.challenge.is_empty());
        // Verifier and challenge should differ
        assert_ne!(pkce.verifier, pkce.challenge);
    }

    #[test]
    fn build_auth_url() {
        let client = OidcClient::new_with_secret(
            test_config(),
            Box::new(MockHttpClient::new()),
            "test-secret".into(),
        );
        let (url, verifier, state) = client.build_auth_url().unwrap();
        assert!(url.starts_with("https://login.test.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=test-client"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!verifier.is_empty());
        assert!(!state.is_empty());
    }

    #[test]
    fn exchange_code_flow() {
        let client = OidcClient::new_with_secret(
            test_config(),
            Box::new(MockHttpClient::new()),
            "test-secret".into(),
        );
        let tokens = client.exchange_code("auth-code", "verifier").unwrap();
        assert_eq!(tokens.access_token, "at-123");
        assert_eq!(tokens.refresh_token.as_deref(), Some("rt-123"));
    }

    #[test]
    fn fetch_userinfo() {
        let client = OidcClient::new_with_secret(
            test_config(),
            Box::new(MockHttpClient::new()),
            "test-secret".into(),
        );
        let info = client.fetch_userinfo("at-123").unwrap();
        assert_eq!(info.email.as_deref(), Some("alice@acme.com"));
        assert_eq!(info.groups, vec!["engineering@acme.com"]);
    }

    #[test]
    fn refresh_token_flow() {
        let client = OidcClient::new_with_secret(
            test_config(),
            Box::new(MockHttpClient::new()),
            "test-secret".into(),
        );
        let tokens = client.refresh_token("rt-123").unwrap();
        assert_eq!(tokens.access_token, "at-123");
    }

    #[test]
    fn discovery_cached() {
        let client = OidcClient::new_with_secret(
            test_config(),
            Box::new(MockHttpClient::new()),
            "test-secret".into(),
        );
        // First call fetches
        let d1 = client.ensure_discovery().unwrap();
        // Second call uses cache
        let d2 = client.ensure_discovery().unwrap();
        assert_eq!(d1.issuer, d2.issuer);
    }
}
