#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// OIDC authentication configuration.
///
/// ```yaml
/// auth:
///   mode: oidc
///   issuer: https://login.acme.com
///   client_id: permit0-ui
///   client_secret_env: PERMIT0_OIDC_SECRET
///   allowed_domains: ["acme.com"]
///   role_mapping:
///     admin: ["security-team@acme.com"]
///     approver: ["engineering@acme.com"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g. `https://login.acme.com`).
    pub issuer: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// Environment variable name containing the client secret.
    pub client_secret_env: String,
    /// Allowed email domains (empty = allow all authenticated users).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Map of role name → list of groups/emails that map to that role.
    #[serde(default)]
    pub role_mapping: HashMap<String, Vec<String>>,
    /// Redirect URI for the callback (e.g. `http://localhost:9091/api/v1/oidc/callback`).
    #[serde(default = "default_redirect_uri")]
    pub redirect_uri: String,
    /// Session cookie name.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Session TTL in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
}

fn default_redirect_uri() -> String {
    "http://localhost:9091/api/v1/oidc/callback".into()
}

fn default_cookie_name() -> String {
    "permit0_session".into()
}

fn default_session_ttl() -> u64 {
    3600
}

/// OIDC discovery document (subset of fields we need).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// Token response from the OIDC provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
}

/// Userinfo response (subset — providers vary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_oidc_config() {
        let yaml = r#"
issuer: https://login.acme.com
client_id: permit0-ui
client_secret_env: PERMIT0_OIDC_SECRET
allowed_domains: ["acme.com"]
role_mapping:
  admin: ["security-team@acme.com"]
  approver: ["engineering@acme.com"]
"#;
        let config: OidcConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.issuer, "https://login.acme.com");
        assert_eq!(config.client_id, "permit0-ui");
        assert_eq!(config.allowed_domains, vec!["acme.com"]);
        assert_eq!(
            config.role_mapping.get("admin").unwrap(),
            &vec!["security-team@acme.com"]
        );
        // Defaults
        assert_eq!(config.session_ttl_secs, 3600);
        assert_eq!(config.cookie_name, "permit0_session");
    }

    #[test]
    fn deserialize_discovery() {
        let json = r#"{
            "issuer": "https://login.acme.com",
            "authorization_endpoint": "https://login.acme.com/authorize",
            "token_endpoint": "https://login.acme.com/oauth/token",
            "userinfo_endpoint": "https://login.acme.com/userinfo"
        }"#;
        let disc: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(
            disc.authorization_endpoint,
            "https://login.acme.com/authorize"
        );
        assert!(disc.end_session_endpoint.is_none());
    }

    #[test]
    fn deserialize_userinfo_with_groups() {
        let json = r#"{
            "sub": "user123",
            "email": "alice@acme.com",
            "name": "Alice",
            "groups": ["engineering@acme.com", "security-team@acme.com"]
        }"#;
        let info: UserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.sub, "user123");
        assert_eq!(info.email.as_deref(), Some("alice@acme.com"));
        assert_eq!(info.groups.len(), 2);
    }
}
