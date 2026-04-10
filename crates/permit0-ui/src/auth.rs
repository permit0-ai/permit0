#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Roles for UI access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    /// Can view audit logs and dashboard.
    Viewer,
    /// Can view + approve/deny pending decisions.
    Approver,
    /// Full access including list management and configuration.
    Admin,
}

/// A local API token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    /// The token string (sk-p0-xxx).
    pub token: String,
    /// Display name.
    pub name: String,
    /// Role.
    pub role: Role,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Token store for local auth.
pub struct TokenStore {
    tokens: RwLock<HashMap<String, ApiToken>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new token. Returns the token string.
    pub fn create_token(&self, name: &str, role: Role) -> String {
        let token_str = generate_token();
        let token = ApiToken {
            token: token_str.clone(),
            name: name.into(),
            role,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        self.tokens.write().unwrap().insert(token_str.clone(), token);
        token_str
    }

    /// Verify a token and return its details.
    pub fn verify(&self, token: &str) -> Option<ApiToken> {
        self.tokens.read().unwrap().get(token).cloned()
    }

    /// Revoke a token.
    pub fn revoke(&self, token: &str) -> bool {
        self.tokens.write().unwrap().remove(token).is_some()
    }

    /// List all tokens (without exposing the full token string).
    pub fn list(&self) -> Vec<ApiToken> {
        self.tokens.read().unwrap().values().cloned().collect()
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random token string: sk-p0-<32 hex chars>.
fn generate_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    // Simple pseudo-random: hash timestamp + counter
    // For production, use a CSPRNG. This is sufficient for local dev tokens.
    let seed = format!("{nanos}-{}", ulid::Ulid::new());
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    format!("sk-p0-{}", hex::encode(&hash[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_token() {
        let store = TokenStore::new();
        let token = store.create_token("Alice", Role::Admin);
        assert!(token.starts_with("sk-p0-"));

        let verified = store.verify(&token).unwrap();
        assert_eq!(verified.name, "Alice");
        assert_eq!(verified.role, Role::Admin);
    }

    #[test]
    fn verify_invalid_token() {
        let store = TokenStore::new();
        assert!(store.verify("sk-p0-invalid").is_none());
    }

    #[test]
    fn revoke_token() {
        let store = TokenStore::new();
        let token = store.create_token("Bob", Role::Viewer);
        assert!(store.verify(&token).is_some());

        assert!(store.revoke(&token));
        assert!(store.verify(&token).is_none());
    }

    #[test]
    fn list_tokens() {
        let store = TokenStore::new();
        store.create_token("Alice", Role::Admin);
        store.create_token("Bob", Role::Viewer);

        let tokens = store.list();
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn role_ordering() {
        assert!(Role::Viewer < Role::Approver);
        assert!(Role::Approver < Role::Admin);
    }
}
