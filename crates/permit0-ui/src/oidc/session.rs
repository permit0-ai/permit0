#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::auth::Role;

/// An OIDC-authenticated session.
#[derive(Debug, Clone)]
pub struct OidcSession {
    /// Session ID (random, stored in HTTP-only cookie).
    pub session_id: String,
    /// OIDC subject identifier.
    pub sub: String,
    /// User email.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Resolved role.
    pub role: Role,
    /// OIDC access token (for userinfo refresh).
    pub access_token: String,
    /// Refresh token (for token rotation).
    pub refresh_token: Option<String>,
    /// ISO 8601 timestamp of session creation.
    pub created_at: String,
    /// ISO 8601 timestamp when the access token expires.
    pub expires_at: String,
}

/// In-memory session store.
///
/// In production, this should be backed by Redis or a database.
/// For the local-first use case, in-memory is sufficient.
pub struct SessionStore {
    sessions: RwLock<HashMap<String, OidcSession>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Create a new session and return its ID.
    pub fn create(&self, session: OidcSession) -> String {
        let session_id = session.session_id.clone();
        self.sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), session);
        session_id
    }

    /// Look up a session by ID.
    pub fn get(&self, session_id: &str) -> Option<OidcSession> {
        let guard = self.sessions.read().unwrap();
        let session = guard.get(session_id)?;

        // Check expiry
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&session.created_at) {
            let now = chrono::Utc::now();
            let elapsed = now.signed_duration_since(created).num_seconds();
            if elapsed > self.ttl.as_secs() as i64 {
                return None;
            }
        }

        Some(session.clone())
    }

    /// Remove a session (logout).
    pub fn remove(&self, session_id: &str) -> bool {
        self.sessions.write().unwrap().remove(session_id).is_some()
    }

    /// Update session tokens after refresh.
    pub fn update_tokens(
        &self,
        session_id: &str,
        access_token: String,
        refresh_token: Option<String>,
        expires_at: String,
    ) -> bool {
        let mut guard = self.sessions.write().unwrap();
        if let Some(session) = guard.get_mut(session_id) {
            session.access_token = access_token;
            if let Some(rt) = refresh_token {
                session.refresh_token = Some(rt);
            }
            session.expires_at = expires_at;
            true
        } else {
            false
        }
    }

    /// Remove expired sessions.
    pub fn cleanup_expired(&self) {
        let now = chrono::Utc::now();
        let ttl_secs = self.ttl.as_secs() as i64;

        let mut guard = self.sessions.write().unwrap();
        guard.retain(|_, session| {
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&session.created_at) {
                now.signed_duration_since(created).num_seconds() < ttl_secs
            } else {
                false
            }
        });
    }

    /// Generate a random session ID.
    pub fn generate_session_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        hex::encode(bytes)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(session_id: &str) -> OidcSession {
        OidcSession {
            session_id: session_id.into(),
            sub: "user-1".into(),
            email: "alice@acme.com".into(),
            name: "Alice".into(),
            role: Role::Admin,
            access_token: "at-123".into(),
            refresh_token: Some("rt-123".into()),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        }
    }

    #[test]
    fn create_and_get_session() {
        let store = SessionStore::new(3600);
        let session = make_session("sess-1");
        store.create(session);

        let retrieved = store.get("sess-1").unwrap();
        assert_eq!(retrieved.email, "alice@acme.com");
        assert_eq!(retrieved.role, Role::Admin);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = SessionStore::new(3600);
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn remove_session() {
        let store = SessionStore::new(3600);
        store.create(make_session("sess-1"));
        assert!(store.remove("sess-1"));
        assert!(store.get("sess-1").is_none());
    }

    #[test]
    fn expired_session_returns_none() {
        let store = SessionStore::new(1); // 1 second TTL
        let mut session = make_session("sess-1");
        // Set created_at to 10 seconds ago
        session.created_at = (chrono::Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        store.create(session);
        assert!(store.get("sess-1").is_none());
    }

    #[test]
    fn update_tokens() {
        let store = SessionStore::new(3600);
        store.create(make_session("sess-1"));

        let new_expires = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        assert!(store.update_tokens(
            "sess-1",
            "at-new".into(),
            Some("rt-new".into()),
            new_expires,
        ));

        let session = store.get("sess-1").unwrap();
        assert_eq!(session.access_token, "at-new");
        assert_eq!(session.refresh_token.as_deref(), Some("rt-new"));
    }

    #[test]
    fn cleanup_expired() {
        let store = SessionStore::new(1);
        let mut old = make_session("old");
        old.created_at = (chrono::Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        store.create(old);
        store.create(make_session("fresh"));

        store.cleanup_expired();
        assert!(store.get("old").is_none());
        assert!(store.get("fresh").is_some());
    }

    #[test]
    fn generate_session_id_is_unique() {
        let id1 = SessionStore::generate_session_id();
        let id2 = SessionStore::generate_session_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 64); // 32 bytes hex encoded
    }
}
