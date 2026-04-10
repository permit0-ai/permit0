#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use crate::context::SessionContext;
use crate::types::ActionRecord;

/// In-memory session storage for development and single-node deployments.
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<String, SessionContext>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Record an action in a session. Creates the session if it doesn't exist.
    pub fn record_action(&self, session_id: &str, record: ActionRecord) {
        let mut sessions = self.sessions.write().unwrap();
        sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionContext::new(session_id))
            .push(record);
    }

    /// Get a snapshot of a session's context.
    pub fn get_session(&self, session_id: &str) -> Option<SessionContext> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).cloned()
    }

    /// Clear a session (e.g., on task completion).
    pub fn clear_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
    }

    /// List all active session IDs.
    pub fn active_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().unwrap();
        sessions.keys().cloned().collect()
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_types::Tier;

    fn make_record(action_type: &str) -> ActionRecord {
        ActionRecord {
            action_type: action_type.into(),
            tier: Tier::Low,
            flags: vec![],
            timestamp: 1_700_000_000.0,
            entities: serde_json::Map::new(),
        }
    }

    #[test]
    fn record_and_get() {
        let store = InMemorySessionStore::new();
        store.record_action("sess-1", make_record("payments.charge"));
        store.record_action("sess-1", make_record("email.send"));

        let ctx = store.get_session("sess-1").unwrap();
        assert_eq!(ctx.records.len(), 2);
        assert_eq!(ctx.session_id, "sess-1");
    }

    #[test]
    fn get_missing_returns_none() {
        let store = InMemorySessionStore::new();
        assert!(store.get_session("nonexistent").is_none());
    }

    #[test]
    fn clear_session() {
        let store = InMemorySessionStore::new();
        store.record_action("sess-1", make_record("a"));
        store.clear_session("sess-1");
        assert!(store.get_session("sess-1").is_none());
    }

    #[test]
    fn active_sessions() {
        let store = InMemorySessionStore::new();
        store.record_action("sess-1", make_record("a"));
        store.record_action("sess-2", make_record("b"));

        let mut sessions = store.active_sessions();
        sessions.sort();
        assert_eq!(sessions, vec!["sess-1", "sess-2"]);
    }
}
