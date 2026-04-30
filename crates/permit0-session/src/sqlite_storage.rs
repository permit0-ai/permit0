#![forbid(unsafe_code)]

//! SQLite-backed session storage for cross-invocation persistence.
//!
//! Each hook invocation opens the same database file, enabling
//! session-level pattern detection (velocity, attack chains) across
//! separate OS processes.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};

use crate::context::SessionContext;
use crate::types::ActionRecord;
use permit0_types::Tier;

/// SQLite-backed session storage. WAL mode for concurrent readers.
///
/// Mirrors the `InMemorySessionStore` interface but persists to disk.
pub struct SqliteSessionStore {
    conn: Mutex<Connection>,
}

impl SqliteSessionStore {
    /// Open (or create) a session database at the given path.
    ///
    /// Auto-creates the schema on first use. Uses WAL journal mode
    /// for safe concurrent access from hook + MCP server processes.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS session_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                tier TEXT NOT NULL,
                flags TEXT NOT NULL,
                timestamp REAL NOT NULL,
                entities TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_session_records_session_id
                ON session_records(session_id);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE session_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                tier TEXT NOT NULL,
                flags TEXT NOT NULL,
                timestamp REAL NOT NULL,
                entities TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX idx_session_records_session_id
                ON session_records(session_id);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record an action in a session.
    pub fn record_action(&self, session_id: &str, record: &ActionRecord) {
        let conn = self.conn.lock().unwrap();
        let flags_json = serde_json::to_string(&record.flags).unwrap_or_default();
        let entities_json = serde_json::to_string(&record.entities).unwrap_or_else(|_| "{}".into());
        let tier_str = record.tier.to_string();

        let _ = conn.execute(
            "INSERT INTO session_records (session_id, action_type, tier, flags, timestamp, entities)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session_id,
                record.action_type,
                tier_str,
                flags_json,
                record.timestamp,
                entities_json,
            ],
        );
    }

    /// Get a snapshot of a session's context.
    pub fn get_session(&self, session_id: &str) -> Option<SessionContext> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT action_type, tier, flags, timestamp, entities
                 FROM session_records
                 WHERE session_id = ?1
                 ORDER BY timestamp ASC",
            )
            .ok()?;

        let records: Vec<ActionRecord> = stmt
            .query_map(params![session_id], |row| {
                let action_type: String = row.get(0)?;
                let tier_str: String = row.get(1)?;
                let flags_json: String = row.get(2)?;
                let timestamp: f64 = row.get(3)?;
                let entities_json: String = row.get(4)?;

                let tier = parse_tier(&tier_str);
                let flags: Vec<String> = serde_json::from_str(&flags_json).unwrap_or_default();
                let entities: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(&entities_json).unwrap_or_default();

                Ok(ActionRecord {
                    action_type,
                    tier,
                    flags,
                    timestamp,
                    entities,
                })
            })
            .ok()?
            .filter_map(|r| r.ok())
            .collect();

        if records.is_empty() {
            return None;
        }

        let mut ctx = SessionContext::new(session_id);
        for record in records {
            ctx.push(record);
        }
        Some(ctx)
    }

    /// Clear a session (e.g., on task completion).
    pub fn clear_session(&self, session_id: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "DELETE FROM session_records WHERE session_id = ?1",
            params![session_id],
        );
    }

    /// List all active session IDs.
    pub fn active_sessions(&self) -> Vec<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT DISTINCT session_id FROM session_records")
            .unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// Remove sessions older than `max_age_hours`.
    pub fn prune_old(&self, max_age_hours: u64) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "DELETE FROM session_records
             WHERE created_at < datetime('now', ?1)",
            params![format!("-{max_age_hours} hours")],
        );
    }
}

fn parse_tier(s: &str) -> Tier {
    match s.to_lowercase().as_str() {
        "minimal" => Tier::Minimal,
        "low" => Tier::Low,
        "medium" => Tier::Medium,
        "high" => Tier::High,
        "critical" => Tier::Critical,
        _ => Tier::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    fn make_record(action_type: &str, tier: Tier) -> ActionRecord {
        ActionRecord {
            action_type: action_type.into(),
            tier,
            flags: vec!["EXECUTION".into()],
            timestamp: 1_700_000_000.0,
            entities: Map::new(),
        }
    }

    #[test]
    fn record_and_get() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        store.record_action("sess-1", &make_record("process.shell", Tier::Low));
        store.record_action("sess-1", &make_record("files.read", Tier::Minimal));

        let ctx = store.get_session("sess-1").unwrap();
        assert_eq!(ctx.records.len(), 2);
        assert_eq!(ctx.session_id, "sess-1");
        assert_eq!(ctx.records[0].action_type, "process.shell");
        assert_eq!(ctx.records[1].action_type, "files.read");
    }

    #[test]
    fn get_missing_returns_none() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        assert!(store.get_session("nonexistent").is_none());
    }

    #[test]
    fn clear_session() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        store.record_action("sess-1", &make_record("a", Tier::Low));
        store.clear_session("sess-1");
        assert!(store.get_session("sess-1").is_none());
    }

    #[test]
    fn active_sessions() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        store.record_action("sess-1", &make_record("a", Tier::Low));
        store.record_action("sess-2", &make_record("b", Tier::Low));

        let mut sessions = store.active_sessions();
        sessions.sort();
        assert_eq!(sessions, vec!["sess-1", "sess-2"]);
    }

    #[test]
    fn tier_roundtrip() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        store.record_action("sess-1", &make_record("a", Tier::Critical));

        let ctx = store.get_session("sess-1").unwrap();
        assert_eq!(ctx.records[0].tier, Tier::Critical);
    }

    #[test]
    fn flags_roundtrip() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        let mut record = make_record("a", Tier::Low);
        record.flags = vec!["FINANCIAL".into(), "OUTBOUND".into()];
        store.record_action("sess-1", &record);

        let ctx = store.get_session("sess-1").unwrap();
        assert_eq!(ctx.records[0].flags, vec!["FINANCIAL", "OUTBOUND"]);
    }

    #[test]
    fn entities_roundtrip() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        let mut record = make_record("a", Tier::Low);
        record
            .entities
            .insert("amount".into(), serde_json::json!(5000));
        store.record_action("sess-1", &record);

        let ctx = store.get_session("sess-1").unwrap();
        assert_eq!(ctx.records[0].entities["amount"], serde_json::json!(5000));
    }

    #[test]
    fn multiple_sessions_isolated() {
        let store = SqliteSessionStore::open_in_memory().unwrap();
        store.record_action("sess-1", &make_record("a", Tier::Low));
        store.record_action("sess-2", &make_record("b", Tier::High));

        let ctx1 = store.get_session("sess-1").unwrap();
        let ctx2 = store.get_session("sess-2").unwrap();
        assert_eq!(ctx1.records.len(), 1);
        assert_eq!(ctx2.records.len(), 1);
        assert_eq!(ctx1.records[0].action_type, "a");
        assert_eq!(ctx2.records[0].action_type, "b");
    }
}
