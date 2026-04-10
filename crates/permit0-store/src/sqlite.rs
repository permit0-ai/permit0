#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};

use permit0_types::{DecisionFilter, DecisionRecord, NormHash, Permission, Tier};

use crate::traits::{Store, StoreError};

/// SQLite-backed persistent store. WAL mode for concurrent reads.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at `path` with WAL mode and schema migration.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(|e| StoreError::Io(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite store (useful for testing persistence logic).
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(|e| StoreError::Io(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;

        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| StoreError::Io(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS denylist (
                norm_hash BLOB PRIMARY KEY,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS allowlist (
                norm_hash BLOB PRIMARY KEY,
                justification TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_cache (
                norm_hash BLOB PRIMARY KEY,
                permission TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                norm_hash BLOB NOT NULL,
                action_type TEXT NOT NULL,
                channel TEXT NOT NULL,
                permission TEXT NOT NULL,
                source TEXT NOT NULL,
                tier TEXT,
                risk_raw REAL,
                blocked INTEGER NOT NULL DEFAULT 0,
                flags TEXT NOT NULL DEFAULT '[]',
                timestamp TEXT NOT NULL,
                surface_tool TEXT NOT NULL,
                surface_command TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_decisions_action_type ON decisions(action_type);
            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_decisions_permission ON decisions(permission);",
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;

        Ok(())
    }
}

fn hash_to_blob(hash: &NormHash) -> Vec<u8> {
    hash.to_vec()
}

fn blob_to_hash(blob: &[u8]) -> NormHash {
    let mut hash = [0u8; 32];
    let len = blob.len().min(32);
    hash[..len].copy_from_slice(&blob[..len]);
    hash
}

fn permission_to_str(p: Permission) -> &'static str {
    match p {
        Permission::Allow => "allow",
        Permission::HumanInTheLoop => "human",
        Permission::Deny => "deny",
    }
}

fn str_to_permission(s: &str) -> Permission {
    match s {
        "allow" => Permission::Allow,
        "human" => Permission::HumanInTheLoop,
        "deny" => Permission::Deny,
        _ => Permission::Deny,
    }
}

fn tier_to_str(t: Tier) -> &'static str {
    match t {
        Tier::Minimal => "minimal",
        Tier::Low => "low",
        Tier::Medium => "medium",
        Tier::High => "high",
        Tier::Critical => "critical",
    }
}

fn str_to_tier(s: &str) -> Tier {
    match s {
        "minimal" => Tier::Minimal,
        "low" => Tier::Low,
        "medium" => Tier::Medium,
        "high" => Tier::High,
        "critical" => Tier::Critical,
        _ => Tier::Critical,
    }
}

impl Store for SqliteStore {
    fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT reason FROM denylist WHERE norm_hash = ?1")
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let result = stmt
            .query_row(params![hash_to_blob(hash)], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(result)
    }

    fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO denylist (norm_hash, reason) VALUES (?1, ?2)",
            params![hash_to_blob(&hash), reason],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn denylist_remove(&self, hash: &NormHash) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute(
            "DELETE FROM denylist WHERE norm_hash = ?1",
            params![hash_to_blob(hash)],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM allowlist WHERE norm_hash = ?1")
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let exists = stmt
            .query_row(params![hash_to_blob(hash)], |_| Ok(()))
            .optional()
            .map_err(|e| StoreError::Io(e.to_string()))?
            .is_some();
        Ok(exists)
    }

    fn allowlist_add(&self, hash: NormHash, justification: String) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO allowlist (norm_hash, justification) VALUES (?1, ?2)",
            params![hash_to_blob(&hash), justification],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute(
            "DELETE FROM allowlist WHERE norm_hash = ?1",
            params![hash_to_blob(hash)],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT permission FROM policy_cache WHERE norm_hash = ?1")
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let result = stmt
            .query_row(params![hash_to_blob(hash)], |row| {
                let s: String = row.get(0)?;
                Ok(str_to_permission(&s))
            })
            .optional()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(result)
    }

    fn policy_cache_set(&self, hash: NormHash, decision: Permission) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO policy_cache (norm_hash, permission) VALUES (?1, ?2)",
            params![hash_to_blob(&hash), permission_to_str(decision)],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn policy_cache_clear(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute("DELETE FROM policy_cache", [])
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        conn.execute(
            "DELETE FROM policy_cache WHERE norm_hash = ?1",
            params![hash_to_blob(hash)],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn save_decision(&self, record: DecisionRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;
        let tier_str = record.tier.map(tier_to_str);
        let flags_json =
            serde_json::to_string(&record.flags).map_err(|e| StoreError::Io(e.to_string()))?;

        conn.execute(
            "INSERT INTO decisions (id, norm_hash, action_type, channel, permission, source, tier, risk_raw, blocked, flags, timestamp, surface_tool, surface_command)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.id,
                hash_to_blob(&record.norm_hash),
                record.action_type,
                record.channel,
                permission_to_str(record.permission),
                record.source,
                tier_str,
                record.risk_raw,
                record.blocked as i32,
                flags_json,
                record.timestamp,
                record.surface_tool,
                record.surface_command,
            ],
        )
        .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn query_decisions(&self, filter: &DecisionFilter) -> Result<Vec<DecisionRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError::Io(e.to_string()))?;

        let mut sql = String::from(
            "SELECT id, norm_hash, action_type, channel, permission, source, tier, risk_raw, blocked, flags, timestamp, surface_tool, surface_command FROM decisions WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref at) = filter.action_type {
            sql.push_str(&format!(" AND action_type LIKE ?{idx}"));
            param_values.push(Box::new(format!("{at}%")));
            idx += 1;
        }
        if let Some(ref perm) = filter.permission {
            sql.push_str(&format!(" AND permission = ?{idx}"));
            param_values.push(Box::new(permission_to_str(*perm).to_string()));
            idx += 1;
        }
        if let Some(ref ch) = filter.channel {
            sql.push_str(&format!(" AND channel = ?{idx}"));
            param_values.push(Box::new(ch.clone()));
            idx += 1;
        }
        if let Some(ref since) = filter.since {
            sql.push_str(&format!(" AND timestamp >= ?{idx}"));
            param_values.push(Box::new(since.clone()));
            idx += 1;
        }

        let limit = filter.limit.unwrap_or(100);
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{idx}"));
        param_values.push(Box::new(limit));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql).map_err(|e| StoreError::Io(e.to_string()))?;
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let norm_hash_blob: Vec<u8> = row.get(1)?;
                let permission_str: String = row.get(4)?;
                let tier_str: Option<String> = row.get(6)?;
                let blocked_int: i32 = row.get(8)?;
                let flags_json: String = row.get(9)?;

                Ok(DecisionRecord {
                    id: row.get(0)?,
                    norm_hash: blob_to_hash(&norm_hash_blob),
                    action_type: row.get(2)?,
                    channel: row.get(3)?,
                    permission: str_to_permission(&permission_str),
                    source: row.get(5)?,
                    tier: tier_str.map(|s| str_to_tier(&s)),
                    risk_raw: row.get(7)?,
                    blocked: blocked_int != 0,
                    flags: serde_json::from_str(&flags_json).unwrap_or_default(),
                    timestamp: row.get(10)?,
                    surface_tool: row.get(11)?,
                    surface_command: row.get(12)?,
                })
            })
            .map_err(|e| StoreError::Io(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| StoreError::Io(e.to_string()))?);
        }
        Ok(results)
    }
}

/// Extension trait for `rusqlite::OptionalExtension`.
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash() -> NormHash {
        [0u8; 32]
    }

    fn other_hash() -> NormHash {
        let mut h = [0u8; 32];
        h[0] = 1;
        h
    }

    fn test_decision(action_type: &str, permission: Permission, channel: &str, ts: &str) -> DecisionRecord {
        DecisionRecord {
            id: format!("test-{ts}-{action_type}"),
            norm_hash: dummy_hash(),
            action_type: action_type.into(),
            channel: channel.into(),
            permission,
            source: "scorer".into(),
            tier: Some(Tier::Low),
            risk_raw: Some(0.25),
            blocked: false,
            flags: vec!["test_flag".into()],
            timestamp: ts.into(),
            surface_tool: "test".into(),
            surface_command: "test cmd".into(),
        }
    }

    #[test]
    fn sqlite_denylist_crud() {
        let store = SqliteStore::in_memory().unwrap();
        assert!(store.denylist_check(&dummy_hash()).unwrap().is_none());

        store.denylist_add(dummy_hash(), "bad".into()).unwrap();
        assert_eq!(store.denylist_check(&dummy_hash()).unwrap(), Some("bad".into()));

        store.denylist_remove(&dummy_hash()).unwrap();
        assert!(store.denylist_check(&dummy_hash()).unwrap().is_none());
    }

    #[test]
    fn sqlite_allowlist_crud() {
        let store = SqliteStore::in_memory().unwrap();
        assert!(!store.allowlist_check(&dummy_hash()).unwrap());

        store.allowlist_add(dummy_hash(), "safe".into()).unwrap();
        assert!(store.allowlist_check(&dummy_hash()).unwrap());

        store.allowlist_remove(&dummy_hash()).unwrap();
        assert!(!store.allowlist_check(&dummy_hash()).unwrap());
    }

    #[test]
    fn sqlite_policy_cache_crud() {
        let store = SqliteStore::in_memory().unwrap();
        assert!(store.policy_cache_get(&dummy_hash()).unwrap().is_none());

        store.policy_cache_set(dummy_hash(), Permission::Allow).unwrap();
        assert_eq!(store.policy_cache_get(&dummy_hash()).unwrap(), Some(Permission::Allow));

        store.policy_cache_invalidate(&dummy_hash()).unwrap();
        assert!(store.policy_cache_get(&dummy_hash()).unwrap().is_none());
    }

    #[test]
    fn sqlite_policy_cache_clear() {
        let store = SqliteStore::in_memory().unwrap();
        store.policy_cache_set(dummy_hash(), Permission::Allow).unwrap();
        store.policy_cache_set(other_hash(), Permission::Deny).unwrap();

        store.policy_cache_clear().unwrap();
        assert!(store.policy_cache_get(&dummy_hash()).unwrap().is_none());
        assert!(store.policy_cache_get(&other_hash()).unwrap().is_none());
    }

    #[test]
    fn sqlite_decision_save_and_query() {
        let store = SqliteStore::in_memory().unwrap();
        store
            .save_decision(test_decision("payments.charge", Permission::Allow, "stripe", "2025-01-01T00:00:00Z"))
            .unwrap();
        store
            .save_decision(test_decision("email.send", Permission::Deny, "gmail", "2025-01-02T00:00:00Z"))
            .unwrap();

        let all = store.query_decisions(&DecisionFilter::default()).unwrap();
        assert_eq!(all.len(), 2);
        // Newest first (ORDER BY timestamp DESC)
        assert_eq!(all[0].action_type, "email.send");
        assert_eq!(all[1].action_type, "payments.charge");
        // Verify tier round-trip
        assert_eq!(all[0].tier, Some(Tier::Low));
        assert_eq!(all[0].flags, vec!["test_flag".to_string()]);
    }

    #[test]
    fn sqlite_decision_query_filters() {
        let store = SqliteStore::in_memory().unwrap();
        store
            .save_decision(test_decision("payments.charge", Permission::Allow, "stripe", "2025-01-01T00:00:00Z"))
            .unwrap();
        store
            .save_decision(test_decision("payments.refund", Permission::Deny, "stripe", "2025-01-02T00:00:00Z"))
            .unwrap();
        store
            .save_decision(test_decision("email.send", Permission::Allow, "gmail", "2025-01-03T00:00:00Z"))
            .unwrap();

        // Action type prefix
        let payments = store
            .query_decisions(&DecisionFilter {
                action_type: Some("payments".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(payments.len(), 2);

        // Permission
        let denies = store
            .query_decisions(&DecisionFilter {
                permission: Some(Permission::Deny),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].action_type, "payments.refund");

        // Channel
        let gmail = store
            .query_decisions(&DecisionFilter {
                channel: Some("gmail".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(gmail.len(), 1);

        // Since filter
        let recent = store
            .query_decisions(&DecisionFilter {
                since: Some("2025-01-02T00:00:00Z".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(recent.len(), 2);

        // Limit
        let limited = store
            .query_decisions(&DecisionFilter {
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn sqlite_restart_survival() {
        let dir = std::env::temp_dir().join("permit0_test_restart");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");

        // First session: populate
        {
            let store = SqliteStore::open(&db_path).unwrap();
            store.denylist_add(dummy_hash(), "blocked".into()).unwrap();
            store.allowlist_add(other_hash(), "approved".into()).unwrap();
            store.policy_cache_set(dummy_hash(), Permission::Deny).unwrap();
            store
                .save_decision(test_decision("payments.charge", Permission::Allow, "stripe", "2025-01-01T00:00:00Z"))
                .unwrap();
        }

        // Second session: verify data survives
        {
            let store = SqliteStore::open(&db_path).unwrap();
            assert_eq!(store.denylist_check(&dummy_hash()).unwrap(), Some("blocked".into()));
            assert!(store.allowlist_check(&other_hash()).unwrap());
            assert_eq!(store.policy_cache_get(&dummy_hash()).unwrap(), Some(Permission::Deny));
            let decisions = store.query_decisions(&DecisionFilter::default()).unwrap();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].action_type, "payments.charge");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
