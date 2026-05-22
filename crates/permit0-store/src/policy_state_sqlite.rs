#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};

use permit0_types::{NormHash, Permission, RiskScore};

use crate::now_epoch;
use crate::policy_state::{
    CachedDecision, HumanDecisionRow, PendingApprovalRow, PolicyState, StateError,
};

/// SQLite-backed `PolicyState`. WAL mode for concurrent reads.
///
/// Schema covers denylist, allowlist, policy_cache, and the durable HITL
/// queue (`pending_approvals` + `resolved_approvals`). The decision log
/// is *not* here — that lives in [`crate::SqliteAuditSink`].
pub struct SqlitePolicyState {
    conn: Mutex<Connection>,
}

impl SqlitePolicyState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let conn = Connection::open(path).map_err(|e| StateError::Io(e.to_string()))?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
        Ok(s)
    }

    pub fn in_memory() -> Result<Self, StateError> {
        let conn = Connection::open_in_memory().map_err(|e| StateError::Io(e.to_string()))?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
        Ok(s)
    }

    fn init_schema(&self) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| StateError::Io(e.to_string()))?;
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
                permission TEXT NOT NULL,
                risk_score_json TEXT,
                created_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_approvals (
                approval_id TEXT PRIMARY KEY,
                norm_hash BLOB NOT NULL,
                action_type TEXT NOT NULL,
                channel TEXT NOT NULL,
                created_at TEXT NOT NULL,
                norm_action_json TEXT NOT NULL,
                risk_score_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS resolved_approvals (
                approval_id TEXT PRIMARY KEY,
                permission TEXT NOT NULL,
                reason TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                decided_at TEXT NOT NULL
            );",
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        // Back-fill columns on databases created before the cache v2 schema.
        // A "duplicate column" error means the column already exists (fresh
        // DBs created with the new CREATE TABLE above) — that is expected and
        // ignored. Any other error is a real failure and must propagate.
        for stmt in [
            "ALTER TABLE policy_cache ADD COLUMN risk_score_json TEXT",
            "ALTER TABLE policy_cache ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        ] {
            match conn.execute_batch(stmt) {
                Ok(()) => {}
                Err(e) if e.to_string().contains("duplicate column name") => {}
                Err(e) => return Err(StateError::Io(e.to_string())),
            }
        }
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
        _ => Permission::Deny,
    }
}

trait OptExt<T> {
    fn opt(self) -> Result<Option<T>, rusqlite::Error>;
}
impl<T> OptExt<T> for Result<T, rusqlite::Error> {
    fn opt(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[async_trait::async_trait]
impl PolicyState for SqlitePolicyState {
    async fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT reason FROM denylist WHERE norm_hash = ?1")
            .map_err(|e| StateError::Io(e.to_string()))?;
        stmt.query_row(params![hash_to_blob(hash)], |row| row.get::<_, String>(0))
            .opt()
            .map_err(|e| StateError::Io(e.to_string()))
    }

    async fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO denylist (norm_hash, reason) VALUES (?1, ?2)",
            params![hash_to_blob(&hash), reason],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn denylist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "DELETE FROM denylist WHERE norm_hash = ?1",
            params![hash_to_blob(hash)],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn denylist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT norm_hash, reason FROM denylist")
            .map_err(|e| StateError::Io(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let reason: String = row.get(1)?;
                Ok((blob_to_hash(&blob), reason))
            })
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StateError::Io(e.to_string()))?);
        }
        Ok(out)
    }

    async fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM allowlist WHERE norm_hash = ?1")
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(stmt
            .query_row(params![hash_to_blob(hash)], |_| Ok(()))
            .opt()
            .map_err(|e| StateError::Io(e.to_string()))?
            .is_some())
    }

    async fn allowlist_add(&self, hash: NormHash, j: String) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO allowlist (norm_hash, justification) VALUES (?1, ?2)",
            params![hash_to_blob(&hash), j],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "DELETE FROM allowlist WHERE norm_hash = ?1",
            params![hash_to_blob(hash)],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn allowlist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT norm_hash, justification FROM allowlist")
            .map_err(|e| StateError::Io(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let j: String = row.get(1)?;
                Ok((blob_to_hash(&blob), j))
            })
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StateError::Io(e.to_string()))?);
        }
        Ok(out)
    }

    async fn policy_cache_get(
        &self,
        hash: &NormHash,
        ttl_secs: i64,
    ) -> Result<Option<CachedDecision>, StateError> {
        let cutoff = now_epoch() - ttl_secs;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT permission, risk_score_json FROM policy_cache
                 WHERE norm_hash = ?1 AND created_at > ?2",
            )
            .map_err(|e| StateError::Io(e.to_string()))?;
        let row: Option<(String, Option<String>)> = stmt
            .query_row(params![hash_to_blob(hash), cutoff], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .opt()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(|(perm, rsj)| {
            let risk_score = rsj.and_then(|j| match serde_json::from_str(&j) {
                Ok(rs) => Some(rs),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to deserialize cached risk_score_json");
                    None
                }
            });
            CachedDecision {
                permission: str_to_permission(&perm),
                risk_score,
            }
        }))
    }

    async fn policy_cache_set(
        &self,
        hash: NormHash,
        p: Permission,
        risk_score: Option<RiskScore>,
    ) -> Result<(), StateError> {
        let rsj = risk_score
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO policy_cache
                (norm_hash, permission, risk_score_json, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![hash_to_blob(&hash), permission_to_str(p), rsj, now_epoch()],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn policy_cache_clear(&self) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute("DELETE FROM policy_cache", [])
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "DELETE FROM policy_cache WHERE norm_hash = ?1",
            params![hash_to_blob(hash)],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn cache_meta_get(&self, key: &str) -> Result<Option<String>, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT value FROM cache_meta WHERE key = ?1")
            .map_err(|e| StateError::Io(e.to_string()))?;
        stmt.query_row(params![key], |row| row.get::<_, String>(0))
            .opt()
            .map_err(|e| StateError::Io(e.to_string()))
    }

    async fn cache_meta_set(&self, key: &str, value: &str) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn approval_create(&self, row: PendingApprovalRow) -> Result<(), StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO pending_approvals
                (approval_id, norm_hash, action_type, channel, created_at, norm_action_json, risk_score_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.approval_id,
                hash_to_blob(&row.norm_hash),
                row.action_type,
                row.channel,
                row.created_at,
                row.norm_action_json,
                row.risk_score_json,
            ],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn approval_get(&self, id: &str) -> Result<Option<PendingApprovalRow>, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT approval_id, norm_hash, action_type, channel, created_at,
                        norm_action_json, risk_score_json
                 FROM pending_approvals WHERE approval_id = ?1",
            )
            .map_err(|e| StateError::Io(e.to_string()))?;
        stmt.query_row(params![id], |row| {
            let blob: Vec<u8> = row.get(1)?;
            Ok(PendingApprovalRow {
                approval_id: row.get(0)?,
                norm_hash: blob_to_hash(&blob),
                action_type: row.get(2)?,
                channel: row.get(3)?,
                created_at: row.get(4)?,
                norm_action_json: row.get(5)?,
                risk_score_json: row.get(6)?,
            })
        })
        .opt()
        .map_err(|e| StateError::Io(e.to_string()))
    }

    async fn approval_resolve(
        &self,
        id: &str,
        decision: HumanDecisionRow,
    ) -> Result<(), StateError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StateError::Io(e.to_string()))?;
        tx.execute(
            "DELETE FROM pending_approvals WHERE approval_id = ?1",
            params![id],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        tx.execute(
            "INSERT OR REPLACE INTO resolved_approvals
                (approval_id, permission, reason, reviewer, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                permission_to_str(decision.permission),
                decision.reason,
                decision.reviewer,
                decision.decided_at,
            ],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        tx.commit().map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn approval_list_pending(&self) -> Result<Vec<PendingApprovalRow>, StateError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT approval_id, norm_hash, action_type, channel, created_at,
                        norm_action_json, risk_score_json
                 FROM pending_approvals ORDER BY created_at ASC",
            )
            .map_err(|e| StateError::Io(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let blob: Vec<u8> = row.get(1)?;
                Ok(PendingApprovalRow {
                    approval_id: row.get(0)?,
                    norm_hash: blob_to_hash(&blob),
                    action_type: row.get(2)?,
                    channel: row.get(3)?,
                    created_at: row.get(4)?,
                    norm_action_json: row.get(5)?,
                    risk_score_json: row.get(6)?,
                })
            })
            .map_err(|e| StateError::Io(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| StateError::Io(e.to_string()))?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h() -> NormHash {
        [0u8; 32]
    }
    fn h2() -> NormHash {
        let mut x = [0u8; 32];
        x[0] = 1;
        x
    }

    #[tokio::test]
    async fn denylist_crud() {
        let s = SqlitePolicyState::in_memory().unwrap();
        assert!(s.denylist_check(&h()).await.unwrap().is_none());
        s.denylist_add(h(), "bad".into()).await.unwrap();
        assert_eq!(s.denylist_check(&h()).await.unwrap(), Some("bad".into()));
        s.denylist_remove(&h()).await.unwrap();
        assert!(s.denylist_check(&h()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn allowlist_crud() {
        let s = SqlitePolicyState::in_memory().unwrap();
        s.allowlist_add(h(), "ok".into()).await.unwrap();
        assert!(s.allowlist_check(&h()).await.unwrap());
        let l = s.allowlist_list().await.unwrap();
        assert_eq!(l.len(), 1);
    }

    #[tokio::test]
    async fn policy_cache_clear() {
        let s = SqlitePolicyState::in_memory().unwrap();
        s.policy_cache_set(h(), Permission::Allow, None)
            .await
            .unwrap();
        s.policy_cache_set(h2(), Permission::Deny, None)
            .await
            .unwrap();
        s.policy_cache_clear().await.unwrap();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_none());
        assert!(s.policy_cache_get(&h2(), 3600).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn policy_cache_ttl_expires() {
        let s = SqlitePolicyState::in_memory().unwrap();
        s.policy_cache_set(h(), Permission::Allow, None)
            .await
            .unwrap();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_some());
        // A TTL of -1 places the cutoff in the future → entry is expired.
        assert!(s.policy_cache_get(&h(), -1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn policy_cache_stores_and_returns_risk_score() {
        let s = SqlitePolicyState::in_memory().unwrap();
        let rs =
            permit0_types::to_risk_score(0.5, vec!["MUTATION".to_string()], "test", false, None);
        let expected_tier = rs.tier;
        s.policy_cache_set(h(), Permission::Allow, Some(rs))
            .await
            .unwrap();
        let got = s
            .policy_cache_get(&h(), 3600)
            .await
            .unwrap()
            .expect("cached");
        assert_eq!(got.permission, Permission::Allow);
        let score = got.risk_score.expect("risk score round-tripped");
        assert_eq!(score.tier, expected_tier);
    }

    #[tokio::test]
    async fn cache_meta_round_trips() {
        let s = SqlitePolicyState::in_memory().unwrap();
        assert!(s.cache_meta_get("fp").await.unwrap().is_none());
        s.cache_meta_set("fp", "abc123").await.unwrap();
        assert_eq!(
            s.cache_meta_get("fp").await.unwrap().as_deref(),
            Some("abc123")
        );
    }

    #[tokio::test]
    async fn approval_lifecycle() {
        let s = SqlitePolicyState::in_memory().unwrap();
        s.approval_create(PendingApprovalRow {
            approval_id: "a1".into(),
            norm_hash: h(),
            action_type: "email.send".into(),
            channel: "gmail".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            norm_action_json: "{}".into(),
            risk_score_json: "{}".into(),
        })
        .await
        .unwrap();
        let got = s.approval_get("a1").await.unwrap().unwrap();
        assert_eq!(got.action_type, "email.send");

        s.approval_resolve(
            "a1",
            HumanDecisionRow {
                permission: Permission::Deny,
                reason: "no".into(),
                reviewer: "alice".into(),
                decided_at: "2026-01-01T00:01:00Z".into(),
            },
        )
        .await
        .unwrap();
        assert!(s.approval_get("a1").await.unwrap().is_none());
    }
}
