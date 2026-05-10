#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};

use permit0_types::Tier;

use crate::audit::chain::{verify_chain_link, verify_entry_hash};
use crate::audit::sink::{AuditError, AuditSink};
use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// SQLite-backed audit sink. Owns the `audit_entries` table.
///
/// The full `AuditEntry` is serialized as JSON in the `entry_json` column
/// for lossless round-trip. A few fields are projected as their own
/// columns so common dashboard queries (filter by action_type, decision,
/// tier, session_id, time range) can use indexes.
pub struct SqliteAuditSink {
    conn: Mutex<Connection>,
}

impl SqliteAuditSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let conn = Connection::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
        Ok(s)
    }

    pub fn in_memory() -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory().map_err(|e| AuditError::Io(e.to_string()))?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.init_schema()?;
        Ok(s)
    }

    fn init_schema(&self) -> Result<(), AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| AuditError::Io(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                entry_id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                channel TEXT NOT NULL,
                decision TEXT NOT NULL,
                tier TEXT,
                session_id TEXT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                has_human_review INTEGER NOT NULL DEFAULT 0,
                entry_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_action_type ON audit_entries(action_type);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_entries(decision);
            CREATE INDEX IF NOT EXISTS idx_audit_tier ON audit_entries(tier);
            CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_entries(session_id);
            CREATE INDEX IF NOT EXISTS idx_audit_human_review ON audit_entries(has_human_review);
            CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_entries(sequence);",
        )
        .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    fn deserialize_entry(json: &str) -> Result<AuditEntry, AuditError> {
        serde_json::from_str(json)
            .map_err(|e| AuditError::Io(format!("audit entry deserialize: {e}")))
    }
}

fn permission_to_str(p: permit0_types::Permission) -> &'static str {
    match p {
        permit0_types::Permission::Allow => "allow",
        permit0_types::Permission::HumanInTheLoop => "human",
        permit0_types::Permission::Deny => "deny",
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

#[async_trait::async_trait]
impl AuditSink for SqliteAuditSink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let json = serde_json::to_string(entry)
            .map_err(|e| AuditError::Io(format!("audit entry serialize: {e}")))?;
        let action_type = entry.norm_action.action_type.as_action_str();
        let tier_str = entry.risk_score.as_ref().map(|rs| tier_to_str(rs.tier));
        conn.execute(
            "INSERT INTO audit_entries
                (entry_id, sequence, timestamp, action_type, channel, decision, tier,
                 session_id, prev_hash, entry_hash, signature, has_human_review, entry_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                entry.entry_id,
                entry.sequence as i64,
                entry.timestamp,
                action_type,
                entry.norm_action.channel,
                permission_to_str(entry.decision),
                tier_str,
                entry.session_id,
                entry.prev_hash,
                entry.entry_hash,
                entry.signature,
                if entry.human_review.is_some() { 1 } else { 0 },
                json,
            ],
        )
        .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    async fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::Io(e.to_string()))?;

        let mut sql = String::from("SELECT entry_json FROM audit_entries WHERE 1=1");
        let mut bindings: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref at) = filter.action_type {
            sql.push_str(&format!(" AND action_type LIKE ?{idx}"));
            bindings.push(Box::new(format!("{at}%")));
            idx += 1;
        }
        if let Some(d) = filter.decision {
            sql.push_str(&format!(" AND decision = ?{idx}"));
            bindings.push(Box::new(permission_to_str(d).to_string()));
            idx += 1;
        }
        if let Some(t) = filter.tier {
            sql.push_str(&format!(" AND tier = ?{idx}"));
            bindings.push(Box::new(tier_to_str(t).to_string()));
            idx += 1;
        }
        if let Some(ref sid) = filter.session_id {
            sql.push_str(&format!(" AND session_id = ?{idx}"));
            bindings.push(Box::new(sid.clone()));
            idx += 1;
        }
        if let Some(ref since) = filter.since {
            sql.push_str(&format!(" AND timestamp >= ?{idx}"));
            bindings.push(Box::new(since.clone()));
            idx += 1;
        }
        if let Some(ref until) = filter.until {
            sql.push_str(&format!(" AND timestamp <= ?{idx}"));
            bindings.push(Box::new(until.clone()));
            idx += 1;
        }

        let limit = filter.limit.unwrap_or(100);
        sql.push_str(&format!(" ORDER BY sequence DESC LIMIT ?{idx}"));
        bindings.push(Box::new(limit));

        let bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bindings.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let rows = stmt
            .query_map(bind_refs.as_slice(), |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .map_err(|e| AuditError::Io(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            let json = r.map_err(|e| AuditError::Io(e.to_string()))?;
            out.push(Self::deserialize_entry(&json)?);
        }
        Ok(out)
    }

    async fn verify_chain(&self, from: u64, to: u64) -> Result<ChainVerification, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT entry_json FROM audit_entries
                 WHERE sequence >= ?1 AND sequence <= ?2
                 ORDER BY sequence ASC",
            )
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let rows = stmt
            .query_map(params![from as i64, to as i64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let mut entries: Vec<AuditEntry> = Vec::new();
        for r in rows {
            let j = r.map_err(|e| AuditError::Io(e.to_string()))?;
            entries.push(Self::deserialize_entry(&j)?);
        }

        if entries.is_empty() {
            return Ok(ChainVerification {
                valid: true,
                entries_checked: 0,
                first_broken_at: None,
                failure_reason: None,
            });
        }

        for e in &entries {
            if !verify_entry_hash(e) {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: e.sequence - from,
                    first_broken_at: Some(e.sequence),
                    failure_reason: Some(format!("Entry {} has invalid hash", e.sequence)),
                });
            }
        }
        for w in entries.windows(2) {
            if !verify_chain_link(&w[0], &w[1]) {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: w[1].sequence - from,
                    first_broken_at: Some(w[1].sequence),
                    failure_reason: Some(format!(
                        "Chain broken between {} and {}",
                        w[0].sequence, w[1].sequence
                    )),
                });
            }
        }

        Ok(ChainVerification {
            valid: true,
            entries_checked: to - from + 1,
            first_broken_at: None,
            failure_reason: None,
        })
    }

    async fn tail(&self) -> Result<Option<(u64, String)>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let row = conn
            .query_row(
                "SELECT sequence, entry_hash FROM audit_entries
                 ORDER BY sequence DESC LIMIT 1",
                [],
                |r| {
                    let seq: i64 = r.get(0)?;
                    let h: String = r.get(1)?;
                    Ok((seq as u64, h))
                },
            )
            .ok();
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::{GENESIS_HASH, compute_entry_hash};
    use crate::audit::signer::{AuditSigner, Ed25519Signer};
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_signed(seq: u64, prev: &str, signer: &Ed25519Signer) -> AuditEntry {
        let mut e = AuditEntry {
            entry_id: format!("e-{seq}"),
            timestamp: format!("2026-01-01T00:00:0{seq}Z"),
            sequence: seq,
            decision: Permission::Allow,
            decision_source: "scorer".into(),
            norm_action: NormAction {
                action_type: ActionType::parse("email.send").unwrap(),
                channel: "gmail".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "test".into(),
                    surface_command: "test".into(),
                },
            },
            norm_hash: [0u8; 32],
            raw_tool_call: json!({"tool": "test"}),
            risk_score: None,
            scoring_detail: None,
            agent_id: "agent".into(),
            session_id: Some("sess-1".into()),
            task_goal: None,
            org_id: "org".into(),
            environment: "test".into(),
            engine_version: "0.1".into(),
            pack_id: "p".into(),
            pack_version: "1".into(),
            dsl_version: "1".into(),
            human_review: None,
            engine_decision: None,
            token_id: None,
            prev_hash: prev.into(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: None,
            retroactive_decision: None,
            decision_trace: Vec::new(),
        };
        e.entry_hash = compute_entry_hash(&e);
        e.signature = signer.sign(&e.entry_hash);
        e
    }

    #[tokio::test]
    async fn append_query_and_verify() {
        let sink = SqliteAuditSink::in_memory().unwrap();
        let signer = Ed25519Signer::generate();
        let e1 = make_signed(1, GENESIS_HASH, &signer);
        let e2 = make_signed(2, &e1.entry_hash, &signer);
        let e3 = make_signed(3, &e2.entry_hash, &signer);
        sink.append(&e1).await.unwrap();
        sink.append(&e2).await.unwrap();
        sink.append(&e3).await.unwrap();

        let all = sink.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].sequence, 3);

        let v = sink.verify_chain(1, 3).await.unwrap();
        assert!(v.valid);
        assert_eq!(v.entries_checked, 3);

        let (seq, hash) = sink.tail().await.unwrap().unwrap();
        assert_eq!(seq, 3);
        assert_eq!(hash, e3.entry_hash);
    }

    #[tokio::test]
    async fn unique_sequence_constraint() {
        let sink = SqliteAuditSink::in_memory().unwrap();
        let signer = Ed25519Signer::generate();
        let e1 = make_signed(1, GENESIS_HASH, &signer);
        let e1_dup = make_signed(1, GENESIS_HASH, &signer);
        sink.append(&e1).await.unwrap();
        // Same sequence should fail.
        assert!(sink.append(&e1_dup).await.is_err());
    }

    #[tokio::test]
    async fn filter_by_session() {
        let sink = SqliteAuditSink::in_memory().unwrap();
        let signer = Ed25519Signer::generate();
        let mut e1 = make_signed(1, GENESIS_HASH, &signer);
        e1.session_id = Some("sess-A".into());
        e1.entry_hash = compute_entry_hash(&e1);
        e1.signature = signer.sign(&e1.entry_hash);

        let mut e2 = make_signed(2, &e1.entry_hash, &signer);
        e2.session_id = Some("sess-B".into());
        e2.entry_hash = compute_entry_hash(&e2);
        e2.signature = signer.sign(&e2.entry_hash);

        sink.append(&e1).await.unwrap();
        sink.append(&e2).await.unwrap();

        let only_a = sink
            .query(&AuditFilter {
                session_id: Some("sess-A".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].sequence, 1);
    }
}
