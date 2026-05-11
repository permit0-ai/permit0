#![forbid(unsafe_code)]

use sqlx::postgres::{PgPool, PgPoolOptions};

use permit0_types::{Permission, Tier};

use crate::audit::chain::{verify_chain_link, verify_entry_hash};
use crate::audit::digest::{Digest, DigestStore};
use crate::audit::sink::{AuditError, AuditSink};
use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// Postgres advisory lock id used to serialize chain writes (insert +
/// digest emission). Arbitrary 64-bit constant — must be unique across
/// other advisory locks the database hosts. ASCII for "permit0\0".
const CHAIN_LOCK_ID: i64 = 0x7065_726d_6974_3000;

/// Postgres-backed `AuditSink`.
///
/// Chain integrity (`prev_hash` linkage + monotonic `sequence`) is
/// preserved across concurrent writers and across daemon restarts via
/// `pg_advisory_xact_lock(CHAIN_LOCK_ID)` held inside each `append`
/// transaction. The classic `INSERT ... RETURNING` with a SQL sequence
/// can't serialize prev_hash linkage on its own — two concurrent inserts
/// would both read the same head row.
pub struct PostgresAuditSink {
    pool: PgPool,
}

impl PostgresAuditSink {
    pub async fn connect(url: &str) -> Result<Self, AuditError> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(url)
            .await
            .map_err(|e| AuditError::Io(format!("connect audit DB: {e}")))?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), AuditError> {
        sqlx::migrate!("./migrations/audit")
            .run(&self.pool)
            .await
            .map_err(|e| AuditError::Io(format!("audit migrate: {e}")))?;
        Ok(())
    }

    /// Record a signing key's public hex in `signing_keys`. Idempotent.
    pub async fn register_signing_key(&self, public_key_hex: &str) -> Result<(), AuditError> {
        sqlx::query(
            "INSERT INTO signing_keys (public_key_hex) VALUES ($1)
             ON CONFLICT (public_key_hex) DO NOTHING",
        )
        .bind(public_key_hex)
        .execute(&self.pool)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    /// Borrow the underlying pool to build a sibling [`PostgresDigestStore`]
    /// without re-opening a second connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// `DigestStore` backed by the `digests` table in the audit DB. Built
/// from the same `PgPool` as [`PostgresAuditSink`] so they share a
/// connection pool — and so digests live in the same database that
/// holds the entries they cover, which is the natural blast radius.
pub struct PostgresDigestStore {
    pool: PgPool,
}

impl PostgresDigestStore {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl DigestStore for PostgresDigestStore {
    async fn append(&self, d: &Digest) -> Result<(), AuditError> {
        sqlx::query(
            "INSERT INTO digests
                (digest_id, sequence_from, sequence_to, prev_digest_hash,
                 entry_hashes_root, digest_hash, signature, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&d.digest_id)
        .bind(d.sequence_from as i64)
        .bind(d.sequence_to as i64)
        .bind(&d.prev_digest_hash)
        .bind(&d.entry_hashes_root)
        .bind(&d.digest_hash)
        .bind(&d.signature)
        .bind(&d.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    async fn tail(&self) -> Result<Option<Digest>, AuditError> {
        let row: Option<(String, i64, i64, String, String, String, String, String)> =
            sqlx::query_as(
                "SELECT digest_id, sequence_from, sequence_to, prev_digest_hash,
                        entry_hashes_root, digest_hash, signature, created_at
                 FROM digests ORDER BY sequence_to DESC LIMIT 1",
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(row.map(
            |(
                digest_id,
                sequence_from,
                sequence_to,
                prev_digest_hash,
                entry_hashes_root,
                digest_hash,
                signature,
                created_at,
            )| Digest {
                digest_id,
                created_at,
                sequence_from: sequence_from as u64,
                sequence_to: sequence_to as u64,
                entry_hashes_root,
                prev_digest_hash,
                digest_hash,
                signature,
            },
        ))
    }
}

fn permission_to_str(p: Permission) -> &'static str {
    match p {
        Permission::Allow => "allow",
        Permission::HumanInTheLoop => "human",
        Permission::Deny => "deny",
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
impl AuditSink for PostgresAuditSink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let json = serde_json::to_value(entry)
            .map_err(|e| AuditError::Io(format!("audit entry serialize: {e}")))?;
        let action_type = entry.norm_action.action_type.as_action_str();
        let tier_str = entry.risk_score.as_ref().map(|rs| tier_to_str(rs.tier));

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;

        // Serialize all chain mutations behind this lock. Released at COMMIT.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CHAIN_LOCK_ID)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuditError::Io(format!("acquire chain lock: {e}")))?;

        sqlx::query(
            "INSERT INTO audit_entries
                (entry_id, sequence, timestamp, action_type, channel, decision, tier,
                 session_id, prev_hash, entry_hash, signature, has_human_review, entry_json)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(&entry.entry_id)
        .bind(entry.sequence as i64)
        .bind(&entry.timestamp)
        .bind(action_type)
        .bind(&entry.norm_action.channel)
        .bind(permission_to_str(entry.decision))
        .bind(tier_str)
        .bind(entry.session_id.as_deref())
        .bind(&entry.prev_hash)
        .bind(&entry.entry_hash)
        .bind(&entry.signature)
        .bind(entry.human_review.is_some())
        .bind(json)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    async fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        let mut sql = String::from("SELECT entry_json FROM audit_entries WHERE TRUE");
        let mut idx = 1;
        let mut binds: Vec<String> = Vec::new();

        if let Some(ref at) = filter.action_type {
            sql.push_str(&format!(" AND action_type LIKE ${idx}"));
            binds.push(format!("{at}%"));
            idx += 1;
        }
        if let Some(d) = filter.decision {
            sql.push_str(&format!(" AND decision = ${idx}"));
            binds.push(permission_to_str(d).to_string());
            idx += 1;
        }
        if let Some(t) = filter.tier {
            sql.push_str(&format!(" AND tier = ${idx}"));
            binds.push(tier_to_str(t).to_string());
            idx += 1;
        }
        if let Some(ref sid) = filter.session_id {
            sql.push_str(&format!(" AND session_id = ${idx}"));
            binds.push(sid.clone());
            idx += 1;
        }
        if let Some(ref since) = filter.since {
            sql.push_str(&format!(" AND timestamp >= ${idx}"));
            binds.push(since.clone());
            idx += 1;
        }
        if let Some(ref until) = filter.until {
            sql.push_str(&format!(" AND timestamp <= ${idx}"));
            binds.push(until.clone());
            idx += 1;
        }

        let limit = filter.limit.unwrap_or(100) as i64;
        sql.push_str(&format!(" ORDER BY sequence DESC LIMIT ${idx}"));

        let mut q = sqlx::query_as::<_, (serde_json::Value,)>(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q = q.bind(limit);

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for (json,) in rows {
            let entry: AuditEntry = serde_json::from_value(json)
                .map_err(|e| AuditError::Io(format!("audit entry deserialize: {e}")))?;
            out.push(entry);
        }
        Ok(out)
    }

    async fn verify_chain(&self, from: u64, to: u64) -> Result<ChainVerification, AuditError> {
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT entry_json FROM audit_entries
             WHERE sequence >= $1 AND sequence <= $2
             ORDER BY sequence ASC",
        )
        .bind(from as i64)
        .bind(to as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;

        let mut entries: Vec<AuditEntry> = Vec::with_capacity(rows.len());
        for (j,) in rows {
            entries.push(serde_json::from_value(j).map_err(|e| AuditError::Io(e.to_string()))?);
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
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT sequence, entry_hash FROM audit_entries
             ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(row.map(|(s, h)| (s as u64, h)))
    }

    async fn query_sequence_range(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        if to < from {
            return Ok(Vec::new());
        }
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT entry_json FROM audit_entries
             WHERE sequence >= $1 AND sequence <= $2
             ORDER BY sequence ASC",
        )
        .bind(from as i64)
        .bind(to as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for (json,) in rows {
            out.push(serde_json::from_value(json).map_err(|e| AuditError::Io(e.to_string()))?);
        }
        Ok(out)
    }
}
