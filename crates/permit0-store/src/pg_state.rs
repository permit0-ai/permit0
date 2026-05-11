#![forbid(unsafe_code)]

use sqlx::postgres::{PgPool, PgPoolOptions};

use permit0_types::{NormHash, Permission};

use crate::policy_state::{HumanDecisionRow, PendingApprovalRow, PolicyState, StateError};

/// Postgres-backed `PolicyState`. Production storage for the engine.
///
/// Uses `sqlx::PgPool` for connection management. `connect()` opens the
/// pool; `migrate()` runs the migrations baked into the binary at compile
/// time so the engine can boot against a fresh database without external
/// tooling.
pub struct PostgresPolicyState {
    pool: PgPool,
}

impl PostgresPolicyState {
    /// Connect to Postgres at `url` (e.g. `postgres://user:pass@host:5432/permit0_state`).
    pub async fn connect(url: &str) -> Result<Self, StateError> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(url)
            .await
            .map_err(|e| StateError::Io(format!("connect state DB: {e}")))?;
        Ok(Self { pool })
    }

    /// Build from an existing pool (useful for tests with `testcontainers`).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Run the bundled migrations.
    pub async fn migrate(&self) -> Result<(), StateError> {
        sqlx::migrate!("./migrations/state")
            .run(&self.pool)
            .await
            .map_err(|e| StateError::Io(format!("state migrate: {e}")))?;
        Ok(())
    }
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

#[async_trait::async_trait]
impl PolicyState for PostgresPolicyState {
    async fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StateError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT reason FROM denylist WHERE norm_hash = $1")
                .bind(hash.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(|(r,)| r))
    }

    async fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StateError> {
        sqlx::query(
            "INSERT INTO denylist (norm_hash, reason) VALUES ($1, $2)
             ON CONFLICT (norm_hash) DO UPDATE SET reason = EXCLUDED.reason",
        )
        .bind(hash.as_slice())
        .bind(reason)
        .execute(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn denylist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        sqlx::query("DELETE FROM denylist WHERE norm_hash = $1")
            .bind(hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn denylist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let rows: Vec<(Vec<u8>, String)> = sqlx::query_as("SELECT norm_hash, reason FROM denylist")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|(b, r)| (blob_to_hash(&b), r))
            .collect())
    }

    async fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StateError> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM allowlist WHERE norm_hash = $1")
            .bind(hash.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.is_some())
    }

    async fn allowlist_add(&self, hash: NormHash, j: String) -> Result<(), StateError> {
        sqlx::query(
            "INSERT INTO allowlist (norm_hash, justification) VALUES ($1, $2)
             ON CONFLICT (norm_hash) DO UPDATE SET justification = EXCLUDED.justification",
        )
        .bind(hash.as_slice())
        .bind(j)
        .execute(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        sqlx::query("DELETE FROM allowlist WHERE norm_hash = $1")
            .bind(hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn allowlist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let rows: Vec<(Vec<u8>, String)> =
            sqlx::query_as("SELECT norm_hash, justification FROM allowlist")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|(b, j)| (blob_to_hash(&b), j))
            .collect())
    }

    async fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StateError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT permission FROM policy_cache WHERE norm_hash = $1")
                .bind(hash.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(|(s,)| str_to_permission(&s)))
    }

    async fn policy_cache_set(&self, hash: NormHash, p: Permission) -> Result<(), StateError> {
        sqlx::query(
            "INSERT INTO policy_cache (norm_hash, permission) VALUES ($1, $2)
             ON CONFLICT (norm_hash) DO UPDATE SET permission = EXCLUDED.permission",
        )
        .bind(hash.as_slice())
        .bind(permission_to_str(p))
        .execute(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn policy_cache_clear(&self) -> Result<(), StateError> {
        sqlx::query("DELETE FROM policy_cache")
            .execute(&self.pool)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError> {
        sqlx::query("DELETE FROM policy_cache WHERE norm_hash = $1")
            .bind(hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn approval_create(&self, row: PendingApprovalRow) -> Result<(), StateError> {
        let na: serde_json::Value = serde_json::from_str(&row.norm_action_json)
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let rs: serde_json::Value = serde_json::from_str(&row.risk_score_json)
            .unwrap_or(serde_json::Value::Object(Default::default()));
        sqlx::query(
            "INSERT INTO pending_approvals
                (approval_id, norm_hash, action_type, channel, created_at, norm_action_json, risk_score_json)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (approval_id) DO NOTHING",
        )
        .bind(&row.approval_id)
        .bind(row.norm_hash.as_slice())
        .bind(&row.action_type)
        .bind(&row.channel)
        .bind(&row.created_at)
        .bind(na)
        .bind(rs)
        .execute(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn approval_get(&self, id: &str) -> Result<Option<PendingApprovalRow>, StateError> {
        let row: Option<(
            String,
            Vec<u8>,
            String,
            String,
            String,
            serde_json::Value,
            serde_json::Value,
        )> = sqlx::query_as(
            "SELECT approval_id, norm_hash, action_type, channel, created_at,
                    norm_action_json, risk_score_json
             FROM pending_approvals WHERE approval_id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(
            |(approval_id, nh, action_type, channel, created_at, na, rs)| PendingApprovalRow {
                approval_id,
                norm_hash: blob_to_hash(&nh),
                action_type,
                channel,
                created_at,
                norm_action_json: na.to_string(),
                risk_score_json: rs.to_string(),
            },
        ))
    }

    async fn approval_resolve(
        &self,
        id: &str,
        decision: HumanDecisionRow,
    ) -> Result<(), StateError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        sqlx::query("DELETE FROM pending_approvals WHERE approval_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        sqlx::query(
            "INSERT INTO resolved_approvals
                (approval_id, permission, reason, reviewer, decided_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (approval_id) DO UPDATE SET
               permission = EXCLUDED.permission,
               reason = EXCLUDED.reason,
               reviewer = EXCLUDED.reviewer,
               decided_at = EXCLUDED.decided_at",
        )
        .bind(id)
        .bind(permission_to_str(decision.permission))
        .bind(&decision.reason)
        .bind(&decision.reviewer)
        .bind(&decision.decided_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }

    async fn approval_list_pending(&self) -> Result<Vec<PendingApprovalRow>, StateError> {
        let rows: Vec<(
            String,
            Vec<u8>,
            String,
            String,
            String,
            serde_json::Value,
            serde_json::Value,
        )> = sqlx::query_as(
            "SELECT approval_id, norm_hash, action_type, channel, created_at,
                    norm_action_json, risk_score_json
             FROM pending_approvals ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(
                |(approval_id, nh, action_type, channel, created_at, na, rs)| PendingApprovalRow {
                    approval_id,
                    norm_hash: blob_to_hash(&nh),
                    action_type,
                    channel,
                    created_at,
                    norm_action_json: na.to_string(),
                    risk_score_json: rs.to_string(),
                },
            )
            .collect())
    }
}

fn blob_to_hash(blob: &[u8]) -> NormHash {
    let mut hash = [0u8; 32];
    let len = blob.len().min(32);
    hash[..len].copy_from_slice(&blob[..len]);
    hash
}
