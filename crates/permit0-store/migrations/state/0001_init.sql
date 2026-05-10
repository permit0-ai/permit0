-- permit0-state-db: denylist, allowlist, policy cache, durable HITL queue.

CREATE TABLE IF NOT EXISTS denylist (
    norm_hash BYTEA PRIMARY KEY,
    reason    TEXT  NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist (
    norm_hash     BYTEA PRIMARY KEY,
    justification TEXT  NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_cache (
    norm_hash  BYTEA PRIMARY KEY,
    permission TEXT  NOT NULL CHECK (permission IN ('allow', 'deny', 'human'))
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id      TEXT  PRIMARY KEY,
    norm_hash        BYTEA NOT NULL,
    action_type      TEXT  NOT NULL,
    channel          TEXT  NOT NULL,
    created_at       TEXT  NOT NULL,
    norm_action_json JSONB NOT NULL,
    risk_score_json  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_created_at ON pending_approvals (created_at);

CREATE TABLE IF NOT EXISTS resolved_approvals (
    approval_id TEXT PRIMARY KEY,
    permission  TEXT NOT NULL CHECK (permission IN ('allow', 'deny', 'human')),
    reason      TEXT NOT NULL,
    reviewer    TEXT NOT NULL,
    decided_at  TEXT NOT NULL
);
