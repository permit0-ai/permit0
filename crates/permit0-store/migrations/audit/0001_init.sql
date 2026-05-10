-- permit0-audit-db: signed, hash-chained decision log.

CREATE TABLE IF NOT EXISTS audit_entries (
    entry_id          TEXT      PRIMARY KEY,
    sequence          BIGINT    NOT NULL UNIQUE,
    timestamp         TEXT      NOT NULL,
    action_type       TEXT      NOT NULL,
    channel           TEXT      NOT NULL,
    decision          TEXT      NOT NULL CHECK (decision IN ('allow', 'deny', 'human')),
    tier              TEXT,
    session_id        TEXT,
    prev_hash         TEXT      NOT NULL,
    entry_hash        TEXT      NOT NULL,
    signature         TEXT      NOT NULL,
    has_human_review  BOOLEAN   NOT NULL DEFAULT FALSE,
    entry_json        JSONB     NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_action_type    ON audit_entries (action_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp      ON audit_entries (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_decision       ON audit_entries (decision);
CREATE INDEX IF NOT EXISTS idx_audit_tier           ON audit_entries (tier);
CREATE INDEX IF NOT EXISTS idx_audit_session        ON audit_entries (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_human_review   ON audit_entries (has_human_review);

-- Rotation log for the audit signing key. Append-only; one row per
-- distinct public key the daemon has ever used (keyed by the hex pubkey
-- as a natural primary key — the daemon registers itself on boot via
-- INSERT ... ON CONFLICT DO NOTHING).
CREATE TABLE IF NOT EXISTS signing_keys (
    public_key_hex  TEXT        PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
