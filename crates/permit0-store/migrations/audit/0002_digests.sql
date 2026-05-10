-- Periodic batch digests over the audit chain (CloudTrail-style).
--
-- Each row pins a contiguous, non-overlapping range of `audit_entries`
-- and is independently chained to the previous digest. Auditors can
-- verify a JSONL export against a single signed digest instead of
-- replaying the full per-entry chain.
--
-- The on-disk file under `PERMIT0_DIGEST_DIR` mirrors this row 1:1 —
-- both are written inside the same advisory-lock transaction in
-- `DigestWriter::flush_once` so the views never race.

CREATE TABLE IF NOT EXISTS digests (
    digest_id          TEXT       PRIMARY KEY,
    sequence_from      BIGINT     NOT NULL,
    sequence_to        BIGINT     NOT NULL,
    prev_digest_hash   TEXT       NOT NULL,
    entry_hashes_root  TEXT       NOT NULL,
    digest_hash        TEXT       NOT NULL,
    signature          TEXT       NOT NULL,
    created_at         TEXT       NOT NULL,
    -- The `(sequence_from, sequence_to)` ranges are contiguous; this
    -- index makes "find digest covering sequence N" lookups cheap for
    -- the verifier.
    CHECK (sequence_to >= sequence_from)
);

CREATE INDEX IF NOT EXISTS idx_digests_sequence_to ON digests (sequence_to);
CREATE INDEX IF NOT EXISTS idx_digests_created_at ON digests (created_at);
