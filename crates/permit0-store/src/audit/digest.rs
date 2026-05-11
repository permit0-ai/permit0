#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// CloudTrail-style batch digest covering a contiguous range of audit
/// entries.
///
/// Per-entry hashing (`AuditEntry::entry_hash` + `prev_hash`) gives
/// tamper detection at the row level. Digests give *file-level*
/// tamper detection: each digest pins a contiguous range of entry
/// hashes and is itself chained to the previous digest, so an
/// auditor can verify a JSONL export against a single signed digest
/// instead of replaying the entire chain.
///
/// Wire format on disk: one JSON object per file, named
/// `digest-<sequence_to>-<digest_id>.json`. The on-disk file and the
/// `digests` Postgres row are equivalent — written together inside
/// the same advisory-lock transaction in [`super::digest_writer`] so
/// the disk view never lags or races the DB view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest {
    /// Unique digest ID (ULID string).
    pub digest_id: String,
    /// ISO 8601 wall-clock at digest emission.
    pub created_at: String,
    /// First `AuditEntry::sequence` covered by this digest (inclusive).
    pub sequence_from: u64,
    /// Last `AuditEntry::sequence` covered by this digest (inclusive).
    pub sequence_to: u64,
    /// SHA-256 over the concatenated `entry_hash` bytes of every entry
    /// in `[sequence_from, sequence_to]`, hex-encoded. Pins the exact
    /// set of entries the digest covers — flipping any byte of any
    /// covered entry changes this root.
    pub entry_hashes_root: String,
    /// `digest_hash` of the previous digest, or [`GENESIS_DIGEST_HASH`]
    /// for the first one. Chains digests independently of the entry
    /// chain so a tamper that excises a whole window of entries (and
    /// fakes both ends of the entry chain) is still caught at the
    /// digest level.
    pub prev_digest_hash: String,
    /// SHA-256 over `digest_id | created_at | sequence_from |
    /// sequence_to | entry_hashes_root | prev_digest_hash`,
    /// hex-encoded. The signature signs this hash.
    pub digest_hash: String,
    /// ed25519 signature over `digest_hash`, hex-encoded.
    pub signature: String,
}

/// Sentinel for the first digest in the chain.
pub const GENESIS_DIGEST_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Pluggable durable backing for digests, separate from `AuditSink` so
/// the writer can fan-out to multiple stores (typically: a file
/// directory + a Postgres table).
#[async_trait::async_trait]
pub trait DigestStore: Send + Sync {
    /// Append a fully-formed signed digest. Implementations should
    /// reject non-monotonic sequence ranges and return [`AuditError`]
    /// on conflict so the caller can recover.
    async fn append(&self, digest: &Digest) -> Result<(), crate::audit::sink::AuditError>;

    /// Return the most recent digest by `sequence_to`, or `None` if
    /// the store is empty. Used by [`super::digest_writer::DigestWriter`]
    /// to seed `prev_digest_hash` and `sequence_from`.
    async fn tail(&self) -> Result<Option<Digest>, crate::audit::sink::AuditError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trips_through_serde() {
        let d = Digest {
            digest_id: "01HZ".into(),
            created_at: "2026-05-10T00:00:00Z".into(),
            sequence_from: 1,
            sequence_to: 100,
            entry_hashes_root: "abc".into(),
            prev_digest_hash: GENESIS_DIGEST_HASH.into(),
            digest_hash: "def".into(),
            signature: "sig".into(),
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Digest = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }
}
