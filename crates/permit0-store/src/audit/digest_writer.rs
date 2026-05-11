#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::audit::chain::{compute_digest_hash, compute_entry_hashes_root};
use crate::audit::digest::{Digest, DigestStore, GENESIS_DIGEST_HASH};
use crate::audit::signer::AuditSigner;
use crate::audit::sink::{AuditError, AuditSink};

/// Background task that emits CloudTrail-style signed batch digests
/// over the audit chain.
///
/// Wakes on a fixed interval, asks each configured [`DigestStore`] for
/// its tail, and if `audit_sink.tail()` advanced past `tail.sequence_to`
/// emits a new `Digest` covering the gap. Caps the batch at
/// `batch_max` so a long catch-up after downtime doesn't write one
/// enormous digest.
///
/// Intentional sharp edges:
/// * If multiple `DigestStore`s disagree on tail, the writer trusts
///   the *minimum* `sequence_to` so any lagging store catches up. The
///   primary store should always be the one you treat as canonical
///   (in compose: the file directory, since it's verifiable offline).
/// * `flush_once` is also exposed so tests and CLI tooling (e.g.
///   `permit0 digest verify --emit`) can drive a single tick without
///   spawning the background task.
pub struct DigestWriter {
    sink: Arc<dyn AuditSink>,
    signer: Arc<dyn AuditSigner>,
    stores: Vec<Arc<dyn DigestStore>>,
    interval: Duration,
    batch_max: usize,
}

impl DigestWriter {
    pub fn new(
        sink: Arc<dyn AuditSink>,
        signer: Arc<dyn AuditSigner>,
        stores: Vec<Arc<dyn DigestStore>>,
        interval: Duration,
        batch_max: usize,
    ) -> Self {
        Self {
            sink,
            signer,
            stores,
            interval,
            batch_max,
        }
    }

    /// Spawn the background loop on the current tokio runtime. The
    /// returned handle is detached on drop unless the caller awaits or
    /// aborts it.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            // Skip the initial immediate tick so the engine has a chance
            // to write its first entries before we look for a digest gap.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match self.flush_once().await {
                    Ok(Some(d)) => {
                        tracing::debug!(
                            sequence_from = d.sequence_from,
                            sequence_to = d.sequence_to,
                            "emitted audit digest",
                        );
                    }
                    Ok(None) => {} // chain is at digest tail; nothing to do.
                    Err(e) => {
                        tracing::warn!(error = %e, "digest writer flush failed");
                    }
                }
            }
        })
    }

    /// Single-shot: read the current chain tail, and if there are any
    /// uncovered entries, emit one signed digest covering up to
    /// `batch_max` of them. Returns `Ok(None)` if no new entries.
    pub async fn flush_once(&self) -> Result<Option<Digest>, AuditError> {
        if self.stores.is_empty() {
            return Ok(None);
        }

        // Find the highest already-covered sequence across all stores.
        // Trust the minimum so a lagging store catches up.
        let mut last_seq: u64 = 0;
        let mut prev_digest_hash: String = GENESIS_DIGEST_HASH.into();
        let mut have_any = false;
        for store in &self.stores {
            if let Some(d) = store.tail().await? {
                if !have_any || d.sequence_to < last_seq {
                    last_seq = d.sequence_to;
                    prev_digest_hash = d.digest_hash;
                }
                have_any = true;
            }
        }
        if !have_any {
            // First-ever digest — chain from genesis.
            last_seq = 0;
        }

        let chain_tail = self.sink.tail().await?;
        let max_seq = match chain_tail {
            Some((s, _)) => s,
            None => return Ok(None), // empty audit chain, nothing to digest.
        };
        if max_seq <= last_seq {
            return Ok(None);
        }

        let from = last_seq + 1;
        let to = std::cmp::min(max_seq, from + self.batch_max as u64 - 1);

        // Indexed bounded fetch — Postgres / SQLite override the trait
        // default with a real `WHERE sequence BETWEEN $1 AND $2` query.
        let entries = self.sink.query_sequence_range(from, to).await?;
        if entries.is_empty() {
            // Chain claims tail at `max_seq` but the entries aren't
            // visible to query — could happen with a sink whose tail()
            // and query() race. Skip this tick and try again.
            tracing::debug!(
                from,
                to,
                "digest skipped: tail advanced but entries not yet queryable",
            );
            return Ok(None);
        }
        // Defensive: refuse to emit if there's a gap in the queried
        // range. Verifiers reject digests whose root doesn't match the
        // referenced entries, so a partial digest is worse than no
        // digest at this tick.
        for (idx, e) in entries.iter().enumerate() {
            let expected = from + idx as u64;
            if e.sequence != expected {
                return Err(AuditError::Io(format!(
                    "digest writer: sequence gap — expected {expected}, got {}",
                    e.sequence
                )));
            }
        }

        let entry_hashes_root = compute_entry_hashes_root(&entries);
        let actual_to = entries.last().map(|e| e.sequence).unwrap_or(to);
        let now = chrono::Utc::now().to_rfc3339();
        let digest_id = ulid::Ulid::new().to_string();

        let mut digest = Digest {
            digest_id,
            created_at: now,
            sequence_from: from,
            sequence_to: actual_to,
            entry_hashes_root,
            prev_digest_hash,
            digest_hash: String::new(),
            signature: String::new(),
        };
        digest.digest_hash = compute_digest_hash(&digest);
        digest.signature = self.signer.sign(&digest.digest_hash);

        // Fan out. A single store failure aborts the tick — better to
        // re-emit on the next tick than leave stores diverging mid-write.
        for store in &self.stores {
            store.append(&digest).await?;
        }

        Ok(Some(digest))
    }
}

/// `DigestStore` that persists digests as one JSON file per digest in
/// a directory. Filename is `digest-<sequence_to>-<digest_id>.json` so
/// `ls` gives chronological order.
///
/// Operators can verify offline against just this directory + a JSONL
/// audit export — no DB connection required. That's the whole point of
/// pushing digests through a separate store.
pub struct FileDigestStore {
    dir: PathBuf,
}

impl FileDigestStore {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| AuditError::Io(format!("create digest dir {}: {e}", dir.display())))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Iterate every `digest-*.json` in the directory, sorted by
    /// `sequence_to` ascending. Used by the verifier and by `tail()`.
    pub fn read_all(&self) -> Result<Vec<Digest>, AuditError> {
        let mut out: Vec<Digest> = Vec::new();
        let entries = std::fs::read_dir(&self.dir)
            .map_err(|e| AuditError::Io(format!("read digest dir: {e}")))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|s| s.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if !name.starts_with("digest-") || !name.ends_with(".json") {
                continue;
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| AuditError::Io(format!("read {}: {e}", path.display())))?;
            let d: Digest = serde_json::from_slice(&bytes)
                .map_err(|e| AuditError::Io(format!("parse digest {}: {e}", path.display())))?;
            out.push(d);
        }
        out.sort_by_key(|d| d.sequence_to);
        Ok(out)
    }
}

#[async_trait::async_trait]
impl DigestStore for FileDigestStore {
    async fn append(&self, digest: &Digest) -> Result<(), AuditError> {
        let name = format!(
            "digest-{:020}-{}.json",
            digest.sequence_to, digest.digest_id
        );
        let path = self.dir.join(&name);
        let body = serde_json::to_vec_pretty(digest)
            .map_err(|e| AuditError::Io(format!("serialize digest: {e}")))?;
        // Atomic rename so a reader never sees a half-written file.
        let tmp = self.dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, &body)
            .map_err(|e| AuditError::Io(format!("write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| AuditError::Io(format!("rename {}: {e}", path.display())))?;
        Ok(())
    }

    async fn tail(&self) -> Result<Option<Digest>, AuditError> {
        let all = self.read_all()?;
        Ok(all.into_iter().last())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::{GENESIS_HASH, compute_entry_hash, verify_digest_hash};
    use crate::audit::memory_sink::InMemoryAuditSink;
    use crate::audit::signer::Ed25519Signer;
    use crate::audit::types::AuditEntry;
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_signed(seq: u64, prev: &str, signer: &Ed25519Signer) -> AuditEntry {
        let mut e = AuditEntry {
            entry_id: format!("e-{seq}"),
            timestamp: format!("2026-01-01T00:00:{seq:02}Z"),
            sequence: seq,
            decision: Permission::Allow,
            decision_source: "scorer".into(),
            norm_action: NormAction {
                action_type: ActionType::parse("email.send").unwrap(),
                channel: "test".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "t".into(),
                    surface_command: "c".into(),
                },
            },
            norm_hash: [0u8; 32],
            raw_tool_call: json!({}),
            risk_score: None,
            scoring_detail: None,
            agent_id: String::new(),
            session_id: None,
            task_goal: None,
            org_id: String::new(),
            environment: String::new(),
            engine_version: "0.1".into(),
            pack_id: String::new(),
            pack_version: String::new(),
            dsl_version: "1.0".into(),
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

    async fn populate_chain(sink: &InMemoryAuditSink, signer: &Ed25519Signer, n: u64) {
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=n {
            let e = make_signed(i, &prev, signer);
            prev = e.entry_hash.clone();
            sink.append(&e).await.unwrap();
        }
    }

    #[tokio::test]
    async fn first_digest_chains_from_genesis_and_signs() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(InMemoryAuditSink::new());
        let signer = Arc::new(Ed25519Signer::generate());
        populate_chain(&sink, &signer, 5).await;

        let file_store: Arc<dyn DigestStore> =
            Arc::new(FileDigestStore::new(dir.path().to_path_buf()).unwrap());
        let writer = DigestWriter::new(
            sink as Arc<dyn AuditSink>,
            signer as Arc<dyn AuditSigner>,
            vec![file_store.clone()],
            Duration::from_secs(60),
            100,
        );

        let d = writer.flush_once().await.unwrap().unwrap();
        assert_eq!(d.sequence_from, 1);
        assert_eq!(d.sequence_to, 5);
        assert_eq!(d.prev_digest_hash, GENESIS_DIGEST_HASH);
        assert!(verify_digest_hash(&d));

        // Second flush is a no-op: chain hasn't advanced.
        assert!(writer.flush_once().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn second_digest_chains_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(InMemoryAuditSink::new());
        let signer = Arc::new(Ed25519Signer::generate());
        populate_chain(&sink, &signer, 3).await;

        let file_store: Arc<dyn DigestStore> =
            Arc::new(FileDigestStore::new(dir.path().to_path_buf()).unwrap());
        let writer = DigestWriter::new(
            sink.clone() as Arc<dyn AuditSink>,
            signer.clone() as Arc<dyn AuditSigner>,
            vec![file_store.clone()],
            Duration::from_secs(60),
            100,
        );
        let d1 = writer.flush_once().await.unwrap().unwrap();

        // Add more entries, flush again.
        let mut prev = sink.all_entries().last().unwrap().entry_hash.clone();
        for i in 4..=6 {
            let e = make_signed(i, &prev, &signer);
            prev = e.entry_hash.clone();
            sink.append(&e).await.unwrap();
        }
        let d2 = writer.flush_once().await.unwrap().unwrap();

        assert_eq!(d2.sequence_from, 4);
        assert_eq!(d2.sequence_to, 6);
        assert_eq!(d2.prev_digest_hash, d1.digest_hash);
        assert!(verify_digest_hash(&d2));
    }

    #[tokio::test]
    async fn batch_max_caps_single_digest_size() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(InMemoryAuditSink::new());
        let signer = Arc::new(Ed25519Signer::generate());
        populate_chain(&sink, &signer, 10).await;

        let file_store: Arc<dyn DigestStore> =
            Arc::new(FileDigestStore::new(dir.path().to_path_buf()).unwrap());
        let writer = DigestWriter::new(
            sink as Arc<dyn AuditSink>,
            signer as Arc<dyn AuditSigner>,
            vec![file_store.clone()],
            Duration::from_secs(60),
            4, // cap
        );
        let d1 = writer.flush_once().await.unwrap().unwrap();
        assert_eq!(d1.sequence_to - d1.sequence_from + 1, 4);
        let d2 = writer.flush_once().await.unwrap().unwrap();
        assert_eq!(d2.sequence_from, d1.sequence_to + 1);
    }

    #[tokio::test]
    async fn empty_chain_is_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(InMemoryAuditSink::new());
        let signer = Arc::new(Ed25519Signer::generate());
        let file_store: Arc<dyn DigestStore> =
            Arc::new(FileDigestStore::new(dir.path().to_path_buf()).unwrap());
        let writer = DigestWriter::new(
            sink as Arc<dyn AuditSink>,
            signer as Arc<dyn AuditSigner>,
            vec![file_store],
            Duration::from_secs(60),
            100,
        );
        assert!(writer.flush_once().await.unwrap().is_none());
    }
}
