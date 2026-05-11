#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
#[cfg(test)]
use permit0_store::audit::Digest;
use permit0_store::audit::{
    AuditEntry, Ed25519Verifier, FileDigestStore, GENESIS_DIGEST_HASH, chain,
};

/// `permit0 digest verify` — offline forensic verification of an
/// on-disk digest directory against an exported audit JSONL file.
///
/// The on-disk digest files are independently signed and chained, so
/// this command works on an air-gapped machine with just:
///
/// 1. The digest directory (e.g. mounted from S3 or copied from the
///    `audit-key` volume).
/// 2. A JSONL export of the audit entries (`/api/v1/audit/export`).
/// 3. The signing public key (printed by `permit0 serve --ui` at boot,
///    or read from `signing_keys` in the audit DB).
///
/// Verifies, for each digest:
///   - `digest_hash == compute_digest_hash(d)` — content integrity.
///   - `verifier.verify(digest_hash, signature)` — signature integrity.
///   - `prev_digest_hash` chains to the previous digest (or genesis).
///   - Every entry in `[sequence_from, sequence_to]` is present in the
///     audit JSONL.
///   - `entry_hashes_root` recomputes from those entries.
///
/// Any failure aborts with a non-zero exit. A passing run prints a
/// short summary so this can be wired into a cron/audit pipeline.
pub fn verify(digests_dir: &str, audit_jsonl: &str, public_key_hex: &str) -> Result<()> {
    let store = FileDigestStore::new(Path::new(digests_dir))
        .with_context(|| format!("opening digest dir {digests_dir}"))?;
    let digests = store.read_all().with_context(|| "reading digest files")?;
    if digests.is_empty() {
        println!("No digest files found in {digests_dir}.");
        return Ok(());
    }

    let verifier = Ed25519Verifier::from_hex(public_key_hex)
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;

    let entries = load_entries(audit_jsonl)?;
    let by_seq: HashMap<u64, &AuditEntry> = entries.iter().map(|e| (e.sequence, e)).collect();

    println!(
        "Verifying {} digest(s) against {} audit entr{} from {}...",
        digests.len(),
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        audit_jsonl,
    );

    let mut prev_digest_hash = GENESIS_DIGEST_HASH.to_string();
    let mut total_entries_covered = 0u64;

    for (i, d) in digests.iter().enumerate() {
        let label = format!(
            "digest {} (seq {}..={})",
            i + 1,
            d.sequence_from,
            d.sequence_to
        );

        // Content hash.
        if !chain::verify_digest_hash(d) {
            bail!("{label}: digest_hash mismatch");
        }
        // Signature.
        if !verifier.verify(&d.digest_hash, &d.signature) {
            bail!("{label}: invalid signature");
        }
        // Chain link.
        if d.prev_digest_hash != prev_digest_hash {
            bail!(
                "{label}: prev_digest_hash mismatch (expected {}, got {})",
                short(&prev_digest_hash),
                short(&d.prev_digest_hash),
            );
        }
        // Every entry the digest claims to cover must be in the JSONL.
        let mut covered: Vec<&AuditEntry> = Vec::new();
        for s in d.sequence_from..=d.sequence_to {
            match by_seq.get(&s) {
                Some(e) => covered.push(e),
                None => bail!("{label}: missing audit entry for sequence {s} in {audit_jsonl}"),
            }
        }
        // Per-entry integrity: recompute each covered entry's hash from
        // its content. The digest's `entry_hashes_root` only pins the
        // *stored* hash strings; without this check, an attacker who
        // edited an entry's body but left `entry_hash` alone would
        // pass digest verification.
        for e in &covered {
            if !chain::verify_entry_hash(e) {
                bail!(
                    "{label}: covered audit entry seq {} has tampered content (entry_hash mismatch)",
                    e.sequence,
                );
            }
        }
        // Recompute the root from the (now-verified) entry hashes.
        let owned: Vec<AuditEntry> = covered.iter().map(|&e| e.clone()).collect();
        let recomputed = chain::compute_entry_hashes_root(&owned);
        if recomputed != d.entry_hashes_root {
            bail!(
                "{label}: entry_hashes_root mismatch (recomputed {}, digest claims {})",
                short(&recomputed),
                short(&d.entry_hashes_root),
            );
        }

        total_entries_covered += d.sequence_to - d.sequence_from + 1;
        prev_digest_hash = d.digest_hash.clone();
    }

    let first = digests.first().unwrap();
    let last = digests.last().unwrap();
    println!();
    println!("  Digest count ........... {}", digests.len());
    println!(
        "  Sequence span .......... {}..={} ({} entries covered)",
        first.sequence_from, last.sequence_to, total_entries_covered,
    );
    println!("  Digest chain ........... VALID");
    println!("  Digest signatures ...... ALL VALID");
    println!("  Entry roots ............ ALL VALID");
    println!();
    println!("OK");
    Ok(())
}

fn load_entries(audit_jsonl: &str) -> Result<Vec<AuditEntry>> {
    let raw = std::fs::read_to_string(audit_jsonl)
        .with_context(|| format!("reading audit JSONL {audit_jsonl}"))?;
    let mut out = Vec::new();
    for (lineno, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let e: AuditEntry = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "parsing audit entry on line {} of {audit_jsonl}",
                lineno + 1
            )
        })?;
        out.push(e);
    }
    Ok(out)
}

fn short(hash: &str) -> String {
    if hash.len() <= 16 {
        hash.to_string()
    } else {
        format!("{}…{}", &hash[..8], &hash[hash.len() - 4..])
    }
}

/// Convenience for unit testing offline verification end-to-end.
#[cfg(test)]
pub fn verify_with_digests(
    digests: &[Digest],
    entries: &[AuditEntry],
    public_key_hex: &str,
) -> Result<()> {
    let verifier = Ed25519Verifier::from_hex(public_key_hex)
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;
    let by_seq: HashMap<u64, &AuditEntry> = entries.iter().map(|e| (e.sequence, e)).collect();
    let mut prev = GENESIS_DIGEST_HASH.to_string();
    for d in digests {
        if !chain::verify_digest_hash(d) {
            bail!(
                "digest_hash mismatch at {}..={}",
                d.sequence_from,
                d.sequence_to
            );
        }
        if !verifier.verify(&d.digest_hash, &d.signature) {
            bail!(
                "invalid signature at {}..={}",
                d.sequence_from,
                d.sequence_to
            );
        }
        if d.prev_digest_hash != prev {
            bail!(
                "prev_digest_hash mismatch at {}..={}",
                d.sequence_from,
                d.sequence_to
            );
        }
        let mut covered = Vec::new();
        for s in d.sequence_from..=d.sequence_to {
            match by_seq.get(&s) {
                Some(e) => covered.push((*e).clone()),
                None => bail!("missing entry for sequence {s}"),
            }
        }
        for e in &covered {
            if !chain::verify_entry_hash(e) {
                bail!("entry_hash mismatch for sequence {}", e.sequence);
            }
        }
        if chain::compute_entry_hashes_root(&covered) != d.entry_hashes_root {
            bail!(
                "entry_hashes_root mismatch at {}..={}",
                d.sequence_from,
                d.sequence_to
            );
        }
        prev = d.digest_hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_store::audit::{
        AuditSigner, AuditSink, DigestStore, DigestWriter, Ed25519Signer, InMemoryAuditSink,
        chain::{GENESIS_HASH, compute_entry_hash},
    };
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use std::sync::Arc;
    use std::time::Duration;

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
            raw_tool_call: serde_json::json!({}),
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

    #[tokio::test]
    async fn round_trip_passes_verification() {
        let sink = Arc::new(InMemoryAuditSink::new());
        let signer = Arc::new(Ed25519Signer::generate());
        let pubkey = signer.public_key_hex();

        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=8 {
            let e = make_signed(i, &prev, &signer);
            prev = e.entry_hash.clone();
            sink.append(&e).await.unwrap();
        }
        let entries = sink.all_entries();

        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn DigestStore> =
            Arc::new(FileDigestStore::new(dir.path().to_path_buf()).unwrap());
        let writer = DigestWriter::new(
            sink as Arc<dyn AuditSink>,
            signer as Arc<dyn AuditSigner>,
            vec![store.clone()],
            Duration::from_secs(60),
            4, // two digests of 4 each
        );
        writer.flush_once().await.unwrap();
        writer.flush_once().await.unwrap();

        let read_store = FileDigestStore::new(dir.path().to_path_buf()).unwrap();
        let digests = read_store.read_all().unwrap();
        assert_eq!(digests.len(), 2);

        verify_with_digests(&digests, &entries, &pubkey).unwrap();
    }

    #[tokio::test]
    async fn tamper_in_audit_entry_breaks_root() {
        let sink = Arc::new(InMemoryAuditSink::new());
        let signer = Arc::new(Ed25519Signer::generate());
        let pubkey = signer.public_key_hex();

        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=4 {
            let e = make_signed(i, &prev, &signer);
            prev = e.entry_hash.clone();
            sink.append(&e).await.unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn DigestStore> =
            Arc::new(FileDigestStore::new(dir.path().to_path_buf()).unwrap());
        let writer = DigestWriter::new(
            sink.clone() as Arc<dyn AuditSink>,
            signer as Arc<dyn AuditSigner>,
            vec![store.clone()],
            Duration::from_secs(60),
            10,
        );
        writer.flush_once().await.unwrap();
        let digests = FileDigestStore::new(dir.path().to_path_buf())
            .unwrap()
            .read_all()
            .unwrap();

        // Tamper with one entry's content (simulates an attacker who
        // edited the JSONL after export but didn't rehash).
        let mut entries = sink.all_entries();
        entries[1].decision = Permission::Deny;

        let err = verify_with_digests(&digests, &entries, &pubkey).unwrap_err();
        assert!(
            err.to_string().contains("entry_hash mismatch"),
            "expected per-entry hash mismatch, got: {err}"
        );
    }
}
