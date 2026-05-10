#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256};

use crate::audit::digest::Digest;
use crate::audit::types::AuditEntry;

/// The genesis hash for the first entry in the chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute the content hash for an audit entry.
/// Hashes all fields except `entry_hash` and `signature`.
pub fn compute_entry_hash(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();

    // Identity
    hasher.update(entry.entry_id.as_bytes());
    hasher.update(entry.timestamp.as_bytes());
    hasher.update(entry.sequence.to_le_bytes());

    // Decision
    hasher.update(format!("{:?}", entry.decision).as_bytes());
    hasher.update(entry.decision_source.as_bytes());

    // What was decided
    let norm_json = serde_json::to_string(&entry.norm_action).unwrap_or_default();
    hasher.update(norm_json.as_bytes());
    hasher.update(entry.norm_hash);
    let raw_json = serde_json::to_string(&entry.raw_tool_call).unwrap_or_default();
    hasher.update(raw_json.as_bytes());

    // Scoring
    if let Some(ref rs) = entry.risk_score {
        let rs_json = serde_json::to_string(rs).unwrap_or_default();
        hasher.update(rs_json.as_bytes());
    }
    if let Some(ref sd) = entry.scoring_detail {
        let sd_json = serde_json::to_string(sd).unwrap_or_default();
        hasher.update(sd_json.as_bytes());
    }

    // Who / where / why
    hasher.update(entry.agent_id.as_bytes());
    if let Some(ref sid) = entry.session_id {
        hasher.update(sid.as_bytes());
    }
    if let Some(ref tg) = entry.task_goal {
        hasher.update(tg.as_bytes());
    }
    hasher.update(entry.org_id.as_bytes());
    hasher.update(entry.environment.as_bytes());

    // Provenance
    hasher.update(entry.engine_version.as_bytes());
    hasher.update(entry.pack_id.as_bytes());
    hasher.update(entry.pack_version.as_bytes());
    hasher.update(entry.dsl_version.as_bytes());

    // Human review
    if let Some(ref hr) = entry.human_review {
        let hr_json = serde_json::to_string(hr).unwrap_or_default();
        hasher.update(hr_json.as_bytes());
    }
    if let Some(ref ed) = entry.engine_decision {
        hasher.update(format!("{ed:?}").as_bytes());
    }

    // Token
    if let Some(ref tid) = entry.token_id {
        hasher.update(tid.as_bytes());
    }

    // Chain link
    hasher.update(entry.prev_hash.as_bytes());

    // Correction
    if let Some(ref cid) = entry.correction_of {
        hasher.update(cid.as_bytes());
    }

    // Failed-open replay context (Lane A step 1b)
    if let Some(ref foc) = entry.failed_open_context {
        let foc_json = serde_json::to_string(foc).unwrap_or_default();
        hasher.update(foc_json.as_bytes());
    }
    if let Some(ref rd) = entry.retroactive_decision {
        hasher.update(format!("{rd:?}").as_bytes());
    }

    // Decision trace — hashed only when non‑empty so legacy entries
    // (written before this field existed) hash identically to before.
    // Operationally critical: any pre‑change JSONL on disk must continue
    // to verify with the same recomputed hash.
    if !entry.decision_trace.is_empty() {
        let trace_json = serde_json::to_string(&entry.decision_trace).unwrap_or_default();
        hasher.update(trace_json.as_bytes());
    }

    hex::encode(hasher.finalize())
}

/// Verify that an entry's hash is correct.
pub fn verify_entry_hash(entry: &AuditEntry) -> bool {
    let computed = compute_entry_hash(entry);
    computed == entry.entry_hash
}

/// Verify the chain link between two consecutive entries.
pub fn verify_chain_link(prev: &AuditEntry, current: &AuditEntry) -> bool {
    // The current entry's prev_hash must equal the previous entry's entry_hash
    current.prev_hash == prev.entry_hash
        // Sequence must be monotonically increasing
        && current.sequence == prev.sequence + 1
}

/// SHA-256 over the concatenated `entry_hash` bytes of every entry in
/// the slice, hex-encoded. The slice should already be sorted by
/// sequence — pinning order is what makes the root reproducible at
/// verification time.
pub fn compute_entry_hashes_root(entries: &[AuditEntry]) -> String {
    let mut hasher = Sha256::new();
    for e in entries {
        hasher.update(e.entry_hash.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Compute the content hash for a digest. Hashes every field except
/// `digest_hash` and `signature` so re-running the helper on a digest
/// loaded from disk reproduces the same value.
pub fn compute_digest_hash(d: &Digest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(d.digest_id.as_bytes());
    hasher.update(d.created_at.as_bytes());
    hasher.update(d.sequence_from.to_le_bytes());
    hasher.update(d.sequence_to.to_le_bytes());
    hasher.update(d.entry_hashes_root.as_bytes());
    hasher.update(d.prev_digest_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a digest's content hash is consistent with its other fields.
pub fn verify_digest_hash(d: &Digest) -> bool {
    compute_digest_hash(d) == d.digest_hash
}

/// Verify two consecutive digests link properly.
pub fn verify_digest_link(prev: &Digest, current: &Digest) -> bool {
    current.prev_digest_hash == prev.digest_hash
        // Digests must cover contiguous, non-overlapping sequence ranges.
        && current.sequence_from == prev.sequence_to + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{AuditEntry, DecisionStage};
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_entry(seq: u64, prev_hash: &str) -> AuditEntry {
        let mut entry = AuditEntry {
            entry_id: format!("entry-{seq}"),
            timestamp: "2025-01-01T00:00:00Z".into(),
            sequence: seq,
            decision: Permission::Allow,
            decision_source: "scorer".into(),
            norm_action: NormAction {
                action_type: ActionType::parse("email.send").unwrap(),
                channel: "gmail".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "test".into(),
                    surface_command: "test cmd".into(),
                },
            },
            norm_hash: [0u8; 32],
            raw_tool_call: json!({"tool": "test"}),
            risk_score: None,
            scoring_detail: None,
            agent_id: "agent-1".into(),
            session_id: None,
            task_goal: None,
            org_id: "org-1".into(),
            environment: "test".into(),
            engine_version: "0.1.0".into(),
            pack_id: "test-pack".into(),
            pack_version: "1.0".into(),
            dsl_version: "1.0".into(),
            human_review: None,
            engine_decision: None,
            token_id: None,
            prev_hash: prev_hash.into(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: None,
            retroactive_decision: None,
            decision_trace: Vec::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry);
        entry
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let e1 = make_entry(1, GENESIS_HASH);
        let e2 = make_entry(1, GENESIS_HASH);
        assert_eq!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn entry_hash_changes_with_content() {
        let e1 = make_entry(1, GENESIS_HASH);
        let e2 = make_entry(2, GENESIS_HASH);
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn verify_entry_hash_passes() {
        let entry = make_entry(1, GENESIS_HASH);
        assert!(verify_entry_hash(&entry));
    }

    #[test]
    fn verify_entry_hash_detects_tampering() {
        let mut entry = make_entry(1, GENESIS_HASH);
        entry.decision = Permission::Deny; // tamper
        assert!(!verify_entry_hash(&entry));
    }

    #[test]
    fn chain_link_valid() {
        let e1 = make_entry(1, GENESIS_HASH);
        let e2 = make_entry(2, &e1.entry_hash);
        assert!(verify_chain_link(&e1, &e2));
    }

    #[test]
    fn chain_link_broken_hash() {
        let e1 = make_entry(1, GENESIS_HASH);
        let e2 = make_entry(2, "wrong_hash");
        assert!(!verify_chain_link(&e1, &e2));
    }

    #[test]
    fn chain_link_broken_sequence() {
        let e1 = make_entry(1, GENESIS_HASH);
        let e3 = make_entry(3, &e1.entry_hash); // gap: 1 → 3
        assert!(!verify_chain_link(&e1, &e3));
    }

    #[test]
    fn empty_decision_trace_does_not_change_hash() {
        // Backward compatibility guarantee: any AuditEntry produced
        // before decision_trace existed had `decision_trace: vec![]`
        // (after deserialization with #[serde(default)]). Such entries
        // must hash *identically* to the pre-change implementation, or
        // every existing JSONL on disk fails `audit verify`.
        //
        // We can't compare against a frozen pre-change hex because the
        // surrounding fixture pulls in version strings; instead we
        // assert the property: an entry with empty trace hashes the
        // same as one with the field reset to default after we
        // explicitly set it to a non-empty trace and back. Equivalently:
        // mutating a non-empty trace to empty must reproduce the
        // original empty-trace hash.
        let e = make_entry(1, GENESIS_HASH);
        let baseline = e.entry_hash.clone();
        let mut mutated = e.clone();
        mutated.decision_trace = vec![DecisionStage {
            stage: "denylist".into(),
            outcome: "miss".into(),
            raw_tool_call: serde_json::json!({}),
            detail: None,
        }];
        mutated.entry_hash = compute_entry_hash(&mutated);
        assert_ne!(
            baseline, mutated.entry_hash,
            "non-empty trace must affect hash"
        );

        let mut reset = mutated.clone();
        reset.decision_trace.clear();
        reset.entry_hash = compute_entry_hash(&reset);
        assert_eq!(
            baseline, reset.entry_hash,
            "empty trace must hash identically to pre-change entries",
        );
    }

    #[test]
    fn populated_decision_trace_round_trips_through_serde() {
        // Ensure the new field survives JSON round-trip exactly so an
        // entry written to a JSONL audit file deserializes with the
        // same trace and the same content hash.
        let mut e = make_entry(1, GENESIS_HASH);
        e.decision_trace = vec![
            DecisionStage {
                stage: "normalize".into(),
                outcome: "ok".into(),
                raw_tool_call: serde_json::json!({"tool_name": "gmail_read"}),
                detail: Some(serde_json::json!({"action_type": "email.read"})),
            },
            DecisionStage {
                stage: "risk_scoring".into(),
                outcome: "evaluated".into(),
                raw_tool_call: serde_json::json!({"tool_name": "gmail_read"}),
                detail: Some(serde_json::json!({"tier": "Low", "raw": 0.12})),
            },
        ];
        e.entry_hash = compute_entry_hash(&e);

        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision_trace.len(), 2);
        assert_eq!(parsed.decision_trace[0].stage, "normalize");
        assert_eq!(parsed.decision_trace[1].outcome, "evaluated");
        assert!(
            verify_entry_hash(&parsed),
            "hash must survive serde round-trip"
        );
    }

    #[test]
    fn legacy_jsonl_without_trace_field_still_deserializes() {
        // Concrete proof of backward compat: a JSONL line written
        // before this field existed has no `decision_trace` key. Serde
        // must default it to an empty Vec without erroring.
        let legacy = r#"{
            "entry_id": "legacy-1",
            "timestamp": "2025-01-01T00:00:00Z",
            "sequence": 1,
            "decision": "Allow",
            "decision_source": "scorer",
            "norm_action": {
                "action_type": {"domain": "email", "verb": "send"},
                "channel": "gmail",
                "entities": {},
                "execution": {"surface_tool": "test", "surface_command": "test cmd"}
            },
            "norm_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "raw_tool_call": {"tool": "test"},
            "risk_score": null,
            "scoring_detail": null,
            "agent_id": "agent-1",
            "session_id": null,
            "task_goal": null,
            "org_id": "org-1",
            "environment": "test",
            "engine_version": "0.1.0",
            "pack_id": "test-pack",
            "pack_version": "1.0",
            "dsl_version": "1.0",
            "human_review": null,
            "token_id": null,
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "entry_hash": "x",
            "signature": "y",
            "correction_of": null,
            "failed_open_context": null,
            "retroactive_decision": null
        }"#;
        let parsed: AuditEntry = serde_json::from_str(legacy)
            .expect("legacy entry without decision_trace must deserialize");
        assert!(parsed.decision_trace.is_empty());
    }
}
