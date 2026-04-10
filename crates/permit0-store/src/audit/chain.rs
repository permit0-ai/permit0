#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::audit::types::AuditEntry;

/// The genesis hash for the first entry in the chain.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::AuditEntry;
    use permit0_types::{NormAction, ActionType, ExecutionMeta, Permission};
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
            token_id: None,
            prev_hash: prev_hash.into(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
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
}
