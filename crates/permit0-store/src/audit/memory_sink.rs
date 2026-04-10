#![forbid(unsafe_code)]

use std::sync::RwLock;

use crate::audit::chain::{verify_chain_link, verify_entry_hash};
use crate::audit::sink::{AuditError, AuditSink};
use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// In-memory audit sink for testing and development.
pub struct InMemoryAuditSink {
    entries: RwLock<Vec<AuditEntry>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Get all entries (for testing).
    pub fn all_entries(&self) -> Vec<AuditEntry> {
        self.entries.read().unwrap().clone()
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for InMemoryAuditSink {
    fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut guard = self
            .entries
            .write()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        guard.push(entry.clone());
        Ok(())
    }

    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        let guard = self
            .entries
            .read()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let limit = filter.limit.unwrap_or(100) as usize;

        let results: Vec<AuditEntry> = guard
            .iter()
            .rev()
            .filter(|e| {
                if let Some(ref at) = filter.action_type {
                    let action_str = e.norm_action.action_type.as_action_str();
                    if !action_str.starts_with(at.as_str()) {
                        return false;
                    }
                }
                if let Some(ref d) = filter.decision {
                    if e.decision != *d {
                        return false;
                    }
                }
                if let Some(ref t) = filter.tier {
                    match &e.risk_score {
                        Some(rs) if rs.tier == *t => {}
                        _ => return false,
                    }
                }
                if let Some(ref sid) = filter.session_id {
                    if e.session_id.as_deref() != Some(sid.as_str()) {
                        return false;
                    }
                }
                if let Some(ref since) = filter.since {
                    if e.timestamp.as_str() < since.as_str() {
                        return false;
                    }
                }
                if let Some(ref until) = filter.until {
                    if e.timestamp.as_str() > until.as_str() {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect();

        Ok(results)
    }

    fn verify_chain(&self, from: u64, to: u64) -> Result<ChainVerification, AuditError> {
        let guard = self
            .entries
            .read()
            .map_err(|e| AuditError::Io(e.to_string()))?;

        // Find entries in range
        let range: Vec<&AuditEntry> = guard
            .iter()
            .filter(|e| e.sequence >= from && e.sequence <= to)
            .collect();

        if range.is_empty() {
            return Ok(ChainVerification {
                valid: true,
                entries_checked: 0,
                first_broken_at: None,
                failure_reason: None,
            });
        }

        // Verify each entry's hash
        for entry in &range {
            if !verify_entry_hash(entry) {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: entry.sequence - from,
                    first_broken_at: Some(entry.sequence),
                    failure_reason: Some(format!(
                        "Entry {} has invalid hash",
                        entry.sequence
                    )),
                });
            }
        }

        // Verify chain links
        for window in range.windows(2) {
            if !verify_chain_link(window[0], window[1]) {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: window[1].sequence - from,
                    first_broken_at: Some(window[1].sequence),
                    failure_reason: Some(format!(
                        "Chain broken between {} and {}",
                        window[0].sequence, window[1].sequence
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::{compute_entry_hash, GENESIS_HASH};
    use crate::audit::signer::{AuditSigner, Ed25519Signer};
    use crate::audit::types::AuditEntry;
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_signed_entry(
        seq: u64,
        prev_hash: &str,
        signer: &Ed25519Signer,
    ) -> AuditEntry {
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
        entry.signature = signer.sign(&entry.entry_hash);
        entry
    }

    #[test]
    fn append_and_query() {
        let sink = InMemoryAuditSink::new();
        let signer = Ed25519Signer::generate();
        let e1 = make_signed_entry(1, GENESIS_HASH, &signer);
        let e2 = make_signed_entry(2, &e1.entry_hash, &signer);

        sink.append(&e1).unwrap();
        sink.append(&e2).unwrap();

        let all = sink.query(&AuditFilter::default()).unwrap();
        assert_eq!(all.len(), 2);
        // Newest first
        assert_eq!(all[0].sequence, 2);
        assert_eq!(all[1].sequence, 1);
    }

    #[test]
    fn verify_chain_valid() {
        let sink = InMemoryAuditSink::new();
        let signer = Ed25519Signer::generate();
        let e1 = make_signed_entry(1, GENESIS_HASH, &signer);
        let e2 = make_signed_entry(2, &e1.entry_hash, &signer);
        let e3 = make_signed_entry(3, &e2.entry_hash, &signer);

        sink.append(&e1).unwrap();
        sink.append(&e2).unwrap();
        sink.append(&e3).unwrap();

        let result = sink.verify_chain(1, 3).unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 3);
    }

    #[test]
    fn verify_chain_tampered_entry() {
        let sink = InMemoryAuditSink::new();
        let signer = Ed25519Signer::generate();
        let e1 = make_signed_entry(1, GENESIS_HASH, &signer);
        let mut e2 = make_signed_entry(2, &e1.entry_hash, &signer);
        e2.decision = Permission::Deny; // tamper without rehashing

        sink.append(&e1).unwrap();
        sink.append(&e2).unwrap();

        let result = sink.verify_chain(1, 2).unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_broken_at, Some(2));
    }

    #[test]
    fn verify_chain_broken_link() {
        let sink = InMemoryAuditSink::new();
        let signer = Ed25519Signer::generate();
        let e1 = make_signed_entry(1, GENESIS_HASH, &signer);
        let e2 = make_signed_entry(2, "wrong_prev_hash", &signer);

        sink.append(&e1).unwrap();
        sink.append(&e2).unwrap();

        let result = sink.verify_chain(1, 2).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn query_with_filters() {
        let sink = InMemoryAuditSink::new();
        let signer = Ed25519Signer::generate();

        let mut e1 = make_signed_entry(1, GENESIS_HASH, &signer);
        e1.decision = Permission::Allow;
        e1.entry_hash = compute_entry_hash(&e1);
        e1.signature = signer.sign(&e1.entry_hash);

        let mut e2 = make_signed_entry(2, &e1.entry_hash, &signer);
        e2.decision = Permission::Deny;
        e2.entry_hash = compute_entry_hash(&e2);
        e2.signature = signer.sign(&e2.entry_hash);

        sink.append(&e1).unwrap();
        sink.append(&e2).unwrap();

        // Filter by decision
        let denies = sink
            .query(&AuditFilter {
                decision: Some(Permission::Deny),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].sequence, 2);
    }
}
