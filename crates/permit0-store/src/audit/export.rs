#![forbid(unsafe_code)]

use std::io::Write;

use crate::audit::types::AuditEntry;

/// Export entries as JSONL (one JSON object per line).
pub fn export_jsonl(entries: &[AuditEntry], writer: &mut dyn Write) -> Result<(), std::io::Error> {
    for entry in entries {
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        writeln!(writer, "{line}")?;
    }
    Ok(())
}

/// Export entries as CSV.
pub fn export_csv(entries: &[AuditEntry], writer: &mut dyn Write) -> Result<(), std::io::Error> {
    // Header
    writeln!(
        writer,
        "entry_id,timestamp,sequence,decision,decision_source,action_type,channel,risk_score,tier,agent_id,session_id,org_id,environment,prev_hash,entry_hash"
    )?;

    for entry in entries {
        let action_str = entry.norm_action.action_type.as_action_str();
        let risk_score = entry
            .risk_score
            .as_ref()
            .map(|rs| rs.score.to_string())
            .unwrap_or_default();
        let tier = entry
            .risk_score
            .as_ref()
            .map(|rs| format!("{}", rs.tier))
            .unwrap_or_default();
        let session_id = entry.session_id.as_deref().unwrap_or("");

        writeln!(
            writer,
            "{},{},{},{:?},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&entry.entry_id),
            csv_escape(&entry.timestamp),
            entry.sequence,
            entry.decision,
            csv_escape(&entry.decision_source),
            csv_escape(&action_str),
            csv_escape(&entry.norm_action.channel),
            risk_score,
            tier,
            csv_escape(&entry.agent_id),
            csv_escape(session_id),
            csv_escape(&entry.org_id),
            csv_escape(&entry.environment),
            csv_escape(&entry.prev_hash),
            csv_escape(&entry.entry_hash),
        )?;
    }
    Ok(())
}

/// Escape a CSV field if it contains commas, quotes, or newlines.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::{GENESIS_HASH, compute_entry_hash};
    use crate::audit::types::AuditEntry;
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_entry(seq: u64) -> AuditEntry {
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
            session_id: Some("sess-1".into()),
            task_goal: None,
            org_id: "org-1".into(),
            environment: "test".into(),
            engine_version: "0.1.0".into(),
            pack_id: "test-pack".into(),
            pack_version: "1.0".into(),
            dsl_version: "1.0".into(),
            human_review: None,
            token_id: None,
            prev_hash: GENESIS_HASH.into(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: None,
            retroactive_decision: None,
        };
        entry.entry_hash = compute_entry_hash(&entry);
        entry
    }

    #[test]
    fn jsonl_export_roundtrip() {
        let entries = vec![make_entry(1), make_entry(2)];
        let mut buf = Vec::new();
        export_jsonl(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in &lines {
            let parsed: AuditEntry = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.decision, Permission::Allow);
        }
    }

    #[test]
    fn csv_export_has_header() {
        let entries = vec![make_entry(1)];
        let mut buf = Vec::new();
        export_csv(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 row
        assert!(lines[0].starts_with("entry_id,"));
        assert!(lines[1].contains("entry-1"));
    }

    #[test]
    fn csv_escape_commas() {
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("simple"), "simple");
    }
}
