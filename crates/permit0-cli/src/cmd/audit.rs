#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use permit0_store::audit::{AuditEntry, Ed25519Verifier, chain};

/// Verify a JSONL audit file: chain integrity + ed25519 signatures.
pub fn verify(path: &str, public_key: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?;

    let verifier = Ed25519Verifier::from_hex(public_key)
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;

    let entries = parse_entries(&content)?;
    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("Verifying {} audit entries...", entries.len());
    println!();

    // Verify each entry hash + signature
    for (i, entry) in entries.iter().enumerate() {
        if !chain::verify_entry_hash(entry) {
            bail!(
                "FAILED: entry {} (seq {}) has invalid hash",
                i + 1,
                entry.sequence
            );
        }
        if !verifier.verify(&entry.entry_hash, &entry.signature) {
            bail!(
                "FAILED: entry {} (seq {}) has invalid signature",
                i + 1,
                entry.sequence
            );
        }
    }

    // Verify chain links
    for window in entries.windows(2) {
        if !chain::verify_chain_link(&window[0], &window[1]) {
            bail!(
                "FAILED: chain broken between seq {} and {}",
                window[0].sequence,
                window[1].sequence
            );
        }
    }

    println!("  Chain integrity .... VALID");
    println!("  Signatures ........ ALL VALID ({} checked)", entries.len());
    println!("  First entry seq ... {}", entries.first().unwrap().sequence);
    println!("  Last entry seq .... {}", entries.last().unwrap().sequence);
    println!();
    println!("PASS: audit trail is intact and authentic.");
    Ok(())
}

/// Inspect a JSONL audit file: show summary and entries.
pub fn inspect(path: &str, limit: usize) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?;

    let entries = parse_entries(&content)?;
    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("Audit file: {path}");
    println!("Total entries: {}", entries.len());
    println!(
        "Sequence range: {} — {}",
        entries.first().unwrap().sequence,
        entries.last().unwrap().sequence
    );
    println!();

    let show = entries.len().min(limit);
    for entry in entries.iter().take(show) {
        let action_str = entry.norm_action.action_type.as_action_str();
        let decision = format!("{:?}", entry.decision);
        let ts = &entry.timestamp;

        println!(
            "  seq={:<3} | {} | {:<20} | {:<6} | hash={}...",
            entry.sequence,
            ts,
            action_str,
            decision,
            &entry.entry_hash[..16],
        );
    }
    if show < entries.len() {
        println!("  ... ({} more entries not shown)", entries.len() - show);
    }
    Ok(())
}

/// Dump full JSON of a specific entry by sequence number.
pub fn dump_entry(path: &str, sequence: u64) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?;

    let entries = parse_entries(&content)?;
    let entry = entries
        .iter()
        .find(|e| e.sequence == sequence)
        .with_context(|| format!("no entry with sequence {sequence}"))?;

    let json = serde_json::to_string_pretty(entry)?;
    println!("{json}");
    Ok(())
}

fn parse_entries(content: &str) -> Result<Vec<AuditEntry>> {
    let mut entries = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)
            .with_context(|| format!("invalid JSON on line {}", i + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}
