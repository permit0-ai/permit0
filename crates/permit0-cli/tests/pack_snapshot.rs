//! Engine-level snapshot test for the pack taxonomy refactor.
//!
//! Loads `packs/email/` via the production pack-loader, normalizes a
//! fixed corpus of `RawToolCall`s, and asserts each one produces the
//! exact same canonicalized NormAction across PRs that move files
//! around. Catches drift between PR 3's directory restructure and
//! PR 4+'s subsequent shape changes.
//!
//! When the snapshot intentionally changes (e.g. a new entity is
//! extracted), update the expected blocks here in the same commit
//! that introduces the change. A drifting snapshot in a "no-op"
//! refactor PR is the bug this test exists to catch.

use permit0_normalize::{NormalizeCtx, NormalizerRegistry};
use permit0_types::{NormAction, RawToolCall};
use serde_json::json;
use std::path::Path;

/// Build a `NormalizerRegistry` populated from the email pack. Mirrors
/// the production load path but stays in the test process so we don't
/// shell out to the CLI and bring scoring/audit/etc. into the picture.
///
/// Looks for the pack at the schema v2 owner-namespaced location first
/// (`packs/permit0/email/`), then falls back to the legacy flat path
/// (`packs/email/`). Same fixture survives PR 3's file move.
fn build_email_registry() -> NormalizerRegistry {
    let root = workspace_root();
    let pack_dir = {
        let owner_ns = root.join("packs").join("permit0").join("email");
        if owner_ns.is_dir() {
            owner_ns
        } else {
            root.join("packs").join("email")
        }
    };
    let mut reg = NormalizerRegistry::new();

    // Walk normalizers/ at depth 1 AND depth 2 to handle both the
    // legacy flat layout (PR 2) and the per-channel layout (PR 4 of
    // the pack taxonomy refactor). Stable across the migration window.
    let normalizers = pack_dir.join("normalizers");
    let mut yamls: Vec<std::path::PathBuf> = Vec::new();
    walk_yamls(&normalizers, &mut yamls);
    yamls.sort();
    for path in &yamls {
        let basename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if basename.starts_with('_') || basename == "aliases.yaml" {
            continue;
        }
        let yaml = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let n = permit0_dsl::normalizer::DslNormalizer::from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        reg.register(std::sync::Arc::new(n))
            .unwrap_or_else(|e| panic!("register {}: {e}", path.display()));
    }

    // Aliases — pack-root for PR 2, per-channel for PR 4. Try both.
    let pack_root_aliases = pack_dir.join("aliases.yaml");
    if pack_root_aliases.is_file() {
        let yaml = std::fs::read_to_string(&pack_root_aliases).unwrap();
        reg.install_aliases_yaml(&yaml).unwrap();
    }
    for entry in std::fs::read_dir(&normalizers)
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let channel_aliases = path.join("aliases.yaml");
        if channel_aliases.is_file() {
            let yaml = std::fs::read_to_string(&channel_aliases).unwrap();
            reg.install_aliases_yaml(&yaml).unwrap();
        }
    }

    reg
}

/// Walk `dir` and append every `.yaml` file (at depth 1 and depth 2,
/// not deeper) to `out`. Skips the directory itself and any non-yaml
/// entries. Mirrors the loader's traversal so the snapshot test sees
/// what the engine sees.
fn walk_yamls(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Depth 2 (per-channel subdirs).
            if let Ok(rd2) = std::fs::read_dir(&path) {
                for sub in rd2.flatten() {
                    let p = sub.path();
                    if p.is_file() && p.extension().is_some_and(|e| e == "yaml") {
                        out.push(p);
                    }
                }
            }
        } else if path.is_file() && path.extension().is_some_and(|e| e == "yaml") {
            out.push(path);
        }
    }
}

fn workspace_root() -> std::path::PathBuf {
    // tests/ runs with CARGO_MANIFEST_DIR == crates/permit0-cli/.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Canonical fingerprint for a NormAction: action_type + channel +
/// entities (sorted) + execution metadata. Serializes via serde_json
/// in canonical form (sorted object keys are guaranteed by serde_json's
/// `Map<String, Value>` insertion order, which we control by inserting
/// in alphabetic order below).
fn fingerprint(n: &NormAction) -> String {
    let mut entities: Vec<(&String, &serde_json::Value)> = n.entities.iter().collect();
    entities.sort_by_key(|(k, _)| k.as_str());
    let entities_obj: serde_json::Map<_, _> = entities
        .into_iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let canonical = json!({
        "action_type": n.action_type.as_action_str(),
        "channel": n.channel,
        "entities": entities_obj,
        "execution": {
            "surface_tool": n.execution.surface_tool,
            "surface_command": n.execution.surface_command,
        },
    });
    serde_json::to_string(&canonical).unwrap()
}

fn normalize_or_panic(reg: &NormalizerRegistry, raw: RawToolCall) -> NormAction {
    let ctx = NormalizeCtx::new().with_org_domain("acme.com");
    reg.normalize(&raw, &ctx)
        .unwrap_or_else(|e| panic!("normalize failed for {:?}: {e}", raw.tool_name))
}

fn raw(tool: &str, params: serde_json::Value) -> RawToolCall {
    RawToolCall {
        tool_name: tool.into(),
        parameters: params,
        metadata: Default::default(),
    }
}

#[test]
fn snapshot_gmail_send_to_external() {
    let reg = build_email_registry();
    let n = normalize_or_panic(
        &reg,
        raw(
            "gmail_send",
            json!({
                "to": "bob@external.com",
                "subject": "Hello",
                "body": "Test"
            }),
        ),
    );
    insta_assert_eq(
        &fingerprint(&n),
        // EXPECTED — update only when the snapshot intentionally changes.
        r#"{"action_type":"email.send","channel":"gmail","entities":{"body":"Test","domain":"external.com","recipient_scope":"external","subject":"Hello","to":"bob@external.com"},"execution":{"surface_command":"gmail_send","surface_tool":"gmail_send"}}"#,
    );
}

#[test]
fn snapshot_outlook_send_to_external() {
    let reg = build_email_registry();
    let n = normalize_or_panic(
        &reg,
        raw(
            "outlook_send",
            json!({
                "to": "alice@external.com",
                "subject": "Meeting",
                "body": "Notes"
            }),
        ),
    );
    insta_assert_eq(
        &fingerprint(&n),
        r#"{"action_type":"email.send","channel":"outlook","entities":{"body":"Notes","domain":"external.com","recipient_scope":"external","subject":"Meeting","to":"alice@external.com"},"execution":{"surface_command":"outlook_send","surface_tool":"outlook_send"}}"#,
    );
}

#[test]
fn snapshot_gmail_archive() {
    let reg = build_email_registry();
    let n = normalize_or_panic(&reg, raw("gmail_archive", json!({"message_id": "msg-123"})));
    insta_assert_eq(
        &fingerprint(&n),
        r#"{"action_type":"email.archive","channel":"gmail","entities":{"message_id":"msg-123"},"execution":{"surface_command":"gmail_archive","surface_tool":"gmail_archive"}}"#,
    );
}

#[test]
fn snapshot_outlook_search() {
    let reg = build_email_registry();
    let n = normalize_or_panic(&reg, raw("outlook_search", json!({"query": "from:boss"})));
    insta_assert_eq(
        &fingerprint(&n),
        r#"{"action_type":"email.search","channel":"outlook","entities":{"query":"from:boss"},"execution":{"surface_command":"outlook_search","surface_tool":"outlook_search"}}"#,
    );
}

#[test]
fn snapshot_outlook_list_drafts() {
    let reg = build_email_registry();
    let n = normalize_or_panic(
        &reg,
        raw("outlook_list_drafts", json!({"filter": "isDraft eq true"})),
    );
    insta_assert_eq(
        &fingerprint(&n),
        r#"{"action_type":"email.list_drafts","channel":"outlook","entities":{"query":"isDraft eq true"},"execution":{"surface_command":"outlook_list_drafts","surface_tool":"outlook_list_drafts"}}"#,
    );
}

#[test]
fn snapshot_alias_google_send_routes_to_gmail_send() {
    // Google's official Gmail MCP exposes `send_message`. The alias
    // rewrites this to `gmail_send` before normalizer dispatch, so
    // surface_tool/surface_command also reflect the rewritten name —
    // per registry.rs:91-94, the registry hands the rewritten
    // RawToolCall to the normalizer, collapsing the foreign name in
    // the audit trail. This is the intentional invariant the snapshot
    // pins down.
    let reg = build_email_registry();
    let n = normalize_or_panic(
        &reg,
        raw(
            "send_message",
            json!({
                "to": "bob@external.com",
                "subject": "Hi",
                "body": "ok"
            }),
        ),
    );
    insta_assert_eq(
        &fingerprint(&n),
        r#"{"action_type":"email.send","channel":"gmail","entities":{"body":"ok","domain":"external.com","recipient_scope":"external","subject":"Hi","to":"bob@external.com"},"execution":{"surface_command":"gmail_send","surface_tool":"gmail_send"}}"#,
    );
}

/// Local approximation of `insta::assert_eq`. Prints both sides on
/// mismatch to make snapshot diffs reviewable in CI logs without
/// adding the `insta` dep.
fn insta_assert_eq(actual: &str, expected: &str) {
    if actual != expected {
        panic!(
            "snapshot mismatch\n--- expected ---\n{expected}\n--- actual   ---\n{actual}\n----------------\n"
        );
    }
}
