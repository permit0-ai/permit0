//! Keep `docs/taxonomy.md` in sync with the canonical
//! `permit0_types::taxonomy` enum.
//!
//! The doc is hand-written (it carries prose, threat scenarios,
//! "✅ shipped" markers) but the enum is the source of truth. CI
//! enforces both halves stay aligned:
//!
//! - **Every `Domain::Verb` in the enum appears in the doc.**
//!   Missing a new verb in the doc is a CI failure, not a release
//!   surprise.
//! - **Every `domain.verb` mentioned in the doc parses as a valid
//!   `ActionType`.** A typo or stale reference fails the build.
//!
//! When the enum changes, edit `docs/taxonomy.md` in the same PR.
//! That's the price for keeping the doc human-readable instead of
//! auto-generated.

use permit0_test_utils::load_test_fixture;
use permit0_types::{ALL_DOMAINS, ActionType, all_action_types};

const TAXONOMY_DOC: &str = "docs/taxonomy.md";

#[test]
fn every_action_type_in_enum_appears_in_doc() {
    let doc = load_test_fixture(TAXONOMY_DOC);
    let mut missing = Vec::new();
    for at in all_action_types() {
        let needle = format!("`{}`", at.as_action_str());
        if !doc.contains(&needle) {
            missing.push(at.as_action_str());
        }
    }
    assert!(
        missing.is_empty(),
        "the following action_types are in `permit0_types::taxonomy` \
         but missing from {TAXONOMY_DOC} (look for them as `domain.verb` \
         in backticks): {missing:?}\n\n\
         Action: add a row in the matching `### <domain>` section of {TAXONOMY_DOC}.",
    );
}

#[test]
fn every_action_type_mentioned_in_doc_is_valid() {
    let doc = load_test_fixture(TAXONOMY_DOC);
    // Anchor on real domain names from the enum so file paths
    // (`docs/taxonomy.md`), version ranges (`1.x`), Rust paths
    // (`permit0_types::taxonomy`), and the literal placeholder
    // `domain.verb` don't get flagged as invalid action types.
    let known_domains: std::collections::BTreeSet<&'static str> =
        ALL_DOMAINS.iter().map(|d| d.as_str()).collect();

    let mut invalid: Vec<String> = Vec::new();
    let mut idx = 0usize;
    while let Some(open) = doc[idx..].find('`') {
        let start = idx + open + 1;
        let close_off = match doc[start..].find('`') {
            Some(o) => o,
            None => break,
        };
        let token = &doc[start..start + close_off];
        idx = start + close_off + 1;

        if !looks_like_action_type(token, &known_domains) {
            continue;
        }
        if ActionType::parse(token).is_err() {
            invalid.push(token.to_string());
        }
    }
    invalid.sort();
    invalid.dedup();
    assert!(
        invalid.is_empty(),
        "the following `domain.verb` references in {TAXONOMY_DOC} do \
         not parse as valid ActionTypes (typo or stale reference): \
         {invalid:?}\n\n\
         Action: either fix the spelling, or — if the verb is intentional \
         and new — add the variant to `permit0_types::taxonomy::Verb` first."
    );
}

/// "This token looks like a `domain.verb` action type" check.
///
/// Anchored on the closed set of domain names so non-action-type
/// dotted strings (filenames like `dsl.md`, version ranges like `1.x`,
/// the literal `domain.verb` placeholder in tutorial text) don't get
/// scrutinized.
fn looks_like_action_type(s: &str, known_domains: &std::collections::BTreeSet<&str>) -> bool {
    let (domain, verb) = match s.split_once('.') {
        Some(pair) => pair,
        None => return false,
    };
    if !known_domains.contains(domain) {
        return false;
    }
    if verb.is_empty() {
        return false;
    }
    if s.matches('.').count() != 1 {
        return false;
    }
    if s.chars()
        .any(|c| c == '/' || c == ' ' || c == '\\' || c == ':')
    {
        return false;
    }
    verb.chars()
        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
}

#[test]
fn looks_like_action_type_filter() {
    let domains: std::collections::BTreeSet<&str> =
        ALL_DOMAINS.iter().map(|d| d.as_str()).collect();
    // True positives — real action types.
    assert!(looks_like_action_type("email.send", &domains));
    assert!(looks_like_action_type("email.set_forwarding", &domains));
    assert!(looks_like_action_type("unknown.unclassified", &domains));
    // False positives the heuristic must reject.
    assert!(!looks_like_action_type("README.md", &domains));
    assert!(!looks_like_action_type("1.x", &domains));
    assert!(!looks_like_action_type("docs/taxonomy.md", &domains));
    assert!(!looks_like_action_type("permit0_types::taxonomy", &domains));
    assert!(!looks_like_action_type("a.b.c", &domains));
    assert!(!looks_like_action_type("", &domains));
    assert!(!looks_like_action_type(".foo", &domains));
    assert!(!looks_like_action_type("foo.", &domains));
    assert!(!looks_like_action_type("dsl.md", &domains));
    assert!(!looks_like_action_type("pack.yaml", &domains));
    assert!(!looks_like_action_type("permit.md", &domains));
    assert!(!looks_like_action_type("domain.verb", &domains));
}
