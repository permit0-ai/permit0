#![forbid(unsafe_code)]

//! Manifest-level pack validation.
//!
//! Per-file validation (normalizer YAML, risk rule YAML) lives in the
//! pre-existing [`crate::validate`] module. This module checks the
//! manifest itself plus cross-pack invariants that span the manifest
//! and the filesystem:
//!
//! - Schema version (`pack_format: 2`).
//! - Trust tier consistency (declared vs derived).
//! - Action type taxonomy compliance (every entry is a real `domain.verb`).
//! - Coverage (every action type has a normalizer + a risk rule).
//! - Orphans (every normalizer / risk rule maps to a listed action type).
//! - Security lint (no `allow` rule on critical action types).
//!
//! The validator returns a list of [`PackViolation`] rather than panicking
//! so all problems surface in one pass — useful for CI output.

use std::collections::BTreeSet;

use crate::schema::pack::{
    PACK_FORMAT_VERSION, PackManifest, TrustTier, derive_trust_tier, extract_owner,
};
use crate::schema::risk_rule::{MutationDef, RiskRuleDef, RuleDef, SessionRuleDef};
use permit0_types::ActionType;

/// Action types that MUST NOT carry an `allow` decision in any rule.
/// These are bypass-class operations: their security impact is high
/// enough that the engine should always require human-in-the-loop or
/// explicit policy override, regardless of pack tier.
///
/// Maintained as a flat list rather than per-domain because the set is
/// small and one-off; if it grows, restructure into a `BTreeMap<Domain, &[Verb]>`.
pub const ALWAYS_HUMAN_ACTION_TYPES: &[&str] = &[
    "email.set_forwarding",
    "email.add_delegate",
    "iam.create",
    "iam.delete",
    "iam.assign_role",
    "iam.revoke_role",
    "iam.reset_password",
    "iam.generate_api_key",
    "secret.get",
    "secret.create",
    "secret.update",
    "secret.rotate",
    "payment.charge",
    "payment.transfer",
    "payment.refund",
];

/// One violation produced by [`validate_pack`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackViolation {
    pub code: ViolationCode,
    pub message: String,
}

/// Categorical code for a violation. Stable identifier so CI can opt
/// individual checks in or out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    /// `pack_format` is missing or not equal to the supported version.
    SchemaVersion,
    /// `vendor` field is set in a v2 manifest (dropped in schema v2).
    LegacyVendorField,
    /// `permit0_pack` is missing the `<owner>/<name>` slash separator.
    MalformedPermit0Pack,
    /// Self-declared `trust_tier` disagrees with the value derived from owner.
    TrustTierMismatch,
    /// An entry in `action_types:` is not a recognized `domain.verb` from
    /// the action taxonomy.
    UnknownActionType,
    /// An action type listed in `action_types:` has no normalizer mapping
    /// to it.
    MissingNormalizer,
    /// An action type listed in `action_types:` has no risk rule scoring it.
    MissingRiskRule,
    /// A normalizer maps to an action type not listed in the pack's
    /// `action_types:`.
    OrphanNormalizer,
    /// A risk rule scores an action type not listed in the pack's
    /// `action_types:`.
    OrphanRiskRule,
    /// A rule for a critical action type
    /// (see [`ALWAYS_HUMAN_ACTION_TYPES`]) lacks any `gate` mutation
    /// across both `rules` and `session_rules`. Critical actions must
    /// require explicit human review; gateless rules can let the engine
    /// auto-approve based on score alone.
    MissingGateOnCriticalAction,
    /// A normalizer's `match.tool` doesn't satisfy the channel's
    /// `tool_pattern` glob. Indicates cross-channel poisoning — a
    /// normalizer placed in `normalizers/gmail/` claiming an `outlook_*`
    /// tool would route Outlook traffic through gmail-channel risk
    /// rules and aliases.
    ToolPatternMismatch,
    /// A `normalizers/<channel>/` directory exists but lacks an
    /// `_channel.yaml`. The validator can't enforce `tool_pattern`
    /// without the manifest; treat as warning rather than hard error
    /// to keep coexistence with PR 2's flat normalizer layout.
    MissingChannelManifest,
}

/// Run every manifest-level check and return a flat list of violations.
///
/// `normalizer_action_types` is the set of action types produced by the
/// pack's normalizers (extracted from each normalizer's
/// `produces.action_type` field).
///
/// `risk_rule_targets` is the list of (action_type, rule_def) pairs from
/// the pack's risk rules.
///
/// Both are passed in by the caller so this module stays IO-free; the
/// CLI subcommand handles loading.
pub fn validate_pack(
    manifest: &PackManifest,
    normalizer_action_types: &BTreeSet<String>,
    risk_rule_targets: &[(String, RiskRuleDef)],
) -> Vec<PackViolation> {
    let mut out = Vec::new();
    check_schema_version(manifest, &mut out);
    check_legacy_vendor(manifest, &mut out);
    check_trust_tier(manifest, &mut out);
    check_action_types_taxonomy(manifest, &mut out);
    check_coverage(
        manifest,
        normalizer_action_types,
        risk_rule_targets,
        &mut out,
    );
    check_orphans(
        manifest,
        normalizer_action_types,
        risk_rule_targets,
        &mut out,
    );
    check_security_lint(risk_rule_targets, &mut out);
    out
}

fn check_schema_version(m: &PackManifest, out: &mut Vec<PackViolation>) {
    match m.pack_format {
        Some(v) if v == PACK_FORMAT_VERSION => {}
        Some(v) => out.push(PackViolation {
            code: ViolationCode::SchemaVersion,
            message: format!(
                "pack_format: {v} is not supported; expected {PACK_FORMAT_VERSION}"
            ),
        }),
        None => out.push(PackViolation {
            code: ViolationCode::SchemaVersion,
            message: format!(
                "pack_format is missing; v2 manifests must declare `pack_format: {PACK_FORMAT_VERSION}`"
            ),
        }),
    }
}

fn check_legacy_vendor(m: &PackManifest, out: &mut Vec<PackViolation>) {
    if m.vendor.is_some() {
        out.push(PackViolation {
            code: ViolationCode::LegacyVendorField,
            message:
                "`vendor:` field is removed in schema v2; owner is derived from `permit0_pack:`"
                    .to_string(),
        });
    }
}

fn check_trust_tier(m: &PackManifest, out: &mut Vec<PackViolation>) {
    let Some(owner) = extract_owner(&m.permit0_pack) else {
        out.push(PackViolation {
            code: ViolationCode::MalformedPermit0Pack,
            message: format!(
                "permit0_pack: \"{}\" must be \"<owner>/<name>\"",
                m.permit0_pack
            ),
        });
        return;
    };
    let derived = derive_trust_tier(owner);
    if let Some(declared) = m.trust_tier
        && declared != derived
    {
        out.push(PackViolation {
            code: ViolationCode::TrustTierMismatch,
            message: format!(
                "declared trust_tier: {declared:?} disagrees with derived: {derived:?} (owner=\"{owner}\")"
            ),
        });
    }
    // Phase 2 tiers cannot be derived in Phase 1 — flag any pack that
    // self-attests to one. The mismatch above already catches owner=permit0
    // declaring Verified/Experimental; this catches non-permit0 owners
    // declaring Verified/Experimental too.
    if matches!(
        m.trust_tier,
        Some(TrustTier::Verified | TrustTier::Experimental)
    ) {
        out.push(PackViolation {
            code: ViolationCode::TrustTierMismatch,
            message: "trust_tier: verified/experimental requires Phase 2 signing infrastructure"
                .to_string(),
        });
    }
}

fn check_action_types_taxonomy(m: &PackManifest, out: &mut Vec<PackViolation>) {
    for at in &m.action_types {
        if ActionType::parse(at).is_err() {
            out.push(PackViolation {
                code: ViolationCode::UnknownActionType,
                message: format!(
                    "action_types entry \"{at}\" is not a valid `domain.verb` from the taxonomy"
                ),
            });
        }
    }
}

fn check_coverage(
    m: &PackManifest,
    normalizer_action_types: &BTreeSet<String>,
    risk_rule_targets: &[(String, RiskRuleDef)],
    out: &mut Vec<PackViolation>,
) {
    let risk_targets: BTreeSet<&str> = risk_rule_targets
        .iter()
        .map(|(at, _)| at.as_str())
        .collect();

    for at in &m.action_types {
        if !normalizer_action_types.contains(at) {
            out.push(PackViolation {
                code: ViolationCode::MissingNormalizer,
                message: format!("action_types lists \"{at}\" but no normalizer produces it"),
            });
        }
        if !risk_targets.contains(at.as_str()) {
            out.push(PackViolation {
                code: ViolationCode::MissingRiskRule,
                message: format!("action_types lists \"{at}\" but no risk rule covers it"),
            });
        }
    }
}

fn check_orphans(
    m: &PackManifest,
    normalizer_action_types: &BTreeSet<String>,
    risk_rule_targets: &[(String, RiskRuleDef)],
    out: &mut Vec<PackViolation>,
) {
    let listed: BTreeSet<&str> = m.action_types.iter().map(String::as_str).collect();

    for at in normalizer_action_types {
        if !listed.contains(at.as_str()) {
            out.push(PackViolation {
                code: ViolationCode::OrphanNormalizer,
                message: format!(
                    "normalizer produces \"{at}\" but it's not listed in action_types"
                ),
            });
        }
    }
    for (at, _) in risk_rule_targets {
        if !listed.contains(at.as_str()) {
            out.push(PackViolation {
                code: ViolationCode::OrphanRiskRule,
                message: format!("risk rule covers \"{at}\" but it's not listed in action_types"),
            });
        }
    }
}

/// Match a tool name against a `_channel.yaml` `tool_pattern` glob.
///
/// Supported wildcards (intentionally minimal):
/// - `*` matches any sequence of characters (including empty).
/// - Everything else matches literally.
///
/// Examples:
/// - `gmail_*` matches `gmail_send`, `gmail_archive`, but not
///   `outlook_send` or just `gmail`.
/// - `*` matches everything (escape hatch for legacy packs).
/// - `gmail_send` matches only the literal name.
///
/// We don't pull in the `glob` crate for one matcher — patterns are
/// short and the wildcard set is fixed. If patterns get more complex
/// (character classes, recursive globs), revisit.
pub fn tool_pattern_matches(pattern: &str, tool: &str) -> bool {
    // Split on `*` and verify the parts appear in order in `tool`.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcards — literal match.
        return parts[0] == tool;
    }
    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 {
            // First non-empty part must be a prefix.
            if !tool[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
        } else if idx == parts.len() - 1 {
            // Last non-empty part must be a suffix.
            return tool[cursor..].ends_with(part);
        } else {
            // Middle parts: any occurrence at-or-after `cursor`.
            match tool[cursor..].find(part) {
                Some(off) => cursor += off + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Walk every `normalizers/<channel>/` subdirectory of a pack and
/// verify each normalizer's `match.tool` satisfies the directory's
/// `_channel.yaml` `tool_pattern`. Surfaces:
/// - `ToolPatternMismatch` when a normalizer's tool name escapes
///   the pattern (cross-channel poisoning).
/// - `MissingChannelManifest` when a per-channel directory has
///   normalizer YAMLs but no `_channel.yaml` (warning).
///
/// IO-bound, so this lives outside the pure `validate_pack`
/// pipeline; the CLI calls it after the manifest checks. Returns an
/// empty vec if the pack is still on the flat layout (no per-channel
/// subdirectories).
pub fn validate_channel_directories(
    pack_dir: &std::path::Path,
) -> Result<Vec<PackViolation>, std::io::Error> {
    use crate::schema::pack::ChannelManifest;
    let mut violations = Vec::new();

    let normalizers_dir = pack_dir.join("normalizers");
    if !normalizers_dir.is_dir() {
        return Ok(violations);
    }

    for entry in std::fs::read_dir(&normalizers_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let basename = match path.file_name().and_then(|s| s.to_str()) {
            Some(b) => b,
            None => continue,
        };
        if basename.starts_with('_') || basename.starts_with('.') {
            continue;
        }

        // Try to load _channel.yaml for the pattern. Surface a
        // warning if missing; nothing else to enforce without it.
        let channel_yaml_path = path.join(crate::CHANNEL_MANIFEST_FILENAME);
        let pattern: Option<String> = if channel_yaml_path.is_file() {
            let yaml = std::fs::read_to_string(&channel_yaml_path)?;
            match serde_yaml::from_str::<ChannelManifest>(&yaml) {
                Ok(m) => m.tool_pattern,
                Err(_) => None,
            }
        } else {
            violations.push(PackViolation {
                code: ViolationCode::MissingChannelManifest,
                message: format!(
                    "normalizers/{basename}/ has normalizer YAMLs but no _channel.yaml \
                     declaring `tool_pattern:`; tool-pattern enforcement skipped"
                ),
            });
            None
        };

        let Some(pattern) = pattern else {
            // _channel.yaml exists but doesn't declare tool_pattern;
            // we already surfaced the manifest issue above (or chose
            // to silently allow patternless channel manifests for
            // back-compat). Skip enforcement.
            continue;
        };

        // Check every normalizer YAML in the channel directory.
        for sub in std::fs::read_dir(&path)? {
            let sub = sub?;
            let sub_path = sub.path();
            let sub_basename = match sub_path.file_name().and_then(|s| s.to_str()) {
                Some(b) => b,
                None => continue,
            };
            if !sub_path
                .extension()
                .is_some_and(|e| e == "yaml" || e == "yml")
            {
                continue;
            }
            if sub_basename == crate::CHANNEL_MANIFEST_FILENAME
                || sub_basename == crate::ALIASES_FILENAME
            {
                continue;
            }
            let yaml = std::fs::read_to_string(&sub_path)?;
            // Pull `match.tool` out without deserializing the full
            // normalizer schema. The normalizer DSL is permissive
            // enough that re-parsing here would couple the validator
            // to its evolution; a one-field probe is robust enough.
            let parsed: serde_yaml::Value = match serde_yaml::from_str(&yaml) {
                Ok(v) => v,
                Err(_) => continue, // schema-level error already surfaced elsewhere
            };
            let Some(tool) = parsed
                .get("match")
                .and_then(|m| m.get("tool"))
                .and_then(|t| t.as_str())
            else {
                continue;
            };
            if !tool_pattern_matches(&pattern, tool) {
                violations.push(PackViolation {
                    code: ViolationCode::ToolPatternMismatch,
                    message: format!(
                        "normalizers/{basename}/{sub_basename} has match.tool: \"{tool}\" \
                         which does not match channel pattern \"{pattern}\" — \
                         cross-channel poisoning suspected"
                    ),
                });
            }
        }
    }

    Ok(violations)
}

fn check_security_lint(risk_rule_targets: &[(String, RiskRuleDef)], out: &mut Vec<PackViolation>) {
    let critical: BTreeSet<&str> = ALWAYS_HUMAN_ACTION_TYPES.iter().copied().collect();
    for (at, rule) in risk_rule_targets {
        if !critical.contains(at.as_str()) {
            continue;
        }
        if !rule_has_gate(rule) {
            out.push(PackViolation {
                code: ViolationCode::MissingGateOnCriticalAction,
                message: format!(
                    "risk rule for critical action \"{at}\" must include at least one `gate:` \
                     mutation (across `rules` or `session_rules`); without one, the engine can \
                     auto-approve from score alone"
                ),
            });
        }
    }
}

/// Returns true if the risk rule contains at least one `Gate` mutation
/// anywhere in its `rules` or `session_rules` `then:` blocks.
fn rule_has_gate(rule: &RiskRuleDef) -> bool {
    rule.rules.iter().any(rule_branch_has_gate)
        || rule.session_rules.iter().any(session_branch_has_gate)
}

fn rule_branch_has_gate(branch: &RuleDef) -> bool {
    branch.then.iter().any(mutation_is_gate)
}

fn session_branch_has_gate(branch: &SessionRuleDef) -> bool {
    branch.then.iter().any(mutation_is_gate)
}

fn mutation_is_gate(m: &MutationDef) -> bool {
    matches!(m, MutationDef::Gate { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_manifest() -> PackManifest {
        PackManifest {
            pack_format: Some(2),
            name: "email".into(),
            version: "0.3.0".into(),
            permit0_pack: "permit0/email".into(),
            description: None,
            homepage: None,
            license: None,
            permit0_engine: None,
            taxonomy: None,
            action_types: vec![],
            maintainers: vec![],
            channels: Default::default(),
            trust_tier: None,
            signature: None,
            provenance: None,
            content_hash: None,
            normalizers: vec![],
            risk_rules: vec![],
            vendor: None,
            min_engine_version: None,
        }
    }

    #[test]
    fn minimal_v2_passes() {
        let m = minimal_manifest();
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.is_empty(), "expected zero violations, got: {v:#?}");
    }

    #[test]
    fn missing_pack_format_fails() {
        let mut m = minimal_manifest();
        m.pack_format = None;
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::SchemaVersion));
    }

    #[test]
    fn wrong_pack_format_fails() {
        let mut m = minimal_manifest();
        m.pack_format = Some(1);
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::SchemaVersion));
    }

    #[test]
    fn legacy_vendor_field_flagged() {
        let mut m = minimal_manifest();
        m.vendor = Some("permit0".into());
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::LegacyVendorField));
    }

    #[test]
    fn malformed_permit0_pack_flagged() {
        let mut m = minimal_manifest();
        m.permit0_pack = "no-slash".into();
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(
            v.iter()
                .any(|x| x.code == ViolationCode::MalformedPermit0Pack)
        );
    }

    #[test]
    fn declared_built_in_for_non_permit0_owner_flagged() {
        let mut m = minimal_manifest();
        m.permit0_pack = "alice/jira".into();
        m.trust_tier = Some(TrustTier::BuiltIn);
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::TrustTierMismatch));
    }

    #[test]
    fn declared_verified_phase_two_flagged() {
        let mut m = minimal_manifest();
        m.trust_tier = Some(TrustTier::Verified);
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::TrustTierMismatch));
    }

    #[test]
    fn unknown_action_type_flagged() {
        let mut m = minimal_manifest();
        m.action_types = vec!["bogus.invented".into()];
        let v = validate_pack(&m, &BTreeSet::new(), &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::UnknownActionType));
    }

    #[test]
    fn missing_normalizer_flagged() {
        let mut m = minimal_manifest();
        m.action_types = vec!["email.send".into()];
        // No normalizer; risk rule present.
        let mut risk = sample_risk_rule("email.send");
        risk.permit0_pack = "permit0/email".into();
        let v = validate_pack(&m, &BTreeSet::new(), &[("email.send".into(), risk)]);
        assert!(v.iter().any(|x| x.code == ViolationCode::MissingNormalizer));
    }

    #[test]
    fn missing_risk_rule_flagged() {
        let mut m = minimal_manifest();
        m.action_types = vec!["email.send".into()];
        let mut norms = BTreeSet::new();
        norms.insert("email.send".to_string());
        let v = validate_pack(&m, &norms, &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::MissingRiskRule));
    }

    #[test]
    fn orphan_normalizer_flagged() {
        let m = minimal_manifest(); // action_types is empty
        let mut norms = BTreeSet::new();
        norms.insert("email.send".to_string());
        let v = validate_pack(&m, &norms, &[]);
        assert!(v.iter().any(|x| x.code == ViolationCode::OrphanNormalizer));
    }

    #[test]
    fn orphan_risk_rule_flagged() {
        let m = minimal_manifest();
        let v = validate_pack(
            &m,
            &BTreeSet::new(),
            &[("email.send".into(), sample_risk_rule("email.send"))],
        );
        assert!(v.iter().any(|x| x.code == ViolationCode::OrphanRiskRule));
    }

    #[test]
    fn security_lint_flags_critical_action_without_gate() {
        let mut m = minimal_manifest();
        m.action_types = vec!["email.set_forwarding".into()];
        let mut norms = BTreeSet::new();
        norms.insert("email.set_forwarding".to_string());

        // A rule with no Gate mutation anywhere — should be flagged.
        let rule = gateless_risk_rule("email.set_forwarding");
        let v = validate_pack(&m, &norms, &[("email.set_forwarding".into(), rule)]);
        assert!(
            v.iter()
                .any(|x| x.code == ViolationCode::MissingGateOnCriticalAction),
            "expected MissingGateOnCriticalAction, got: {v:#?}"
        );
    }

    #[test]
    fn security_lint_passes_when_critical_action_has_gate() {
        let mut m = minimal_manifest();
        m.action_types = vec!["email.set_forwarding".into()];
        let mut norms = BTreeSet::new();
        norms.insert("email.set_forwarding".to_string());

        // A rule with a Gate mutation in `rules:` should not trip the lint.
        let rule = risk_rule_with_gate("email.set_forwarding");
        let v = validate_pack(&m, &norms, &[("email.set_forwarding".into(), rule)]);
        assert!(
            !v.iter()
                .any(|x| x.code == ViolationCode::MissingGateOnCriticalAction),
            "did not expect MissingGateOnCriticalAction, got: {v:#?}"
        );
    }

    #[test]
    fn security_lint_ignores_non_critical_action_types() {
        // email.search is not on the always-human list, so missing gate
        // is fine.
        let mut m = minimal_manifest();
        m.action_types = vec!["email.search".into()];
        let mut norms = BTreeSet::new();
        norms.insert("email.search".to_string());

        let rule = gateless_risk_rule("email.search");
        let v = validate_pack(&m, &norms, &[("email.search".into(), rule)]);
        assert!(
            !v.iter()
                .any(|x| x.code == ViolationCode::MissingGateOnCriticalAction)
        );
    }

    fn sample_risk_rule(action_type: &str) -> RiskRuleDef {
        gateless_risk_rule(action_type)
    }

    fn gateless_risk_rule(action_type: &str) -> RiskRuleDef {
        let yaml = format!(
            r#"
permit0_pack: "permit0/email"
action_type: "{action_type}"
base:
  flags: {{}}
  amplifiers: {{}}
rules: []
session_rules: []
"#
        );
        serde_yaml::from_str(&yaml).expect("valid risk rule")
    }

    // ── tool_pattern_matches ──

    #[test]
    fn tool_pattern_literal_matches_exactly() {
        assert!(tool_pattern_matches("gmail_send", "gmail_send"));
        assert!(!tool_pattern_matches("gmail_send", "gmail_archive"));
        assert!(!tool_pattern_matches("gmail_send", "outlook_send"));
    }

    #[test]
    fn tool_pattern_prefix_wildcard() {
        assert!(tool_pattern_matches("gmail_*", "gmail_send"));
        assert!(tool_pattern_matches("gmail_*", "gmail_archive"));
        assert!(tool_pattern_matches("gmail_*", "gmail_"));
        assert!(!tool_pattern_matches("gmail_*", "outlook_send"));
        // Pattern requires the prefix to literally start the tool name.
        assert!(!tool_pattern_matches("gmail_*", "x_gmail_send"));
    }

    #[test]
    fn tool_pattern_suffix_wildcard() {
        assert!(tool_pattern_matches("*_send", "gmail_send"));
        assert!(tool_pattern_matches("*_send", "outlook_send"));
        assert!(!tool_pattern_matches("*_send", "gmail_archive"));
    }

    #[test]
    fn tool_pattern_universal() {
        assert!(tool_pattern_matches("*", "anything"));
        assert!(tool_pattern_matches("*", ""));
    }

    #[test]
    fn tool_pattern_middle_wildcard() {
        assert!(tool_pattern_matches("g*l_send", "gmail_send"));
        assert!(!tool_pattern_matches("g*l_send", "gmail_archive"));
    }

    fn risk_rule_with_gate(action_type: &str) -> RiskRuleDef {
        let yaml = format!(
            r#"
permit0_pack: "permit0/email"
action_type: "{action_type}"
base:
  flags: {{}}
  amplifiers: {{}}
rules:
  - when:
      destination:
        exists: true
    then:
      - gate: "human_review"
session_rules: []
"#
        );
        serde_yaml::from_str(&yaml).expect("valid risk rule")
    }
}
