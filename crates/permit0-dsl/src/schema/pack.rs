#![forbid(unsafe_code)]

use serde::Deserialize;

/// Pack manifest — `pack.yaml` at the root of a pack directory.
///
/// Schema v2 (introduced in PR 2 of the pack taxonomy refactor). The
/// engine refuses to load any pack with `pack_format != Some(2)`. The
/// previous schema (no `pack_format`, mandatory `vendor`, mandatory
/// explicit `normalizers`/`risk_rules` lists) is unsupported.
#[derive(Debug, Clone, Deserialize)]
pub struct PackManifest {
    /// Manifest schema version. Engine rejects anything other than `Some(2)`.
    /// Wrapped in `Option` so absent → clear "missing pack_format" error
    /// rather than a misleading serde mismatch.
    #[serde(default)]
    pub pack_format: Option<u32>,

    pub name: String,
    pub version: String,
    pub permit0_pack: String,

    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license: Option<String>,

    /// Engine compatibility range, e.g. `">=0.5.0,<0.6"`. Optional in
    /// schema v2; mandatory once semver gating is wired up.
    #[serde(default)]
    pub permit0_engine: Option<String>,

    /// Taxonomy compatibility range, e.g. `"1.x"`.
    #[serde(default)]
    pub taxonomy: Option<String>,

    /// Action types this pack is responsible for. Validator cross-checks
    /// against installed normalizers and risk rules.
    #[serde(default)]
    pub action_types: Vec<String>,

    /// Pack maintainers (informational; not used for trust decisions).
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,

    /// Channel metadata. Keyed by channel slug (e.g. `gmail`, `outlook`).
    /// Empty in PR 2; populated in PR 3 once normalizers are channel-grouped.
    #[serde(default)]
    pub channels: std::collections::BTreeMap<String, ChannelMeta>,

    /// Self-declared trust tier. **Informational only** — the engine
    /// derives the authoritative tier from `permit0_pack`'s owner prefix
    /// (and, in Phase 2, signature). A community pack declaring
    /// `trust_tier: built-in` does not become built-in; the validator
    /// flags the mismatch.
    #[serde(default)]
    pub trust_tier: Option<TrustTier>,

    /// Phase 2 forward-compat: signature over the pack's lockfile + manifest.
    /// Reserved; empty in Phase 1.
    #[serde(default)]
    pub signature: Option<String>,

    /// Phase 2 forward-compat: provenance attestation (build origin, signer
    /// identity). Reserved; empty in Phase 1.
    #[serde(default)]
    pub provenance: Option<String>,

    /// Phase 2 forward-compat: content hash of the pack's normalized
    /// contents (lockfile-derived). Reserved; empty in Phase 1.
    #[serde(default)]
    pub content_hash: Option<String>,

    /// Explicit normalizer file list. Empty → auto-discover from filesystem.
    #[serde(default)]
    pub normalizers: Vec<String>,

    /// Explicit risk rule file list. Empty → auto-discover from filesystem.
    #[serde(default)]
    pub risk_rules: Vec<String>,

    /// Legacy schema v1 field. Ignored in v2; left here so v1 manifests
    /// produce a clean version-gate error rather than a serde failure.
    #[serde(default)]
    pub vendor: Option<String>,

    /// Legacy schema v1 field. Ignored in v2.
    #[serde(default)]
    pub min_engine_version: Option<String>,
}

/// Pack maintainer record. Either GitHub handle or email; both optional.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Maintainer {
    #[serde(default)]
    pub github: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Channel-level metadata (per-vendor).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChannelMeta {
    /// Path to the MCP server adapter for this channel, e.g.
    /// `clients/gmail-mcp`.
    #[serde(default)]
    pub mcp_server: Option<String>,
    /// Display name (UI-facing).
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Authoritative pack trust tier.
///
/// Distinct from `permit0_types::Tier` (the per-decision risk tier) — that
/// classifies *requests* on a confidence scale, this classifies *packs* on
/// a trust scale.
///
/// Used in two roles:
/// - As an `Option<TrustTier>` in `PackManifest::trust_tier`: the *declared*
///   value, informational only.
/// - As the return value of [`derive_trust_tier`]: the *authoritative* value
///   the engine uses for trust decisions.
///
/// Validators compare the declared and derived values and flag mismatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Maintained by the permit0 core team. Path: `packs/permit0/*`.
    BuiltIn,
    /// Community-maintained, permit0-co-signed. Phase 2 (requires signing infra).
    Verified,
    /// Community-maintained, no co-sign. Default for non-permit0 owners in Phase 1.
    Community,
    /// Hidden by default; opt-in to install. Phase 2.
    Experimental,
}

/// Derive the authoritative trust tier from a pack's owner.
///
/// Phase 1 implementation:
/// - `owner == "permit0"` → `TrustTier::BuiltIn`
/// - everything else → `TrustTier::Community`
///
/// Phase 2 will extend this to consult the lockfile signature and the
/// federated registry. Until then, `Verified` and `Experimental` are
/// unreachable via derivation — packs declaring them are flagged by the
/// validator.
pub fn derive_trust_tier(owner: &str) -> TrustTier {
    if owner == "permit0" {
        TrustTier::BuiltIn
    } else {
        TrustTier::Community
    }
}

/// Owner extracted from a `permit0_pack` manifest field (`<owner>/<name>`).
/// Returns `None` if the field is missing the slash separator.
pub fn extract_owner(permit0_pack: &str) -> Option<&str> {
    permit0_pack.split_once('/').map(|(o, _)| o)
}

/// Current pack manifest schema version. Bump on breaking schema changes.
pub const PACK_FORMAT_VERSION: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_v2_manifest() {
        let yaml = r#"
pack_format: 2
name: email
version: "0.3.0"
permit0_pack: "permit0/email"
"#;
        let m: PackManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.pack_format, Some(2));
        assert_eq!(m.name, "email");
        assert!(m.normalizers.is_empty());
        assert!(m.action_types.is_empty());
        assert!(m.channels.is_empty());
    }

    #[test]
    fn parses_full_v2_manifest() {
        let yaml = r#"
pack_format: 2
name: email
version: "0.3.0"
permit0_pack: "permit0/email"
permit0_engine: ">=0.5.0,<0.6"
taxonomy: "1.x"
trust_tier: built-in
maintainers:
  - github: "@permit0-team"
channels:
  gmail:
    mcp_server: clients/gmail-mcp
    display_name: "Gmail"
  outlook:
    mcp_server: clients/outlook-mcp
action_types:
  - email.send
  - email.archive
signature: ""
provenance: ""
content_hash: ""
"#;
        let m: PackManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.pack_format, Some(2));
        assert_eq!(m.trust_tier, Some(TrustTier::BuiltIn));
        assert_eq!(m.channels.len(), 2);
        assert_eq!(
            m.channels.get("gmail").and_then(|c| c.mcp_server.as_deref()),
            Some("clients/gmail-mcp")
        );
        assert_eq!(m.action_types, vec!["email.send", "email.archive"]);
    }

    #[test]
    fn parses_v1_manifest_without_pack_format() {
        // The legacy schema (no pack_format, has vendor + explicit lists)
        // still parses. The engine rejects it later via the version gate.
        let yaml = r#"
name: email
version: "0.2.0"
permit0_pack: "permit0/email"
vendor: permit0
normalizers:
  - normalizers/gmail_send.yaml
risk_rules:
  - risk_rules/send.yaml
"#;
        let m: PackManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.pack_format, None);
        assert_eq!(m.vendor.as_deref(), Some("permit0"));
        assert_eq!(m.normalizers.len(), 1);
    }

    #[test]
    fn rejects_unknown_trust_tier_value() {
        let yaml = r#"
pack_format: 2
name: email
version: "0.3.0"
permit0_pack: "permit0/email"
trust_tier: gold-plated
"#;
        let err = serde_yaml::from_str::<PackManifest>(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("gold-plated") || msg.contains("variant"));
    }

    #[test]
    fn extracts_owner_from_permit0_pack() {
        assert_eq!(extract_owner("permit0/email"), Some("permit0"));
        assert_eq!(extract_owner("anthropic/audit"), Some("anthropic"));
        assert_eq!(extract_owner("bad-no-slash"), None);
        assert_eq!(extract_owner(""), None);
    }

    #[test]
    fn derive_trust_tier_classifies_owners() {
        assert_eq!(derive_trust_tier("permit0"), TrustTier::BuiltIn);
        assert_eq!(derive_trust_tier("anthropic"), TrustTier::Community);
        assert_eq!(derive_trust_tier("alice"), TrustTier::Community);
        assert_eq!(derive_trust_tier(""), TrustTier::Community);
    }

    #[test]
    fn declared_tier_can_disagree_with_derived() {
        // Manifest declares built-in but owner is "alice" → derived is community.
        // The validator (separate module) will flag this as a self-attestation
        // mismatch. The derive function always returns the authoritative value.
        let yaml = r#"
pack_format: 2
name: jira
version: "0.1.0"
permit0_pack: "alice/jira"
trust_tier: built-in
"#;
        let m: PackManifest = serde_yaml::from_str(yaml).unwrap();
        let owner = extract_owner(&m.permit0_pack).unwrap();
        let derived = derive_trust_tier(owner);
        assert_eq!(m.trust_tier, Some(TrustTier::BuiltIn));
        assert_eq!(derived, TrustTier::Community);
        assert_ne!(m.trust_tier.unwrap(), derived);
    }
}
