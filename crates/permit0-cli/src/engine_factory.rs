#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context, Result};
use permit0_dsl::{
    PACK_LOCKFILE_FILENAME, PackLockfile, discover_alias_yamls, discover_normalizer_yamls,
    discover_packs,
};
use permit0_engine::EngineBuilder;
use permit0_scoring::{Guardrails, ProfileOverrides, ScoringConfig};

/// Process-wide lockfile policy override. Set once at startup by the
/// CLI dispatcher when the user passes `--strict-lockfile`; read by
/// every default-policy load. Defaults to `false` (lazy mode).
///
/// Threading the flag through every `build_engine_*` call site
/// (check, hook, gateway, calibrate, serve, ...) would touch six
/// files; a process-global covers all of them by reading from
/// effective_default_policy().
static STRICT_LOCKFILE_OVERRIDE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set by `main()` after CLI parse. Affects every subsequent
/// `build_engine_*` call that uses the default lockfile policy.
pub fn set_strict_lockfile_override(strict: bool) {
    STRICT_LOCKFILE_OVERRIDE.store(strict, std::sync::atomic::Ordering::Relaxed);
}

fn effective_default_policy() -> LockfilePolicy {
    if STRICT_LOCKFILE_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        LockfilePolicy::Required
    } else {
        LockfilePolicy::Lazy
    }
}

/// How strictly the loader should treat pack lockfiles.
///
/// Three modes:
/// - **Lazy** (default): use the lockfile to enumerate files when
///   present; warn but proceed if absent; verify hashes only if the
///   lockfile says so. Matches the historical behavior of "load whatever
///   the filesystem holds."
/// - **Required**: refuse to load any pack without `pack.lock.yaml`.
///   Matches `--strict-lockfile`. Used in CI / production where
///   reproducibility is a hard requirement.
/// - **AlwaysVerify**: always verify every loaded file's sha256 against
///   the lockfile. Catches on-disk tampering between `pack lock` and
///   load time. Implied by Required.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LockfilePolicy {
    /// Use lockfile when present; tolerate absence with a warning;
    /// don't verify hashes (enumeration only). Phase 1 default.
    #[default]
    Lazy,
    /// Require a lockfile and verify every file's hash. CI / prod mode.
    Required,
}

/// Load all packs into an `EngineBuilder` without finalizing it. Lets
/// callers stack additional configuration (e.g. audit sink + signer)
/// before calling `.build()`.
///
/// Search order for packs is the same as `build_engine_from_packs`.
/// Honors the process-wide `--strict-lockfile` override (set by main
/// after CLI parse); see
/// [`build_engine_builder_from_packs_with_lock_policy`] for stricter modes.
pub fn build_engine_builder_from_packs(
    profile: Option<&str>,
    packs_dir: Option<&str>,
) -> Result<EngineBuilder> {
    build_engine_builder_from_packs_with_lock_policy(profile, packs_dir, effective_default_policy())
}

/// Same as [`build_engine_builder_from_packs`] but with an explicit
/// lockfile policy.
pub fn build_engine_builder_from_packs_with_lock_policy(
    profile: Option<&str>,
    packs_dir: Option<&str>,
    lock_policy: LockfilePolicy,
) -> Result<EngineBuilder> {
    let config = load_scoring_config(profile)?;
    let mut builder = EngineBuilder::new().with_config(config);

    let resolved_dir = resolve_packs_dir(packs_dir);
    if let Some(dir) = &resolved_dir {
        let pack_dirs = discover_packs(dir)
            .with_context(|| format!("discovering packs in {}", dir.display()))?;
        for pack_dir in pack_dirs {
            builder = install_pack_with_lock(builder, &pack_dir, lock_policy)?;
        }
    }

    Ok(builder)
}

/// Load all packs from the packs/ directory and build an engine.
///
/// Search order for packs:
/// 1. Explicit `packs_dir` if provided
/// 2. `./packs/` relative to CWD
/// 3. `~/.permit0/packs/`
pub fn build_engine_from_packs(
    profile: Option<&str>,
    packs_dir: Option<&str>,
) -> Result<permit0_engine::Engine> {
    build_engine_builder_from_packs(profile, packs_dir)?
        .build()
        .map_err(Into::into)
}

/// Same as [`build_engine_from_packs`] but with an explicit lockfile
/// policy. Exposed for callers that want to override the global
/// `--strict-lockfile` flag programmatically (e.g. embedding the CLI
/// engine in a longer-lived process).
#[allow(dead_code)]
pub fn build_engine_from_packs_with_lock_policy(
    profile: Option<&str>,
    packs_dir: Option<&str>,
    lock_policy: LockfilePolicy,
) -> Result<permit0_engine::Engine> {
    build_engine_builder_from_packs_with_lock_policy(profile, packs_dir, lock_policy)?
        .build()
        .map_err(Into::into)
}

/// Resolve the packs directory from explicit path, CWD, or ~/.permit0/packs/.
pub fn resolve_packs_dir(explicit: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(dir) = explicit {
        let p = Path::new(dir);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // CWD/packs/
    let cwd_packs = Path::new("packs");
    if cwd_packs.exists() {
        return Some(cwd_packs.to_path_buf());
    }
    // ~/.permit0/packs/
    if let Some(home) = dirs_home() {
        let home_packs = home.join(".permit0").join("packs");
        if home_packs.exists() {
            return Some(home_packs);
        }
    }
    None
}

pub fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// Load scoring config with optional profile overlay.
pub fn load_scoring_config(profile: Option<&str>) -> Result<ScoringConfig> {
    let profile_overrides = match profile {
        Some(name) => {
            let path = format!("profiles/{name}.profile.yaml");
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read profile: {path}"))?;
            let overrides: ProfileYaml = serde_yaml::from_str(&yaml)
                .with_context(|| format!("failed to parse profile: {path}"))?;
            Some(overrides.into_overrides()?)
        }
        None => None,
    };

    let guardrails = Guardrails::default();
    ScoringConfig::from_layers(profile_overrides.as_ref(), None, &guardrails)
        .map_err(|e| anyhow::anyhow!("guardrail violation: {e}"))
}

/// Install a pack honoring an explicit lockfile policy. See
/// [`LockfilePolicy`] for what each variant requires.
///
/// Normalizer enumeration via `discover_normalizer_yamls` walks both the
/// flat legacy layout and the per-channel layout introduced in PR 4 of
/// the pack taxonomy refactor. Aliases are loaded from every per-channel
/// `aliases.yaml` plus the legacy pack-root `aliases.yaml`.
fn install_pack_with_lock(
    mut builder: EngineBuilder,
    pack_dir: &Path,
    lock_policy: LockfilePolicy,
) -> Result<EngineBuilder> {
    let lockfile = load_lockfile_for_pack(pack_dir, lock_policy)?;

    let load_yaml = |path: &Path| -> Result<String> {
        let yaml =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if let Some(lock) = lockfile.as_ref() {
            verify_against_lockfile(lock, pack_dir, path, yaml.as_bytes())?;
        }
        Ok(yaml)
    };

    for path in discover_normalizer_yamls(pack_dir)
        .with_context(|| format!("discovering normalizers in {}", pack_dir.display()))?
    {
        let yaml = load_yaml(&path)?;
        builder = builder
            .install_normalizer_yaml(&yaml)
            .with_context(|| format!("installing normalizer {}", path.display()))?;
    }

    let rules_dir = pack_dir.join("risk_rules");
    if rules_dir.exists() {
        for entry in std::fs::read_dir(&rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                let yaml = load_yaml(&path)?;
                builder = builder
                    .install_risk_rule_yaml(&yaml)
                    .with_context(|| format!("installing risk rule {}", path.display()))?;
            }
        }
    }

    // Aliases — pack-root for legacy packs, per-channel for the schema
    // v2 layout. Each channel's table is merged into one resolver.
    for path in discover_alias_yamls(pack_dir)
        .with_context(|| format!("discovering aliases in {}", pack_dir.display()))?
    {
        let yaml = load_yaml(&path)?;
        builder = builder
            .install_aliases_yaml(&yaml)
            .with_context(|| format!("installing aliases {}", path.display()))?;
    }

    Ok(builder)
}

/// Try to read the lockfile at `<pack_dir>/pack.lock.yaml`. The
/// `lock_policy` decides what to do when the file is missing:
/// - `Lazy` returns `None` and prints a one-line warning to stderr.
/// - `Required` errors out — caller's intent was to refuse load
///   without a lockfile.
fn load_lockfile_for_pack(
    pack_dir: &Path,
    lock_policy: LockfilePolicy,
) -> Result<Option<PackLockfile>> {
    let path = pack_dir.join(PACK_LOCKFILE_FILENAME);
    if !path.is_file() {
        return match lock_policy {
            LockfilePolicy::Lazy => {
                eprintln!(
                    "warning: {} not present; loading from filesystem walk \
                     (run `permit0 pack lock {}` to commit a lockfile)",
                    path.display(),
                    pack_dir.display()
                );
                Ok(None)
            }
            LockfilePolicy::Required => anyhow::bail!(
                "lockfile policy is `Required` but {} is missing",
                path.display()
            ),
        };
    }
    let lock = PackLockfile::read(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(lock))
}

/// Verify a file's bytes against the lockfile. Errors when the file
/// isn't listed (stowaway) or when its hash mismatches (tampering).
///
/// `pack_dir` and `abs_path` are used together to compute the
/// pack-relative key the lockfile indexes by.
fn verify_against_lockfile(
    lock: &PackLockfile,
    pack_dir: &Path,
    abs_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let rel = abs_path
        .strip_prefix(pack_dir)
        .with_context(|| {
            format!(
                "{} is not inside pack {}",
                abs_path.display(),
                pack_dir.display()
            )
        })?
        .to_string_lossy()
        .replace('\\', "/");
    match lock.verify(&rel, bytes) {
        Ok(true) => Ok(()),
        Ok(false) => anyhow::bail!(
            "lockfile hash mismatch for {} — file may have been tampered with after `pack lock`",
            rel
        ),
        Err(e) => anyhow::bail!("{}: {e}", rel),
    }
}

/// Intermediate type for parsing profile YAML (which has extra fields we ignore).
#[derive(serde::Deserialize)]
struct ProfileYaml {
    #[serde(default)]
    risk_weight_adjustments: std::collections::HashMap<String, f64>,
    #[serde(default)]
    amp_weight_adjustments: std::collections::HashMap<String, f64>,
    #[serde(default)]
    action_type_floors: std::collections::HashMap<String, String>,
    /// Named sets for DSL `in_set` / `not_in_set` predicates. Each key is a
    /// dotted identifier (e.g., `org.trusted_domains`); each value is a list
    /// of strings. Later layers replace whole sets under the same key.
    #[serde(default)]
    named_sets: std::collections::HashMap<String, Vec<String>>,
    #[allow(dead_code)]
    #[serde(default)]
    additional_block_rules: Vec<serde_yaml::Value>,
    // Ignored fields
    #[allow(dead_code)]
    #[serde(default)]
    tier_threshold_shifts: std::collections::HashMap<String, f64>,
}

impl ProfileYaml {
    fn into_overrides(self) -> Result<ProfileOverrides> {
        let mut floors = std::collections::HashMap::new();
        for (action_str, tier_str) in &self.action_type_floors {
            let at = permit0_types::ActionType::parse(action_str)
                .map_err(|e| anyhow::anyhow!("invalid action type {action_str}: {e}"))?;
            let tier = match tier_str.to_uppercase().as_str() {
                "MINIMAL" => permit0_types::Tier::Minimal,
                "LOW" => permit0_types::Tier::Low,
                "MEDIUM" => permit0_types::Tier::Medium,
                "HIGH" => permit0_types::Tier::High,
                "CRITICAL" => permit0_types::Tier::Critical,
                _ => anyhow::bail!("unknown tier: {tier_str}"),
            };
            floors.insert(at, tier);
        }

        let named_sets: std::collections::HashMap<String, std::collections::HashSet<String>> = self
            .named_sets
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        Ok(ProfileOverrides {
            risk_weight_adjustments: self.risk_weight_adjustments,
            amp_weight_adjustments: self.amp_weight_adjustments,
            action_type_floors: floors,
            named_sets,
            ..Default::default()
        })
    }
}
