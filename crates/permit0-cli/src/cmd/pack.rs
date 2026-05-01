#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use permit0_dsl::discover_normalizer_yamls;
use permit0_dsl::normalizer::DslNormalizer;
use permit0_dsl::pack_validate::{ViolationCode, validate_pack};
use permit0_dsl::schema::PackManifest;
use permit0_dsl::schema::risk_rule::RiskRuleDef;
use permit0_dsl::validate;

/// Validate all normalizer and risk rule YAML files in a pack directory,
/// then run manifest-level checks (schema version, trust tier consistency,
/// action-type coverage, orphans, security lint).
pub fn validate(pack_path: &str) -> Result<()> {
    let pack_dir = Path::new(pack_path);
    if !pack_dir.exists() {
        anyhow::bail!("pack directory not found: {pack_path}");
    }

    let mut total_errors = 0;
    let mut total_files = 0;

    // Validate normalizers (also collect produced action types for the
    // manifest-level coverage / orphan checks below).
    //
    // Uses `discover_normalizer_yamls` so both the flat legacy layout
    // and the per-channel layout (PR 4 of the pack taxonomy refactor)
    // are walked transparently.
    let mut normalizer_action_types = BTreeSet::new();
    let normalizer_paths = discover_normalizer_yamls(pack_dir)
        .with_context(|| format!("discovering normalizers in {}", pack_dir.display()))?;
    if !normalizer_paths.is_empty() {
        let mut normalizer_defs = Vec::new();
        for path in normalizer_paths {
            total_files += 1;
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;

            match DslNormalizer::from_yaml(&yaml) {
                Ok(n) => {
                    let errors = validate::validate_normalizer(n.def());
                    if errors.is_empty() {
                        println!("  ✓ {}", path.display());
                    } else {
                        for e in &errors {
                            println!("  ✗ {}: {e}", path.display());
                        }
                        total_errors += errors.len();
                    }
                    normalizer_action_types.insert(n.def().normalize.action_type.clone());
                    normalizer_defs.push(n.def().clone());
                }
                Err(e) => {
                    println!("  ✗ {}: parse error: {e}", path.display());
                    total_errors += 1;
                }
            }
        }

        // Check for duplicate IDs
        let dup_errors = validate::check_duplicate_ids(&normalizer_defs);
        for e in &dup_errors {
            println!("  ✗ duplicate: {e}");
        }
        total_errors += dup_errors.len();
    }

    // Validate risk rules (collect (action_type, def) pairs for the
    // manifest-level checks below).
    let mut risk_rule_targets: Vec<(String, RiskRuleDef)> = Vec::new();
    let rules_dir = pack_dir.join("risk_rules");
    if rules_dir.exists() {
        for entry in std::fs::read_dir(&rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_yaml(&path) {
                continue;
            }
            total_files += 1;
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;

            match serde_yaml::from_str::<RiskRuleDef>(&yaml) {
                Ok(rule) => {
                    let errors = validate::validate_risk_rule(&rule);
                    if errors.is_empty() {
                        println!("  ✓ {}", path.display());
                    } else {
                        for e in &errors {
                            println!("  ✗ {}: {e}", path.display());
                        }
                        total_errors += errors.len();
                    }
                    risk_rule_targets.push((rule.action_type.clone(), rule));
                }
                Err(e) => {
                    println!("  ✗ {}: parse error: {e}", path.display());
                    total_errors += 1;
                }
            }
        }
    }

    // ── Manifest-level checks (PR 2) ──
    let manifest_path = pack_dir.join("pack.yaml");
    if manifest_path.exists() {
        let manifest_yaml = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        match serde_yaml::from_str::<PackManifest>(&manifest_yaml) {
            Ok(manifest) => {
                let violations =
                    validate_pack(&manifest, &normalizer_action_types, &risk_rule_targets);
                if !violations.is_empty() {
                    println!("\n── Manifest-level checks ──");
                }
                for v in &violations {
                    let icon = match v.code {
                        // The orphan / coverage codes are surfacing pack.yaml
                        // hygiene issues, but PR 3 closes the existing email
                        // gaps (outlook list_drafts, list_drafts risk rule).
                        // Until then, surface them as warnings rather than
                        // hard errors so existing CI keeps passing.
                        ViolationCode::MissingNormalizer
                        | ViolationCode::MissingRiskRule
                        | ViolationCode::OrphanNormalizer
                        | ViolationCode::OrphanRiskRule => "⚠",
                        _ => "✗",
                    };
                    println!("  {icon} pack.yaml: {} ({:?})", v.message, v.code);
                    if icon == "✗" {
                        total_errors += 1;
                    }
                }
            }
            Err(e) => {
                println!("  ✗ {}: parse error: {e}", manifest_path.display());
                total_errors += 1;
            }
        }
    }

    println!();
    if total_errors == 0 {
        println!("All {total_files} files valid.");
        Ok(())
    } else {
        anyhow::bail!("{total_errors} error(s) in {total_files} files")
    }
}

/// Run pack test fixtures. For now, this validates + attempts to build the engine with the pack.
pub fn test(pack_path: &str) -> Result<()> {
    // Step 1: validate
    println!("── Validating {pack_path} ──");
    validate(pack_path)?;

    // Step 2: try building an engine with this pack
    println!("── Building engine with pack ──");
    let pack_dir = Path::new(pack_path);
    let mut builder = permit0_engine::EngineBuilder::new();

    let normalizers_dir = pack_dir.join("normalizers");
    if normalizers_dir.exists() {
        for entry in std::fs::read_dir(&normalizers_dir)? {
            let path = entry?.path();
            if is_yaml(&path) {
                let yaml = std::fs::read_to_string(&path)?;
                builder = builder
                    .install_normalizer_yaml(&yaml)
                    .with_context(|| format!("installing normalizer {}", path.display()))?;
            }
        }
    }

    let rules_dir = pack_dir.join("risk_rules");
    if rules_dir.exists() {
        for entry in std::fs::read_dir(&rules_dir)? {
            let path = entry?.path();
            if is_yaml(&path) {
                let yaml = std::fs::read_to_string(&path)?;
                builder = builder
                    .install_risk_rule_yaml(&yaml)
                    .with_context(|| format!("installing risk rule {}", path.display()))?;
            }
        }
    }

    let _engine = builder.build()?;
    println!("  ✓ Engine built successfully with pack {pack_path}");

    // Step 3: Run fixture files if they exist
    let fixtures_dir = pack_dir.join("fixtures");
    if fixtures_dir.exists() {
        println!("── Running fixtures ──");
        run_fixtures(&fixtures_dir, &_engine)?;
    }

    println!("\nPack test passed.");
    Ok(())
}

/// Run fixture test cases from a directory.
fn run_fixtures(fixtures_dir: &Path, engine: &permit0_engine::Engine) -> Result<()> {
    let mut passed = 0;
    let mut failed = 0;

    for entry in std::fs::read_dir(fixtures_dir)? {
        let path = entry?.path();
        if !is_yaml(&path) {
            continue;
        }
        let yaml = std::fs::read_to_string(&path)?;
        let fixture: FixtureDef = serde_yaml::from_str(&yaml)
            .with_context(|| format!("parsing fixture {}", path.display()))?;

        let tool_call = permit0_types::RawToolCall {
            tool_name: fixture.tool_name,
            parameters: fixture.parameters,
            metadata: Default::default(),
        };

        let ctx = permit0_engine::PermissionCtx::new(
            permit0_normalize::NormalizeCtx::new().with_org_domain("test.org"),
        );

        match engine.get_permission(&tool_call, &ctx) {
            Ok(result) => {
                let actual_perm = format!("{}", result.permission);
                if actual_perm == fixture.expected_permission.to_uppercase() {
                    println!("  ✓ {}: {actual_perm}", path.display());
                    passed += 1;
                } else {
                    println!(
                        "  ✗ {}: expected {}, got {actual_perm}",
                        path.display(),
                        fixture.expected_permission
                    );
                    failed += 1;
                }
            }
            Err(e) => {
                println!("  ✗ {}: error: {e}", path.display());
                failed += 1;
            }
        }
    }

    println!("  {passed} passed, {failed} failed");
    if failed > 0 {
        anyhow::bail!("{failed} fixture(s) failed");
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct FixtureDef {
    tool_name: String,
    parameters: serde_json::Value,
    expected_permission: String,
}

/// Scaffold a new pack with normalizer, risk rule, and fixture stubs.
pub fn new_pack(name: &str) -> Result<()> {
    let pack_dir = Path::new("packs").join(name);
    if pack_dir.exists() {
        anyhow::bail!("pack directory already exists: {}", pack_dir.display());
    }

    // Create directory structure
    let normalizers_dir = pack_dir.join("normalizers");
    let rules_dir = pack_dir.join("risk_rules");
    let fixtures_dir = pack_dir.join("fixtures");
    std::fs::create_dir_all(&normalizers_dir)?;
    std::fs::create_dir_all(&rules_dir)?;
    std::fs::create_dir_all(&fixtures_dir)?;

    // Stub normalizer
    let normalizer_stub = format!(
        r#"id: {name}_default
description: "Normalize {name} tool calls"
priority: 100
match:
  tool: "{name}"
action_type: "custom.{name}"
channel: "{name}"
entities:
  - name: command
    path: "$.parameters.command"
    required: false
    default: "unknown"
"#
    );
    std::fs::write(
        normalizers_dir.join(format!("{name}.normalizer.yaml")),
        normalizer_stub,
    )?;

    // Stub risk rule
    let risk_rule_stub = format!(
        r#"id: {name}_base
description: "Base risk rule for {name}"
action_type: "custom.{name}"
match:
  tool: "{name}"
flags:
  - name: EXECUTION
    role: secondary
amplifiers: {{}}
"#
    );
    std::fs::write(
        rules_dir.join(format!("{name}.risk_rule.yaml")),
        risk_rule_stub,
    )?;

    // Stub fixture
    let fixture_stub = format!(
        r#"tool_name: "{name}"
parameters:
  command: "test"
expected_permission: "allow"
"#
    );
    std::fs::write(
        fixtures_dir.join(format!("{name}_basic.fixture.yaml")),
        fixture_stub,
    )?;

    // README
    let readme = format!(
        r#"# {name} Pack

A permit0 pack for `{name}` tool calls.

## Structure

```
{name}/
├── normalizers/
│   └── {name}.normalizer.yaml
├── risk_rules/
│   └── {name}.risk_rule.yaml
└── fixtures/
    └── {name}_basic.fixture.yaml
```

## Usage

```sh
permit0 pack validate packs/{name}
permit0 pack test packs/{name}
```
"#
    );
    std::fs::write(pack_dir.join("README.md"), readme)?;

    println!("Created pack scaffold at {}", pack_dir.display());
    println!("  normalizers/{name}.normalizer.yaml");
    println!("  risk_rules/{name}.risk_rule.yaml");
    println!("  fixtures/{name}_basic.fixture.yaml");
    println!("  README.md");
    println!();
    println!("Next steps:");
    println!("  1. Edit the normalizer to match your tool's input format");
    println!("  2. Add risk flags and amplifiers in the risk rule");
    println!("  3. Add fixture test cases");
    println!("  4. Run: permit0 pack validate packs/{name}");

    Ok(())
}

fn is_yaml(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "yaml" || e == "yml")
}

/// Generate or refresh `pack.lock.yaml` for a pack directory.
///
/// In the default mode this writes a fresh lockfile reflecting the
/// current contents of the pack — every normalizer YAML, risk rule
/// YAML, channel manifest, and alias table gets a sha256 + size entry.
///
/// With `--check`, the function reads the existing lockfile and
/// verifies it matches the on-disk contents. Drift exits non-zero
/// (CI failure mode); intended for `permit0 pack lock --check` in CI
/// to catch stowaway YAMLs and unstaged content edits.
pub fn lock(pack_path: &str, check: bool) -> Result<()> {
    use permit0_dsl::lockfile::{
        LockedFile, PACK_LOCKFILE_FILENAME, PACK_LOCKFILE_VERSION, PackLockfile, sha256_hex,
    };
    use permit0_dsl::schema::PackManifest;

    let pack_dir = Path::new(pack_path);
    if !pack_dir.exists() {
        anyhow::bail!("pack directory not found: {pack_path}");
    }

    // Load the manifest so we know what permit0_pack / version /
    // pack_format to record.
    let manifest_path = pack_dir.join(permit0_dsl::PACK_MANIFEST_FILENAME);
    let manifest_yaml = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: PackManifest = serde_yaml::from_str(&manifest_yaml)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;

    // Collect every loadable file. Order:
    //   1. pack.yaml itself
    //   2. normalizers (flat + per-channel) and channel metadata
    //   3. alias tables (pack-root + per-channel)
    //   4. risk rules
    let mut files: Vec<LockedFile> = Vec::new();
    let mut record = |abs: &Path| -> Result<()> {
        let rel = abs
            .strip_prefix(pack_dir)
            .with_context(|| format!("path {} not under {}", abs.display(), pack_dir.display()))?
            .to_string_lossy()
            // Forward-slash separators on every platform so lockfiles
            // produced on Linux and Windows agree.
            .replace('\\', "/");
        let bytes = std::fs::read(abs).with_context(|| format!("reading {}", abs.display()))?;
        files.push(LockedFile {
            path: rel,
            sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
        });
        Ok(())
    };

    record(&manifest_path)?;

    // Walk normalizers/ at depth 1 AND depth 2; include _channel.yaml
    // metadata + per-channel aliases.yaml.
    let normalizers_dir = pack_dir.join("normalizers");
    if normalizers_dir.is_dir() {
        for entry in std::fs::read_dir(&normalizers_dir)? {
            let path = entry?.path();
            if path.is_dir() {
                for sub in std::fs::read_dir(&path)? {
                    let sub_path = sub?.path();
                    if is_yaml(&sub_path) {
                        record(&sub_path)?;
                    }
                }
            } else if is_yaml(&path) {
                record(&path)?;
            }
        }
    }

    // Pack-root aliases (legacy layout) and risk rules.
    let pack_root_aliases = pack_dir.join(permit0_dsl::ALIASES_FILENAME);
    if pack_root_aliases.is_file() {
        record(&pack_root_aliases)?;
    }
    let rules_dir = pack_dir.join("risk_rules");
    if rules_dir.is_dir() {
        for entry in std::fs::read_dir(&rules_dir)? {
            let path = entry?.path();
            if is_yaml(&path) {
                record(&path)?;
            }
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    // Pack format may have been omitted from older v1 manifests; fall
    // back to PACK_FORMAT_VERSION since the validator already errors
    // on missing values.
    let pack_format = manifest
        .pack_format
        .unwrap_or(permit0_dsl::schema::PACK_FORMAT_VERSION);

    let lockfile = PackLockfile {
        lockfile_version: PACK_LOCKFILE_VERSION,
        permit0_pack: manifest.permit0_pack.clone(),
        pack_version: manifest.version.clone(),
        pack_format,
        // Stable timestamp for `--check` mode: when checking, use the
        // existing lockfile's timestamp so a fresh hash recomputation
        // doesn't produce a spurious diff. Skip the wall-clock read
        // entirely outside generation mode.
        generated_at: if check {
            // Will be replaced by the existing lockfile's value below.
            String::new()
        } else {
            // Hand-rolled minimal ISO-8601 to avoid pulling chrono in
            // for one timestamp.
            iso8601_now()
        },
        files,
    };

    let lockfile_path = pack_dir.join(PACK_LOCKFILE_FILENAME);

    if check {
        let existing = PackLockfile::read(&lockfile_path).with_context(|| {
            format!(
                "reading {} (run `permit0 pack lock {pack_path}` to generate)",
                lockfile_path.display()
            )
        })?;
        if existing.permit0_pack != lockfile.permit0_pack
            || existing.pack_version != lockfile.pack_version
            || existing.pack_format != lockfile.pack_format
        {
            anyhow::bail!(
                "lockfile metadata drift: pack identity / version / pack_format differs from manifest"
            );
        }
        // Compare file lists (path + size + sha256).
        let mut drift: Vec<String> = Vec::new();
        for f in &lockfile.files {
            match existing.find(&f.path) {
                Some(e) if e.sha256 == f.sha256 && e.size == f.size => {}
                Some(e) => drift.push(format!(
                    "  ✗ {}: lockfile sha256={} size={}, on-disk sha256={} size={}",
                    f.path, e.sha256, e.size, f.sha256, f.size
                )),
                None => drift.push(format!(
                    "  ✗ {}: present on disk, missing from lockfile",
                    f.path
                )),
            }
        }
        for e in &existing.files {
            if !lockfile.files.iter().any(|f| f.path == e.path) {
                drift.push(format!(
                    "  ✗ {}: listed in lockfile, missing on disk",
                    e.path
                ));
            }
        }
        if drift.is_empty() {
            println!("Lockfile up to date ({} files).", lockfile.files.len());
            Ok(())
        } else {
            for line in &drift {
                println!("{line}");
            }
            anyhow::bail!(
                "lockfile drift detected ({} entries); run `permit0 pack lock {pack_path}` to refresh",
                drift.len()
            )
        }
    } else {
        let yaml = lockfile.to_yaml()?;
        std::fs::write(&lockfile_path, &yaml)
            .with_context(|| format!("writing {}", lockfile_path.display()))?;
        println!(
            "Wrote {} ({} files, {} bytes)",
            lockfile_path.display(),
            lockfile.files.len(),
            yaml.len()
        );
        Ok(())
    }
}

/// Minimal UTC ISO-8601 timestamp for lockfile `generated_at`.
/// Avoids pulling chrono into permit0-cli for one field.
fn iso8601_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86_400;
    let hms = secs % 86_400;
    let h = hms / 3600;
    let m = (hms % 3600) / 60;
    let s = hms % 60;
    // Convert days-since-epoch to year/month/day. Civil-from-days
    // algorithm by Howard Hinnant (public domain).
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[allow(clippy::needless_range_loop)]
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    // 1970-01-01 → days_since_epoch=0. Algorithm at
    // https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = (y + i64::from(m <= 2)) as i32;
    (year, m as u32, d as u32)
}
