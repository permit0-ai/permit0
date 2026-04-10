#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context, Result};
use permit0_dsl::normalizer::DslNormalizer;
use permit0_dsl::schema::risk_rule::RiskRuleDef;
use permit0_dsl::validate;

/// Validate all normalizer and risk rule YAML files in a pack directory.
pub fn validate(pack_path: &str) -> Result<()> {
    let pack_dir = Path::new(pack_path);
    if !pack_dir.exists() {
        anyhow::bail!("pack directory not found: {pack_path}");
    }

    let mut total_errors = 0;
    let mut total_files = 0;

    // Validate normalizers
    let normalizers_dir = pack_dir.join("normalizers");
    if normalizers_dir.exists() {
        let mut normalizer_defs = Vec::new();
        for entry in std::fs::read_dir(&normalizers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_yaml(&path) {
                continue;
            }
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

    // Validate risk rules
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
                }
                Err(e) => {
                    println!("  ✗ {}: parse error: {e}", path.display());
                    total_errors += 1;
                }
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
fn run_fixtures(
    fixtures_dir: &Path,
    engine: &permit0_engine::Engine,
) -> Result<()> {
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

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e == "yaml" || e == "yml")
}
