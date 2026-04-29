//! End-to-end tests for the dispatcher's inline YAML registration and
//! unknown-command policies.
//!
//! Note: pack-loaded dispatchers (gog, stripe, gh, aws) tests were removed
//! when the project was simplified to only support the `email` pack.

use permit0_shell_dispatch::{DispatchOutcome, Dispatcher, UnknownCommandPolicy};

#[test]
fn unrecognized_bash_passes_through_under_passthrough() {
    let d = Dispatcher::new(UnknownCommandPolicy::Passthrough);
    let outcome = d.dispatch("grep foo /tmp/file.txt").unwrap();
    assert!(matches!(outcome, DispatchOutcome::Passthrough));
}

#[test]
fn unrecognized_bash_flagged_under_strict_policy() {
    let d = Dispatcher::new(UnknownCommandPolicy::FlagAsUnknown);
    let outcome = d.dispatch("weird-tool do --stuff").unwrap();
    match outcome {
        DispatchOutcome::FlaggedUnknown(parsed) => {
            assert_eq!(parsed.program, "weird-tool");
        }
        other => panic!("expected FlaggedUnknown, got {other:?}"),
    }
}

// ── Dispatcher API surface ──

#[test]
fn inline_yaml_str_registration() {
    let d = Dispatcher::new(UnknownCommandPolicy::Passthrough)
        .with_yaml_str(
            r#"
program: myorg
subcommand_depth: 2
dispatches:
  - match: { subcommands: [database, backup] }
    tool_name: myorg_database_backup
    parameters:
      target_db: { from: flags.database, default: "primary" }
      bucket: { from: flags.s3_bucket }
"#,
        )
        .unwrap();
    let action = d
        .dispatch("myorg database backup --database customers --s3-bucket backups-prod")
        .unwrap()
        .action()
        .cloned()
        .unwrap();
    assert_eq!(action.tool_name, "myorg_database_backup");
    assert_eq!(action.parameters["target_db"], "customers");
    assert_eq!(action.parameters["bucket"], "backups-prod");
}
