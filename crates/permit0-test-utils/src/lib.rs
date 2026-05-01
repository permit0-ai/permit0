#![forbid(unsafe_code)]

//! Shared test fixture loading for crates in the permit0 workspace.
//!
//! Replaces ad-hoc `include_str!("../../../packs/...")` paths that break
//! silently whenever the `packs/` directory is reorganized (see PR 3 of the
//! pack taxonomy refactor). Resolves paths relative to the workspace root
//! using `CARGO_MANIFEST_DIR`, so any consuming crate gets the same
//! behavior regardless of its depth in the workspace.

use std::path::{Path, PathBuf};

/// Absolute path to the workspace root.
///
/// Computed from this crate's manifest dir (`crates/permit0-test-utils/`),
/// climbed two parents up. If the workspace ever stops being two levels
/// deep, this needs to change.
pub fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(&manifest_dir)
        .to_path_buf()
}

/// Load a fixture YAML (or any text file) from a workspace-relative path.
///
/// Panics with a clear message if the file is missing or unreadable. Tests
/// should fail loudly when fixtures move.
///
/// # Examples
///
/// ```ignore
/// use permit0_test_utils::load_test_fixture;
/// let yaml = load_test_fixture("packs/email/normalizers/gmail_send.yaml");
/// ```
pub fn load_test_fixture(rel_path: &str) -> String {
    let full = workspace_root().join(rel_path);
    std::fs::read_to_string(&full).unwrap_or_else(|err| {
        panic!(
            "load_test_fixture: failed to read {} (workspace_root={}): {err}",
            full.display(),
            workspace_root().display(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_contains_cargo_toml() {
        let root = workspace_root();
        assert!(
            root.join("Cargo.toml").exists(),
            "workspace_root() = {} should contain a Cargo.toml",
            root.display()
        );
    }

    #[test]
    fn load_test_fixture_reads_existing_file() {
        // Cargo.toml at workspace root is always present.
        let content = load_test_fixture("Cargo.toml");
        assert!(content.contains("[workspace]"));
    }

    #[test]
    #[should_panic(expected = "load_test_fixture: failed to read")]
    fn load_test_fixture_panics_on_missing() {
        let _ = load_test_fixture("does/not/exist.yaml");
    }
}
