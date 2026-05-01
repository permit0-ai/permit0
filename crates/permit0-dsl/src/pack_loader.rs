#![forbid(unsafe_code)]

//! Pack discovery — walks a packs root and returns every directory that
//! contains a `pack.yaml`.
//!
//! Two layouts are supported simultaneously:
//!
//! 1. **Flat (legacy / PR 2)**: `<root>/<pack>/pack.yaml`.
//! 2. **Owner-namespaced (PR 3)**: `<root>/<owner>/<pack>/pack.yaml`.
//!
//! Discovery walks at most two levels deep. Anything further is ignored
//! to bound the cost on cold start. Symlinks are followed but a
//! per-walk cycle guard prevents runaway recursion.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Filename the discovery routine looks for at each candidate level.
pub const PACK_MANIFEST_FILENAME: &str = "pack.yaml";

/// Errors discovery can surface. Only `Io` is fatal at the call site;
/// `MalformedRoot` is informational.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("packs root not found: {0}")]
    NotFound(PathBuf),
    #[error("packs root is not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Walk `<root>` and return every directory containing `pack.yaml`,
/// up to two levels deep. Results are sorted by path for deterministic
/// load order.
///
/// Layout precedence at each entry:
/// - If `<root>/<entry>/pack.yaml` exists → emit `<root>/<entry>` (flat).
/// - Otherwise, descend one level: `<root>/<entry>/<sub>/pack.yaml` →
///   emit `<root>/<entry>/<sub>` (owner-namespaced).
///
/// The two layouts can coexist during the PR 3 migration window. After
/// PR 3, packs/permit0/email/ will be the only shape in the repo, but
/// `~/.permit0/packs/` may still hold flat third-party packs from older
/// releases.
pub fn discover_packs(root: impl AsRef<Path>) -> Result<Vec<PathBuf>, DiscoveryError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(DiscoveryError::NotFound(root.to_path_buf()));
    }
    if !root.is_dir() {
        return Err(DiscoveryError::NotADirectory(root.to_path_buf()));
    }

    let mut packs = Vec::new();
    let mut seen = HashSet::new();
    walk_level(root, 0, &mut packs, &mut seen)?;
    packs.sort();
    Ok(packs)
}

fn walk_level(
    dir: &Path,
    depth: u8,
    out: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) -> Result<(), DiscoveryError> {
    if depth > 1 {
        return Ok(());
    }
    // Cycle guard for symlinked dirs.
    let canon = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !seen.insert(canon) {
        return Ok(());
    }

    let entries = std::fs::read_dir(dir).map_err(|e| DiscoveryError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| DiscoveryError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        // Skip dotfiles and underscore-prefixed dirs (reserved for
        // metadata like _channel.yaml, _template).
        let basename = entry.file_name();
        if let Some(s) = basename.to_str()
            && (s.starts_with('.') || s.starts_with('_'))
        {
            continue;
        }

        if path.join(PACK_MANIFEST_FILENAME).is_file() {
            // Flat or owner-namespaced terminal: emit and stop descending.
            out.push(path);
            continue;
        }
        // No pack.yaml here. Recurse one level deeper if we are still at
        // the root (depth == 0). Pack manifests must live at depth 1
        // (flat) or depth 2 (owner-namespaced); anything deeper is ignored.
        if depth == 0 {
            walk_level(&path, depth + 1, out, seen)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Make a tempdir-like scratch root inside CARGO_TARGET_TMPDIR so the
    /// test is hermetic and doesn't depend on `tempfile`.
    fn scratch(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "permit0-discover-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn flat_layout_finds_packs() {
        let root = scratch("flat");
        write(&root.join("email/pack.yaml"), "name: email");
        write(&root.join("slack/pack.yaml"), "name: slack");

        let packs = discover_packs(&root).unwrap();
        assert_eq!(packs.len(), 2);
        assert!(packs.iter().any(|p| p.ends_with("email")));
        assert!(packs.iter().any(|p| p.ends_with("slack")));
    }

    #[test]
    fn owner_namespaced_layout_finds_packs() {
        let root = scratch("owner-ns");
        write(&root.join("permit0/email/pack.yaml"), "name: email");
        write(&root.join("permit0/slack/pack.yaml"), "name: slack");
        write(&root.join("anthropic/audit/pack.yaml"), "name: audit");

        let packs = discover_packs(&root).unwrap();
        assert_eq!(packs.len(), 3);
        assert!(packs.iter().any(|p| p.ends_with("permit0/email")));
        assert!(packs.iter().any(|p| p.ends_with("permit0/slack")));
        assert!(packs.iter().any(|p| p.ends_with("anthropic/audit")));
    }

    #[test]
    fn three_level_community_layout_is_phase_two() {
        // Phase 2 layout `<root>/community/<author>/<pack>/pack.yaml`
        // is depth 3. PR 2's discovery deliberately stops at depth 2 —
        // the community sub-tree lights up when the federated registry
        // and signing infrastructure ship. Test pinned so the limit
        // is intentional, not accidental.
        let root = scratch("phase-two");
        write(
            &root.join("community/alice/jira/pack.yaml"),
            "name: jira",
        );
        let packs = discover_packs(&root).unwrap();
        assert!(packs.is_empty(), "phase-2 community packs not yet discoverable");
    }

    #[test]
    fn mixed_layouts_coexist() {
        let root = scratch("mixed");
        write(&root.join("email/pack.yaml"), "name: email"); // flat
        write(&root.join("permit0/slack/pack.yaml"), "name: slack"); // owner-ns
        let packs = discover_packs(&root).unwrap();
        assert_eq!(packs.len(), 2);
    }

    #[test]
    fn skips_underscore_and_dot_dirs() {
        let root = scratch("skip");
        write(&root.join("email/pack.yaml"), "name: email");
        write(&root.join("_template/pack.yaml"), "name: template");
        write(&root.join(".hidden/pack.yaml"), "name: hidden");

        let packs = discover_packs(&root).unwrap();
        assert_eq!(packs.len(), 1);
        assert!(packs[0].ends_with("email"));
    }

    #[test]
    fn caps_depth_at_two() {
        let root = scratch("deep");
        // Depth 3: ignored.
        write(
            &root.join("a/b/c/pack.yaml"),
            "name: too-deep",
        );
        let packs = discover_packs(&root).unwrap();
        assert!(packs.is_empty());
    }

    #[test]
    fn missing_root_errors() {
        let err = discover_packs("/definitely/not/a/real/path-9b27ce").unwrap_err();
        matches!(err, DiscoveryError::NotFound(_));
    }

    #[test]
    fn empty_root_yields_no_packs() {
        let root = scratch("empty");
        let packs = discover_packs(&root).unwrap();
        assert!(packs.is_empty());
    }

    #[test]
    fn results_are_sorted_for_determinism() {
        let root = scratch("sorted");
        write(&root.join("zeta/pack.yaml"), "");
        write(&root.join("alpha/pack.yaml"), "");
        write(&root.join("permit0/middle/pack.yaml"), "");

        let packs = discover_packs(&root).unwrap();
        let names: Vec<_> = packs
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
