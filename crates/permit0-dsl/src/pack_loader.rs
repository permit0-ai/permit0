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

/// Filename for per-channel metadata. Excluded from normalizer-file
/// enumeration since it contains channel config, not a normalizer.
pub const CHANNEL_MANIFEST_FILENAME: &str = "_channel.yaml";

/// Filename for per-pack or per-channel alias tables. Excluded from
/// normalizer-file enumeration; loaded via a separate path (see the
/// alias resolver).
pub const ALIASES_FILENAME: &str = "aliases.yaml";

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

/// Enumerate every normalizer YAML inside a pack's `normalizers/` directory.
///
/// Walks at depth 1 (legacy flat: `normalizers/<verb>.yaml` or
/// `normalizers/<channel>_<verb>.yaml`) AND depth 2 (per-channel:
/// `normalizers/<channel>/<verb>.yaml`). The two layouts can coexist
/// during the PR 4 migration window.
///
/// Skips `_channel.yaml` (channel metadata) and `aliases.yaml` (alias
/// table) since neither is a normalizer.
pub fn discover_normalizer_yamls(
    pack_dir: impl AsRef<Path>,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let normalizers_dir = pack_dir.as_ref().join("normalizers");
    if !normalizers_dir.exists() {
        return Ok(Vec::new());
    }
    let mut yamls = Vec::new();
    walk_normalizers(&normalizers_dir, 0, &mut yamls)?;
    yamls.sort();
    Ok(yamls)
}

/// Enumerate every per-channel `aliases.yaml` plus the legacy pack-root
/// `aliases.yaml`, in stable order. Used by the alias resolver to build
/// one merged routing table from the channel-split layout.
pub fn discover_alias_yamls(
    pack_dir: impl AsRef<Path>,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let pack_dir = pack_dir.as_ref();
    let mut paths = Vec::new();

    // Pack-root aliases (legacy / pre-PR-4 layout).
    let root_aliases = pack_dir.join(ALIASES_FILENAME);
    if root_aliases.is_file() {
        paths.push(root_aliases);
    }

    // Per-channel aliases (PR 4 layout).
    let normalizers_dir = pack_dir.join("normalizers");
    if normalizers_dir.is_dir() {
        let entries = std::fs::read_dir(&normalizers_dir).map_err(|e| DiscoveryError::Io {
            path: normalizers_dir.clone(),
            source: e,
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let candidate = path.join(ALIASES_FILENAME);
            if candidate.is_file() {
                paths.push(candidate);
            }
        }
    }

    paths.sort();
    Ok(paths)
}

fn walk_normalizers(
    dir: &Path,
    depth: u8,
    out: &mut Vec<PathBuf>,
) -> Result<(), DiscoveryError> {
    if depth > 1 {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|e| DiscoveryError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        let basename = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        if basename == CHANNEL_MANIFEST_FILENAME || basename == ALIASES_FILENAME {
            continue;
        }
        let is_dir = path.is_dir();
        if is_dir && depth == 0 {
            // Skip dotfile and underscore-prefixed dirs (reserved metadata).
            if basename.starts_with('.') || basename.starts_with('_') {
                continue;
            }
            walk_normalizers(&path, depth + 1, out)?;
            continue;
        }
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") && path.is_file() {
            out.push(path);
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
        let base =
            std::env::temp_dir().join(format!("permit0-discover-{}-{}", name, std::process::id()));
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
        write(&root.join("community/alice/jira/pack.yaml"), "name: jira");
        let packs = discover_packs(&root).unwrap();
        assert!(
            packs.is_empty(),
            "phase-2 community packs not yet discoverable"
        );
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
        write(&root.join("a/b/c/pack.yaml"), "name: too-deep");
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
    fn discover_normalizer_yamls_walks_flat_layout() {
        let root = scratch("norm-flat");
        write(&root.join("normalizers/gmail_send.yaml"), "");
        write(&root.join("normalizers/outlook_send.yaml"), "");
        let yamls = discover_normalizer_yamls(&root).unwrap();
        assert_eq!(yamls.len(), 2);
    }

    #[test]
    fn discover_normalizer_yamls_walks_per_channel() {
        let root = scratch("norm-per-ch");
        write(&root.join("normalizers/gmail/send.yaml"), "");
        write(&root.join("normalizers/gmail/archive.yaml"), "");
        write(&root.join("normalizers/outlook/send.yaml"), "");
        // _channel.yaml is metadata; aliases.yaml is alias table —
        // both must be excluded from normalizer enumeration.
        write(&root.join("normalizers/gmail/_channel.yaml"), "channel: gmail");
        write(&root.join("normalizers/gmail/aliases.yaml"), "aliases: []");

        let yamls = discover_normalizer_yamls(&root).unwrap();
        assert_eq!(yamls.len(), 3);
        assert!(yamls.iter().all(|p| {
            let bn = p.file_name().unwrap().to_str().unwrap();
            bn != "_channel.yaml" && bn != "aliases.yaml"
        }));
    }

    #[test]
    fn discover_normalizer_yamls_handles_mixed_layout() {
        // During PR 4's migration window flat and per-channel can coexist.
        let root = scratch("norm-mixed");
        write(&root.join("normalizers/gmail_send.yaml"), "");
        write(&root.join("normalizers/outlook/send.yaml"), "");
        let yamls = discover_normalizer_yamls(&root).unwrap();
        assert_eq!(yamls.len(), 2);
    }

    #[test]
    fn discover_alias_yamls_finds_pack_root_and_per_channel() {
        let root = scratch("aliases");
        write(&root.join("aliases.yaml"), "aliases: []");
        write(&root.join("normalizers/gmail/aliases.yaml"), "aliases: []");
        write(&root.join("normalizers/outlook/aliases.yaml"), "aliases: []");

        let aliases = discover_alias_yamls(&root).unwrap();
        assert_eq!(aliases.len(), 3);
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
