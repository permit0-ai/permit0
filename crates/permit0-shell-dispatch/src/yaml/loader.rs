//! Filesystem loaders that collect YAML dispatcher files into
//! [`YamlCommandParser`]s.
//!
//! Two conventions are supported:
//!
//! 1. **Pack-owned** (`packs/<name>/dispatchers/*.yaml`) — every pack ships
//!    the dispatchers for its own service. Preferred for production:
//!    [`load_pack_dispatchers`].
//!
//! 2. **Flat directory** (`<dir>/*.yaml`) — useful for tests or for
//!    out-of-tree configuration pinned by a caller: [`load_yaml_dir`].
//!
//! Both entry points MERGE multiple files that declare rules for the same
//! `program:` into a single parser, so each CLI appears exactly once in
//! the dispatcher.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::parser::{YamlCommandParser, YamlParserError};

/// Errors from loader operations.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("I/O reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: YamlParserError,
    },
}

/// Walk a single directory of `*.yaml` / `*.yml` files and build one
/// parser per distinct `program:` value. Files inside a subdirectory are
/// not followed — use this for flat layouts only.
pub fn load_yaml_dir<P: AsRef<Path>>(dir: P) -> Result<Vec<YamlCommandParser>, LoadError> {
    let path_buf = dir.as_ref().to_path_buf();
    let entries = read_dir_sorted(&path_buf)?;
    let yaml_files: Vec<_> = entries.into_iter().filter(|p| is_yaml_file(p)).collect();
    load_files_merging_by_program(&yaml_files)
}

/// Scan every pack under `packs_dir` for a `dispatchers/` subdirectory and
/// produce one parser per program. Packs without a `dispatchers/`
/// subdirectory are skipped.
///
/// Pack discovery delegates to `permit0_dsl::discover_packs`, which finds
/// packs at depth 1 (flat legacy layout) and depth 2 (owner-namespaced
/// layout introduced in PR 3 of the pack taxonomy refactor).
///
/// `packs_dir` is typically the repo-root `packs/` directory.
pub fn load_pack_dispatchers<P: AsRef<Path>>(
    packs_dir: P,
) -> Result<Vec<YamlCommandParser>, LoadError> {
    let base = packs_dir.as_ref();
    let packs = permit0_dsl::discover_packs(base).map_err(|e| LoadError::Io {
        path: base.display().to_string(),
        source: std::io::Error::other(e.to_string()),
    })?;

    let mut all_files = Vec::new();
    for pack_dir in packs {
        let dispatchers = pack_dir.join("dispatchers");
        if !dispatchers.is_dir() {
            continue;
        }
        let files = read_dir_sorted(&dispatchers)?;
        for f in files {
            if is_yaml_file(&f) {
                all_files.push(f);
            }
        }
    }

    load_files_merging_by_program(&all_files)
}

fn load_files_merging_by_program(files: &[PathBuf]) -> Result<Vec<YamlCommandParser>, LoadError> {
    let mut by_program: HashMap<String, YamlCommandParser> = HashMap::new();

    for path in files {
        let parser = YamlCommandParser::from_file(path).map_err(|e| LoadError::Parse {
            path: path.display().to_string(),
            source: e,
        })?;
        let key = parser.program().to_ascii_lowercase();
        if let Some(existing) = by_program.remove(&key) {
            let mut combined = existing;
            combined.merge(parser).map_err(|e| LoadError::Parse {
                path: path.display().to_string(),
                source: e,
            })?;
            by_program.insert(key, combined);
        } else {
            by_program.insert(key, parser);
        }
    }

    // Stable output order — alphabetic by program name keeps tests
    // deterministic.
    let mut out: Vec<_> = by_program.into_values().collect();
    out.sort_by(|a, b| a.program().cmp(b.program()));
    Ok(out)
}

fn is_yaml_file(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml") | Some("yml") => path.is_file(),
        _ => false,
    }
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let rd = std::fs::read_dir(dir).map_err(|e| LoadError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    let mut entries: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    entries.sort();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permit0-shell-dispatch-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn flat_dir_loads_multiple_programs() {
        let dir = tmp_dir();
        write(
            &dir,
            "gog.yaml",
            r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send
    parameters: {}
"#,
        );
        write(
            &dir,
            "gh.yaml",
            r#"
program: gh
dispatches:
  - match: { subcommands: [pr, create] }
    tool_name: gh_pr_create
    parameters: {}
"#,
        );

        let parsers = load_yaml_dir(&dir).unwrap();
        let programs: Vec<&str> = parsers.iter().map(|p| p.program()).collect();
        assert_eq!(programs, vec!["gh", "gog"]); // sorted

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn flat_dir_merges_same_program() {
        let dir = tmp_dir();
        write(
            &dir,
            "gog-gmail.yaml",
            r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send
    parameters: {}
"#,
        );
        write(
            &dir,
            "gog-stripe.yaml",
            r#"
program: gog
dispatches:
  - match: { subcommands: [stripe, charge] }
    tool_name: http
    parameters: {}
"#,
        );

        let parsers = load_yaml_dir(&dir).unwrap();
        assert_eq!(parsers.len(), 1, "two files, one program → one parser");
        assert_eq!(parsers[0].rule_count(), 2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pack_layout_discovers_dispatchers() {
        let base = tmp_dir();
        // Each pack directory needs pack.yaml — that is what
        // permit0_dsl::discover_packs uses to identify a pack.

        // packs/gmail/{pack.yaml,dispatchers/gog.yaml}
        std::fs::create_dir_all(base.join("gmail/dispatchers")).unwrap();
        write(&base.join("gmail"), "pack.yaml", "name: gmail");
        write(
            &base.join("gmail/dispatchers"),
            "gog.yaml",
            r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send
    parameters: {}
"#,
        );
        // packs/stripe/{pack.yaml,dispatchers/gog.yaml} — same program, different rules
        std::fs::create_dir_all(base.join("stripe/dispatchers")).unwrap();
        write(&base.join("stripe"), "pack.yaml", "name: stripe");
        write(
            &base.join("stripe/dispatchers"),
            "gog.yaml",
            r#"
program: gog
dispatches:
  - match: { subcommands: [stripe, charge] }
    tool_name: http
    parameters: {}
"#,
        );
        // packs/bash/{pack.yaml,normalizers/...} — no dispatchers/ → ignored
        std::fs::create_dir_all(base.join("bash/normalizers")).unwrap();
        write(&base.join("bash"), "pack.yaml", "name: bash");
        write(
            &base.join("bash/normalizers"),
            "shell.yaml",
            "program: irrelevant",
        );

        let parsers = load_pack_dispatchers(&base).unwrap();
        assert_eq!(parsers.len(), 1);
        assert_eq!(parsers[0].rule_count(), 2);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn pack_layout_supports_owner_namespaced() {
        // PR 3 layout: packs/<owner>/<pack>/dispatchers/<file>.yaml.
        // Verifies discover_packs's depth-2 walk reaches the
        // dispatcher YAMLs.
        let base = tmp_dir();
        std::fs::create_dir_all(base.join("permit0/email/dispatchers")).unwrap();
        write(&base.join("permit0/email"), "pack.yaml", "name: email");
        write(
            &base.join("permit0/email/dispatchers"),
            "gog.yaml",
            r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send
    parameters: {}
"#,
        );

        let parsers = load_pack_dispatchers(&base).unwrap();
        assert_eq!(parsers.len(), 1);
        assert_eq!(parsers[0].rule_count(), 1);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn non_yaml_files_ignored() {
        let dir = tmp_dir();
        write(&dir, "readme.md", "# not yaml");
        write(&dir, "config.toml", "[section]");
        write(
            &dir,
            "gog.yaml",
            r#"
program: gog
dispatches: []
"#,
        );

        let parsers = load_yaml_dir(&dir).unwrap();
        assert_eq!(parsers.len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
