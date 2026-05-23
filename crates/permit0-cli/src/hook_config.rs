#![forbid(unsafe_code)]
// Public API is wired in by Task 4 (hook entry point); until then the
// surface is intentionally dormant. Remove this once `cmd::hook` calls
// `hook_config::load` / `hook_config::resolve`.
#![allow(dead_code)]

//! Per-user TOML config for the `permit0 hook` adapter.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cmd::hook::{ClientKind, UnknownMode};

/// Routing for HITL verdicts (configured per-hook in the TOML file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HitlRouting {
    /// Default — Claude Code's inline ask UI.
    #[default]
    CcPrompt,
    /// Block at the engine until a human approves in the dashboard.
    UiWait,
}

impl std::str::FromStr for HitlRouting {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "cc-prompt" | "cc_prompt" => Ok(Self::CcPrompt),
            "ui-wait" | "ui_wait" => Ok(Self::UiWait),
            other => Err(format!(
                "unknown hitl_routing '{other}' (supported: cc-prompt, ui-wait)"
            )),
        }
    }
}

/// Raw deserialized form of `~/.config/permit0/config.toml`.
///
/// All fields are optional; a field that fails to parse (wrong type,
/// unknown enum value) is a hard error — silent fallback to defaults
/// would hide misconfiguration in a security tool. `deny_unknown_fields`
/// catches typos like `hitl_route` vs `hitl_routing`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfigFile {
    pub remote: Option<String>,
    pub hitl_routing: Option<String>,
    pub hitl_timeout_secs: Option<u64>,
    pub unknown_mode: Option<String>,
    pub org_domain: Option<String>,
    pub client: Option<String>,
    pub shadow: Option<bool>,
}

/// Resolved configuration after layering CLI > env > file > default.
#[derive(Debug, Clone)]
pub struct ResolvedHookConfig {
    pub remote: Option<String>,
    pub hitl_routing: HitlRouting,
    pub hitl_timeout_secs: u64,
    pub unknown_mode: UnknownMode,
    pub org_domain: String,
    pub client: ClientKind,
    pub shadow: bool,
}

/// CLI flags relevant to the hook config (a subset of `Commands::Hook`).
/// Passed into `resolve` so we can apply the highest-precedence layer.
#[derive(Debug, Default, Clone)]
pub struct HookCliArgs {
    pub remote: Option<String>,
    pub unknown: Option<String>,
    pub org_domain: Option<String>,
    pub client: Option<String>,
    pub shadow: Option<bool>,
}

/// Per-process env-var snapshot. Captured once so tests can inject.
#[derive(Debug, Default, Clone)]
pub struct HookEnv {
    pub permit0_remote: Option<String>,
    pub permit0_unknown: Option<String>,
    pub permit0_client: Option<String>,
    pub permit0_shadow: Option<bool>,
}

impl HookEnv {
    /// Read from the real process env. CLI uses this; tests construct
    /// `HookEnv { ... }` directly.
    pub fn from_process() -> Self {
        let nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        Self {
            permit0_remote: nonempty("PERMIT0_REMOTE"),
            permit0_unknown: nonempty("PERMIT0_UNKNOWN"),
            permit0_client: nonempty("PERMIT0_CLIENT"),
            permit0_shadow: std::env::var("PERMIT0_SHADOW")
                .ok()
                .map(|v| !v.is_empty() && v != "0"),
        }
    }
}

/// Parse a TOML string into `HookConfigFile`. Hard-errors on unknown
/// fields and on type mismatches.
pub fn parse(s: &str) -> Result<HookConfigFile> {
    toml::from_str(s).context("parsing hook TOML config")
}

/// Resolve the path the hook should load. Order:
/// 1. `explicit` (the `--config <path>` CLI flag value)
/// 2. `$PERMIT0_CONFIG`
/// 3. `~/.config/permit0/config.toml` (only this layer is existence-checked)
///
/// Returns `None` only when no layer produces a candidate. Explicit
/// and env-var paths are returned verbatim so `load_from_path` can
/// produce a loud "file at PATH not found" error when the operator
/// pointed at a missing file.
pub fn resolve_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(p) = std::env::var("PERMIT0_CONFIG") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let home = dirs::home_dir()?;
    let candidate = home.join(".config").join("permit0").join("config.toml");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Load the file at `path`, parsing it. A `None` path returns the
/// default empty `HookConfigFile`. A `Some(path)` that points at a
/// missing file is a hard error — explicit paths from `--config` or
/// `$PERMIT0_CONFIG` should not silently fall back.
pub fn load_from_path(path: Option<&Path>) -> Result<HookConfigFile> {
    let Some(p) = path else {
        return Ok(HookConfigFile::default());
    };
    let bytes = std::fs::read_to_string(p)
        .with_context(|| format!("reading hook config at {}", p.display()))?;
    parse(&bytes)
}

/// Top-level loader used by the CLI: resolves the path, reads the file
/// (or returns defaults if none), and returns the parsed file plus the
/// path that was used (for error breadcrumbs).
pub fn load(explicit: Option<&Path>) -> Result<(HookConfigFile, Option<PathBuf>)> {
    let path = resolve_path(explicit);
    let file = load_from_path(path.as_deref())?;
    Ok((file, path))
}

/// Layer file < env < CLI, returning the fully-resolved config. Returns
/// an error if any string field fails to parse to its typed form.
pub fn resolve(file: HookConfigFile, env: HookEnv, cli: HookCliArgs) -> Result<ResolvedHookConfig> {
    use std::str::FromStr;

    // remote: cli > env > file > None
    let remote = cli.remote.or(env.permit0_remote).or(file.remote);

    // hitl_routing: file only (no env/CLI surface in this PR — keep the
    // surface tight so we don't promise more configurability than the
    // spec asks for; can be promoted later if needed).
    let hitl_routing = match file.hitl_routing.as_deref() {
        Some(s) => HitlRouting::from_str(s).map_err(anyhow::Error::msg)?,
        None => HitlRouting::default(),
    };
    // hitl_timeout_secs: file-only for symmetry with hitl_routing.
    let hitl_timeout_secs = file.hitl_timeout_secs.unwrap_or(300);

    // unknown_mode: cli > env > file > default(Defer)
    let unknown_str = cli.unknown.or(env.permit0_unknown).or(file.unknown_mode);
    let unknown_mode = match unknown_str {
        Some(s) => UnknownMode::from_str(&s).map_err(anyhow::Error::msg)?,
        None => UnknownMode::default(),
    };

    // org_domain: cli > file > default. No env layer — the daemon
    // owns the org for remote evaluation; the hook only needs to
    // override at the local boundary.
    let org_domain = cli
        .org_domain
        .or(file.org_domain)
        .unwrap_or_else(|| "default.org".into());

    // client: cli > env > file > default(ClaudeCode)
    let client_str = cli.client.or(env.permit0_client).or(file.client);
    let client = match client_str {
        Some(s) => ClientKind::from_str(&s).map_err(anyhow::Error::msg)?,
        None => ClientKind::default(),
    };

    // shadow: cli > env > file > false
    let shadow = cli
        .shadow
        .or(env.permit0_shadow)
        .or(file.shadow)
        .unwrap_or(false);

    Ok(ResolvedHookConfig {
        remote,
        hitl_routing,
        hitl_timeout_secs,
        unknown_mode,
        org_domain,
        client,
        shadow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_env() -> HookEnv {
        HookEnv::default()
    }

    fn empty_cli() -> HookCliArgs {
        HookCliArgs::default()
    }

    #[test]
    fn parse_empty_string_returns_defaults() {
        let f = parse("").unwrap();
        assert!(f.remote.is_none());
        assert!(f.hitl_routing.is_none());
    }

    #[test]
    fn parse_full_file() {
        let toml = r#"
remote = "http://127.0.0.1:9090"
hitl_routing = "ui-wait"
hitl_timeout_secs = 600
unknown_mode = "defer"
org_domain = "acme.example"
client = "claude-code"
shadow = true
"#;
        let f = parse(toml).unwrap();
        assert_eq!(f.remote.as_deref(), Some("http://127.0.0.1:9090"));
        assert_eq!(f.hitl_routing.as_deref(), Some("ui-wait"));
        assert_eq!(f.hitl_timeout_secs, Some(600));
        assert_eq!(f.unknown_mode.as_deref(), Some("defer"));
        assert_eq!(f.org_domain.as_deref(), Some("acme.example"));
        assert_eq!(f.client.as_deref(), Some("claude-code"));
        assert_eq!(f.shadow, Some(true));
    }

    #[test]
    fn parse_unknown_field_is_fatal() {
        // Mis-config in a security tool must be loud. Silent ignore would
        // mask typos like `hitl_route` vs `hitl_routing`.
        let toml = r#"hitl_route = "ui-wait""#;
        let err = parse(toml).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("hitl_route") || msg.contains("unknown field"));
    }

    #[test]
    fn parse_malformed_toml_is_fatal() {
        let err = parse("this is not valid = = toml").unwrap_err();
        assert!(format!("{err:?}").contains("parsing hook TOML config"));
    }

    #[test]
    fn resolve_uses_defaults_when_everything_unset() {
        let r = resolve(HookConfigFile::default(), empty_env(), empty_cli()).unwrap();
        assert!(r.remote.is_none());
        assert_eq!(r.hitl_routing, HitlRouting::CcPrompt);
        assert_eq!(r.hitl_timeout_secs, 300);
        assert_eq!(r.unknown_mode, UnknownMode::default());
        assert_eq!(r.org_domain, "default.org");
        assert_eq!(r.client, ClientKind::default());
        assert!(!r.shadow);
    }

    #[test]
    fn resolve_file_wins_over_default() {
        let file = HookConfigFile {
            hitl_routing: Some("ui-wait".into()),
            hitl_timeout_secs: Some(120),
            org_domain: Some("acme.example".into()),
            shadow: Some(true),
            ..HookConfigFile::default()
        };
        let r = resolve(file, empty_env(), empty_cli()).unwrap();
        assert_eq!(r.hitl_routing, HitlRouting::UiWait);
        assert_eq!(r.hitl_timeout_secs, 120);
        assert_eq!(r.org_domain, "acme.example");
        assert!(r.shadow);
    }

    #[test]
    fn resolve_env_wins_over_file() {
        let file = HookConfigFile {
            remote: Some("http://file:9090".into()),
            shadow: Some(false),
            ..HookConfigFile::default()
        };
        let env = HookEnv {
            permit0_remote: Some("http://env:9090".into()),
            permit0_shadow: Some(true),
            ..HookEnv::default()
        };
        let r = resolve(file, env, empty_cli()).unwrap();
        assert_eq!(r.remote.as_deref(), Some("http://env:9090"));
        assert!(r.shadow);
    }

    #[test]
    fn resolve_cli_wins_over_env() {
        let env = HookEnv {
            permit0_remote: Some("http://env:9090".into()),
            permit0_client: Some("openclaw".into()),
            ..HookEnv::default()
        };
        let cli = HookCliArgs {
            remote: Some("http://cli:9090".into()),
            client: Some("claude-code".into()),
            ..HookCliArgs::default()
        };
        let r = resolve(HookConfigFile::default(), env, cli).unwrap();
        assert_eq!(r.remote.as_deref(), Some("http://cli:9090"));
        assert_eq!(r.client, ClientKind::ClaudeCode);
    }

    #[test]
    fn resolve_invalid_hitl_routing_is_fatal() {
        let file = HookConfigFile {
            hitl_routing: Some("inline".into()),
            ..HookConfigFile::default()
        };
        let err = resolve(file, empty_env(), empty_cli()).unwrap_err();
        assert!(format!("{err}").contains("hitl_routing"));
    }

    #[test]
    fn resolve_invalid_unknown_mode_is_fatal() {
        let file = HookConfigFile {
            unknown_mode: Some("yolo".into()),
            ..HookConfigFile::default()
        };
        let err = resolve(file, empty_env(), empty_cli()).unwrap_err();
        assert!(format!("{err}").contains("yolo") || format!("{err}").contains("unknown"));
    }

    #[test]
    fn resolve_path_explicit_wins() {
        let p = Path::new("/tmp/permit0-explicit.toml");
        let resolved = resolve_path(Some(p)).unwrap();
        assert_eq!(resolved, p);
    }

    #[test]
    fn load_from_missing_explicit_path_errors_but_none_returns_default() {
        let p = Path::new("/tmp/permit0-does-not-exist-xyz-task3.toml");
        let f = load_from_path(Some(p));
        // Explicit-but-missing must error so misconfiguration is loud.
        assert!(f.is_err(), "explicit missing path must error, got {f:?}");
        // None (no candidate exists at all) returns defaults.
        let no_path: Option<&Path> = None;
        let f = load_from_path(no_path).unwrap();
        assert!(f.remote.is_none());
    }
}
