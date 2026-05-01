#![forbid(unsafe_code)]

mod cmd;
mod engine_factory;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "permit0", about = "Agent safety & permission framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Score a tool call and print the decision
    Check {
        /// JSON tool call (reads from stdin if omitted)
        #[arg(long)]
        input: Option<String>,
        /// Domain profile to use
        #[arg(long)]
        profile: Option<String>,
        /// Organization domain for normalization
        #[arg(long, default_value = "default.org")]
        org_domain: String,
    },
    /// Claude Code PreToolUse hook adapter (reads JSON from stdin)
    Hook {
        /// Domain profile to use
        #[arg(long)]
        profile: Option<String>,
        /// Organization domain
        #[arg(long, default_value = "default.org")]
        org_domain: String,
        /// SQLite database path for session persistence
        #[arg(long)]
        db: Option<String>,
        /// Session ID (default: derived from CLAUDE_SESSION_ID or PPID)
        #[arg(long)]
        session_id: Option<String>,
        /// Path to packs directory (default: ./packs/ or ~/.permit0/packs/)
        #[arg(long)]
        packs_dir: Option<String>,
        /// Shadow mode: log decisions to stderr but always return "allow".
        /// Useful for observing what permit0 *would* do before enforcing.
        /// Also enabled when PERMIT0_SHADOW=1.
        #[arg(long)]
        shadow: bool,
        /// Which MCP host (agent) is calling the hook. Controls how
        /// MCP tool-name prefixes are stripped before normalization.
        /// Supported: claude-code (default), claude-desktop, raw.
        /// Override via PERMIT0_CLIENT env var.
        #[arg(long, value_name = "CLIENT")]
        client: Option<String>,
    },
    /// Generic stdin/stdout JSON gateway (JSONL mode)
    Gateway {
        /// Domain profile to use
        #[arg(long)]
        profile: Option<String>,
        /// Organization domain
        #[arg(long, default_value = "default.org")]
        org_domain: String,
    },
    /// Start HTTP server for remote agents
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "9090")]
        port: u16,
        /// Domain profile to use
        #[arg(long)]
        profile: Option<String>,
        /// Organization domain
        #[arg(long, default_value = "default.org")]
        org_domain: String,
        /// Mount the approval UI API
        #[arg(long)]
        ui: bool,
        /// Calibration mode: every fresh decision goes to human-in-the-loop
        /// (regardless of risk tier), so you can audit and override permit0's
        /// recommendations to build a calibration corpus. Implies --ui.
        #[arg(long)]
        calibrate: bool,
    },
    /// Pack management: validate, test, scaffold
    #[command(subcommand)]
    Pack(PackCmd),
    /// Calibration: profiles, corpus testing, guardrail validation
    #[command(subcommand)]
    Calibrate(CalibrateCmd),
    /// Audit trail verification and inspection
    #[command(subcommand)]
    Audit(AuditCmd),
}

#[derive(Subcommand)]
enum PackCmd {
    /// Validate normalizer and risk rule YAML files
    Validate {
        /// Path to the pack directory (e.g. packs/email)
        path: String,
    },
    /// Run pack test fixtures
    Test {
        /// Path to the pack directory or glob pattern
        path: String,
    },
    /// Scaffold a new pack with normalizer, risk rule, and fixture stubs
    New {
        /// Pack name (e.g. "slack", "jira")
        name: String,
    },
    /// Generate or refresh `pack.lock.yaml` for a pack directory
    Lock {
        /// Path to the pack directory (e.g. packs/permit0/email)
        path: String,
        /// Verify the existing lockfile against current contents
        /// without writing changes. Exits non-zero on drift.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify chain integrity and signatures of a JSONL audit file
    Verify {
        /// Path to the JSONL audit file
        path: String,
        /// ed25519 public key (hex)
        #[arg(long)]
        public_key: String,
    },
    /// Inspect audit entries: show summary table
    Inspect {
        /// Path to the JSONL audit file
        path: String,
        /// Maximum entries to display
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Dump full JSON of a single entry by sequence number
    Dump {
        /// Path to the JSONL audit file
        path: String,
        /// Sequence number to dump
        #[arg(long)]
        seq: u64,
    },
}

#[derive(Subcommand)]
enum CalibrateCmd {
    /// Run golden calibration corpus
    Test {
        /// Path to the corpus directory
        #[arg(long, default_value = "corpora/calibration")]
        corpus: String,
    },
    /// Validate a profile against guardrails
    Validate {
        /// Profile name (e.g. fintech, healthtech)
        #[arg(long)]
        profile: String,
    },
    /// Show diff between base config and a profile
    Diff {
        /// Profile name
        #[arg(long)]
        profile: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            input,
            profile,
            org_domain,
        } => cmd::check::run(input, profile, &org_domain),
        Commands::Hook {
            profile,
            org_domain,
            db,
            session_id,
            packs_dir,
            shadow,
            client,
        } => {
            // Precedence: --client flag > PERMIT0_CLIENT env var > default.
            let client_str = client.or_else(|| std::env::var("PERMIT0_CLIENT").ok());
            let client_kind = match client_str {
                Some(s) => s
                    .parse::<cmd::hook::ClientKind>()
                    .map_err(anyhow::Error::msg)?,
                None => cmd::hook::ClientKind::default(),
            };
            cmd::hook::run(
                profile,
                &org_domain,
                db,
                session_id,
                packs_dir,
                shadow,
                client_kind,
            )
        }
        Commands::Gateway {
            profile,
            org_domain,
        } => cmd::gateway::run(profile, &org_domain),
        Commands::Serve {
            port,
            profile,
            org_domain,
            ui,
            calibrate,
        } => cmd::serve::run(port, profile, &org_domain, ui || calibrate, calibrate),
        Commands::Pack(pack_cmd) => match pack_cmd {
            PackCmd::Validate { path } => cmd::pack::validate(&path),
            PackCmd::Test { path } => cmd::pack::test(&path),
            PackCmd::New { name } => cmd::pack::new_pack(&name),
            PackCmd::Lock { path, check } => cmd::pack::lock(&path, check),
        },
        Commands::Audit(audit_cmd) => match audit_cmd {
            AuditCmd::Verify { path, public_key } => cmd::audit::verify(&path, &public_key),
            AuditCmd::Inspect { path, limit } => cmd::audit::inspect(&path, limit),
            AuditCmd::Dump { path, seq } => cmd::audit::dump_entry(&path, seq),
        },
        Commands::Calibrate(cal_cmd) => match cal_cmd {
            CalibrateCmd::Test { corpus } => cmd::calibrate::test_corpus(&corpus),
            CalibrateCmd::Validate { profile } => cmd::calibrate::validate_profile(&profile),
            CalibrateCmd::Diff { profile } => cmd::calibrate::diff_profile(&profile),
        },
    }
}
