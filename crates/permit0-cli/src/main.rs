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
    },
    /// Pack management: validate, test, scaffold
    #[command(subcommand)]
    Pack(PackCmd),
    /// Calibration: profiles, corpus testing, guardrail validation
    #[command(subcommand)]
    Calibrate(CalibrateCmd),
}

#[derive(Subcommand)]
enum PackCmd {
    /// Validate normalizer and risk rule YAML files
    Validate {
        /// Path to the pack directory (e.g. packs/stripe)
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
        } => cmd::hook::run(profile, &org_domain),
        Commands::Gateway {
            profile,
            org_domain,
        } => cmd::gateway::run(profile, &org_domain),
        Commands::Serve {
            port,
            profile,
            org_domain,
            ui,
        } => cmd::serve::run(port, profile, &org_domain, ui),
        Commands::Pack(pack_cmd) => match pack_cmd {
            PackCmd::Validate { path } => cmd::pack::validate(&path),
            PackCmd::Test { path } => cmd::pack::test(&path),
            PackCmd::New { name } => cmd::pack::new_pack(&name),
        },
        Commands::Calibrate(cal_cmd) => match cal_cmd {
            CalibrateCmd::Test { corpus } => cmd::calibrate::test_corpus(&corpus),
            CalibrateCmd::Validate { profile } => cmd::calibrate::validate_profile(&profile),
            CalibrateCmd::Diff { profile } => cmd::calibrate::diff_profile(&profile),
        },
    }
}
