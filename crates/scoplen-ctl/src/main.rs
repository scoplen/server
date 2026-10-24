// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit local administration operations; no remote setup recovery endpoint exists.

use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode, sync::OnceLock};

static PROCESS_LEASE: OnceLock<scoplen_server::deployment_lease::DeploymentLease> = OnceLock::new();

#[derive(Parser)]
#[command(name = "splctl", about = "Scoplen local deployment administration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Replace a lost or expired first-operator link on this server host.
    Bootstrap {
        /// Explicitly replace only the pending entitlement; completed setup cannot reopen.
        #[arg(long, required = true)]
        reissue_pending: bool,
        /// Local server configuration, including database and key-management settings.
        #[arg(long, default_value = "spl-server.toml", env = "SPL_CONFIG")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Bootstrap { config, reissue_pending: _ } => run(&config).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("splctl: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(path: &std::path::Path) -> Result<(), scoplen_server::ServerError> {
    let config = scoplen_server::Config::load(path)?;
    let lease = scoplen_server::admit_local_deployment(&config)?;
    PROCESS_LEASE.get_or_init(|| lease);
    let disclosure = scoplen_server::reissue_operator_setup(&config).await?;
    println!("one-time operator setup link (keep private): {}", disclosure.expose_link().as_str());
    Ok(())
}
