// SPDX-License-Identifier: AGPL-3.0-only
//! `spl-server` command-line entry point.

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, ValueEnum};
use scoplen_server::{Config, Role, ServerError, VERSION, prepare_roles, resolve_roles};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "spl-server", version = VERSION, about = "Scoplen self-hosted server")]
struct Cli {
    /// Configuration TOML file. Missing files use Personal-profile defaults.
    #[arg(long, default_value = "spl-server.toml", env = "SPL_CONFIG")]
    config: PathBuf,
    /// Override the roles in the configuration. May be repeated.
    #[arg(long, value_enum)]
    role: Vec<CliRole>,
    /// Validate configuration and exit without starting listeners or generating material.
    #[arg(long)]
    validate_config: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliRole {
    Api,
    Worker,
    Ca,
    Edge,
    Gateway,
    All,
}

impl CliRole {
    fn as_name(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Worker => "worker",
            Self::Ca => "ca",
            Self::Edge => "edge",
            Self::Gateway => "gateway",
            Self::All => "all",
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("spl-server: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), ServerError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .try_init()
        .ok();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let role_names = if cli.role.is_empty() {
        config.roles.names.clone()
    } else {
        cli.role.iter().map(|role| role.as_name().to_owned()).collect()
    };
    let roles = resolve_roles(&role_names).map_err(|error| {
        ServerError::Config(scoplen_server::ConfigError::Invalid(error.to_string()))
    })?;
    config.validate_for_roles(&roles)?;
    if cli.validate_config {
        println!("configuration valid: {}", cli.config.display());
        return Ok(());
    }

    let prepared = prepare_roles(&config, &roles).await?;
    if let Some(link) = prepared.setup_link {
        println!("one-time operator setup link (keep private): {}", link.expose_link().as_str());
    }
    scoplen_server::run_roles(
        config,
        roles,
        prepared.store,
        prepared.postgres_store,
        prepared.object_storage,
        prepared.key_management,
        prepared.audit_signer,
    )
    .await
}

// Keep the public role names visible to rustdoc and downstream CLI tooling.
#[allow(dead_code)]
fn _role_type_is_public(_: Role) {}
