// SPDX-License-Identifier: AGPL-3.0-only
//! Archive commands with process-lifetime deployment admission.

use std::{path::PathBuf, process::ExitCode};

use clap::Subcommand;
use scoplen_server::{
    Config,
    backup::{self, BackupReport},
    deployment_lease::DeploymentLease,
};

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Create a complete encrypted archive; stop the deployment unless using --online.
    Create {
        /// Capture live SQLite with stable local files and plain or static-files TLS.
        #[arg(long)]
        online: bool,
        #[arg(long, default_value = "spl-server.toml", env = "SPL_CONFIG")]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// File containing 1–4,096 exact UTF-8 bytes, without trimming.
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Authenticate the complete archive and check its retained deployment state.
    Verify {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Restore into an absent child of an existing private parent directory.
    Restore {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
}

pub(crate) async fn run(command: Command) -> ExitCode {
    match execute(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("splctl: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Create { online, config, output, passphrase_file } => {
            let config = Config::load(&config)?;
            let lease = if online {
                DeploymentLease::try_shared(&config.server.data_dir)?
            } else {
                DeploymentLease::try_exclusive(&config.server.data_dir)?
            };
            let lease = super::PROCESS_LEASE.get_or_init(|| lease);
            if online {
                backup::create_online(&config, &output, &passphrase_file, lease).await?;
            } else {
                backup::create(&config, &output, &passphrase_file, lease).await?;
            }
            println!("Backup created.");
        }
        Command::Verify { archive, passphrase_file } => {
            let report = backup::verify(&archive, &passphrase_file).await?;
            println!("Backup verified.");
            settings(&report);
        }
        Command::Restore { archive, data_dir, passphrase_file } => {
            let root = std::path::absolute(&data_dir)?;
            let report = backup::restore(&archive, &data_dir, &passphrase_file).await?;
            println!("Backup restored.");
            settings(&report);
            println!("Before starting, configure server.data_dir = {}", root.display());
            println!("storage.object.directory = {}", root.join("objects").display());
            println!("storage.kms.key_file = {}", root.join("kms.key").display());
            println!("storage.kms.audit_key_file = {}", root.join("audit-signing.key").display());
            if report.tls_mode == "files" {
                if !report.external_tls_certificate {
                    println!("tls.cert_file = {}", root.join("tls/certificate.pem").display());
                }
                if !report.external_tls_key {
                    println!("tls.key_file = {}", root.join("tls/private-key.pem").display());
                }
            }
            println!(
                "Supply the original operator TOML/environment settings separately before starting the server."
            );
        }
    }
    Ok(())
}

fn settings(report: &BackupReport) {
    println!("Original public origin: {}", report.origin);
    println!(
        "server.public_host = {}; server.public_port = {}; tls.mode = {}",
        report.public_host, report.public_port, report.tls_mode
    );
    if report.external_tls_certificate || report.external_tls_key {
        println!("Reprovision the external TLS certificate and private key for this same origin.");
    }
}
