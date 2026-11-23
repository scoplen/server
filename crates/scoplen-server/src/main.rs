// SPDX-License-Identifier: AGPL-3.0-only
//! `spl-server` command-line entry point.

use std::{path::PathBuf, process::ExitCode, sync::OnceLock};

use clap::{Parser, ValueEnum};
use scoplen_server::{Config, Role, ServerError, VERSION, prepare_roles, resolve_roles};
use tracing_subscriber::{EnvFilter, Layer as _, filter::filter_fn, layer::SubscriberExt as _};

static PROCESS_LEASE: OnceLock<scoplen_server::deployment_lease::DeploymentLease> = OnceLock::new();

// Wire traces can carry request targets, TLS names or headers even without application logging.
const WIRE_LOG_TARGETS: &[&str] = &["reqwest", "hyper", "h2", "rustls", "tokio_rustls"];

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
        if matches!(error, ServerError::ShutdownTimedOut) {
            // The fatal drain already retained deployment admission. Tokio teardown would
            // otherwise wait for an unfinished blocking capture beyond that deadline.
            std::process::exit(1);
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), ServerError> {
    let events = tracing_subscriber::fmt::layer()
        .json()
        .with_filter(filter_fn(|metadata| application_log_target(metadata.target())));
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(events);
    tracing::subscriber::set_global_default(subscriber).ok();
    wire_filtered_log_bridge().ok();

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

    if roles.iter().any(|role| role.requires_store()) {
        let lease = scoplen_server::admit_local_deployment(&config)?;
        PROCESS_LEASE.get_or_init(|| lease);
    }
    let prepared = prepare_roles(&config, &roles).await?;
    if let Some(link) = prepared.setup_link.as_ref() {
        println!("one-time operator setup link (keep private): {}", link.expose_link().as_str());
    }
    scoplen_server::run_roles(config, roles, prepared).await
}

fn application_log_target(target: &str) -> bool {
    !WIRE_LOG_TARGETS.iter().any(|wire| target.starts_with(*wire))
}

fn wire_filtered_log_bridge() -> Result<(), tracing_log::log::SetLoggerError> {
    tracing_log::LogTracer::builder().ignore_all(WIRE_LOG_TARGETS.iter().copied()).init()
}

// Keep the public role names visible to rustdoc and downstream CLI tooling.
#[allow(dead_code)]
fn _role_type_is_public(_: Role) {}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

    use super::{EnvFilter, application_log_target, filter_fn, wire_filtered_log_bridge};

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("fixture log lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn wire_trace_targets_are_excluded_from_server_logs() {
        for target in [
            "reqwest::connect",
            "hyper::proto::h1",
            "hyper_util::client::legacy::pool",
            "h2::codec",
            "rustls::conn",
            "rustls_platform_verifier::verification",
            "rustls_native_certs",
            "tokio_rustls",
        ] {
            assert!(!application_log_target(target), "{target}");
        }
        assert!(application_log_target("scoplen_server::oidc"));
        assert!(application_log_target("scoplen_server::runtime"));

        let logs = LogBuffer::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("trace,reqwest::connect=trace"))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || writer.clone())
                    .with_filter(filter_fn(|metadata| application_log_target(metadata.target()))),
            );
        wire_filtered_log_bridge().expect("install fixture log bridge");
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(target: "reqwest::connect", "provider wire trace fixture");
            tracing::trace!(target: "scoplen_server::oidc", "typed application trace fixture");
            tracing_log::log::trace!(target: "reqwest::connect", "provider wire log fixture");
            tracing_log::log::trace!(target: "scoplen_server::oidc", "bridged application event fixture");
        });
        let logs = logs.0.lock().expect("read fixture logs");
        let output = std::str::from_utf8(&logs).expect("UTF-8 fixture log");
        assert!(!output.contains("provider wire trace fixture"));
        assert!(!output.contains("provider wire log fixture"));
        assert!(output.contains("typed application trace fixture"));
        assert!(output.contains("bridged application event fixture"));
    }
}
