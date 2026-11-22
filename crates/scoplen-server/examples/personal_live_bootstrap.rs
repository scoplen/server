// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable, loopback-only public HTTPS bootstrap for independent integration consumers.

use std::{
    env::vars_os,
    fs,
    io::Read as _,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{body::Bytes, http::Request};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use scoplen_api::{
    auth::BrowserAuthTokenResponse,
    operator_auth::{
        OperatorLoginFinishRequest, OperatorLoginOptionsResponse, OperatorLogoutResponse,
        OperatorSetupFinishRequest, OperatorSetupFinishResponse, OperatorSetupOptionsRequest,
        OperatorSetupOptionsResponse,
    },
    organization::{OrganizationPage, OrganizationResource},
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken, P256SigningKey};
use scoplen_server::{Config, TlsMode};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsConnector;
use url::Url;
use zeroize::Zeroizing;

#[path = "personal_live_bootstrap/account.rs"]
mod account;
#[path = "../../scoplen-store/tests/support/passkey.rs"]
mod passkey;
#[path = "../src/private_material.rs"]
mod private_material;

type Result<T> = std::result::Result<T, &'static str>;
const MARKER: &str = "disposable-scoplen-public-https-v1";
const SETUP_PREFIX: &str = "one-time operator setup link (keep private): ";
const SETUP_OPTIONS: &str = "/api/v1/auth/operator/setup/options";
const SETUP_FINISH: &str = "/api/v1/auth/operator/setup/finish";
const LOGIN_OPTIONS: &str = "/api/v1/auth/operator/login/options";
const LOGIN_FINISH: &str = "/api/v1/auth/operator/login/finish";
const LOGOUT: &str = "/api/v1/auth/operator/logout";
const GRANTS_ACCEPTANCE: &str = "{\"grant_device_browser_https_verified\":true,\"grant_certificate_expiry_verified\":true,\"grant_lifecycle_tenant_verified\":true,\"grant_personal_sync_preserved\":true}";
const REQUESTS_ACCEPTANCE: &str = "{\"request_device_browser_https_verified\":true,\"request_current_routing_tenant_verified\":true,\"request_original_confirmation_verified\":true,\"request_personal_sync_preserved\":true}";
const REQUEST_RESPONSE_LOSS_ACCEPTANCE: &str = "{\"request_device_browser_response_loss_verified\":true,\"request_original_confirmation_verified\":true,\"request_single_transition_effects_verified\":true,\"request_personal_sync_preserved\":true}";
const TENANT_ISOLATION_ACCEPTANCE: &str = "{\"tenant_foreign_absent_inventory_verified\":true,\"tenant_custom_policy_boundary_verified\":true,\"tenant_view_revision_verified\":true,\"tenant_view_connect_separation_verified\":true,\"tenant_foreign_reference_verified\":true,\"tenant_membership_removal_verified\":true,\"tenant_personal_sync_preserved\":true}";
const PASSWORD_CHANGE_ACCEPTANCE: &str = "{\"password_change_native_https_verified\":true,\"password_change_browser_generation_verified\":true,\"password_change_historical_receipt_verified\":true}";

#[derive(Parser)]
#[command(about = "Disposable loopback HTTPS fixture; never use a real deployment or passkey")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new fixture directory. The caller starts/stops spl-server and owns its database.
    Prepare {
        directory: PathBuf,
        /// Private JSON containing only `database_url` for an empty `scoplen_fixture_*` database.
        #[arg(long)]
        postgres_config: Option<PathBuf>,
        /// Fixed unprivileged port, or a currently available port when omitted.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1024..))]
        port: Option<u16>,
    },
    /// Once only: verify public Operator setup/login/logout and retired entry absence.
    Bootstrap {
        directory: PathBuf,
        /// Private stdout capture from the first production server startup; defaults to server.log.
        #[arg(long)]
        server_log: Option<PathBuf>,
    },
    /// Once only: verify two Accounts' password entry, Host/Credential sync and isolation.
    VerifyAccount {
        directory: PathBuf,
        /// Also verify two password Accounts' teams, name settings and Personal isolation.
        #[arg(long)]
        with_team: bool,
        /// Retain Device credentials in memory across one controller-owned service restart.
        #[arg(long, requires = "with_team")]
        across_restart: bool,
    },
    /// Once only: retain independent Devices across a live archive and restored restart.
    VerifyOnlineBackup { directory: PathBuf },
    /// Verify Worker-triggered capture and restoration, retaining original Device keys.
    VerifyDailyBackup { directory: PathBuf },
    /// Once only: prove public Account entry and encrypted sync after daily capture failure.
    VerifyDailyBackupAvailable {
        directory: PathBuf,
        /// Use the separate one-attempt receipt for an empty passphrase failure.
        #[arg(long)]
        passphrase_failure: bool,
    },
    /// Once only: verify ordinary password change, existing Devices and Personal continuity.
    VerifyPasswordChange { directory: PathBuf },
    /// Once only: register two password Accounts for independent browser team acceptance.
    PrepareBrowserAccounts {
        directory: PathBuf,
        /// The fixture controller's running spl-server process id; never starts or stops it.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        server_pid: u32,
    },
    /// Once only: verify Organization audit reads with genuine Device and browser sessions.
    VerifyAudit { directory: PathBuf },
    /// Once only: verify Host Grant management and certificate bounds through real HTTPS.
    VerifyGrants { directory: PathBuf },
    /// Once only: verify request denials, routing and original confirmation through real HTTPS.
    VerifyRequests { directory: PathBuf },
    /// Once only: lose request replies and explicitly confirm their original operations over HTTPS.
    VerifyRequestResponseLoss { directory: PathBuf },
    /// Once only: verify the minimal two-Organization tenant isolation matrix through real HTTPS.
    VerifyTenantIsolation { directory: PathBuf },
    /// Once only: verify atomic inventory imports with genuine Device and browser writers.
    VerifyInventoryImport {
        directory: PathBuf,
        #[arg(long, value_enum, default_value = "csv")]
        source: InventoryImportSource,
    },
    /// Once only: prepare three private phases for independent Grant SSH/SFTP acceptance.
    PrepareGrantClient(GrantClientArguments),
    /// Once only: use imported default Logins for independent Grant SSH/SFTP acceptance.
    PrepareInventoryImportClient(InventoryImportClientArguments),
    /// Once only: hand off a real member request, independent approval and SSH/SFTP use.
    PrepareRequestClient(GrantClientArguments),
    /// Once only: publish six private phases for independent Team Snippet consumption.
    PrepareSnippetClient(GrantClientArguments),
}

#[derive(Args)]
struct GrantClientArguments {
    directory: PathBuf,
    /// Existing owned OpenSSH fixture descriptor; no target is created or changed here.
    #[arg(long)]
    openssh_descriptor: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum InventoryImportSource {
    Csv,
    #[value(name = "openssh")]
    OpenSsh,
}

#[derive(Args)]
struct InventoryImportClientArguments {
    #[command(flatten)]
    target: GrantClientArguments,
    #[arg(long, value_enum, default_value = "csv")]
    source: InventoryImportSource,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresConfig {
    database_url: String,
}

#[derive(Serialize)]
struct Descriptor<'a> {
    disposable: bool,
    origin: &'a str,
    operator_lifecycle_verified: bool,
    ca_certificate: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("personal_live_bootstrap: {message}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run(command: Command) -> Result<()> {
    if vars_os().any(|(name, _)| name.to_string_lossy().to_ascii_uppercase().starts_with("SPL_")) {
        return Err("unset SPL_* overrides before preparing or using a disposable fixture");
    }
    match command {
        Command::Prepare { directory, postgres_config, port } => {
            prepare(&directory, postgres_config.as_deref(), port)?;
            println!("fixture prepared");
        }
        Command::Bootstrap { directory, server_log } => {
            bootstrap(&directory, server_log.as_deref()).await?;
            println!("fixture descriptor ready");
        }
        Command::VerifyAccount { directory, with_team, across_restart } => {
            let directory = canonical_fixture_directory(&directory)?;
            let config = fixture_config(&directory)?;
            let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
            let https = Https::new(&directory, config.server.listen_port, origin)?;
            write_private(
                &directory.join("account-check.started"),
                "One attempt only; discard this fixture after any failure.",
            )?;
            tokio::time::timeout(
                Duration::from_secs(240),
                Box::pin(account::verify(
                    &https,
                    with_team,
                    across_restart.then_some(directory.as_path()),
                )),
            )
            .await
            .map_err(|_| "Account check exceeded its deadline; abandon this fixture")??;
            write_private(
                &directory.join("account-acceptance.json"),
                "{\"account_password_sync_verified\":true,\"account_credential_sync_verified\":true,\"account_credential_isolation_verified\":true}",
            )?;
            if with_team {
                write_private(
                    &directory.join("team-acceptance.json"),
                    "{\"team_creation_personal_sync_verified\":true,\"team_settings_personal_sync_verified\":true,\"team_account_isolation_verified\":true}",
                )?;
            }
            if across_restart {
                write_private(
                    &directory.join("team-restart-acceptance.json"),
                    "{\"team_membership_restart_verified\":true,\"team_settings_restart_verified\":true,\"team_account_isolation_restart_verified\":true}",
                )?;
            }
            println!("public Account password and encrypted sync check passed");
        }
        Command::VerifyOnlineBackup { directory } => {
            let directory = canonical_fixture_directory(&directory)?;
            let config = fixture_config(&directory)?;
            let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
            let https = Https::new(&directory, config.server.listen_port, origin)?;
            write_private(&directory.join("online-backup.started"), "One attempt only.")?;
            tokio::time::timeout(
                Duration::from_secs(300),
                Box::pin(account::verify_online_backup(&https, &directory)),
            )
            .await
            .map_err(|_| "online backup check exceeded its deadline; abandon this fixture")??;
            write_private(
                &directory.join("online-backup-acceptance.json"),
                "{\"online_public_writes_verified\":true,\"online_restored_device_team_verified\":true,\"online_restored_restart_verified\":true}",
            )?;
            println!("public online archive and restored Device check passed");
        }
        Command::VerifyDailyBackup { directory } => {
            let directory = canonical_fixture_directory(&directory)?;
            let config = fixture_config(&directory)?;
            let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
            let https = Https::new(&directory, config.server.listen_port, origin)?;
            write_private(&directory.join("daily-backup.started"), "One attempt only.")?;
            tokio::time::timeout(
                Duration::from_secs(600),
                Box::pin(account::verify_daily_backup(&https, &directory)),
            )
            .await
            .map_err(|_| "daily backup check exceeded its deadline; abandon this fixture")??;
            write_private(
                &directory.join("daily-backup-acceptance.json"),
                "{\"daily_public_writes_verified\":true,\"daily_restored_device_team_verified\":true,\"daily_restored_restart_verified\":true}",
            )?;
            println!("public daily archive and restored Device check passed");
        }
        Command::VerifyDailyBackupAvailable { directory, passphrase_failure } => {
            let directory = canonical_fixture_directory(&directory)?;
            let config = fixture_config(&directory)?;
            let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
            let https = Https::new(&directory, config.server.listen_port, origin)?;
            let prefix =
                if passphrase_failure { "daily-passphrase-failure" } else { "daily-failure" };
            write_private(&directory.join(format!("{prefix}.started")), "One attempt only.")?;
            tokio::time::timeout(
                Duration::from_secs(120),
                Box::pin(account::verify(&https, false, None)),
            )
            .await
            .map_err(|_| "daily failure check exceeded its deadline; abandon this fixture")??;
            write_private(
                &directory.join(format!("{prefix}-acceptance.json")),
                "{\"daily_failure_public_sync_verified\":true}",
            )?;
            println!("public Account and encrypted sync remain available after daily failure");
        }
        Command::PrepareBrowserAccounts { directory, server_pid } => {
            let directory = canonical_fixture_directory(&directory)?;
            let config = fixture_config(&directory)?;
            let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
            let https = Https::new(&directory, config.server.listen_port, origin)?;
            write_private(
                &directory.join("browser-accounts.started"),
                "One attempt only; discard this fixture after any failure.",
            )?;
            let descriptor = tokio::time::timeout(
                Duration::from_secs(120),
                account::prepare_browser_accounts(&https, &directory, server_pid),
            )
            .await
            .map_err(
                |_| "browser Account preparation exceeded its deadline; abandon this fixture",
            )??;
            println!("browser Accounts prepared: {}", descriptor.display());
        }
        Command::VerifyAudit { directory } => {
            let directory = canonical_fixture_directory(&directory)?;
            let config = fixture_config(&directory)?;
            let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
            let https = Https::new(&directory, config.server.listen_port, origin)?;
            write_private(
                &directory.join("audit-check.started"),
                "One attempt only; discard this fixture after any failure.",
            )?;
            tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(240),
                    Box::pin(account::verify_audit(&https)),
                )
                .await
                .map_err(|_| "Audit check exceeded its deadline; abandon this fixture")?
            })
            .await
            .map_err(|_| "Audit check task failed; abandon this fixture")??;
            write_private(
                &directory.join("audit-acceptance.json"),
                "{\"audit_device_browser_https_verified\":true,\"audit_current_authority_verified\":true,\"audit_filter_pagination_verified\":true,\"audit_unsigned_ranges_verified\":true}",
            )?;
            println!("public Device and Account-browser audit check passed");
        }
        Command::VerifyGrants { directory } => verify_grants(&directory).await?,
        Command::VerifyPasswordChange { directory } => verify_password_change(&directory).await?,
        Command::VerifyRequests { directory } => verify_requests(&directory).await?,
        Command::VerifyRequestResponseLoss { directory } => {
            verify_request_response_loss(&directory).await?;
        }
        Command::VerifyTenantIsolation { directory } => verify_tenant_isolation(&directory).await?,
        Command::VerifyInventoryImport { directory, source } => {
            verify_inventory_import(&directory, source).await?;
        }
        Command::PrepareGrantClient(arguments) => prepare_grant_client(arguments, None).await?,
        Command::PrepareInventoryImportClient(arguments) => {
            prepare_grant_client(arguments.target, Some(arguments.source)).await?;
        }
        Command::PrepareRequestClient(arguments) => prepare_request_client(arguments).await?,
        Command::PrepareSnippetClient(arguments) => prepare_snippet_client(arguments).await?,
    }
    Ok(())
}

async fn prepare_grant_client(
    arguments: GrantClientArguments,
    import_inventory: Option<InventoryImportSource>,
) -> Result<()> {
    let directory = canonical_fixture_directory(&arguments.directory)?;
    let openssh_descriptor = arguments.openssh_descriptor;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("grant-client.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_mins(15),
            Box::pin(account::prepare_grant_client(
                &https,
                &directory,
                &openssh_descriptor,
                import_inventory,
            )),
        )
        .await
        .map_err(|_| "Grant client preparation exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Grant client preparation task failed; abandon this fixture")??;
    println!("independent Grant client handoff completed");
    Ok(())
}

async fn prepare_request_client(arguments: GrantClientArguments) -> Result<()> {
    let directory = canonical_fixture_directory(&arguments.directory)?;
    let openssh_descriptor = arguments.openssh_descriptor;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("request-client.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_mins(15),
            Box::pin(account::prepare_request_client(&https, &directory, &openssh_descriptor)),
        )
        .await
        .map_err(|_| "Request client preparation exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Request client preparation task failed; abandon this fixture")??;
    println!("independent Request client handoff completed");
    Ok(())
}

async fn prepare_snippet_client(arguments: GrantClientArguments) -> Result<()> {
    let directory = canonical_fixture_directory(&arguments.directory)?;
    let openssh_descriptor = arguments.openssh_descriptor;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("snippet-client.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_mins(30),
            Box::pin(account::prepare_snippet_client(&https, &directory, &openssh_descriptor)),
        )
        .await
        .map_err(|_| "Snippet client preparation exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Snippet client preparation task failed; abandon this fixture")??;
    println!("independent Snippet client handoff completed");
    Ok(())
}

async fn verify_grants(directory: &Path) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("grants-check.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(360), Box::pin(account::verify_grants(&https)))
            .await
            .map_err(|_| "Grant check exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Grant check task failed; abandon this fixture")??;
    write_private(&directory.join("grants-acceptance.json"), GRANTS_ACCEPTANCE)?;
    println!("public Device and Account-browser Grant HTTPS check passed");
    Ok(())
}

async fn verify_password_change(directory: &Path) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("password-change-check.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(240),
            Box::pin(account::verify_password_change(&https)),
        )
        .await
        .map_err(|_| "Password-change check exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Password-change check task failed; abandon this fixture")??;
    write_private(&directory.join("password-change-acceptance.json"), PASSWORD_CHANGE_ACCEPTANCE)?;
    println!("public password-change, Device and Personal continuity HTTPS check passed");
    Ok(())
}

async fn verify_requests(directory: &Path) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("requests-check.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(Duration::from_mins(12), Box::pin(account::verify_requests(&https)))
            .await
            .map_err(|_| "Request check exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Request check task failed; abandon this fixture")??;
    write_private(&directory.join("requests-acceptance.json"), REQUESTS_ACCEPTANCE)?;
    println!("public Device and Account-browser request HTTPS check passed");
    Ok(())
}

async fn verify_request_response_loss(directory: &Path) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("request-response-loss-check.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_mins(12),
            Box::pin(account::verify_request_response_loss(&https)),
        )
        .await
        .map_err(|_| "Request response-loss check exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Request response-loss task failed; abandon this fixture")??;
    write_private(
        &directory.join("request-response-loss-acceptance.json"),
        REQUEST_RESPONSE_LOSS_ACCEPTANCE,
    )?;
    println!("public Device and Account-browser request response-loss HTTPS check passed");
    Ok(())
}

async fn verify_tenant_isolation(directory: &Path) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    write_private(
        &directory.join("tenant-isolation-check.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(180),
            Box::pin(account::verify_tenant_isolation(&https)),
        )
        .await
        .map_err(|_| "Tenant isolation check exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Tenant isolation check task failed; abandon this fixture")??;
    write_private(
        &directory.join("tenant-isolation-acceptance.json"),
        TENANT_ISOLATION_ACCEPTANCE,
    )?;
    println!("public two-Organization tenant isolation HTTPS check passed");
    Ok(())
}

async fn verify_inventory_import(directory: &Path, source: InventoryImportSource) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    let (started, acceptance_file, acceptance) = match source {
        InventoryImportSource::Csv => (
            "inventory-import-check.started",
            "inventory-import-acceptance.json",
            "{\"inventory_import_device_browser_https_verified\":true,\"inventory_import_original_confirmation_verified\":true,\"inventory_import_tenant_view_audit_verified\":true}",
        ),
        InventoryImportSource::OpenSsh => (
            "openssh-import-check.started",
            "openssh-import-acceptance.json",
            "{\"openssh_import_device_browser_https_verified\":true,\"openssh_import_original_confirmation_verified\":true,\"openssh_import_current_policy_verified\":true,\"openssh_import_tenant_view_audit_verified\":true}",
        ),
    };
    write_private(
        &directory.join(started),
        "One attempt only; discard this fixture after any failure.",
    )?;
    tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_mins(5),
            Box::pin(account::verify_inventory_import(&https, source)),
        )
        .await
        .map_err(|_| "Inventory import check exceeded its deadline; abandon this fixture")?
    })
    .await
    .map_err(|_| "Inventory import check task failed; abandon this fixture")??;
    write_private(&directory.join(acceptance_file), acceptance)?;
    println!("public Device and Account-browser inventory import HTTPS check passed");
    Ok(())
}

fn canonical_fixture_directory(directory: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        if let Some(Component::Prefix(prefix)) = directory.components().next()
            && !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        {
            return Err("fixture directory must resolve to an ordinary local-drive path");
        }
    }
    let canonical = fs::canonicalize(directory).map_err(|_| "fixture directory missing")?;
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        let mut components = canonical.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err("fixture directory must resolve to an ordinary local-drive path"),
            },
            _ => return Err("fixture directory must resolve to an ordinary local-drive path"),
        };
        // Rust canonicalization emits a verbatim prefix on Windows. Convert only
        // drive paths and confirm ordinary Win32 resolution still names the same directory.
        let mut ordinary = PathBuf::from(format!("{}:\\", char::from(drive)));
        for component in components {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => ordinary.push(name),
                _ => return Err("fixture directory must resolve to an ordinary local-drive path"),
            }
        }
        if fs::canonicalize(&ordinary).ok().as_ref() != Some(&canonical) {
            return Err("fixture directory changes under ordinary local-drive path resolution");
        }
        Ok(ordinary)
    }
    #[cfg(not(windows))]
    Ok(canonical)
}

fn prepare(directory: &Path, postgres_config: Option<&Path>, port: Option<u16>) -> Result<()> {
    let parent = canonical_fixture_directory(
        directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )
    .map_err(|_| "fixture parent must already exist at a supported local path")?;
    if parent.ancestors().any(|path| path.join(".git").exists()) {
        return Err("fixture directory must be outside every Git checkout");
    }
    let postgres = postgres_config
        .map(|path| {
            let source = read_bounded(path, 16_384)?;
            let config: PostgresConfig =
                serde_json::from_str(&source).map_err(|_| "invalid private PostgreSQL JSON")?;
            validate_postgres(&config.database_url)?;
            Ok::<_, &'static str>(Zeroizing::new(config.database_url))
        })
        .transpose()?;
    let port = port.map_or_else(
        || {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .and_then(|listener| listener.local_addr())
                .map(|address| address.port())
                .map_err(|_| "could not select a loopback port")
        },
        Ok,
    )?;
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    let directory = parent.join(directory.file_name().ok_or("fixture directory name missing")?);
    builder
        .create(&directory)
        .map_err(|_| "fixture directory must be new with an existing private parent")?;
    let result = prepare_files(&directory, postgres.as_deref().map(String::as_str), port);
    if result.is_err() {
        // This path was just exclusively created above; it never names an existing deployment.
        if fs::remove_dir_all(&directory).is_err() {
            return Err(
                "prepare failed; remove the newly created private fixture directory manually",
            );
        }
    }
    result
}

fn prepare_files(directory: &Path, postgres: Option<&str>, port: u16) -> Result<()> {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| "CA parameters failed")?;
    ca_params.distinguished_name.push(DnType::CommonName, "Scoplen disposable fixture CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().map_err(|_| "CA generation failed")?;
    let ca = ca_params.self_signed(&ca_key).map_err(|_| "CA signing failed")?;
    let leaf_key = KeyPair::generate().map_err(|_| "TLS key generation failed")?;
    let leaf = CertificateParams::new(vec!["localhost".into()])
        .map_err(|_| "TLS parameters failed")?
        .signed_by(&leaf_key, &ca, &ca_key)
        .map_err(|_| "TLS certificate signing failed")?;
    write_private(&directory.join("ca.pem"), &ca.pem())?;
    write_private(&directory.join("localhost.pem"), &format!("{}{}", leaf.pem(), ca.pem()))?;
    write_private(&directory.join("localhost-key.pem"), &Zeroizing::new(leaf_key.serialize_pem()))?;
    let mut value = serde_json::json!({
        "server": {
            "listen_addr": "127.0.0.1", "listen_port": port,
            "public_host": "localhost", "public_port": port, "data_dir": directory.join("data"),
        },
        "tls": { "mode": "files", "cert_file": directory.join("localhost.pem"),
                 "key_file": directory.join("localhost-key.pem") },
        "roles": { "names": ["api"] },
        "console": { "assets_dir": directory.join("unused-console") },
        "storage": { "backend": if postgres.is_some() { "postgres" } else { "sqlite" } },
    });
    if let Some(url) = postgres {
        value["storage"]["database_url"] = url.into();
    }
    let config = Zeroizing::new(toml::to_string(&value).map_err(|_| "config encoding failed")?);
    write_private(&directory.join("server.toml"), &config)?;
    write_private(&directory.join(".scoplen-disposable-fixture"), MARKER)
}

fn validate_postgres(value: &str) -> Result<()> {
    let url = Url::parse(value).map_err(|_| "invalid private PostgreSQL URL")?;
    let name = url.path().strip_prefix('/').unwrap_or_default();
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        || !name.starts_with("scoplen_fixture_")
        || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "PostgreSQL must be loopback with an empty disposable scoplen_fixture_* database and no URL query",
        );
    }
    Ok(())
}

fn write_private(path: &Path, value: &str) -> Result<()> {
    private_material::write_private(path, value)
        .map_err(|_| "could not exclusively write private fixture material")
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)
        .and_then(|file| file.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "could not read private fixture input")?;
    if bytes.len() > maximum {
        return Err("private fixture input exceeds its size limit");
    }
    std::str::from_utf8(&bytes)
        .map(|value| Zeroizing::new(value.to_owned()))
        .map_err(|_| "private fixture input is not UTF-8")
}

fn fixture_config(directory: &Path) -> Result<Config> {
    if read_bounded(&directory.join(".scoplen-disposable-fixture"), 128)?.as_str()
        != format!("{MARKER}\n")
    {
        return Err("directory is not a prepared disposable fixture");
    }
    let source = read_bounded(&directory.join("server.toml"), 16_384)?;
    let config: Config = toml::from_str(&source).map_err(|_| "prepared config is invalid")?;
    if config.server.listen_addr != "127.0.0.1"
        || config.server.public_host != "localhost"
        || config.server.listen_port < 1024
        || config.server.listen_port != config.server.public_port
        || config.server.data_dir != directory.join("data")
        || config.tls.mode != TlsMode::Files
        || config.tls.cert_file.as_deref() != Some(directory.join("localhost.pem").as_path())
        || config.tls.key_file.as_deref() != Some(directory.join("localhost-key.pem").as_path())
        || config.console.assets_dir != directory.join("unused-console")
    {
        return Err("prepared config must retain its owned loopback HTTPS boundary");
    }
    match config.storage.backend.as_str() {
        "sqlite" if config.storage.database_url.is_none() => {}
        "postgres" => {
            let value: toml::Value =
                toml::from_str(&source).map_err(|_| "prepared config is invalid")?;
            validate_postgres(
                value
                    .get("storage")
                    .and_then(|v| v.get("database_url"))
                    .and_then(toml::Value::as_str)
                    .ok_or("PostgreSQL URL missing")?,
            )?;
        }
        _ => return Err("prepared storage backend is invalid"),
    }
    Ok(config)
}

fn setup_token(log: &str, origin: &str) -> Result<[u8; 32]> {
    let mut links = log.lines().filter_map(|line| line.strip_prefix(SETUP_PREFIX));
    let link = links.next().ok_or("first-start setup link missing from private server log")?;
    if links.next().is_some() {
        return Err("private server log contains multiple setup links; use a fresh fixture");
    }
    let token = link
        .strip_prefix(&format!("{origin}/setup#token="))
        .ok_or("setup link does not match prepared origin")?;
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "invalid setup token")?
        .try_into()
        .map_err(|_| "invalid setup token length")?;
    if URL_SAFE_NO_PAD.encode(bytes) != token {
        return Err("invalid setup token encoding");
    }
    Ok(bytes)
}

async fn bootstrap(directory: &Path, server_log: Option<&Path>) -> Result<()> {
    let directory = canonical_fixture_directory(directory)?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let log = read_bounded(server_log.unwrap_or(&directory.join("server.log")), 4_194_304)?;
    let token = setup_token(&log, &origin)?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    if directory.join("descriptor.json").exists() {
        return Err("descriptor already exists; use a fresh fixture");
    }
    write_private(
        &directory.join("bootstrap.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    public_flow(&https, token).await?;
    let descriptor = Descriptor {
        disposable: true,
        origin: &https.origin,
        operator_lifecycle_verified: true,
        ca_certificate: directory.join("ca.pem"),
    };
    let json = Zeroizing::new(
        serde_json::to_string_pretty(&descriptor).map_err(|_| "descriptor encoding failed")?,
    );
    if json.len() > 8_192 {
        return Err("descriptor exceeds consumer size limit; use a shorter fixture path");
    }
    let pending = directory.join("descriptor.pending");
    let result = write_private(&pending, &json).and_then(|()| {
        fs::rename(&pending, directory.join("descriptor.json"))
            .map_err(|_| "descriptor publication failed")
    });
    if result.is_err() {
        let _ = fs::remove_file(pending);
    }
    result
}

async fn public_flow(https: &Https, token: [u8; 32]) -> Result<()> {
    let key =
        scoplen_crypto::generate_p256_signing_key().map_err(|_| "DPoP key generation failed")?;
    let mut authenticator = passkey::ResidentPasskey::authenticator();
    let request = OperatorSetupOptionsRequest { setup_token: token }
        .to_json()
        .map_err(|_| "setup options encoding failed")?;
    let reply = https.post(SETUP_OPTIONS, &request, &key, None, 200).await?;
    let setup = OperatorSetupOptionsResponse::from_json(&reply)
        .map_err(|_| "setup options response invalid")?;
    let options: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|_| "setup options JSON invalid")?;
    let credential = authenticator
        .do_registration(
            Url::parse(&https.origin).map_err(|_| "fixture origin invalid")?,
            passkey::creation(&options["public_key"]),
        )
        .map_err(|_| "software passkey registration failed")?;
    let request = OperatorSetupFinishRequest {
        setup_token: token,
        ceremony_id: setup.ceremony_id,
        credential_id: credential.raw_id.as_ref().to_vec(),
        client_data_json: credential.response.client_data_json.as_ref().to_vec(),
        attestation_object: credential.response.attestation_object.as_ref().to_vec(),
    }
    .to_json()
    .map_err(|_| "setup finish encoding failed")?;
    let reply = https.post(SETUP_FINISH, &request, &key, None, 201).await?;
    OperatorSetupFinishResponse::from_json(&reply).map_err(|_| "setup finish response invalid")?;
    let reply = https.post(LOGIN_OPTIONS, b"{}", &key, None, 200).await?;
    let login = OperatorLoginOptionsResponse::from_json(&reply)
        .map_err(|_| "login options response invalid")?;
    let options: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|_| "login options JSON invalid")?;
    let assertion = authenticator
        .do_authentication(
            Url::parse(&https.origin).map_err(|_| "fixture origin invalid")?,
            passkey::authentication(&options["public_key"]),
        )
        .map_err(|_| "software passkey assertion failed")?;
    let request = OperatorLoginFinishRequest {
        ceremony_id: login.ceremony_id,
        credential_id: assertion.raw_id.as_ref().to_vec(),
        client_data_json: assertion.response.client_data_json.as_ref().to_vec(),
        authenticator_data: assertion.response.authenticator_data.as_ref().to_vec(),
        signature: assertion.response.signature.as_ref().to_vec(),
        user_handle: assertion
            .response
            .user_handle
            .ok_or("resident user handle missing")?
            .as_ref()
            .try_into()
            .map_err(|_| "resident user handle invalid")?,
    }
    .to_json()
    .map_err(|_| "login finish encoding failed")?;
    let reply = https.post(LOGIN_FINISH, &request, &key, None, 200).await?;
    let session = BrowserAuthTokenResponse::from_json(
        std::str::from_utf8(&reply).map_err(|_| "login response is not UTF-8")?,
    )
    .map_err(|_| "login response invalid")?;
    for _ in 0..2 {
        let reply = https.post(LOGOUT, b"{}", &key, Some(&session.access_token), 200).await?;
        OperatorLogoutResponse::from_json(&reply).map_err(|_| "logout confirmation invalid")?;
    }
    for (method, path) in [
        ("POST", "/api/v1/admin/personal-invitations"),
        ("POST", "/api/v1/auth/personal-enroll"),
        ("POST", "/api/v1/auth/pairings"),
        ("GET", "/api/v1/auth/pairings/019a0000-0000-7000-8000-000000000001"),
        ("DELETE", "/api/v1/auth/pairings/019a0000-0000-7000-8000-000000000001"),
        ("POST", "/api/v1/auth/pairings/019a0000-0000-7000-8000-000000000001/claim"),
        ("POST", "/api/v1/auth/pairings/019a0000-0000-7000-8000-000000000001/messages"),
        ("POST", "/api/v1/auth/pairings/019a0000-0000-7000-8000-000000000001/complete"),
        ("GET", "/pair"),
    ] {
        https.exchange(method, path, b"{}", None, 404).await?;
    }
    Ok(())
}

struct Https {
    origin: String,
    port: u16,
    connector: TlsConnector,
}

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Https {
    fn new(directory: &Path, port: u16, origin: String) -> Result<Self> {
        let pem = read_bounded(&directory.join("ca.pem"), 65_536)?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
            roots
                .add(cert.map_err(|_| "fixture CA PEM invalid")?)
                .map_err(|_| "fixture CA invalid")?;
        }
        let mut tls = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS 1.3 unavailable")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self { origin, port, connector: TlsConnector::from(Arc::new(tls)) })
    }

    async fn post(
        &self,
        path: &str,
        body: &[u8],
        key: &P256SigningKey,
        token: Option<&str>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.exchange("POST", path, body, Some((key, token)), expected).await
    }

    async fn exchange(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        proof: Option<(&P256SigningKey, Option<&str>)>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        tokio::time::timeout(
            Duration::from_secs(15),
            self.request(method, path, body, proof, None, expected),
        )
        .await
        .map_err(|_| "HTTPS request timed out; abandon this fixture after an uncertain operation")?
    }

    async fn create_organization(
        &self,
        body: &[u8],
        key: &P256SigningKey,
        token: &str,
        idempotency_key: uuid::Uuid,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let idempotency_key = idempotency_key.to_string();
        tokio::time::timeout(
            Duration::from_secs(15),
            self.request(
                "POST",
                "/api/v1/orgs",
                body,
                Some((key, Some(token))),
                Some(("Idempotency-Key", &idempotency_key)),
                201,
            ),
        )
        .await
        .map_err(|_| "HTTPS request timed out; abandon this fixture after an uncertain operation")?
    }

    async fn update_organization(
        &self,
        path: &str,
        body: &[u8],
        key: &P256SigningKey,
        token: &str,
        etag: &str,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        tokio::time::timeout(
            Duration::from_secs(15),
            self.request(
                "PATCH",
                path,
                body,
                Some((key, Some(token))),
                Some(("If-Match", etag)),
                expected,
            ),
        )
        .await
        .map_err(|_| "HTTPS request timed out; abandon this fixture after an uncertain operation")?
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        proof: Option<(&P256SigningKey, Option<&str>)>,
        condition: Option<(&'static str, &str)>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.origin))
            .header(
                "Content-Type",
                if path.starts_with("/sync/") { "application/cbor" } else { "application/json" },
            )
            .header("Origin", &self.origin);
        if let Some((name, value)) = condition {
            request = request.header(name, value);
        }
        if let Some((key, token)) = proof {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock invalid")?
                .as_secs();
            let proof = DpopProof::sign(
                key,
                &key.public_key_sec1(),
                &DpopTarget::new(
                    method,
                    &self.origin,
                    path.split('?').next().ok_or("DPoP path missing")?,
                )
                .map_err(|_| "DPoP target invalid")?,
                token.map_or(DpopToken::Refresh, DpopToken::Protected),
                now,
                None,
            )
            .map_err(|_| "DPoP signing failed")?;
            request = request.header("DPoP", proof.as_str());
            if let Some(token) = token {
                request = request.header("Authorization", format!("DPoP {token}"));
            }
        }
        let tcp =
            tokio::net::TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)))
                .await
                .map_err(|_| "loopback server is not running")?;
        let tls = self
            .connector
            .connect(ServerName::try_from("localhost").map_err(|_| "TLS name invalid")?, tcp)
            .await
            .map_err(|_| "fixture TLS certificate verification failed")?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("fixture server did not negotiate HTTP/2");
        }
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .max_header_list_size(16_384)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(|_| "HTTPS connection failed")?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let reply = sender
            .send_request(
                request
                    .body(Full::new(Bytes::copy_from_slice(body)))
                    .map_err(|_| "HTTPS request encoding failed")?,
            )
            .await
            .map_err(|_| "HTTPS request failed; operation outcome may be unknown")?;
        if reply.status().as_u16() != expected {
            return Err(
                "public fixture API rejected request; abandon the fixture and inspect only private server diagnostics",
            );
        }
        if expected == 404 && !path.starts_with("/api/v1/orgs") {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let content_type = if path.starts_with("/sync/") {
            if expected >= 400 { "application/problem+cbor" } else { "application/cbor" }
        } else if expected >= 400 {
            "application/problem+json"
        } else {
            "application/json"
        };
        if reply.headers().get("content-type").and_then(|v| v.to_str().ok()) != Some(content_type)
            || reply.headers().get("cache-control").and_then(|v| v.to_str().ok())
                != Some("no-store")
        {
            return Err("public fixture API response privacy headers invalid");
        }
        let (parts, body) = reply.into_parts();
        let bytes = Limited::new(body, if path.starts_with("/sync/") { 65_536 } else { 8_192 })
            .collect()
            .await
            .map_err(|_| "public bootstrap response exceeds limit or is incomplete")?
            .to_bytes();
        if path.starts_with("/api/v1/orgs") {
            verify_organization_response(method, path, expected, &parts.headers, &bytes)?;
        }
        Ok(Zeroizing::new(bytes.to_vec()))
    }
}

fn verify_organization_response(
    method: &str,
    path: &str,
    expected: u16,
    headers: &axum::http::HeaderMap,
    bytes: &[u8],
) -> Result<()> {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    if header("x-request-id").is_none_or(str::is_empty) || headers.contains_key("set-cookie") {
        return Err("team response metadata invalid");
    }
    if expected >= 400 {
        if expected == 404 && headers.contains_key("etag") {
            return Err("team problem response disclosed a Resource version");
        }
        return Ok(());
    }
    if method == "GET" && path == "/api/v1/orgs" {
        OrganizationPage::from_http_json(bytes, header("cache-control"), header("pragma"))
            .map_err(|_| "team discovery response invalid")?;
    } else {
        OrganizationResource::from_http_json(
            bytes,
            header("etag"),
            header("cache-control"),
            header("pragma"),
        )
        .map_err(|_| "team Resource response invalid")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            Self(
                std::env::temp_dir().join(format!("scoplen-live-fixture-{}", uuid::Uuid::new_v4())),
            )
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove exclusively owned fixture");
            }
        }
    }

    #[test]
    fn restart_acceptance_requires_team_verification() {
        assert!(
            Cli::try_parse_from(["consumer", "verify-account", "unused", "--across-restart"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "consumer",
                "verify-account",
                "unused",
                "--with-team",
                "--across-restart"
            ])
            .is_ok()
        );
    }

    #[test]
    fn only_explicit_loopback_disposable_databases_are_accepted() {
        for value in [
            "postgres://fixture:synthetic@127.0.0.1:5432/scoplen_fixture_test",
            "postgresql://fixture:synthetic@localhost/scoplen_fixture_test",
            "postgres://fixture:synthetic@[::1]:5432/scoplen_fixture_test",
        ] {
            validate_postgres(value).expect("explicit disposable database");
        }
        for value in [
            "postgres://fixture:synthetic@db.example.com/scoplen_fixture_test",
            "postgres://fixture:synthetic@127.0.0.1/production",
            "postgres://fixture:synthetic@127.0.0.1/scoplen_fixture_test?host=db.example.com",
            "postgres://fixture:synthetic@127.0.0.1/scoplen_fixture_test%2fproduction",
            "file:///scoplen_fixture_test",
        ] {
            assert!(validate_postgres(value).is_err());
        }
    }

    #[test]
    fn prepare_preserves_existing_directories_and_requires_owned_loopback_config() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, Some(18443)).expect("prepare");
        let directory = canonical_fixture_directory(&scratch.0).expect("canonical fixture");
        let config = fixture_config(&directory).expect("owned config");
        assert_eq!(config.public_origin().unwrap(), "https://localhost:18443");
        let key = fs::read(directory.join("localhost-key.pem")).expect("private key");
        assert!(prepare(&scratch.0, None, Some(18444)).is_err());
        assert_eq!(fs::read(directory.join("localhost-key.pem")).unwrap(), key);
        let path = directory.join("server.toml");
        let source = fs::read_to_string(&path).unwrap();
        fs::write(&path, source.replace("127.0.0.1", "0.0.0.0")).unwrap();
        assert!(fixture_config(&directory).is_err());
        for (section, field) in [
            ("server", "data_dir"),
            ("tls", "cert_file"),
            ("tls", "key_file"),
            ("console", "assets_dir"),
        ] {
            let mut config: toml::Value = toml::from_str(&source).unwrap();
            config[section][field] = directory.join("elsewhere").to_str().unwrap().into();
            fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
            assert!(fixture_config(&directory).is_err(), "prepared path changed");
        }
        assert!(!directory.join("descriptor.json").exists());
    }

    #[cfg(windows)]
    #[test]
    fn prepared_windows_paths_pass_public_admission_without_accepting_aliases() {
        use std::path::{Component, Prefix};

        let scratch = Scratch::new();
        assert!(!scratch.0.exists());
        let mut parent = Config::default();
        parent.server.data_dir = scratch.0.clone();
        drop(scoplen_server::admit_local_deployment(&parent).expect("new private fixture parent"));
        let fixture = scratch.0.join("personal");
        prepare(&fixture, None, Some(18443)).expect("prepare");
        let directory = canonical_fixture_directory(&fixture).expect("ordinary fixture path");
        let config = fixture_config(&directory).expect("exact owned config");
        for path in [
            &config.server.data_dir,
            config.tls.cert_file.as_ref().unwrap(),
            config.tls.key_file.as_ref().unwrap(),
            &config.console.assets_dir,
        ] {
            assert!(
                matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
            );
        }
        assert!(!config.server.data_dir.exists());
        let lease =
            scoplen_server::admit_local_deployment(&config).expect("prepared public admission");
        assert!(config.server.data_dir.is_dir());
        drop(lease);
        for rejected in [
            fs::canonicalize(&config.server.data_dir).unwrap(),
            directory.join("data."),
            directory.join("data "),
        ] {
            let mut altered = config.clone();
            altered.server.data_dir = rejected;
            assert!(scoplen_server::admit_local_deployment(&altered).is_err());
        }
        drop(scoplen_server::admit_local_deployment(&config).expect("owned path remains admitted"));
    }

    #[cfg(windows)]
    #[test]
    fn fixture_paths_refuse_unc_and_device_names_without_accessing_them() {
        for path in [r"\\server\share", r"\\?\UNC\server\share", r"\\.\C:\fixture"] {
            assert_eq!(
                canonical_fixture_directory(Path::new(path)).unwrap_err(),
                "fixture directory must resolve to an ordinary local-drive path"
            );
        }
    }

    #[test]
    fn prepared_ca_and_leaf_have_distinct_subjects_for_schannel_chain_building() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, Some(18443)).expect("prepare");
        let subjects = ["ca.pem", "localhost.pem"].map(|name| {
            let pem = fs::read(scratch.0.join(name)).unwrap();
            let cert = rustls_pemfile::certs(&mut pem.as_slice()).next().unwrap().unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert).unwrap();
            roots.roots[0].subject.as_ref().to_vec()
        });
        assert_ne!(subjects[0], subjects[1]);
    }

    #[test]
    fn setup_capture_requires_one_exact_origin_and_bounded_inputs() {
        let token = URL_SAFE_NO_PAD.encode([7; 32]);
        let log = format!("{SETUP_PREFIX}https://localhost:18443/setup#token={token}\n");
        assert_eq!(setup_token(&log, "https://localhost:18443").unwrap(), [7; 32]);
        assert!(setup_token(&log, "https://localhost:18444").is_err());
        assert!(setup_token(&format!("{log}{log}"), "https://localhost:18443").is_err());
        let scratch = Scratch::new();
        fs::create_dir(&scratch.0).unwrap();
        let path = scratch.0.join("input");
        write_private(&path, "12345678").unwrap();
        assert!(read_bounded(&path, 8).is_err());
        assert!(read_bounded(&path, 9).is_ok());
    }

    #[tokio::test]
    async fn failed_bootstrap_publishes_nothing_and_cannot_repeat_an_uncertain_attempt() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let directory = canonical_fixture_directory(&scratch.0).unwrap();
        let config = fixture_config(&directory).unwrap();
        let token = URL_SAFE_NO_PAD.encode([7; 32]);
        write_private(
            &directory.join("server.log"),
            &format!("{SETUP_PREFIX}{}/setup#token={token}", config.public_origin().unwrap()),
        )
        .unwrap();
        assert!(bootstrap(&directory, None).await.is_err());
        assert!(directory.join("bootstrap.started").is_file());
        assert!(!directory.join("descriptor.json").exists());
        assert!(!directory.join("descriptor.pending").exists());
        assert_eq!(
            bootstrap(&directory, None).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[test]
    fn descriptor_has_only_the_four_consumer_contract_fields() {
        let descriptor = Descriptor {
            disposable: true,
            origin: "https://localhost:18443",
            operator_lifecycle_verified: true,
            ca_certificate: PathBuf::from("/private/fixture/ca.pem"),
        };
        let value = serde_json::to_value(descriptor).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ca_certificate", "disposable", "operator_lifecycle_verified", "origin"]);
    }

    #[test]
    fn grant_acceptance_has_only_fixed_https_evidence_fields() {
        let value: serde_json::Value = serde_json::from_str(GRANTS_ACCEPTANCE).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        for name in [
            "grant_device_browser_https_verified",
            "grant_certificate_expiry_verified",
            "grant_lifecycle_tenant_verified",
            "grant_personal_sync_preserved",
        ] {
            assert_eq!(object.get(name), Some(&serde_json::Value::Bool(true)));
        }
        assert!(Cli::try_parse_from(["consumer", "verify-grants", "unused"]).is_ok());
    }

    #[tokio::test]
    async fn failed_grant_check_publishes_nothing_and_refuses_replay() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        assert!(run(Command::VerifyGrants { directory: scratch.0.clone() }).await.is_err());
        assert!(scratch.0.join("grants-check.started").is_file());
        assert!(!scratch.0.join("grants-acceptance.json").exists());
        assert_eq!(
            run(Command::VerifyGrants { directory: scratch.0.clone() }).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[tokio::test]
    async fn password_change_failure_publishes_nothing_and_refuses_replay() {
        assert!(Cli::try_parse_from(["consumer", "verify-password-change", "unused"]).is_ok());
        let value: serde_json::Value = serde_json::from_str(PASSWORD_CHANGE_ACCEPTANCE).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 3);
        for name in [
            "password_change_native_https_verified",
            "password_change_browser_generation_verified",
            "password_change_historical_receipt_verified",
        ] {
            assert_eq!(object.get(name), Some(&serde_json::Value::Bool(true)));
        }
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let command = || Command::VerifyPasswordChange { directory: scratch.0.clone() };
        assert!(run(command()).await.is_err());
        assert!(scratch.0.join("password-change-check.started").is_file());
        assert!(!scratch.0.join("password-change-acceptance.json").exists());
        assert_eq!(
            run(command()).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[test]
    fn request_acceptance_keeps_deadline_and_ssh_claims_separate() {
        let value: serde_json::Value = serde_json::from_str(REQUESTS_ACCEPTANCE).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        for name in [
            "request_device_browser_https_verified",
            "request_current_routing_tenant_verified",
            "request_original_confirmation_verified",
            "request_personal_sync_preserved",
        ] {
            assert_eq!(object.get(name), Some(&serde_json::Value::Bool(true)));
        }
        assert!(Cli::try_parse_from(["consumer", "verify-requests", "unused"]).is_ok());
    }

    #[test]
    fn tenant_isolation_acceptance_has_only_fixed_matrix_claims() {
        let value: serde_json::Value = serde_json::from_str(TENANT_ISOLATION_ACCEPTANCE).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 7);
        for name in [
            "tenant_foreign_absent_inventory_verified",
            "tenant_custom_policy_boundary_verified",
            "tenant_view_revision_verified",
            "tenant_view_connect_separation_verified",
            "tenant_foreign_reference_verified",
            "tenant_membership_removal_verified",
            "tenant_personal_sync_preserved",
        ] {
            assert_eq!(object.get(name), Some(&serde_json::Value::Bool(true)));
        }
        assert!(Cli::try_parse_from(["consumer", "verify-tenant-isolation", "unused"]).is_ok());
    }

    #[test]
    fn request_response_loss_receipt_keeps_unverified_claims_separate() {
        let value: serde_json::Value =
            serde_json::from_str(REQUEST_RESPONSE_LOSS_ACCEPTANCE).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        for name in [
            "request_device_browser_response_loss_verified",
            "request_original_confirmation_verified",
            "request_single_transition_effects_verified",
            "request_personal_sync_preserved",
        ] {
            assert_eq!(object.get(name), Some(&serde_json::Value::Bool(true)));
        }
        assert!(
            Cli::try_parse_from(["consumer", "verify-request-response-loss", "unused"]).is_ok()
        );
    }

    #[tokio::test]
    async fn failed_request_check_publishes_nothing_and_refuses_replay() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let command = || Command::VerifyRequests { directory: scratch.0.clone() };
        assert!(run(command()).await.is_err());
        assert!(scratch.0.join("requests-check.started").is_file());
        assert!(!scratch.0.join("requests-acceptance.json").exists());
        assert_eq!(
            run(command()).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[tokio::test]
    async fn failed_request_response_loss_publishes_nothing_and_refuses_replay() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let command = || Command::VerifyRequestResponseLoss { directory: scratch.0.clone() };
        assert!(run(command()).await.is_err());
        assert!(scratch.0.join("request-response-loss-check.started").is_file());
        assert!(!scratch.0.join("request-response-loss-acceptance.json").exists());
        assert_eq!(
            run(command()).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[tokio::test]
    async fn inventory_import_failure_never_publishes_acceptance_or_repeats_business() {
        assert!(Cli::try_parse_from(["consumer", "verify-inventory-import", "unused"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "consumer",
                "verify-inventory-import",
                "unused",
                "--source",
                "openssh",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "consumer",
                "verify-inventory-import",
                "unused",
                "--source",
                "other",
            ])
            .is_err()
        );
        for (source, prefix) in
            [(InventoryImportSource::Csv, "inventory"), (InventoryImportSource::OpenSsh, "openssh")]
        {
            let scratch = Scratch::new();
            prepare(&scratch.0, None, None).expect("prepare");
            let command =
                || Command::VerifyInventoryImport { directory: scratch.0.clone(), source };
            assert!(run(command()).await.is_err());
            assert!(scratch.0.join(format!("{prefix}-import-check.started")).is_file());
            assert!(!scratch.0.join(format!("{prefix}-import-acceptance.json")).exists());
            assert_eq!(
                run(command()).await.unwrap_err(),
                "could not exclusively write private fixture material"
            );
        }
    }

    #[tokio::test]
    async fn grant_client_handoff_requires_owned_target_and_refuses_replay() {
        for command in ["prepare-grant-client", "prepare-inventory-import-client"] {
            assert!(
                Cli::try_parse_from([
                    "consumer",
                    command,
                    "unused",
                    "--openssh-descriptor",
                    "unused.json",
                ])
                .is_ok()
            );
            assert!(Cli::try_parse_from(["consumer", command, "unused"]).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "consumer",
                "prepare-inventory-import-client",
                "unused",
                "--openssh-descriptor",
                "unused.json",
                "--source",
                "openssh",
            ])
            .is_ok()
        );
        for source in [None, Some(InventoryImportSource::Csv), Some(InventoryImportSource::OpenSsh)]
        {
            let scratch = Scratch::new();
            prepare(&scratch.0, None, None).expect("prepare");
            let command = || {
                let target = GrantClientArguments {
                    directory: scratch.0.clone(),
                    openssh_descriptor: scratch.0.join("absent-openssh.json"),
                };
                match source {
                    Some(source) => {
                        Command::PrepareInventoryImportClient(InventoryImportClientArguments {
                            target,
                            source,
                        })
                    }
                    None => Command::PrepareGrantClient(target),
                }
            };
            assert!(run(command()).await.is_err());
            assert!(scratch.0.join("grant-client.started").is_file());
            for phase in ["before", "active", "withdrawn"] {
                assert!(!scratch.0.join(format!("grant-client-{phase}.json")).exists());
                assert!(!scratch.0.join(format!("grant-client-{phase}.ready")).exists());
            }
            assert!(!scratch.0.join("grant-client-owner-password.txt").exists());
            assert_eq!(
                run(command()).await.unwrap_err(),
                "could not exclusively write private fixture material"
            );
        }
    }

    #[tokio::test]
    async fn request_client_handoff_requires_owned_target_and_refuses_replay() {
        assert!(
            Cli::try_parse_from([
                "consumer",
                "prepare-request-client",
                "unused",
                "--openssh-descriptor",
                "unused.json",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["consumer", "prepare-request-client", "unused"]).is_err());
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let command = || {
            Command::PrepareRequestClient(GrantClientArguments {
                directory: scratch.0.clone(),
                openssh_descriptor: scratch.0.join("absent-openssh.json"),
            })
        };
        assert!(run(command()).await.is_err());
        assert!(scratch.0.join("request-client.started").is_file());
        for phase in ["before", "active", "withdrawn"] {
            for suffix in ["json", "ready", "complete"] {
                assert!(!scratch.0.join(format!("request-client-{phase}.{suffix}")).exists());
            }
        }
        assert!(!scratch.0.join("request-client-owner-password.txt").exists());
        assert!(!scratch.0.join("request-client-member-password.txt").exists());
        assert_eq!(
            run(command()).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[tokio::test]
    async fn snippet_client_handoff_requires_owned_target_and_refuses_replay() {
        assert!(
            Cli::try_parse_from([
                "consumer",
                "prepare-snippet-client",
                "unused",
                "--openssh-descriptor",
                "unused.json",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["consumer", "prepare-snippet-client", "unused"]).is_err());
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let command = || {
            Command::PrepareSnippetClient(GrantClientArguments {
                directory: scratch.0.clone(),
                openssh_descriptor: scratch.0.join("absent-openssh.json"),
            })
        };
        assert!(run(command()).await.is_err());
        assert!(scratch.0.join("snippet-client.started").is_file());
        for phase in [
            "published",
            "replaced",
            "view-withdrawn",
            "restored",
            "membership-withdrawn",
            "deleted",
        ] {
            for suffix in ["json", "ready", "complete"] {
                assert!(!scratch.0.join(format!("snippet-client-{phase}.{suffix}")).exists());
            }
        }
        assert!(!scratch.0.join("snippet-client-member-password.txt").exists());
        assert!(!scratch.0.join("snippet-client-ssh-setup.json").exists());
        assert_eq!(
            run(command()).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }
}
