// SPDX-License-Identifier: AGPL-3.0-only
//! First-run material and role supervision.

use std::{
    future::Future,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Extension, Router, extract::connect_info::ConnectInfo, http::StatusCode, routing::get};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use rustls_acme::{AcmeConfig, caches::DirCache};
use scoplen_audit::{checkpoint_payload, deployment_checkpoint_payload};
use scoplen_store::kms::{AuditCheckpointSigner, LocalAuditSigner, LocalKeyFile};
use scoplen_store::sync::MAX_PAGE_SIZE;
use scoplen_store::{
    AuditChainHead, AuditCheckpoint, AuditStoreError, DeploymentAuditChainHead,
    DeploymentAuditCheckpoint, JobQueueError, ObjectStorage, PostgresStore, SqliteStore,
    sync::SyncStoreError,
};
use scoplen_sync::http::{ReadBodyLimits, WriteBodyLimits, WriteRateLimits};
use scoplen_sync::{notification_fanout::PostgresNotificationFanout, notify::NotificationHub};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::sleep};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};
use tracing::{error, info, warn};

use crate::{Config, Role, ServerError, TlsMode, device_auth, personal_enrollment, personal_sync};

#[cfg(windows)]
#[path = "private_material/windows.rs"]
mod windows_private_directory;

/// Role-specific startup resources prepared before role tasks begin.
pub struct PreparedRoles {
    /// Database pool for roles that need relational storage.
    pub store: Option<SqliteStore>,
    /// PostgreSQL pool for database-backed high-availability roles.
    pub postgres_store: Option<PostgresStore>,
    /// Object storage backend for roles that need relational storage.
    pub object_storage: Option<ObjectStorage>,
    /// Initialized key-management backend for database-backed roles.
    pub key_management: Option<LocalKeyFile>,
    /// Initialized audit checkpoint signer for database-backed roles.
    pub audit_signer: Option<LocalAuditSigner>,
    /// First-run setup link only for roles that initialize the deployment.
    pub setup_link: Option<scoplen_store::operator_setup::SetupDisclosure>,
}

#[derive(Clone)]
pub(crate) enum ListenerDatabase {
    Sqlite(Arc<SqliteStore>),
    Postgres(Arc<PostgresStore>),
}

impl ListenerDatabase {
    async fn ping(&self) -> Result<(), scoplen_store::StoreError> {
        match self {
            Self::Sqlite(store) => store.ping().await?,
            Self::Postgres(store) => store.ping().await?,
        }
        Ok(())
    }
}

/// Create the data directory, deployment key and internal CA as needed.
///
/// # Errors
///
/// Returns an error when the data directory or generated key material cannot be created.
/// Operator setup entitlements are initialized separately, in the API role's database.
pub fn bootstrap(config: &Config) -> Result<(), ServerError> {
    prepare_data_directory(config)?;

    let deployment_key = config.server.data_dir.join("deployment.key");
    if !deployment_key.exists() {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|source| ServerError::Material {
            path: deployment_key.clone(),
            source: std::io::Error::other(source.to_string()),
        })?;
        write_private(&deployment_key, &hex_bytes(&bytes))?;
    }

    let audit_signing_key = config.storage.kms_audit_key_file(&config.server.data_dir)?;
    if !audit_signing_key.exists() {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|source| ServerError::Material {
            path: audit_signing_key.clone(),
            source: std::io::Error::other(source.to_string()),
        })?;
        write_private(&audit_signing_key, &hex_bytes(&bytes))?;
    }

    let ca_certificate = config.server.data_dir.join("internal-ca.pem");
    let ca_key = config.server.data_dir.join("internal-ca-key.pem");
    let certificate_exists = ca_certificate
        .try_exists()
        .map_err(|source| ServerError::Material { path: ca_certificate.clone(), source })?;
    let key_exists = ca_key
        .try_exists()
        .map_err(|source| ServerError::Material { path: ca_key.clone(), source })?;
    if certificate_exists != key_exists {
        return Err(ServerError::Material {
            path: if certificate_exists { ca_key } else { ca_certificate },
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "internal CA certificate and key must both exist; restore the incomplete pair from backup",
            ),
        });
    }
    if !certificate_exists {
        let mut params = CertificateParams::new(vec![config.server.public_host.clone()])
            .map_err(|error| ServerError::Tls(error.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate().map_err(|error| ServerError::Tls(error.to_string()))?;
        let certificate =
            params.self_signed(&key_pair).map_err(|error| ServerError::Tls(error.to_string()))?;
        write_private(&ca_certificate, &certificate.pem())?;
        write_private(&ca_key, &key_pair.serialize_pem())?;
    }

    Ok(())
}

fn prepare_data_directory(config: &Config) -> Result<(), ServerError> {
    let directory = &config.server.data_dir;
    #[cfg(windows)]
    let private_files = [
        directory.join("deployment.key"),
        config.storage.kms_key_file(directory)?,
        config.storage.kms_audit_key_file(directory)?,
        directory.join("internal-ca-key.pem"),
        directory.join("scoplen.sqlite.migration.lock"),
    ];
    #[cfg(windows)]
    let result = (|| {
        windows_private_directory::prepare_directory(directory, &private_files)?;
        let snapshots = directory.join("scoplen.sqlite.migration-snapshots");
        match std::fs::symlink_metadata(&snapshots) {
            Ok(_) => {
                windows_private_directory::prepare_directory(&snapshots, &[])?;
                let files = std::fs::read_dir(&snapshots)
                    .and_then(|entries| {
                        entries.map(|entry| entry.map(|entry| entry.path())).collect::<Result<Vec<_>, _>>()
                    })
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                        "Windows snapshot permissions could not be verified; inspect the private migration-snapshot directory before restarting"))?;
                windows_private_directory::prepare_directory(&snapshots, &files)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Windows snapshot permissions could not be verified; inspect the private migration-snapshot directory before restarting",
            )),
        }
    })();
    #[cfg(not(windows))]
    let result = std::fs::create_dir_all(directory);
    result.map_err(|source| {
        #[cfg(windows)]
        return ServerError::PrivateMaterialAccess(source);
        #[cfg(not(windows))]
        ServerError::DataDirectory { path: directory.clone(), source }
    })
}

fn write_private(path: &Path, contents: &str) -> Result<(), ServerError> {
    crate::private_material::write_private(path, contents)
        .map_err(|source| ServerError::Material { path: path.to_path_buf(), source })
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

fn uses_postgres(config: &Config) -> bool {
    config.storage.backend.trim().eq_ignore_ascii_case("postgres")
}

/// Prepare only the resources required by the selected roles.
///
/// # Errors
///
/// Returns an error when role-specific configuration, database migration, or first-run material
/// initialization fails.
pub async fn prepare_roles(config: &Config, roles: &[Role]) -> Result<PreparedRoles, ServerError> {
    prepare_roles_with_setup(config, roles, false).await
}

/// Explicit server-host recovery for an uncompleted first-operator setup entitlement.
///
/// # Errors
/// Requires the locally configured database and KMS; completed setup is never reopened.
pub async fn reissue_operator_setup(
    config: &Config,
) -> Result<scoplen_store::operator_setup::SetupDisclosure, ServerError> {
    let mut prepared = prepare_roles_with_setup(config, &[Role::Api], true).await?;
    prepared
        .setup_link
        .take()
        .ok_or_else(|| ServerError::Task("operator setup is already completed".into()))
}

async fn prepare_roles_with_setup(
    config: &Config,
    roles: &[Role],
    reissue: bool,
) -> Result<PreparedRoles, ServerError> {
    config.validate_for_roles(roles)?;
    if !roles.iter().any(|role| role.requires_store()) {
        return Ok(PreparedRoles {
            store: None,
            postgres_store: None,
            object_storage: None,
            key_management: None,
            audit_signer: None,
            setup_link: None,
        });
    }
    prepare_data_directory(config)?;
    let (store, postgres_store) = if uses_postgres(config) {
        let database_url = config
            .storage
            .database_url
            .as_ref()
            .ok_or_else(|| {
                ServerError::Config(crate::ConfigError::Invalid(
                    "storage.database_url is required when storage.backend = postgres".into(),
                ))
            })?
            .expose();
        (
            None,
            Some(
                PostgresStore::connect_with_sync_limits(
                    &database_url,
                    config.sync.cardinality_limits(),
                    config.sync.write_body_limits()?.codec_limits(),
                )
                .await?,
            ),
        )
    } else {
        (
            Some(
                SqliteStore::open_with_sync_limits(
                    &config.server.data_dir.join("scoplen.sqlite"),
                    config.sync.cardinality_limits(),
                    config.sync.write_body_limits()?.codec_limits(),
                )
                .await?,
            ),
            None,
        )
    };
    let origin = config.public_origin()?;
    if let Some(store) = &store {
        store.check_operator_setup_startup(&origin, reissue).await?;
    } else if let Some(store) = &postgres_store {
        store.check_operator_setup_startup(&origin, reissue).await?;
    } else {
        return Err(ServerError::MissingStore);
    }
    let object_config = config.storage.object_storage_config(&config.server.data_dir)?;
    let object_storage = ObjectStorage::from_config(&object_config)?;
    bootstrap(config)?;
    let key_management =
        Some(LocalKeyFile::load(config.storage.kms_key_file(&config.server.data_dir)?)?);
    let audit_signer =
        Some(LocalAuditSigner::load(config.storage.kms_audit_key_file(&config.server.data_dir)?)?);
    let setup_link = if roles.contains(&Role::Api) {
        if let Some(store) = &store {
            store.initialize_operator_setup(&origin, reissue).await?
        } else if let Some(store) = &postgres_store {
            store.initialize_operator_setup(&origin, reissue).await?
        } else {
            return Err(ServerError::MissingStore);
        }
    } else {
        None
    };
    Ok(PreparedRoles {
        store,
        postgres_store,
        object_storage: Some(object_storage),
        key_management,
        audit_signer,
        setup_link,
    })
}

/// Run the requested roles until Ctrl-C using role-specific startup resources.
///
/// # Errors
///
/// Returns an error when signal handling, listener startup, or a role task fails.
pub async fn run_roles(
    config: Config,
    roles: Vec<Role>,
    store: Option<SqliteStore>,
    postgres_store: Option<PostgresStore>,
    object_storage: Option<ObjectStorage>,
    key_management: Option<LocalKeyFile>,
    audit_signer: Option<LocalAuditSigner>,
) -> Result<(), ServerError> {
    if roles.iter().any(|role| role.requires_store())
        && (store.is_none() && postgres_store.is_none() || object_storage.is_none())
    {
        return Err(ServerError::MissingStore);
    }
    if roles.iter().any(|role| role.requires_store()) && key_management.is_none() {
        return Err(ServerError::MissingKeyManagement);
    }
    if roles.iter().any(|role| role.requires_store()) && audit_signer.is_none() {
        return Err(ServerError::MissingKeyManagement);
    }
    let key_management = key_management.map(Arc::new);
    let store = store.map(Arc::new);
    let postgres_store = postgres_store.map(Arc::new);
    let object_storage = object_storage.map(Arc::new);
    let postgres = uses_postgres(&config);
    if let Some(kms) = key_management.as_ref() {
        if postgres {
            let store = postgres_store.as_ref().ok_or(ServerError::MissingStore)?;
            store
                .ensure_device_token_keyring(kms.as_ref())
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
        } else if let Some(store) = store.as_ref() {
            store
                .ensure_device_token_keyring(kms.as_ref())
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
        }
    }
    let mut tasks = tokio::task::JoinSet::new();
    if roles.contains(&Role::Api) || roles.contains(&Role::Edge) {
        let database = if postgres {
            ListenerDatabase::Postgres(
                postgres_store.as_ref().ok_or(ServerError::MissingStore)?.clone(),
            )
        } else {
            ListenerDatabase::Sqlite(store.as_ref().ok_or(ServerError::MissingStore)?.clone())
        };
        let object_storage = object_storage.as_ref().ok_or(ServerError::MissingStore)?.clone();
        tasks.spawn(run_public_listener(
            config.clone(),
            roles.clone(),
            database,
            object_storage,
            key_management.as_ref().ok_or(ServerError::MissingKeyManagement)?.clone(),
        ));
    }
    if roles.contains(&Role::Worker) {
        let signer = audit_signer.as_ref().ok_or(ServerError::MissingKeyManagement)?;
        if postgres {
            let store = postgres_store.as_ref().ok_or(ServerError::MissingStore)?.clone();
            tasks.spawn(run_worker_role(store, Arc::new(signer.clone())));
        } else {
            let store = store.as_ref().ok_or(ServerError::MissingStore)?.clone();
            tasks.spawn(run_worker_role(store, Arc::new(signer.clone())));
        }
    }
    if roles.contains(&Role::Ca) {
        tasks.spawn(run_periodic_role("ca"));
    }
    if roles.contains(&Role::Gateway) {
        tasks.spawn(run_periodic_role("gateway"));
    }
    info!(roles = ?roles, "server roles started");
    let result = tokio::select! {
        signal = tokio::signal::ctrl_c() => signal.map_err(ServerError::Runtime),
        completed = tasks.join_next() => match completed {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(ServerError::Task(error.to_string())),
            _ => Err(ServerError::Task("server role stopped unexpectedly".into())),
        },
    };
    tasks.shutdown().await;
    info!("server shutdown requested");
    result
}

async fn run_periodic_role(name: &'static str) -> Result<(), ServerError> {
    loop {
        info!(role = name, "role heartbeat");
        sleep(Duration::from_secs(30)).await;
    }
}

const WORKER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const RETENTION_JOB_KIND: &str = "sync-retention";
const RETENTION_WORKER_OWNER: &str = "sync-retention-worker";
const RETENTION_JOB_LEASE_MS: i64 = 60_000;
const RETENTION_RETRY_MS: i64 = 60_000;
const AUDIT_CHECKPOINT_INTERVAL_MS: i64 = 60 * 60 * 1_000;
const AUDIT_HEAD_PAGE_SIZE: u32 = 256;

trait WorkerStoreBackend: Send + Sync {
    fn requeue_expired_jobs(
        &self,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, JobQueueError>> + Send;
    fn list_sync_vault_ids(
        &self,
        limit: u16,
    ) -> impl Future<Output = Result<Vec<[u8; 16]>, SyncStoreError>> + Send;
    fn enqueue_job_if_absent(
        &self,
        id: [u8; 16],
        kind: &str,
        payload: &[u8],
        available_at_ms: i64,
    ) -> impl Future<Output = Result<bool, JobQueueError>> + Send;
    fn claim_job_kind(
        &self,
        kind: &str,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> impl Future<Output = Result<Option<scoplen_store::Job>, JobQueueError>> + Send;
    fn purge_sync_history(
        &self,
        vault_id: [u8; 16],
        acknowledged_through: Option<u64>,
        now_ms: i64,
    ) -> impl Future<Output = Result<scoplen_store::sync::PurgeReport, SyncStoreError>> + Send;
    fn complete_job(
        &self,
        id: [u8; 16],
        owner: &str,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), JobQueueError>> + Send;
    fn fail_job(
        &self,
        id: [u8; 16],
        owner: &str,
        now_ms: i64,
        retry_at_ms: i64,
        error: &str,
    ) -> impl Future<Output = Result<(), JobQueueError>> + Send;
    fn list_audit_heads_page(
        &self,
        after_organization: Option<[u8; 16]>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AuditChainHead>, AuditStoreError>> + Send;
    fn verify_audit_chain(
        &self,
        organization_id: [u8; 16],
    ) -> impl Future<Output = Result<[u8; 32], AuditStoreError>> + Send;
    fn latest_audit_checkpoint(
        &self,
        organization_id: [u8; 16],
    ) -> impl Future<Output = Result<Option<AuditCheckpoint>, AuditStoreError>> + Send;
    fn write_audit_checkpoint(
        &self,
        checkpoint: &AuditCheckpoint,
    ) -> impl Future<Output = Result<(), AuditStoreError>> + Send;
    fn verify_deployment_audit_chain(
        &self,
    ) -> impl Future<Output = Result<Option<DeploymentAuditChainHead>, AuditStoreError>> + Send;
    fn latest_deployment_audit_checkpoint(
        &self,
    ) -> impl Future<Output = Result<Option<DeploymentAuditCheckpoint>, AuditStoreError>> + Send;
    fn write_deployment_audit_checkpoint(
        &self,
        checkpoint: &DeploymentAuditCheckpoint,
    ) -> impl Future<Output = Result<(), AuditStoreError>> + Send;
}

macro_rules! impl_worker_store_backend {
    ($store:ty) => {
        impl WorkerStoreBackend for $store {
            fn requeue_expired_jobs(
                &self,
                now_ms: i64,
            ) -> impl Future<Output = Result<u64, JobQueueError>> + Send {
                <$store>::requeue_expired_jobs(self, now_ms)
            }

            fn list_sync_vault_ids(
                &self,
                limit: u16,
            ) -> impl Future<Output = Result<Vec<[u8; 16]>, SyncStoreError>> + Send {
                <$store>::list_sync_vault_ids(self, limit)
            }

            fn enqueue_job_if_absent(
                &self,
                id: [u8; 16],
                kind: &str,
                payload: &[u8],
                available_at_ms: i64,
            ) -> impl Future<Output = Result<bool, JobQueueError>> + Send {
                <$store>::enqueue_job_if_absent(self, id, kind, payload, available_at_ms)
            }

            fn claim_job_kind(
                &self,
                kind: &str,
                owner: &str,
                now_ms: i64,
                lease_ms: i64,
            ) -> impl Future<Output = Result<Option<scoplen_store::Job>, JobQueueError>> + Send {
                <$store>::claim_job_kind(self, kind, owner, now_ms, lease_ms)
            }

            fn purge_sync_history(
                &self,
                vault_id: [u8; 16],
                acknowledged_through: Option<u64>,
                now_ms: i64,
            ) -> impl Future<Output = Result<scoplen_store::sync::PurgeReport, SyncStoreError>> + Send {
                <$store>::purge_sync_history(self, vault_id, acknowledged_through, now_ms)
            }

            fn complete_job(
                &self,
                id: [u8; 16],
                owner: &str,
                now_ms: i64,
            ) -> impl Future<Output = Result<(), JobQueueError>> + Send {
                <$store>::complete_job(self, id, owner, now_ms)
            }

            fn fail_job(
                &self,
                id: [u8; 16],
                owner: &str,
                now_ms: i64,
                retry_at_ms: i64,
                error: &str,
            ) -> impl Future<Output = Result<(), JobQueueError>> + Send {
                <$store>::fail_job(self, id, owner, now_ms, retry_at_ms, error)
            }

            fn list_audit_heads_page(
                &self,
                after_organization: Option<[u8; 16]>,
                limit: u32,
            ) -> impl Future<Output = Result<Vec<AuditChainHead>, AuditStoreError>> + Send {
                <$store>::list_audit_heads_page(self, after_organization, limit)
            }

            fn verify_audit_chain(
                &self,
                organization_id: [u8; 16],
            ) -> impl Future<Output = Result<[u8; 32], AuditStoreError>> + Send {
                <$store>::verify_audit_chain(self, organization_id)
            }

            fn latest_audit_checkpoint(
                &self,
                organization_id: [u8; 16],
            ) -> impl Future<Output = Result<Option<AuditCheckpoint>, AuditStoreError>> + Send {
                <$store>::latest_audit_checkpoint(self, organization_id)
            }

            fn write_audit_checkpoint(
                &self,
                checkpoint: &AuditCheckpoint,
            ) -> impl Future<Output = Result<(), AuditStoreError>> + Send {
                <$store>::write_audit_checkpoint(self, checkpoint)
            }

            fn verify_deployment_audit_chain(
                &self,
            ) -> impl Future<Output = Result<Option<DeploymentAuditChainHead>, AuditStoreError>> + Send {
                <$store>::verify_deployment_audit_chain(self)
            }

            fn latest_deployment_audit_checkpoint(
                &self,
            ) -> impl Future<Output = Result<Option<DeploymentAuditCheckpoint>, AuditStoreError>> + Send {
                <$store>::latest_deployment_audit_checkpoint(self)
            }

            fn write_deployment_audit_checkpoint(
                &self,
                checkpoint: &DeploymentAuditCheckpoint,
            ) -> impl Future<Output = Result<(), AuditStoreError>> + Send {
                <$store>::write_deployment_audit_checkpoint(self, checkpoint)
            }
        }
    };
}

impl_worker_store_backend!(SqliteStore);
impl_worker_store_backend!(PostgresStore);

async fn run_worker_role<S: WorkerStoreBackend + 'static>(
    store: Arc<S>,
    signer: Arc<LocalAuditSigner>,
) -> Result<(), ServerError> {
    let mut interval = tokio::time::interval(WORKER_HEARTBEAT_INTERVAL);
    loop {
        interval.tick().await;
        match worker_heartbeat(store.as_ref()).await {
            Ok(requeued) => {
                info!(role = "worker", requeued_expired_jobs = requeued, "worker heartbeat");
            }
            Err(error) => error!(%error, role = "worker", "worker heartbeat failed"),
        }
        match worker_retention_pass(store.as_ref()).await {
            Ok((scheduled, processed)) => {
                info!(
                    role = "worker",
                    scheduled_retention_jobs = scheduled,
                    processed_retention_jobs = processed,
                    "retention pass"
                );
            }
            Err(error) => error!(%error, role = "worker", "retention pass failed"),
        }
        match worker_audit_checkpoint_pass(store.as_ref(), signer.as_ref()).await {
            Ok(written) => {
                info!(role = "worker", audit_checkpoints = written, "audit checkpoint pass");
            }
            Err(error) => error!(%error, role = "worker", "audit checkpoint pass failed"),
        }
    }
}

async fn worker_heartbeat<S: WorkerStoreBackend>(store: &S) -> Result<u64, ServerError> {
    let now = worker_now_ms()?;
    store.requeue_expired_jobs(now).await.map_err(|error| ServerError::Task(error.to_string()))
}

fn worker_now_ms() -> Result<i64, ServerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ServerError::Task(format!("worker clock is before Unix epoch: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| ServerError::Task("worker clock exceeds database timestamp range".into()))
}

async fn worker_retention_pass<S: WorkerStoreBackend>(
    store: &S,
) -> Result<(u64, u64), ServerError> {
    let now = worker_now_ms()?;
    worker_retention_pass_at(store, now).await
}

async fn worker_retention_pass_at<S: WorkerStoreBackend>(
    store: &S,
    now: i64,
) -> Result<(u64, u64), ServerError> {
    let mut scheduled = 0_u64;
    for vault_id in store
        .list_sync_vault_ids(MAX_PAGE_SIZE)
        .await
        .map_err(|error| ServerError::Task(error.to_string()))?
    {
        if store
            .enqueue_job_if_absent(
                uuid::Uuid::new_v4().into_bytes(),
                RETENTION_JOB_KIND,
                &vault_id,
                now,
            )
            .await
            .map_err(|error| ServerError::Task(error.to_string()))?
        {
            scheduled = scheduled.saturating_add(1);
        }
    }

    let mut processed = 0_u64;
    while let Some(job) = store
        .claim_job_kind(RETENTION_JOB_KIND, RETENTION_WORKER_OWNER, now, RETENTION_JOB_LEASE_MS)
        .await
        .map_err(|error| ServerError::Task(error.to_string()))?
    {
        let result = job
            .payload
            .as_slice()
            .try_into()
            .map(|vault_id| store.purge_sync_history(vault_id, None, now));
        let result = match result {
            Ok(purge) => purge.await,
            Err(_) => Err(SyncStoreError::CorruptRow("retention payload")),
        };
        let transition_now = now.max(job.created_at_ms);
        match result {
            Ok(_) => store
                .complete_job(job.id, RETENTION_WORKER_OWNER, transition_now)
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?,
            Err(error) => {
                let retry_at = transition_now.saturating_add(RETENTION_RETRY_MS);
                store
                    .fail_job(
                        job.id,
                        RETENTION_WORKER_OWNER,
                        transition_now,
                        retry_at,
                        &error.to_string(),
                    )
                    .await
                    .map_err(|error| ServerError::Task(error.to_string()))?;
            }
        }
        processed = processed.saturating_add(1);
    }
    Ok((scheduled, processed))
}

async fn worker_audit_checkpoint_pass<S: WorkerStoreBackend>(
    store: &S,
    signer: &impl AuditCheckpointSigner,
) -> Result<u64, ServerError> {
    let now = worker_now_ms()?;
    worker_audit_checkpoint_pass_at(store, signer, now).await
}

async fn worker_audit_checkpoint_pass_at<S: WorkerStoreBackend>(
    store: &S,
    signer: &impl AuditCheckpointSigner,
    now: i64,
) -> Result<u64, ServerError> {
    let mut written = 0_u64;
    let mut after_organization = None;
    loop {
        let heads = store
            .list_audit_heads_page(after_organization, AUDIT_HEAD_PAGE_SIZE)
            .await
            .map_err(|error| ServerError::Task(error.to_string()))?;
        if heads.is_empty() {
            break;
        }
        for head in &heads {
            let verified_head = store
                .verify_audit_chain(head.organization_id)
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
            if verified_head != head.head_hash {
                return Err(ServerError::Task(
                    "audit chain head changed or failed verification".into(),
                ));
            }
            if let Some(previous) = store
                .latest_audit_checkpoint(head.organization_id)
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?
            {
                if previous.sequence == head.sequence && previous.head_hash == head.head_hash {
                    continue;
                }
                if now.saturating_sub(previous.signed_at_ms) < AUDIT_CHECKPOINT_INTERVAL_MS {
                    continue;
                }
            }
            let payload = checkpoint_payload(
                &head.organization_id,
                head.sequence,
                &head.head_hash,
                u64::try_from(now)
                    .map_err(|_| ServerError::Task("worker clock is negative".into()))?,
            )
            .map_err(|error| ServerError::Task(error.to_string()))?;
            let checkpoint = AuditCheckpoint {
                organization_id: head.organization_id,
                sequence: head.sequence,
                head_hash: head.head_hash,
                signature: signer.sign_checkpoint(&payload),
                signed_at_ms: now,
            };
            match store.write_audit_checkpoint(&checkpoint).await {
                Ok(()) => written = written.saturating_add(1),
                Err(scoplen_store::AuditStoreError::CheckpointConflict) => {
                    let current = store
                        .latest_audit_checkpoint(head.organization_id)
                        .await
                        .map_err(|error| ServerError::Task(error.to_string()))?;
                    if !current.is_some_and(|current| {
                        current.sequence == head.sequence && current.head_hash == head.head_hash
                    }) {
                        return Err(ServerError::Task(
                            "audit checkpoint changed to a different chain head concurrently"
                                .into(),
                        ));
                    }
                }
                Err(error) => return Err(ServerError::Task(error.to_string())),
            }
        }
        after_organization = heads.last().map(|head| head.organization_id);
        if heads.len() < AUDIT_HEAD_PAGE_SIZE as usize {
            break;
        }
    }
    Ok(written
        .saturating_add(worker_deployment_audit_checkpoint_pass_at(store, signer, now).await?))
}

async fn worker_deployment_audit_checkpoint_pass_at<S: WorkerStoreBackend>(
    store: &S,
    signer: &impl AuditCheckpointSigner,
    now: i64,
) -> Result<u64, ServerError> {
    let Some(head) = store
        .verify_deployment_audit_chain()
        .await
        .map_err(|error| ServerError::Task(error.to_string()))?
    else {
        return Ok(0);
    };
    if let Some(previous) = store
        .latest_deployment_audit_checkpoint()
        .await
        .map_err(|error| ServerError::Task(error.to_string()))?
    {
        if previous.sequence == head.sequence && previous.head_hash == head.head_hash {
            return Ok(0);
        }
        if now.saturating_sub(previous.signed_at_ms) < AUDIT_CHECKPOINT_INTERVAL_MS {
            return Ok(0);
        }
    }
    let payload = deployment_checkpoint_payload(
        head.sequence,
        &head.head_hash,
        u64::try_from(now).map_err(|_| ServerError::Task("worker clock is negative".into()))?,
    )
    .map_err(|error| ServerError::Task(error.to_string()))?;
    let checkpoint = DeploymentAuditCheckpoint {
        sequence: head.sequence,
        head_hash: head.head_hash,
        signature: signer.sign_checkpoint(&payload),
        signed_at_ms: now,
    };
    match store.write_deployment_audit_checkpoint(&checkpoint).await {
        Ok(()) => Ok(1),
        Err(AuditStoreError::CheckpointDeferred) => Ok(0),
        Err(AuditStoreError::CheckpointConflict) => {
            let current = store
                .latest_deployment_audit_checkpoint()
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
            if !current.is_some_and(|current| {
                current.sequence == head.sequence && current.head_hash == head.head_hash
            }) {
                return Err(ServerError::Task(
                    "deployment audit checkpoint changed to a different chain head concurrently"
                        .into(),
                ));
            }
            Ok(0)
        }
        Err(error) => Err(ServerError::Task(error.to_string())),
    }
}

#[cfg(test)]
pub(crate) fn api_router(
    database: ListenerDatabase,
    object_storage: Arc<ObjectStorage>,
    key_management: Arc<LocalKeyFile>,
    trusted_origin: String,
    enrollment_enabled: bool,
) -> Router {
    api_router_with_limits(
        database,
        object_storage,
        key_management,
        trusted_origin,
        enrollment_enabled,
        WriteRateLimits::default(),
        WriteBodyLimits::default(),
        ReadBodyLimits::default(),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn api_router_with_limits(
    database: ListenerDatabase,
    object_storage: Arc<ObjectStorage>,
    key_management: Arc<LocalKeyFile>,
    trusted_origin: String,
    enrollment_enabled: bool,
    write_rate_limits: WriteRateLimits,
    write_body_limits: WriteBodyLimits,
    read_body_limits: ReadBodyLimits,
) -> Router {
    api_router_with_notifications(
        database,
        object_storage,
        key_management,
        trusted_origin,
        enrollment_enabled,
        write_rate_limits,
        write_body_limits,
        read_body_limits,
        NotificationHub::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn api_router_with_notifications(
    database: ListenerDatabase,
    object_storage: Arc<ObjectStorage>,
    key_management: Arc<LocalKeyFile>,
    trusted_origin: String,
    enrollment_enabled: bool,
    write_rate_limits: WriteRateLimits,
    write_body_limits: WriteBodyLimits,
    read_body_limits: ReadBodyLimits,
    notifications: NotificationHub,
) -> Router {
    let enrollment_backend = match &database {
        ListenerDatabase::Sqlite(store) => {
            personal_enrollment::EnrollmentBackend::Sqlite(store.clone())
        }
        ListenerDatabase::Postgres(store) => {
            personal_enrollment::EnrollmentBackend::Postgres(store.clone())
        }
    };
    let auth_backend = match &database {
        ListenerDatabase::Sqlite(store) => device_auth::AuthBackend::Sqlite(store.clone()),
        ListenerDatabase::Postgres(store) => device_auth::AuthBackend::Postgres(store.clone()),
    };
    let sync_backend = match &database {
        ListenerDatabase::Sqlite(store) => scoplen_sync::http::SyncBackend::Sqlite(store.clone()),
        ListenerDatabase::Postgres(store) => {
            scoplen_sync::http::SyncBackend::Postgres(store.clone())
        }
    };
    let readiness_notifications = notifications.clone();
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let database = database.clone();
                let object_storage = object_storage.clone();
                let notifications = readiness_notifications.clone();
                async move {
                    if !notifications.is_available() {
                        return (StatusCode::SERVICE_UNAVAILABLE, "notifications unavailable");
                    }
                    match (database.ping().await, object_storage.check().await) {
                        (Ok(()), Ok(())) => (StatusCode::OK, "ready"),
                        (Err(error), _) => {
                            error!(%error, "readiness database query failed");
                            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
                        }
                        (_, Err(error)) => {
                            error!(%error, "readiness object storage check failed");
                            (StatusCode::SERVICE_UNAVAILABLE, "object storage unavailable")
                        }
                    }
                }
            }),
        )
        .route("/metrics", get(|| async {
            format!(
                "# HELP scoplen_server_info Server build information.\n# TYPE scoplen_server_info gauge\nscoplen_server_info{{version=\"{}\"}} 1\n",
                crate::VERSION
            )
        }));
    if enrollment_enabled {
        router
            .merge(personal_enrollment::router(trusted_origin.clone(), enrollment_backend))
            .merge(crate::account_devices::router(
                trusted_origin.clone(),
                auth_backend.clone(),
                key_management.clone(),
            ))
            .merge(crate::account_profile::router(
                trusted_origin.clone(),
                auth_backend.clone(),
                key_management.clone(),
            ))
            .merge(crate::pairing::router(
                trusted_origin.clone(),
                auth_backend.clone(),
                key_management.clone(),
            ))
            .merge(device_auth::router(
                trusted_origin.clone(),
                auth_backend.clone(),
                key_management.clone(),
            ))
            .merge(scoplen_sync::http::personal_router_with_notifications(
                sync_backend,
                personal_sync::PersonalSyncAuthenticator::new(
                    auth_backend,
                    key_management,
                    trusted_origin,
                ),
                notifications,
                write_rate_limits,
                write_body_limits,
                read_body_limits,
            ))
    } else {
        router
    }
}

async fn run_public_listener(
    config: Config,
    roles: Vec<Role>,
    database: ListenerDatabase,
    object_storage: Arc<ObjectStorage>,
    key_management: Arc<LocalKeyFile>,
) -> Result<(), ServerError> {
    let address = config.listen_address();
    let trusted_origin = config.public_origin()?;
    let enrollment_enabled = roles.contains(&Role::Api);
    let write_rate_limits = config.sync.write_rate_limits()?;
    let write_body_limits = config.sync.write_body_limits()?;
    let read_body_limits = config.sync.read_body_limits()?;
    let notifications = NotificationHub::default();
    let fanout = match &database {
        ListenerDatabase::Postgres(store) if enrollment_enabled => Some(
            PostgresNotificationFanout::connect(
                store.clone(),
                personal_sync::PersonalSyncAuthenticator::new(
                    device_auth::AuthBackend::Postgres(store.clone()),
                    key_management.clone(),
                    trusted_origin.clone(),
                ),
                notifications.clone(),
            )
            .await
            .map_err(|_| ServerError::Task("sync notification subscription unavailable".into()))?,
        ),
        _ => None,
    };
    let router = api_router_with_notifications(
        database,
        object_storage,
        key_management,
        trusted_origin,
        enrollment_enabled,
        write_rate_limits,
        write_body_limits,
        read_body_limits,
        notifications,
    )
    .merge(crate::console::router(&config.console.assets_dir, enrollment_enabled).await);
    let listener = TcpListener::bind(&address).await?;
    info!(%address, tls_mode = ?config.tls.mode, "public listener started");
    let serve = serve_public_listener(config, roles, listener, router);
    if let Some(fanout) = fanout {
        tokio::select! {
            result = serve => result,
            _ = fanout.run() => Err(ServerError::Task("sync notification worker stopped".into())),
        }
    } else {
        serve.await
    }
}

async fn serve_public_listener(
    config: Config,
    roles: Vec<Role>,
    listener: TcpListener,
    router: Router,
) -> Result<(), ServerError> {
    match config.tls.mode {
        TlsMode::Plain => {
            if roles.contains(&Role::Edge) {
                warn!(
                    "edge role is configured behind plain HTTP; gateway ALPN requires direct TLS"
                );
            }
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .map_err(|error| ServerError::Task(error.to_string()))?;
        }
        TlsMode::Files => {
            let acceptor = TlsAcceptor::from(Arc::new(tls_config(&config)?));
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (stream, peer) = tokio::select! {
                    accepted = listener.accept() => accepted?,
                    Some(_) = connections.join_next() => continue,
                };
                let acceptor = acceptor.clone();
                let router = router.clone().layer(Extension(ConnectInfo(peer)));
                connections.spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls) => {
                            if let Err(error) = serve_tls_connection(tls, router).await {
                                error!(%peer, %error, "TLS connection failed");
                            }
                        }
                        Err(error) => error!(%peer, %error, "TLS handshake failed"),
                    }
                });
            }
        }
        TlsMode::Acme => {
            run_acme_listener(config, listener, router).await?;
        }
    }
    Ok(())
}

fn tls_config(config: &Config) -> Result<ServerConfig, ServerError> {
    let cert_path = config
        .tls
        .cert_file
        .as_ref()
        .ok_or_else(|| ServerError::Tls("tls.cert_file is required in files mode".into()))?;
    let key_path = config
        .tls
        .key_file
        .as_ref()
        .ok_or_else(|| ServerError::Tls("tls.key_file is required in files mode".into()))?;
    let mut cert_file = std::io::BufReader::new(
        std::fs::File::open(cert_path).map_err(|error| ServerError::Tls(error.to_string()))?,
    );
    let certificates = rustls_pemfile::certs(&mut cert_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ServerError::Tls(error.to_string()))?;
    if certificates.is_empty() {
        return Err(ServerError::Tls("tls.cert_file contains no certificates".into()));
    }
    let mut key_file = std::io::BufReader::new(
        std::fs::File::open(key_path).map_err(|error| ServerError::Tls(error.to_string()))?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_file)
        .map_err(|error| ServerError::Tls(error.to_string()))?
        .ok_or_else(|| ServerError::Tls("tls.key_file contains no private key".into()))?;
    let mut server = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| ServerError::Tls(error.to_string()))?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|error| ServerError::Tls(error.to_string()))?;
    server.alpn_protocols = application_alpn_protocols();
    Ok(server)
}

async fn run_acme_listener(
    config: Config,
    listener: TcpListener,
    router: Router,
) -> Result<(), ServerError> {
    let email = config
        .tls
        .acme_email
        .as_deref()
        .ok_or_else(|| ServerError::Tls("tls.acme_email is required in acme mode".into()))?;
    let cache_dir = config.server.data_dir.join("acme-cache");
    let mut tls_incoming = AcmeConfig::new([config.server.public_host.as_str()])
        .contact_push(acme_contact(email))
        .cache(DirCache::new(cache_dir))
        .directory_lets_encrypt(config.tls.acme_production)
        .tokio_incoming(TcpListenerStream::new(listener), application_alpn_protocols());
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let result = tokio::select! {
            incoming = tls_incoming.next() => match incoming { Some(value) => value, None => break },
            Some(_) = connections.join_next() => continue,
        };
        let tls = result.map_err(ServerError::Runtime)?;
        let is_gateway = tls
            .get_ref()
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|protocol| protocol == b"spl-gw/1");
        let peer = tls.get_ref().get_ref().0.get_ref().peer_addr().map_err(ServerError::Runtime)?;
        let router = router.clone().layer(Extension(ConnectInfo(peer)));
        connections.spawn(async move {
            if let Err(error) = serve_tls_io(tls, router, is_gateway).await {
                error!(%error, "ACME TLS connection failed");
            }
        });
    }
    Ok(())
}

fn acme_contact(email: &str) -> String {
    let email = email.trim();
    if email.starts_with("mailto:") { email.to_owned() } else { format!("mailto:{email}") }
}

fn application_alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"spl-gw/1".to_vec()]
}

async fn serve_tls_connection(
    stream: TlsStream<tokio::net::TcpStream>,
    router: Router,
) -> Result<(), ServerError> {
    let is_gateway =
        stream.get_ref().1.alpn_protocol().is_some_and(|protocol| protocol == b"spl-gw/1");
    serve_tls_io(stream, router, is_gateway).await
}

pub(crate) async fn serve_tls_io<S>(
    mut stream: S,
    router: Router,
    is_gateway: bool,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if is_gateway {
        stream
            .write_all(b"SPL gateway protocol is reserved for the managed data-path gate.\n")
            .await?;
        return Ok(());
    }
    let io = TokioIo::new(stream);
    let service = TowerToHyperService::new(router);
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http2().enable_connect_protocol();
    builder
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|error| ServerError::Task(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use scoplen_store::RelationalStore;
    use scoplen_store::operator_setup::OperatorSetupError;
    use scoplen_store::sync::{ObjectWrite, TOMBSTONE_PURGE_AFTER_DAYS, VaultKind};
    use tokio::io::AsyncReadExt;

    async fn remove_test_directory(path: &Path) {
        for attempt in 0..20 {
            match fs::remove_dir_all(path) {
                Ok(()) => return,
                Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("remove test directory {}: {error}", path.display()),
            }
        }
    }

    #[cfg(feature = "postgres-integration")]
    async fn postgres_fixture() -> (url::Url, sqlx::PgPool, String) {
        let database = std::env::var("SCOPLEN_TEST_DATABASE_URL")
            .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
        let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
        let schema = format!("runtime_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .expect("owned runtime schema");
        let mut url = url::Url::parse(&database).expect("fixture URL");
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        (url, pool, schema)
    }

    #[cfg(feature = "postgres-integration")]
    async fn cleanup_postgres_fixture(pool: sqlx::PgPool, schema: String) {
        assert!(
            schema.starts_with("runtime_")
                && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .expect("remove owned runtime schema");
        pool.close().await;
    }

    #[tokio::test]
    async fn files_tls_negotiates_trusted_https_and_h2() {
        use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
        use tokio_rustls::TlsConnector;

        let data_dir =
            std::env::temp_dir().join(format!("scoplen-files-tls-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&data_dir).expect("owned TLS directory");
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("test certificate");
        let mut config = Config::default();
        config.tls.cert_file = Some(data_dir.join("localhost.pem"));
        config.tls.key_file = Some(data_dir.join("localhost-key.pem"));
        fs::write(config.tls.cert_file.as_ref().expect("certificate path"), cert.pem())
            .expect("test certificate file");
        fs::write(config.tls.key_file.as_ref().expect("key path"), key_pair.serialize_pem())
            .expect("test private key file");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config(&config).expect("files TLS config")));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("TLS listener");
        let address = listener.local_addr().expect("TLS address");
        let server = tokio::spawn(async move {
            for protocol in [b"http/1.1".as_slice(), b"h2".as_slice()] {
                let (tcp, _) = listener.accept().await.expect("incoming TLS connection");
                let mut tls = acceptor.accept(tcp).await.expect("trusted TLS handshake");
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(protocol));
                if protocol == b"http/1.1" {
                    serve_tls_connection(
                        tls,
                        Router::new().route("/healthz", get(|| async { "ok" })),
                    )
                    .await
                    .expect("production HTTPS adapter");
                } else {
                    tls.shutdown().await.expect("close H2 handshake");
                }
            }
            let (tcp, _) = listener.accept().await.expect("untrusted TLS connection");
            assert!(acceptor.accept(tcp).await.is_err(), "unknown issuer must fail");
        });
        for protocol in [b"http/1.1".as_slice(), b"h2".as_slice(), b"untrusted".as_slice()] {
            let mut roots = RootCertStore::empty();
            if protocol != b"untrusted" {
                roots.add(cert.der().clone()).expect("test-only trust root");
            }
            let mut client = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("supported TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            client.alpn_protocols = vec![if protocol == b"untrusted" {
                b"http/1.1".to_vec()
            } else {
                protocol.to_vec()
            }];
            let connector = TlsConnector::from(Arc::new(client));
            let tcp = tokio::net::TcpStream::connect(address).await.expect("TLS TCP connection");
            let result =
                connector.connect(ServerName::try_from("localhost").expect("SNI"), tcp).await;
            if protocol == b"untrusted" {
                let error = result.expect_err("test must retain certificate verification");
                assert!(matches!(
                    error.get_ref().and_then(|cause| cause.downcast_ref::<rustls::Error>()),
                    Some(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::UnknownIssuer
                    ))
                ));
                continue;
            }
            let mut tls = result.expect("verified HTTPS connection");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(protocol));
            if protocol == b"http/1.1" {
                tls.write_all(
                    b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("health request");
                let mut reply = String::new();
                tls.read_to_string(&mut reply).await.expect("HTTPS health response");
                assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"));
                assert!(reply.ends_with("\r\n\r\nok"));
            } else {
                let mut reply = Vec::new();
                tls.read_to_end(&mut reply).await.expect("H2 handshake closed");
                assert_eq!(reply, [] as [u8; 0]);
            }
        }
        server.await.expect("TLS server completed");
        remove_test_directory(&data_dir).await;
    }

    #[test]
    fn bootstrap_creates_private_material_once() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-server-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.server.public_host = "example.com".into();
        config.server.public_port = 9443;

        bootstrap(&config).expect("first bootstrap succeeds");
        assert!(!data_dir.join("setup-link.txt").exists());
        for name in
            ["deployment.key", "audit-signing.key", "internal-ca.pem", "internal-ca-key.pem"]
        {
            let path = data_dir.join(name);
            assert!(path.is_file(), "expected generated material at {}", path.display());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).expect("material metadata").permissions().mode() & 0o777,
                    0o600
                );
            }
        }

        bootstrap(&config).expect("second bootstrap is idempotent");
        fs::remove_dir_all(data_dir).expect("test material is removable");
    }

    #[test]
    fn incomplete_ca_material_is_not_overwritten() {
        for (missing_name, survivor_name) in
            [("internal-ca-key.pem", "internal-ca.pem"), ("internal-ca.pem", "internal-ca-key.pem")]
        {
            let data_dir =
                std::env::temp_dir().join(format!("scoplen-bootstrap-{}", uuid::Uuid::new_v4()));
            let mut config = Config::default();
            config.server.data_dir = data_dir.clone();
            bootstrap(&config).expect("initial bootstrap");
            let survivor = data_dir.join(survivor_name);
            let existing = fs::read(&survivor).expect("existing material");
            let missing = data_dir.join(missing_name);
            fs::remove_file(&missing).expect("remove owned test material");
            for _ in 0..2 {
                let error = bootstrap(&config).expect_err("incomplete CA must fail closed");
                assert!(matches!(error, ServerError::Material { source, .. }
                    if source.kind() == std::io::ErrorKind::InvalidData));
                assert_eq!(fs::read(&survivor).expect("retained material"), existing);
                assert!(!missing.exists());
            }
            fs::remove_dir_all(data_dir).expect("remove owned test material");
        }
    }

    #[tokio::test]
    async fn listener_failure_stops_supervised_roles_and_releases_resources() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-role-failure-{}", uuid::Uuid::new_v4()));
        let occupied = TcpListener::bind("127.0.0.1:0").await.expect("owned occupied listener");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.server.listen_addr = "127.0.0.1".into();
        config.server.listen_port = occupied.local_addr().expect("occupied address").port();
        config.tls.mode = TlsMode::Plain;
        let prepared =
            prepare_roles(&config, &[Role::Api, Role::Worker]).await.expect("prepared roles");
        let store = prepared.store.as_ref().expect("SQLite").clone();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_roles(
                config,
                vec![Role::Api, Role::Worker],
                prepared.store,
                prepared.postgres_store,
                prepared.object_storage,
                prepared.key_management,
                prepared.audit_signer,
            ),
        )
        .await
        .expect("failed role must propagate without waiting for Ctrl-C");
        assert!(matches!(result, Err(ServerError::Runtime(_))));
        store.pool().close().await;
        drop((store, occupied));
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn readiness_follows_database_availability() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-ready-{}", uuid::Uuid::new_v4()));
        let store =
            SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("open database");
        let object_root = data_dir.join("objects");
        let object_storage =
            ObjectStorage::from_config(&scoplen_store::ObjectStorageConfig::Filesystem {
                root: object_root.clone(),
            })
            .expect("open object storage");
        fs::write(data_dir.join("deployment.key"), "09".repeat(32)).expect("test deployment key");
        let key_management =
            Arc::new(LocalKeyFile::load(data_dir.join("deployment.key")).expect("test KMS"));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind isolated HTTP listener");
        let address = listener.local_addr().expect("read listener address");
        let server_store = store.clone();
        let server_object_storage = object_storage.clone();
        let server_key_management = key_management.clone();
        let notifications = NotificationHub::default();
        let server_notifications = notifications.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                api_router_with_notifications(
                    ListenerDatabase::Sqlite(Arc::new(server_store)),
                    Arc::new(server_object_storage),
                    server_key_management,
                    "https://example.com".to_owned(),
                    true,
                    WriteRateLimits::default(),
                    WriteBodyLimits::default(),
                    ReadBodyLimits::default(),
                    server_notifications,
                )
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("serve readiness endpoint");
        });
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 200 OK"));
        notifications.unavailable();
        let unavailable = http_readiness(address).await;
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(unavailable.contains("notifications unavailable"));
        notifications.available();
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 200 OK"));
        let enrollment = http_request(address, b"POST /api/v1/auth/personal-enroll HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}").await;
        assert!(enrollment.starts_with("HTTP/1.1 415 Unsupported Media Type"), "{enrollment}");
        assert!(enrollment.contains("auth.invalid_request"));
        let challenge = http_request(address, b"POST /api/v1/auth/challenge HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}").await;
        assert!(challenge.starts_with("HTTP/1.1 415 Unsupported Media Type"), "{challenge}");
        let jwks = http_request(
            address,
            b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(jwks.starts_with("HTTP/1.1 200 OK"), "{jwks}");
        let edge_listener = TcpListener::bind("127.0.0.1:0").await.expect("edge-only listener");
        let edge_address = edge_listener.local_addr().expect("edge-only address");
        let edge_store = store.clone();
        let edge_object_storage = object_storage.clone();
        let edge_key_management = key_management.clone();
        let edge_server = tokio::spawn(async move {
            axum::serve(
                edge_listener,
                api_router(
                    ListenerDatabase::Sqlite(Arc::new(edge_store)),
                    Arc::new(edge_object_storage),
                    edge_key_management,
                    "https://example.com".to_owned(),
                    false,
                )
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("serve edge-only listener");
        });
        let edge_enrollment = http_request(edge_address, b"POST /api/v1/auth/personal-enroll HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}").await;
        assert!(edge_enrollment.starts_with("HTTP/1.1 404 Not Found"), "{edge_enrollment}");
        let edge_jwks = http_request(
            edge_address,
            b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(edge_jwks.starts_with("HTTP/1.1 404 Not Found"), "{edge_jwks}");
        edge_server.abort();
        let _ = edge_server.await;

        fs::remove_dir_all(&object_root).expect("remove object root for readiness failure");
        assert!(
            http_readiness(address).await.starts_with("HTTP/1.1 503 Service Unavailable"),
            "object storage failure must make readiness fail"
        );

        store.pool().close().await;
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 503 Service Unavailable"));
        server.abort();
        let _ = server.await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_api_edge_readiness_follows_selected_database() {
        let (database_url, fixture_pool, schema) = postgres_fixture().await;
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-postgres-ready-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.storage.backend = " PoStGrEs ".into();
        config.sync.max_objects_per_vault = 2;
        config.storage.database_url = Some(
            toml::Value::String(database_url.into()).try_into().expect("PostgreSQL URL setting"),
        );
        let prepared = prepare_roles(&config, &[Role::Api, Role::Edge])
            .await
            .expect("prepare PostgreSQL API and edge roles");
        assert!(prepared.store.is_none(), "PostgreSQL roles must not open SQLite");
        let store = prepared.postgres_store.expect("PostgreSQL pool");
        assert_eq!(store.sync_cardinality_limits().max_objects_per_vault, 2);
        let object_storage = prepared.object_storage.expect("object storage");
        let key_management = Arc::new(prepared.key_management.expect("test KMS"));
        let object_root = data_dir.join("objects");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind isolated HTTP listener");
        let address = listener.local_addr().expect("read listener address");
        let server = tokio::spawn({
            let store = store.clone();
            let key_management = key_management.clone();
            async move {
                axum::serve(
                    listener,
                    api_router(
                        ListenerDatabase::Postgres(Arc::new(store)),
                        Arc::new(object_storage),
                        key_management,
                        "https://example.com".to_owned(),
                        true,
                    )
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .await
                .expect("serve PostgreSQL readiness endpoint");
            }
        });
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 200 OK"));

        fs::remove_dir(&object_root).expect("remove empty object root");
        let unavailable = http_readiness(address).await;
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(unavailable.contains("object storage unavailable"));
        fs::create_dir_all(&object_root).expect("restore object root");
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 200 OK"));

        store.pool().close().await;
        let unavailable = http_readiness(address).await;
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(unavailable.contains("database unavailable"));
        server.abort();
        let _ = server.await;
        drop(store);
        cleanup_postgres_fixture(fixture_pool, schema).await;
        remove_test_directory(&data_dir).await;
    }

    #[test]
    fn acme_contacts_are_normalized_for_account_registration() {
        assert_eq!(acme_contact("operator@example.com"), "mailto:operator@example.com");
        assert_eq!(acme_contact("  mailto:operator@example.com  "), "mailto:operator@example.com");
    }

    async fn http_readiness(address: std::net::SocketAddr) -> String {
        http_request(
            address,
            b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
    }

    async fn http_request(address: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream =
            tokio::net::TcpStream::connect(address).await.expect("connect to listener");
        stream.write_all(request).await.expect("send HTTP request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read HTTP response");
        String::from_utf8(response).expect("HTTP response is UTF-8")
    }

    #[tokio::test]
    async fn server_refuses_non_directory_before_storage_initialization() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-path-{}", uuid::Uuid::new_v4()));
        fs::write(&data_dir, "occupied").expect("create file where directory is needed");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        let result = prepare_roles(&config, &[Role::Worker]).await;
        #[cfg(windows)]
        assert!(matches!(result, Err(ServerError::PrivateMaterialAccess(_))));
        #[cfg(not(windows))]
        assert!(matches!(result, Err(ServerError::DataDirectory { .. })));
        assert_eq!(fs::read_to_string(&data_dir).expect("retained occupied path"), "occupied");
        fs::remove_file(data_dir).expect("test file is removable");
    }

    #[tokio::test]
    async fn prepare_roles_initializes_configured_object_storage() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-object-runtime-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        let prepared = prepare_roles(&config, &[Role::Worker]).await.expect("prepare worker");
        assert!(prepared.store.is_some());
        assert!(prepared.object_storage.is_some());
        assert!(data_dir.join("objects").is_dir());
        drop(prepared);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn only_api_issues_operator_setup_once_and_local_reissue_replaces_it() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-operator-runtime-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.server.public_host = "operator.example.com".into();
        for role in [Role::Edge, Role::Worker] {
            let prepared = prepare_roles(&config, &[role]).await.expect("prepare background role");
            assert!(prepared.setup_link.is_none());
            let store = prepared.store.as_ref().expect("SQLite store");
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_setup")
                .fetch_one(store.pool())
                .await
                .expect("singleton count");
            assert_eq!(count, 0);
            store.pool().close().await;
        }
        let prepared = prepare_roles(&config, &[Role::Api]).await.expect("prepare API");
        assert!(prepared.setup_link.is_some());
        assert!(!data_dir.join("setup-link.txt").exists());
        let store = prepared.store.as_ref().expect("SQLite store");
        let initial: (Vec<u8>, i64) =
            sqlx::query_as("SELECT token_digest, expires_at_s FROM operator_setup")
                .fetch_one(store.pool())
                .await
                .expect("initial singleton");
        store.pool().close().await;
        drop(prepared);
        let restarted = prepare_roles(&config, &[Role::Api]).await.expect("restart API");
        assert!(restarted.setup_link.is_none());
        let store = restarted.store.as_ref().expect("SQLite store");
        let retained: (Vec<u8>, i64) =
            sqlx::query_as("SELECT token_digest, expires_at_s FROM operator_setup")
                .fetch_one(store.pool())
                .await
                .expect("retained singleton");
        assert_eq!(initial, retained);
        store.pool().close().await;
        drop(restarted);
        config.server.public_port = 9443;
        for role in [Role::Api, Role::Worker, Role::Edge] {
            assert!(matches!(
                prepare_roles(&config, &[role]).await,
                Err(ServerError::OperatorSetup(OperatorSetupError::OriginMismatch))
            ));
        }
        let replacement = reissue_operator_setup(&config).await.expect("local reissue");
        assert!(
            replacement.expose_link().starts_with("https://operator.example.com:9443/setup#token=")
        );
        let store = SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("read back");
        let (digest, origin): (Vec<u8>, String) =
            sqlx::query_as("SELECT token_digest, trusted_origin FROM operator_setup")
                .fetch_one(store.pool())
                .await
                .expect("replacement setup");
        assert_ne!(digest, initial.0);
        assert_eq!(origin, "https://operator.example.com:9443");
        store.pool().close().await;
        for role in [Role::Api, Role::Worker, Role::Edge] {
            let prepared = prepare_roles(&config, &[role]).await.expect("reissued origin");
            assert!(prepared.setup_link.is_none());
            prepared.store.as_ref().expect("SQLite store").pool().close().await;
        }
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn pending_operator_setup_requires_dns_and_completed_setup_retains_origin() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-operator-origin-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.server.public_host = "127.0.0.1".into();
        assert!(matches!(
            prepare_roles(&config, &[Role::Api]).await,
            Err(ServerError::OperatorSetup(
                scoplen_store::operator_setup::OperatorSetupError::Configuration
            ))
        ));
        config.server.public_host = "operator.example.com".into();
        let prepared = prepare_roles(&config, &[Role::Api]).await.expect("valid DNS RP");
        let store = prepared.store.as_ref().expect("SQLite store");
        sqlx::query("UPDATE operator_setup SET completed_at_s = issued_at_s")
            .execute(store.pool())
            .await
            .expect("completed fixture singleton");
        store.pool().close().await;
        drop(prepared);
        config.server.public_host = "127.0.0.1".into();
        assert!(matches!(
            prepare_roles(&config, &[Role::Api]).await,
            Err(ServerError::OperatorSetup(OperatorSetupError::OriginMismatch))
        ));
        assert!(matches!(
            reissue_operator_setup(&config).await,
            Err(ServerError::OperatorSetup(
                scoplen_store::operator_setup::OperatorSetupError::Denied { consumed: false }
            ))
        ));
        config.server.public_host = "operator.example.com".into();
        let completed = prepare_roles(&config, &[Role::Api]).await.expect("retained DNS origin");
        assert!(completed.setup_link.is_none());
        completed.store.as_ref().expect("SQLite store").pool().close().await;
        drop(completed);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn sqlite_storage_roles_check_completed_origin_before_creating_material() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-origin-guard-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.server.public_host = "operator.example.com".into();
        prepare_data_directory(&config).expect("private fixture directory");
        let store =
            SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("fixture store");
        store
            .initialize_operator_setup("https://operator.example.com", false)
            .await
            .expect("initial setup")
            .expect("initial link");
        sqlx::query("UPDATE operator_setup SET completed_at_s = issued_at_s")
            .execute(store.pool())
            .await
            .expect("complete fixture setup");
        let setup_before: (Vec<u8>, String, Option<i64>) = sqlx::query_as(
            "SELECT token_digest, trusted_origin, completed_at_s FROM operator_setup",
        )
        .fetch_one(store.pool())
        .await
        .expect("fixture setup");
        let audits_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("fixture audit count");
        store.pool().close().await;

        config.server.public_host = "other.example.com".into();
        for role in [Role::Api, Role::Worker, Role::Edge] {
            match prepare_roles(&config, &[role]).await {
                Err(ServerError::OperatorSetup(OperatorSetupError::OriginMismatch)) => {}
                Err(error) => panic!("{role} returned {error} instead of an origin mismatch"),
                Ok(prepared) => {
                    prepared.store.as_ref().expect("SQLite store").pool().close().await;
                    panic!("{role} accepted a changed origin");
                }
            }
            assert!(!data_dir.join("deployment.key").exists());
            assert!(!data_dir.join("internal-ca.pem").exists());
            assert!(!data_dir.join("objects").exists());
        }
        assert!(matches!(
            reissue_operator_setup(&config).await,
            Err(ServerError::OperatorSetup(
                scoplen_store::operator_setup::OperatorSetupError::Denied { consumed: false }
            ))
        ));
        assert!(!data_dir.join("deployment.key").exists());
        let store =
            SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("read back fixture");
        let setup_after: (Vec<u8>, String, Option<i64>) = sqlx::query_as(
            "SELECT token_digest, trusted_origin, completed_at_s FROM operator_setup",
        )
        .fetch_one(store.pool())
        .await
        .expect("unchanged setup");
        let audits_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("unchanged audit count");
        assert_eq!(setup_before, setup_after);
        assert_eq!(audits_before, audits_after);
        store.pool().close().await;

        config.server.public_host = "operator.example.com".into();
        for role in [Role::Api, Role::Worker, Role::Edge] {
            let prepared = prepare_roles(&config, &[role]).await.expect("retained origin");
            prepared.store.as_ref().expect("SQLite store").pool().close().await;
        }
        remove_test_directory(&data_dir).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_storage_roles_check_completed_origin_before_creating_material() {
        let (database_url, fixture_pool, schema) = postgres_fixture().await;
        let store = PostgresStore::connect(database_url.as_str()).await.expect("fixture store");
        store
            .initialize_operator_setup("https://operator.example.com", false)
            .await
            .expect("initial setup")
            .expect("initial link");
        sqlx::query("UPDATE operator_setup SET completed_at_s = issued_at_s")
            .execute(store.pool())
            .await
            .expect("complete fixture setup");
        let setup_before: (Vec<u8>, String, Option<i64>) = sqlx::query_as(
            "SELECT token_digest, trusted_origin, completed_at_s FROM operator_setup",
        )
        .fetch_one(store.pool())
        .await
        .expect("fixture setup");
        let audits_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("fixture audit count");
        store.pool().close().await;

        let data_dir =
            std::env::temp_dir().join(format!("scoplen-postgres-origin-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.server.public_host = "other.example.com".into();
        config.storage.backend = "postgres".into();
        config.storage.database_url = Some(
            toml::Value::String(database_url.to_string())
                .try_into()
                .expect("PostgreSQL URL setting"),
        );
        for role in [Role::Api, Role::Worker, Role::Edge] {
            match prepare_roles(&config, &[role]).await {
                Err(ServerError::OperatorSetup(OperatorSetupError::OriginMismatch)) => {}
                Err(error) => panic!("{role} returned {error} instead of an origin mismatch"),
                Ok(prepared) => {
                    prepared
                        .postgres_store
                        .as_ref()
                        .expect("PostgreSQL store")
                        .pool()
                        .close()
                        .await;
                    panic!("{role} accepted a changed origin");
                }
            }
            assert!(!data_dir.join("deployment.key").exists());
            assert!(!data_dir.join("internal-ca.pem").exists());
            assert!(!data_dir.join("objects").exists());
        }
        assert!(matches!(
            reissue_operator_setup(&config).await,
            Err(ServerError::OperatorSetup(
                scoplen_store::operator_setup::OperatorSetupError::Denied { consumed: false }
            ))
        ));
        assert!(!data_dir.join("deployment.key").exists());
        let store = PostgresStore::connect(database_url.as_str()).await.expect("read back fixture");
        let setup_after: (Vec<u8>, String, Option<i64>) = sqlx::query_as(
            "SELECT token_digest, trusted_origin, completed_at_s FROM operator_setup",
        )
        .fetch_one(store.pool())
        .await
        .expect("unchanged setup");
        let audits_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("unchanged audit count");
        assert_eq!(setup_before, setup_after);
        assert_eq!(audits_before, audits_after);
        store.pool().close().await;

        config.server.public_host = "operator.example.com".into();
        for role in [Role::Api, Role::Worker, Role::Edge] {
            let prepared = prepare_roles(&config, &[role]).await.expect("retained origin");
            prepared.postgres_store.as_ref().expect("PostgreSQL store").pool().close().await;
        }
        cleanup_postgres_fixture(fixture_pool, schema).await;
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn prepare_roles_passes_sync_cardinality_limits_to_sqlite() {
        let data_dir = std::env::temp_dir()
            .join(format!("scoplen-sync-limits-runtime-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.sync.max_objects_per_vault = 100_001;
        config.sync.max_shared_vaults_per_account = 1_001;
        config.sync.max_members_per_shared_vault = 2;
        let prepared = prepare_roles(&config, &[Role::Api]).await.expect("prepare api role");
        assert_eq!(
            prepared.store.as_ref().expect("sqlite store").sync_cardinality_limits(),
            config.sync.cardinality_limits()
        );
        drop(prepared);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn worker_heartbeat_requeues_expired_jobs() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-worker-{}", uuid::Uuid::new_v4()));
        let store = SqliteStore::open(&data_dir.join("scoplen.sqlite"))
            .await
            .expect("open worker database");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis()
            .try_into()
            .expect("current timestamp fits SQLite integer");
        let job_id = [42_u8; 16];
        store
            .enqueue_job(job_id, "sync-retention", &[], now - 1_000)
            .await
            .expect("enqueue expired worker job");
        store
            .claim_job("worker-a", now - 1_000, 1)
            .await
            .expect("claim worker job")
            .expect("job is available");

        assert_eq!(worker_heartbeat(&store).await.expect("heartbeat succeeds"), 1);
        let reclaimed = store
            .claim_job("worker-b", now, 1_000)
            .await
            .expect("claim requeued job")
            .expect("requeued job is available");
        assert_eq!(reclaimed.id, job_id);
        assert_eq!(reclaimed.lease_owner.as_deref(), Some("worker-b"));

        store.pool().close().await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn worker_retention_pass_schedules_and_purges_old_tombstones() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-retention-{}", uuid::Uuid::new_v4()));
        let store = SqliteStore::open(&data_dir.join("scoplen.sqlite"))
            .await
            .expect("open retention database");
        let vault = [61; 16];
        store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");
        store
            .write_sync_batch(
                vault,
                &[ObjectWrite {
                    object_id: [62; 16],
                    base_sequence: None,
                    envelope: vec![1, 2, 3],
                    key_epoch: 1,
                    tombstone: false,
                    signer_device_id: Some([63; 16]),
                }],
            )
            .await
            .expect("write object");
        store
            .write_sync_batch(
                vault,
                &[ObjectWrite {
                    object_id: [62; 16],
                    base_sequence: Some(1),
                    envelope: vec![4, 5, 6],
                    key_epoch: 1,
                    tombstone: true,
                    signer_device_id: Some([63; 16]),
                }],
            )
            .await
            .expect("write tombstone");
        let now =
            worker_now_ms().expect("clock") + TOMBSTONE_PURGE_AFTER_DAYS * 24 * 60 * 60 * 1_000 + 1;
        let (scheduled, processed) =
            worker_retention_pass_at(&store, now).await.expect("retention pass");
        assert_eq!((scheduled, processed), (1, 1));
        assert_eq!(store.sync_snapshot(vault, 0, 10).await.expect("snapshot").objects.len(), 0);
        assert!(
            store
                .claim_job_kind(
                    RETENTION_JOB_KIND,
                    RETENTION_WORKER_OWNER,
                    worker_now_ms().expect("clock"),
                    RETENTION_JOB_LEASE_MS
                )
                .await
                .expect("queue is empty")
                .is_none()
        );

        store.pool().close().await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn worker_retention_pass_retries_malformed_payload_without_blocking_valid_jobs() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-retention-retry-{}", uuid::Uuid::new_v4()));
        let store = SqliteStore::open(&data_dir.join("scoplen.sqlite"))
            .await
            .expect("open retention database");
        let vault = [63; 16];
        store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");
        let now = worker_now_ms().expect("clock");
        let malformed = [64; 16];
        store
            .enqueue_job(malformed, RETENTION_JOB_KIND, &[1], now)
            .await
            .expect("enqueue malformed retention job");

        let (_, processed) = worker_retention_pass(&store).await.expect("retention retry pass");
        assert_eq!(processed, 2);
        let failed = store.get_job(malformed).await.expect("read failed retention job");
        assert!(
            failed.last_error.as_deref().is_some_and(|error| error.contains("retention payload"))
        );
        assert!(failed.available_at_ms >= now + RETENTION_RETRY_MS);
        assert!(failed.lease_owner.is_none());

        store.pool().close().await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn worker_audit_checkpoint_pass_is_hourly_and_idempotent() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-audit-worker-{}", uuid::Uuid::new_v4()));
        let store =
            SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("open audit database");
        let organization = [71_u8; 16];
        sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, ?)")
            .bind(organization.as_slice())
            .bind("audit worker")
            .bind(1_i64)
            .execute(store.pool())
            .await
            .expect("create organization");
        store.append_audit_event(organization, b"first", 1).await.expect("append first event");
        let signer_path = data_dir.join("audit-signing.key");
        fs::write(
            &signer_path,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n",
        )
        .expect("write audit key");
        let signer = LocalAuditSigner::load(&signer_path).expect("load audit signer");

        let first_at = 3_600_000_i64;
        assert_eq!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at)
                .await
                .expect("write first checkpoint"),
            1
        );
        assert_eq!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at + 1)
                .await
                .expect("repeat checkpoint pass"),
            0
        );
        store
            .append_audit_event(organization, b"second", first_at + 2)
            .await
            .expect("append second event");
        assert_eq!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at + 3)
                .await
                .expect("respect hourly cadence"),
            0
        );
        assert_eq!(
            worker_audit_checkpoint_pass_at(
                &store,
                &signer,
                first_at + AUDIT_CHECKPOINT_INTERVAL_MS,
            )
            .await
            .expect("write advanced checkpoint"),
            1
        );
        let checkpoint = store
            .latest_audit_checkpoint(organization)
            .await
            .expect("read checkpoint")
            .expect("checkpoint exists");
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&signer.verification_key())
            .expect("verification key");
        let payload = checkpoint_payload(
            &organization,
            checkpoint.sequence,
            &checkpoint.head_hash,
            u64::try_from(checkpoint.signed_at_ms).expect("test checkpoint timestamp is positive"),
        )
        .expect("checkpoint payload");
        verifying
            .verify_strict(&payload, &ed25519_dalek::Signature::from_bytes(&checkpoint.signature))
            .expect("checkpoint signature verifies");

        store.pool().close().await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    #[tokio::test]
    async fn worker_deployment_audit_checkpoint_is_hourly_and_domain_separated() {
        let data_dir = std::env::temp_dir()
            .join(format!("scoplen-deployment-audit-worker-{}", uuid::Uuid::new_v4()));
        let store =
            SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("open audit database");
        let first = store.append_deployment_audit_event(b"first", 1).await.expect("first event");
        let signer_path = data_dir.join("audit-signing.key");
        fs::write(
            &signer_path,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n",
        )
        .expect("write audit key");
        let signer = LocalAuditSigner::load(&signer_path).expect("load audit signer");
        let first_at = 3_600_000_i64;
        assert_eq!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at).await.expect("first pass"),
            1
        );
        assert_eq!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at + 1)
                .await
                .expect("repeat pass"),
            0
        );
        let checkpoint = store
            .latest_deployment_audit_checkpoint()
            .await
            .expect("latest")
            .expect("checkpoint exists");
        assert_eq!(checkpoint.sequence, first.sequence);
        assert_eq!(checkpoint.head_hash, first.event_hash);
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&signer.verification_key())
            .expect("verification key");
        let payload = deployment_checkpoint_payload(
            checkpoint.sequence,
            &checkpoint.head_hash,
            u64::try_from(checkpoint.signed_at_ms).expect("positive time"),
        )
        .expect("deployment payload");
        let signature = ed25519_dalek::Signature::from_bytes(&checkpoint.signature);
        verifying.verify_strict(&payload, &signature).expect("deployment signature");
        let organization_payload = checkpoint_payload(
            &[0; 16],
            checkpoint.sequence,
            &checkpoint.head_hash,
            u64::try_from(checkpoint.signed_at_ms).expect("positive time"),
        )
        .expect("organization payload");
        assert!(verifying.verify_strict(&organization_payload, &signature).is_err());

        store.append_deployment_audit_event(b"second", first_at + 2).await.expect("second");
        assert_eq!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at + 3)
                .await
                .expect("before hour"),
            0
        );
        assert_eq!(
            worker_audit_checkpoint_pass_at(
                &store,
                &signer,
                first_at + AUDIT_CHECKPOINT_INTERVAL_MS
            )
            .await
            .expect("after hour"),
            1
        );
        assert_eq!(
            store.latest_deployment_audit_checkpoint().await.expect("latest").unwrap().sequence,
            2
        );
        store.pool().close().await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_worker_signs_advanced_deployment_prefix() {
        let (database_url, fixture_pool, schema) = postgres_fixture().await;
        let store =
            PostgresStore::connect(database_url.as_str()).await.expect("open PostgreSQL store");
        let previous = store.latest_deployment_audit_checkpoint().await.expect("latest checkpoint");
        let first_at = previous.map_or(3_600_000, |checkpoint| {
            checkpoint.signed_at_ms.saturating_add(AUDIT_CHECKPOINT_INTERVAL_MS + 1)
        });
        let first = store
            .append_deployment_audit_event(b"postgres worker first", first_at - 2)
            .await
            .expect("first event");
        let key_dir = std::env::temp_dir()
            .join(format!("scoplen-deployment-audit-pg-worker-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&key_dir).expect("create signer directory");
        let signer_path = key_dir.join("audit-signing.key");
        fs::write(
            &signer_path,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n",
        )
        .expect("write audit key");
        let signer = LocalAuditSigner::load(&signer_path).expect("load audit signer");
        assert!(
            worker_audit_checkpoint_pass_at(&store, &signer, first_at).await.expect("first pass")
                >= 1
        );
        let checkpoint = store
            .latest_deployment_audit_checkpoint()
            .await
            .expect("latest checkpoint")
            .expect("checkpoint exists");
        assert_eq!(checkpoint.sequence, first.sequence);
        assert_eq!(checkpoint.head_hash, first.event_hash);
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&signer.verification_key())
            .expect("verification key");
        let payload = deployment_checkpoint_payload(
            checkpoint.sequence,
            &checkpoint.head_hash,
            u64::try_from(checkpoint.signed_at_ms).expect("positive time"),
        )
        .expect("deployment payload");
        verifying
            .verify_strict(&payload, &ed25519_dalek::Signature::from_bytes(&checkpoint.signature))
            .expect("signature verifies");
        store
            .append_deployment_audit_event(b"postgres worker second", first_at + 1)
            .await
            .expect("second event");
        worker_audit_checkpoint_pass_at(&store, &signer, first_at + 2).await.expect("before hour");
        assert_eq!(
            store.latest_deployment_audit_checkpoint().await.expect("latest").unwrap().sequence,
            first.sequence
        );
        worker_audit_checkpoint_pass_at(&store, &signer, first_at + AUDIT_CHECKPOINT_INTERVAL_MS)
            .await
            .expect("after hour");
        assert_eq!(
            store.latest_deployment_audit_checkpoint().await.expect("latest").unwrap().sequence,
            first.sequence + 1
        );
        store.pool().close().await;
        drop(store);
        cleanup_postgres_fixture(fixture_pool, schema).await;
        remove_test_directory(&key_dir).await;
    }

    #[tokio::test]
    async fn standalone_ca_and_gateway_do_not_open_sqlite_or_generate_setup_material() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-role-{}", uuid::Uuid::new_v4()));
        fs::write(&data_dir, "occupied").expect("create file where a database cannot be opened");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.storage.backend = "postgres".into();

        for roles in [vec![Role::Ca], vec![Role::Gateway], vec![Role::Ca, Role::Gateway]] {
            let prepared = prepare_roles(&config, &roles).await.expect("roles need no database");
            assert!(prepared.store.is_none());
            assert!(prepared.setup_link.is_none());
        }
        assert_eq!(fs::read(&data_dir).expect("original file remains"), b"occupied");
        fs::remove_file(data_dir).expect("test file is removable");
    }

    #[tokio::test]
    async fn api_and_edge_require_the_configured_database() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-role-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        prepare_data_directory(&config).expect("private data directory");
        fs::write(data_dir.join("scoplen.sqlite"), "invalid database")
            .expect("invalid database fixture");

        for role in [Role::Api, Role::Edge] {
            let result = prepare_roles(&config, &[role]).await;
            assert!(matches!(result, Err(ServerError::Storage(_))), "{role} must open SQLite");
        }
        let result = run_roles(config, vec![Role::Api], None, None, None, None, None).await;
        assert!(matches!(result, Err(ServerError::MissingStore)));
        fs::remove_dir_all(data_dir).expect("owned test directory is removable");
    }
}
