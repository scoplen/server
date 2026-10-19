// SPDX-License-Identifier: AGPL-3.0-only
//! First-run material and role supervision.

use std::{
    future::Future,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Router, http::StatusCode, routing::get};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use rustls_acme::{AcmeConfig, caches::DirCache};
use scoplen_audit::checkpoint_payload;
use scoplen_store::kms::{AuditCheckpointSigner, LocalAuditSigner, LocalKeyFile};
use scoplen_store::sync::MAX_PAGE_SIZE;
use scoplen_store::{
    AuditChainHead, AuditCheckpoint, AuditStoreError, JobQueueError, ObjectStorage, PostgresStore,
    SqliteStore, sync::SyncStoreError,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::sleep};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};
use tracing::{error, info, warn};

use crate::{Config, Role, ServerError, TlsMode};

/// Result of first-run material generation.
#[derive(Debug, Default)]
pub struct BootstrapResult {
    /// One-time setup link when this invocation created it.
    pub setup_link: Option<String>,
}

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
    pub setup_link: Option<String>,
}

#[derive(Clone)]
enum ListenerDatabase {
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

/// Create the data directory, deployment key, internal CA, and one-time setup link as needed.
///
/// # Errors
///
/// Returns an error when the data directory, generated key material, or setup-link file cannot
/// be created.
pub fn bootstrap(config: &Config) -> Result<BootstrapResult, ServerError> {
    std::fs::create_dir_all(&config.server.data_dir).map_err(|source| {
        ServerError::DataDirectory { path: config.server.data_dir.clone(), source }
    })?;

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
    if !ca_certificate.exists() || !ca_key.exists() {
        let mut params = CertificateParams::new(vec![config.server.public_host.clone()])
            .map_err(|error| ServerError::Tls(error.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate().map_err(|error| ServerError::Tls(error.to_string()))?;
        let certificate =
            params.self_signed(&key_pair).map_err(|error| ServerError::Tls(error.to_string()))?;
        write_private(&ca_certificate, &certificate.pem())?;
        write_private(&ca_key, &key_pair.serialize_pem())?;
    }

    let setup_file = config.server.data_dir.join("setup-link.txt");
    if setup_file.exists() {
        return Ok(BootstrapResult::default());
    }
    let token = uuid::Uuid::new_v4();
    let link = format!("https://{}/setup/{}", config.server.public_host, token);
    write_private(&setup_file, &link)?;
    Ok(BootstrapResult { setup_link: Some(link) })
}

fn write_private(path: &Path, contents: &str) -> Result<(), ServerError> {
    std::fs::write(path, format!("{contents}\n"))
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
                )
                .await?,
            ),
            None,
        )
    };
    let object_config = config.storage.object_storage_config(&config.server.data_dir)?;
    let object_storage = ObjectStorage::from_config(&object_config)?;
    let bootstrap = bootstrap(config)?;
    let key_management =
        Some(LocalKeyFile::load(config.storage.kms_key_file(&config.server.data_dir)?)?);
    let audit_signer =
        Some(LocalAuditSigner::load(config.storage.kms_audit_key_file(&config.server.data_dir)?)?);
    Ok(PreparedRoles {
        store,
        postgres_store,
        object_storage: Some(object_storage),
        key_management,
        audit_signer,
        setup_link: bootstrap.setup_link,
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
    let _key_management = key_management;
    let store = store.map(Arc::new);
    let postgres_store = postgres_store.map(Arc::new);
    let object_storage = object_storage.map(Arc::new);
    let postgres = uses_postgres(&config);
    let mut tasks = Vec::new();
    if roles.contains(&Role::Api) || roles.contains(&Role::Edge) {
        let database = if postgres {
            ListenerDatabase::Postgres(
                postgres_store.as_ref().ok_or(ServerError::MissingStore)?.clone(),
            )
        } else {
            ListenerDatabase::Sqlite(store.as_ref().ok_or(ServerError::MissingStore)?.clone())
        };
        let object_storage = object_storage.as_ref().ok_or(ServerError::MissingStore)?.clone();
        tasks.push(tokio::spawn(run_public_listener(
            config.clone(),
            roles.clone(),
            database,
            object_storage,
        )));
    }
    if roles.contains(&Role::Worker) {
        let signer = audit_signer.as_ref().ok_or(ServerError::MissingKeyManagement)?;
        if postgres {
            let store = postgres_store.as_ref().ok_or(ServerError::MissingStore)?.clone();
            tasks.push(tokio::spawn(run_worker_role(store, Arc::new(signer.clone()))));
        } else {
            let store = store.as_ref().ok_or(ServerError::MissingStore)?.clone();
            tasks.push(tokio::spawn(run_worker_role(store, Arc::new(signer.clone()))));
        }
    }
    if roles.contains(&Role::Ca) {
        tasks.push(tokio::spawn(run_periodic_role("ca")));
    }
    if roles.contains(&Role::Gateway) {
        tasks.push(tokio::spawn(run_periodic_role("gateway")));
    }
    info!(roles = ?roles, "server roles started");
    tokio::signal::ctrl_c().await.map_err(ServerError::Runtime)?;
    for task in tasks {
        task.abort();
    }
    info!("server shutdown requested");
    Ok(())
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
    Ok(written)
}

fn api_router(database: ListenerDatabase, object_storage: Arc<ObjectStorage>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let database = database.clone();
                let object_storage = object_storage.clone();
                async move {
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
        }))
        .route("/", get(|| async { "Scoplen server" }))
}

async fn run_public_listener(
    config: Config,
    roles: Vec<Role>,
    database: ListenerDatabase,
    object_storage: Arc<ObjectStorage>,
) -> Result<(), ServerError> {
    let address = config.listen_address();
    let listener = TcpListener::bind(&address).await?;
    info!(%address, tls_mode = ?config.tls.mode, "public listener started");
    match config.tls.mode {
        TlsMode::Plain => {
            if roles.contains(&Role::Edge) {
                warn!(
                    "edge role is configured behind plain HTTP; gateway ALPN requires direct TLS"
                );
            }
            axum::serve(listener, api_router(database, object_storage))
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
        }
        TlsMode::Files => {
            let acceptor = TlsAcceptor::from(Arc::new(tls_config(&config)?));
            loop {
                let (stream, peer) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let router = api_router(database.clone(), object_storage.clone());
                tokio::spawn(async move {
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
            run_acme_listener(config, listener, database, object_storage).await?;
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
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| ServerError::Tls(error.to_string()))?;
    server.alpn_protocols = application_alpn_protocols();
    Ok(server)
}

async fn run_acme_listener(
    config: Config,
    listener: TcpListener,
    database: ListenerDatabase,
    object_storage: Arc<ObjectStorage>,
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

    while let Some(result) = tls_incoming.next().await {
        let tls = result.map_err(ServerError::Runtime)?;
        let is_gateway = tls
            .get_ref()
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|protocol| protocol == b"spl-gw/1");
        let router = api_router(database.clone(), object_storage.clone());
        tokio::spawn(async move {
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

async fn serve_tls_io<S>(mut stream: S, router: Router, is_gateway: bool) -> Result<(), ServerError>
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
    Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|error| ServerError::Task(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use scoplen_store::RelationalStore;
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

    #[test]
    fn bootstrap_creates_private_material_once() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-server-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();

        let first = bootstrap(&config).expect("first bootstrap succeeds");
        assert!(first.setup_link.is_some());
        for name in [
            "deployment.key",
            "audit-signing.key",
            "internal-ca.pem",
            "internal-ca-key.pem",
            "setup-link.txt",
        ] {
            let path = data_dir.join(name);
            assert!(path.is_file(), "expected generated material at {}", path.display());
        }

        let second = bootstrap(&config).expect("second bootstrap is idempotent");
        assert!(second.setup_link.is_none());
        fs::remove_dir_all(data_dir).expect("test material is removable");
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
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind isolated HTTP listener");
        let address = listener.local_addr().expect("read listener address");
        let server_store = store.clone();
        let server_object_storage = object_storage.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                api_router(
                    ListenerDatabase::Sqlite(Arc::new(server_store)),
                    Arc::new(server_object_storage),
                ),
            )
            .await
            .expect("serve readiness endpoint");
        });
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 200 OK"));

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
        let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
            .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-postgres-ready-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        config.storage.backend = " PoStGrEs ".into();
        config.sync.max_objects_per_vault = 2;
        config.storage.database_url =
            Some(toml::Value::String(database_url).try_into().expect("PostgreSQL URL setting"));
        let prepared = prepare_roles(&config, &[Role::Api, Role::Edge])
            .await
            .expect("prepare PostgreSQL API and edge roles");
        assert!(prepared.store.is_none(), "PostgreSQL roles must not open SQLite");
        let store = prepared.postgres_store.expect("PostgreSQL pool");
        assert_eq!(store.sync_cardinality_limits().max_objects_per_vault, 2);
        let object_storage = prepared.object_storage.expect("object storage");
        let object_root = data_dir.join("objects");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind isolated HTTP listener");
        let address = listener.local_addr().expect("read listener address");
        let server = tokio::spawn({
            let store = store.clone();
            async move {
                axum::serve(
                    listener,
                    api_router(
                        ListenerDatabase::Postgres(Arc::new(store)),
                        Arc::new(object_storage),
                    ),
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
        remove_test_directory(&data_dir).await;
    }

    #[test]
    fn acme_contacts_are_normalized_for_account_registration() {
        assert_eq!(acme_contact("operator@example.com"), "mailto:operator@example.com");
        assert_eq!(acme_contact("  mailto:operator@example.com  "), "mailto:operator@example.com");
    }

    async fn http_readiness(address: std::net::SocketAddr) -> String {
        let mut stream =
            tokio::net::TcpStream::connect(address).await.expect("connect to listener");
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("send HTTP request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read HTTP response");
        String::from_utf8(response).expect("HTTP response is UTF-8")
    }

    #[tokio::test]
    async fn server_refuses_unwritable_database_path() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-path-{}", uuid::Uuid::new_v4()));
        fs::write(&data_dir, "occupied").expect("create file where directory is needed");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        let result = prepare_roles(&config, &[Role::Worker]).await;
        assert!(matches!(result, Err(ServerError::Storage(_))));
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
        fs::write(&data_dir, "occupied").expect("create file where a database cannot be opened");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();

        for role in [Role::Api, Role::Edge] {
            let result = prepare_roles(&config, &[role]).await;
            assert!(matches!(result, Err(ServerError::Storage(_))), "{role} must open SQLite");
        }
        let result = run_roles(config, vec![Role::Api], None, None, None, None, None).await;
        assert!(matches!(result, Err(ServerError::MissingStore)));
        fs::remove_file(data_dir).expect("test file is removable");
    }
}
