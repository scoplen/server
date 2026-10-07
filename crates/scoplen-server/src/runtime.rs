// SPDX-License-Identifier: AGPL-3.0-only
//! First-run material and role supervision.

use std::{
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
use scoplen_store::kms::LocalKeyFile;
use scoplen_store::sync::{MAX_PAGE_SIZE, SyncStoreError};
use scoplen_store::{ObjectStorage, SqliteStore};
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
    /// Object storage backend for roles that need relational storage.
    pub object_storage: Option<ObjectStorage>,
    /// Initialized key-management backend for database-backed roles.
    pub key_management: Option<LocalKeyFile>,
    /// First-run setup link only for roles that initialize the deployment.
    pub setup_link: Option<String>,
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
            object_storage: None,
            key_management: None,
            setup_link: None,
        });
    }
    let store = SqliteStore::open(&config.server.data_dir.join("scoplen.sqlite")).await?;
    let object_config = config.storage.object_storage_config(&config.server.data_dir)?;
    let object_storage = ObjectStorage::from_config(&object_config)?;
    let bootstrap = bootstrap(config)?;
    let key_management =
        Some(LocalKeyFile::load(config.storage.kms_key_file(&config.server.data_dir)?)?);
    Ok(PreparedRoles {
        store: Some(store),
        object_storage: Some(object_storage),
        key_management,
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
    object_storage: Option<ObjectStorage>,
    key_management: Option<LocalKeyFile>,
) -> Result<(), ServerError> {
    if roles.iter().any(|role| role.requires_store())
        && (store.is_none() || object_storage.is_none())
    {
        return Err(ServerError::MissingStore);
    }
    if roles.iter().any(|role| role.requires_store()) && key_management.is_none() {
        return Err(ServerError::MissingKeyManagement);
    }
    let _key_management = key_management;
    let store = store.map(Arc::new);
    let object_storage = object_storage.map(Arc::new);
    let mut tasks = Vec::new();
    if roles.contains(&Role::Api) || roles.contains(&Role::Edge) {
        let store = store.as_ref().ok_or(ServerError::MissingStore)?.clone();
        let object_storage = object_storage.as_ref().ok_or(ServerError::MissingStore)?.clone();
        tasks.push(tokio::spawn(run_public_listener(
            config.clone(),
            roles.clone(),
            store,
            object_storage,
        )));
    }
    if roles.contains(&Role::Worker) {
        let store = store.as_ref().ok_or(ServerError::MissingStore)?.clone();
        tasks.push(tokio::spawn(run_worker_role(store)));
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

async fn run_worker_role(store: Arc<SqliteStore>) -> Result<(), ServerError> {
    let mut interval = tokio::time::interval(WORKER_HEARTBEAT_INTERVAL);
    loop {
        interval.tick().await;
        match worker_heartbeat(&store).await {
            Ok(requeued) => {
                info!(role = "worker", requeued_expired_jobs = requeued, "worker heartbeat");
            }
            Err(error) => error!(%error, role = "worker", "worker heartbeat failed"),
        }
        match worker_retention_pass(&store).await {
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
    }
}

async fn worker_heartbeat(store: &SqliteStore) -> Result<u64, ServerError> {
    let now = worker_now_ms()?;
    store.requeue_expired_jobs(now).await.map_err(|error| ServerError::Task(error.to_string()))
}

fn worker_now_ms() -> Result<i64, ServerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ServerError::Task(format!("worker clock is before Unix epoch: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| ServerError::Task("worker clock exceeds SQLite timestamp range".into()))
}

async fn worker_retention_pass(store: &SqliteStore) -> Result<(u64, u64), ServerError> {
    let now = worker_now_ms()?;
    worker_retention_pass_at(store, now).await
}

async fn worker_retention_pass_at(
    store: &SqliteStore,
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

fn api_router(store: Arc<SqliteStore>, object_storage: Arc<ObjectStorage>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let store = store.clone();
                let object_storage = object_storage.clone();
                async move {
                    match (store.ping().await, object_storage.check().await) {
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
    store: Arc<SqliteStore>,
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
            axum::serve(listener, api_router(store, object_storage))
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
        }
        TlsMode::Files => {
            let acceptor = TlsAcceptor::from(Arc::new(tls_config(&config)?));
            loop {
                let (stream, peer) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let router = api_router(store.clone(), object_storage.clone());
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
            run_acme_listener(config, listener, store, object_storage).await?;
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
    store: Arc<SqliteStore>,
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
        let router = api_router(store.clone(), object_storage.clone());
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
        for name in ["deployment.key", "internal-ca.pem", "internal-ca-key.pem", "setup-link.txt"] {
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
                api_router(Arc::new(server_store), Arc::new(server_object_storage)),
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
    async fn api_worker_and_edge_still_require_sqlite() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-role-{}", uuid::Uuid::new_v4()));
        fs::write(&data_dir, "occupied").expect("create file where a database cannot be opened");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();

        for role in [Role::Api, Role::Worker, Role::Edge] {
            let result = prepare_roles(&config, &[role]).await;
            assert!(matches!(result, Err(ServerError::Storage(_))), "{role} must open SQLite");
        }
        let result = run_roles(config, vec![Role::Api], None, None, None).await;
        assert!(matches!(result, Err(ServerError::MissingStore)));
        fs::remove_file(data_dir).expect("test file is removable");
    }
}
