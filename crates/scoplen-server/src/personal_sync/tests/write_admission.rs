// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const SCALE: u128 = 1_000_000_000;

macro_rules! with_pool {
    ($database:expr, $pool:ident, $body:expr) => {
        match $database {
            ListenerDatabase::Sqlite(store) => {
                let $pool = store.pool();
                $body
            }
            ListenerDatabase::Postgres(store) => {
                let $pool = store.pool();
                $body
            }
        }
    };
}

struct Listener {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Listener {
    async fn start(
        database: ListenerDatabase,
        directory: &std::path::Path,
        limits: WriteRateLimits,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let objects = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: directory.join("objects"),
        })
        .expect("objects");
        let app = api_router_with_limits(
            database,
            Arc::new(objects),
            kms(directory),
            ORIGIN.into(),
            true,
            limits,
            WriteBodyLimits::new(266_240, 1, 4_194_304).expect("one-object limit"),
            ReadBodyLimits::default(),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve real API");
        });
        Self { address, task }
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn request(listener: &Listener, method: &str, path: &str, body: &[u8], token: &str) -> Reply {
    let authorization = format!("DPoP {token}");
    let dpop = proof(method, path.split_once('?').map_or(path, |(path, _)| path), token);
    http(
        listener.address,
        method,
        path,
        body,
        &[("Content-Type", "application/cbor"), ("Authorization", &authorization), ("DPoP", &dpop)],
    )
    .await
}

fn denied(reply: &Reply, status: u16, code: &str) {
    problem(reply, status, code);
    let problem = ProblemDetails::from_cbor(&reply.body).expect("problem");
    assert!(problem.retryable);
    if status == 429 {
        let retry = reply
            .headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("retry-after").then_some(value.trim())
            })
            .expect("Retry-After")
            .parse::<u128>()
            .expect("unsigned delay");
        assert!(retry >= 1);
    }
}

async fn exhausted_without_body(listener: &Listener, path: &str, token: &str) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(listener.address).await.expect("connect");
    let dpop = proof("POST", path, token);
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Type: application/cbor\r\nAuthorization: DPoP {token}\r\nDPoP: {dpop}\r\nContent-Length: 1000000\r\n\r\n"
    );
    stream.write_all(headers.as_bytes()).await.expect("headers without body");
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("exhaustion must not collect the body")
        .expect("response");
    parse_reply(&bytes)
}

fn future() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos()
        + 300 * SCALE
}

async fn seed(database: &ListenerDatabase) -> (Uuid, Uuid, Uuid) {
    match database {
        ListenerDatabase::Sqlite(store) => seed_sqlite(store).await,
        ListenerDatabase::Postgres(store) => {
            #[cfg(feature = "postgres-integration")]
            {
                seed_postgres(store).await
            }
            #[cfg(not(feature = "postgres-integration"))]
            {
                let _ = store;
                unreachable!("PostgreSQL integration disabled")
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn exercise(
    mut first: ListenerDatabase,
    second: ListenerDatabase,
    directory: &std::path::Path,
    postgres_url: Option<&str>,
) {
    let (_, device, vault) = seed(&first).await;
    let (_, other_device, other_vault) = seed(&first).await;
    let origin = future();
    with_pool!(&first, pool, {
        sqlx::query("UPDATE sync_write_admission_clock SET retired_through_ns=$1")
            .bind(origin.to_be_bytes().as_slice())
            .execute(pool)
            .await
            .expect("pin refill origin");
    });
    let limits = WriteRateLimits::new(1, 5).expect("rate");
    let a = Listener::start(first.clone(), directory, limits).await;
    let b = Listener::start(second.clone(), directory, limits).await;
    let token = issue_token(a.address, device).await;
    let other_token = issue_token(b.address, other_device).await;
    let path = format!("/sync/v1/vaults/{vault}/objects");
    let before: i64 = with_pool!(
        &first,
        pool,
        sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(pool)
            .await
            .expect("audit count")
    );
    problem(
        &http(a.address, "POST", &path, &[0xff], &[("Content-Type", "application/cbor")]).await,
        401,
        "auth.authentication_required",
    );
    let count: i64 = with_pool!(
        &first,
        pool,
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_write_admission")
            .fetch_one(pool)
            .await
            .expect("bucket count")
    );
    assert_eq!(count, 0, "unauthenticated attempts are not charged");
    let oversized = SyncWriteBatch {
        writes: vec![
            signed_write(vault, device, Uuid::now_v7()),
            signed_write(vault, device, Uuid::now_v7()),
        ],
    }
    .to_cbor()
    .expect("two-object batch");
    let (malformed, oversized) = tokio::join!(
        request(&a, "POST", &path, &[0xff], &token),
        request(&b, "POST", &path, &oversized, &token)
    );
    problem(&malformed, 400, "sync.invalid_request");
    problem(&oversized, 413, "sync.invalid_request");
    let sequence: i64 = with_pool!(
        &first,
        pool,
        sqlx::query_scalar("SELECT current_seq FROM sync_vaults WHERE vault_id=$1")
            .bind(vault.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .expect("sequence")
    );
    assert_eq!(sequence, 0);
    let body = SyncWriteBatch { writes: vec![signed_write(vault, device, Uuid::now_v7())] }
        .to_cbor()
        .expect("valid signed write");
    let success = request(&b, "POST", &path, &body, &token).await;
    assert_eq!(success.status, 200);
    assert_eq!(
        SyncWriteBatchResponse::from_cbor(&success.body).expect("assignment").assignments[0].seq,
        1
    );
    problem(&request(&a, "POST", &path, &body, &token).await, 409, "sync.conflict");
    let unauthorized_signer =
        SyncWriteBatch { writes: vec![signed_write(vault, other_device, Uuid::now_v7())] }
            .to_cbor()
            .expect("other-account signer");
    problem(&request(&b, "POST", &path, &unauthorized_signer, &token).await, 403, "policy.denied");
    denied(&exhausted_without_body(&a, &path, &token).await, 429, "sync.rate_limited");
    let stored: Vec<u8> = with_pool!(
        &first,
        pool,
        sqlx::query_scalar("SELECT tokens FROM sync_write_admission WHERE device_id=$1")
            .bind(device.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .expect("balance")
    );
    assert_eq!(stored, vec![0; 16], "all five outcomes retain their charge across instances");
    for path in [
        format!("/sync/v1/vaults/{vault}/changes?after=0&limit=10"),
        format!("/sync/v1/vaults/{vault}/keys"),
        "/sync/v1/keys".into(),
    ] {
        assert_eq!(
            request(&a, "GET", &path, &[], &token).await.status,
            200,
            "read independent of write debt"
        );
    }
    let ack_path = format!("/sync/v1/vaults/{vault}/ack");
    let ack = SyncAckRequest { cursor: 1 }.to_cbor().expect("ACK");
    assert_eq!(
        request(&b, "POST", &ack_path, &ack, &token).await.status,
        200,
        "ACK independent of write debt"
    );
    let other_path = format!("/sync/v1/vaults/{other_vault}/objects");
    problem(
        &request(&a, "POST", &other_path, &[0xff], &other_token).await,
        400,
        "sync.invalid_request",
    );
    let alternate = Listener::start(
        second.clone(),
        directory,
        WriteRateLimits::new(2, 4).expect("alternate policy"),
    )
    .await;
    denied(
        &request(&alternate, "POST", &path, &body, &token).await,
        503,
        "sync.storage_unavailable",
    );
    alternate.stop().await;
    a.stop().await;
    with_pool!(&first, pool, pool.close().await);
    first = match first {
        ListenerDatabase::Sqlite(_) => ListenerDatabase::Sqlite(Arc::new(
            SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("reopened pool"),
        )),
        ListenerDatabase::Postgres(_) => ListenerDatabase::Postgres(Arc::new(
            scoplen_store::PostgresStore::connect(postgres_url.expect("PostgreSQL URL"))
                .await
                .expect("reopened pool"),
        )),
    };
    let restarted = Listener::start(first.clone(), directory, limits).await;
    denied(&request(&restarted, "POST", &path, &body, &token).await, 429, "sync.rate_limited");
    // Even a missing clock row fails before the valid business write is dispatched.
    with_pool!(&first, pool, {
        sqlx::query("DELETE FROM sync_write_admission_clock")
            .execute(pool)
            .await
            .expect("missing watermark fixture");
    });
    denied(
        &exhausted_without_body(&restarted, &path, &token).await,
        503,
        "sync.storage_unavailable",
    );
    let sequence: i64 = with_pool!(
        &first,
        pool,
        sqlx::query_scalar("SELECT current_seq FROM sync_vaults WHERE vault_id=$1")
            .bind(vault.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .expect("sequence")
    );
    assert_eq!(sequence, 1, "admission failures never dispatch another object write");
    let after: i64 = with_pool!(
        &first,
        pool,
        sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(pool)
            .await
            .expect("audit count")
    );
    assert_eq!(after, before, "admission creates no business audit events");
    restarted.stop().await;
    b.stop().await;
    with_pool!(&first, pool, pool.close().await);
}

#[tokio::test]
async fn sqlite_two_independent_listeners_share_durable_write_admission() {
    let directory = directory();
    let path = directory.join("scoplen.sqlite");
    let first = Arc::new(SqliteStore::open(&path).await.expect("first pool"));
    let second = Arc::new(SqliteStore::open(&path).await.expect("second pool"));
    exercise(
        ListenerDatabase::Sqlite(first.clone()),
        ListenerDatabase::Sqlite(second.clone()),
        &directory,
        None,
    )
    .await;
    first.pool().close().await;
    second.pool().close().await;
    remove_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture()
-> (Arc<PostgresStore>, Arc<PostgresStore>, sqlx::PgPool, String, url::Url) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("sync_write_http_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let first = Arc::new(PostgresStore::connect(url.as_str()).await.expect("first pool"));
    let second = Arc::new(PostgresStore::connect(url.as_str()).await.expect("second pool"));
    (first, second, pool, schema, url)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup(
    first: Arc<PostgresStore>,
    second: Arc<PostgresStore>,
    pool: sqlx::PgPool,
    schema: String,
) {
    first.pool().close().await;
    second.pool().close().await;
    assert!(
        schema.starts_with("sync_write_http_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_two_independent_listeners_share_durable_write_admission() {
    let directory = directory();
    let (first, second, pool, schema, url) = postgres_fixture().await;
    exercise(
        ListenerDatabase::Postgres(first.clone()),
        ListenerDatabase::Postgres(second.clone()),
        &directory,
        Some(url.as_str()),
    )
    .await;
    cleanup(first, second, pool, schema).await;
    remove_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_admission_lost_commit_ack_is_retryable_without_dispatching_write() {
    use std::sync::atomic::Ordering;
    let directory = directory();
    let (first, second, pool, schema, url) = postgres_fixture().await;
    let (_, device, vault) = seed_postgres(&first).await;
    let proxy = crate::test_lost_commit::LostCommitProxy::start(url.as_str()).await;
    let proxied =
        Arc::new(PostgresStore::connect(&proxy.database_url).await.expect("proxied store"));
    let limits = WriteRateLimits::new(1, 3).expect("rate");
    let listener =
        Listener::start(ListenerDatabase::Postgres(proxied.clone()), &directory, limits).await;
    let token = issue_token(listener.address, device).await;
    let origin = future();
    sqlx::query("UPDATE sync_write_admission_clock SET retired_through_ns=$1")
        .bind(origin.to_be_bytes().as_slice())
        .execute(first.pool())
        .await
        .expect("pin clock");
    first.admit_sync_write(device.into_bytes(), limits).await.expect("initial charge");
    let mut blocker = first.pool().begin().await.expect("block admission");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("blocker pid");
    sqlx::query("SELECT device_id FROM sync_write_admission WHERE device_id=$1 FOR UPDATE")
        .bind(device.as_bytes().as_slice())
        .fetch_one(&mut *blocker)
        .await
        .expect("device lock");
    let path = format!("/sync/v1/vaults/{vault}/objects");
    let body = SyncWriteBatch { writes: vec![signed_write(vault, device, Uuid::now_v7())] }
        .to_cbor()
        .expect("valid write");
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
        .fetch_one(first.pool())
        .await
        .expect("audits");
    let reply = {
        let pending = request(&listener, "POST", &path, &body, &token);
        tokio::pin!(pending);
        let reached = async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                )
                .bind(pid)
                .fetch_one(second.pool())
                .await
                .expect("observe waiter");
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {
            reply=&mut pending=>panic!("request completed before admission lock: {}",reply.status),
            result=tokio::time::timeout(Duration::from_secs(10),reached)=>result.expect("admission reached after authentication"),
        }
        proxy.armed.store(true, Ordering::SeqCst);
        blocker.rollback().await.expect("release direct connection");
        pending.await
    };
    denied(&reply, 503, "sync.storage_unavailable");
    assert_eq!(
        proxy.dropped.load(Ordering::SeqCst),
        1,
        "one real committed counter acknowledgement withheld"
    );
    let balance: Vec<u8> =
        sqlx::query_scalar("SELECT tokens FROM sync_write_admission WHERE device_id=$1")
            .bind(device.as_bytes().as_slice())
            .fetch_one(first.pool())
            .await
            .expect("durable counter");
    assert_eq!(balance, SCALE.to_be_bytes(), "charged once without automatic replay");
    let sequence: i64 = sqlx::query_scalar("SELECT current_seq FROM sync_vaults WHERE vault_id=$1")
        .bind(vault.as_bytes().as_slice())
        .fetch_one(first.pool())
        .await
        .expect("sequence");
    assert_eq!(sequence, 0);
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
        .fetch_one(first.pool())
        .await
        .expect("audits");
    assert_eq!(after, before);
    listener.stop().await;
    proxied.pool().close().await;
    drop(proxy);
    cleanup(first, second, pool, schema).await;
    remove_directory(&directory).await;
}
