// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt::Write as _, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use scoplen_api::account_admission::{AccountRequestIntent, AccountRequestKind};
use scoplen_store::{RelationalStore as _, SqliteStore};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use super::*;

const ORIGIN: &str = "https://example.com";
const ROUTE: &str = "/api/v1/auth/accounts/requests/challenge";

pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) headers: String,
    pub(super) body: Vec<u8>,
}

impl Reply {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.trim()))
    }

    pub(super) fn private(&self) {
        assert_eq!(self.header("cache-control"), Some("no-store"));
        assert_eq!(self.header("pragma"), Some("no-cache"));
        for forbidden in
            ["set-cookie", "access-control-allow-origin", "access-control-allow-credentials"]
        {
            assert!(self.header(forbidden).is_none());
        }
    }

    pub(super) fn problem(&self, status: u16, code: &str, retryable: bool) {
        assert_eq!(self.status, status);
        self.private();
        assert_eq!(self.header("content-type"), Some("application/problem+json"));
        assert!(self.body.len() <= 4_096);
        let value: serde_json::Value = serde_json::from_slice(&self.body).expect("problem JSON");
        assert_eq!(value.as_object().expect("problem object").len(), 8);
        assert_eq!(value["status"], status);
        assert_eq!(value["code"], code);
        assert_eq!(value["changed"], false);
        assert_eq!(value["retryable"], retryable);
    }
}

pub(super) fn directory() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("scoplen-account-entry-http-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("owned test directory");
    directory
}

fn request() -> AccountRequestChallengeRequest {
    AccountRequestChallengeRequest {
        kind: AccountRequestKind::Register,
        intent: AccountRequestIntent::Submit,
        operation_id: Uuid::now_v7(),
        device_id: Uuid::now_v7(),
    }
}

async fn serve(backend: AuthBackend) -> (SocketAddr, JoinHandle<()>) {
    serve_with_settings(backend, AccountSettings::default()).await
}

async fn serve_with_settings(
    backend: AuthBackend,
    settings: AccountSettings,
) -> (SocketAddr, JoinHandle<()>) {
    serve_router(router(ORIGIN.into(), backend, settings, test_kms())).await
}

fn test_kms() -> Arc<scoplen_store::kms::LocalKeyFile> {
    let directory = directory();
    let path = directory.join("kms.key");
    std::fs::write(&path, "07".repeat(32)).expect("owned test KMS file");
    let kms = scoplen_store::kms::LocalKeyFile::load(&path).expect("test KMS");
    std::fs::remove_file(path).expect("remove owned test KMS file");
    std::fs::remove_dir(directory).expect("remove empty KMS fixture");
    Arc::new(kms)
}

pub(super) async fn serve_router(app: Router) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("HTTP listener");
    let address = listener.local_addr().expect("bound address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("Account HTTP server");
    });
    (address, server)
}

mod registration;
mod startup;

pub(super) async fn exchange(address: SocketAddr, bytes: &[u8]) -> Reply {
    exchange_with_budget(address, bytes, Duration::from_secs(5)).await
}

async fn exchange_with_budget(address: SocketAddr, bytes: &[u8], budget: Duration) -> Reply {
    let mut stream = TcpStream::connect(address).await.expect("HTTP connection");
    stream.write_all(bytes).await.expect("HTTP request");
    let mut bytes = Vec::new();
    tokio::time::timeout(budget, stream.read_to_end(&mut bytes))
        .await
        .expect("bounded HTTP response")
        .expect("HTTP response read");
    let split = bytes.windows(4).position(|part| part == b"\r\n\r\n").expect("HTTP headers");
    let headers = String::from_utf8(bytes[..split].to_vec()).expect("HTTP header text");
    let status = headers
        .lines()
        .next()
        .expect("HTTP status")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    Reply { status, headers, body: bytes[split + 4..].to_vec() }
}

pub(super) async fn http(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Reply {
    let mut wire = format!(
        "{method} {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        write!(wire, "{name}: {value}\r\n").expect("write request header");
    }
    wire.push_str("\r\n");
    let mut wire = wire.into_bytes();
    wire.extend_from_slice(body);
    exchange(address, &wire).await
}

pub(super) async fn stop(server: JoinHandle<()>) {
    server.abort();
    assert!(server.await.expect_err("cancel owned server").is_cancelled());
}

#[tokio::test]
async fn sqlite_challenge_is_real_bounded_digest_only_and_survives_restart() {
    let directory = directory();
    let path = directory.join("store.sqlite");
    let store = SqliteStore::open(&path).await.expect("store");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    let first_request = request();
    let first = http(
        address,
        "POST",
        ROUTE,
        &first_request.to_json().expect("request"),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(first.status, 200);
    first.private();
    assert!(first.body.len() <= 1_024);
    let first =
        AccountRequestChallengeResponse::from_json(&first.body).expect("shared response parser");
    assert_ne!(first.attempt_id, first.nonce);
    let attempt = Sha256::new()
        .chain_update(b"spl-account-request-attempt-v1")
        .chain_update(first.attempt_id.as_ref())
        .finalize();
    let retained: Vec<u8> =
        sqlx::query_scalar("SELECT attempt_digest FROM account_request_challenges")
            .fetch_one(store.pool())
            .await
            .expect("digest row");
    let exact_digest = retained.as_slice() == attempt.as_slice();
    let raw_attempt_retained = retained.as_slice() == first.attempt_id.as_ref();
    assert!(exact_digest, "only the attempt digest is retained");
    assert!(!raw_attempt_retained, "the raw attempt is never retained");
    stop(server).await;
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("reopened store");
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
        .fetch_one(reopened.pool())
        .await
        .expect("retained challenges");
    assert_eq!(retained, 1);
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(reopened.clone()))).await;
    let mut confirm = first_request;
    confirm.intent = AccountRequestIntent::Confirm;
    let second = http(
        address,
        "POST",
        ROUTE,
        &confirm.to_json().expect("confirm request"),
        &[
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Encoding", "identity"),
            ("Origin", ORIGIN),
        ],
    )
    .await;
    assert_eq!(second.status, 200);
    second.private();
    let second = AccountRequestChallengeResponse::from_json(&second.body)
        .expect("fresh confirmation challenge");
    assert_ne!(first.attempt_id, second.attempt_id);
    assert_ne!(first.nonce, second.nonce);
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
        .fetch_one(reopened.pool())
        .await
        .expect("no account side effect");
    assert_eq!(accounts, 0);
    stop(server).await;
    reopened.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::type_complexity)]
async fn sqlite_metadata_and_structural_denials_are_audited_without_challenges() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    let valid = request().to_json().expect("valid request");
    let cases: Vec<(&str, Vec<u8>, Vec<(&str, &str)>, u16, &str)> = vec![
        (ROUTE, valid.clone(), vec![], 415, "auth.invalid_request"),
        (
            ROUTE,
            valid.clone(),
            vec![("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
            415,
            "auth.invalid_request",
        ),
        (
            ROUTE,
            valid.clone(),
            vec![("Content-Type", "application/json"), ("Origin", "https://other.test")],
            403,
            "policy.denied",
        ),
        (
            ROUTE,
            valid.clone(),
            vec![("Content-Type", "application/json"), ("Origin", ORIGIN), ("Origin", ORIGIN)],
            400,
            "auth.invalid_request",
        ),
        (
            ROUTE,
            valid.clone(),
            vec![("Content-Type", "application/json"), ("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
        (
            "/api/v1/auth/accounts/requests/challenge?",
            valid.clone(),
            vec![("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
        (
            ROUTE,
            vec![b' '; 513],
            vec![("Content-Type", "application/json")],
            413,
            "auth.invalid_request",
        ),
        (
            ROUTE,
            b"{\"kind\":\"register\",\"kind\":\"admit\"}".to_vec(),
            vec![("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
        (
            ROUTE,
            [b"\xef\xbb\xbf".as_slice(), &valid].concat(),
            vec![("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
        (
            ROUTE,
            vec![0xff],
            vec![("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
    ];
    let mut denials = 0;
    for (path, body, headers, status, code) in cases {
        http(address, "POST", path, &body, &headers).await.problem(status, code, false);
        denials += 1;
    }
    for forbidden in ["Authorization", "DPoP", "Cookie", "Idempotency-Key", "If-Match"] {
        http(
            address,
            "POST",
            ROUTE,
            &valid,
            &[("Content-Type", "application/json"), (forbidden, "")],
        )
        .await
        .problem(400, "auth.invalid_request", false);
        denials += 1;
    }
    let options = http(address, "OPTIONS", ROUTE, &[], &[]).await;
    options.problem(405, "auth.invalid_request", false);
    assert_eq!(options.header("allow"), Some("POST"));
    denials += 1;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
        .fetch_one(store.pool())
        .await
        .expect("no challenges");
    assert_eq!(count, 0);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit").expect("denial events").sequence,
        denials
    );
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_source_rate_rejects_before_body_and_ignores_forwarded_source() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=4000000020000")
        .execute(store.pool())
        .await
        .expect("stable admission window");
    let source = "127.0.0.1".parse().expect("source");
    for _ in 0..30 {
        assert!(matches!(
            store
                .admit_account_entry_source(AccountEntryEndpoint::RequestChallenge, source)
                .await
                .expect("source admission"),
            AccountEntryAdmissionDecision::Admitted
        ));
    }
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    // No body is sent: a handler that reads first cannot produce the required response.
    let wire = format!(
        "POST {ROUTE} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 512\r\nX-Forwarded-For: 192.0.2.1\r\nConnection: close\r\n\r\n"
    );
    let reply = exchange(address, wire.as_bytes()).await;
    reply.problem(429, "auth.rate_limited", true);
    let wait: u16 =
        reply.header("retry-after").expect("retry delay").parse().expect("numeric retry delay");
    assert!((1..=300).contains(&wait));
    let expected = AuthRateLimitHeaders::new(wait).expect("rate profile");
    assert_eq!(reply.header("ratelimit-policy"), Some(expected.rate_limit_policy()));
    assert_eq!(reply.header("ratelimit"), Some(expected.rate_limit().as_str()));
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_decoded_device_rate_is_shared_between_real_http_instances() {
    let directory = directory();
    let path = directory.join("store.sqlite");
    let first = SqliteStore::open(&path).await.expect("first instance");
    let second = SqliteStore::open(&path).await.expect("second instance");
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=4000000020000")
        .execute(first.pool())
        .await
        .expect("stable admission window");
    let (first_address, first_server) = serve(AuthBackend::Sqlite(Arc::new(first.clone()))).await;
    let (second_address, second_server) =
        serve(AuthBackend::Sqlite(Arc::new(second.clone()))).await;
    let request = request().to_json().expect("request");
    for index in 0..10 {
        let address = if index % 2 == 0 { first_address } else { second_address };
        assert_eq!(
            http(address, "POST", ROUTE, &request, &[("Content-Type", "application/json")])
                .await
                .status,
            200
        );
    }
    http(second_address, "POST", ROUTE, &request, &[("Content-Type", "application/json")])
        .await
        .problem(429, "auth.rate_limited", true);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
        .fetch_one(first.pool())
        .await
        .expect("bounded challenge rows");
    assert_eq!(count, 10);
    stop(first_server).await;
    stop(second_server).await;
    first.pool().close().await;
    second.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_mandatory_audit_failure_overrides_metadata_denial() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let mut fault = store.pool().acquire().await.expect("owned fault connection");
    sqlx::query("CREATE TRIGGER fail_account_http_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END").execute(&mut *fault).await.expect("audit fault");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    http(address, "POST", ROUTE, &[], &[]).await.problem(503, "auth.storage_unavailable", true);
    assert!(store.deployment_audit_head().await.expect("audit head").is_none());
    sqlx::query("DROP TRIGGER fail_account_http_audit")
        .execute(&mut *fault)
        .await
        .expect("remove owned fault");
    drop(fault);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
pub(super) async fn postgres_fixture()
-> (scoplen_store::PostgresStore, sqlx::PgPool, String, url::Url) {
    let database =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture is required");
    let admin = sqlx::PgPool::connect(&database).await.expect("owned fixture admin pool");
    let schema = format!("account_entry_http_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut database = url::Url::parse(&database).expect("fixture URL");
    database.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store =
        scoplen_store::PostgresStore::connect(database.as_str()).await.expect("PostgreSQL store");
    (store, admin, schema, database)
}

#[cfg(feature = "postgres-integration")]
pub(super) async fn postgres_cleanup(admin: sqlx::PgPool, schema: String) {
    assert!(
        schema.starts_with("account_entry_http_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_challenge_and_private_rate_survive_second_instance() {
    let (first, admin, schema, database) = postgres_fixture().await;
    let second =
        scoplen_store::PostgresStore::connect(database.as_str()).await.expect("second instance");
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=4000000020000")
        .execute(first.pool())
        .await
        .expect("stable admission window");
    let (first_address, first_server) = serve(AuthBackend::Postgres(Arc::new(first.clone()))).await;
    let (second_address, second_server) =
        serve(AuthBackend::Postgres(Arc::new(second.clone()))).await;
    let request = request().to_json().expect("request");
    for index in 0..10 {
        let address = if index % 2 == 0 { first_address } else { second_address };
        let reply =
            http(address, "POST", ROUTE, &request, &[("Content-Type", "application/json")]).await;
        assert_eq!(reply.status, 200);
        reply.private();
        AccountRequestChallengeResponse::from_json(&reply.body)
            .expect("published bounded challenge");
    }
    http(second_address, "POST", ROUTE, &request, &[("Content-Type", "application/json")])
        .await
        .problem(429, "auth.rate_limited", true);
    http(
        first_address,
        "POST",
        ROUTE,
        &request,
        &[("Content-Type", "application/json"), ("Cookie", "")],
    )
    .await
    .problem(400, "auth.invalid_request", false);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
        .fetch_one(first.pool())
        .await
        .expect("bounded challenge rows");
    assert_eq!(count, 10);
    stop(first_server).await;
    stop(second_server).await;
    first.pool().close().await;
    second.pool().close().await;
    postgres_cleanup(admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_source_rate_precedes_body_and_audit_failure_masks_denial() {
    let (store, admin, schema, _) = postgres_fixture().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=4000000020000")
        .execute(store.pool())
        .await
        .expect("stable admission window");
    let source = "127.0.0.1".parse().expect("source");
    for _ in 0..30 {
        assert!(matches!(
            store
                .admit_account_entry_source(AccountEntryEndpoint::RequestChallenge, source)
                .await
                .expect("source admission"),
            AccountEntryAdmissionDecision::Admitted
        ));
    }
    let (address, server) = serve(AuthBackend::Postgres(Arc::new(store.clone()))).await;
    let wire = format!(
        "POST {ROUTE} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n"
    );
    exchange(address, wire.as_bytes()).await.problem(429, "auth.rate_limited", true);
    sqlx::raw_sql("CREATE FUNCTION fail_account_http_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''unavailable''; END'; CREATE TRIGGER fail_account_http_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_account_http_audit()")
        .execute(store.pool()).await.expect("owned audit fault");
    exchange(address, wire.as_bytes()).await.problem(503, "auth.storage_unavailable", true);
    sqlx::raw_sql("DROP TRIGGER fail_account_http_audit ON deployment_audit_events; DROP FUNCTION fail_account_http_audit()")
        .execute(store.pool()).await.expect("remove owned audit fault");
    stop(server).await;
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}
