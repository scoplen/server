// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
use crate::test_lost_commit as lost_commit;
use crate::{test_passkey as passkey, test_support as support};

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::ProblemDetails;
use scoplen_crypto::P256SigningKey;
use scoplen_store::{RelationalStore, SqliteStore, kms::LocalKeyFile};
use std::path::PathBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use webauthn_authenticator_rs::prelude::Url;

const ORIGIN: &str = "https://setup.example.com:9443";

struct Fixture {
    backend: AuthBackend,
    address: SocketAddr,
    server: tokio::task::JoinHandle<()>,
    directory: PathBuf,
    #[cfg(feature = "postgres-integration")]
    postgres: Option<(sqlx::PgPool, String)>,
}

impl Fixture {
    async fn sqlite() -> Self {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("test.sqlite")).await.expect("SQLite");
        Self::start(AuthBackend::Sqlite(Arc::new(store)), directory).await
    }

    #[cfg(feature = "postgres-integration")]
    async fn postgres() -> Self {
        let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("dedicated PG URL");
        let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
        let schema = format!("operator_http_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("test schema");
        let mut url = Url::parse(&database).expect("fixture URL");
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let store = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("PostgreSQL");
        let mut fixture = Self::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
        fixture.postgres = Some((pool, schema));
        fixture
    }

    async fn start(backend: AuthBackend, directory: PathBuf) -> Self {
        let path = directory.join("deployment.key");
        std::fs::write(&path, "09".repeat(32)).expect("fixture KMS");
        let kms = Arc::new(LocalKeyFile::load(&path).expect("load KMS"));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = crate::device_auth::router(ORIGIN.into(), backend.clone(), kms);
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("HTTP server");
        });
        Self {
            backend,
            address,
            server,
            directory,
            #[cfg(feature = "postgres-integration")]
            postgres: None,
        }
    }

    async fn token(&self) -> [u8; 32] {
        let disclosure = match &self.backend {
            AuthBackend::Sqlite(store) => store.initialize_operator_setup(ORIGIN, false).await,
            AuthBackend::Postgres(store) => store.initialize_operator_setup(ORIGIN, false).await,
        }
        .expect("initialize setup")
        .expect("first disclosure");
        URL_SAFE_NO_PAD
            .decode(disclosure.expose_link().split("#token=").nth(1).expect("fragment"))
            .expect("canonical token")
            .try_into()
            .expect("32 bytes")
    }

    async fn execute(&self, sql: &str) {
        match &self.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::raw_sql(sql).execute(store.pool()).await.expect("fixture SQL");
            }
            AuthBackend::Postgres(store) => {
                sqlx::raw_sql(sql).execute(store.pool()).await.expect("fixture SQL");
            }
        }
    }

    async fn count(&self, sql: &str) -> i64 {
        match &self.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query_scalar(sql).fetch_one(store.pool()).await.expect("SQLite count")
            }
            AuthBackend::Postgres(store) => {
                sqlx::query_scalar(sql).fetch_one(store.pool()).await.expect("PostgreSQL count")
            }
        }
    }

    async fn reset_admission(&self) {
        self.execute("DELETE FROM operator_auth_admission").await;
    }

    async fn options(&self, token: [u8; 32], key: &P256SigningKey) -> serde_json::Value {
        let body = OperatorSetupOptionsRequest { setup_token: token }.to_json().expect("request");
        let reply = self.post(OPTIONS_PATH, &body, key).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        OperatorSetupOptionsResponse::from_json(&reply.body).expect("typed options");
        assert!(reply.body.len() <= 4_096);
        serde_json::from_slice(&reply.body).expect("options JSON")
    }

    async fn post(&self, path: &str, body: &[u8], key: &P256SigningKey) -> Reply {
        http(
            self.address,
            path,
            body,
            &[
                ("Content-Type", "application/json"),
                ("Origin", ORIGIN),
                ("DPoP", &proof(key, path)),
            ],
        )
        .await
    }

    async fn cleanup(self) {
        self.server.abort();
        let _ = self.server.await;
        match &self.backend {
            AuthBackend::Sqlite(store) => store.pool().close().await,
            AuthBackend::Postgres(store) => store.pool().close().await,
        }
        drop(self.backend);
        #[cfg(feature = "postgres-integration")]
        if let Some((pool, schema)) = self.postgres {
            assert!(
                schema.starts_with("operator_http_")
                    && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            );
            sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                .execute(&pool)
                .await
                .expect("remove owned schema");
            pool.close().await;
        }
        support::remove_test_directory(self.directory).await;
    }
}

fn directory() -> PathBuf {
    let directory = std::env::temp_dir().join(format!("scoplen-operator-http-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("test directory");
    directory
}

fn key(value: u8) -> P256SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = value;
    P256SigningKey::from_bytes(&bytes).expect("software DPoP key")
}

fn proof(key: &P256SigningKey, path: &str) -> String {
    DpopProof::sign(
        key,
        &key.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, path).expect("target"),
        DpopToken::Refresh,
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs(),
        None,
    )
    .expect("signed proof")
    .as_str()
    .to_owned()
}

fn registration(options: &serde_json::Value, token: [u8; 32]) -> OperatorSetupFinishRequest {
    let mut authenticator = passkey::ResidentPasskey::authenticator();
    let result = authenticator
        .do_registration(
            Url::parse(ORIGIN).expect("origin"),
            passkey::creation(&options["public_key"]),
        )
        .expect("real software passkey");
    OperatorSetupFinishRequest {
        setup_token: token,
        ceremony_id: Uuid::parse_str(options["ceremony_id"].as_str().expect("ceremony"))
            .expect("UUID"),
        credential_id: result.raw_id.as_ref().to_vec(),
        client_data_json: result.response.client_data_json.as_ref().to_vec(),
        attestation_object: result.response.attestation_object.as_ref().to_vec(),
    }
}

struct Reply {
    status: u16,
    headers: String,
    body: Vec<u8>,
}
impl Reply {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("UTF8 response")
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    }
    fn privacy(&self) {
        assert_eq!(self.header("cache-control"), Some("no-store"));
        assert_eq!(self.header("pragma"), Some("no-cache"));
        assert_eq!(self.header("referrer-policy"), Some("no-referrer"));
        assert_eq!(self.header("set-cookie"), None);
        assert!(!self.text().contains("access_token"));
    }
    fn problem(&self, status: u16, code: &str, changed: bool, retryable: bool) {
        assert_eq!(self.status, status, "{}", self.text());
        assert_eq!(self.header("content-type"), Some("application/problem+json"));
        let problem: ProblemDetails = serde_json::from_slice(&self.body).expect("typed problem");
        assert_eq!(problem.code.as_str(), code);
        assert_eq!(problem.changed, changed);
        assert_eq!(problem.retryable, retryable);
        assert_ne!(problem.instance, "");
        assert!(self.body.len() <= 4_096);
        self.privacy();
    }
}

async fn http(address: SocketAddr, path: &str, body: &[u8], headers: &[(&str, &str)]) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(address).await.expect("connect");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: setup.example.com:9443\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.expect("headers");
    stream.write_all(body).await.expect("body");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("HTTP reply");
    let boundary = bytes.windows(4).position(|v| v == b"\r\n\r\n").expect("HTTP boundary");
    let headers = std::str::from_utf8(&bytes[..boundary]).expect("HTTP headers").to_owned();
    let status = headers
        .lines()
        .next()
        .expect("status")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    Reply { status, headers, body: bytes[boundary + 4..].to_vec() }
}

async fn lifecycle(fixture: Fixture) {
    let token = fixture.token().await;
    let client_key = key(1);
    let options = fixture.options(token, &client_key).await;
    let input = registration(&options, token);
    let body = input.to_json().expect("finish wire");
    fixture.post(FINISH_PATH, &body, &key(2)).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_ceremonies WHERE consumed_at_s IS NOT NULL")
            .await,
        0
    );
    let reply = fixture.post(FINISH_PATH, &body, &client_key).await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    reply.privacy();
    let finished = OperatorSetupFinishResponse::from_json(&reply.body).expect("finish response");
    assert_eq!(finished.operator_id.get_version_num(), 7);
    assert!(reply.body.len() <= 256);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM deployment_operators").await, 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_credentials").await, 1);
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM operator_setup WHERE completed_at_s IS NOT NULL").await,
        1
    );
    for table in ["identity_accounts", "identity_devices", "sync_vaults", "device_refresh_families"]
    {
        assert_eq!(fixture.count(&format!("SELECT COUNT(*) FROM {table}")).await, 0);
    }
    fixture.post(FINISH_PATH, &body, &client_key).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    fixture.reset_admission().await;
    let body = OperatorSetupOptionsRequest { setup_token: token }.to_json().expect("options");
    fixture.post(OPTIONS_PATH, &body, &client_key).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_setup_registers_independent_operator() {
    lifecycle(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_setup_registers_independent_operator() {
    lifecycle(Fixture::postgres().await).await;
}

#[allow(clippy::too_many_lines)]
async fn guards(fixture: Fixture) {
    let token = fixture.token().await;
    let client_key = key(1);
    let body = OperatorSetupOptionsRequest { setup_token: token }.to_json().expect("options");
    let signed = proof(&client_key, OPTIONS_PATH);
    let valid =
        [("Content-Type", "application/json"), ("Origin", ORIGIN), ("DPoP", signed.as_str())];
    for invalid in [
        b"{}".to_vec(),
        b"{\"setup_token\":null}".to_vec(),
        b"{\"setup_token\":1}".to_vec(),
        b"{\"setup_token\":\"invalid\"}".to_vec(),
        b"\xff".to_vec(),
        [body.as_slice(), b" "].concat().into_iter().cycle().take(257).collect(),
    ] {
        let reply = http(fixture.address, OPTIONS_PATH, &invalid, &valid).await;
        reply.problem(
            if invalid.len() > 256 { 413 } else { 400 },
            "auth.invalid_request",
            false,
            false,
        );
    }
    let duplicate = format!(
        "{{\"setup_token\":\"{}\",\"setup_token\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode(token),
        URL_SAFE_NO_PAD.encode(token)
    );
    http(fixture.address, OPTIONS_PATH, duplicate.as_bytes(), &valid).await.problem(
        400,
        "auth.invalid_request",
        false,
        false,
    );
    for path in [format!("{OPTIONS_PATH}?"), format!("{OPTIONS_PATH}?ignored=1")] {
        http(fixture.address, &path, &body, &valid).await.problem(
            400,
            "auth.invalid_request",
            false,
            false,
        );
    }
    for field in [
        ("Authorization", "Bearer forbidden"),
        ("Idempotency-Key", "forbidden"),
        ("Cookie", "__Secure-spl-refresh=forbidden"),
    ] {
        let mut headers = valid.to_vec();
        headers.push(field);
        http(fixture.address, OPTIONS_PATH, &body, &headers).await.problem(
            400,
            "auth.invalid_request",
            false,
            false,
        );
    }
    for origin in [None, Some("null"), Some("https://other.example.com")] {
        let mut headers = vec![valid[0], valid[2]];
        if let Some(value) = origin {
            headers.push(("Origin", value));
        }
        http(fixture.address, OPTIONS_PATH, &body, &headers).await.problem(
            403,
            "policy.denied",
            false,
            false,
        );
    }
    let mut duplicate_origin = valid.to_vec();
    duplicate_origin.push(("Origin", ORIGIN));
    http(fixture.address, OPTIONS_PATH, &body, &duplicate_origin).await.problem(
        403,
        "policy.denied",
        false,
        false,
    );
    http(
        fixture.address,
        OPTIONS_PATH,
        &body,
        &[("Content-Type", "text/plain"), valid[1], valid[2]],
    )
    .await
    .problem(415, "auth.invalid_request", false, false);
    for submitted in [
        vec![],
        vec![("DPoP", "invalid")],
        vec![("DPoP", signed.as_str()), ("DPoP", signed.as_str())],
    ] {
        let mut headers = vec![valid[0], valid[1]];
        headers.extend(submitted);
        http(fixture.address, OPTIONS_PATH, &body, &headers).await.problem(
            400,
            "auth.invalid_dpop_proof",
            false,
            false,
        );
    }
    let oversized = "x".repeat(8_193);
    http(fixture.address, OPTIONS_PATH, &body, &[valid[0], valid[1], ("DPoP", &oversized)])
        .await
        .problem(400, "auth.invalid_dpop_proof", false, false);
    let wrong_target = proof(&client_key, FINISH_PATH);
    http(fixture.address, OPTIONS_PATH, &body, &[valid[0], valid[1], ("DPoP", &wrong_target)])
        .await
        .problem(400, "auth.invalid_dpop_proof", false, false);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_ceremonies").await, 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_dpop_replays").await, 0);
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM operator_auth_admission WHERE kind = 2").await,
        0
    );
    fixture.reset_admission().await;
    let reply = http(fixture.address, OPTIONS_PATH, &body, &valid).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.privacy();
    let options: serde_json::Value = serde_json::from_slice(&reply.body).expect("options");
    http(fixture.address, OPTIONS_PATH, &body, &valid).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_ceremonies").await, 1);
    let registration = registration(&options, token);
    let finish = registration.to_json().expect("finish");
    let mut invalid: serde_json::Value = serde_json::from_slice(&finish).expect("JSON");
    invalid["credential_id"] = serde_json::json!("bad=");
    fixture
        .post(FINISH_PATH, &serde_json::to_vec(&invalid).expect("JSON"), &client_key)
        .await
        .problem(400, "auth.invalid_request", false, false);
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_ceremonies WHERE consumed_at_s IS NOT NULL")
            .await,
        0
    );
    fixture.execute("UPDATE operator_ceremonies SET issued_at_s = issued_at_s - 1000, expires_at_s = issued_at_s - 999").await;
    fixture.post(FINISH_PATH, &finish, &client_key).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_setup_guards_preserve_ceremonies() {
    guards(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_setup_guards_preserve_ceremonies() {
    guards(Fixture::postgres().await).await;
}

async fn audit_atomicity(fixture: Fixture) {
    let token = fixture.token().await;
    let client_key = key(1);
    let options = fixture.options(token, &client_key).await;
    let mut input = registration(&options, token);
    input.client_data_json = b"{".to_vec();
    let body = input.to_json().expect("opaque malformed embedded JSON");
    match &fixture.backend {
        AuthBackend::Sqlite(_) => fixture.execute("CREATE TRIGGER reject_operator_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END").await,
        AuthBackend::Postgres(_) => fixture.execute("CREATE FUNCTION reject_operator_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END; $$; CREATE TRIGGER reject_operator_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_operator_audit();").await,
    }
    fixture.post(FINISH_PATH, &body, &client_key).await.problem(
        503,
        "auth.storage_unavailable",
        false,
        true,
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_ceremonies WHERE consumed_at_s IS NOT NULL")
            .await,
        0
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM deployment_operators").await, 0);
    http(fixture.address, OPTIONS_PATH, b"{}", &[("Content-Type", "application/json")])
        .await
        .problem(503, "auth.storage_unavailable", false, true);
    match &fixture.backend {
        AuthBackend::Sqlite(_) => fixture.execute("DROP TRIGGER reject_operator_audit").await,
        AuthBackend::Postgres(_) => fixture.execute("DROP TRIGGER reject_operator_audit ON deployment_audit_events; DROP FUNCTION reject_operator_audit();").await,
    }
    let audits = fixture.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    fixture.post(FINISH_PATH, &body, &client_key).await.problem(
        401,
        "auth.authentication_required",
        true,
        false,
    );
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM deployment_audit_events").await,
        audits + 1,
        "consuming denial must not receive a second HTTP failure audit"
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_ceremonies WHERE consumed_at_s IS NOT NULL")
            .await,
        1
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_auth_admission WHERE failure_streak = 1")
            .await,
        2
    );
    let limited = fixture.post(FINISH_PATH, &body, &client_key).await;
    limited.problem(429, "auth.rate_limited", false, true);
    assert!(limited.header("retry-after").is_some());
    assert!(limited.header("ratelimit-policy").is_some());
    assert!(limited.header("ratelimit").is_some());
    fixture.reset_admission().await;
    fixture.post(FINISH_PATH, &body, &client_key).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    fixture.reset_admission().await;
    fixture.options(token, &client_key).await;
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM operator_setup WHERE completed_at_s IS NOT NULL").await,
        0
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_setup_embedded_denial_and_audit_are_atomic() {
    audit_atomicity(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_setup_embedded_denial_and_audit_are_atomic() {
    audit_atomicity(Fixture::postgres().await).await;
}

async fn quota_and_race(fixture: Fixture) {
    let token = fixture.token().await;
    let client_key = key(1);
    let options = fixture.options(token, &client_key).await;
    let body = OperatorSetupOptionsRequest { setup_token: token }.to_json().expect("options");
    fixture.execute("UPDATE operator_auth_admission SET attempts = 5 WHERE kind = 2").await;
    fixture.post(OPTIONS_PATH, &body, &client_key).await.problem(
        429,
        "auth.rate_limited",
        false,
        true,
    );
    fixture.reset_admission().await;
    // Populate the source bucket through a malformed request, then prove quota precedes parsing.
    http(fixture.address, OPTIONS_PATH, b"{}", &[]).await.problem(
        403,
        "policy.denied",
        false,
        false,
    );
    fixture.execute("UPDATE operator_auth_admission SET attempts = 30 WHERE kind = 1").await;
    http(fixture.address, OPTIONS_PATH, b"not JSON", &[]).await.problem(
        429,
        "auth.rate_limited",
        false,
        true,
    );
    fixture.reset_admission().await;
    let input = registration(&options, token);
    let body = input.to_json().expect("finish");
    let (first, second) = tokio::join!(
        fixture.post(FINISH_PATH, &body, &client_key),
        fixture.post(FINISH_PATH, &body, &client_key)
    );
    assert_eq!(
        [first.status, second.status].iter().filter(|&&s| s == 201).count(),
        1,
        "exactly one setup winner"
    );
    for reply in [&first, &second] {
        reply.privacy();
        if reply.status != 201 {
            reply.problem(401, "auth.authentication_required", false, false);
        }
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM deployment_operators").await, 1);
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_setup_admission_and_concurrent_finish() {
    quota_and_race(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_setup_admission_and_concurrent_finish() {
    quota_and_race(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_real_http_setup_uncertain_commit_discloses_no_success() {
    let fixture = Fixture::sqlite().await;
    let token = fixture.token().await;
    let client_key = key(1);
    let options = fixture.options(token, &client_key).await;
    let input = registration(&options, token);
    fixture.execute("CREATE TABLE operator_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE operator_commit_child (id INTEGER REFERENCES operator_commit_parent (id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER operator_commit_failure AFTER UPDATE OF consumed_at_s ON operator_ceremonies BEGIN INSERT INTO operator_commit_child VALUES (1); END;").await;
    fixture.post(FINISH_PATH, &input.to_json().expect("finish"), &client_key).await.problem(
        503,
        "auth.commit_outcome_unknown",
        true,
        false,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM deployment_operators").await, 0);
    fixture.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_setup_lost_commit_ack_discloses_no_success() {
    use std::sync::atomic::Ordering;
    let fixture = Fixture::postgres().await;
    let token = fixture.token().await;
    let client_key = key(1);
    let options = fixture.options(token, &client_key).await;
    let input = registration(&options, token);
    let AuthBackend::Postgres(direct) = &fixture.backend else { unreachable!() };
    let schema = &fixture.postgres.as_ref().expect("isolated schema").1;
    let mut url =
        Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("fixture URL")).expect("URL");
    let application = format!("operator_http_lost_{}", Uuid::new_v4().simple());
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"))
        .append_pair("application_name", &application);
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    let http_fixture = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let mut barrier = direct.pool().begin().await.expect("setup barrier");
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1330660690)")
        .execute(&mut *barrier)
        .await
        .expect("hold setup serialization lock");
    let address = http_fixture.address;
    let body = input.to_json().expect("finish");
    let signed = proof(&client_key, FINISH_PATH);
    let request = tokio::spawn(async move {
        http(
            address,
            FINISH_PATH,
            &body,
            &[("Content-Type", "application/json"), ("Origin", ORIGIN), ("DPoP", &signed)],
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock'").bind(&application).fetch_one(direct.pool()).await.expect("observe finish barrier");
            if waiting > 0 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("finish must reach setup lock after the three admission/replay commits");
    proxy.armed.store(true, Ordering::SeqCst);
    barrier.commit().await.expect("release setup barrier");
    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), request)
        .await
        .expect("HTTP finishes")
        .expect("HTTP task");
    reply.problem(503, "auth.commit_outcome_unknown", true, false);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM deployment_operators").await,
        1,
        "business commit is durable despite withheld acknowledgement"
    );
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM operator_setup WHERE completed_at_s IS NOT NULL").await,
        1
    );
    http_fixture.cleanup().await;
    drop(proxy);
    fixture.cleanup().await;
}
