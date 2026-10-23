// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
use crate::test_lost_commit as lost_commit;
use crate::{test_passkey as passkey, test_support as support};

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::personal_enrollment::PersonalInvitationResponse;
use scoplen_crypto::{
    DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    dpop_jwk_thumbprint,
};
use scoplen_identity::operator_passkeys::{AssertionArtifacts, OperatorPasskeyVerifier};
use scoplen_store::{
    RelationalStore, SqliteStore, operator_sessions::OperatorAuthentication,
    operator_setup::OperatorRegistration,
};
use std::path::PathBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use webauthn_authenticator_rs::prelude::Url;

const ORIGIN: &str = "https://operator.example.com:9443";

struct Fixture {
    backend: AuthBackend,
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    directory: PathBuf,
    token: String,
    key: P256SigningKey,
    #[cfg(feature = "postgres-integration")]
    postgres: Option<(sqlx::PgPool, String)>,
}

macro_rules! login {
    ($store:expr,$kms:expr,$key:expr) => {{
        let store = &$store;
        let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
        let setup =
            store.initialize_operator_setup(ORIGIN, false).await.expect("init").expect("setup");
        let token: [u8; 32] = URL_SAFE_NO_PAD
            .decode(setup.expose_link().split("#token=").nth(1).expect("token"))
            .expect("base64")
            .try_into()
            .expect("32 bytes");
        let binding = dpop_jwk_thumbprint(&$key.public_key_sec1()).expect("binding");
        let options =
            store.operator_setup_options(&token, &binding, &verifier).await.expect("options");
        let mut authenticator = passkey::ResidentPasskey::authenticator();
        let registration = authenticator
            .do_registration(
                Url::parse(ORIGIN).expect("origin"),
                passkey::creation(&options.public_key),
            )
            .expect("real passkey registration");
        let operator = store
            .finish_operator_setup(
                &OperatorRegistration {
                    source: "192.0.2.91".parse().expect("peer"),
                    setup_token: &token,
                    ceremony_id: options.ceremony_id,
                    browser_jkt: &binding,
                    credential_id: registration.raw_id.as_ref(),
                    client_data_json: registration.response.client_data_json.as_ref(),
                    attestation_object: registration.response.attestation_object.as_ref(),
                },
                &verifier,
            )
            .await
            .expect("setup");
        let options =
            store.operator_login_options(&binding, &verifier).await.expect("login options");
        let assertion = authenticator
            .do_authentication(
                Url::parse(ORIGIN).expect("origin"),
                passkey::authentication(&options.public_key),
            )
            .expect("real passkey assertion");
        let keyring = store.ensure_operator_token_keyring($kms).await.expect("keyring");
        let response = store
            .finish_operator_login(
                &OperatorAuthentication {
                    source: "192.0.2.91".parse().expect("peer"),
                    ceremony_id: options.ceremony_id,
                    browser_jkt: &binding,
                    artifacts: AssertionArtifacts {
                        credential_id: assertion.raw_id.as_ref(),
                        client_data: assertion.response.client_data_json.as_ref(),
                        authenticator_data: assertion.response.authenticator_data.as_ref(),
                        signature: assertion.response.signature.as_ref(),
                        user_handle: operator.as_bytes(),
                    },
                },
                &verifier,
                &keyring,
            )
            .await
            .expect("real passkey login");
        response.browser().access_token.clone()
    }};
}

macro_rules! device_token {
    ($store:expr, $kms:expr, $active:literal) => {{
        let store = $store;
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let account_key = Ed25519SigningKey::from_bytes(&[7; 32]).expect("account key");
        let device_key = key(2);
        let kem = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("device KEM");
        let certificate = DeviceCertificate::issue(
            &account_key, device, account, device_key.public_key_sec1(),
            kem.public_key().to_vec(), "test device".into(), "windows".into(), 1,
        ).expect("certificate").encode().expect("canonical certificate");
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES ($1,$2,$3,1)")
            .bind(account.as_bytes().as_slice()).bind(account_key.public_key().as_slice())
            .bind([4_u8;32].as_slice()).execute(store.pool()).await.expect("account");
        sqlx::query(concat!("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES ($1,$2,$3,",$active,",1)"))
            .bind(device.as_bytes().as_slice()).bind(account.as_bytes().as_slice()).bind(&certificate)
            .execute(store.pool()).await.expect("device");
        sqlx::query("INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES ($1,$2)")
            .bind(account.as_bytes().as_slice()).bind(&certificate).execute(store.pool()).await.expect("published certificate");
        let challenge = store.issue_device_challenge(device.into_bytes()).await.expect("challenge");
        let nonce = challenge.nonce();
        let hex: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let context = DeviceAuthContext::new(ORIGIN, &hex, device).expect("possession context");
        let signature = device_key.sign(&context.signature_input());
        let keyring = store.ensure_device_token_keyring($kms).await.expect("device keys");
        store.authenticate_device("192.0.2.92".parse().expect("peer"),ORIGIN,device.into_bytes(),nonce,&signature,&keyring)
            .await.expect("real device authentication").access_token
    }};
}

impl Fixture {
    async fn sqlite() -> Self {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("SQLite");
        Self::start(AuthBackend::Sqlite(Arc::new(store)), directory).await
    }
    #[cfg(feature = "postgres-integration")]
    async fn postgres() -> Self {
        let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("dedicated test database");
        let pool = sqlx::PgPool::connect(&database).await.expect("PG admin");
        let schema = format!("invitation_http_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
        let mut url = Url::parse(&database).expect("database URL");
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let store = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("PG");
        let mut fixture = Self::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
        fixture.postgres = Some((pool, schema));
        fixture
    }
    async fn start(backend: AuthBackend, directory: PathBuf) -> Self {
        let path = directory.join("deployment.key");
        std::fs::write(&path, "41".repeat(32)).expect("test KMS");
        let kms = Arc::new(LocalKeyFile::load(&path).expect("KMS"));
        let key = key(1);
        let token = match &backend {
            AuthBackend::Sqlite(store) => login!(store, kms.as_ref(), key),
            AuthBackend::Postgres(store) => login!(store, kms.as_ref(), key),
        };
        Self::listen(backend, directory, kms, token, key).await
    }
    async fn listen(
        backend: AuthBackend,
        directory: PathBuf,
        kms: Arc<LocalKeyFile>,
        token: String,
        key: P256SigningKey,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = crate::device_auth::router(ORIGIN.into(), backend.clone(), kms);
        let task = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("HTTP");
        });
        Self {
            backend,
            address,
            task,
            directory,
            token,
            key,
            #[cfg(feature = "postgres-integration")]
            postgres: None,
        }
    }
    fn proof(&self) -> String {
        proof(&self.key, &self.token)
    }
    async fn post(&self, body: &[u8]) -> Reply {
        self.request(
            ROUTE,
            body,
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &format!("DPoP {}", self.token)),
                ("DPoP", &self.proof()),
                ("Origin", ORIGIN),
            ],
        )
        .await
    }
    async fn request(&self, path: &str, body: &[u8], headers: &[(&str, &str)]) -> Reply {
        http(self.address, path, body, headers).await
    }
    async fn pending_body(&self) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.expect("TCP");
        let headers = format!(
            "POST {ROUTE} HTTP/1.1\r\nHost: operator.example.com:9443\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\nOrigin: {ORIGIN}\r\nAuthorization: DPoP {}\r\nDPoP: {}\r\n\r\n",
            self.token,
            self.proof()
        );
        stream.write_all(headers.as_bytes()).await.expect("pending headers");
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if self.count("SELECT CAST(COALESCE(SUM(attempts),0) AS BIGINT) FROM personal_invitation_admission WHERE kind=2").await > 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("request must finish authentication before its body arrives");
        stream
    }
    async fn verified(&self) -> VerifiedOperatorAccessToken {
        let kms = LocalKeyFile::load(self.directory.join("deployment.key")).expect("KMS");
        let keyring = self.backend.operator_keyring(&kms).await.expect("keyring");
        let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
        for key in keyring.verification_keys() {
            trusted.insert(&key.kid, &key.public_key).expect("trusted public key");
        }
        OperatorAccessToken::parse(&self.token)
            .expect("token")
            .verify(
                &trusted,
                u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
            )
            .expect("genuine Operator token")
    }
    async fn reset_quota(&self) {
        self.execute("DELETE FROM personal_invitation_admission").await;
        assert_eq!(
            self.backend
                .invitation_source("127.0.0.1".parse().expect("peer"))
                .await
                .expect("source"),
            PersonalAdmissionDecision::Admitted
        );
        assert_eq!(
            self.backend
                .invitation_operator(self.verified().await.claims().sub)
                .await
                .expect("Operator"),
            PersonalAdmissionDecision::Admitted
        );
        // A full fixture window keeps a quota burst independent of UTC minute boundaries.
        let now = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        self.execute(&format!("UPDATE personal_invitation_admission SET attempts=0, window_start_ms={now}, retain_until_ms={}", now + 60_000)).await;
    }
    async fn execute(&self, sql: &str) {
        match &self.backend {
            AuthBackend::Sqlite(s) => {
                sqlx::raw_sql(sql).execute(s.pool()).await.expect("fixture SQL");
            }
            AuthBackend::Postgres(s) => {
                sqlx::raw_sql(sql).execute(s.pool()).await.expect("fixture SQL");
            }
        }
    }
    async fn count(&self, sql: &str) -> i64 {
        match &self.backend {
            AuthBackend::Sqlite(s) => {
                sqlx::query_scalar(sql).fetch_one(s.pool()).await.expect("count")
            }
            AuthBackend::Postgres(s) => {
                sqlx::query_scalar(sql).fetch_one(s.pool()).await.expect("count")
            }
        }
    }
    async fn cleanup(self) {
        self.task.abort();
        let _ = self.task.await;
        match &self.backend {
            AuthBackend::Sqlite(s) => s.pool().close().await,
            AuthBackend::Postgres(s) => s.pool().close().await,
        }
        drop(self.backend);
        #[cfg(feature = "postgres-integration")]
        if let Some((pool, schema)) = self.postgres {
            assert!(
                schema.starts_with("invitation_http_")
                    && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            );
            sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                .execute(&pool)
                .await
                .expect("drop owned schema");
            pool.close().await;
        }
        support::remove_test_directory(self.directory).await;
    }
}

async fn http(address: SocketAddr, path: &str, body: &[u8], headers: &[(&str, &str)]) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(address).await.expect("TCP");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: operator.example.com:9443\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.expect("HTTP headers");
    stream.write_all(body).await.expect("HTTP body");
    read_reply(&mut stream).await
}

async fn read_reply(stream: &mut tokio::net::TcpStream) -> Reply {
    let mut bytes = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .expect("HTTP deadline")
        .expect("reply");
    let index = bytes.windows(4).position(|part| part == b"\r\n\r\n").expect("HTTP response");
    let headers = String::from_utf8(bytes[..index].to_vec()).expect("ASCII headers");
    let status =
        headers.split_whitespace().nth(1).expect("status").parse().expect("numeric status");
    Reply { status, headers, body: bytes[index + 4..].to_vec() }
}
fn directory() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("scoplen-invitation-http-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("directory");
    directory
}
fn key(value: u8) -> P256SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = value;
    P256SigningKey::from_bytes(&bytes).expect("DPoP key")
}
fn proof(key: &P256SigningKey, token: &str) -> String {
    DpopProof::sign(
        key,
        &key.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, ROUTE).expect("target"),
        DpopToken::Protected(token),
        u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("proof")
    .as_str()
    .to_owned()
}
struct Reply {
    status: u16,
    headers: String,
    body: Vec<u8>,
}
impl Reply {
    fn private_headers(&self) {
        let lower = self.headers.to_ascii_lowercase();
        assert!(lower.contains("cache-control: no-store"));
        assert!(lower.contains("pragma: no-cache"));
        assert!(lower.contains("referrer-policy: no-referrer"));
        assert!(!lower.contains("set-cookie:"));
    }
    fn problem(&self, status: u16, code: &str, changed: bool) {
        assert_eq!(self.status, status);
        self.private_headers();
        let p: ProblemDetails = serde_json::from_slice(&self.body).expect("problem");
        assert_eq!(p.code.as_str(), code);
        assert_eq!(p.changed, changed);
        assert_eq!(p.retryable, status == 429 || status == 503 && !changed);
        assert_ne!(p.instance, "");
    }
}

async fn lifecycle(f: Fixture) {
    let first = f.post(b"{}").await;
    assert_eq!(first.status, 201);
    first.private_headers();
    let one = PersonalInvitationResponse::from_json(&first.body).expect("invitation");
    let second = f.post(b" { } ").await;
    assert_eq!(second.status, 201);
    let two = PersonalInvitationResponse::from_json(&second.body).expect("invitation");
    assert_ne!(one.invitation_url, two.invitation_url);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM personal_invitations WHERE consumed_at_ms IS NULL").await,
        2
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first.body)
            .expect("JSON")
            .as_object()
            .expect("object")
            .len(),
        2
    );
    for (table, column) in [("deployment_operators", "active"), ("operator_credentials", "active")]
    {
        f.execute(&format!("UPDATE {table} SET {column}=0")).await;
        f.post(b"{}").await.problem(401, "auth.authentication_required", false);
        f.execute(&format!("UPDATE {table} SET {column}=1")).await;
    }
    f.execute("UPDATE operator_refresh_families SET revoked_at_ms=created_at_ms").await;
    f.post(b"{}").await.problem(401, "auth.authentication_required", false);
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 2);
    f.cleanup().await;
}

async fn guards(f: Fixture) {
    let auth = format!("DPoP {}", f.token);
    f.request(ROUTE, b"{}", &[("Content-Type", "application/json")]).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    for body in [b"[]".as_slice(), b"null", b"{\"x\":1}", b"{\"x\":1,\"x\":2}"] {
        f.post(body).await.problem(400, "auth.invalid_request", false);
    }
    f.post(&vec![b' '; 257]).await.problem(413, "auth.invalid_request", false);
    f.request(
        ROUTE,
        b"{}",
        &[("Content-Type", "text/plain"), ("Authorization", &auth), ("DPoP", &f.proof())],
    )
    .await
    .problem(415, "auth.invalid_request", false);
    f.request(
        ROUTE,
        b"{}",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
            ("DPoP", &f.proof()),
            ("Origin", "https://elsewhere.example"),
        ],
    )
    .await
    .problem(403, "policy.denied", false);
    for (path, extra) in [
        (ROUTE, Some(("Idempotency-Key", "one"))),
        ("/api/v1/admin/personal-invitations?x=1", None),
    ] {
        let p = f.proof();
        let mut headers =
            vec![("Content-Type", "application/json"), ("Authorization", &auth), ("DPoP", &p)];
        if let Some(extra) = extra {
            headers.push(extra);
        }
        f.request(path, b"{}", &headers).await.problem(400, "auth.invalid_request", false);
    }
    f.request(
        ROUTE,
        b"{}",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
            ("DPoP", &proof(&key(2), &f.token)),
        ],
    )
    .await
    .problem(401, "auth.authentication_required", false);
    let p = f.proof();
    let headers = [("Content-Type", "application/json"), ("Authorization", &auth), ("DPoP", &p)];
    assert_eq!(f.request(ROUTE, b"{}", &headers).await.status, 201);
    f.request(ROUTE, b"{}", &headers).await.problem(401, "auth.authentication_required", false);
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 1);
    f.cleanup().await;
}

async fn quotas(f: Fixture) {
    f.reset_quota().await;
    for _ in 0..10 {
        assert_eq!(f.post(b"{}").await.status, 201);
    }
    let rejected = f.post(b"{}").await;
    rejected.problem(429, "auth.rate_limited", false);
    let lower = rejected.headers.to_ascii_lowercase();
    assert!(lower.contains("ratelimit-policy: \"personal\";q=30;w=60"));
    assert!(lower.contains("retry-after:"));
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 10);
    f.reset_quota().await;
    for _ in 0..30 {
        f.request(ROUTE, b"{}", &[("Content-Type", "application/json")]).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
    }
    f.post(b"not json").await.problem(429, "auth.rate_limited", false);
    f.cleanup().await;
}

async fn audit_rollback(f: Fixture) {
    match &f.backend {
        AuthBackend::Sqlite(_)=>f.execute("CREATE TRIGGER fail_invitation_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END").await,
        AuthBackend::Postgres(_)=>f.execute("CREATE FUNCTION fail_invitation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unavailable'; END $$; CREATE TRIGGER fail_invitation_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_invitation_audit()").await,
    }
    f.post(b"{}").await.problem(503, "auth.storage_unavailable", false);
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 0);
    f.request(ROUTE, b"{}", &[("Content-Type", "application/json")]).await.problem(
        503,
        "auth.storage_unavailable",
        false,
    );
    match &f.backend {AuthBackend::Sqlite(_)=>f.execute("DROP TRIGGER fail_invitation_audit").await,AuthBackend::Postgres(_)=>f.execute("DROP TRIGGER fail_invitation_audit ON deployment_audit_events; DROP FUNCTION fail_invitation_audit()").await}
    assert_eq!(f.post(b"{}").await.status, 201);
    f.cleanup().await;
}

async fn principal_and_scope(f: Fixture) {
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let token = match &f.backend {
        AuthBackend::Sqlite(store) => device_token!(store, &kms, "1"),
        AuthBackend::Postgres(store) => device_token!(store, &kms, "TRUE"),
    };
    f.request(
        ROUTE,
        b"{}",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("DPoP {token}")),
            ("DPoP", &proof(&key(2), &token)),
        ],
    )
    .await
    .problem(403, "policy.denied", false);
    let keyring = f.backend.operator_keyring(&kms).await.expect("Operator keys");
    let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("public key");
    }
    let mut claims = f.verified().await.claims().clone();
    claims.scope = "deployment:read".into();
    let signer = keyring.signing_key();
    let token = OperatorAccessToken::sign(signer, &trusted, signer.kid(), &claims)
        .expect("reduced-scope signed token");
    f.request(
        ROUTE,
        b"{}",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("DPoP {}", token.as_str())),
            ("DPoP", &proof(&f.key, token.as_str())),
        ],
    )
    .await
    .problem(403, "policy.denied", false);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM personal_invitation_admission WHERE kind=2").await,
        0,
        "rejected principals must not select an Operator quota bucket"
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 0);
    assert_eq!(f.post(b"{}").await.status, 201);
    f.cleanup().await;
}

async fn revocation_after_preflight(f: Fixture) {
    let mut stream = f.pending_body().await;
    f.execute("UPDATE deployment_operators SET active=0").await;
    stream.write_all(b"{}").await.expect("complete delayed body");
    read_reply(&mut stream).await.problem(401, "auth.authentication_required", false);
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 0);
    f.cleanup().await;
}

async fn concurrent_issuance(f: Fixture) {
    f.reset_quota().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..15 {
        let address = f.address;
        let token = f.token.clone();
        tasks.spawn(async move {
            http(
                address,
                ROUTE,
                b"{}",
                &[
                    ("Content-Type", "application/json"),
                    ("Authorization", &format!("DPoP {token}")),
                    ("DPoP", &proof(&key(1), &token)),
                ],
            )
            .await
        });
    }
    let mut successes = 0;
    while let Some(reply) = tasks.join_next().await {
        let reply = reply.expect("request task");
        if reply.status == 201 {
            successes += 1;
        } else {
            reply.problem(429, "auth.rate_limited", false);
        }
    }
    assert_eq!(successes, 10, "concurrent issuance shares one durable Operator quota");
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 10);
    f.cleanup().await;
}

async fn replica_source_quota(f: Fixture, replica: AuthBackend) {
    f.reset_quota().await;
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..40 {
        let backend = if index % 2 == 0 { f.backend.clone() } else { replica.clone() };
        let source = if index % 2 == 0 { "127.0.0.1" } else { "::ffff:127.0.0.1" };
        tasks.spawn(async move {
            backend
                .invitation_source(source.parse().expect("peer"))
                .await
                .expect("durable source admission")
        });
    }
    let mut admitted = 0;
    while let Some(decision) = tasks.join_next().await {
        match decision.expect("admission task") {
            PersonalAdmissionDecision::Admitted => admitted += 1,
            PersonalAdmissionDecision::RateLimited(delay) => assert!((1..=60).contains(&delay)),
        }
    }
    assert_eq!(admitted, 30, "independent pools and IPv4-mapped peers share the same quota");
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitation_admission WHERE kind=1").await, 1);
    assert_eq!(
        f.count(
            "SELECT CAST(SUM(attempts) AS BIGINT) FROM personal_invitation_admission WHERE kind=1"
        )
        .await,
        30
    );
    match &replica {
        AuthBackend::Sqlite(store) => store.pool().close().await,
        AuthBackend::Postgres(store) => store.pool().close().await,
    }
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_invitation_source_quota_across_replicas() {
    let f = Fixture::sqlite().await;
    let replica =
        SqliteStore::open(&f.directory.join("store.sqlite")).await.expect("independent pool");
    replica_source_quota(f, AuthBackend::Sqlite(Arc::new(replica))).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_invitation_source_quota_across_replicas() {
    let f = Fixture::postgres().await;
    let schema = &f.postgres.as_ref().expect("owned schema").1;
    let mut url = Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("database URL"))
        .expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let replica =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("independent pool");
    replica_source_quota(f, AuthBackend::Postgres(Arc::new(replica))).await;
}

#[tokio::test]
async fn sqlite_real_http_invitation_principal_and_scope() {
    principal_and_scope(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_invitation_rechecks_revocation() {
    revocation_after_preflight(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_invitation_concurrent_quota() {
    concurrent_issuance(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_invitation_uncertain_commit() {
    let f = Fixture::sqlite().await;
    f.execute("CREATE TABLE invitation_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE invitation_commit_child (id INTEGER REFERENCES invitation_commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER invitation_commit_failure AFTER INSERT ON personal_invitations BEGIN INSERT INTO invitation_commit_child VALUES (1); END").await;
    f.post(b"{}").await.problem(503, "auth.commit_outcome_unknown", true);
    assert_eq!(f.count("SELECT COUNT(*) FROM personal_invitations").await, 0);
    f.execute("DROP TRIGGER invitation_commit_failure").await;
    assert_eq!(f.post(b"{}").await.status, 201);
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_principal_and_scope() {
    principal_and_scope(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_rechecks_revocation() {
    revocation_after_preflight(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_concurrent_quota() {
    concurrent_issuance(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_lost_commit_ack() {
    use std::sync::atomic::Ordering;
    let f = Fixture::postgres().await;
    let AuthBackend::Postgres(direct) = &f.backend else { unreachable!() };
    let schema = &f.postgres.as_ref().expect("owned schema").1;
    let mut url = Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("database URL"))
        .expect("URL");
    let application = format!("invitation_lost_{}", Uuid::new_v4().simple());
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"))
        .append_pair("application_name", &application);
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let store =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    let kms = Arc::new(LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS"));
    let proxied = Fixture::listen(
        AuthBackend::Postgres(Arc::new(store)),
        directory(),
        kms,
        f.token.clone(),
        key(1),
    )
    .await;
    // Withhold the body until all source, replay, current-session and Operator-admission commits finish.
    let mut stream = proxied.pending_body().await;
    let mut barrier = direct.pool().begin().await.expect("issuance barrier");
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048,1397052243)")
        .execute(&mut *barrier)
        .await
        .expect("hold session lock");
    stream.write_all(b"{}").await.expect("release body");
    tokio::time::timeout(std::time::Duration::from_secs(10),async {
        loop {
            let waiting:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name=$1 AND l.locktype='advisory' AND l.classid=1396916048 AND l.objid=1397052243 AND l.objsubid=2 AND NOT l.granted").bind(&application).fetch_one(direct.pool()).await.expect("observe final issuance guard");
            if waiting>0 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("issuance reaches its transaction-local guard");
    let audit_before = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    proxy.armed.store(true, Ordering::SeqCst);
    barrier.commit().await.expect("release issuance");
    read_reply(&mut stream).await.problem(503, "auth.commit_outcome_unknown", true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM personal_invitations").await,
        1,
        "issuance committed despite the withheld acknowledgement"
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM deployment_audit_events").await,
        audit_before + 2,
        "issuance and safe unknown-outcome failure both audit"
    );
    proxied.cleanup().await;
    drop(proxy);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_invitation_lifecycle() {
    lifecycle(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_invitation_guards() {
    guards(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_invitation_quotas() {
    quotas(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_invitation_audit_rollback() {
    audit_rollback(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_lifecycle() {
    lifecycle(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_guards() {
    guards(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_quotas() {
    quotas(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_invitation_audit_rollback() {
    audit_rollback(Fixture::postgres().await).await;
}
