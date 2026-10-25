// SPDX-License-Identifier: AGPL-3.0-only

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use scoplen_api::account_admission::{
    AccountBootstrapSnapshot, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
    AccountPasswordOptionsRequest, AccountPasswordOptionsResponse, AccountRegistrationPayload,
};
use scoplen_crypto::{
    Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets,
    SecretBytes, SecretVec, account_capability_digest,
};
use scoplen_store::{
    RelationalStore as _, SqliteStore,
    account_bootstrap::create_sqlite_password_account_in_transaction,
    account_entry_admission::AccountEntryAdmissionDecision, kms::LocalKeyFile,
};
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};
use uuid::Uuid;

use super::*;
use crate::account_entry::tests::{Reply, directory, exchange, http, serve_router, stop};

const ORIGIN: &str = "https://example.com";
const OPTIONS: &str = "/api/v1/auth/accounts/password/options";
const LOGIN: &str = "/api/v1/auth/accounts/password/login";
const FUTURE: i64 = 4_000_000_020_000;

struct Fixture {
    state: Arc<EntryState>,
    address: SocketAddr,
    server: JoinHandle<()>,
    directory: PathBuf,
    audit_connection: Mutex<Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>>,
    #[cfg(feature = "postgres-integration")]
    postgres: Option<(sqlx::PgPool, String)>,
}

impl Fixture {
    async fn sqlite(initialize: bool) -> Self {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
        let fixture = Self::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
        if initialize {
            fixture.initialize().await;
        }
        fixture
    }

    #[cfg(feature = "postgres-integration")]
    async fn postgres(initialize: bool) -> Self {
        let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
        let mut fixture = Self::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
        fixture.postgres = Some((admin, schema));
        if initialize {
            fixture.initialize().await;
        }
        fixture
    }

    async fn start(backend: AuthBackend, directory: PathBuf) -> Self {
        let path = directory.join("kms.key");
        std::fs::write(&path, "07".repeat(32)).expect("owned fixture KMS file");
        let state = Arc::new(EntryState {
            origin: ORIGIN.into(),
            backend,
            settings: crate::AccountSettings {
                registration_enabled: false,
                ..crate::AccountSettings::default()
            },
            proof_jobs: Semaphore::new(16),
            kms: Arc::new(LocalKeyFile::load(path).expect("fixture KMS")),
        });
        let (address, server) = serve_router(routes().with_state(state.clone())).await;
        Self {
            state,
            address,
            server,
            directory,
            audit_connection: Mutex::new(None),
            #[cfg(feature = "postgres-integration")]
            postgres: None,
        }
    }

    async fn initialize(&self) {
        match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                store.ensure_account_probe_key(self.state.kms.as_ref()).await.expect("probe key");
            }
            AuthBackend::Postgres(store) => {
                store.ensure_account_probe_key(self.state.kms.as_ref()).await.expect("probe key");
            }
        }
        self.execute("UPDATE account_entry_state SET time_high_water_ms=4000000020000").await;
    }

    async fn establish(&self, username: &str) -> (AccountRegistrationPayload, PasswordSecrets) {
        let (payload, secrets) = registration(username);
        match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                store.initialize_account_id_retention(16).await.expect("retention initialization");
                let mut tx = store.pool().begin().await.expect("fixture transaction");
                create_sqlite_password_account_in_transaction(
                    &mut tx, ORIGIN, 16, &payload, FUTURE,
                )
                .await
                .expect("complete signed password aggregate");
                tx.commit().await.expect("fixture commit");
            }
            AuthBackend::Postgres(store) => {
                store.initialize_account_id_retention(16).await.expect("retention initialization");
                let mut tx = store.pool().begin().await.expect("fixture transaction");
                scoplen_store::account_bootstrap::create_postgres_password_account_in_transaction(
                    &mut tx, ORIGIN, 16, &payload, FUTURE,
                )
                .await
                .expect("complete signed password aggregate");
                tx.commit().await.expect("fixture commit");
            }
        }
        (payload, secrets)
    }

    async fn execute(&self, query: &str) {
        match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::raw_sql(query)
                    .execute(store.pool())
                    .await
                    .expect("owned SQLite fixture update");
            }
            AuthBackend::Postgres(store) => {
                sqlx::raw_sql(query)
                    .execute(store.pool())
                    .await
                    .expect("owned PostgreSQL fixture update");
            }
        }
    }

    async fn count(&self, query: &str) -> i64 {
        match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query_scalar(query).fetch_one(store.pool()).await.expect("fixture count")
            }
            AuthBackend::Postgres(store) => {
                sqlx::query_scalar(query).fetch_one(store.pool()).await.expect("fixture count")
            }
        }
    }

    async fn bytes(&self, query: &str) -> Vec<u8> {
        match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query_scalar(query).fetch_one(store.pool()).await.expect("fixture bytes")
            }
            AuthBackend::Postgres(store) => {
                sqlx::query_scalar(query).fetch_one(store.pool()).await.expect("fixture bytes")
            }
        }
    }

    async fn options(&self, username: &str) -> Reply {
        let body = AccountPasswordOptionsRequest { username: username.into() }
            .to_json()
            .expect("options body");
        http(self.address, "POST", OPTIONS, &body, &[("Content-Type", "application/json")]).await
    }

    async fn login(&self, attempt: SecretBytes<32>, secret: SecretBytes<32>) -> Reply {
        let body = login_body(attempt, secret);
        http(self.address, "POST", LOGIN, body.as_bytes(), &[("Content-Type", "application/json")])
            .await
    }

    async fn fault_audit(&self, enabled: bool) {
        if let AuthBackend::Sqlite(store) = &self.state.backend {
            let mut owned = self.audit_connection.lock().await;
            if enabled {
                assert!(owned.is_none());
                let mut connection =
                    store.pool().acquire().await.expect("owned audit fault connection");
                sqlx::query("CREATE TRIGGER password_http_audit_fault BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END")
                    .execute(&mut *connection).await.expect("owned audit fault");
                *owned = Some(connection);
            } else {
                let mut connection = owned.take().expect("retained audit fault connection");
                sqlx::query("DROP TRIGGER password_http_audit_fault")
                    .execute(&mut *connection)
                    .await
                    .expect("remove owned audit fault on its creating connection");
            }
            return;
        }
        let query = if enabled {
            "CREATE FUNCTION password_http_audit_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''unavailable''; END'; CREATE TRIGGER password_http_audit_fault BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION password_http_audit_fault()"
        } else {
            "DROP TRIGGER password_http_audit_fault ON deployment_audit_events; DROP FUNCTION password_http_audit_fault()"
        };
        self.execute(query).await;
    }

    async fn corrupt_probe(&self) {
        let query = "UPDATE account_password_probe_key SET encrypted_key=$1";
        match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query(query)
                    .bind(vec![0_u8; 73])
                    .execute(store.pool())
                    .await
                    .expect("owned corruption");
            }
            AuthBackend::Postgres(store) => {
                sqlx::query(query)
                    .bind(vec![0_u8; 73])
                    .execute(store.pool())
                    .await
                    .expect("owned corruption");
            }
        }
    }

    async fn exhaust_source(&self, endpoint: AccountEntryEndpoint) {
        let source = self.address.ip();
        for _ in 0..=30 {
            let decision = match &self.state.backend {
                AuthBackend::Sqlite(store) => {
                    store.admit_account_entry_source(endpoint, source).await
                }
                AuthBackend::Postgres(store) => {
                    store.admit_account_entry_source(endpoint, source).await
                }
            }
            .expect("source admission");
            if matches!(decision, AccountEntryAdmissionDecision::RateLimited(_)) {
                return;
            }
        }
        panic!("source admission must be bounded");
    }

    async fn close(self) {
        stop(self.server).await;
        drop(self.audit_connection.into_inner());
        match &self.state.backend {
            AuthBackend::Sqlite(store) => store.pool().close().await,
            AuthBackend::Postgres(store) => store.pool().close().await,
        }
        #[cfg(feature = "postgres-integration")]
        if let Some((admin, schema)) = self.postgres {
            crate::account_entry::tests::postgres_cleanup(admin, schema).await;
        }
        drop(self.state);
        crate::test_support::remove_test_directory(self.directory).await;
    }
}

fn registration(username: &str) -> (AccountRegistrationPayload, PasswordSecrets) {
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account signing key");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let device = P256SigningKey::from_bytes(&scalar).expect("Device signing key");
    let identity = crate::test_legacy_identity::LegacyIdentity::new(&signing, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        username,
        SecretVec::new(b"a password for real HTTP bootstrap".to_vec()),
    )
    .expect("password derivation");
    let context = PasswordBootstrapContext::new(
        secrets.context().clone(),
        identity.account_id,
        identity.personal_vault_id,
        &identity.account_signing_public_key,
        &identity.account_kem_public_key,
        1,
    )
    .expect("password bootstrap context");
    let payload = AccountRegistrationPayload {
        operation_id: Uuid::now_v7(),
        origin: ORIGIN.into(),
        username: username.into(),
        account_id: identity.account_id,
        personal_vault_id: identity.personal_vault_id,
        device_id: identity.device_certificate.device_id,
        account_signing_public_key: identity.account_signing_public_key,
        account_kem_public_key: identity.account_kem_public_key,
        password_salt: *secrets.context().salt(),
        verifier: *secrets.verifier().as_bytes(),
        password_ark: PasswordArkWrap::seal(&secrets, &context, &SecretBytes::new([11; 32]))
            .expect("encrypted password ARK")
            .encode(),
        device_certificate: identity.device_certificate.encode().expect("certificate"),
        key_bundle: identity.key_bundle_update.to_cbor().expect("signed complete PUT"),
        personal_wrapped_key: identity.wrapped_personal_vault_key.try_into().expect("Personal key"),
    };
    (payload, secrets)
}

fn login_body(attempt_id: SecretBytes<32>, auth_secret: SecretBytes<32>) -> SecretVec {
    AccountPasswordLoginRequest { attempt_id, auth_secret }.to_json().expect("login body")
}

fn issued(reply: &Reply) -> AccountPasswordOptionsResponse {
    assert_eq!(reply.status, 200);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.body.len() <= 1_024);
    AccountPasswordOptionsResponse::from_json(&reply.body).expect("published options response")
}

fn authenticated(reply: &Reply) -> AccountPasswordLoginResponse {
    assert_eq!(reply.status, 200);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.body.len() <= 12_587_008);
    AccountPasswordLoginResponse::from_json(&reply.body).expect("published login response")
}

fn rate(reply: &Reply) {
    reply.problem(429, "auth.rate_limited", true);
    let wait: u16 =
        reply.header("retry-after").expect("Retry-After").parse().expect("rate seconds");
    assert!((1..=300).contains(&wait));
    let expected =
        scoplen_api::auth::AuthRateLimitHeaders::new(wait).expect("bounded rate profile");
    assert_eq!(reply.header("ratelimit-policy"), Some(expected.rate_limit_policy()));
    assert_eq!(reply.header("ratelimit"), Some(expected.rate_limit().as_str()));
}

fn problem_without_instance(reply: &Reply) -> serde_json::Value {
    let mut problem: serde_json::Value = serde_json::from_slice(&reply.body).expect("problem JSON");
    problem.as_object_mut().expect("problem object").remove("instance");
    problem
}

async fn lifecycle(fixture: &Fixture) {
    let (payload, secrets) = fixture.establish("password-user").await;
    let options = issued(&fixture.options("password-user").await);
    assert_eq!(options.salt, payload.password_salt);
    assert_eq!(options.expires_at_ms, u64::try_from(FUTURE + 120_000).expect("options expiry"));
    let raw = fixture.login(options.attempt_id.clone(), secrets.auth_secret().clone()).await;
    let login = authenticated(&raw);
    assert_eq!(login.expires_at_ms, u64::try_from(FUTURE + 300_000).expect("capability expiry"));
    let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes())
        .expect("complete verified bootstrap");
    assert_eq!(snapshot.origin, ORIGIN);
    assert_eq!(snapshot.username, "password-user");
    assert_eq!(snapshot.account_id, payload.account_id);
    assert_eq!(snapshot.personal_vault_id, payload.personal_vault_id);
    assert_eq!(snapshot.key_bundle, payload.key_bundle);
    assert_eq!(snapshot.certificates, vec![payload.device_certificate]);
    assert_eq!(snapshot.password_ark, payload.password_ark);
    assert_eq!(snapshot.personal.epochs.len(), 1);
    assert_eq!(
        fixture.bytes("SELECT token_digest FROM account_admission_capabilities").await,
        account_capability_digest(login.admission_token.as_bytes())
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 0);
    for query in [
        "SELECT COUNT(*) FROM identity_accounts",
        "SELECT COUNT(*) FROM identity_devices",
        "SELECT COUNT(*) FROM sync_personal_vaults",
        "SELECT COUNT(*) FROM account_admission_capabilities",
    ] {
        assert_eq!(fixture.count(query).await, 1);
    }
    fixture.login(options.attempt_id, secrets.auth_secret().clone()).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 1);
}

async fn generic_denials(fixture: &Fixture) {
    let _ = fixture.establish("known-user").await;
    let known = issued(&fixture.options("known-user").await);
    let wrong = fixture.login(known.attempt_id, SecretBytes::new([5; 32])).await;
    wrong.problem(401, "auth.authentication_required", false);
    fixture
        .execute("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+1001")
        .await;
    let unknown = issued(&fixture.options("unknown-user").await);
    let repeated = issued(&fixture.options("unknown-user").await);
    assert_eq!(unknown.salt, repeated.salt);
    assert_ne!(unknown.attempt_id, repeated.attempt_id);
    let denied = fixture.login(unknown.attempt_id, SecretBytes::new([6; 32])).await;
    denied.problem(401, "auth.authentication_required", false);
    assert_eq!(problem_without_instance(&wrong), problem_without_instance(&denied));
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 1);
}

async fn strict_requests(fixture: &Fixture) {
    let options = issued(&fixture.options("strict-user").await);
    let login = login_body(options.attempt_id, SecretBytes::new([8; 32]));
    for (route, valid, limit) in [
        (OPTIONS, b"{\"username\":\"strict-user\"}".as_slice(), 256),
        (LOGIN, login.as_bytes(), 512),
    ] {
        for header in ["Authorization", "DPoP", "Cookie", "Idempotency-Key", "If-Match"] {
            http(
                fixture.address,
                "POST",
                route,
                valid,
                &[("Content-Type", "application/json"), (header, "")],
            )
            .await
            .problem(400, "auth.invalid_request", false);
        }
        http(fixture.address, "POST", route, valid, &[]).await.problem(
            415,
            "auth.invalid_request",
            false,
        );
        http(
            fixture.address,
            "POST",
            route,
            valid,
            &[("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
        )
        .await
        .problem(415, "auth.invalid_request", false);
        http(
            fixture.address,
            "POST",
            route,
            valid,
            &[("Content-Type", "application/json"), ("Origin", "https://other.test")],
        )
        .await
        .problem(403, "policy.denied", false);
        http(
            fixture.address,
            "POST",
            &format!("{route}?"),
            valid,
            &[("Content-Type", "application/json")],
        )
        .await
        .problem(400, "auth.invalid_request", false);
        for body in [
            b"{\"username\":\"strict-user\",\"username\":\"strict-user\"}".to_vec(),
            b"{\"unknown\":true}".to_vec(),
            [b"\xef\xbb\xbf".as_slice(), valid].concat(),
            vec![0xff],
        ] {
            http(fixture.address, "POST", route, &body, &[("Content-Type", "application/json")])
                .await
                .problem(400, "auth.invalid_request", false);
        }
        let method = http(fixture.address, "OPTIONS", route, &[], &[]).await;
        method.problem(405, "auth.invalid_request", false);
        assert_eq!(method.header("allow"), Some("POST"));
        let wire = format!(
            "POST {route} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            limit + 1
        );
        exchange(fixture.address, wire.as_bytes()).await.problem(
            413,
            "auth.invalid_request",
            false,
        );
        let oversized = vec![b' '; limit + 1];
        let wire = format!(
            "POST {route} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            oversized.len(),
            String::from_utf8(oversized).expect("ASCII body")
        );
        exchange(fixture.address, wire.as_bytes()).await.problem(
            413,
            "auth.invalid_request",
            false,
        );
    }
    for field in ["attempt_id", "auth_secret"] {
        let mut oversized: serde_json::Value =
            serde_json::from_slice(login.as_bytes()).expect("valid login fixture");
        oversized[field] = serde_json::Value::String("A".repeat(44));
        let body = serde_json::to_vec(&oversized).expect("oversized decoded field");
        assert!(body.len() < 512, "field limit is independent of whole-body limit");
        http(fixture.address, "POST", LOGIN, &body, &[("Content-Type", "application/json")])
            .await
            .problem(413, "auth.invalid_request", false);
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 0);
}

async fn source_before_body(fixture: &Fixture) {
    let _ = issued(&fixture.options("rate-user").await);
    for (route, endpoint) in [
        (OPTIONS, AccountEntryEndpoint::PasswordOptions),
        (LOGIN, AccountEntryEndpoint::PasswordLogin),
    ] {
        fixture.exhaust_source(endpoint).await;
        let wire = format!(
            "POST {route} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 256\r\nX-Forwarded-For: 192.0.2.1\r\nConnection: close\r\n\r\n"
        );
        rate(&exchange(fixture.address, wire.as_bytes()).await);
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 1);
}

async fn concurrency_before_body(fixture: &Fixture) {
    let _ = issued(&fixture.options("concurrency-user").await);
    let permits =
        fixture.state.proof_jobs.acquire_many(16).await.expect("occupy validation capacity");
    let wire = format!(
        "POST {LOGIN} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n"
    );
    rate(&exchange(fixture.address, wire.as_bytes()).await);
    let _ = issued(&fixture.options("concurrency-user").await);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 2);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 0);
    drop(permits);
}

async fn probe_fail_closed(fixture: &Fixture) {
    fixture.options("missing-key-user").await.problem(503, "auth.storage_unavailable", true);
    fixture.login(SecretBytes::new([1; 32]), SecretBytes::new([2; 32])).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    assert_eq!(
        fixture
            .count(
                "SELECT COUNT(*) FROM account_password_probe_key WHERE encrypted_key IS NOT NULL"
            )
            .await,
        0
    );
    fixture.initialize().await;
    fixture.corrupt_probe().await;
    fixture.options("corrupt-key-user").await.problem(503, "auth.storage_unavailable", true);
    fixture.login(SecretBytes::new([1; 32]), SecretBytes::new([2; 32])).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    assert_eq!(
        fixture.bytes("SELECT encrypted_key FROM account_password_probe_key").await,
        vec![0; 73]
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 0);
}

async fn audit_fail_closed(fixture: &Fixture) {
    let (_, secrets) = fixture.establish("audit-user").await;
    let options = issued(&fixture.options("audit-user").await);
    fixture.fault_audit(true).await;
    for route in [OPTIONS, LOGIN] {
        http(fixture.address, "POST", route, &[], &[]).await.problem(
            503,
            "auth.storage_unavailable",
            true,
        );
    }
    fixture.login(options.attempt_id.clone(), SecretBytes::new([3; 32])).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 0);
    fixture.fault_audit(false).await;
    let _ = authenticated(&fixture.login(options.attempt_id, secrets.auth_secret().clone()).await);
}

async fn unsupported_bootstrap(fixture: &Fixture) {
    let (_, secrets) = fixture.establish("transition-user").await;
    let options = issued(&fixture.options("transition-user").await);
    fixture.execute("UPDATE sync_vaults SET rotation_pending=TRUE").await;
    fixture.login(options.attempt_id, secrets.auth_secret().clone()).await.problem(
        409,
        "auth.admission_conflict",
        false,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 0);
    fixture.execute("UPDATE sync_vaults SET rotation_pending=FALSE").await;
    let options = issued(&fixture.options("transition-user").await);
    let _ = authenticated(&fixture.login(options.attempt_id, secrets.auth_secret().clone()).await);
}

async fn private_and_capability_limits(fixture: &Fixture) {
    let (_, secrets) = fixture.establish("capacity-user").await;
    for index in 0..5 {
        let options = issued(&fixture.options("capacity-user").await);
        let reply = fixture.login(options.attempt_id, secrets.auth_secret().clone()).await;
        if index < 4 {
            let _ = authenticated(&reply);
        } else {
            rate(&reply);
        }
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await, 4);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM account_password_attempts").await, 1);
    for _ in 0..10 {
        let _ = issued(&fixture.options("unknown-capacity-user").await);
    }
    rate(&fixture.options("unknown-capacity-user").await);
}

macro_rules! backends {
    ($sqlite:ident, $postgres:ident, $initialize:expr, $scenario:ident) => {
        #[tokio::test]
        async fn $sqlite() {
            let fixture = Fixture::sqlite($initialize).await;
            $scenario(&fixture).await;
            fixture.close().await;
        }

        #[cfg(feature = "postgres-integration")]
        #[tokio::test]
        async fn $postgres() {
            let fixture = Fixture::postgres($initialize).await;
            $scenario(&fixture).await;
            fixture.close().await;
        }
    };
}

backends!(sqlite_http_password_lifecycle, postgres_http_password_lifecycle, true, lifecycle);
backends!(
    sqlite_http_password_generic_denials,
    postgres_http_password_generic_denials,
    true,
    generic_denials
);
backends!(
    sqlite_http_password_strict_requests,
    postgres_http_password_strict_requests,
    true,
    strict_requests
);
backends!(
    sqlite_http_password_source_before_body,
    postgres_http_password_source_before_body,
    true,
    source_before_body
);
backends!(
    sqlite_http_password_concurrency_before_body,
    postgres_http_password_concurrency_before_body,
    true,
    concurrency_before_body
);
backends!(
    sqlite_http_password_probe_fail_closed,
    postgres_http_password_probe_fail_closed,
    false,
    probe_fail_closed
);
backends!(
    sqlite_http_password_audit_fail_closed,
    postgres_http_password_audit_fail_closed,
    true,
    audit_fail_closed
);
backends!(
    sqlite_http_password_unsupported_bootstrap,
    postgres_http_password_unsupported_bootstrap,
    true,
    unsupported_bootstrap
);
backends!(
    sqlite_http_password_private_and_capability_limits,
    postgres_http_password_private_and_capability_limits,
    true,
    private_and_capability_limits
);

#[cfg(feature = "postgres-integration")]
async fn lost_commit_ack(login: bool) {
    use std::sync::atomic::Ordering;

    let fixture = Fixture::postgres(true).await;
    let (_, secrets) = fixture.establish("lost-response-user").await;
    let body = if login {
        let options = issued(&fixture.options("lost-response-user").await);
        login_body(options.attempt_id, secrets.auth_secret().clone())
    } else {
        SecretVec::new(
            AccountPasswordOptionsRequest { username: "lost-response-user".into() }
                .to_json()
                .expect("options body"),
        )
    };
    let schema = &fixture.postgres.as_ref().expect("isolated PostgreSQL schema").1;
    let mut url =
        url::Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("fixture URL"))
            .expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    // Source admission commits first. Drop only the following options/capability COMMIT reply.
    let proxy = crate::test_lost_commit::LostCommitProxy::start_skipping(url.as_str(), 1).await;
    let store =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    let state = Arc::new(EntryState {
        origin: ORIGIN.into(),
        backend: AuthBackend::Postgres(Arc::new(store.clone())),
        settings: crate::AccountSettings::default(),
        proof_jobs: Semaphore::new(16),
        kms: fixture.state.kms.clone(),
    });
    let (address, server) = serve_router(routes().with_state(state)).await;
    proxy.armed.store(true, Ordering::SeqCst);
    let reply = http(
        address,
        "POST",
        if login { LOGIN } else { OPTIONS },
        body.as_bytes(),
        &[("Content-Type", "application/json")],
    )
    .await;
    reply.problem(503, "auth.storage_unavailable", true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let problem: serde_json::Value = serde_json::from_slice(&reply.body).expect("problem JSON");
    for secret in ["attempt_id", "admission_token", "snapshot", "access_token", "refresh_token"] {
        assert!(problem.get(secret).is_none());
    }
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM account_password_attempts").await,
        i64::from(!login)
    );
    assert_eq!(
        fixture.count("SELECT COUNT(*) FROM account_admission_capabilities").await,
        i64::from(login)
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM identity_accounts").await, 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM identity_devices").await, 1);
    stop(server).await;
    store.pool().close().await;
    drop(store);
    drop(proxy);
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_http_password_login_lost_commit_ack_discloses_no_capability() {
    lost_commit_ack(true).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_http_password_options_lost_commit_ack_discloses_no_attempt() {
    lost_commit_ack(false).await;
}
