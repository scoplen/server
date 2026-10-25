// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_api::account_admission::{
    AccountBootstrapSnapshot, AccountCommittedConfirmation, AccountPasswordLoginRequest,
    AccountPasswordLoginResponse, AccountPasswordOptionsRequest, AccountPasswordOptionsResponse,
    AccountRegistrationPayload, AccountRegistrationRequest,
};
use scoplen_crypto::{
    AccountRequestProof, AccountRequestSignatureInput, Ed25519SigningKey, P256SigningKey,
    PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets, SecretBytes,
};

use super::*;

const REGISTER: &str = "/api/v1/auth/accounts/register";
const JSON: &[(&str, &str)] = &[("Content-Type", "application/json")];

mod admission;

struct Registration {
    payload: AccountRegistrationPayload,
    root: Ed25519SigningKey,
    device: P256SigningKey,
    auth_secret: SecretBytes<32>,
}

impl Registration {
    fn new() -> Self {
        let root = Ed25519SigningKey::from_bytes(&[7; 32]).expect("test Account key");
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let device = P256SigningKey::from_bytes(&scalar).expect("independent test Device key");
        let identity = crate::test_legacy_identity::LegacyIdentity::new(&root, &device);
        let secrets = PasswordSecrets::create(
            ORIGIN,
            "http-registration",
            SecretVec::new(b"a test password for HTTP registration".to_vec()),
        )
        .expect("real password derivation");
        let context = PasswordBootstrapContext::new(
            secrets.context().clone(),
            identity.account_id,
            identity.personal_vault_id,
            &identity.account_signing_public_key,
            &identity.account_kem_public_key,
            1,
        )
        .expect("bound password context");
        let payload = AccountRegistrationPayload {
            operation_id: Uuid::now_v7(),
            origin: ORIGIN.into(),
            username: "http-registration".into(),
            account_id: identity.account_id,
            personal_vault_id: identity.personal_vault_id,
            device_id: identity.device_certificate.device_id,
            account_signing_public_key: identity.account_signing_public_key,
            account_kem_public_key: identity.account_kem_public_key,
            password_salt: *secrets.context().salt(),
            verifier: *secrets.verifier().as_bytes(),
            password_ark: PasswordArkWrap::seal(&secrets, &context, &SecretBytes::new([11; 32]))
                .expect("bound password ARK")
                .encode(),
            device_certificate: identity.device_certificate.encode().expect("certificate"),
            key_bundle: identity.key_bundle_update.to_cbor().expect("signed PUT"),
            personal_wrapped_key: identity.wrapped_personal_vault_key.try_into().expect("wrap"),
        };
        payload.validate().expect("complete registration");
        Self { payload, root, device, auth_secret: secrets.auth_secret().clone() }
    }

    async fn request(
        &self,
        address: SocketAddr,
        intent: AccountRequestIntent,
    ) -> AccountRegistrationRequest {
        let binding = AccountRequestChallengeRequest {
            kind: AccountRequestKind::Register,
            intent,
            operation_id: self.payload.operation_id,
            device_id: self.payload.device_id,
        };
        let reply = http(address, "POST", ROUTE, &binding.to_json().expect("binding"), JSON).await;
        assert_eq!(reply.status, 200);
        reply.private();
        let challenge = AccountRequestChallengeResponse::from_json(&reply.body).expect("challenge");
        let payload = self.payload.to_cbor().expect("stable payload");
        let input = AccountRequestSignatureInput::new(AccountRequestKind::Register, &payload)
            .expect("Account signature input");
        let account_signature = input.sign(&self.root);
        let digest = input.request_digest(&account_signature);
        let proof = AccountRequestProof::new(
            AccountRequestKind::Register,
            intent,
            ORIGIN,
            challenge.attempt_id.as_bytes(),
            challenge.nonce.as_bytes(),
            self.payload.operation_id,
            self.payload.device_id,
            &digest,
        )
        .expect("fresh possession input");
        AccountRegistrationRequest {
            intent,
            payload: SecretVec::new(payload),
            account_signature,
            attempt_id: challenge.attempt_id,
            nonce: challenge.nonce,
            device_proof: proof.sign(&self.device).expect("fresh Device proof"),
        }
    }
}

fn settings(enabled: bool) -> AccountSettings {
    AccountSettings { registration_enabled: enabled, used_account_id_limit: 32 }
}

fn committed(reply: &Reply, request: &AccountRegistrationRequest, status: u16) {
    assert_eq!(reply.status, status);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let confirmation = AccountCommittedConfirmation::from_json(&reply.body).expect("confirmation");
    confirmation
        .validate_for_request(
            AccountRequestKind::Register,
            request.payload.as_bytes(),
            &request.account_signature,
        )
        .expect("only the exact original operation");
    let fields: serde_json::Value = serde_json::from_slice(&reply.body).expect("confirmation JSON");
    for forbidden in ["access_token", "refresh_token", "admission_token", "snapshot", "verifier"] {
        assert!(fields.get(forbidden).is_none());
    }
}

macro_rules! registration_lifecycle {
    ($store:expr, $backend:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(1).await.expect("retention initialization");
        store
            .ensure_account_probe_key(test_kms().as_ref())
            .await
            .expect("API probe initialization");
        let fixture = Registration::new();
        let policy = AccountSettings { used_account_id_limit: 1, ..settings(true) };
        let (address, server) = serve_with_settings($backend, policy).await;
        let request = fixture.request(address, AccountRequestIntent::Submit).await;
        let created =
            http(address, "POST", REGISTER, &request.to_json().expect("body"), JSON).await;
        committed(&created, &request, 201);
        let options = AccountPasswordOptionsRequest { username: fixture.payload.username.clone() }
            .to_json()
            .expect("password options body");
        let reply =
            http(address, "POST", "/api/v1/auth/accounts/password/options", &options, JSON).await;
        assert_eq!(reply.status, 200);
        reply.private();
        let options = AccountPasswordOptionsResponse::from_json(&reply.body)
            .expect("real registered password options");
        assert_eq!(options.salt, fixture.payload.password_salt);
        let login = AccountPasswordLoginRequest {
            attempt_id: options.attempt_id,
            auth_secret: fixture.auth_secret.clone(),
        }
        .to_json()
        .expect("password login body");
        let reply =
            http(address, "POST", "/api/v1/auth/accounts/password/login", login.as_bytes(), JSON)
                .await;
        assert_eq!(reply.status, 200);
        reply.private();
        let login = AccountPasswordLoginResponse::from_json(&reply.body)
            .expect("password bootstrap after public registration");
        let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes())
            .expect("complete current snapshot");
        assert_eq!(snapshot.account_id, fixture.payload.account_id);
        assert_eq!(snapshot.personal_vault_id, fixture.payload.personal_vault_id);
        assert_eq!(snapshot.key_bundle, fixture.payload.key_bundle);
        let audits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("initial audits");
        for table in [
            "identity_accounts",
            "identity_devices",
            "account_operation_receipts",
            "account_used_ids",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("one atomic aggregate");
            assert_eq!(count, 1);
        }
        stop(server).await;
        assert_eq!(
            store
                .account_id_retention_summary()
                .await
                .expect("exhausted registration capacity")
                .used,
            1
        );
        let (address, server) = serve_with_settings(
            $backend,
            AccountSettings { registration_enabled: false, ..policy },
        )
        .await;
        let confirmation = fixture.request(address, AccountRequestIntent::Confirm).await;
        let confirmed =
            http(address, "POST", REGISTER, &confirmation.to_json().expect("body"), JSON).await;
        committed(&confirmed, &confirmation, 200);
        assert_eq!(created.body, confirmed.body);
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("confirmation audits");
        assert_eq!(audits, after, "confirmation adds no duplicate success audit");
        let denied = fixture.request(address, AccountRequestIntent::Submit).await;
        http(address, "POST", REGISTER, &denied.to_json().expect("body"), JSON).await.problem(
            403,
            "policy.denied",
            false,
        );
        stop(server).await;
        let mut deletion = store.pool().begin().await.expect("owned Account deletion fixture");
        sqlx::query("DELETE FROM identity_devices WHERE account_id=$1")
            .bind(fixture.payload.account_id.as_bytes().as_slice())
            .execute(&mut *deletion)
            .await
            .expect("delete owned Device fixtures before Account");
        sqlx::query("DELETE FROM identity_accounts WHERE account_id=$1")
            .bind(fixture.payload.account_id.as_bytes().as_slice())
            .execute(&mut *deletion)
            .await
            .expect("delete owned Account fixture");
        deletion.commit().await.expect("commit owned Account deletion fixture");
        let (address, server) = serve_with_settings($backend, policy).await;
        let absent = fixture.request(address, AccountRequestIntent::Confirm).await;
        http(address, "POST", REGISTER, &absent.to_json().expect("body"), JSON).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
            .fetch_one(store.pool())
            .await
            .expect("no mutation fallback");
        assert_eq!(accounts, 0);
        assert_eq!(
            store.account_id_retention_summary().await.expect("permanent retention").used,
            1
        );
        stop(server).await;
    }};
}

#[tokio::test]
async fn sqlite_registration_http_creates_and_confirms_after_closure_without_recreation() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    registration_lifecycle!(store, AuthBackend::Sqlite(Arc::new(store.clone())));
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_registration_http_creates_and_confirms_after_closure_without_recreation() {
    let (store, admin, schema, _) = postgres_fixture().await;
    registration_lifecycle!(store, AuthBackend::Postgres(Arc::new(store.clone())));
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}

#[tokio::test]
async fn sqlite_registration_source_and_proof_capacity_reject_before_body() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=4000000020000")
        .execute(store.pool())
        .await
        .expect("stable source window");
    let state = Arc::new(EntryState {
        origin: ORIGIN.into(),
        backend: AuthBackend::Sqlite(Arc::new(store.clone())),
        settings: settings(true),
        proof_jobs: Semaphore::new(16),
        kms: test_kms(),
    });
    let permits = state.proof_jobs.acquire_many(16).await.expect("all proof workers busy");
    let (address, server) = serve_router(routes().with_state(state.clone())).await;
    let challenge = request().to_json().expect("independent challenge request");
    assert_eq!(http(address, "POST", ROUTE, &challenge, JSON).await.status, 200);
    let incomplete = format!(
        "POST {REGISTER} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 524288\r\nConnection: close\r\n\r\n"
    );
    let rejected = exchange(address, incomplete.as_bytes()).await;
    rejected.problem(429, "auth.rate_limited", true);
    assert!(rejected.header("retry-after").is_some());
    let login = incomplete.replace(REGISTER, "/api/v1/auth/accounts/password/login");
    exchange(address, login.as_bytes()).await.problem(429, "auth.rate_limited", true);
    drop(permits);
    http(address, "POST", REGISTER, b"{}", JSON).await.problem(400, "auth.invalid_request", false);
    for _ in 0..28 {
        assert_eq!(
            store
                .admit_account_entry_source(
                    AccountEntryEndpoint::Register,
                    "127.0.0.1".parse().expect("source")
                )
                .await
                .expect("source debt"),
            AccountEntryAdmissionDecision::Admitted
        );
    }
    exchange(address, incomplete.as_bytes()).await.problem(429, "auth.rate_limited", true);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
        .fetch_one(store.pool())
        .await
        .expect("no business dispatch");
    assert_eq!(count, 0);
    let challenges: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
        .fetch_one(store.pool())
        .await
        .expect("no protocol consumption on rate rejection");
    assert_eq!(challenges, 1);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_registration_metadata_chunked_and_method_failures_are_bounded() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    for (path, headers, status, code) in [
        (REGISTER, vec![], 415, "auth.invalid_request"),
        (
            REGISTER,
            vec![("Content-Type", "application/json"), ("Origin", "https://other.test")],
            403,
            "policy.denied",
        ),
        (
            REGISTER,
            vec![("Content-Type", "application/json"), ("Authorization", "Bearer rejected")],
            400,
            "auth.invalid_request",
        ),
        (
            REGISTER,
            vec![("Content-Type", "application/json"), ("Cookie", "rejected=1")],
            400,
            "auth.invalid_request",
        ),
        (
            REGISTER,
            vec![("Content-Type", "application/json"), ("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
        (
            REGISTER,
            vec![("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
            415,
            "auth.invalid_request",
        ),
        (
            "/api/v1/auth/accounts/register?intent=submit",
            JSON.to_vec(),
            400,
            "auth.invalid_request",
        ),
    ] {
        http(address, "POST", path, b"{}", &headers).await.problem(status, code, false);
    }
    let reply = http(address, "GET", REGISTER, b"", &[]).await;
    reply.problem(405, "auth.invalid_request", false);
    assert_eq!(reply.header("allow"), Some("POST"));
    let oversized_header = format!(
        "POST {REGISTER} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 524289\r\nConnection: close\r\n\r\n"
    );
    exchange(address, oversized_header.as_bytes()).await.problem(
        413,
        "auth.invalid_request",
        false,
    );
    let encoded = "x".repeat(524_289);
    let chunked = format!(
        "POST {REGISTER} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{encoded}\r\n0\r\n\r\n",
        encoded.len()
    );
    exchange(address, chunked.as_bytes()).await.problem(413, "auth.invalid_request", false);
    let trailer = format!(
        "POST {REGISTER} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: x-test\r\nConnection: close\r\n\r\n2\r\n{{}}\r\n0\r\nx-test: ignored\r\n\r\n"
    );
    exchange(address, trailer.as_bytes()).await.problem(400, "auth.invalid_request", false);
    assert!(store.deployment_audit_head().await.expect("mandatory denials").is_some());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_request_challenges")
        .fetch_one(store.pool())
        .await
        .expect("no transient claim");
    assert_eq!(count, 0);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_registration_audit_failure_overrides_http_denial() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let mut fault = store.pool().acquire().await.expect("owned fault connection");
    sqlx::query("CREATE TRIGGER fail_registration_http_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END")
        .execute(&mut *fault).await.expect("audit fault");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    http(address, "POST", REGISTER, b"{}", &[]).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    sqlx::query("DROP TRIGGER fail_registration_http_audit")
        .execute(&mut *fault)
        .await
        .expect("remove owned fault");
    drop(fault);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_registration_stalled_body_expires_and_releases_proof_capacity() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let state = Arc::new(EntryState {
        origin: ORIGIN.into(),
        backend: AuthBackend::Sqlite(Arc::new(store.clone())),
        settings: settings(true),
        proof_jobs: Semaphore::new(16),
        kms: test_kms(),
    });
    let (address, server) = serve_router(routes().with_state(state.clone())).await;
    let incomplete = format!(
        "POST {REGISTER} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{{"
    );
    exchange_with_budget(address, incomplete.as_bytes(), Duration::from_secs(25)).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    assert_eq!(state.proof_jobs.available_permits(), 16);
    http(address, "POST", REGISTER, b"{}", JSON).await.problem(400, "auth.invalid_request", false);
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_accounts")
        .fetch_one(store.pool())
        .await
        .expect("no business state after timeout");
    assert_eq!(accounts, 0);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_registration_invalid_possession_consumes_challenge_without_business_state() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    store.initialize_account_id_retention(32).await.expect("retention");
    let fixture = Registration::new();
    let (address, server) =
        serve_with_settings(AuthBackend::Sqlite(Arc::new(store.clone())), settings(true)).await;
    let mut request = fixture.request(address, AccountRequestIntent::Submit).await;
    request.device_proof[0] ^= 1;
    http(address, "POST", REGISTER, &request.to_json().expect("structurally valid envelope"), JSON)
        .await
        .problem(401, "auth.authentication_required", false);
    for table in [
        "account_request_challenges",
        "identity_accounts",
        "account_operation_receipts",
        "account_used_ids",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(store.pool())
            .await
            .expect("denial state");
        assert_eq!(count, 0);
    }
    assert!(store.deployment_audit_head().await.expect("mandatory denial audit").is_some());
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_registration_http_lost_commit_requires_exact_fresh_confirmation() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, database) = postgres_fixture().await;
    store.initialize_account_id_retention(32).await.expect("retention");
    let fixture = Registration::new();
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), 2).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy store");
    let (address, server) =
        serve_with_settings(AuthBackend::Postgres(Arc::new(proxied.clone())), settings(true)).await;
    let request = fixture.request(address, AccountRequestIntent::Submit).await;
    proxy.armed.store(true, Ordering::SeqCst);
    let unknown = http(address, "POST", REGISTER, &request.to_json().expect("body"), JSON).await;
    assert_eq!(unknown.status, 503);
    unknown.private();
    let problem: serde_json::Value = serde_json::from_slice(&unknown.body).expect("problem");
    assert_eq!(problem["code"], "auth.commit_outcome_unknown");
    assert_eq!(problem["changed"], true);
    assert_eq!(problem["retryable"], false);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    stop(server).await;
    proxied.pool().close().await;
    drop(proxy);
    let (address, server) =
        serve_with_settings(AuthBackend::Postgres(Arc::new(store.clone())), settings(false)).await;
    let confirmation = fixture.request(address, AccountRequestIntent::Confirm).await;
    let reply = http(address, "POST", REGISTER, &confirmation.to_json().expect("body"), JSON).await;
    committed(&reply, &confirmation, 200);
    stop(server).await;
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), 2).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy store");
    let (address, server) =
        serve_with_settings(AuthBackend::Postgres(Arc::new(proxied.clone())), settings(false))
            .await;
    let confirmation = fixture.request(address, AccountRequestIntent::Confirm).await;
    proxy.armed.store(true, Ordering::SeqCst);
    http(address, "POST", REGISTER, &confirmation.to_json().expect("body"), JSON).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    stop(server).await;
    proxied.pool().close().await;
    drop(proxy);
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}
