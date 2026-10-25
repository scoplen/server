// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_api::{
    account_admission::{AccountDeviceAdmissionPayload, AccountDeviceAdmissionRequest},
    auth::{AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthTokenResponse},
    sync::{
        SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundleUpdate,
        SyncSessionRequest, SyncSessionResponse, SyncVaultKeysResponse,
    },
};
use scoplen_crypto::{
    DeviceArkWrap, DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair, DpopProof, DpopTarget,
    DpopToken, account_bootstrap_digest, account_capability_digest,
};
use scoplen_store::{ObjectStorage, ObjectStorageConfig};
use scoplen_sync::{
    http::{ReadBodyLimits, WriteBodyLimits, WriteRateLimits},
    notify::NotificationHub,
};

use super::*;

const ADMIT: &str = "/api/v1/auth/accounts/device-admissions";

async fn serve_api(backend: AuthBackend, directory: &Path) -> (SocketAddr, JoinHandle<()>) {
    let kms = test_kms();
    prepare(&backend, kms.as_ref(), settings(true)).await.expect("production entry startup");
    let database = match backend {
        AuthBackend::Sqlite(store) => crate::runtime::ListenerDatabase::Sqlite(store),
        AuthBackend::Postgres(store) => crate::runtime::ListenerDatabase::Postgres(store),
    };
    let storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
        root: directory.join("objects"),
    })
    .expect("owned object storage");
    serve_router(crate::runtime::api_router_with_notifications(
        database,
        Arc::new(storage),
        kms,
        ORIGIN.into(),
        true,
        WriteRateLimits::default(),
        WriteBodyLimits::default(),
        ReadBodyLimits::default(),
        NotificationHub::default(),
        settings(true),
    ))
    .await
}

async fn register_account(address: SocketAddr) -> Registration {
    let fixture = Registration::new();
    let request = fixture.request(address, AccountRequestIntent::Submit).await;
    let reply =
        http(address, "POST", REGISTER, &request.to_json().expect("registration"), JSON).await;
    committed(&reply, &request, 201);
    fixture
}

async fn login(address: SocketAddr, account: &Registration) -> AccountPasswordLoginResponse {
    let options = AccountPasswordOptionsRequest { username: account.payload.username.clone() };
    let reply = http(
        address,
        "POST",
        "/api/v1/auth/accounts/password/options",
        &options.to_json().expect("options"),
        JSON,
    )
    .await;
    assert_eq!(reply.status, 200);
    reply.private();
    let options = AccountPasswordOptionsResponse::from_json(&reply.body).expect("options response");
    assert_eq!(options.salt, account.payload.password_salt);
    let request = AccountPasswordLoginRequest {
        attempt_id: options.attempt_id,
        auth_secret: account.auth_secret.clone(),
    }
    .to_json()
    .expect("password login");
    let reply =
        http(address, "POST", "/api/v1/auth/accounts/password/login", request.as_bytes(), JSON)
            .await;
    assert_eq!(reply.status, 200);
    reply.private();
    AccountPasswordLoginResponse::from_json(&reply.body).expect("complete public bootstrap")
}

struct Candidate {
    payload: AccountDeviceAdmissionPayload,
    signer: P256SigningKey,
    kem: DeviceKemKeyPair,
    token: SecretBytes<32>,
}

impl Candidate {
    fn new(account: &Registration, login: &AccountPasswordLoginResponse, seed: u8) -> Self {
        let snapshot =
            AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes()).expect("snapshot");
        assert_eq!(snapshot.account_id, account.payload.account_id);
        assert_eq!(snapshot.personal_vault_id, account.payload.personal_vault_id);
        let mut scalar = [0; 32];
        scalar[31] = seed;
        let signer = P256SigningKey::from_bytes(&scalar).expect("new Device signing key");
        scalar[31] += 100;
        let kem = DeviceKemKeyPair::from_private_bytes(&scalar).expect("new independent KEM");
        let device_id = Uuid::now_v7();
        let certificate = DeviceCertificate::issue(
            &account.root,
            device_id,
            snapshot.account_id,
            signer.public_key_sec1(),
            kem.public_key().to_vec(),
            "Independent HTTP Device".into(),
            "test".into(),
            1,
        )
        .expect("root-signed certificate")
        .encode()
        .expect("certificate artifact");
        let mut bundle =
            SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).expect("old PUT");
        bundle.revision += 1;
        bundle.device_wraps.push(SyncAccountDeviceWrap {
            device_id,
            wrapped_ark: DeviceArkWrap::seal(
                snapshot.account_id,
                device_id,
                kem.public_key(),
                &SecretBytes::new([11; 32]),
            )
            .expect("new Device ARK")
            .encode()
            .to_vec(),
        });
        bundle.device_wraps.sort_by_key(|wrap| wrap.device_id);
        bundle.signature =
            account.root.sign(&bundle.signature_input().expect("next PUT input")).to_vec();
        Self {
            payload: AccountDeviceAdmissionPayload {
                operation_id: Uuid::now_v7(),
                origin: ORIGIN.into(),
                username: snapshot.username,
                account_id: snapshot.account_id,
                personal_vault_id: snapshot.personal_vault_id,
                device_id,
                credential_generation: snapshot.credential_generation,
                snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
                capability_digest: account_capability_digest(login.admission_token.as_bytes()),
                device_certificate: certificate,
                key_bundle: bundle.to_cbor().expect("signed next PUT"),
            },
            signer,
            kem,
            token: login.admission_token.clone(),
        }
    }

    async fn request(
        &self,
        address: SocketAddr,
        account: &Registration,
        intent: AccountRequestIntent,
    ) -> AccountDeviceAdmissionRequest {
        let binding = AccountRequestChallengeRequest {
            kind: AccountRequestKind::Admit,
            intent,
            operation_id: self.payload.operation_id,
            device_id: self.payload.device_id,
        };
        let reply = http(address, "POST", ROUTE, &binding.to_json().expect("binding"), JSON).await;
        assert_eq!(reply.status, 200);
        reply.private();
        let challenge =
            AccountRequestChallengeResponse::from_json(&reply.body).expect("fresh challenge");
        let payload = self.payload.to_cbor().expect("retained admission payload");
        let input = AccountRequestSignatureInput::new(AccountRequestKind::Admit, &payload)
            .expect("Account input");
        let account_signature = input.sign(&account.root);
        let proof = AccountRequestProof::new(
            AccountRequestKind::Admit,
            intent,
            ORIGIN,
            challenge.attempt_id.as_bytes(),
            challenge.nonce.as_bytes(),
            self.payload.operation_id,
            self.payload.device_id,
            &input.request_digest(&account_signature),
        )
        .expect("fresh Device possession");
        AccountDeviceAdmissionRequest {
            intent,
            payload: SecretVec::new(payload),
            account_signature,
            attempt_id: challenge.attempt_id,
            nonce: challenge.nonce,
            device_proof: proof.sign(&self.signer).expect("Device proof"),
            admission_token: (intent == AccountRequestIntent::Submit).then(|| self.token.clone()),
        }
    }
}

fn admission_committed(reply: &Reply, request: &AccountDeviceAdmissionRequest, status: u16) {
    assert_eq!(reply.status, status);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    AccountCommittedConfirmation::from_json(&reply.body)
        .expect("bounded confirmation")
        .validate_for_request(
            AccountRequestKind::Admit,
            request.payload.as_bytes(),
            &request.account_signature,
        )
        .expect("exact original admitted facts");
    let fields: serde_json::Value = serde_json::from_slice(&reply.body).expect("JSON");
    for forbidden in ["access_token", "refresh_token", "admission_token", "snapshot", "verifier"] {
        assert!(fields.get(forbidden).is_none());
    }
}

async fn protected(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    token: &str,
    signer: &P256SigningKey,
) -> Reply {
    let target = DpopTarget::new(method, ORIGIN, path).expect("protected target");
    let proof = DpopProof::sign(
        signer,
        &signer.public_key_sec1(),
        &target,
        DpopToken::Protected(token),
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs(),
        None,
    )
    .expect("DPoP proof");
    http(
        address,
        method,
        path,
        body,
        &[
            ("Content-Type", "application/cbor"),
            ("Origin", ORIGIN),
            ("Authorization", &format!("DPoP {token}")),
            ("DPoP", proof.as_str()),
        ],
    )
    .await
}

async fn authenticate_and_sync(address: SocketAddr, candidate: &Candidate) {
    let device_id = candidate.payload.device_id;
    let request =
        AuthChallengeRequest::new(device_id).expect("Device challenge").to_json().expect("JSON");
    let reply = http(address, "POST", "/api/v1/auth/challenge", request.as_bytes(), JSON).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let challenge =
        AuthChallengeResponse::from_json(std::str::from_utf8(&reply.body).expect("JSON text"))
            .expect("ordinary Device challenge");
    let context =
        DeviceAuthContext::new(ORIGIN, &challenge.nonce, device_id).expect("Device auth context");
    let mut signature = String::new();
    for byte in candidate.signer.sign(&context.signature_input()) {
        write!(signature, "{byte:02x}").expect("signature encoding");
    }
    let request = AuthDeviceRequest::new(device_id, &challenge.nonce, signature)
        .expect("Device proof")
        .to_json()
        .expect("JSON");
    let reply = http(address, "POST", "/api/v1/auth/device", request.as_bytes(), JSON).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let token = AuthTokenResponse::from_json(std::str::from_utf8(&reply.body).expect("JSON text"))
        .expect("ordinary native token")
        .access_token;
    let request =
        SyncSessionRequest { client_version: "0.1.0".into(), model_version: 1, device_id }
            .to_cbor()
            .expect("session request");
    let reply =
        protected(address, "POST", "/sync/v1/session", &request, &token, &candidate.signer).await;
    assert_eq!(reply.status, 200);
    let session = SyncSessionResponse::from_cbor(&reply.body).expect("same Account session");
    assert_eq!(session.vaults.len(), 1);
    assert_eq!(session.vaults[0].id, candidate.payload.personal_vault_id);
    let reply = protected(address, "GET", "/sync/v1/keys", &[], &token, &candidate.signer).await;
    assert_eq!(reply.status, 200);
    let bundle = SyncAccountKeyBundle::from_cbor(&reply.body).expect("current K-4 projection");
    assert_eq!(bundle.revision, 2);
    assert!(bundle.certificates.contains(&candidate.payload.device_certificate));
    assert_eq!(
        DeviceArkWrap::decode(&bundle.wrapped_ark)
            .expect("Device wrap")
            .open(candidate.payload.account_id, device_id, &candidate.kem)
            .expect("new Device decrypts its ARK"),
        SecretBytes::new([11; 32])
    );
    let path = format!("/sync/v1/vaults/{}/keys", candidate.payload.personal_vault_id);
    let reply = protected(address, "GET", &path, &[], &token, &candidate.signer).await;
    assert_eq!(reply.status, 200);
    let keys = SyncVaultKeysResponse::from_cbor(&reply.body).expect("same Personal vault key");
    assert_eq!(keys.keys.len(), 1);
}

macro_rules! public_lifecycle {
    ($store:expr, $backend:expr, $directory:expr) => {{
        let store = &$store;
        let (address, server) = serve_api($backend, $directory).await;
        let account = register_account(address).await;
        let candidate = Candidate::new(&account, &login(address, &account).await, 9);
        let stale = Candidate::new(&account, &login(address, &account).await, 10);
        let mut invalid = candidate.request(address, &account, AccountRequestIntent::Submit).await;
        invalid.device_proof[0] ^= 1;
        http(address, "POST", ADMIT, &invalid.to_json().expect("invalid proof body"), JSON)
            .await
            .problem(401, "auth.authentication_required", false);
        // The admitted denial cools both the source and Device for one second.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
        let admitted =
            http(address, "POST", ADMIT, &request.to_json().expect("admission"), JSON).await;
        admission_committed(&admitted, &request, 201);
        let audits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("audit before confirmation");
        let confirmation =
            candidate.request(address, &account, AccountRequestIntent::Confirm).await;
        let confirmed =
            http(address, "POST", ADMIT, &confirmation.to_json().expect("confirmation"), JSON)
                .await;
        admission_committed(&confirmed, &confirmation, 200);
        assert_eq!(admitted.body, confirmed.body);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployment_audit_events")
                .fetch_one(store.pool())
                .await
                .expect("receipt-only audit count"),
            audits
        );
        let stale = stale.request(address, &account, AccountRequestIntent::Submit).await;
        http(address, "POST", ADMIT, &stale.to_json().expect("stale snapshot"), JSON)
            .await
            .problem(409, "auth.admission_conflict", false);
        for (table, expected) in [
            ("identity_accounts", 1_i64),
            ("identity_devices", 2),
            ("account_operation_receipts", 2),
            ("account_admission_capabilities", 0),
        ] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(store.pool())
                    .await
                    .expect("atomic aggregate"),
                expected
            );
        }
        authenticate_and_sync(address, &candidate).await;
        stop(server).await;
    }};
}

#[tokio::test]
async fn sqlite_admission_public_registration_login_device_auth_and_k4_session() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    public_lifecycle!(store, AuthBackend::Sqlite(Arc::new(store.clone())), &directory);
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_admission_public_registration_login_device_auth_and_k4_session() {
    let (store, admin, schema, _) = postgres_fixture().await;
    let directory = directory();
    public_lifecycle!(store, AuthBackend::Postgres(Arc::new(store.clone())), &directory);
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_admission_metadata_methods_and_encoded_decoded_limits_are_bounded() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    for (path, headers, status, code) in [
        (ADMIT, vec![], 415, "auth.invalid_request"),
        (
            ADMIT,
            vec![("Content-Type", "application/json"), ("Origin", "https://other.test")],
            403,
            "policy.denied",
        ),
        (
            ADMIT,
            vec![("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
            415,
            "auth.invalid_request",
        ),
        (
            ADMIT,
            vec![("Content-Type", "application/json"), ("Content-Type", "application/json")],
            400,
            "auth.invalid_request",
        ),
        ("/api/v1/auth/accounts/device-admissions?", JSON.to_vec(), 400, "auth.invalid_request"),
    ] {
        http(address, "POST", path, b"{}", &headers).await.problem(status, code, false);
    }
    for forbidden in ["Authorization", "DPoP", "Cookie", "Idempotency-Key", "If-Match"] {
        http(
            address,
            "POST",
            ADMIT,
            b"{}",
            &[("Content-Type", "application/json"), (forbidden, "")],
        )
        .await
        .problem(400, "auth.invalid_request", false);
    }
    let denied = http(address, "OPTIONS", ADMIT, &[], &[]).await;
    denied.problem(405, "auth.invalid_request", false);
    assert_eq!(denied.header("allow"), Some("POST"));
    let wire = format!(
        "POST {ADMIT} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 6291457\r\nConnection: close\r\n\r\n"
    );
    exchange(address, wire.as_bytes()).await.problem(413, "auth.invalid_request", false);
    let encoded = "x".repeat(6_291_457);
    let wire = format!(
        "POST {ADMIT} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{encoded}\r\n0\r\n\r\n",
        encoded.len()
    );
    exchange(address, wire.as_bytes()).await.problem(413, "auth.invalid_request", false);
    let malformed = br#"{"intent":"submit","payload":"","account_signature":"","attempt_id":"","nonce":"","device_proof":"","admission_token":""}"#;
    http(address, "POST", ADMIT, malformed, JSON).await.problem(400, "auth.invalid_request", false);
    let mut oversized: serde_json::Value = serde_json::from_slice(malformed).expect("JSON");
    oversized["admission_token"] = serde_json::Value::String("A".repeat(44));
    http(address, "POST", ADMIT, &serde_json::to_vec(&oversized).expect("field overage"), JSON)
        .await
        .problem(413, "auth.invalid_request", false);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM identity_devices")
            .fetch_one(store.pool())
            .await
            .expect("no business mutation"),
        0
    );
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_admission_source_and_shared_proof_capacity_reject_before_body() {
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
    let permits = state.proof_jobs.acquire_many(16).await.expect("all entry proof jobs held");
    let (address, server) = serve_router(routes().with_state(state.clone())).await;
    let incomplete = format!(
        "POST {ADMIT} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 6291456\r\nX-Forwarded-For: 192.0.2.50\r\nConnection: close\r\n\r\n"
    );
    let reply = exchange(address, incomplete.as_bytes()).await;
    reply.problem(429, "auth.rate_limited", true);
    let wait: u16 = reply.header("retry-after").expect("rate delay").parse().expect("seconds");
    let rate = scoplen_api::auth::AuthRateLimitHeaders::new(wait).expect("common rate profile");
    assert_eq!(reply.header("ratelimit-policy"), Some(rate.rate_limit_policy()));
    assert_eq!(reply.header("ratelimit"), Some(rate.rate_limit().as_str()));
    drop(permits);
    http(address, "POST", ADMIT, b"{}", JSON).await.problem(400, "auth.invalid_request", false);
    for _ in 0..28 {
        assert_eq!(
            store
                .admit_account_entry_source(
                    AccountEntryEndpoint::DeviceAdmission,
                    "127.0.0.1".parse().expect("actual peer")
                )
                .await
                .expect("source debt"),
            AccountEntryAdmissionDecision::Admitted
        );
    }
    exchange(address, incomplete.as_bytes()).await.problem(429, "auth.rate_limited", true);
    assert_eq!(state.proof_jobs.available_permits(), 16);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_admission_stalled_body_expires_and_releases_proof_capacity() {
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
    let wire = format!(
        "POST {ADMIT} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{{"
    );
    exchange_with_budget(address, wire.as_bytes(), Duration::from_secs(25)).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    assert_eq!(state.proof_jobs.available_permits(), 16);
    http(address, "POST", ADMIT, b"{}", JSON).await.problem(400, "auth.invalid_request", false);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_admission_audit_failure_overrides_http_denial() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    sqlx::query("CREATE TRIGGER fail_admission_http_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END")
        .execute(store.pool()).await.expect("owned audit fault");
    let (address, server) = serve(AuthBackend::Sqlite(Arc::new(store.clone()))).await;
    http(address, "POST", ADMIT, b"{}", JSON).await.problem(503, "auth.storage_unavailable", true);
    sqlx::query("DROP TRIGGER fail_admission_http_audit")
        .execute(store.pool())
        .await
        .expect("remove owned fault");
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_admission_http_lost_commit_requires_exact_fresh_confirmation() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, database) = postgres_fixture().await;
    let directory = directory();
    let (address, server) =
        serve_api(AuthBackend::Postgres(Arc::new(store.clone())), &directory).await;
    let account = register_account(address).await;
    let candidate = Candidate::new(&account, &login(address, &account).await, 9);
    stop(server).await;
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), 2).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy store");
    let (address, server) = serve(AuthBackend::Postgres(Arc::new(proxied.clone()))).await;
    let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
    proxy.armed.store(true, Ordering::SeqCst);
    let reply = http(address, "POST", ADMIT, &request.to_json().expect("admission"), JSON).await;
    assert_eq!(reply.status, 503);
    reply.private();
    let problem: serde_json::Value = serde_json::from_slice(&reply.body).expect("problem");
    assert_eq!(problem["code"], "auth.commit_outcome_unknown");
    assert_eq!(problem["changed"], true);
    assert_eq!(problem["retryable"], false);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    stop(server).await;
    proxied.pool().close().await;
    drop(proxy);
    let (address, server) = serve(AuthBackend::Postgres(Arc::new(store.clone()))).await;
    let confirmation = candidate.request(address, &account, AccountRequestIntent::Confirm).await;
    let reply =
        http(address, "POST", ADMIT, &confirmation.to_json().expect("confirmation"), JSON).await;
    admission_committed(&reply, &confirmation, 200);
    stop(server).await;
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), 2).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy store");
    let (address, server) = serve(AuthBackend::Postgres(Arc::new(proxied.clone()))).await;
    let confirmation = candidate.request(address, &account, AccountRequestIntent::Confirm).await;
    proxy.armed.store(true, Ordering::SeqCst);
    http(address, "POST", ADMIT, &confirmation.to_json().expect("confirmation"), JSON)
        .await
        .problem(503, "auth.storage_unavailable", true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    stop(server).await;
    proxied.pool().close().await;
    drop(proxy);
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
    crate::test_support::remove_test_directory(directory).await;
}
