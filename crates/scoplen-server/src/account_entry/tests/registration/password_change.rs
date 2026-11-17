// SPDX-License-Identifier: AGPL-3.0-only

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::account_admission::{
    AccountPasswordChangeConfirmation, AccountPasswordChangePayload, AccountPasswordChangeRequest,
};
use scoplen_crypto::{account_bootstrap_digest, account_capability_digest};

use super::*;

const CHANGE: &str = "/api/v1/auth/accounts/password-changes";
const OPTIONS: &str = "/api/v1/auth/accounts/password/options";
const LOGIN: &str = "/api/v1/auth/accounts/password/login";

struct Change {
    payload: AccountPasswordChangePayload,
    token: SecretBytes<32>,
    auth_secret: SecretBytes<32>,
}

impl Change {
    fn new(account: &Registration, login: &AccountPasswordLoginResponse, password: &[u8]) -> Self {
        let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes())
            .expect("complete verified snapshot");
        let secrets =
            PasswordSecrets::create(ORIGIN, &snapshot.username, SecretVec::new(password.to_vec()))
                .expect("different real password derivation");
        let next = snapshot.credential_generation.checked_add(1).expect("next generation");
        let context = PasswordBootstrapContext::new(
            secrets.context().clone(),
            snapshot.account_id,
            snapshot.personal_vault_id,
            &snapshot.account_signing_public_key,
            &snapshot.account_kem_public_key,
            next,
        )
        .expect("next password context");
        let wrapper = PasswordArkWrap::seal(&secrets, &context, &SecretBytes::new([11; 32]))
            .expect("same ARK wrapped under new password");
        assert_eq!(
            wrapper.open(&secrets, &context).expect("local new wrapper opening"),
            SecretBytes::new([11; 32])
        );
        Self {
            payload: AccountPasswordChangePayload {
                operation_id: Uuid::now_v7(),
                origin: ORIGIN.into(),
                username: snapshot.username,
                account_id: snapshot.account_id,
                personal_vault_id: snapshot.personal_vault_id,
                device_id: account.payload.device_id,
                credential_generation: snapshot.credential_generation,
                new_credential_generation: next,
                snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
                capability_digest: account_capability_digest(login.admission_token.as_bytes()),
                password_salt: *secrets.context().salt(),
                verifier: *secrets.verifier().as_bytes(),
                password_ark: wrapper.encode(),
            },
            token: login.admission_token.clone(),
            auth_secret: secrets.auth_secret().clone(),
        }
    }

    async fn request(
        &self,
        address: SocketAddr,
        account: &Registration,
        intent: AccountRequestIntent,
    ) -> AccountPasswordChangeRequest {
        self.request_with_payload(
            address,
            account,
            intent,
            self.payload.to_cbor().expect("retained protected password change"),
        )
        .await
    }

    async fn request_with_payload(
        &self,
        address: SocketAddr,
        account: &Registration,
        intent: AccountRequestIntent,
        payload: Vec<u8>,
    ) -> AccountPasswordChangeRequest {
        let binding = AccountRequestChallengeRequest {
            kind: AccountRequestKind::PasswordChange,
            intent,
            operation_id: self.payload.operation_id,
            device_id: self.payload.device_id,
        };
        let reply =
            http(address, "POST", ROUTE, &binding.to_json().expect("challenge request"), JSON)
                .await;
        assert_eq!(reply.status, 200);
        reply.private();
        let challenge =
            AccountRequestChallengeResponse::from_json(&reply.body).expect("fresh challenge");
        let input = AccountRequestSignatureInput::new(AccountRequestKind::PasswordChange, &payload)
            .expect("password change domain");
        let account_signature = input.sign(&account.root);
        let device_proof = AccountRequestProof::new(
            AccountRequestKind::PasswordChange,
            intent,
            ORIGIN,
            challenge.attempt_id.as_bytes(),
            challenge.nonce.as_bytes(),
            self.payload.operation_id,
            self.payload.device_id,
            &input.request_digest(&account_signature),
        )
        .expect("existing Device possession context")
        .sign(&account.device)
        .expect("existing Device proof");
        AccountPasswordChangeRequest {
            intent,
            payload: SecretVec::new(payload),
            account_signature,
            attempt_id: challenge.attempt_id,
            nonce: challenge.nonce,
            device_proof,
            admission_token: (intent == AccountRequestIntent::Submit).then(|| self.token.clone()),
        }
    }
}

async fn register(address: SocketAddr) -> Registration {
    let account = Registration::new();
    let request = account.request(address, AccountRequestIntent::Submit).await;
    let reply =
        http(address, "POST", REGISTER, &request.to_json().expect("registration"), JSON).await;
    committed(&reply, &request, 201);
    account
}

async fn login(
    address: SocketAddr,
    account: &Registration,
    secret: &SecretBytes<32>,
) -> AccountPasswordLoginResponse {
    let reply = password_login(address, &account.payload.username, secret).await;
    assert_eq!(reply.status, 200);
    reply.private();
    AccountPasswordLoginResponse::from_json(&reply.body).expect("current password bootstrap")
}

async fn password_login(address: SocketAddr, username: &str, secret: &SecretBytes<32>) -> Reply {
    let body =
        AccountPasswordOptionsRequest { username: username.into() }.to_json().expect("options");
    let reply = http(address, "POST", OPTIONS, &body, JSON).await;
    assert_eq!(reply.status, 200);
    reply.private();
    let options = AccountPasswordOptionsResponse::from_json(&reply.body).expect("password options");
    let body =
        AccountPasswordLoginRequest { attempt_id: options.attempt_id, auth_secret: secret.clone() }
            .to_json()
            .expect("login");
    http(address, "POST", LOGIN, body.as_bytes(), JSON).await
}

fn changed(reply: &Reply, request: &AccountPasswordChangeRequest, status: u16) {
    assert_eq!(reply.status, status);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.body.len() <= 1_024);
    AccountPasswordChangeConfirmation::from_json(&reply.body)
        .expect("bounded receipt")
        .validate_for_request(request.payload.as_bytes(), &request.account_signature)
        .expect("exact original operation");
    let value: serde_json::Value = serde_json::from_slice(&reply.body).expect("receipt JSON");
    assert_eq!(value.as_object().expect("receipt object").len(), 8);
}

fn non_successor_payload(candidate: &Change) -> Vec<u8> {
    let bytes = candidate.payload.to_cbor().expect("valid initial protected map");
    let mut value: ciborium::value::Value =
        ciborium::de::from_reader(bytes.as_slice()).expect("independent CBOR reader");
    let ciborium::value::Value::Map(fields) = &mut value else { panic!("protected map") };
    let (_, generation) = fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("new_credential_generation"))
        .expect("next generation field");
    *generation =
        ciborium::value::Value::Integer((candidate.payload.credential_generation + 2).into());
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("independent canonical-map writer");
    bytes
}

// The public strict encoder deliberately rejects this authenticated conflict fixture.
fn independent_request(request: &AccountPasswordChangeRequest) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "intent": if request.intent == AccountRequestIntent::Submit { "submit" } else { "confirm" },
        "payload": URL_SAFE_NO_PAD.encode(request.payload.as_bytes()),
        "account_signature": URL_SAFE_NO_PAD.encode(request.account_signature),
        "attempt_id": URL_SAFE_NO_PAD.encode(request.attempt_id.as_bytes()),
        "nonce": URL_SAFE_NO_PAD.encode(request.nonce.as_bytes()),
        "device_proof": URL_SAFE_NO_PAD.encode(request.device_proof),
        "admission_token": request.admission_token.as_ref().map(|token| URL_SAFE_NO_PAD.encode(token.as_bytes())),
    })).expect("independent native JSON producer")
}

macro_rules! checked_denials {
    ($store:expr, $backend:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(32).await.expect("retention");
        store.ensure_account_probe_key(test_kms().as_ref()).await.expect("probe");
        let (address, server) = serve_with_settings($backend, settings(true)).await;
        let account = register(address).await;
        let candidate = Change::new(
            &account,
            &login(address, &account, &account.auth_secret).await,
            b"non-successor password proposal for HTTP",
        );
        let request = candidate
            .request_with_payload(
                address,
                &account,
                AccountRequestIntent::Submit,
                non_successor_payload(&candidate),
            )
            .await;
        assert!(AccountPasswordChangeRequest::to_json(&request).is_err());
        http(address, "POST", CHANGE, &independent_request(&request), JSON).await.problem(
            409,
            "auth.admission_conflict",
            false,
        );
        let mut reused = Change::new(
            &account,
            &login(address, &account, &account.auth_secret).await,
            b"reused-operation password proposal for HTTP",
        );
        reused.payload.operation_id = account.payload.operation_id;
        let request = reused.request(address, &account, AccountRequestIntent::Submit).await;
        http(address, "POST", CHANGE, &request.to_json().expect("existing operation submit"), JSON)
            .await
            .problem(409, "auth.admission_conflict", false);
        let missing = Change::new(
            &account,
            &login(address, &account, &account.auth_secret).await,
            b"missing-receipt password proposal for HTTP",
        );
        let request = missing.request(address, &account, AccountRequestIntent::Confirm).await;
        http(address, "POST", CHANGE, &request.to_json().expect("missing original receipt"), JSON)
            .await
            .problem(401, "auth.authentication_required", false);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut candidate = Change::new(
            &account,
            &login(address, &account, &account.auth_secret).await,
            b"committed password proposal for receipt checks",
        );
        let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
        let created =
            http(address, "POST", CHANGE, &request.to_json().expect("confirmed change"), JSON)
                .await;
        changed(&created, &request, 201);
        candidate.payload.verifier[0] ^= 1;
        let request = candidate.request(address, &account, AccountRequestIntent::Confirm).await;
        http(
            address,
            "POST",
            CHANGE,
            &request.to_json().expect("different protected payload"),
            JSON,
        )
        .await
        .problem(401, "auth.authentication_required", false);
        tokio::time::sleep(Duration::from_secs(1)).await;
        candidate.payload.verifier[0] ^= 1;
        let request = candidate.request(address, &account, AccountRequestIntent::Confirm).await;
        let reply = http(
            address,
            "POST",
            CHANGE,
            &request.to_json().expect("exact original receipt"),
            JSON,
        )
        .await;
        changed(&reply, &request, 200);
        assert_eq!(reply.body, created.body);
        let login = login(address, &account, &candidate.auth_secret).await;
        let snapshot =
            AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes()).expect("current reader");
        assert_eq!(snapshot.credential_generation, 2);
        assert_eq!(snapshot.key_bundle, account.payload.key_bundle);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_operation_receipts")
                .fetch_one(store.pool())
                .await
                .expect("no denied operation receipt"),
            2
        );
        stop(server).await;
    }};
}

#[tokio::test]
async fn sqlite_password_change_http_checked_conflicts_and_inexact_receipts_never_mutate() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    checked_denials!(store, AuthBackend::Sqlite(Arc::new(store.clone())));
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_change_http_checked_conflicts_and_inexact_receipts_never_mutate() {
    let (store, admin, schema, _) = postgres_fixture().await;
    checked_denials!(store, AuthBackend::Postgres(Arc::new(store.clone())));
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}

macro_rules! lifecycle {
    ($store:expr, $backend:expr) => {{
        let store = &$store;
        store.initialize_account_id_retention(32).await.expect("retention");
        store.ensure_account_probe_key(test_kms().as_ref()).await.expect("probe initialization");
        let (address, server) = serve_with_settings($backend, settings(true)).await;
        let account = register(address).await;
        let original_login = login(address, &account, &account.auth_secret).await;
        let original = AccountBootstrapSnapshot::from_cbor(original_login.snapshot.as_bytes())
            .expect("original snapshot");
        let candidate =
            Change::new(&account, &original_login, b"different password for HTTP lifecycle");
        let stale = Change::new(
            &account,
            &login(address, &account, &account.auth_secret).await,
            b"stale password proposal for HTTP lifecycle",
        );
        let mut invalid = candidate.request(address, &account, AccountRequestIntent::Submit).await;
        invalid.device_proof[0] ^= 1;
        http(address, "POST", CHANGE, &invalid.to_json().expect("invalid proof envelope"), JSON)
            .await
            .problem(401, "auth.authentication_required", false);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
        let created =
            http(address, "POST", CHANGE, &request.to_json().expect("change"), JSON).await;
        changed(&created, &request, 201);
        let stale_request = stale.request(address, &account, AccountRequestIntent::Submit).await;
        http(address, "POST", CHANGE, &stale_request.to_json().expect("stale"), JSON)
            .await
            .problem(409, "auth.admission_conflict", false);
        let current_login = login(address, &account, &candidate.auth_secret).await;
        let current = AccountBootstrapSnapshot::from_cbor(current_login.snapshot.as_bytes())
            .expect("next generation reader");
        let mut expected = original.clone();
        expected.credential_generation = 2;
        expected.password_salt = candidate.payload.password_salt;
        expected.password_ark = candidate.payload.password_ark;
        assert_eq!(current, expected, "every non-password artifact is unchanged");
        password_login(address, &account.payload.username, &account.auth_secret).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        let later =
            Change::new(&account, &current_login, b"another different password for HTTP lifecycle");
        let request = later.request(address, &account, AccountRequestIntent::Submit).await;
        let reply =
            http(address, "POST", CHANGE, &request.to_json().expect("later change"), JSON).await;
        changed(&reply, &request, 201);
        let audits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("success audits before confirmation");
        for _ in 0..2 {
            let confirmation =
                candidate.request(address, &account, AccountRequestIntent::Confirm).await;
            let reply =
                http(address, "POST", CHANGE, &confirmation.to_json().expect("confirmation"), JSON)
                    .await;
            changed(&reply, &confirmation, 200);
            assert_eq!(
                reply.body, created.body,
                "receipt remains historical after generation three"
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployment_audit_events")
                .fetch_one(store.pool())
                .await
                .expect("no duplicate audit"),
            audits
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM identity_devices")
                .fetch_one(store.pool())
                .await
                .expect("same Device"),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_operation_receipts")
                .fetch_one(store.pool())
                .await
                .expect("one receipt for each business operation"),
            3
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("consumed shared capabilities"),
            0
        );
        let final_login = login(address, &account, &later.auth_secret).await;
        let final_snapshot = AccountBootstrapSnapshot::from_cbor(final_login.snapshot.as_bytes())
            .expect("generation three reader");
        assert_eq!(final_snapshot.credential_generation, 3);
        assert_eq!(final_snapshot.key_bundle, original.key_bundle);
        assert_eq!(final_snapshot.certificates, original.certificates);
        assert_eq!(final_snapshot.personal, original.personal);
        stop(server).await;
    }};
}

#[tokio::test]
async fn sqlite_password_change_http_preserves_artifacts_and_original_historical_receipts() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    lifecycle!(store, AuthBackend::Sqlite(Arc::new(store.clone())));
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_change_http_preserves_artifacts_and_original_historical_receipts() {
    let (store, admin, schema, _) = postgres_fixture().await;
    lifecycle!(store, AuthBackend::Postgres(Arc::new(store.clone())));
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}

#[tokio::test]
async fn sqlite_password_change_http_audit_failure_rolls_back_password_receipt_and_claims() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    store.initialize_account_id_retention(32).await.expect("retention");
    store.ensure_account_probe_key(test_kms().as_ref()).await.expect("probe");
    let (address, server) =
        serve_with_settings(AuthBackend::Sqlite(Arc::new(store.clone())), settings(true)).await;
    let account = register(address).await;
    let candidate = Change::new(
        &account,
        &login(address, &account, &account.auth_secret).await,
        b"a different password for audit rollback",
    );
    let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
    sqlx::query("CREATE TRIGGER fail_password_change_http_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END")
        .execute(store.pool()).await.expect("owned audit failure");
    http(address, "POST", CHANGE, &request.to_json().expect("change"), JSON).await.problem(
        503,
        "auth.storage_unavailable",
        true,
    );
    for (table, expected) in [
        ("account_operation_receipts", 1_i64),
        ("account_admission_capabilities", 1),
        ("account_request_challenges", 1),
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .expect("rolled back atomic claims"),
            expected
        );
    }
    sqlx::query("DROP TRIGGER fail_password_change_http_audit")
        .execute(store.pool())
        .await
        .expect("remove owned audit fault");
    let current = login(address, &account, &account.auth_secret).await;
    let snapshot = AccountBootstrapSnapshot::from_cbor(current.snapshot.as_bytes())
        .expect("unchanged generation one");
    assert_eq!(snapshot.credential_generation, 1);
    assert_eq!(snapshot.password_salt, account.payload.password_salt);
    assert_eq!(snapshot.password_ark, account.payload.password_ark);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_password_change_http_metadata_and_body_bounds_preserve_live_proofs() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    store.initialize_account_id_retention(32).await.expect("retention");
    store.ensure_account_probe_key(test_kms().as_ref()).await.expect("probe");
    let (address, server) =
        serve_with_settings(AuthBackend::Sqlite(Arc::new(store.clone())), settings(true)).await;
    let account = register(address).await;
    let candidate = Change::new(
        &account,
        &login(address, &account, &account.auth_secret).await,
        b"a different password for metadata checks",
    );
    let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
    let body = request.to_json().expect("valid body");
    for (name, value) in [
        ("Authorization", "DPoP ignored"),
        ("DPoP", "ignored"),
        ("Cookie", "ignored=value"),
        ("Idempotency-Key", "ignored"),
        ("If-Match", "ignored"),
    ] {
        http(
            address,
            "POST",
            CHANGE,
            &body,
            &[("Content-Type", "application/json"), (name, value)],
        )
        .await
        .problem(400, "auth.invalid_request", false);
    }
    http(address, "POST", &format!("{CHANGE}?extra=1"), &body, JSON).await.problem(
        400,
        "auth.invalid_request",
        false,
    );
    http(address, "POST", CHANGE, &body, &[("Content-Type", "text/plain")]).await.problem(
        415,
        "auth.invalid_request",
        false,
    );
    http(address, "POST", CHANGE, &vec![b' '; 16_385], JSON).await.problem(
        413,
        "auth.invalid_request",
        false,
    );
    let reply = http(address, "POST", CHANGE, &body, JSON).await;
    changed(&reply, &request, 201);
    stop(server).await;
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_change_http_lost_commit_requires_exact_fresh_confirmation() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, database) = postgres_fixture().await;
    store.initialize_account_id_retention(32).await.expect("retention");
    store.ensure_account_probe_key(test_kms().as_ref()).await.expect("probe");
    let (address, server) =
        serve_with_settings(AuthBackend::Postgres(Arc::new(store.clone())), settings(true)).await;
    let account = register(address).await;
    let candidate = Change::new(
        &account,
        &login(address, &account, &account.auth_secret).await,
        b"a different password for lost commit",
    );
    stop(server).await;
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), 2).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy store");
    let (address, server) =
        serve_with_settings(AuthBackend::Postgres(Arc::new(proxied.clone())), settings(true)).await;
    let request = candidate.request(address, &account, AccountRequestIntent::Submit).await;
    proxy.armed.store(true, Ordering::SeqCst);
    let unknown = http(address, "POST", CHANGE, &request.to_json().expect("change"), JSON).await;
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
        serve_with_settings(AuthBackend::Postgres(Arc::new(store.clone())), settings(true)).await;
    let confirmation = candidate.request(address, &account, AccountRequestIntent::Confirm).await;
    let reply = http(
        address,
        "POST",
        CHANGE,
        &confirmation.to_json().expect("exact original confirmation"),
        JSON,
    )
    .await;
    changed(&reply, &confirmation, 200);
    stop(server).await;
    let proxy =
        crate::test_lost_commit::LostCommitProxy::start_skipping(database.as_str(), 2).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy store");
    let (address, server) =
        serve_with_settings(AuthBackend::Postgres(Arc::new(proxied.clone())), settings(true)).await;
    let confirmation = candidate.request(address, &account, AccountRequestIntent::Confirm).await;
    proxy.armed.store(true, Ordering::SeqCst);
    http(address, "POST", CHANGE, &confirmation.to_json().expect("confirmation"), JSON)
        .await
        .problem(503, "auth.storage_unavailable", true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    stop(server).await;
    proxied.pool().close().await;
    drop(proxy);
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}
