// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
#[path = "support/passkey.rs"]
mod passkey;
mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_crypto::{
    DpopProof, DpopTarget, DpopToken, OperatorAccessToken, P256SigningKey,
    TrustedOperatorAccessTokenKeys, dpop_jwk_thumbprint,
};
use scoplen_identity::operator_passkeys::{AssertionArtifacts, OperatorPasskeyVerifier};
use scoplen_store::{
    RelationalStore, SqliteStore,
    kms::KeyManagementService,
    operator_admission::{OperatorAuthEndpoint as Endpoint, OperatorPrivateBucket as Private},
    operator_sessions::{
        OperatorAuthentication, OperatorSessionError as Error, OperatorSessionResponse,
    },
    operator_setup::OperatorRegistration,
};
use sqlx::Row;
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use webauthn_authenticator_rs::prelude::Url;

const ORIGIN: &str = "https://operator.example.com:9443";
struct TestKms;
impl KeyManagementService for TestKms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &[71; 32]
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}
fn source() -> IpAddr {
    "192.0.2.90".parse().expect("source")
}
fn millis() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("time")
}
fn key(scalar: u8) -> P256SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    P256SigningKey::from_bytes(&bytes).expect("key")
}
fn proof(key: &P256SigningKey) -> DpopProof {
    DpopProof::sign(
        key,
        &key.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, "/api/v1/auth/refresh").expect("target"),
        DpopToken::Refresh,
        u64::try_from(millis() / 1000).expect("time"),
        None,
    )
    .expect("proof")
}
fn cookie(response: &OperatorSessionResponse) -> String {
    response
        .set_cookie()
        .strip_prefix("__Secure-spl-refresh=")
        .expect("cookie name")
        .split(';')
        .next()
        .expect("token")
        .to_owned()
}
async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("scoplen-operator-session-{}", Uuid::new_v4()));
    (SqliteStore::open(&dir.join("store.sqlite")).await.expect("SQLite"), dir)
}

macro_rules! setup {
    ($store:expr) => {{
        let store = &$store;
        let verifier = OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
        let disclosure = store
            .initialize_operator_setup(ORIGIN, false)
            .await
            .expect("init")
            .expect("setup token");
        let token: [u8; 32] = URL_SAFE_NO_PAD
            .decode(disclosure.expose_link().split("#token=").nth(1).expect("fragment"))
            .expect("canonical token")
            .try_into()
            .expect("token32");
        let binding = dpop_jwk_thumbprint(&key(1).public_key_sec1()).expect("JKT");
        let options = store
            .operator_setup_options(&token, &binding, &verifier)
            .await
            .expect("registration options");
        let mut auth = passkey::ResidentPasskey::authenticator();
        let registration = auth
            .do_registration(
                Url::parse(ORIGIN).expect("origin"),
                passkey::creation(&options.public_key),
            )
            .expect("real registration");
        let operator = store
            .finish_operator_setup(
                &OperatorRegistration {
                    source: source(),
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
        (verifier, auth, operator, binding)
    }};
}
macro_rules! assertion {
    ($store:expr,$auth:expr,$verifier:expr,$binding:expr) => {{
        let options =
            $store.operator_login_options($binding, $verifier).await.expect("login options");
        let result = $auth
            .do_authentication(
                Url::parse(ORIGIN).expect("origin"),
                passkey::authentication(&options.public_key),
            )
            .expect("real assertion");
        (options, result)
    }};
}
macro_rules! input {
    ($options:expr,$assertion:expr,$binding:expr,$handle:expr) => {
        OperatorAuthentication {
            source: source(),
            ceremony_id: $options.ceremony_id,
            browser_jkt: $binding,
            artifacts: AssertionArtifacts {
                credential_id: $assertion.raw_id.as_ref(),
                client_data: $assertion.response.client_data_json.as_ref(),
                authenticator_data: $assertion.response.authenticator_data.as_ref(),
                signature: $assertion.response.signature.as_ref(),
                user_handle: $handle,
            },
        }
    };
}
macro_rules! lifecycle {
    ($store:expr) => {{
        let store=&$store;
        let (verifier,mut auth,operator,binding)=setup!(store);
        let keyring=store.ensure_operator_token_keyring(&TestKms).await.expect("dedicated keyring");
        let handle=operator.into_bytes();
        let (options,assertion)=assertion!(store,auth,&verifier,&binding);
        assert_eq!(options.public_key["allowCredentials"],serde_json::json!([]));
        assert_eq!(options.public_key["timeout"],300000);
        assert!((299..=300).contains(&(options.expires_at_s-millis()/1000)));
        let login=store.finish_operator_login(&input!(options,assertion,&binding,&handle),&verifier,&keyring).await.expect("login");
        assert!(format!("{login:?}").contains("REDACTED"));
        let json=login.browser().to_json().expect("browser JSON");
        let browser:serde_json::Value=serde_json::from_str(&json).expect("JSON");
        assert_eq!(browser.as_object().expect("object").len(),4);
        assert!(browser.get("refresh_token").is_none());
        assert_eq!(login.browser().expires_in,600);
        assert_eq!(login.browser().refresh_expires_in,2_592_000);
        let original=cookie(&login);
        assert_eq!(URL_SAFE_NO_PAD.decode(&original).expect("32 random bytes").len(),32);
        assert_eq!(login.set_cookie(),format!("__Secure-spl-refresh={original}; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000"));
        let mut trusted=TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
        for k in keyring.verification_keys() { trusted.insert(&k.kid,&k.public_key).expect("trusted key"); }
        let token=OperatorAccessToken::parse(&login.browser().access_token).expect("operator token");
        let verified=token.verify(&trusted,u64::try_from(millis()/1000).expect("now")).expect("real signature");
        assert_eq!(verified.claims().sub,operator);
        assert_eq!(verified.claims().cnf_jkt,binding);
        assert!(store.current_operator_session(&verified).await.expect("current session").is_some());
        let row=sqlx::query("SELECT principal_kind,credential_id,expires_at_ms,created_at_ms FROM operator_refresh_families").fetch_one(store.pool()).await.expect("independent family");
        assert_eq!(row.get::<String,_>("principal_kind"),"operator");
        assert_eq!(row.get::<Vec<u8>,_>("credential_id"),assertion.raw_id.as_ref());
        assert_eq!(row.get::<i64,_>("expires_at_ms")-row.get::<i64,_>("created_at_ms"),2_592_000_000);
        for table in ["identity_accounts","identity_devices","device_refresh_families"] {
            let count:i64=sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(store.pool()).await.expect("no device identity"); assert_eq!(count,0);
        }
        let rotate_proof=proof(&key(1));
        let rotated=store.refresh_operator(source(),ORIGIN,&original,rotate_proof.as_str(),&keyring).await.expect("single-use rotate");
        let next=cookie(&rotated);assert_ne!(next,original);
        assert!(rotated.browser().refresh_expires_in<=login.browser().refresh_expires_in);
        let new=OperatorAccessToken::parse(&rotated.browser().access_token).expect("new token").verify(&trusted,u64::try_from(millis()/1000).expect("now")).expect("new signature");
        assert_eq!(new.claims().sid,verified.claims().sid);
        assert!(matches!(store.refresh_operator(source(),ORIGIN,&original,proof(&key(2)).as_str(),&keyring).await,Err(Error::InvalidDpopProof)),"wrong key cannot revoke");
        assert!(matches!(store.refresh_operator(source(),ORIGIN,&original,rotate_proof.as_str(),&keyring).await,Err(Error::InvalidDpopProof)),"replayed proof cannot revoke");
        assert!(store.current_operator_session(&verified).await.expect("still active").is_some());
        store.cleanup_refresh_families().await.expect("maintenance retains live reuse evidence");
        assert!(matches!(store.refresh_operator(source(),ORIGIN,&original,proof(&key(1)).as_str(),&keyring).await,Err(Error::Denied {changed:true})),"matching spent-token reuse revokes");
        assert!(store.current_operator_session(&verified).await.expect("revoked sid").is_none());
        assert!(store.current_operator_session(&new).await.expect("all family access revoked").is_none());
        store.cleanup_refresh_families().await.expect("maintenance retains revoked-unexpired evidence");
        let stored:Vec<Vec<u8>>=sqlx::query_scalar("SELECT token_digest FROM operator_refresh_tokens").fetch_all(store.pool()).await.expect("only digests stored");assert_eq!(stored.len(),2);assert!(stored.iter().all(|d|d.len()==32));
        store.verify_deployment_audit_chain().await.expect("audit chain");
    }};
}

macro_rules! rollback {
    ($store:expr,$fail_sql:expr,$clear_sql:expr) => {{
        let store = &$store;
        let (verifier, mut auth, operator, binding) = setup!(store);
        let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
        let handle = operator.into_bytes();
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        let mut request = input!(options, assertion, &binding, &handle);
        let wrong_binding = dpop_jwk_thumbprint(&key(2).public_key_sec1()).expect("wrong JKT");
        request.browser_jkt = &wrong_binding;
        assert!(matches!(
            store.finish_operator_login(&request, &verifier, &keyring).await,
            Err(Error::InvalidDpopProof)
        ));
        request.browser_jkt = &binding;
        let original_state: Vec<u8> =
            sqlx::query_scalar("SELECT credential_state FROM operator_credentials")
                .fetch_one(store.pool())
                .await
                .expect("original credential");
        sqlx::raw_sql($fail_sql).execute(store.pool()).await.expect("audit failure injection");
        assert!(matches!(
            store.finish_operator_login(&request, &verifier, &keyring).await,
            Err(Error::Audit)
        ));
        let consumed: Option<i64> =
            sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies WHERE purpose=2")
                .fetch_one(store.pool())
                .await
                .expect("consumption rollback");
        assert!(consumed.is_none());
        let state: Vec<u8> =
            sqlx::query_scalar("SELECT credential_state FROM operator_credentials")
                .fetch_one(store.pool())
                .await
                .expect("counter rollback");
        assert_eq!(state, original_state);
        let families: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_refresh_families")
            .fetch_one(store.pool())
            .await
            .expect("no family");
        assert_eq!(families, 0);
        sqlx::raw_sql($clear_sql).execute(store.pool()).await.expect("remove failure injection");
        let login = store
            .finish_operator_login(&request, &verifier, &keyring)
            .await
            .expect("same ceremony survived audit rollback");
        assert!(matches!(
            store.finish_operator_login(&request, &verifier, &keyring).await,
            Err(Error::Denied { changed: false })
        ));
        let refresh = cookie(&login);
        sqlx::raw_sql($fail_sql).execute(store.pool()).await.expect("rotation audit failure");
        assert!(matches!(
            store
                .refresh_operator(source(), ORIGIN, &refresh, proof(&key(1)).as_str(), &keyring)
                .await,
            Err(Error::Audit)
        ));
        let spent: Option<i64> =
            sqlx::query_scalar("SELECT spent_at_ms FROM operator_refresh_tokens")
                .fetch_one(store.pool())
                .await
                .expect("unspent after rollback");
        assert!(spent.is_none());
        sqlx::raw_sql($clear_sql).execute(store.pool()).await.expect("restore audit");
        store
            .refresh_operator(source(), ORIGIN, &refresh, proof(&key(1)).as_str(), &keyring)
            .await
            .expect("rotation after rollback");
        sqlx::raw_sql($fail_sql).execute(store.pool()).await.expect("revocation audit failure");
        assert!(matches!(
            store
                .refresh_operator(source(), ORIGIN, &refresh, proof(&key(1)).as_str(), &keyring)
                .await,
            Err(Error::Audit)
        ));
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
                .fetch_one(store.pool())
                .await
                .expect("reuse revocation rollback");
        assert!(revoked.is_none());
        sqlx::raw_sql($clear_sql).execute(store.pool()).await.expect("restore audit");
        assert!(matches!(
            store
                .refresh_operator(source(), ORIGIN, &refresh, proof(&key(1)).as_str(), &keyring)
                .await,
            Err(Error::Denied { changed: true })
        ));
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        let mut failed = input!(options, assertion, &binding, &handle);
        failed.artifacts.client_data = b"{}";
        sqlx::raw_sql($fail_sql).execute(store.pool()).await.expect("denial audit failure");
        assert!(matches!(
            store.finish_operator_login(&failed, &verifier, &keyring).await,
            Err(Error::Audit)
        ));
        let consumed: Option<i64> = sqlx::query_scalar(
            "SELECT consumed_at_s FROM operator_ceremonies WHERE ceremony_id=$1",
        )
        .bind(options.ceremony_id.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .expect("failed-assertion consumption rolled back");
        assert!(consumed.is_none());
        sqlx::raw_sql($clear_sql).execute(store.pool()).await.expect("restore denial audit");
        assert!(matches!(
            store.finish_operator_login(&failed, &verifier, &keyring).await,
            Err(Error::Denied { changed: true })
        ));
    }};
}

macro_rules! current_counter_and_concurrent_refresh {
    ($store:expr) => {{
        let store = &$store;
        let (verifier, mut auth, operator, binding) = setup!(store);
        let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
        let handle = operator.into_bytes();
        let (early, old_assertion) = assertion!(store, auth, &verifier, &binding);
        let (later, new_assertion) = assertion!(store, auth, &verifier, &binding);
        let login = store
            .finish_operator_login(
                &input!(later, new_assertion, &binding, &handle),
                &verifier,
                &keyring,
            )
            .await
            .expect("newer valid counter first");
        assert!(
            matches!(
                store
                    .finish_operator_login(
                        &input!(early, old_assertion, &binding, &handle),
                        &verifier,
                        &keyring
                    )
                    .await,
                Err(Error::Denied { changed: true })
            ),
            "earlier signed counter must compare against current durable credential"
        );
        let active: i64 = sqlx::query_scalar("SELECT active FROM operator_credentials")
            .fetch_one(store.pool())
            .await
            .expect("counter signal does not revoke");
        assert_eq!(active, 1);
        let attempts: i64 = sqlx::query_scalar(
            "SELECT attempts FROM operator_auth_admission WHERE endpoint=4 AND kind=4",
        )
        .fetch_one(store.pool())
        .await
        .expect("only authenticated assertion selects operator bucket");
        assert_eq!(attempts, 1);
        let refresh = cookie(&login);
        let a = proof(&key(1));
        let b = proof(&key(1));
        let replica = store.clone();
        let (first, second) = tokio::join!(
            store.refresh_operator(source(), ORIGIN, &refresh, a.as_str(), &keyring),
            replica.refresh_operator(source(), ORIGIN, &refresh, b.as_str(), &keyring)
        );
        assert!(
            matches!(
                (first, second),
                (Ok(_), Err(Error::Denied { changed: true }))
                    | (Err(Error::Denied { changed: true }), Ok(_))
            ),
            "one rotation; concurrent matching reuse revokes that family"
        );
        let spent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL",
        )
        .fetch_one(store.pool())
        .await
        .expect("one spent digest");
        assert_eq!(spent, 1);
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at_ms FROM operator_refresh_families")
                .fetch_one(store.pool())
                .await
                .expect("reuse revocation");
        assert!(revoked.is_some());
    }};
}

macro_rules! expiry_after_lock {
    ($store:expr,$begin:expr,$hold:expr) => {{
        let store=&$store;
        let (verifier,mut auth,operator,binding)=setup!(store);
        let keyring=std::sync::Arc::new(store.ensure_operator_token_keyring(&TestKms).await.expect("keyring"));
        let handle=operator.into_bytes();
        let (options,assertion)=assertion!(store,auth,&verifier,&binding);
        let mut tx=$begin;
        sqlx::query($hold).execute(&mut *tx).await.expect("hold session serialization");
        let waiting={let replica=store.clone();let keyring=keyring.clone();let binding=binding.clone();tokio::spawn(async move {
            let verifier=OperatorPasskeyVerifier::new(ORIGIN).expect("verifier");
            replica.finish_operator_login(&input!(options,assertion,&binding,&handle),&verifier,&keyring).await
        })};
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        sqlx::query("UPDATE operator_ceremonies SET issued_at_s=issued_at_s-301,expires_at_s=expires_at_s-301 WHERE purpose=2").execute(&mut *tx).await.expect("expiry while waiting");
        tx.commit().await.expect("release lock");
        assert!(matches!(waiting.await.expect("waiter"),Err(Error::Denied {changed:false})),"expired ceremony cannot be consumed using pre-lock time");
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM operator_refresh_families").fetch_one(store.pool()).await.expect("no family");assert_eq!(count,0);
    }};
}

macro_rules! refresh_expiry_after_lock {
    ($store:expr,$begin:expr,$hold:expr) => {{
        let store = &$store;
        let (verifier, mut auth, operator, binding) = setup!(store);
        let keyring = std::sync::Arc::new(
            store.ensure_operator_token_keyring(&TestKms).await.expect("keyring"),
        );
        let handle = operator.into_bytes();
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        let login = store
            .finish_operator_login(
                &input!(options, assertion, &binding, &handle),
                &verifier,
                &keyring,
            )
            .await
            .expect("login");
        let refresh = cookie(&login);
        let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
        for key in keyring.verification_keys() {
            trusted.insert(&key.kid, &key.public_key).expect("key");
        }
        let verified = std::sync::Arc::new(
            OperatorAccessToken::parse(&login.browser().access_token)
                .expect("token")
                .verify(&trusted, u64::try_from(millis() / 1000).expect("time"))
                .expect("verified"),
        );
        let mut tx = $begin;
        sqlx::query($hold).execute(&mut *tx).await.expect("hold session lock");
        let waiting_refresh = {
            let replica = store.clone();
            let keyring = keyring.clone();
            tokio::spawn(async move {
                replica
                    .refresh_operator(source(), ORIGIN, &refresh, proof(&key(1)).as_str(), &keyring)
                    .await
            })
        };
        let waiting_current = {
            let replica = store.clone();
            let verified = verified.clone();
            tokio::spawn(async move { replica.current_operator_session(&verified).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let expired = millis() - 1;
        sqlx::query("UPDATE operator_refresh_families SET created_at_ms=$1,expires_at_ms=$2")
            .bind(expired - 2_592_000_000_i64)
            .bind(expired)
            .execute(&mut *tx)
            .await
            .expect("expire family during lock wait");
        tx.commit().await.expect("release lock");
        assert!(matches!(
            waiting_refresh.await.expect("refresh waiter"),
            Err(Error::Denied { changed: false })
        ));
        assert!(waiting_current.await.expect("authorization waiter").expect("current").is_none());
        let row = sqlx::query(
            "SELECT f.revoked_at_ms,t.spent_at_ms FROM operator_refresh_families f JOIN operator_refresh_tokens t ON t.family_id=f.family_id",
        )
        .fetch_one(store.pool())
        .await
        .expect("expired family remains unmodified");
        assert!(row.try_get::<Option<i64>, _>("revoked_at_ms").expect("not revoked").is_none());
        assert!(row.try_get::<Option<i64>, _>("spent_at_ms").expect("not rotated").is_none());
    }};
}

macro_rules! remaining_cookie_lifetime {
    ($store:expr) => {{
        let store = &$store;
        let (verifier, mut auth, operator, binding) = setup!(store);
        let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
        let handle = operator.into_bytes();
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        let login = store
            .finish_operator_login(
                &input!(options, assertion, &binding, &handle),
                &verifier,
                &keyring,
            )
            .await
            .expect("login");
        let expires = millis() + 900;
        sqlx::query("UPDATE operator_refresh_families SET created_at_ms=$1,expires_at_ms=$2")
            .bind(expires - 2_592_000_000_i64)
            .bind(expires)
            .execute(store.pool())
            .await
            .expect("subsecond remaining lifetime");
        assert!(matches!(
            store
                .refresh_operator(
                    source(),
                    ORIGIN,
                    &cookie(&login),
                    proof(&key(1)).as_str(),
                    &keyring
                )
                .await,
            Err(Error::Denied { changed: false })
        ));
        let unspent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NULL",
        )
        .fetch_one(store.pool())
        .await
        .expect("no zero-age cookie or rotation");
        assert_eq!(unspent, 1);
    }};
}

#[tokio::test]
async fn sqlite_refresh_and_current_session_expiry_are_rechecked_after_lock() {
    let (store, dir) = sqlite().await;
    refresh_expiry_after_lock!(
        store,
        store.pool().begin_with("BEGIN IMMEDIATE").await.expect("write lock"),
        "SELECT 1"
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_subsecond_refresh_lifetime_does_not_rotate() {
    let (store, dir) = sqlite().await;
    remaining_cookie_lifetime!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_current_counter_and_concurrent_refresh() {
    let (store, dir) = sqlite().await;
    current_counter_and_concurrent_refresh!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}
#[tokio::test]
async fn sqlite_ceremony_expiry_is_rechecked_after_lock() {
    let (store, dir) = sqlite().await;
    expiry_after_lock!(
        store,
        store.pool().begin_with("BEGIN IMMEDIATE").await.expect("write lock"),
        "SELECT 1"
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_real_login_rotation_and_reuse_revocation() {
    let (store, dir) = sqlite().await;
    lifecycle!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}
#[tokio::test]
async fn sqlite_login_rotation_and_revocation_roll_back_on_audit_failure() {
    let (store, dir) = sqlite().await;
    // Toggle rows rather than repeatedly replacing DDL: pooled SQLite connections may
    // retain an old trigger schema until their next stepped statement refreshes it.
    sqlx::raw_sql(
        "CREATE TABLE audit_failure_switch (enabled INTEGER PRIMARY KEY CHECK (enabled=1));
         CREATE TRIGGER reject_operator_session_audit BEFORE INSERT ON deployment_audit_events
         WHEN EXISTS (SELECT 1 FROM audit_failure_switch)
         BEGIN SELECT RAISE(ABORT,'fixture failure'); END",
    )
    .execute(store.pool())
    .await
    .expect("install stable audit failure trigger");
    rollback!(
        store,
        "INSERT INTO audit_failure_switch (enabled) VALUES (1)",
        "DELETE FROM audit_failure_switch"
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

macro_rules! failure_paths {
    ($store:expr) => {{
        let store = &$store;
        let (verifier, mut auth, operator, binding) = setup!(store);
        let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
        let handle = operator.into_bytes();
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        let mut request = input!(options, assertion, &binding, &handle);
        request.artifacts.client_data = &[];
        assert!(matches!(
            store.finish_operator_login(&request, &verifier, &keyring).await,
            Err(Error::InvalidInput)
        ));
        request.artifacts.client_data = assertion.response.client_data_json.as_ref();
        let mut signature = request.artifacts.signature.to_vec();
        signature[5] ^= 1;
        request.artifacts.signature = &signature;
        assert!(matches!(
            store.finish_operator_login(&request, &verifier, &keyring).await,
            Err(Error::Denied { changed: true })
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_refresh_families")
            .fetch_one(store.pool())
            .await
            .expect("none");
        assert_eq!(count, 0);
        let (options, assertion) = assertion!(store, auth, &verifier, &binding);
        for _ in 0..10 {
            store
                .admit_operator_auth_private(
                    Endpoint::LoginFinish,
                    Private::AuthenticatedOperator(operator),
                )
                .await
                .expect("fill operator quota");
        }
        let request = input!(options, assertion, &binding, &handle);
        assert!(matches!(
            store.finish_operator_login(&request, &verifier, &keyring).await,
            Err(Error::RateLimited(_))
        ));
        let consumed: Option<i64> = sqlx::query_scalar(
            "SELECT consumed_at_s FROM operator_ceremonies WHERE ceremony_id=$1",
        )
        .bind(options.ceremony_id.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .expect("rate does not consume");
        assert!(consumed.is_none());
        sqlx::query(
            "UPDATE operator_auth_admission SET attempts=0,cooldown_until_ms=0 WHERE endpoint=4",
        )
        .execute(store.pool())
        .await
        .expect("quota reset fixture");
        let login = store
            .finish_operator_login(&request, &verifier, &keyring)
            .await
            .expect("valid signature after rate rejection");
        let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
        for k in keyring.verification_keys() {
            trusted.insert(&k.kid, &k.public_key).expect("key");
        }
        let verified = OperatorAccessToken::parse(&login.browser().access_token)
            .expect("token")
            .verify(&trusted, u64::try_from(millis() / 1000).expect("now"))
            .expect("verified");
        sqlx::query("UPDATE operator_credentials SET active=0")
            .execute(store.pool())
            .await
            .expect("fixture credential revocation");
        assert!(
            store.current_operator_session(&verified).await.expect("revoked credential").is_none()
        );
        sqlx::query("UPDATE operator_credentials SET active=1")
            .execute(store.pool())
            .await
            .expect("restore fixture credential");
        sqlx::query("UPDATE deployment_operators SET active=0")
            .execute(store.pool())
            .await
            .expect("fixture operator revocation");
        assert!(
            store.current_operator_session(&verified).await.expect("revoked operator").is_none()
        );
    }};
}

#[tokio::test]
async fn sqlite_failed_assertion_consumption_outer_bounds_and_rate_rejection() {
    let (store, dir) = sqlite().await;
    failure_paths!(store);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (scoplen_store::PostgresStore, sqlx::PgPool, String, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PG fixture");
    let pool = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("operator_session_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let database = url.to_string();
    let store = scoplen_store::PostgresStore::connect(&database).await.expect("PG");
    (store, pool, schema, database)
}
#[cfg(feature = "postgres-integration")]
async fn cleanup(store: scoplen_store::PostgresStore, pool: sqlx::PgPool, schema: String) {
    store.pool().close().await;
    assert!(
        schema.starts_with("operator_session_")
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
async fn postgres_real_login_rotation_and_reuse_revocation() {
    let (store, pool, schema, _) = postgres_fixture().await;
    lifecycle!(store);
    cleanup(store, pool, schema).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_login_rotation_and_revocation_roll_back_on_audit_failure() {
    let (store, pool, schema, _) = postgres_fixture().await;
    rollback!(
        store,
        "CREATE FUNCTION reject_operator_session_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END; $$; CREATE TRIGGER reject_operator_session_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_operator_session_audit()",
        "DROP TRIGGER reject_operator_session_audit ON deployment_audit_events; DROP FUNCTION reject_operator_session_audit()"
    );
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_failed_assertion_consumption_outer_bounds_and_rate_rejection() {
    let (store, pool, schema, _) = postgres_fixture().await;
    failure_paths!(store);
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_current_counter_and_concurrent_refresh() {
    let (store, pool, schema, _) = postgres_fixture().await;
    current_counter_and_concurrent_refresh!(store);
    cleanup(store, pool, schema).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_ceremony_expiry_is_rechecked_after_lock() {
    let (store, pool, schema, _) = postgres_fixture().await;
    expiry_after_lock!(
        store,
        store.pool().begin().await.expect("transaction"),
        "SELECT pg_advisory_xact_lock(1396916048,1397052243)"
    );
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_refresh_and_current_session_expiry_are_rechecked_after_lock() {
    let (store, pool, schema, _) = postgres_fixture().await;
    refresh_expiry_after_lock!(
        store,
        store.pool().begin().await.expect("transaction"),
        "SELECT pg_advisory_xact_lock(1396916048,1397052243)"
    );
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_subsecond_refresh_lifetime_does_not_rotate() {
    let (store, pool, schema, _) = postgres_fixture().await;
    remaining_cookie_lifetime!(store);
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_session_guard_holds_identity_rows_until_commit_or_rollback() {
    use scoplen_store::operator_sessions::verify_operator_session_in_postgres_transaction;
    use std::time::Duration;

    let (store, pool, schema, _) = postgres_fixture().await;
    let (verifier, mut auth, operator, binding) = setup!(store);
    let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
    let handle = operator.into_bytes();
    let (options, assertion) = assertion!(store, auth, &verifier, &binding);
    let login = store
        .finish_operator_login(&input!(options, assertion, &binding, &handle), &verifier, &keyring)
        .await
        .expect("login");
    let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("key");
    }
    let principal = OperatorAccessToken::parse(&login.browser().access_token)
        .expect("token")
        .verify(&trusted, u64::try_from(millis() / 1000).expect("time"))
        .expect("verified");
    for commit in [false, true] {
        for (mutation, restore) in [
            (
                "UPDATE deployment_operators SET active=0",
                "UPDATE deployment_operators SET active=1",
            ),
            (
                "UPDATE operator_credentials SET active=0",
                "UPDATE operator_credentials SET active=1",
            ),
            (
                "UPDATE operator_refresh_families SET revoked_at_ms=created_at_ms",
                "UPDATE operator_refresh_families SET revoked_at_ms=NULL",
            ),
        ] {
            let mut caller = store.pool().begin().await.expect("caller transaction");
            assert!(
                verify_operator_session_in_postgres_transaction(&mut caller, &principal)
                    .await
                    .expect("authorized under row locks")
                    .is_some()
            );
            let mut connection = store.pool().acquire().await.expect("independent updater");
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *connection)
                .await
                .expect("updater pid");
            let updater = tokio::spawn(async move {
                sqlx::query(mutation).execute(&mut *connection).await.expect("direct revocation")
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    assert!(!updater.is_finished(), "revocation escaped caller's row locks");
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
                    )
                    .bind(pid)
                    .fetch_one(&pool)
                    .await
                    .expect("inspect independent lock wait");
                    if waiting {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("direct update must block until caller ends");
            if commit {
                caller.commit().await.expect("caller commit");
            } else {
                caller.rollback().await.expect("caller rollback");
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), updater)
                    .await
                    .expect("revocation released after transaction end")
                    .expect("updater task")
                    .rows_affected(),
                1
            );
            assert!(
                store.current_operator_session(&principal).await.expect("fresh guard").is_none()
            );
            sqlx::query(restore).execute(store.pool()).await.expect("restore fixture identity");
        }
    }
    cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_lost_finish_rotation_and_revocation_commit_acknowledgements() {
    use std::sync::atomic::Ordering;
    let (store, pool, schema, database) = postgres_fixture().await;
    let (verifier, mut auth, operator, binding) = setup!(store);
    let keyring = store.ensure_operator_token_keyring(&TestKms).await.expect("keyring");
    let handle = operator.into_bytes();
    let proxy = lost_commit::LostCommitProxy::start(&database).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxy pool");
    let (options, assertion) = assertion!(store, auth, &verifier, &binding);
    let request = input!(options, assertion, &binding, &handle);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.finish_operator_login(&request, &verifier, &keyring).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_refresh_families")
        .fetch_one(store.pool())
        .await
        .expect("unknown login committed");
    assert_eq!(count, 1);
    let (options, assertion) = assertion!(store, auth, &verifier, &binding);
    let login = store
        .finish_operator_login(&input!(options, assertion, &binding, &handle), &verifier, &keyring)
        .await
        .expect("fresh reauthentication");
    let token = cookie(&login);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.refresh_operator(source(), ORIGIN, &token, proof(&key(1)).as_str(), &keyring).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    let spent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL",
    )
    .fetch_one(store.pool())
    .await
    .expect("unknown rotation committed");
    assert_eq!(spent, 1);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.refresh_operator(source(), ORIGIN, &token, proof(&key(1)).as_str(), &keyring).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    let revoked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL",
    )
    .fetch_one(store.pool())
    .await
    .expect("unknown reuse revocation committed");
    assert_eq!(revoked, 1);
    let (options, assertion) = assertion!(store, auth, &verifier, &binding);
    let mut bad = input!(options, assertion, &binding, &handle);
    bad.artifacts.client_data = b"{}";
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        proxied.finish_operator_login(&bad, &verifier, &keyring).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 4);
    let consumed: Option<i64> =
        sqlx::query_scalar("SELECT consumed_at_s FROM operator_ceremonies WHERE ceremony_id=$1")
            .bind(options.ceremony_id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("unknown denial consumed");
    assert!(consumed.is_some());
    proxied.pool().close().await;
    drop(proxy);
    cleanup(store, pool, schema).await;
}

#[path = "support/operator_logout.rs"]
mod logout;
