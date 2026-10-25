// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
#[path = "support/pool_close.rs"]
mod pool_close;
mod support;

use std::{net::IpAddr, time::Duration};

use scoplen_api::account_admission::{
    AccountBootstrapSnapshot, AccountPasswordLoginRequest, AccountPasswordOptionsRequest,
    AccountRegistrationPayload,
};
use scoplen_crypto::{
    Ed25519SigningKey, P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordSecrets,
    SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest,
};
#[cfg(feature = "postgres-integration")]
use scoplen_store::{
    PostgresStore,
    account_admission_capabilities::{
        claim_postgres_account_admission_capability_in_transaction as postgres_claim,
        finish_postgres_account_admission_capability_in_transaction as postgres_finish,
    },
    account_bootstrap::create_postgres_password_account_in_transaction as postgres_create,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_admission_capabilities::{
        claim_sqlite_account_admission_capability_in_transaction as sqlite_claim,
        finish_sqlite_account_admission_capability_in_transaction as sqlite_finish,
    },
    account_bootstrap::create_sqlite_password_account_in_transaction as sqlite_create,
    account_entry_admission::{AccountEntryAdmissionDecision, AccountEntryEndpoint as Endpoint},
    account_password_login::AccountPasswordLoginError as Error,
    kms::KeyManagementService,
};
use tokio::time::Instant;
use uuid::Uuid;

const ORIGIN: &str = "https://password.example.test";
const FUTURE: i64 = 4_000_000_020_000;
struct Kms;
impl KeyManagementService for Kms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &[7; 32]
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}
fn source() -> IpAddr {
    "192.0.2.42".parse().expect("source")
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn options(username: &str) -> Vec<u8> {
    AccountPasswordOptionsRequest { username: username.into() }.to_json().expect("options body")
}
fn login(attempt: SecretBytes<32>, secret: SecretBytes<32>) -> SecretVec {
    AccountPasswordLoginRequest { attempt_id: attempt, auth_secret: secret }
        .to_json()
        .expect("login body")
}
fn fixture(username: &str) -> (AccountRegistrationPayload, PasswordSecrets) {
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("signing");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let device = P256SigningKey::from_bytes(&scalar).expect("Device");
    let identity = legacy_identity::LegacyIdentity::new(&signing, &device);
    let secrets = PasswordSecrets::create(
        ORIGIN,
        username,
        SecretVec::new(b"a password for real encrypted bootstrap".to_vec()),
    )
    .expect("password secrets");
    let context = PasswordBootstrapContext::new(
        secrets.context().clone(),
        identity.account_id,
        identity.personal_vault_id,
        &identity.account_signing_public_key,
        &identity.account_kem_public_key,
        1,
    )
    .expect("context");
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
            .expect("password envelope")
            .encode(),
        device_certificate: identity.device_certificate.encode().expect("certificate"),
        key_bundle: identity.key_bundle_update.to_cbor().expect("signed PUT"),
        personal_wrapped_key: identity.wrapped_personal_vault_key.try_into().expect("Personal key"),
    };
    (payload, secrets)
}

async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("scoplen-password-{}", Uuid::now_v7()));
    (SqliteStore::open(&path.join("store.sqlite")).await.expect("store"), path)
}
async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
#[cfg(feature = "postgres-integration")]
async fn postgres_begin(
    store: &PostgresStore,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    store.pool().begin().await
}

macro_rules! initialize {
    ($store:expr) => {{
        $store.ensure_account_probe_key(&Kms).await.expect("startup-only initialization");
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE)
            .execute($store.pool())
            .await
            .expect("durable clock");
    }};
}
macro_rules! admit {
    ($store:expr,$endpoint:expr) => {{
        assert_eq!(
            $store
                .admit_account_entry_source($endpoint, source())
                .await
                .expect("HTTP source admission"),
            AccountEntryAdmissionDecision::Admitted
        );
    }};
}
macro_rules! establish {
    ($store:expr,$create:ident,$username:expr) => {{
        $store.initialize_account_id_retention(16).await.expect("retention ceiling");
        let (payload, secrets) = fixture($username);
        let mut tx = $store.pool().begin().await.expect("registration aggregate");
        $create(&mut tx, ORIGIN, 16, &payload, FUTURE).await.expect("signed initial aggregate");
        tx.commit().await.expect("fixture creation");
        (payload, secrets)
    }};
}

macro_rules! lifecycle {
    ($store:expr,$begin:ident,$create:ident,$claim:ident,$finish:ident) => {{
        let store = &$store;
        initialize!(store);
        let (payload, secrets) = establish!(store, $create, "password-user");
        admit!(store, Endpoint::PasswordOptions);
        let issued = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("password-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("options");
        assert_eq!(issued.salt, payload.password_salt);
        assert_eq!(issued.expires_at_ms, u64::try_from(FUTURE + 120_000).expect("expiry"));
        let retained: Vec<u8> =
            sqlx::query_scalar("SELECT attempt_digest FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("digest only");
        assert_ne!(retained, issued.attempt_id.as_ref());
        assert_eq!(retained, account_capability_digest(issued.attempt_id.as_bytes()));
        admit!(store, Endpoint::PasswordLogin);
        let authenticated = store
            .execute_account_password_login(
                source(),
                ORIGIN,
                login(issued.attempt_id.clone(), secrets.auth_secret().clone()),
                &Kms,
                deadline(),
            )
            .await
            .expect("password login");
        assert_eq!(authenticated.expires_at_ms, u64::try_from(FUTURE + 300_000).expect("expiry"));
        let snapshot = AccountBootstrapSnapshot::from_cbor(authenticated.snapshot.as_bytes())
            .expect("complete signed snapshot");
        assert_eq!(snapshot.account_id, payload.account_id);
        assert_eq!(snapshot.key_bundle, payload.key_bundle);
        assert_eq!(snapshot.certificates, vec![payload.device_certificate.clone()]);
        let retained: Vec<u8> =
            sqlx::query_scalar("SELECT token_digest FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("capability digest");
        assert_eq!(retained, account_capability_digest(authenticated.admission_token.as_bytes()));
        assert_ne!(retained, authenticated.admission_token.as_ref());
        let mut tx = $begin(store).await.expect("provisional claim");
        let claim = $claim(&mut tx, authenticated.admission_token.as_bytes())
            .await
            .expect("claim")
            .expect("live");
        assert_eq!(claim.account_id(), payload.account_id);
        assert_eq!(claim.credential_generation(), 1);
        assert_eq!(
            claim.snapshot_digest(),
            &account_bootstrap_digest(authenticated.snapshot.as_bytes())
        );
        tx.rollback().await.expect("proof rejection must restore capability");
        let mut tx = $begin(store).await.expect("new admission");
        let claim = $claim(&mut tx, authenticated.admission_token.as_bytes())
            .await
            .expect("claim")
            .expect("restored");
        $finish(&mut tx, claim).await.expect("final expiry");
        tx.commit().await.expect("coordinator commit");
        let mut tx = $begin(store).await.expect("used capability");
        assert!(
            $claim(&mut tx, authenticated.admission_token.as_bytes())
                .await
                .expect("lookup")
                .is_none()
        );
        tx.rollback().await.expect("end lookup");
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(issued.attempt_id, secrets.auth_secret().clone()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        for table in ["identity_accounts", "identity_devices", "sync_personal_vaults"] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(store.pool())
                    .await
                    .expect("no new identity"),
                1
            );
        }
        for table in [
            "device_refresh_families",
            "device_refresh_tokens",
            "account_password_attempts",
            "account_admission_capabilities",
        ] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(store.pool())
                    .await
                    .expect("no session or secret retry state"),
                0
            );
        }
    }};
}

macro_rules! synthetic_and_denials {
    ($store:expr) => {{
        let store = &$store;
        initialize!(store);
        let mut issued = Vec::new();
        for name in ["unknown-user", "unknown-user", "another-user"] {
            admit!(store, Endpoint::PasswordOptions);
            issued.push(
                store
                    .issue_account_password_options(
                        source(),
                        ORIGIN,
                        &options(name),
                        &Kms,
                        deadline(),
                    )
                    .await
                    .expect("same public response"),
            );
        }
        assert_eq!(issued[0].salt, issued[1].salt);
        assert_ne!(issued[0].salt, issued[2].salt);
        assert_ne!(issued[0].attempt_id, issued[1].attempt_id);
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(issued[0].attempt_id.clone(), SecretBytes::new([19; 32])),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("matching denial consumed once"),
            2
        );
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE + 1000)
            .execute(store.pool())
            .await
            .expect("cooldown passes");
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(SecretBytes::new([99; 32]), SecretBytes::new([19; 32])),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM identity_accounts")
                .fetch_one(store.pool())
                .await
                .expect("no synthetic account"),
            0
        );
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1,last_cleanup_ms=0")
            .bind(FUTURE + 120_000)
            .execute(store.pool())
            .await
            .expect("expire");
        let cleanup = store.cleanup_account_entry_state().await.expect("shared cleanup gate");
        assert_eq!(cleanup.password_attempt_rows, 2);
        assert_eq!(
            store
                .cleanup_account_entry_state()
                .await
                .expect("one second gate")
                .password_attempt_rows,
            0
        );
    }};
}

macro_rules! capacity_and_cascade {
    ($store:expr,$create:ident) => {{
        let store = &$store;
        initialize!(store);
        let (payload, secrets) = establish!(store, $create, "capacity-user");
        for index in 0..5 {
            admit!(store, Endpoint::PasswordOptions);
            let issued = store
                .issue_account_password_options(
                    source(),
                    ORIGIN,
                    &options("capacity-user"),
                    &Kms,
                    deadline(),
                )
                .await
                .expect("options at capacity");
            admit!(store, Endpoint::PasswordLogin);
            let result = store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(issued.attempt_id, secrets.auth_secret().clone()),
                    &Kms,
                    deadline(),
                )
                .await;
            if index < 4 {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(Error::RateLimited(1))));
            }
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("account cap"),
            4
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("rate denial restores claim"),
            1
        );
        sqlx::query("DELETE FROM identity_devices WHERE account_id=$1")
            .bind(payload.account_id.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("remove noncascading Device reference");
        sqlx::query("DELETE FROM identity_accounts WHERE account_id=$1")
            .bind(payload.account_id.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("owned account removal");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("capabilities cascade"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_used_ids")
                .fetch_one(store.pool())
                .await
                .expect("permanent id retained"),
            1
        );
    }};
}

#[tokio::test]
async fn sqlite_password_login_complete_snapshot_and_one_use_capability() {
    let (store, path) = sqlite().await;
    lifecycle!(store, sqlite_begin, sqlite_create, sqlite_claim, sqlite_finish);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[tokio::test]
async fn sqlite_password_unknown_common_denial_and_retirement() {
    let (store, path) = sqlite().await;
    synthetic_and_denials!(store);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[tokio::test]
async fn sqlite_password_capability_capacity_and_account_deletion() {
    let (store, path) = sqlite().await;
    capacity_and_cascade!(store, sqlite_create);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}

macro_rules! missing_key_and_strict_decode {
    ($store:expr) => {{
        let store = &$store;
        admit!(store, Endpoint::PasswordOptions);
        assert!(matches!(
            store
                .issue_account_password_options(
                    source(),
                    ORIGIN,
                    &options("unknown-user"),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::StorageUnavailable)
        ));
        assert!(
            sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT encrypted_key FROM account_password_probe_key"
            )
            .fetch_one(store.pool())
            .await
            .expect("not initialized")
            .is_none()
        );
        initialize!(store);
        for body in [
            b"{\"username\":\"valid-user\",\"extra\":1}".as_slice(),
            b"{\"username\":\"valid-user\",\"username\":\"valid-user\"}",
        ] {
            admit!(store, Endpoint::PasswordOptions);
            assert!(matches!(
                store
                    .issue_account_password_options(source(), ORIGIN, body, &Kms, deadline())
                    .await,
                Err(Error::InvalidRequest)
            ));
        }
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    SecretVec::new(b"{}".to_vec()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::InvalidRequest)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("invalid input retains no attempt"),
            0
        );
    }};
}
#[tokio::test]
async fn sqlite_password_requires_retained_key_and_strict_decoding() {
    let (store, path) = sqlite().await;
    missing_key_and_strict_decode!(store);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_password_login_does_not_attach_credentials_to_legacy_account() {
    let (store, path) = sqlite().await;
    initialize!(store);
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account key");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let device = P256SigningKey::from_bytes(&scalar).expect("Device key");
    let identity = legacy_identity::LegacyIdentity::new(&signing, &device);
    legacy_identity::seed_sqlite(store.pool(), &identity, true).await;
    admit!(store, Endpoint::PasswordOptions);
    let issued = store
        .issue_account_password_options(source(), ORIGIN, &options("legacy-user"), &Kms, deadline())
        .await
        .expect("synthetic options");
    admit!(store, Endpoint::PasswordLogin);
    assert!(matches!(
        store
            .execute_account_password_login(
                source(),
                ORIGIN,
                login(issued.attempt_id, SecretBytes::new([1; 32])),
                &Kms,
                deadline()
            )
            .await,
        Err(Error::AuthenticationRequired)
    ));
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT password_owned FROM identity_accounts")
            .fetch_one(store.pool())
            .await
            .expect("legacy ownership unchanged")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_bootstrap")
            .fetch_one(store.pool())
            .await
            .expect("no credential attachment"),
        0
    );
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres() -> (PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("password_login_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    (PostgresStore::connect(url.as_str()).await.expect("isolated store"), pool, schema)
}
#[cfg(feature = "postgres-integration")]
async fn postgres_cleanup(store: PostgresStore, pool: sqlx::PgPool, schema: String) {
    pool_close::close(store.pool()).await;
    drop(store);
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_login_complete_snapshot_and_one_use_capability() {
    let (store, pool, schema) = postgres().await;
    lifecycle!(store, postgres_begin, postgres_create, postgres_claim, postgres_finish);
    postgres_cleanup(store, pool, schema).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_unknown_common_denial_and_retirement() {
    let (store, pool, schema) = postgres().await;
    synthetic_and_denials!(store);
    postgres_cleanup(store, pool, schema).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_capability_capacity_and_account_deletion() {
    let (store, pool, schema) = postgres().await;
    capacity_and_cascade!(store, postgres_create);
    postgres_cleanup(store, pool, schema).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_requires_retained_key_and_strict_decoding() {
    let (store, pool, schema) = postgres().await;
    missing_key_and_strict_decode!(store);
    postgres_cleanup(store, pool, schema).await;
}

macro_rules! capability_race {
    ($store:expr,$create:ident,$db:ty,$global:literal) => {{
        let store = &$store;
        initialize!(store);
        let (_, secrets) = establish!(store, $create, "race-user");
        let mut requests = Vec::new();
        for _ in 0..5 {
            admit!(store, Endpoint::PasswordOptions);
            let issued = store
                .issue_account_password_options(
                    source(),
                    ORIGIN,
                    &options("race-user"),
                    &Kms,
                    deadline(),
                )
                .await
                .expect("options");
            admit!(store, Endpoint::PasswordLogin);
            requests.push(login(issued.attempt_id, secrets.auth_secret().clone()));
        }
        for _ in 0..3 {
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    requests.remove(0),
                    &Kms,
                    deadline(),
                )
                .await
                .expect("three retained capabilities");
        }
        if $global {
            // Other owned Accounts each retain four well-formed transient rows, leaving
            // exactly one deployment-wide slot while this Account also has one slot.
            let mut tx=store.pool().begin().await.expect("owned global-capacity fixture");
            for _ in 0..1023 {
                let account=Uuid::now_v7();
                sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$3,$4)")
                    .bind(account.as_bytes().as_slice()).bind([1_u8;32].as_slice()).bind([2_u8;32].as_slice()).bind(FUTURE)
                    .execute(&mut *tx).await.expect("owned historical Account");
                let mut insert=sqlx::QueryBuilder::<$db>::new("INSERT INTO account_admission_capabilities (token_digest,account_id,credential_generation,snapshot_digest,issued_at_ms,expires_at_ms) ");
                insert.push_values(0..4,|mut row,index| {
                    let mut digest=vec![0;32]; digest[..16].copy_from_slice(account.as_bytes()); digest[16]=index;
                    row.push_bind(digest).push_bind(account.as_bytes().to_vec()).push_bind(1_i64)
                        .push_bind(vec![3_u8;32]).push_bind(FUTURE).push_bind(FUTURE+300_000);
                });
                insert.build().execute(&mut *tx).await.expect("four retained rows per Account");
            }
            tx.commit().await.expect("one remaining global slot");
        }
        let mut tasks = Vec::new();
        for request in requests {
            let instance = store.clone();
            tasks.push(tokio::spawn(async move {
                instance
                    .execute_account_password_login(source(), ORIGIN, request, &Kms, deadline())
                    .await
            }));
        }
        let mut wins = 0;
        let mut limited = 0;
        for task in tasks {
            match task.await.expect("competing login") {
                Ok(_) => wins += 1,
                Err(Error::RateLimited(1)) => limited += 1,
                Err(error) => panic!("unexpected content-free outcome: {error}"),
            }
        }
        assert_eq!((wins, limited), (1, 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("one final slot"),
            if $global {4096}else{4}
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("losing attempt retained"),
            1
        );
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1,last_cleanup_ms=0")
            .bind(FUTURE + 300_000)
            .execute(store.pool())
            .await
            .expect("expire capabilities");
        let cleanup = store.cleanup_account_entry_state().await.expect("both tables in one gate");
        assert_eq!((cleanup.password_attempt_rows, cleanup.admission_capability_rows), (1, if $global {100}else{4}));
    }};
}

macro_rules! credential_and_snapshot_failures {
    ($store:expr,$create:ident) => {{
        let store = &$store;
        initialize!(store);
        let (payload, secrets) = establish!(store, $create, "failure-user");
        admit!(store, Endpoint::PasswordOptions);
        let changed = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("failure-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("bound salt");
        sqlx::query("UPDATE account_password_attempts SET password_salt=$1")
            .bind([9_u8; 16].as_slice())
            .execute(store.pool())
            .await
            .expect("stale attempt salt");
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(changed.attempt_id, secrets.auth_secret().clone()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("stale attempt consumed"),
            0
        );
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE + 1000)
            .execute(store.pool())
            .await
            .expect("cooldown elapsed");
        admit!(store, Endpoint::PasswordOptions);
        let valid = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("failure-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("fresh options");
        sqlx::query("UPDATE sync_vaults SET rotation_pending=TRUE WHERE vault_id=$1")
            .bind(payload.personal_vault_id.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("unsupported current transition");
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(valid.attempt_id, secrets.auth_secret().clone()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AdmissionConflict)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("conflict never issues authority"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("conflict consumed matching attempt"),
            0
        );
        sqlx::query("UPDATE sync_vaults SET rotation_pending=FALSE WHERE vault_id=$1")
            .bind(payload.personal_vault_id.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("restore owned state");
        admit!(store, Endpoint::PasswordOptions);
        let expired = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("failure-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("expiring options");
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE + 121_000)
            .execute(store.pool())
            .await
            .expect("exact expiry");
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(expired.attempt_id, secrets.auth_secret().clone()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("expired attempt never creates capability"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT failure_streak FROM account_entry_admission WHERE endpoint=4 AND kind=2"
            )
            .fetch_one(store.pool())
            .await
            .expect("retained expired username participates in cooldown"),
            2
        );
    }};
}

macro_rules! bounded_attempt_capacity {
    ($store:expr,$db:ty) => {{
        let store=&$store;
        initialize!(store);
        let mut tx=store.pool().begin().await.expect("owned capacity fixture");
        for base in (0_u64..16_383).step_by(512) {
            let mut insert=sqlx::QueryBuilder::<$db>::new("INSERT INTO account_password_attempts (attempt_digest,origin_digest,username,password_profile,password_salt,issued_at_ms,expires_at_ms) ");
            insert.push_values(base..(base+512).min(16_383),|mut row,index| {
                let mut digest=vec![0;32]; digest[24..].copy_from_slice(&index.to_be_bytes());
                row.push_bind(digest).push_bind(vec![7_u8;32]).push_bind("retained-user").push_bind(1_i64)
                    .push_bind(vec![8_u8;16]).push_bind(FUTURE).push_bind(FUTURE+120_000);
            });
            insert.build().execute(&mut *tx).await.expect("bounded row batch");
        }
        tx.commit().await.expect("one slot available");
        let mut tasks=Vec::new();
        for name in ["final-slot-a","final-slot-b"] {
            admit!(store,Endpoint::PasswordOptions);
            let instance=store.clone();
            tasks.push(tokio::spawn(async move {instance.issue_account_password_options(source(),ORIGIN,&options(name),&Kms,deadline()).await}));
        }
        let mut wins=0; let mut limited=0;
        for task in tasks {
            match task.await.expect("competing options") {
                Ok(_)=>wins+=1,
                Err(Error::RateLimited(1))=>limited+=1,
                Err(error)=>panic!("unexpected fixed capacity outcome: {error}"),
            }
        }
        assert_eq!((wins,limited),(1,1));
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM account_password_attempts").fetch_one(store.pool()).await.expect("global final slot serialized"),16_384);
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1,last_cleanup_ms=0").bind(FUTURE+120_000).execute(store.pool()).await.expect("expire retained attempts");
        assert_eq!(store.cleanup_account_entry_state().await.expect("indexed bounded pass").password_attempt_rows,100);
        assert_eq!(store.cleanup_account_entry_state().await.expect("same second throttled").password_attempt_rows,0);
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1").bind(FUTURE+121_000).execute(store.pool()).await.expect("next durable second");
        assert_eq!(store.cleanup_account_entry_state().await.expect("next bounded pass").password_attempt_rows,100);
    }};
}
#[tokio::test]
async fn sqlite_password_attempt_capacity_race_and_bounded_retirement() {
    let (store, path) = sqlite().await;
    bounded_attempt_capacity!(store, sqlx::Sqlite);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_attempt_capacity_race_and_bounded_retirement() {
    let (store, pool, schema) = postgres().await;
    bounded_attempt_capacity!(store, sqlx::Postgres);
    postgres_cleanup(store, pool, schema).await;
}
#[tokio::test]
async fn sqlite_password_stale_salt_unsupported_bootstrap_and_exact_expiry() {
    let (store, path) = sqlite().await;
    credential_and_snapshot_failures!(store, sqlite_create);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_stale_salt_unsupported_bootstrap_and_exact_expiry() {
    let (store, pool, schema) = postgres().await;
    credential_and_snapshot_failures!(store, postgres_create);
    postgres_cleanup(store, pool, schema).await;
}

macro_rules! failed_audit {
    ($store:expr,$create:ident,$install:expr,$remove:expr) => {{
        let store = &$store;
        initialize!(store);
        let (_, secrets) = establish!(store, $create, "audit-user");
        admit!(store, Endpoint::PasswordOptions);
        let issued = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("audit-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("options");
        admit!(store, Endpoint::PasswordLogin);
        let mut owner = store.pool().acquire().await.expect("owned fault connection");
        sqlx::raw_sql($install).execute(&mut *owner).await.expect("install owned audit fault");
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(issued.attempt_id.clone(), secrets.auth_secret().clone()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::StorageUnavailable)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("failed audit rolls back capability"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("failed audit restores attempt"),
            1
        );
        sqlx::raw_sql($remove).execute(&mut *owner).await.expect("remove owned audit fault");
        drop(owner);
        store
            .execute_account_password_login(
                source(),
                ORIGIN,
                login(issued.attempt_id, secrets.auth_secret().clone()),
                &Kms,
                deadline(),
            )
            .await
            .expect("control succeeds after audit recovery");
    }};
}
#[tokio::test]
async fn sqlite_password_audit_failure_rolls_back_capability_and_consumption() {
    let (store, path) = sqlite().await;
    failed_audit!(
        store,
        sqlite_create,
        "CREATE TRIGGER fail_password_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'owned audit failure'); END;",
        "DROP TRIGGER fail_password_audit"
    );
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_audit_failure_rolls_back_capability_and_consumption() {
    let (store, pool, schema) = postgres().await;
    failed_audit!(
        store,
        postgres_create,
        "CREATE FUNCTION fail_password_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END; $$; CREATE TRIGGER fail_password_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_password_audit();",
        "DROP TRIGGER fail_password_audit ON deployment_audit_events; DROP FUNCTION fail_password_audit();"
    );
    postgres_cleanup(store, pool, schema).await;
}
#[tokio::test]
async fn sqlite_password_competing_logins_cannot_overrun_account_capacity() {
    let (store, path) = sqlite().await;
    capability_race!(store, sqlite_create, sqlx::Sqlite, false);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_competing_logins_cannot_overrun_account_capacity() {
    let (store, pool, schema) = postgres().await;
    capability_race!(store, postgres_create, sqlx::Postgres, false);
    postgres_cleanup(store, pool, schema).await;
}

#[tokio::test]
async fn sqlite_password_global_capability_capacity_race_and_bounded_retirement() {
    let (store, path) = sqlite().await;
    capability_race!(store, sqlite_create, sqlx::Sqlite, true);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_global_capability_capacity_race_and_bounded_retirement() {
    let (store, pool, schema) = postgres().await;
    capability_race!(store, postgres_create, sqlx::Postgres, true);
    postgres_cleanup(store, pool, schema).await;
}

macro_rules! wrong_secret {
    ($store:expr,$create:ident) => {{
        let store = &$store;
        initialize!(store);
        let _ = establish!(store, $create, "wrong-secret-user");
        admit!(store, Endpoint::PasswordOptions);
        let issued = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("wrong-secret-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("current options");
        admit!(store, Endpoint::PasswordLogin);
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(issued.attempt_id, SecretBytes::new([91; 32])),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("wrong secret consumes attempt"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("wrong secret discloses no bootstrap authority"),
            0
        );
        let debt: Vec<i64> = sqlx::query_scalar(
            "SELECT failure_streak FROM account_entry_admission WHERE endpoint=4 ORDER BY kind",
        )
        .fetch_all(store.pool())
        .await
        .expect("only admitted source and username debt");
        assert_eq!(debt, vec![1, 1]);
    }};
}
#[tokio::test]
async fn sqlite_password_wrong_known_credential_consumes_matching_attempt() {
    let (store, path) = sqlite().await;
    wrong_secret!(store, sqlite_create);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_wrong_known_credential_consumes_matching_attempt() {
    let (store, pool, schema) = postgres().await;
    wrong_secret!(store, postgres_create);
    postgres_cleanup(store, pool, schema).await;
}

macro_rules! deadline_rollback {
    ($store:expr,$begin:ident,$create:ident) => {{
        let store=&$store;
        initialize!(store);
        let (_,secrets)=establish!(store,$create,"deadline-user");
        admit!(store,Endpoint::PasswordOptions);
        let issued=store.issue_account_password_options(source(),ORIGIN,&options("deadline-user"),&Kms,deadline()).await.expect("options");
        admit!(store,Endpoint::PasswordLogin);
        let mut blocker=$begin(store).await.expect("blocking owner");
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms WHERE singleton=1").execute(&mut *blocker).await.expect("hold singleton");
        let instance=store.clone();
        let body=login(issued.attempt_id.clone(),secrets.auth_secret().clone());
        let task=tokio::spawn(async move {
            instance.execute_account_password_login(source(),ORIGIN,body,&Kms,Instant::now()+Duration::from_millis(25)).await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        blocker.rollback().await.expect("release blocked preparation");
        assert!(matches!(task.await.expect("timed out caller"),Err(Error::StorageUnavailable)));
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM account_password_attempts").fetch_one(store.pool()).await.expect("rollback preserves attempt"),1);
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM account_admission_capabilities").fetch_one(store.pool()).await.expect("no capability"),0);
        store.execute_account_password_login(source(),ORIGIN,login(issued.attempt_id,secrets.auth_secret().clone()),&Kms,deadline()).await.expect("fresh bounded retry succeeds");
    }};
}
#[tokio::test]
async fn sqlite_password_deadline_rolls_back_before_failure_audit() {
    let (store, path) = sqlite().await;
    deadline_rollback!(store, sqlite_begin, sqlite_create);
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_deadline_rolls_back_before_failure_audit() {
    let (store, pool, schema) = postgres().await;
    deadline_rollback!(store, postgres_begin, postgres_create);
    postgres_cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_unconfirmed_login_commit_discloses_no_capability() {
    use std::sync::atomic::Ordering;
    let (store, pool, schema) = postgres().await;
    initialize!(store);
    let (_, secrets) = establish!(store, postgres_create, "lost-response-user");
    admit!(store, Endpoint::PasswordOptions);
    let issued = store
        .issue_account_password_options(
            source(),
            ORIGIN,
            &options("lost-response-user"),
            &Kms,
            deadline(),
        )
        .await
        .expect("options");
    admit!(store, Endpoint::PasswordLogin);
    let mut url =
        url::Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("fixture URL"))
            .expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .execute_account_password_login(
                source(),
                ORIGIN,
                login(issued.attempt_id, secrets.auth_secret().clone()),
                &Kms,
                deadline()
            )
            .await,
        Err(Error::StorageUnavailable)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
            .fetch_one(store.pool())
            .await
            .expect("committed secret never disclosed"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
            .fetch_one(store.pool())
            .await
            .expect("attempt committed once"),
        0
    );
    pool_close::close(uncertain.pool()).await;
    drop(uncertain);
    drop(proxy);
    postgres_cleanup(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_rechecks_verifier_after_waiting_for_account_lock() {
    let (store, pool, schema) = postgres().await;
    initialize!(store);
    let (payload, secrets) = establish!(store, postgres_create, "current-proof-user");
    // Future lifecycle fault injection is confined to this disposable schema.
    sqlx::query("DROP TRIGGER account_password_bootstrap_guard ON account_password_bootstrap")
        .execute(store.pool())
        .await
        .expect("allow owned credential-change fixture");
    admit!(store, Endpoint::PasswordOptions);
    let issued = store
        .issue_account_password_options(
            source(),
            ORIGIN,
            &options("current-proof-user"),
            &Kms,
            deadline(),
        )
        .await
        .expect("options");
    admit!(store, Endpoint::PasswordLogin);
    let mut blocker = postgres_begin(&store).await.expect("Account lifecycle owner");
    let owner: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("lock owner");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(payload.account_id.as_bytes().as_slice())
        .execute(&mut *blocker)
        .await
        .expect("hold Account lock");
    let instance = store.clone();
    let body = login(issued.attempt_id, secrets.auth_secret().clone());
    let task = tokio::spawn(async move {
        instance.execute_account_password_login(source(), ORIGIN, body, &Kms, deadline()).await
    });
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
        )
        .bind(owner)
        .fetch_one(store.pool())
        .await
        .expect("observe Account lock waiter");
        if waiting {
            break;
        }
        assert!(Instant::now() < wait_deadline, "login did not reach Account lock");
        tokio::task::yield_now().await;
    }
    sqlx::query("UPDATE account_password_bootstrap SET verifier=$1 WHERE account_id=$2")
        .bind([12_u8; 32].as_slice())
        .bind(payload.account_id.as_bytes().as_slice())
        .execute(&mut *blocker)
        .await
        .expect("credential changes after initial proof");
    blocker.commit().await.expect("publish credential and release Account lock");
    assert!(matches!(
        task.await.expect("current proof result"),
        Err(Error::AuthenticationRequired)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
            .fetch_one(store.pool())
            .await
            .expect("old proof cannot authorize new snapshot"),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
            .fetch_one(store.pool())
            .await
            .expect("denial consumed once"),
        0
    );
    postgres_cleanup(store, pool, schema).await;
}

macro_rules! final_expiry {
    ($store:expr,$create:ident,$install:expr,$remove:expr) => {{
        let store = &$store;
        initialize!(store);
        let (_, secrets) = establish!(store, $create, "final-expiry-user");
        admit!(store, Endpoint::PasswordOptions);
        let issued = store
            .issue_account_password_options(
                source(),
                ORIGIN,
                &options("final-expiry-user"),
                &Kms,
                deadline(),
            )
            .await
            .expect("options");
        admit!(store, Endpoint::PasswordLogin);
        let before =
            store.deployment_audit_head().await.expect("head").expect("initial audit").sequence;
        let mut owner = store.pool().acquire().await.expect("owned expiry injection connection");
        sqlx::raw_sql($install)
            .execute(&mut *owner)
            .await
            .expect("advance clock only on staged password success");
        assert!(matches!(
            store
                .execute_account_password_login(
                    source(),
                    ORIGIN,
                    login(issued.attempt_id, secrets.auth_secret().clone()),
                    &Kms,
                    deadline()
                )
                .await,
            Err(Error::AuthenticationRequired)
        ));
        sqlx::raw_sql($remove).execute(&mut *owner).await.expect("remove owned clock injection");
        drop(owner);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_admission_capabilities")
                .fetch_one(store.pool())
                .await
                .expect("no expired capability"),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_password_attempts")
                .fetch_one(store.pool())
                .await
                .expect("denial consumption"),
            0
        );
        assert_eq!(
            store.deployment_audit_head().await.expect("head").expect("denial only").sequence,
            before + 1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT time_high_water_ms FROM account_entry_state")
                .fetch_one(store.pool())
                .await
                .expect("expired observation remains durable"),
            FUTURE + 120_000
        );
        let debt: Vec<i64> = sqlx::query_scalar(
            "SELECT failure_streak FROM account_entry_admission WHERE endpoint=4 ORDER BY kind",
        )
        .fetch_all(store.pool())
        .await
        .expect("success reset rolled back before denial");
        assert_eq!(debt, vec![1, 1, 1]);
    }};
}
#[tokio::test]
async fn sqlite_password_final_expiry_rolls_back_capability_and_success_audit() {
    let (store, path) = sqlite().await;
    final_expiry!(
        store,
        sqlite_create,
        "CREATE TRIGGER expire_password_success AFTER INSERT ON deployment_audit_events WHEN substr(NEW.event_bytes,1,length('spl-account-password-outcome-v1'))=CAST('spl-account-password-outcome-v1' AS BLOB) BEGIN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+120000; END;",
        "DROP TRIGGER expire_password_success"
    );
    pool_close::close(store.pool()).await;
    drop(store);
    support::remove_test_directory(path).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_final_expiry_rolls_back_capability_and_success_audit() {
    let (store, pool, schema) = postgres().await;
    final_expiry!(
        store,
        postgres_create,
        "CREATE FUNCTION expire_password_success() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF substring(NEW.event_bytes from 1 for length('spl-account-password-outcome-v1'))=convert_to('spl-account-password-outcome-v1','UTF8') THEN UPDATE account_entry_state SET time_high_water_ms=time_high_water_ms+120000; END IF; RETURN NEW; END; $$; CREATE TRIGGER expire_password_success AFTER INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION expire_password_success();",
        "DROP TRIGGER expire_password_success ON deployment_audit_events; DROP FUNCTION expire_password_success();"
    );
    postgres_cleanup(store, pool, schema).await;
}
