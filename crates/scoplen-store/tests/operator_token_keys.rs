// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use support::remove_test_directory;

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{
    OperatorAccessToken, OperatorAccessTokenClaims, OperatorAccessTokenSigner, P256SigningKey,
    TrustedOperatorAccessTokenKeys, dpop_jwk_thumbprint, ed25519_verify,
};
use scoplen_store::{
    RelationalStore, SqliteStore, kms::KeyManagementService,
    operator_token_keys::OperatorTokenKeyError,
};

struct TestKms([u8; 32]);

impl KeyManagementService for TestKms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &self.0
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}

fn directory() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("scoplen-operator-token-keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create test directory");
    path
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("time range")
}

#[tokio::test]
async fn sqlite_operator_token_key_state_rejects_null_gaps() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    for (retired_at, verify_until) in [(None::<i64>, None::<i64>), (Some(2), None)] {
        let result = sqlx::query("INSERT INTO operator_access_token_keys (kid, public_key, encrypted_seed, activated_at_ms, retired_at_ms, verify_until_ms, active_slot) VALUES (?, ?, ?, 1, ?, ?, ?)")
            .bind("operator-0123456789abcdef0123456789abcdef")
            .bind(vec![0_u8; 32])
            .bind(vec![0_u8; 73])
            .bind(retired_at)
            .bind(verify_until)
            .bind(Option::<i64>::None)
            .execute(store.pool())
            .await;
        assert!(matches!(result, Err(sqlx::Error::Database(error)) if error.is_check_violation()));
    }
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_concurrent_creation_is_one_audited_encrypted_key() {
    let directory = directory();
    let path = directory.join("scoplen.sqlite");
    let first = SqliteStore::open(&path).await.expect("first instance");
    let second = SqliteStore::open(&path).await.expect("second instance");
    let mut tasks = Vec::new();
    for index in 0..8 {
        let store = if index % 2 == 0 { first.clone() } else { second.clone() };
        tasks.push(tokio::spawn(async move {
            let ring =
                store.ensure_operator_token_keyring(&TestKms([7; 32])).await.expect("keyring");
            let signature = ring.signing_key().sign(b"operator-access-token").expect("sign");
            ed25519_verify(ring.signing_key().public_key(), b"operator-access-token", &signature)
                .expect("matching key");
            assert_eq!(ring.verification_keys().len(), 1);
            assert!(format!("{ring:?}").contains("[REDACTED]"));
            ring.signing_key().kid().to_owned()
        }));
    }
    let mut kids = Vec::new();
    for task in tasks {
        kids.push(task.await.expect("join"));
    }
    assert!(kids.iter().all(|kid| kid == &kids[0]));
    let key_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_access_token_keys")
        .fetch_one(first.pool())
        .await
        .expect("key count");
    assert_eq!(key_count, 1);
    assert_eq!(
        first.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        1
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_seed FROM operator_access_token_keys")
            .fetch_one(first.pool())
            .await
            .expect("ciphertext");
    assert_eq!(stored.len(), 73);
    assert_eq!(stored[0], 1);
    first.pool().close().await;
    second.pool().close().await;
    drop((first, second));
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_operator_signing_and_envelopes_are_separate_from_device_keys() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let kms = TestKms([7; 32]);
    let operator = store.ensure_operator_token_keyring(&kms).await.expect("Operator key");
    let device = store.ensure_device_token_keyring(&kms).await.expect("device key");
    let operator_key = operator.signing_key();
    let device_key = device.signing_key();
    assert!(operator_key.kid().starts_with("operator-"));
    assert_eq!(device_key.kid().len(), 32);
    assert_ne!(operator_key.public_key(), device_key.public_key());

    let issuer = "https://example.com";
    let mut trusted = TrustedOperatorAccessTokenKeys::new(issuer).expect("issuer");
    trusted.insert(operator_key.kid(), operator_key.public_key()).expect("Operator public key");
    let now = u64::try_from(now_ms() / 1_000).expect("seconds");
    let browser = P256SigningKey::from_bytes(&[3; 32]).expect("browser key");
    let claims = OperatorAccessTokenClaims {
        iss: issuer.to_owned(),
        sub: uuid::Uuid::now_v7(),
        sid: uuid::Uuid::now_v7(),
        jti: uuid::Uuid::now_v7(),
        cnf_jkt: dpop_jwk_thumbprint(&browser.public_key_sec1()).expect("thumbprint"),
        scope: "personal-invitation:issue".to_owned(),
        iat: now,
        exp: now + 600,
    };
    let token = OperatorAccessToken::sign(operator_key, &trusted, operator_key.kid(), &claims)
        .expect("dedicated Operator signer");
    assert_eq!(token.verify(&trusted, now).expect("Operator JWT").claims().sub, claims.sub);
    let mut substituted = TrustedOperatorAccessTokenKeys::new(issuer).expect("issuer");
    substituted.insert(operator_key.kid(), device_key.public_key()).expect("substituted key");
    assert!(token.verify(&substituted, now).is_err());

    let original: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_seed FROM operator_access_token_keys WHERE kid = ?")
            .bind(operator_key.kid())
            .fetch_one(store.pool())
            .await
            .expect("Operator envelope");
    sqlx::query("UPDATE operator_access_token_keys SET public_key = (SELECT public_key FROM device_access_token_keys WHERE active_slot = 1), encrypted_seed = (SELECT encrypted_seed FROM device_access_token_keys WHERE active_slot = 1)")
        .execute(store.pool()).await.expect("substitute device envelope and public key");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    assert_eq!(
        store
            .ensure_device_token_keyring(&kms)
            .await
            .expect("device remains healthy")
            .signing_key()
            .kid(),
        device_key.kid()
    );
    sqlx::query(
        "UPDATE operator_access_token_keys SET public_key = ?, encrypted_seed = ?, kid = ?",
    )
    .bind(operator_key.public_key().as_slice())
    .bind(original)
    .bind("operator-0123456789abcdef0123456789abcdef")
    .execute(store.pool())
    .await
    .expect("substitute only key identifier");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_rotation_overlap_wrong_kms_and_tamper_fail_closed() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let kms = TestKms([8; 32]);
    let original = store.ensure_operator_token_keyring(&kms).await.expect("first key");
    let old_kid = original.signing_key().kid().to_owned();
    assert!(matches!(
        store.ensure_operator_token_keyring(&TestKms([9; 32])).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    assert!(matches!(
        store.ensure_operator_token_keyring(&TestKms([0; 32])).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    let old_at = now_ms() - 30 * 24 * 60 * 60 * 1_000 - 1_000;
    sqlx::query("UPDATE operator_access_token_keys SET activated_at_ms = ? WHERE kid = ?")
        .bind(old_at)
        .bind(&old_kid)
        .execute(store.pool())
        .await
        .expect("age key");
    let rotated = store.ensure_operator_token_keyring(&kms).await.expect("rotate");
    assert_ne!(rotated.signing_key().kid(), old_kid);
    assert_eq!(rotated.verification_keys().len(), 2);
    assert!(rotated.verification_keys().iter().any(|key| key.kid == old_kid));
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        2
    );
    let current_kid = rotated.signing_key().kid();
    let current_public: Vec<u8> =
        sqlx::query_scalar("SELECT public_key FROM operator_access_token_keys WHERE kid = ?")
            .bind(current_kid)
            .fetch_one(store.pool())
            .await
            .expect("current public key");
    let old_public: Vec<u8> =
        sqlx::query_scalar("SELECT public_key FROM operator_access_token_keys WHERE kid = ?")
            .bind(&old_kid)
            .fetch_one(store.pool())
            .await
            .expect("old public key");
    sqlx::query("UPDATE operator_access_token_keys SET public_key = ? WHERE kid = ?")
        .bind(&old_public)
        .bind(current_kid)
        .execute(store.pool())
        .await
        .expect("tamper public key");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    sqlx::query("UPDATE operator_access_token_keys SET public_key = ? WHERE kid = ?")
        .bind(&current_public)
        .bind(current_kid)
        .execute(store.pool())
        .await
        .expect("restore public key");

    let simulated_retirement = now_ms() - 8 * 24 * 60 * 60 * 1_000;
    sqlx::query(
        "UPDATE operator_access_token_keys SET retired_at_ms = ?, verify_until_ms = ? WHERE kid = ?",
    )
    .bind(simulated_retirement)
    .bind(simulated_retirement + 7 * 24 * 60 * 60 * 1_000)
    .bind(&old_kid)
    .execute(store.pool())
    .await
    .expect("age retired key");
    sqlx::query("UPDATE operator_access_token_keys SET activated_at_ms = ? WHERE kid = ?")
        .bind(simulated_retirement)
        .bind(current_kid)
        .execute(store.pool())
        .await
        .expect("age active key");
    let expired_overlap = store.ensure_operator_token_keyring(&kms).await.expect("expired overlap");
    assert_eq!(expired_overlap.verification_keys().len(), 1);
    let next = store.ensure_operator_token_keyring(&kms).await.expect("same active key");
    assert_eq!(next.signing_key().kid(), rotated.signing_key().kid());
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        2
    );

    sqlx::query(
        "UPDATE operator_access_token_keys SET encrypted_seed = zeroblob(73) WHERE kid = ?",
    )
    .bind(rotated.signing_key().kid())
    .execute(store.pool())
    .await
    .expect("tamper key");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_audit_failure_rolls_back_and_time_is_sampled_after_lock() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    sqlx::query("CREATE TRIGGER fail_key_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
        .execute(store.pool()).await.expect("trigger");
    assert!(matches!(
        store.ensure_operator_token_keyring(&TestKms([4; 32])).await,
        Err(OperatorTokenKeyError::Audit(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_access_token_keys")
        .fetch_one(store.pool())
        .await
        .expect("rolled-back key count");
    assert_eq!(count, 0);
    sqlx::query("DROP TRIGGER fail_key_audit").execute(store.pool()).await.expect("drop trigger");

    let transaction = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("hold write lock");
    let waiting_store = store.clone();
    let waiter = tokio::spawn(async move {
        waiting_store
            .ensure_operator_token_keyring(&TestKms([4; 32]))
            .await
            .expect("waited keyring")
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    let before_release = now_ms();
    transaction.commit().await.expect("release write lock");
    let ring = waiter.await.expect("join");
    let activated_at: i64 =
        sqlx::query_scalar("SELECT activated_at_ms FROM operator_access_token_keys WHERE kid = ?")
            .bind(ring.signing_key().kid())
            .fetch_one(store.pool())
            .await
            .expect("activation");
    assert!(activated_at >= before_release, "clock must be sampled after the write lock");
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        1
    );
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (scoplen_store::PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
    let schema = format!("operator_token_keys_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("PG URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("PG store");
    (store, pool, schema)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(store: scoplen_store::PostgresStore, pool: sqlx::PgPool, schema: String) {
    store.pool().close().await;
    assert!(
        schema.starts_with("operator_token_keys_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_operator_token_key_state_rejects_null_gaps() {
    let (store, pool, schema) = postgres_fixture().await;
    for (retired_at, verify_until) in [(None::<i64>, None::<i64>), (Some(2), None)] {
        let result = sqlx::query("INSERT INTO operator_access_token_keys (kid, public_key, encrypted_seed, activated_at_ms, retired_at_ms, verify_until_ms, active_slot) VALUES ($1, $2, $3, 1, $4, $5, $6)")
            .bind("operator-0123456789abcdef0123456789abcdef")
            .bind(vec![0_u8; 32])
            .bind(vec![0_u8; 73])
            .bind(retired_at)
            .bind(verify_until)
            .bind(Option::<i64>::None)
            .execute(store.pool())
            .await;
        assert!(matches!(result, Err(sqlx::Error::Database(error)) if error.is_check_violation()));
    }
    cleanup_postgres(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_concurrent_creation_rotation_tamper_and_audit_rollback() {
    let (store, pool, schema) = postgres_fixture().await;
    let kms = TestKms([5; 32]);
    let baseline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_access_token_keys")
        .fetch_one(store.pool())
        .await
        .expect("baseline");
    assert_eq!(baseline, 0, "use an isolated PostgreSQL integration database");
    let audit_baseline = store
        .deployment_audit_head()
        .await
        .expect("audit baseline")
        .map_or(0, |head| head.sequence);
    sqlx::query("CREATE FUNCTION s6_fail_operator_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$")
        .execute(store.pool()).await.expect("audit failure function");
    sqlx::query("CREATE TRIGGER s6_fail_operator_key_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION s6_fail_operator_key_audit()")
        .execute(store.pool()).await.expect("audit failure trigger");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Audit(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_access_token_keys")
        .fetch_one(store.pool())
        .await
        .expect("rolled-back create");
    assert_eq!(count, 0);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").map_or(0, |head| head.sequence),
        audit_baseline
    );
    sqlx::query("DROP TRIGGER s6_fail_operator_key_audit ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("drop audit trigger");
    sqlx::query("DROP FUNCTION s6_fail_operator_key_audit()")
        .execute(store.pool())
        .await
        .expect("drop audit function");

    let mut blocker = store.pool().begin().await.expect("begin lock holder");
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1263683912)")
        .fetch_one(&mut *blocker)
        .await
        .expect("hold keyring lock");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .ensure_operator_token_keyring(&TestKms([5; 32]))
                .await
                .expect("keyring")
                .signing_key()
                .kid()
                .to_owned()
        }));
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    let before_release = now_ms();
    blocker.commit().await.expect("release keyring lock");
    let mut kids = Vec::new();
    for task in tasks {
        kids.push(task.await.expect("join"));
    }
    assert!(kids.iter().all(|kid| kid == &kids[0]));
    let activated_at: i64 =
        sqlx::query_scalar("SELECT activated_at_ms FROM operator_access_token_keys WHERE kid = $1")
            .bind(&kids[0])
            .fetch_one(store.pool())
            .await
            .expect("activation");
    assert!(activated_at >= before_release, "clock must be sampled after the advisory lock");
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("created").sequence,
        audit_baseline + 1
    );
    let old_at = now_ms() - 30 * 24 * 60 * 60 * 1_000 - 1_000;
    sqlx::query("UPDATE operator_access_token_keys SET activated_at_ms = $1 WHERE kid = $2")
        .bind(old_at)
        .bind(&kids[0])
        .execute(store.pool())
        .await
        .expect("age key");
    sqlx::query("CREATE FUNCTION s6_fail_operator_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$")
        .execute(store.pool()).await.expect("rotation failure function");
    sqlx::query("CREATE TRIGGER s6_fail_operator_key_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION s6_fail_operator_key_audit()")
        .execute(store.pool()).await.expect("rotation failure trigger");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Audit(_))
    ));
    let active_kid: String =
        sqlx::query_scalar("SELECT kid FROM operator_access_token_keys WHERE active_slot = 1")
            .fetch_one(store.pool())
            .await
            .expect("active after rollback");
    assert_eq!(active_kid, kids[0]);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("created").sequence,
        audit_baseline + 1
    );
    sqlx::query("DROP TRIGGER s6_fail_operator_key_audit ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("drop rotation trigger");
    sqlx::query("DROP FUNCTION s6_fail_operator_key_audit()")
        .execute(store.pool())
        .await
        .expect("drop rotation function");
    let rotated = store.ensure_operator_token_keyring(&kms).await.expect("rotate");
    assert_eq!(rotated.verification_keys().len(), 2);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("rotated").sequence,
        audit_baseline + 2
    );
    assert!(matches!(
        store.ensure_operator_token_keyring(&TestKms([6; 32])).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    let device = store.ensure_device_token_keyring(&kms).await.expect("independent device key");
    assert_ne!(device.signing_key().public_key(), rotated.signing_key().public_key());
    sqlx::query("UPDATE operator_access_token_keys SET public_key = (SELECT public_key FROM device_access_token_keys WHERE active_slot = 1), encrypted_seed = (SELECT encrypted_seed FROM device_access_token_keys WHERE active_slot = 1) WHERE active_slot = 1")
        .execute(store.pool()).await.expect("substitute device envelope and public key");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    assert_eq!(
        store
            .ensure_device_token_keyring(&kms)
            .await
            .expect("device remains healthy")
            .signing_key()
            .kid(),
        device.signing_key().kid()
    );
    sqlx::query("UPDATE operator_access_token_keys SET encrypted_seed = decode(repeat('00', 73), 'hex') WHERE kid = $1")
        .bind(rotated.signing_key().kid()).execute(store.pool()).await.expect("tamper");
    assert!(matches!(
        store.ensure_operator_token_keyring(&kms).await,
        Err(OperatorTokenKeyError::Integrity)
    ));
    cleanup_postgres(store, pool, schema).await;
}
