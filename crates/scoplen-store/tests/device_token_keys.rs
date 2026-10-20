// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use support::remove_test_directory;

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{DeviceAccessTokenSigner, ed25519_verify};
use scoplen_store::{
    RelationalStore, SqliteStore, device_token_keys::DeviceTokenKeyError, kms::KeyManagementService,
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
        std::env::temp_dir().join(format!("scoplen-device-token-keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create test directory");
    path
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("time range")
}

#[tokio::test]
async fn sqlite_device_token_key_state_rejects_null_gaps() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    for (retired_at, verify_until) in [(None::<i64>, None::<i64>), (Some(2), None)] {
        let result = sqlx::query("INSERT INTO device_access_token_keys (kid, public_key, encrypted_seed, activated_at_ms, retired_at_ms, verify_until_ms, active_slot) VALUES (?, ?, ?, 1, ?, ?, ?)")
            .bind("0123456789abcdef0123456789abcdef")
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
            let ring = store.ensure_device_token_keyring(&TestKms([7; 32])).await.expect("keyring");
            let signature = ring.signing_key().sign(b"device-access-token").expect("sign");
            ed25519_verify(ring.signing_key().public_key(), b"device-access-token", &signature)
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
    let key_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_access_token_keys")
        .fetch_one(first.pool())
        .await
        .expect("key count");
    assert_eq!(key_count, 1);
    assert_eq!(
        first.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        1
    );
    let stored: Vec<u8> = sqlx::query_scalar("SELECT encrypted_seed FROM device_access_token_keys")
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
async fn sqlite_rotation_overlap_wrong_kms_and_tamper_fail_closed() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let kms = TestKms([8; 32]);
    let original = store.ensure_device_token_keyring(&kms).await.expect("first key");
    let old_kid = original.signing_key().kid().to_owned();
    assert!(matches!(
        store.ensure_device_token_keyring(&TestKms([9; 32])).await,
        Err(DeviceTokenKeyError::Integrity)
    ));
    assert!(matches!(
        store.ensure_device_token_keyring(&TestKms([0; 32])).await,
        Err(DeviceTokenKeyError::Integrity)
    ));
    let old_at = now_ms() - 30 * 24 * 60 * 60 * 1_000 - 1_000;
    sqlx::query("UPDATE device_access_token_keys SET activated_at_ms = ? WHERE kid = ?")
        .bind(old_at)
        .bind(&old_kid)
        .execute(store.pool())
        .await
        .expect("age key");
    let rotated = store.ensure_device_token_keyring(&kms).await.expect("rotate");
    assert_ne!(rotated.signing_key().kid(), old_kid);
    assert_eq!(rotated.verification_keys().len(), 2);
    assert!(rotated.verification_keys().iter().any(|key| key.kid == old_kid));
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        2
    );
    let current_kid = rotated.signing_key().kid();
    let current_public: Vec<u8> =
        sqlx::query_scalar("SELECT public_key FROM device_access_token_keys WHERE kid = ?")
            .bind(current_kid)
            .fetch_one(store.pool())
            .await
            .expect("current public key");
    let old_public: Vec<u8> =
        sqlx::query_scalar("SELECT public_key FROM device_access_token_keys WHERE kid = ?")
            .bind(&old_kid)
            .fetch_one(store.pool())
            .await
            .expect("old public key");
    sqlx::query("UPDATE device_access_token_keys SET public_key = ? WHERE kid = ?")
        .bind(&old_public)
        .bind(current_kid)
        .execute(store.pool())
        .await
        .expect("tamper public key");
    assert!(matches!(
        store.ensure_device_token_keyring(&kms).await,
        Err(DeviceTokenKeyError::Integrity)
    ));
    sqlx::query("UPDATE device_access_token_keys SET public_key = ? WHERE kid = ?")
        .bind(&current_public)
        .bind(current_kid)
        .execute(store.pool())
        .await
        .expect("restore public key");

    let simulated_retirement = now_ms() - 8 * 24 * 60 * 60 * 1_000;
    sqlx::query(
        "UPDATE device_access_token_keys SET retired_at_ms = ?, verify_until_ms = ? WHERE kid = ?",
    )
    .bind(simulated_retirement)
    .bind(simulated_retirement + 7 * 24 * 60 * 60 * 1_000)
    .bind(&old_kid)
    .execute(store.pool())
    .await
    .expect("age retired key");
    sqlx::query("UPDATE device_access_token_keys SET activated_at_ms = ? WHERE kid = ?")
        .bind(simulated_retirement)
        .bind(current_kid)
        .execute(store.pool())
        .await
        .expect("age active key");
    let expired_overlap = store.ensure_device_token_keyring(&kms).await.expect("expired overlap");
    assert_eq!(expired_overlap.verification_keys().len(), 1);
    let next = store.ensure_device_token_keyring(&kms).await.expect("same active key");
    assert_eq!(next.signing_key().kid(), rotated.signing_key().kid());
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("event").sequence,
        2
    );

    sqlx::query("UPDATE device_access_token_keys SET encrypted_seed = zeroblob(73) WHERE kid = ?")
        .bind(rotated.signing_key().kid())
        .execute(store.pool())
        .await
        .expect("tamper key");
    assert!(matches!(
        store.ensure_device_token_keyring(&kms).await,
        Err(DeviceTokenKeyError::Integrity)
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
        store.ensure_device_token_keyring(&TestKms([4; 32])).await,
        Err(DeviceTokenKeyError::Audit(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_access_token_keys")
        .fetch_one(store.pool())
        .await
        .expect("rolled-back key count");
    assert_eq!(count, 0);
    sqlx::query("DROP TRIGGER fail_key_audit").execute(store.pool()).await.expect("drop trigger");

    let transaction = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("hold write lock");
    let waiting_store = store.clone();
    let waiter = tokio::spawn(async move {
        waiting_store.ensure_device_token_keyring(&TestKms([4; 32])).await.expect("waited keyring")
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    let before_release = now_ms();
    transaction.commit().await.expect("release write lock");
    let ring = waiter.await.expect("join");
    let activated_at: i64 =
        sqlx::query_scalar("SELECT activated_at_ms FROM device_access_token_keys WHERE kid = ?")
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
#[tokio::test]
async fn postgres_device_token_key_state_rejects_null_gaps() {
    use scoplen_store::PostgresStore;

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    for (retired_at, verify_until) in [(None::<i64>, None::<i64>), (Some(2), None)] {
        let result = sqlx::query("INSERT INTO device_access_token_keys (kid, public_key, encrypted_seed, activated_at_ms, retired_at_ms, verify_until_ms, active_slot) VALUES ($1, $2, $3, 1, $4, $5, $6)")
            .bind("0123456789abcdef0123456789abcdef")
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
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_concurrent_creation_rotation_tamper_and_audit_rollback() {
    use scoplen_store::PostgresStore;

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    let kms = TestKms([5; 32]);
    let baseline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_access_token_keys")
        .fetch_one(store.pool())
        .await
        .expect("baseline");
    assert_eq!(baseline, 0, "use an isolated PostgreSQL integration database");
    let audit_baseline = store
        .deployment_audit_head()
        .await
        .expect("audit baseline")
        .map_or(0, |head| head.sequence);
    sqlx::query("CREATE FUNCTION s6_fail_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$")
        .execute(store.pool()).await.expect("audit failure function");
    sqlx::query("CREATE TRIGGER s6_fail_key_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION s6_fail_key_audit()")
        .execute(store.pool()).await.expect("audit failure trigger");
    assert!(matches!(
        store.ensure_device_token_keyring(&kms).await,
        Err(DeviceTokenKeyError::Audit(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_access_token_keys")
        .fetch_one(store.pool())
        .await
        .expect("rolled-back create");
    assert_eq!(count, 0);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").map_or(0, |head| head.sequence),
        audit_baseline
    );
    sqlx::query("DROP TRIGGER s6_fail_key_audit ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("drop audit trigger");
    sqlx::query("DROP FUNCTION s6_fail_key_audit()")
        .execute(store.pool())
        .await
        .expect("drop audit function");

    let mut blocker = store.pool().begin().await.expect("begin lock holder");
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1263683911)")
        .fetch_one(&mut *blocker)
        .await
        .expect("hold keyring lock");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .ensure_device_token_keyring(&TestKms([5; 32]))
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
        sqlx::query_scalar("SELECT activated_at_ms FROM device_access_token_keys WHERE kid = $1")
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
    sqlx::query("UPDATE device_access_token_keys SET activated_at_ms = $1 WHERE kid = $2")
        .bind(old_at)
        .bind(&kids[0])
        .execute(store.pool())
        .await
        .expect("age key");
    sqlx::query("CREATE FUNCTION s6_fail_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$")
        .execute(store.pool()).await.expect("rotation failure function");
    sqlx::query("CREATE TRIGGER s6_fail_key_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION s6_fail_key_audit()")
        .execute(store.pool()).await.expect("rotation failure trigger");
    assert!(matches!(
        store.ensure_device_token_keyring(&kms).await,
        Err(DeviceTokenKeyError::Audit(_))
    ));
    let active_kid: String =
        sqlx::query_scalar("SELECT kid FROM device_access_token_keys WHERE active_slot = 1")
            .fetch_one(store.pool())
            .await
            .expect("active after rollback");
    assert_eq!(active_kid, kids[0]);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("created").sequence,
        audit_baseline + 1
    );
    sqlx::query("DROP TRIGGER s6_fail_key_audit ON deployment_audit_events")
        .execute(store.pool())
        .await
        .expect("drop rotation trigger");
    sqlx::query("DROP FUNCTION s6_fail_key_audit()")
        .execute(store.pool())
        .await
        .expect("drop rotation function");
    let rotated = store.ensure_device_token_keyring(&kms).await.expect("rotate");
    assert_eq!(rotated.verification_keys().len(), 2);
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("rotated").sequence,
        audit_baseline + 2
    );
    assert!(matches!(
        store.ensure_device_token_keyring(&TestKms([6; 32])).await,
        Err(DeviceTokenKeyError::Integrity)
    ));
    sqlx::query("UPDATE device_access_token_keys SET encrypted_seed = decode(repeat('00', 73), 'hex') WHERE kid = $1")
        .bind(rotated.signing_key().kid()).execute(store.pool()).await.expect("tamper");
    assert!(matches!(
        store.ensure_device_token_keyring(&kms).await,
        Err(DeviceTokenKeyError::Integrity)
    ));
}
