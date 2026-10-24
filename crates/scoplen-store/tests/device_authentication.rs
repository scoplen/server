// SPDX-License-Identifier: AGPL-3.0-only

mod support;

#[cfg(feature = "postgres-integration")]
use std::time::Duration;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE;
use scoplen_crypto::{
    DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair, DpopProof, DpopTarget, DpopToken,
    Ed25519SigningKey, P256SigningKey, TrustedDeviceAccessTokenKeys,
};
#[cfg(feature = "postgres-integration")]
use scoplen_crypto::{RevocationStatement, dpop_jwk_thumbprint};
#[cfg(feature = "postgres-integration")]
use scoplen_store::PostgresStore;
use scoplen_store::{
    RelationalStore, SqliteStore,
    device_authentication::{DeviceAuthAdmission, DeviceAuthEndpoint, DeviceAuthenticationError},
    kms::KeyManagementService,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const ORIGIN: &str = "https://example.com";

struct TestKms([u8; 32]);

impl KeyManagementService for TestKms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &self.0
    }

    fn backend_name(&self) -> &'static str {
        "test"
    }
}

fn device_key() -> P256SigningKey {
    let mut scalar = [0_u8; 32];
    scalar[31] = 1;
    P256SigningKey::from_bytes(&scalar).expect("device key")
}

fn wrong_device_key() -> P256SigningKey {
    let mut scalar = [0_u8; 32];
    scalar[31] = 2;
    P256SigningKey::from_bytes(&scalar).expect("wrong device key")
}

fn account_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[7; 32]).expect("account key")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn source() -> IpAddr {
    "192.0.2.44".parse().expect("source address")
}

fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
}

fn now_millis() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("timestamp")
}

fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-device-auth-{}", Uuid::now_v7()));
    std::fs::create_dir(&path).expect("create test directory");
    path
}

fn certificate(account_id: Uuid, device_id: Uuid) -> Vec<u8> {
    let kem = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("KEM");
    DeviceCertificate::issue(
        &account_key(),
        device_id,
        account_id,
        device_key().public_key_sec1(),
        kem.public_key().to_vec(),
        "test device".into(),
        "windows".into(),
        1,
    )
    .expect("certificate")
    .encode()
    .expect("canonical certificate")
}

async fn seed_sqlite_identity(store: &SqliteStore) -> (Uuid, Uuid) {
    let account_id = Uuid::now_v7();
    let device_id = Uuid::now_v7();
    let certificate = certificate(account_id, device_id);
    sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, ?, ?, ?)")
        .bind(account_id.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
        .bind([4_u8; 32].as_slice()).bind(1_i64)
        .execute(store.pool()).await.expect("account");
    sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES (?, ?, ?, 1, ?)")
        .bind(device_id.as_bytes().as_slice()).bind(account_id.as_bytes().as_slice())
        .bind(&certificate).bind(1_i64)
        .execute(store.pool()).await.expect("device");
    sqlx::query(
        "INSERT INTO sync_account_key_certificates (account_id, certificate) VALUES (?, ?)",
    )
    .bind(account_id.as_bytes().as_slice())
    .bind(&certificate)
    .execute(store.pool())
    .await
    .expect("published certificate");
    (account_id, device_id)
}

#[cfg(feature = "postgres-integration")]
async fn seed_postgres_identity(store: &PostgresStore) -> (Uuid, Uuid) {
    let account_id = Uuid::now_v7();
    let device_id = Uuid::now_v7();
    let certificate = certificate(account_id, device_id);
    sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES ($1, $2, $3, $4)")
        .bind(account_id.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
        .bind([4_u8; 32].as_slice()).bind(1_i64)
        .execute(store.pool()).await.expect("account");
    sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES ($1, $2, $3, true, $4)")
        .bind(device_id.as_bytes().as_slice()).bind(account_id.as_bytes().as_slice())
        .bind(&certificate).bind(1_i64)
        .execute(store.pool()).await.expect("device");
    sqlx::query(
        "INSERT INTO sync_account_key_certificates (account_id, certificate) VALUES ($1, $2)",
    )
    .bind(account_id.as_bytes().as_slice())
    .bind(&certificate)
    .execute(store.pool())
    .await
    .expect("published certificate");
    (account_id, device_id)
}

#[cfg(feature = "postgres-integration")]
async fn wait_for_shared_account_key_lock(store: &PostgresStore) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock_shared%'")
                .fetch_one(store.pool()).await.expect("lock wait state");
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authentication must wait for account key replacement");
}

fn device_signature(device_id: Uuid, nonce: &[u8; 32]) -> [u8; 64] {
    let context = DeviceAuthContext::new(ORIGIN, &hex(nonce), device_id).expect("context");
    device_key().sign(&context.signature_input())
}

fn refresh_proof(key: &P256SigningKey) -> DpopProof {
    let target = DpopTarget::new("POST", ORIGIN, "/api/v1/auth/refresh").expect("target");
    DpopProof::sign(key, &key.public_key_sec1(), &target, DpopToken::Refresh, now_seconds(), None)
        .expect("proof")
}

async fn assert_sqlite_admission_windows(
    store: &SqliteStore,
    kind: i64,
    limit: i64,
    decisions: &[DeviceAuthAdmission],
) {
    let observations: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT window_start_ms, attempts FROM admission_observations WHERE kind=? ORDER BY sequence",
    )
    .bind(kind)
    .fetch_all(store.pool())
    .await
    .expect("committed admission observations");
    assert_eq!(observations.len(), decisions.len(), "every decision has one committed observation");
    let mut windows = BTreeMap::<i64, i64>::new();
    let mut expected_admitted = 0;
    for (window, attempts) in observations {
        let count = windows.entry(window).or_default();
        *count += 1;
        assert_eq!(
            attempts,
            (*count).min(limit),
            "exact quota sequence in committed window {window}"
        );
        if *count <= limit {
            expected_admitted += 1;
        }
    }
    let mut admitted = 0;
    for decision in decisions {
        match decision {
            DeviceAuthAdmission::Admitted => admitted += 1,
            DeviceAuthAdmission::RateLimited(delay) => assert!((1..=60).contains(delay)),
        }
    }
    assert_eq!(admitted, expected_admitted, "decisions match the exact quota in every window");
}

#[tokio::test]
async fn sqlite_admission_and_challenges_are_durable_and_non_identifying() {
    let directory = directory();
    let path = directory.join("scoplen.sqlite");
    let first = SqliteStore::open(&path).await.expect("first");
    let second = SqliteStore::open(&path).await.expect("second");
    // Real-clock transactions can span minutes; retain every committed counter transition.
    sqlx::raw_sql(
        "CREATE TABLE admission_observations (
             sequence INTEGER PRIMARY KEY, kind INTEGER, window_start_ms INTEGER, attempts INTEGER
         );
         CREATE TRIGGER observe_admission_insert AFTER INSERT ON device_auth_admission BEGIN
             INSERT INTO admission_observations (kind, window_start_ms, attempts)
                 VALUES (NEW.kind, NEW.window_start_ms, NEW.attempts);
         END;
         CREATE TRIGGER observe_admission_update AFTER UPDATE ON device_auth_admission BEGIN
             INSERT INTO admission_observations (kind, window_start_ms, attempts)
                 VALUES (NEW.kind, NEW.window_start_ms, NEW.attempts);
         END;",
    )
    .execute(first.pool())
    .await
    .expect("observe committed admission windows");
    let device_id = Uuid::now_v7();
    let mut tasks = Vec::new();
    for index in 0..40 {
        let store = if index % 2 == 0 { first.clone() } else { second.clone() };
        tasks.push(tokio::spawn(async move {
            store.admit_device_auth_source(DeviceAuthEndpoint::Challenge, source()).await
        }));
    }
    let mut decisions = Vec::new();
    for task in tasks {
        decisions.push(task.await.expect("join").expect("admission"));
    }
    assert_sqlite_admission_windows(&second, 1, 30, &decisions).await;
    let mut device_decisions = Vec::new();
    for index in 0..11 {
        let store = if index % 2 == 0 { &first } else { &second };
        device_decisions.push(
            store
                .admit_device_auth_device(DeviceAuthEndpoint::Challenge, *device_id.as_bytes())
                .await
                .expect("device admission"),
        );
    }
    assert_sqlite_admission_windows(&second, 2, 10, &device_decisions).await;
    let challenge = first.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let digest: [u8; 32] = Sha256::digest(challenge.nonce()).into();
    let stored: Vec<u8> = sqlx::query_scalar("SELECT nonce_digest FROM device_auth_challenges")
        .fetch_one(second.pool())
        .await
        .expect("stored digest");
    assert_eq!(stored, digest);
    assert_ne!(stored, challenge.nonce().to_vec());
    first.pool().close().await;
    second.pool().close().await;
    drop((first, second));
    support::remove_test_directory(directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_device_exchange_refresh_and_spent_reuse_revoke_atomically() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let ring = store.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("keyring");
    let (account_id, device_id) = seed_sqlite_identity(&store).await;
    assert_eq!(
        store.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source"),
        DeviceAuthAdmission::Admitted
    );
    assert_eq!(
        store
            .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
            .await
            .expect("device"),
        DeviceAuthAdmission::Admitted
    );
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let signed = device_signature(device_id, challenge.nonce());
    let first = store
        .authenticate_device(
            source(),
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &signed,
            &ring,
        )
        .await
        .expect("device exchange");
    let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in ring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("key");
    }
    let token = scoplen_crypto::DeviceAccessToken::parse(&first.access_token).expect("token");
    let claims = token.verify(&trusted, now_seconds()).expect("signed token");
    assert_eq!(claims.claims().sub, account_id);
    assert_eq!(claims.claims().did, device_id);
    assert_eq!(claims.claims().scope, INITIAL_DEVICE_ACCESS_SCOPE);
    assert_eq!(first.refresh_expires_in, 2_592_000);
    assert!(matches!(
        store
            .authenticate_device(
                source(),
                ORIGIN,
                *device_id.as_bytes(),
                challenge.nonce(),
                &signed,
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    store.admit_device_auth_source(DeviceAuthEndpoint::Refresh, source()).await.expect("source");
    let wrong_proof = refresh_proof(&wrong_device_key());
    assert!(matches!(
        store
            .refresh_device(source(), ORIGIN, &first.refresh_token, wrong_proof.as_str(), &ring)
            .await,
        Err(DeviceAuthenticationError::InvalidDpopProof)
    ));
    let revoked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_refresh_families WHERE revoked_at_ms IS NOT NULL",
    )
    .fetch_one(store.pool())
    .await
    .expect("revoked count");
    assert_eq!(revoked, 0);
    let source_failures: i64 = sqlx::query_scalar("SELECT failure_streak FROM device_auth_admission WHERE endpoint=3 AND kind=1 AND bucket_key=?")
        .bind([192_u8, 0, 2, 44].as_slice()).fetch_one(store.pool()).await.expect("source failures");
    assert_eq!(source_failures, 0);
    let second = store
        .refresh_device(
            source(),
            ORIGIN,
            &first.refresh_token,
            refresh_proof(&device_key()).as_str(),
            &ring,
        )
        .await
        .expect("rotation");
    assert!((1..=2_592_000).contains(&second.refresh_expires_in));
    assert_ne!(first.refresh_token, second.refresh_token);
    let used_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT token_digest FROM device_refresh_tokens WHERE spent_at_ms IS NOT NULL",
    )
    .fetch_one(store.pool())
    .await
    .expect("spent digest");
    assert_eq!(used_digest, Sha256::digest(first.refresh_token.as_bytes()).to_vec());
    assert!(matches!(
        store
            .refresh_device(
                source(),
                ORIGIN,
                &first.refresh_token,
                refresh_proof(&device_key()).as_str(),
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Denied { changed: true })
    ));
    let revoked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_refresh_families WHERE revoked_at_ms IS NOT NULL",
    )
    .fetch_one(store.pool())
    .await
    .expect("revoked count");
    assert_eq!(revoked, 1);
    store.pool().close().await;
    drop(store);
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_audit_failure_rolls_back_nonce_family_rotation_and_replay() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let ring = store.ensure_device_token_keyring(&TestKms([11; 32])).await.expect("keyring");
    let (_account_id, device_id) = seed_sqlite_identity(&store).await;
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let signature = device_signature(device_id, challenge.nonce());
    sqlx::query("CREATE TABLE device_auth_audit_fault (enabled INTEGER NOT NULL)")
        .execute(store.pool())
        .await
        .expect("fault control table");
    sqlx::query("INSERT INTO device_auth_audit_fault (enabled) VALUES (1)")
        .execute(store.pool())
        .await
        .expect("enable audit fault");
    // Keep the schema fixed while pooled connections exercise both rollback phases.
    sqlx::query("CREATE TRIGGER fail_device_auth_audit BEFORE INSERT ON deployment_audit_events WHEN (SELECT enabled FROM device_auth_audit_fault)=1 BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
        .execute(store.pool()).await.expect("failure trigger");
    assert!(matches!(
        store
            .authenticate_device(
                source(),
                ORIGIN,
                *device_id.as_bytes(),
                challenge.nonce(),
                &signature,
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Audit)
    ));
    let consumed: Option<i64> =
        sqlx::query_scalar("SELECT consumed_at_ms FROM device_auth_challenges")
            .fetch_one(store.pool())
            .await
            .expect("nonce state");
    assert_eq!(consumed, None);
    let families: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_refresh_families")
        .fetch_one(store.pool())
        .await
        .expect("family count");
    assert_eq!(families, 0);
    sqlx::query("UPDATE device_auth_audit_fault SET enabled=0")
        .execute(store.pool())
        .await
        .expect("restore audit");
    let first = store
        .authenticate_device(
            source(),
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &signature,
            &ring,
        )
        .await
        .expect("retry after known rollback");
    let proof = refresh_proof(&device_key());
    sqlx::query("UPDATE device_auth_audit_fault SET enabled=1")
        .execute(store.pool())
        .await
        .expect("enable audit fault again");
    assert!(matches!(
        store.refresh_device(source(), ORIGIN, &first.refresh_token, proof.as_str(), &ring).await,
        Err(DeviceAuthenticationError::Audit)
    ));
    let spent: Option<i64> = sqlx::query_scalar("SELECT spent_at_ms FROM device_refresh_tokens")
        .fetch_one(store.pool())
        .await
        .expect("refresh state");
    assert_eq!(spent, None);
    let replay_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_dpop_replays")
        .fetch_one(store.pool())
        .await
        .expect("replay state");
    assert_eq!(replay_count, 0);
    sqlx::query("UPDATE device_auth_audit_fault SET enabled=0")
        .execute(store.pool())
        .await
        .expect("restore audit");
    store
        .refresh_device(source(), ORIGIN, &first.refresh_token, proof.as_str(), &ring)
        .await
        .expect("refresh after known rollback");
    store.pool().close().await;
    drop(store);
    support::remove_test_directory(directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_private_quota_preserves_credentials_and_invalid_scope_denies() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let ring = store.ensure_device_token_keyring(&TestKms([14; 32])).await.expect("keyring");
    let (account_id, device_id) = seed_sqlite_identity(&store).await;
    let now = now_millis();
    let window = now.div_euclid(60_000) * 60_000;
    sqlx::query("INSERT INTO device_auth_admission (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak, retain_until_ms) VALUES (2, 3, ?, ?, 30, 0, ?)")
        .bind(account_id.as_bytes().as_slice()).bind(window).bind(window + 60_000)
        .execute(store.pool()).await.expect("device account quota");
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let signature = device_signature(device_id, challenge.nonce());
    assert!(matches!(
        store
            .authenticate_device(
                source(),
                ORIGIN,
                *device_id.as_bytes(),
                challenge.nonce(),
                &signature,
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::RateLimited(_))
    ));
    let consumed: Option<i64> =
        sqlx::query_scalar("SELECT consumed_at_ms FROM device_auth_challenges")
            .fetch_one(store.pool())
            .await
            .expect("nonce state");
    assert_eq!(consumed, None);
    let families: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_refresh_families")
        .fetch_one(store.pool())
        .await
        .expect("family count");
    assert_eq!(families, 0);
    sqlx::query(
        "UPDATE device_auth_admission SET attempts=0 WHERE endpoint=2 AND kind=3 AND bucket_key=?",
    )
    .bind(account_id.as_bytes().as_slice())
    .execute(store.pool())
    .await
    .expect("restore account quota");
    let first = store
        .authenticate_device(
            source(),
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &signature,
            &ring,
        )
        .await
        .expect("device exchange");
    sqlx::query("INSERT INTO device_auth_admission (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak, retain_until_ms) VALUES (3, 3, ?, ?, 30, 0, ?)")
        .bind(account_id.as_bytes().as_slice()).bind(window).bind(window + 60_000)
        .execute(store.pool()).await.expect("refresh account quota");
    store.admit_device_auth_source(DeviceAuthEndpoint::Refresh, source()).await.expect("source");
    assert!(matches!(
        store
            .refresh_device(
                source(),
                ORIGIN,
                &first.refresh_token,
                refresh_proof(&device_key()).as_str(),
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::RateLimited(_))
    ));
    let spent: Option<i64> = sqlx::query_scalar("SELECT spent_at_ms FROM device_refresh_tokens")
        .fetch_one(store.pool())
        .await
        .expect("token state");
    assert_eq!(spent, None);
    let replays: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_dpop_replays")
        .fetch_one(store.pool())
        .await
        .expect("replay count");
    assert_eq!(replays, 0);
    sqlx::query(
        "UPDATE device_auth_admission SET attempts=0 WHERE endpoint=3 AND kind=3 AND bucket_key=?",
    )
    .bind(account_id.as_bytes().as_slice())
    .execute(store.pool())
    .await
    .expect("restore refresh quota");
    sqlx::query("UPDATE device_refresh_families SET scope='account:read rogue sync:read'")
        .execute(store.pool())
        .await
        .expect("corrupt family scope");
    assert!(matches!(
        store
            .refresh_device(
                source(),
                ORIGIN,
                &first.refresh_token,
                refresh_proof(&device_key()).as_str(),
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    let spent: Option<i64> = sqlx::query_scalar("SELECT spent_at_ms FROM device_refresh_tokens")
        .fetch_one(store.pool())
        .await
        .expect("token state");
    assert_eq!(spent, None);
    let failure_streaks: Vec<i64> = sqlx::query_scalar(
        "SELECT failure_streak FROM device_auth_admission WHERE endpoint=3 ORDER BY kind",
    )
    .fetch_all(store.pool())
    .await
    .expect("cooldown state");
    assert_eq!(failure_streaks, vec![1, 1, 1]);
    store.pool().close().await;
    drop(store);
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_refresh_rotation_preserves_absolute_family_expiry() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let ring = store.ensure_device_token_keyring(&TestKms([15; 32])).await.expect("keyring");
    let (_account_id, device_id) = seed_sqlite_identity(&store).await;
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let first = store
        .authenticate_device(
            source(),
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &device_signature(device_id, challenge.nonce()),
            &ring,
        )
        .await
        .expect("device exchange");
    let deadline = now_millis() + 5_000;
    sqlx::query("UPDATE device_refresh_families SET created_at_ms=?, expires_at_ms=?")
        .bind(deadline - 2_592_000_000_i64)
        .bind(deadline)
        .execute(store.pool())
        .await
        .expect("near expiry");
    store.admit_device_auth_source(DeviceAuthEndpoint::Refresh, source()).await.expect("source");
    let second = store
        .refresh_device(
            source(),
            ORIGIN,
            &first.refresh_token,
            refresh_proof(&device_key()).as_str(),
            &ring,
        )
        .await
        .expect("rotation");
    assert!((1..=5).contains(&second.refresh_expires_in));
    let persisted_deadline: i64 =
        sqlx::query_scalar("SELECT expires_at_ms FROM device_refresh_families")
            .fetch_one(store.pool())
            .await
            .expect("family deadline");
    assert_eq!(persisted_deadline, deadline);
    let expired = now_millis() - 1;
    sqlx::query("UPDATE device_refresh_families SET created_at_ms=?, expires_at_ms=?")
        .bind(expired - 2_592_000_000_i64)
        .bind(expired)
        .execute(store.pool())
        .await
        .expect("expire family");
    assert!(matches!(
        store
            .refresh_device(
                source(),
                ORIGIN,
                &second.refresh_token,
                refresh_proof(&device_key()).as_str(),
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    let failure_streaks: Vec<i64> = sqlx::query_scalar(
        "SELECT failure_streak FROM device_auth_admission WHERE endpoint=3 ORDER BY kind",
    )
    .fetch_all(store.pool())
    .await
    .expect("cooldown state");
    assert_eq!(failure_streaks, vec![1, 1, 1]);
    store.pool().close().await;
    drop(store);
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_concurrent_device_attempts_have_one_nonce_winner() {
    let directory = directory();
    let path = directory.join("scoplen.sqlite");
    let first = SqliteStore::open(&path).await.expect("first instance");
    let second = SqliteStore::open(&path).await.expect("second instance");
    let ring =
        Arc::new(first.ensure_device_token_keyring(&TestKms([12; 32])).await.expect("keyring"));
    let (_account_id, device_id) = seed_sqlite_identity(&first).await;
    let challenge = first.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let nonce = *challenge.nonce();
    let signature = device_signature(device_id, &nonce);
    for _ in 0..2 {
        first.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
        first
            .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
            .await
            .expect("device");
    }
    let mut tasks = Vec::new();
    for store in [first.clone(), second.clone()] {
        let ring = Arc::clone(&ring);
        tasks.push(tokio::spawn(async move {
            store
                .authenticate_device(
                    source(),
                    ORIGIN,
                    *device_id.as_bytes(),
                    &nonce,
                    &signature,
                    &ring,
                )
                .await
        }));
    }
    let mut success = 0;
    let mut denied = 0;
    for task in tasks {
        match task.await.expect("join") {
            Ok(_) => success += 1,
            Err(DeviceAuthenticationError::Denied { changed: false }) => denied += 1,
            Err(error) => panic!("unexpected outcome: {error}"),
        }
    }
    assert_eq!((success, denied), (1, 1));
    let families: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_refresh_families")
        .fetch_one(first.pool())
        .await
        .expect("family count");
    assert_eq!(families, 1);
    first.pool().close().await;
    second.pool().close().await;
    drop((first, second));
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_device_exchange_refresh_and_reuse_are_serialized() {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let store = PostgresStore::connect(&url).await.expect("store");
    let ring = store.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("keyring");
    let (_account_id, device_id) = seed_postgres_identity(&store).await;
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let first = store
        .authenticate_device(
            source(),
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &device_signature(device_id, challenge.nonce()),
            &ring,
        )
        .await
        .expect("device exchange");
    let second = store
        .refresh_device(
            source(),
            ORIGIN,
            &first.refresh_token,
            refresh_proof(&device_key()).as_str(),
            &ring,
        )
        .await
        .expect("rotation");
    assert_ne!(first.refresh_token, second.refresh_token);
    assert!(matches!(
        store
            .refresh_device(
                source(),
                ORIGIN,
                &first.refresh_token,
                refresh_proof(&device_key()).as_str(),
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Denied { changed: true })
    ));
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_audit_failure_rolls_back_nonce_and_rotation() {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let store = PostgresStore::connect(&url).await.expect("store");
    let ring = store.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("keyring");
    let (account_id, device_id) = seed_postgres_identity(&store).await;
    let trigger = format!("fail_device_audit_{}", Uuid::now_v7().simple());
    let create_function = format!(
        "CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF position(decode('{}', 'hex') IN NEW.event_bytes) > 0 THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$",
        hex(account_id.as_bytes())
    );
    let create_trigger = format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION {trigger}()"
    );
    let drop_trigger = format!("DROP TRIGGER {trigger} ON deployment_audit_events");
    let drop_function = format!("DROP FUNCTION {trigger}()");
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let signature = device_signature(device_id, challenge.nonce());
    sqlx::query(&create_function).execute(store.pool()).await.expect("failure function");
    sqlx::query(&create_trigger).execute(store.pool()).await.expect("failure trigger");
    assert!(matches!(
        store
            .authenticate_device(
                source(),
                ORIGIN,
                *device_id.as_bytes(),
                challenge.nonce(),
                &signature,
                &ring
            )
            .await,
        Err(DeviceAuthenticationError::Audit)
    ));
    let consumed: Option<i64> =
        sqlx::query_scalar("SELECT consumed_at_ms FROM device_auth_challenges WHERE device_id=$1")
            .bind(device_id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("nonce state");
    assert_eq!(consumed, None);
    let families: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_refresh_families WHERE device_id=$1")
            .bind(device_id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("family count");
    assert_eq!(families, 0);
    sqlx::query(&drop_trigger).execute(store.pool()).await.expect("restore audit");
    let first = store
        .authenticate_device(
            source(),
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &signature,
            &ring,
        )
        .await
        .expect("exchange after rollback");
    let proof = refresh_proof(&device_key());
    let target = DpopTarget::new("POST", ORIGIN, "/api/v1/auth/refresh").expect("target");
    let jkt = dpop_jwk_thumbprint(&device_key().public_key_sec1()).expect("thumbprint");
    let verified = proof
        .verify(&target, DpopToken::Refresh, &jkt, now_seconds(), None)
        .expect("verified proof");
    let jti_digest = Sha256::digest(verified.jti.as_bytes());
    sqlx::query(&create_trigger).execute(store.pool()).await.expect("failure trigger");
    assert!(matches!(
        store.refresh_device(source(), ORIGIN, &first.refresh_token, proof.as_str(), &ring).await,
        Err(DeviceAuthenticationError::Audit)
    ));
    let spent: Option<i64> = sqlx::query_scalar("SELECT spent_at_ms FROM device_refresh_tokens WHERE family_id IN (SELECT family_id FROM device_refresh_families WHERE device_id=$1)")
        .bind(device_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("token state");
    assert_eq!(spent, None);
    let replay_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_dpop_replays WHERE dpop_jkt=$1 AND jti_digest=$2",
    )
    .bind(&jkt)
    .bind(jti_digest.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("replay state");
    assert_eq!(replay_count, 0);
    sqlx::query(&drop_trigger).execute(store.pool()).await.expect("restore audit");
    sqlx::query(&drop_function).execute(store.pool()).await.expect("remove failure function");
    store
        .refresh_device(source(), ORIGIN, &first.refresh_token, proof.as_str(), &ring)
        .await
        .expect("refresh after rollback");
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_device_exchange_waits_for_account_key_replacement() {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let store = PostgresStore::connect(&url).await.expect("store");
    let ring =
        Arc::new(store.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("keyring"));
    let (account_id, device_id) = seed_postgres_identity(&store).await;
    let peer: IpAddr = "192.0.2.51".parse().expect("peer");
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, peer).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let nonce = *challenge.nonce();
    let signature = device_signature(device_id, &nonce);
    let mut replacement = store.pool().begin().await.expect("replacement transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(account_id.as_bytes().as_slice())
        .execute(&mut *replacement)
        .await
        .expect("account key lock");
    let contender = store.clone();
    let task = tokio::spawn(async move {
        contender
            .authenticate_device(peer, ORIGIN, *device_id.as_bytes(), &nonce, &signature, &ring)
            .await
    });
    wait_for_shared_account_key_lock(&store).await;
    assert!(!task.is_finished(), "authentication cannot issue a token before revocation commits");
    let revocation = RevocationStatement::issue(&account_key(), device_id, 2, "lost".into())
        .expect("revocation")
        .encode()
        .expect("canonical revocation");
    sqlx::query(
        "INSERT INTO sync_account_key_revocations (account_id, revocation) VALUES ($1, $2)",
    )
    .bind(account_id.as_bytes().as_slice())
    .bind(revocation)
    .execute(&mut *replacement)
    .await
    .expect("replace statements");
    replacement.commit().await.expect("commit revocation");
    assert!(matches!(
        task.await.expect("authentication task"),
        Err(DeviceAuthenticationError::Denied { changed: true })
    ));
    let families: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_refresh_families WHERE device_id=$1")
            .bind(device_id.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .expect("family count");
    assert_eq!(families, 0);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_refresh_waits_for_account_key_replacement() {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let store = PostgresStore::connect(&url).await.expect("store");
    let ring =
        Arc::new(store.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("keyring"));
    let (account_id, device_id) = seed_postgres_identity(&store).await;
    let peer: IpAddr = "192.0.2.52".parse().expect("peer");
    store.admit_device_auth_source(DeviceAuthEndpoint::Device, peer).await.expect("source");
    store
        .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
        .await
        .expect("device");
    let challenge = store.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let first = store
        .authenticate_device(
            peer,
            ORIGIN,
            *device_id.as_bytes(),
            challenge.nonce(),
            &device_signature(device_id, challenge.nonce()),
            &ring,
        )
        .await
        .expect("device exchange");
    store.admit_device_auth_source(DeviceAuthEndpoint::Refresh, peer).await.expect("source");
    let mut replacement = store.pool().begin().await.expect("replacement transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(account_id.as_bytes().as_slice())
        .execute(&mut *replacement)
        .await
        .expect("account key lock");
    let contender = store.clone();
    let proof = refresh_proof(&device_key());
    let task = tokio::spawn(async move {
        contender.refresh_device(peer, ORIGIN, &first.refresh_token, proof.as_str(), &ring).await
    });
    wait_for_shared_account_key_lock(&store).await;
    assert!(!task.is_finished(), "refresh cannot rotate before revocation commits");
    let revocation = RevocationStatement::issue(&account_key(), device_id, 2, "lost".into())
        .expect("revocation")
        .encode()
        .expect("canonical revocation");
    sqlx::query(
        "INSERT INTO sync_account_key_revocations (account_id, revocation) VALUES ($1, $2)",
    )
    .bind(account_id.as_bytes().as_slice())
    .bind(revocation)
    .execute(&mut *replacement)
    .await
    .expect("replace statements");
    replacement.commit().await.expect("commit revocation");
    assert!(matches!(
        task.await.expect("refresh task"),
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    let spent: Option<i64> = sqlx::query_scalar("SELECT spent_at_ms FROM device_refresh_tokens WHERE family_id IN (SELECT family_id FROM device_refresh_families WHERE device_id=$1)")
        .bind(device_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("token state");
    assert_eq!(spent, None);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_concurrent_device_attempts_and_refreshes_serialize() {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let first = PostgresStore::connect(&url).await.expect("first instance");
    let second = PostgresStore::connect(&url).await.expect("second instance");
    let ring =
        Arc::new(first.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("keyring"));
    let (_account_id, device_id) = seed_postgres_identity(&first).await;
    let challenge = first.issue_device_challenge(*device_id.as_bytes()).await.expect("challenge");
    let nonce = *challenge.nonce();
    let signature = device_signature(device_id, &nonce);
    for _ in 0..2 {
        first.admit_device_auth_source(DeviceAuthEndpoint::Device, source()).await.expect("source");
        first
            .admit_device_auth_device(DeviceAuthEndpoint::Device, *device_id.as_bytes())
            .await
            .expect("device");
    }
    let mut tasks = Vec::new();
    for store in [first.clone(), second.clone()] {
        let ring = Arc::clone(&ring);
        tasks.push(tokio::spawn(async move {
            store
                .authenticate_device(
                    source(),
                    ORIGIN,
                    *device_id.as_bytes(),
                    &nonce,
                    &signature,
                    &ring,
                )
                .await
        }));
    }
    let mut first_response = None;
    let mut denied = 0;
    for task in tasks {
        match task.await.expect("join") {
            Ok(response) => first_response = Some(response),
            Err(DeviceAuthenticationError::Denied { changed: false }) => denied += 1,
            Err(error) => panic!("unexpected device outcome: {error}"),
        }
    }
    assert_eq!(denied, 1);
    let first_response = first_response.expect("one winner");
    for _ in 0..2 {
        first
            .admit_device_auth_source(DeviceAuthEndpoint::Refresh, source())
            .await
            .expect("source");
    }
    let mut refresh_tasks = Vec::new();
    for store in [first.clone(), second.clone()] {
        let ring = Arc::clone(&ring);
        let credential = first_response.refresh_token.clone();
        let proof = refresh_proof(&device_key());
        refresh_tasks.push(tokio::spawn(async move {
            store.refresh_device(source(), ORIGIN, &credential, proof.as_str(), &ring).await
        }));
    }
    let mut rotated = 0;
    let mut revoked = 0;
    for task in refresh_tasks {
        match task.await.expect("join") {
            Ok(_) => rotated += 1,
            Err(DeviceAuthenticationError::Denied { changed: true }) => revoked += 1,
            Err(error) => panic!("unexpected refresh outcome: {error}"),
        }
    }
    assert_eq!((rotated, revoked), (1, 1));
    let revoked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_refresh_families WHERE device_id=$1 AND revoked_at_ms IS NOT NULL",
    )
    .bind(device_id.as_bytes().as_slice())
    .fetch_one(first.pool())
    .await
    .expect("revoked family");
    assert_eq!(revoked, 1);
    first.pool().close().await;
    second.pool().close().await;
}
