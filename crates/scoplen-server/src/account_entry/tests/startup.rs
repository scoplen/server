// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
use scoplen_store::kms::KeyManagementService;

use super::*;

#[tokio::test]
async fn sqlite_api_startup_preserves_probe_and_rejects_capacity_or_kms_drift() {
    let directory = directory();
    let mut config = crate::Config::default();
    config.server.data_dir = directory.join("deployment");
    config.accounts.used_account_id_limit = 32;
    for role in [crate::Role::Worker, crate::Role::Edge] {
        let prepared =
            crate::prepare_roles(&config, &[role]).await.expect("background preparation");
        let store = prepared.store.as_ref().expect("SQLite store");
        let probe: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT encrypted_key FROM account_password_probe_key WHERE singleton=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("probe singleton");
        assert!(probe.is_none(), "background roles do not initialize Account entry");
        store.pool().close().await;
        drop(prepared);
    }
    let prepared =
        crate::prepare_roles(&config, &[crate::Role::Api]).await.expect("API preparation");
    let store = prepared.store.as_ref().expect("SQLite store");
    let probe: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_key FROM account_password_probe_key WHERE singleton=1",
    )
    .fetch_one(store.pool())
    .await
    .expect("initialized probe");
    assert_eq!(probe.len(), 73);
    assert_eq!(store.account_id_retention_summary().await.expect("admitted ceiling").ceiling, 32);
    store.pool().close().await;
    drop(prepared);
    config.accounts.registration_enabled = false;
    let prepared =
        crate::prepare_roles(&config, &[crate::Role::Api]).await.expect("closed restart");
    let store = prepared.store.as_ref().expect("SQLite store");
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_key FROM account_password_probe_key WHERE singleton=1",
    )
    .fetch_one(store.pool())
    .await
    .expect("retained probe");
    assert!(retained == probe, "restart retains the exact protected probe");
    store.pool().close().await;
    drop(prepared);
    config.accounts.used_account_id_limit = 33;
    assert!(matches!(
        crate::prepare_roles(&config, &[crate::Role::Api]).await,
        Err(ServerError::Task(_))
    ));
    config.accounts.used_account_id_limit = 32;
    let wrong_key = config.server.data_dir.join("other.key");
    std::fs::write(&wrong_key, "08".repeat(32)).expect("owned alternative KMS key");
    config.storage.kms.key_file = Some(wrong_key);
    assert!(matches!(
        crate::prepare_roles(&config, &[crate::Role::Api]).await,
        Err(ServerError::Task(_))
    ));
    crate::test_support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_corrupt_retained_probe_stops_api_startup_without_replacement() {
    let directory = directory();
    let mut config = crate::Config::default();
    config.server.data_dir = directory.join("deployment");
    let prepared =
        crate::prepare_roles(&config, &[crate::Role::Api]).await.expect("API preparation");
    let store = prepared.store.as_ref().expect("SQLite store");
    sqlx::query("UPDATE account_password_probe_key SET encrypted_key=$1 WHERE singleton=1")
        .bind([0_u8; 73].as_slice())
        .execute(store.pool())
        .await
        .expect("owned corruption fixture");
    store.pool().close().await;
    drop(prepared);
    assert!(matches!(
        crate::prepare_roles(&config, &[crate::Role::Api]).await,
        Err(ServerError::Task(_))
    ));
    let store = SqliteStore::open(&config.server.data_dir.join("scoplen.sqlite"))
        .await
        .expect("inspect failed startup");
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_key FROM account_password_probe_key WHERE singleton=1",
    )
    .fetch_one(store.pool())
    .await
    .expect("retained failure state");
    assert!(
        retained.iter().all(|byte| *byte == 0),
        "startup must not silently replace damaged state"
    );
    store.pool().close().await;
    crate::test_support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
struct TestKms([u8; 32]);

#[cfg(feature = "postgres-integration")]
impl KeyManagementService for TestKms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &self.0
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_entry_startup_preserves_probe_and_fails_closed_on_configuration_drift() {
    let (store, admin, schema, _) = postgres_fixture().await;
    let backend = AuthBackend::Postgres(Arc::new(store.clone()));
    let settings = AccountSettings { registration_enabled: false, used_account_id_limit: 32 };
    prepare(&backend, &TestKms([7; 32]), settings).await.expect("initialize closed deployment");
    let probe: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_key FROM account_password_probe_key WHERE singleton=1",
    )
    .fetch_one(store.pool())
    .await
    .expect("initialized probe");
    prepare(&backend, &TestKms([7; 32]), settings).await.expect("same settings restart");
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_key FROM account_password_probe_key WHERE singleton=1",
    )
    .fetch_one(store.pool())
    .await
    .expect("retained probe");
    assert_eq!(probe, retained);
    assert!(prepare(&backend, &TestKms([8; 32]), settings).await.is_err());
    assert!(
        prepare(
            &backend,
            &TestKms([7; 32]),
            AccountSettings { used_account_id_limit: 33, ..settings }
        )
        .await
        .is_err()
    );
    store.pool().close().await;
    postgres_cleanup(admin, schema).await;
}
