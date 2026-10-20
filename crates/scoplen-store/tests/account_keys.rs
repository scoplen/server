// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use support::remove_test_directory;

use std::path::PathBuf;
#[cfg(feature = "postgres-integration")]
use std::time::Duration;

use scoplen_store::{
    RelationalStore, SqliteStore,
    account_keys::{
        AccountKeyBundlePreflight, AccountKeyBundlePut, AccountKeyBundleUpdate,
        AccountKeyStoreError, DeviceWrap, MAX_DEVICE_WRAPS, MAX_KEY_ARTIFACT_BYTES,
    },
};

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-account-keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create isolated test directory");
    path
}

fn update(revision: u64, marker: u8) -> AccountKeyBundleUpdate {
    AccountKeyBundleUpdate {
        revision,
        device_wraps: vec![
            DeviceWrap { device_id: [1; 16], wrapped_ark: vec![marker, 1] },
            DeviceWrap { device_id: [2; 16], wrapped_ark: vec![marker, 2] },
        ],
        account_signing_key: vec![marker, 3],
        account_kem_key: vec![marker, 4],
        recovery_blob: vec![marker, 5],
        signature: [marker; 64],
    }
}

fn full_size_certificates(count: u8) -> Vec<Vec<u8>> {
    (0..count).map(|marker| vec![marker; MAX_KEY_ARTIFACT_BYTES]).collect()
}

#[tokio::test]
async fn bundle_is_scoped_to_device_and_statements_are_sorted() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [7; 16];
    let result = store.put_account_key_bundle(account, &update(1, 10)).await.expect("initial put");
    assert_eq!(result, AccountKeyBundlePut::Applied { revision: 1 });

    store
        .replace_account_key_statements(
            account,
            &[vec![3], vec![1], vec![2], vec![2]],
            &[vec![8, 1], vec![8, 0]],
        )
        .await
        .expect("replace statements");

    let first = store.get_account_key_bundle(account, [1; 16]).await.expect("first device");
    assert_eq!(first.wrapped_ark, vec![10, 1]);
    assert_eq!(first.certificates, vec![vec![1], vec![2], vec![3]]);
    assert_eq!(first.revocations, vec![vec![8, 0], vec![8, 1]]);
    let second = store.get_account_key_bundle(account, [2; 16]).await.expect("second device");
    assert_eq!(second.wrapped_ark, vec![10, 2]);
    assert!(matches!(
        store.get_account_key_bundle(account, [3; 16]).await,
        Err(AccountKeyStoreError::BundleNotFound)
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn revision_replay_is_exact_and_conflicts_leave_state_unchanged() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [8; 16];
    let first = update(1, 20);
    assert_eq!(
        store.put_account_key_bundle(account, &first).await.expect("initial put"),
        AccountKeyBundlePut::Applied { revision: 1 }
    );
    assert_eq!(
        store.put_account_key_bundle(account, &first).await.expect("exact replay"),
        AccountKeyBundlePut::Replay { revision: 1 }
    );

    let mut changed = first.clone();
    changed.account_kem_key = vec![99];
    assert!(matches!(
        store.put_account_key_bundle(account, &changed).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 1 })
    ));
    let skipped = update(3, 30);
    assert!(matches!(
        store.put_account_key_bundle(account, &skipped).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 1 })
    ));
    let current = store.get_account_key_bundle(account, [1; 16]).await.expect("current bundle");
    assert_eq!(current.revision, 1);
    assert_eq!(current.account_kem_key, vec![20, 4]);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn preflight_classifies_exact_replay_and_final_put_rechecks_a_new_revision() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [13; 16];
    let first = update(1, 20);
    assert_eq!(
        store
            .preflight_account_key_bundle_update(account, &first)
            .await
            .expect("initial preflight"),
        AccountKeyBundlePreflight::New
    );
    assert!(matches!(
        store.preflight_account_key_bundle_update(account, &update(2, 21)).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 0 })
    ));
    assert!(matches!(
        store.preflight_account_key_bundle_update(account, &update(0, 21)).await,
        Err(AccountKeyStoreError::InvalidRevision)
    ));
    store.put_account_key_bundle(account, &first).await.expect("initial put");
    assert_eq!(
        store.preflight_account_key_bundle_update(account, &first).await.expect("exact preflight"),
        AccountKeyBundlePreflight::Replay
    );
    for changed in [
        {
            let mut value = first.clone();
            value.account_signing_key.push(1);
            value
        },
        {
            let mut value = first.clone();
            value.account_kem_key.push(1);
            value
        },
        {
            let mut value = first.clone();
            value.recovery_blob.push(1);
            value
        },
        {
            let mut value = first.clone();
            value.signature[0] ^= 1;
            value
        },
        {
            let mut value = first.clone();
            value.device_wraps[1].wrapped_ark.push(1);
            value
        },
    ] {
        assert!(matches!(
            store.preflight_account_key_bundle_update(account, &changed).await,
            Err(AccountKeyStoreError::Conflict { current_revision: 1 })
        ));
    }
    assert_eq!(
        store
            .preflight_account_key_bundle_update(account, &update(2, 22))
            .await
            .expect("next revision"),
        AccountKeyBundlePreflight::New
    );
    assert!(matches!(
        store.preflight_account_key_bundle_update(account, &update(3, 23)).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 1 })
    ));

    let second = update(2, 22);
    store.put_account_key_bundle(account, &second).await.expect("concurrent rotation");
    assert!(matches!(
        store.put_account_key_bundle(account, &first).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 2 })
    ));
    let current = store.get_account_key_bundle(account, [1; 16]).await.expect("new bundle");
    assert_eq!(current.revision, 2);
    assert_eq!(current.account_signing_key, second.account_signing_key);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn input_limits_and_ordering_are_rejected_before_storage() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [9; 16];

    let mut zero = update(0, 1);
    assert!(matches!(
        store.put_account_key_bundle(account, &zero).await,
        Err(AccountKeyStoreError::InvalidRevision)
    ));
    zero.revision = 1;
    zero.account_signing_key.clear();
    assert!(matches!(
        store.put_account_key_bundle(account, &zero).await,
        Err(AccountKeyStoreError::EmptyArtifact("account_signing_key"))
    ));

    let mut oversized = update(1, 2);
    oversized.recovery_blob = vec![0; MAX_KEY_ARTIFACT_BYTES + 1];
    assert!(matches!(
        store.put_account_key_bundle(account, &oversized).await,
        Err(AccountKeyStoreError::ArtifactTooLarge("recovery_blob"))
    ));

    let mut unsorted = update(1, 3);
    unsorted.device_wraps.swap(0, 1);
    assert!(matches!(
        store.put_account_key_bundle(account, &unsorted).await,
        Err(AccountKeyStoreError::InvalidDeviceWraps)
    ));
    let mut duplicate = update(1, 4);
    duplicate.device_wraps[1].device_id = duplicate.device_wraps[0].device_id;
    assert!(matches!(
        store.put_account_key_bundle(account, &duplicate).await,
        Err(AccountKeyStoreError::InvalidDeviceWraps)
    ));
    let mut too_many = update(1, 5);
    too_many.device_wraps = (0..=MAX_DEVICE_WRAPS)
        .map(|index| DeviceWrap {
            device_id: u128::from(index as u64).to_be_bytes(),
            wrapped_ark: vec![u8::try_from(index % 256).expect("bounded marker")],
        })
        .collect();
    assert!(matches!(
        store.put_account_key_bundle(account, &too_many).await,
        Err(AccountKeyStoreError::DeviceWrapLimit)
    ));

    assert!(matches!(
        store.get_account_key_bundle(account, [1; 16]).await,
        Err(AccountKeyStoreError::BundleNotFound)
    ));
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn competing_initial_revisions_are_serialized() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [10; 16];
    let left = update(1, 40);
    let right = update(1, 41);
    let (left_result, right_result) = tokio::join!(
        store.put_account_key_bundle(account, &left),
        store.put_account_key_bundle(account, &right),
    );
    let mut applied = 0;
    let mut conflicts = 0;
    for result in [left_result, right_result] {
        match result {
            Ok(AccountKeyBundlePut::Applied { revision: 1 }) => applied += 1,
            Ok(AccountKeyBundlePut::Replay { .. }) => {
                panic!("different initial updates cannot replay")
            }
            Ok(AccountKeyBundlePut::Applied { .. }) => panic!("unexpected revision"),
            Err(AccountKeyStoreError::Conflict { current_revision: 1 }) => conflicts += 1,
            Err(error) => panic!("unexpected competing write error: {error}"),
        }
    }
    assert_eq!(applied, 1);
    assert_eq!(conflicts, 1);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn preexisting_statements_cannot_admit_an_oversized_first_bundle() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [11; 16];
    store
        .replace_account_key_statements(account, &full_size_certificates(64), &[])
        .await
        .expect("statements can precede a bundle");

    assert!(matches!(
        store.put_account_key_bundle(account, &update(1, 50)).await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    assert!(matches!(
        store.get_account_key_bundle(account, [1; 16]).await,
        Err(AccountKeyStoreError::BundleNotFound)
    ));

    store.replace_account_key_statements(account, &[], &[]).await.expect("free capacity");
    assert_eq!(
        store.put_account_key_bundle(account, &update(1, 50)).await.expect("admit bundle"),
        AccountKeyBundlePut::Applied { revision: 1 }
    );

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn projected_response_checks_every_wrap_and_rolls_back_both_mutations() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [12; 16];
    let first = update(1, 60);
    store.put_account_key_bundle(account, &first).await.expect("initial bundle");
    let certificates = full_size_certificates(63);
    store
        .replace_account_key_statements(account, &certificates, &[])
        .await
        .expect("large admissible statement set");

    let mut oversized = update(2, 61);
    oversized.device_wraps[1].wrapped_ark = vec![61; MAX_KEY_ARTIFACT_BYTES];
    assert!(matches!(
        store.put_account_key_bundle(account, &oversized).await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    let current = store.get_account_key_bundle(account, [2; 16]).await.expect("old second wrap");
    assert_eq!(current.revision, 1);
    assert_eq!(current.wrapped_ark, vec![60, 2]);
    assert_eq!(current.certificates.len(), 63);
    assert_eq!(
        store.put_account_key_bundle(account, &first).await.expect("exact replay"),
        AccountKeyBundlePut::Replay { revision: 1 }
    );

    assert!(matches!(
        store.replace_account_key_statements(account, &full_size_certificates(64), &[]).await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    assert!(matches!(
        store
            .replace_account_key_statements(
                account,
                &certificates,
                &[vec![99; MAX_KEY_ARTIFACT_BYTES]],
            )
            .await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    let current = store.get_account_key_bundle(account, [1; 16]).await.expect("old statements");
    assert_eq!(current.certificates.len(), 63);
    assert_eq!(current.revocations, Vec::<Vec<u8>>::new());

    store.replace_account_key_statements(account, &[], &[]).await.expect("free capacity");
    assert_eq!(
        store.put_account_key_bundle(account, &oversized).await.expect("retry rotation"),
        AccountKeyBundlePut::Applied { revision: 2 }
    );

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_key_preflight_rechecks_final_put() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store =
        scoplen_store::PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let account = uuid::Uuid::new_v4().into_bytes();
    let first = update(1, 90);
    assert_eq!(
        store
            .preflight_account_key_bundle_update(account, &first)
            .await
            .expect("initial preflight"),
        AccountKeyBundlePreflight::New
    );
    store.put_account_key_bundle(account, &first).await.expect("initial put");
    assert_eq!(
        store.preflight_account_key_bundle_update(account, &first).await.expect("replay preflight"),
        AccountKeyBundlePreflight::Replay
    );
    let mut changed = first.clone();
    changed.device_wraps[0].wrapped_ark.push(1);
    assert!(matches!(
        store.preflight_account_key_bundle_update(account, &changed).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 1 })
    ));
    assert_eq!(
        store
            .preflight_account_key_bundle_update(account, &update(2, 91))
            .await
            .expect("next revision"),
        AccountKeyBundlePreflight::New
    );
    store.put_account_key_bundle(account, &update(2, 91)).await.expect("concurrent rotation");
    assert!(matches!(
        store.put_account_key_bundle(account, &first).await,
        Err(AccountKeyStoreError::Conflict { current_revision: 2 })
    ));
    assert_eq!(
        store.get_account_key_bundle(account, [1; 16]).await.expect("new bundle").revision,
        2
    );

    sqlx::query("DELETE FROM sync_account_key_bundles WHERE account_id = $1")
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("remove test bundle");
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_key_response_admission_is_atomic() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store =
        scoplen_store::PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let account = uuid::Uuid::new_v4().into_bytes();
    let first = update(1, 70);
    store.put_account_key_bundle(account, &first).await.expect("initial bundle");
    let certificates = full_size_certificates(63);
    store
        .replace_account_key_statements(account, &certificates, &[])
        .await
        .expect("admissible statements");

    let mut oversized = update(2, 71);
    oversized.device_wraps[1].wrapped_ark = vec![71; MAX_KEY_ARTIFACT_BYTES];
    assert!(matches!(
        store.put_account_key_bundle(account, &oversized).await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    assert!(matches!(
        store.replace_account_key_statements(account, &full_size_certificates(64), &[]).await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    assert!(matches!(
        store
            .replace_account_key_statements(
                account,
                &certificates,
                &[vec![99; MAX_KEY_ARTIFACT_BYTES]],
            )
            .await,
        Err(AccountKeyStoreError::KeyResponseLimit)
    ));
    let current = store.get_account_key_bundle(account, [2; 16]).await.expect("unchanged bundle");
    assert_eq!(current.revision, 1);
    assert_eq!(current.wrapped_ark, vec![70, 2]);
    assert_eq!(current.certificates.len(), 63);
    assert_eq!(current.revocations, Vec::<Vec<u8>>::new());
    assert_eq!(
        store.put_account_key_bundle(account, &first).await.expect("exact replay"),
        AccountKeyBundlePut::Replay { revision: 1 }
    );

    sqlx::query("DELETE FROM sync_account_key_certificates WHERE account_id = $1")
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("remove test certificates");
    sqlx::query("DELETE FROM sync_account_key_bundles WHERE account_id = $1")
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("remove test bundle");
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
async fn wait_for_certificate_read(store: &scoplen_store::PostgresStore, application_name: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                   SELECT 1 FROM pg_stat_activity
                   WHERE datname = current_database()
                     AND pid <> pg_backend_pid()
                     AND application_name = $1
                     AND wait_event_type = 'Lock'
                     AND query LIKE 'SELECT certificate FROM sync_account_key_certificates%'
                 )",
            )
            .bind(application_name)
            .fetch_one(store.pool())
            .await
            .expect("observe blocked read");
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("GET must reach the certificate read");
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_key_read_uses_one_snapshot_during_rotation() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let test_id = uuid::Uuid::new_v4();
    let application_name = format!("scoplen_snapshot_{test_id}");
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{database_url}{separator}application_name={application_name}");
    let store =
        scoplen_store::PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let account = test_id.into_bytes();
    let mut original = update(1, 80);
    original.device_wraps[0].wrapped_ark = vec![80; MAX_KEY_ARTIFACT_BYTES];
    store.put_account_key_bundle(account, &original).await.expect("initial bundle");
    let certificates = full_size_certificates(62);
    store
        .replace_account_key_statements(account, &certificates, &[])
        .await
        .expect("initial statements fit the response bound");

    let mut table_lock = store.pool().begin().await.expect("open blocking transaction");
    sqlx::query("LOCK TABLE sync_account_key_certificates IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *table_lock)
        .await
        .expect("block certificate reads");
    let reader = store.clone();
    let read = tokio::spawn(async move { reader.get_account_key_bundle(account, [1; 16]).await });
    wait_for_certificate_read(&store, &application_name).await;

    // This second valid state changes no certificate row, so it can commit while the GET waits.
    let mut writer = store.pool().begin().await.expect("open rotation transaction");
    sqlx::query(
        "UPDATE sync_account_key_bundles
         SET revision = 2, signature = $2, updated_at_ms = updated_at_ms + 1
         WHERE account_id = $1",
    )
    .bind(account.as_slice())
    .bind(vec![81u8; 64])
    .execute(&mut *writer)
    .await
    .expect("rotate bundle");
    sqlx::query(
        "UPDATE sync_account_key_device_wraps SET wrapped_ark = $3
         WHERE account_id = $1 AND device_id = $2",
    )
    .bind(account.as_slice())
    .bind([1u8; 16].as_slice())
    .bind(vec![81u8, 1])
    .execute(&mut *writer)
    .await
    .expect("replace large wrap");
    sqlx::query(
        "INSERT INTO sync_account_key_revocations (account_id, revocation) VALUES ($1, $2)",
    )
    .bind(account.as_slice())
    .bind(vec![81u8; MAX_KEY_ARTIFACT_BYTES])
    .execute(&mut *writer)
    .await
    .expect("add revocation");
    writer.commit().await.expect("commit rotation");
    table_lock.commit().await.expect("release certificate read");

    let first = tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("GET must finish")
        .expect("reader task")
        .expect("consistent initial bundle");
    assert_eq!(first.revision, 1);
    assert_eq!(first.wrapped_ark.len(), MAX_KEY_ARTIFACT_BYTES);
    assert!(first.wrapped_ark.iter().all(|byte| *byte == 80));
    assert_eq!(first.certificates, certificates);
    assert_eq!(first.revocations.len(), 0);

    let second = store.get_account_key_bundle(account, [1; 16]).await.expect("rotated bundle");
    assert_eq!(second.revision, 2);
    assert_eq!(second.wrapped_ark, vec![81, 1]);
    assert_eq!(second.certificates, certificates);
    assert_eq!(second.revocations.len(), 1);
    assert!(second.revocations[0].iter().all(|byte| *byte == 81));
    store
        .replace_account_key_statements(account, &certificates, &second.revocations)
        .await
        .expect("rotated state also fits the response bound");

    sqlx::query("DELETE FROM sync_account_key_revocations WHERE account_id = $1")
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("remove test revocations");
    sqlx::query("DELETE FROM sync_account_key_certificates WHERE account_id = $1")
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("remove test certificates");
    sqlx::query("DELETE FROM sync_account_key_bundles WHERE account_id = $1")
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("remove test bundle");
    store.pool().close().await;
}
