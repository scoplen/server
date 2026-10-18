// SPDX-License-Identifier: AGPL-3.0-only

use std::{path::PathBuf, time::Duration};

use scoplen_store::{
    RelationalStore, SqliteStore,
    account_keys::{
        AccountKeyBundlePut, AccountKeyBundleUpdate, AccountKeyStoreError, DeviceWrap,
        MAX_DEVICE_WRAPS, MAX_KEY_ARTIFACT_BYTES,
    },
};

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-account-keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create isolated test directory");
    path
}

async fn remove_test_directory(path: PathBuf) {
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => return,
            Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("remove test directory {}: {error}", path.display()),
        }
    }
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
