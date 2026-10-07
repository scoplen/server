// SPDX-License-Identifier: AGPL-3.0-only

use sqlx::Row;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use scoplen_store::{
    RelationalStore, SqliteStore,
    sync::{
        MAX_SHARED_VAULT_KEY_BYTES, ObjectWrite, SharedVaultEpochWrap, SharedVaultKey,
        SyncStoreError, TOMBSTONE_PURGE_AFTER_DAYS, VERSION_RETENTION_DAYS, VaultKind,
    },
};

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-sync-{}", uuid::Uuid::new_v4()));
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

fn write(object_id: u8, base_sequence: Option<u64>, envelope: u8) -> ObjectWrite {
    ObjectWrite {
        object_id: [object_id; 16],
        base_sequence,
        envelope: vec![envelope, envelope + 1],
        tombstone: false,
        signer_device_id: Some([9; 16]),
    }
}

fn tombstone(object_id: u8, base_sequence: u64) -> ObjectWrite {
    ObjectWrite {
        tombstone: true,
        base_sequence: Some(base_sequence),
        ..write(object_id, Some(base_sequence), 99)
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after epoch").as_millis(),
    )
    .expect("current timestamp fits SQLite integer")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn shared_vault_creation_persists_admin_wrap_and_rolls_back_failures() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [11; 16];
    let account = [12; 16];
    store.create_shared_sync_vault(vault, account, &[1, 2, 3]).await.expect("create shared vault");

    let member = sqlx::query(
        "SELECT role, key_epoch, wrapped_vault_key FROM sync_vault_members
         WHERE vault_id = ? AND account_id = ?",
    )
    .bind(vault.as_slice())
    .bind(account.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("initial member");
    assert_eq!(member.get::<String, _>("role"), "admin");
    assert_eq!(member.get::<i64, _>("key_epoch"), 1);
    assert_eq!(member.get::<Vec<u8>, _>("wrapped_vault_key"), vec![1, 2, 3]);
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, account).await.expect("member key lookup"),
        vec![scoplen_store::sync::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![1, 2, 3] }]
    );
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, [13; 16]).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    store
        .publish_shared_sync_vault_epoch(
            vault,
            2,
            &[SharedVaultEpochWrap { account_id: account, wrapped_vault_key: vec![4, 5, 6] }],
        )
        .await
        .expect("publish next epoch");
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, account).await.expect("all epochs"),
        vec![
            scoplen_store::sync::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![1, 2, 3] },
            scoplen_store::sync::SharedVaultKey { epoch: 2, wrapped_vault_key: vec![4, 5, 6] },
        ]
    );
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                2,
                &[SharedVaultEpochWrap { account_id: account, wrapped_vault_key: vec![7] }],
            )
            .await,
        Err(SyncStoreError::EpochConflict { current_epoch: 2 })
    ));
    assert!(matches!(
        store.publish_shared_sync_vault_epoch(vault, 3, &[]).await,
        Err(SyncStoreError::InvalidEpochWraps)
    ));

    store
        .add_shared_sync_vault_member(
            vault,
            [13; 16],
            &[
                SharedVaultKey { epoch: 1, wrapped_vault_key: vec![7, 8] },
                SharedVaultKey { epoch: 2, wrapped_vault_key: vec![9, 10] },
            ],
        )
        .await
        .expect("add shared-vault member");
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, [13; 16]).await.expect("member epoch keys"),
        vec![
            SharedVaultKey { epoch: 1, wrapped_vault_key: vec![7, 8] },
            SharedVaultKey { epoch: 2, wrapped_vault_key: vec![9, 10] },
        ]
    );
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                vault,
                [13; 16],
                &[
                    SharedVaultKey { epoch: 1, wrapped_vault_key: vec![7, 8] },
                    SharedVaultKey { epoch: 2, wrapped_vault_key: vec![9, 10] },
                ],
            )
            .await,
        Err(SyncStoreError::MemberAlreadyExists)
    ));
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                vault,
                [14; 16],
                &[SharedVaultKey { epoch: 1, wrapped_vault_key: vec![11] }],
            )
            .await,
        Err(SyncStoreError::MemberEpochMismatch)
    ));

    sqlx::query(
        "CREATE TRIGGER reject_sync_vault_member_key BEFORE INSERT ON sync_vault_member_keys
         BEGIN SELECT RAISE(ABORT, 'injected member key failure'); END",
    )
    .execute(store.pool())
    .await
    .expect("install member key failure trigger");
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                vault,
                [15; 16],
                &[
                    SharedVaultKey { epoch: 1, wrapped_vault_key: vec![12] },
                    SharedVaultKey { epoch: 2, wrapped_vault_key: vec![13] },
                ],
            )
            .await,
        Err(SyncStoreError::Constraint(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = ? AND account_id = ?",
        )
        .bind(vault.as_slice())
        .bind([15; 16].as_slice())
        .fetch_one(store.pool())
        .await
        .expect("rolled-back member count"),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_member_keys WHERE vault_id = ? AND account_id = ?",
        )
        .bind(vault.as_slice())
        .bind([15; 16].as_slice())
        .fetch_one(store.pool())
        .await
        .expect("rolled-back member key count"),
        0
    );
    sqlx::query("DROP TRIGGER reject_sync_vault_member_key")
        .execute(store.pool())
        .await
        .expect("remove member key failure trigger");

    assert!(matches!(
        store.create_shared_sync_vault(vault, [13; 16], &[9]).await,
        Err(SyncStoreError::VaultAlreadyExists)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("member count"),
        2
    );
    assert!(matches!(
        store.create_shared_sync_vault([14; 16], account, &[]).await,
        Err(SyncStoreError::EmptyVaultKey)
    ));
    assert!(matches!(
        store
            .create_shared_sync_vault([15; 16], account, &vec![0; MAX_SHARED_VAULT_KEY_BYTES + 1])
            .await,
        Err(SyncStoreError::VaultKeyTooLarge)
    ));

    sqlx::query(
        "CREATE TRIGGER reject_sync_vault_member BEFORE INSERT ON sync_vault_members
         BEGIN SELECT RAISE(ABORT, 'injected member failure'); END",
    )
    .execute(store.pool())
    .await
    .expect("install failure trigger");
    let rolled_back_vault = [16; 16];
    assert!(matches!(
        store.create_shared_sync_vault(rolled_back_vault, account, &[4]).await,
        Err(SyncStoreError::Constraint(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_vaults WHERE vault_id = ?")
            .bind(rolled_back_vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("rolled back vault count"),
        0
    );
    sqlx::query("DROP TRIGGER reject_sync_vault_member")
        .execute(store.pool())
        .await
        .expect("remove failure trigger");

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn writes_and_pages_return_only_current_versions() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [1; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    let receipts = store
        .write_sync_batch(vault, &[write(1, None, 10), write(2, None, 20), write(3, None, 30)])
        .await
        .expect("initial batch");
    assert_eq!(receipts.iter().map(|receipt| receipt.sequence).collect::<Vec<_>>(), vec![1, 2, 3]);

    let first_page = store.sync_changes(vault, 0, 2).await.expect("first page");
    assert_eq!(first_page.changes.len(), 2);
    assert!(first_page.more);
    assert_eq!(first_page.next_cursor, 2);
    assert_eq!(first_page.changes[0].object_id, [1; 16]);
    assert_eq!(first_page.changes[1].object_id, [2; 16]);

    let updated = store.write_sync_batch(vault, &[write(1, Some(1), 40)]).await.expect("update");
    assert_eq!(updated[0].sequence, 4);
    let all = store.sync_changes(vault, 0, 10).await.expect("all current versions");
    assert_eq!(all.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(), vec![2, 3, 4]);
    assert!(!all.more);
    assert_eq!(all.next_cursor, 4);
    assert_eq!(all.changes[2].envelope, vec![40, 41]);

    let after_two = store.sync_changes(vault, 2, 10).await.expect("after cursor");
    assert_eq!(
        after_two.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(),
        vec![3, 4]
    );
    let caught_up = store.sync_changes(vault, 4, 10).await.expect("caught up");
    assert_eq!(caught_up.changes.len(), 0);
    assert_eq!(caught_up.next_cursor, 4);

    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_object_versions WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("version rows");
    assert_eq!(version_count, 4);

    let device = [7; 16];
    assert_eq!(store.ack_sync_cursor(vault, device, 4).await.expect("ack current cursor"), 4);
    assert_eq!(store.ack_sync_cursor(vault, device, 3).await.expect("lower ack is no-op"), 4);
    assert!(matches!(
        store.ack_sync_cursor(vault, [8; 16], 5).await,
        Err(SyncStoreError::CursorAhead { cursor: 5, current: 4 })
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn compare_and_swap_conflicts_are_atomic_and_report_current_state() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [2; 16];
    store.create_sync_vault(vault, VaultKind::Shared).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("initial write");

    let error = store
        .write_sync_batch(vault, &[write(1, None, 20), write(2, None, 30)])
        .await
        .expect_err("stale batch must be rejected");
    let SyncStoreError::Conflict { conflicts } = error else {
        panic!("expected CAS conflict");
    };
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].object_id, [1; 16]);
    assert_eq!(conflicts[0].current.as_ref().map(|change| change.sequence), Some(1));

    let next = store
        .write_sync_batch(vault, &[write(2, None, 30)])
        .await
        .expect("rejected batch did not consume a sequence");
    assert_eq!(next[0].sequence, 2);
    let missing = store
        .write_sync_batch(vault, &[write(3, Some(99), 40)])
        .await
        .expect_err("a base for an absent object must conflict");
    assert!(matches!(missing, SyncStoreError::Conflict { .. }));
    let page = store.sync_changes(vault, 0, 10).await.expect("read current state");
    assert_eq!(page.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(), vec![1, 2]);

    let snapshot = store.sync_snapshot(vault, 0, 10).await.expect("snapshot");
    assert_eq!(
        snapshot.objects.iter().map(|change| change.sequence).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let versions = store.sync_versions(vault, [1; 16]).await.expect("version history");
    assert_eq!(versions.iter().map(|change| change.sequence).collect::<Vec<_>>(), vec![1]);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn concurrent_batches_share_one_gap_free_sequence() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [3; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    let left_write = [write(1, None, 10)];
    let right_write = [write(2, None, 20)];
    let (left, right) = tokio::join!(
        store.write_sync_batch(vault, &left_write),
        store.write_sync_batch(vault, &right_write),
    );
    let left = left.expect("left concurrent write");
    let right = right.expect("right concurrent write");
    let mut sequences = vec![left[0].sequence, right[0].sequence];
    sequences.sort_unstable();
    assert_eq!(sequences, vec![1, 2]);

    let page = store.sync_changes(vault, 0, 10).await.expect("read concurrent state");
    assert_eq!(page.changes.len(), 2);
    assert_eq!(page.next_cursor, 2);
    assert!(!page.more);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn expired_and_ahead_cursors_fail_closed() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [4; 16];
    store.create_sync_vault(vault, VaultKind::Organization).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("initial write");
    sqlx::query("UPDATE sync_vaults SET purge_horizon = 1 WHERE vault_id = ?")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("set purge horizon for test");

    assert!(matches!(
        store.sync_changes(vault, 0, 10).await,
        Err(SyncStoreError::CursorExpired { purge_horizon: 1 })
    ));
    assert!(matches!(
        store.sync_changes(vault, 2, 10).await,
        Err(SyncStoreError::CursorAhead { cursor: 2, current: 1 })
    ));
    assert!(store.sync_changes(vault, 1, 10).await.is_ok());
    let snapshot = store.sync_snapshot(vault, 0, 10).await.expect("snapshot starts at zero");
    assert_eq!(snapshot.objects.len(), 1);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn invalid_batches_and_unknown_vaults_fail_closed() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [5; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    assert!(matches!(store.write_sync_batch(vault, &[]).await, Err(SyncStoreError::EmptyBatch)));
    let duplicate = [write(1, None, 10), write(1, None, 20)];
    assert!(matches!(
        store.write_sync_batch(vault, &duplicate).await,
        Err(SyncStoreError::DuplicateObject)
    ));
    let empty_envelope = ObjectWrite { envelope: Vec::new(), ..write(2, None, 20) };
    assert!(matches!(
        store.write_sync_batch(vault, &[empty_envelope]).await,
        Err(SyncStoreError::InvalidEnvelope)
    ));
    assert!(matches!(store.sync_changes(vault, 0, 0).await, Err(SyncStoreError::InvalidPageSize)));
    assert!(matches!(
        store.sync_changes(vault, 0, 1_001).await,
        Err(SyncStoreError::InvalidPageSize)
    ));
    assert!(matches!(
        store.sync_changes([99; 16], 0, 10).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert!(matches!(
        store.sync_versions(vault, [99; 16]).await,
        Err(SyncStoreError::ObjectNotFound)
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn retention_keeps_current_plus_twenty_and_advances_horizon() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [6; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    for sequence in 0..25 {
        let base = (sequence > 0).then_some(sequence);
        store
            .write_sync_batch(vault, &[write(1, base, u8::try_from(sequence).expect("test value"))])
            .await
            .expect("version");
    }
    let now = now_ms();
    let report = store.purge_sync_history(vault, None, now).await.expect("retention pass");
    assert_eq!(report.pruned_versions, 4);
    assert_eq!(report.purged_tombstones, 0);
    assert_eq!(report.purge_horizon, 4);
    let versions = store.sync_versions(vault, [1; 16]).await.expect("retained versions");
    assert_eq!(versions.len(), 21);
    assert_eq!(versions.first().expect("oldest retained").sequence, 5);
    assert!(matches!(
        store.sync_changes(vault, 0, 10).await,
        Err(SyncStoreError::CursorExpired { purge_horizon: 4 })
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn acknowledged_or_expired_tombstones_are_purged_atomically() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [7; 16];
    store.create_sync_vault(vault, VaultKind::Shared).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("initial version");
    store.write_sync_batch(vault, &[write(1, Some(1), 11)]).await.expect("second version");
    let tombstone_receipt =
        store.write_sync_batch(vault, &[tombstone(1, 2)]).await.expect("tombstone");
    assert_eq!(tombstone_receipt[0].sequence, 3);

    let report = store
        .purge_sync_history(vault, Some(3), now_ms())
        .await
        .expect("acknowledged tombstone purge");
    assert_eq!(report.purged_tombstones, 1);
    assert_eq!(report.purge_horizon, 3);
    assert!(matches!(
        store.sync_versions(vault, [1; 16]).await,
        Err(SyncStoreError::ObjectNotFound)
    ));
    assert_eq!(store.sync_snapshot(vault, 0, 10).await.expect("snapshot").objects.len(), 0);

    store.write_sync_batch(vault, &[write(2, None, 20)]).await.expect("new object");
    let old_tombstone = store.write_sync_batch(vault, &[tombstone(2, 3)]).await;
    assert!(old_tombstone.is_err(), "the deleted object must not be resurrected with a stale base");

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn retention_rejects_invalid_ack_floor_and_time() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [8; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("write");
    assert!(matches!(
        store.purge_sync_history(vault, Some(2), now_ms()).await,
        Err(SyncStoreError::CursorAhead { cursor: 2, current: 1 })
    ));
    assert!(matches!(
        store.purge_sync_history(vault, None, -1).await,
        Err(SyncStoreError::InvalidRetentionTime)
    ));
    assert_eq!(VERSION_RETENTION_DAYS, 30);
    assert_eq!(TOMBSTONE_PURGE_AFTER_DAYS, 180);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}
