// SPDX-License-Identifier: AGPL-3.0-only

use sqlx::Row;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "postgres-integration")]
use scoplen_store::PostgresStore;
use scoplen_store::{
    RelationalStore, SqliteStore, StoreError,
    sync::{
        MAX_MEMBERS_PER_SHARED_VAULT, MAX_OBJECTS_PER_VAULT, MAX_SHARED_VAULT_KEY_BYTES,
        MAX_SHARED_VAULT_KEY_EPOCHS, MAX_SHARED_VAULTS_PER_ACCOUNT, ObjectWrite,
        SharedVaultEpochWrap, SharedVaultKey, SyncCardinalityLimits, SyncStoreError,
        TOMBSTONE_PURGE_AFTER_DAYS, VERSION_RETENTION_DAYS, VaultKind,
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

#[cfg(feature = "postgres-integration")]
async fn install_postgres_vault_failure_trigger(
    store: &PostgresStore,
    vault: [u8; 16],
    table: &str,
    event: &str,
) -> (String, String) {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let function = format!("scoplen_test_fail_{suffix}");
    let trigger = format!("scoplen_test_trigger_{suffix}");
    let vault_hex = uuid::Uuid::from_bytes(vault).simple().to_string();
    sqlx::query(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.vault_id = decode('{vault_hex}', 'hex') THEN
           RAISE EXCEPTION 'injected shared-vault mutation failure';
         END IF; RETURN NEW; END $$"
    ))
    .execute(store.pool())
    .await
    .expect("create failure function");
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} {event} ON {table}
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(store.pool())
    .await
    .expect("install failure trigger");
    (trigger, function)
}

#[cfg(feature = "postgres-integration")]
async fn remove_postgres_vault_failure_trigger(
    store: &PostgresStore,
    table: &str,
    trigger: &str,
    function: &str,
) {
    sqlx::query(&format!("DROP TRIGGER {trigger} ON {table}"))
        .execute(store.pool())
        .await
        .expect("remove failure trigger");
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(store.pool())
        .await
        .expect("remove failure function");
}

#[tokio::test]
async fn personal_vault_provisioning_is_unique_atomic_and_account_scoped() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let owner = [21; 16];
    let other = [22; 16];
    let personal = [12; 16];
    let shared = [11; 16];
    store.create_personal_sync_vault(personal, owner, &[7, 8]).await.expect("personal vault");
    store.create_shared_sync_vault(shared, owner, &[9]).await.expect("shared vault");
    store.write_sync_batch(personal, &[write(31, None, 4)]).await.expect("personal write");

    assert_eq!(
        store.get_personal_sync_vault_key(owner).await.expect("owner key"),
        (personal, vec![7, 8])
    );
    assert!(matches!(
        store.get_personal_sync_vault_key(other).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let listed = store.list_sync_vaults_for_account(owner).await.expect("owner vaults");
    assert_eq!(listed.iter().map(|item| item.vault_id).collect::<Vec<_>>(), vec![shared, personal]);
    assert_eq!(listed[0].kind, VaultKind::Shared);
    assert_eq!(listed[1].kind, VaultKind::Personal);
    assert_eq!(listed[1].sequence, 1);
    assert_eq!(listed[1].key_epoch, 1);
    assert!(!listed[1].rotation_pending);
    assert_eq!(store.list_sync_vaults_for_account(other).await.expect("other vaults"), Vec::new());

    assert!(matches!(
        store.create_personal_sync_vault([13; 16], owner, &[1]).await,
        Err(SyncStoreError::VaultAlreadyExists)
    ));
    assert!(matches!(
        store.create_personal_sync_vault(personal, other, &[1]).await,
        Err(SyncStoreError::VaultAlreadyExists)
    ));
    assert!(matches!(
        store.create_personal_sync_vault([14; 16], other, &[]).await,
        Err(SyncStoreError::EmptyVaultKey)
    ));
    assert!(matches!(
        store
            .create_personal_sync_vault([14; 16], other, &vec![1; MAX_SHARED_VAULT_KEY_BYTES + 1])
            .await,
        Err(SyncStoreError::VaultKeyTooLarge)
    ));

    sqlx::query(
        "CREATE TRIGGER reject_personal_ownership BEFORE INSERT ON sync_personal_vaults
         BEGIN SELECT RAISE(ABORT, 'injected ownership failure'); END",
    )
    .execute(store.pool())
    .await
    .expect("install failure trigger");
    assert!(matches!(
        store.create_personal_sync_vault([14; 16], other, &[1]).await,
        Err(SyncStoreError::Constraint(_))
    ));
    let orphan: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_vaults WHERE vault_id = ?")
        .bind([14; 16].as_slice())
        .fetch_one(store.pool())
        .await
        .expect("check transaction rollback");
    assert_eq!(orphan, 0);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_shared_vault_creation_listing_and_keys_are_account_scoped() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let admin = uuid::Uuid::new_v4().into_bytes();
    let outsider = uuid::Uuid::new_v4().into_bytes();
    let first = uuid::Uuid::new_v4().into_bytes();
    let second = uuid::Uuid::new_v4().into_bytes();
    store.create_shared_sync_vault(second, admin, &[2]).await.expect("second vault");
    store.create_shared_sync_vault(first, admin, &[1]).await.expect("first vault");

    let (earlier, later) = if first < second { (first, second) } else { (second, first) };
    let listed = store.list_shared_sync_vaults_for_account(admin).await.expect("admin vaults");
    assert_eq!(listed.iter().map(|vault| vault.vault_id).collect::<Vec<_>>(), vec![earlier, later]);
    assert!(
        listed
            .iter()
            .all(|vault| vault.sequence == 0 && vault.key_epoch == 1 && !vault.rotation_pending)
    );
    assert_eq!(
        store.list_shared_sync_vaults_for_account(outsider).await.expect("outsider vaults"),
        Vec::new()
    );
    assert_eq!(
        store.get_shared_sync_vault_keys(first, admin).await.expect("admin wraps"),
        vec![SharedVaultKey { epoch: 1, wrapped_vault_key: vec![1] }]
    );
    assert!(matches!(
        store.get_shared_sync_vault_keys(first, outsider).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let member: (String, i64, Vec<u8>) = sqlx::query_as(
        "SELECT role, key_epoch, wrapped_vault_key FROM sync_vault_members
         WHERE vault_id = $1 AND account_id = $2",
    )
    .bind(first.as_slice())
    .bind(admin.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("initial admin membership");
    assert_eq!(member, ("admin".to_owned(), 1, vec![1]));

    sqlx::query(
        "UPDATE sync_vaults SET current_seq = 3, rotation_pending = TRUE WHERE vault_id = $1",
    )
    .bind(first.as_slice())
    .execute(store.pool())
    .await
    .expect("advance vault metadata");
    sqlx::query("UPDATE sync_vault_members SET key_epoch = 2 WHERE vault_id = $1")
        .bind(first.as_slice())
        .execute(store.pool())
        .await
        .expect("advance member epoch");
    sqlx::query(
        "INSERT INTO sync_vault_member_keys (vault_id, account_id, epoch, wrapped_vault_key)
         VALUES ($1, $2, 2, $3)",
    )
    .bind(first.as_slice())
    .bind(admin.as_slice())
    .bind([3_u8].as_slice())
    .execute(store.pool())
    .await
    .expect("epoch two wrap");
    assert_eq!(
        store.get_shared_sync_vault_keys(first, admin).await.expect("ordered wraps"),
        vec![
            SharedVaultKey { epoch: 1, wrapped_vault_key: vec![1] },
            SharedVaultKey { epoch: 2, wrapped_vault_key: vec![3] },
        ]
    );
    sqlx::query("INSERT INTO sync_vault_retired_epochs (vault_id, epoch) VALUES ($1, 1)")
        .bind(first.as_slice())
        .execute(store.pool())
        .await
        .expect("retire epoch one");
    assert_eq!(
        store.get_shared_sync_vault_keys(first, admin).await.expect("non-retired wrap"),
        vec![SharedVaultKey { epoch: 2, wrapped_vault_key: vec![3] }]
    );
    let updated = store.list_shared_sync_vaults_for_account(admin).await.expect("updated vaults");
    let first_descriptor =
        updated.iter().find(|vault| vault.vault_id == first).expect("first vault");
    assert_eq!(first_descriptor.sequence, 3);
    assert_eq!(first_descriptor.key_epoch, 2);
    assert!(first_descriptor.rotation_pending);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_shared_vault_concurrent_creation_enforces_quota_and_unique_id() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let limits = SyncCardinalityLimits { max_shared_vaults_per_account: 1, ..Default::default() };
    let store = PostgresStore::connect_with_sync_limits(&database_url, limits)
        .await
        .expect("open PostgreSQL with shared quota");
    let account = uuid::Uuid::new_v4().into_bytes();
    let left = uuid::Uuid::new_v4().into_bytes();
    let right = uuid::Uuid::new_v4().into_bytes();
    let (left_result, right_result) = tokio::join!(
        store.create_shared_sync_vault(left, account, &[1]),
        store.create_shared_sync_vault(right, account, &[2]),
    );
    assert_eq!(usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()), 1);
    assert!(left_result.is_ok() || matches!(left_result, Err(SyncStoreError::QuotaExceeded(_))));
    assert!(right_result.is_ok() || matches!(right_result, Err(SyncStoreError::QuotaExceeded(_))));
    assert_eq!(
        store.list_shared_sync_vaults_for_account(account).await.expect("one vault").len(),
        1
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_vaults WHERE vault_id = $1 OR vault_id = $2")
            .bind(left.as_slice())
            .bind(right.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("one committed vault");
    assert_eq!(rows, 1);

    let duplicate = uuid::Uuid::new_v4().into_bytes();
    let owner_a = uuid::Uuid::new_v4().into_bytes();
    let owner_b = uuid::Uuid::new_v4().into_bytes();
    let (a_result, b_result) = tokio::join!(
        store.create_shared_sync_vault(duplicate, owner_a, &[1]),
        store.create_shared_sync_vault(duplicate, owner_b, &[2]),
    );
    assert_eq!(usize::from(a_result.is_ok()) + usize::from(b_result.is_ok()), 1);
    assert!(a_result.is_ok() || matches!(a_result, Err(SyncStoreError::VaultAlreadyExists)));
    assert!(b_result.is_ok() || matches!(b_result, Err(SyncStoreError::VaultAlreadyExists)));
    let members: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = $1")
            .bind(duplicate.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("one initial member");
    assert_eq!(members, 1);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_shared_vault_creation_rolls_back_after_key_insert_failure() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let account = uuid::Uuid::new_v4().into_bytes();
    let vault = uuid::Uuid::new_v4().into_bytes();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let function_name = format!("reject_shared_key_{suffix}");
    let trigger_name = format!("reject_shared_key_trigger_{suffix}");
    let vault_hex = uuid::Uuid::from_bytes(vault).simple().to_string();
    let create_function = format!(
        "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.vault_id = decode('{vault_hex}', 'hex') THEN
           RAISE EXCEPTION 'injected key-row failure';
         END IF; RETURN NEW; END $$"
    );
    sqlx::query(&create_function).execute(store.pool()).await.expect("create failure function");
    let create_trigger = format!(
        "CREATE TRIGGER {trigger_name} BEFORE INSERT ON sync_vault_member_keys
         FOR EACH ROW EXECUTE FUNCTION {function_name}()"
    );
    sqlx::query(&create_trigger).execute(store.pool()).await.expect("install failure trigger");
    assert!(matches!(
        store.create_shared_sync_vault(vault, account, &[1]).await,
        Err(SyncStoreError::Constraint(_))
    ));
    for table in ["sync_vaults", "sync_vault_members", "sync_vault_member_keys"] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE vault_id = $1"))
                .bind(vault.as_slice())
                .fetch_one(store.pool())
                .await
                .expect("no partial rows");
        assert_eq!(count, 0, "unexpected row in {table}");
    }
    sqlx::query(&format!("DROP TRIGGER {trigger_name} ON sync_vault_member_keys"))
        .execute(store.pool())
        .await
        .expect("remove failure trigger");
    sqlx::query(&format!("DROP FUNCTION {function_name}()"))
        .execute(store.pool())
        .await
        .expect("remove failure function");
    store.create_shared_sync_vault(vault, account, &[1]).await.expect("retry after rollback");
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_shared_vault_epoch_publication_and_retirement_are_atomic() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    let admin = uuid::Uuid::new_v4().into_bytes();
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create shared vault");
    assert!(matches!(
        store.publish_shared_sync_vault_epoch(vault, 2, &[]).await,
        Err(SyncStoreError::InvalidEpochWraps)
    ));
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                3,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![3] }]
            )
            .await,
        Err(SyncStoreError::EpochConflict { current_epoch: 1 })
    ));
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                2,
                &[SharedVaultEpochWrap {
                    account_id: uuid::Uuid::new_v4().into_bytes(),
                    wrapped_vault_key: vec![2]
                }]
            )
            .await,
        Err(SyncStoreError::MemberSetMismatch)
    ));
    store
        .publish_shared_sync_vault_epoch(
            vault,
            2,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
        )
        .await
        .expect("publish epoch two");
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, admin).await.expect("first two epochs"),
        vec![
            SharedVaultKey { epoch: 1, wrapped_vault_key: vec![1] },
            SharedVaultKey { epoch: 2, wrapped_vault_key: vec![2] },
        ]
    );
    let left_wraps = [SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![3] }];
    let right_wraps = [SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![4] }];
    let (left, right) = tokio::join!(
        store.publish_shared_sync_vault_epoch(vault, 3, &left_wraps),
        store.publish_shared_sync_vault_epoch(vault, 3, &right_wraps),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        left.is_ok() || matches!(left, Err(SyncStoreError::EpochConflict { current_epoch: 3 }))
    );
    assert!(
        right.is_ok() || matches!(right, Err(SyncStoreError::EpochConflict { current_epoch: 3 }))
    );
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, admin).await.expect("concurrent epoch").len(),
        3
    );

    store.write_sync_batch(vault, &[write(1, None, 3)]).await.expect("epoch-one object");
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 1).await,
        Err(SyncStoreError::EpochInUse { epoch: 1 })
    ));
    let mut rewritten = write(1, Some(1), 4);
    rewritten.key_epoch = 2;
    store.write_sync_batch(vault, &[rewritten]).await.expect("rewrite to epoch two");
    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("retire old epoch");
    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("repeat retirement");
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, admin).await.expect("retained wraps").len(),
        2
    );
    let mut stale = write(2, None, 5);
    stale.key_epoch = 1;
    assert!(matches!(
        store.write_sync_batch(vault, &[stale]).await,
        Err(SyncStoreError::EpochRetired { epoch: 1 })
    ));
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 3).await,
        Err(SyncStoreError::EpochNewest { epoch: 3 })
    ));
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 4).await,
        Err(SyncStoreError::EpochNotFound { epoch: 4 })
    ));
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(uuid::Uuid::new_v4().into_bytes(), 1).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let personal = uuid::Uuid::new_v4().into_bytes();
    store.create_personal_sync_vault(personal, admin, &[7]).await.expect("personal vault");
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(personal, 1).await,
        Err(SyncStoreError::UnsupportedVaultKind)
    ));
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_shared_vault_epoch_count_limit_reopens_after_retirement() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    let admin = uuid::Uuid::new_v4().into_bytes();
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create shared vault");
    for epoch in 2..=MAX_SHARED_VAULT_KEY_EPOCHS as u64 {
        store
            .publish_shared_sync_vault_epoch(
                vault,
                epoch,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![1] }],
            )
            .await
            .expect("publish within limit");
    }
    let rejected_epoch = MAX_SHARED_VAULT_KEY_EPOCHS as u64 + 1;
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                rejected_epoch,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }]
            )
            .await,
        Err(SyncStoreError::VaultKeyResponseLimit)
    ));
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, admin).await.expect("unchanged keys").len(),
        MAX_SHARED_VAULT_KEY_EPOCHS
    );
    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("retire epoch one");
    store
        .publish_shared_sync_vault_epoch(
            vault,
            rejected_epoch,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
        )
        .await
        .expect("retirement frees capacity");
    let keys = store.get_shared_sync_vault_keys(vault, admin).await.expect("64 served epochs");
    assert_eq!(keys.len(), MAX_SHARED_VAULT_KEY_EPOCHS);
    assert_eq!(keys.first().expect("first epoch").epoch, 2);
    assert_eq!(keys.last().expect("last epoch").epoch, rejected_epoch);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_shared_vault_member_addition_and_removal_preserve_key_isolation() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    let admin = uuid::Uuid::new_v4().into_bytes();
    let member = uuid::Uuid::new_v4().into_bytes();
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create shared vault");
    store
        .publish_shared_sync_vault_epoch(
            vault,
            2,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
        )
        .await
        .expect("publish epoch two");
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                vault,
                member,
                &[SharedVaultKey { epoch: 2, wrapped_vault_key: vec![4] }]
            )
            .await,
        Err(SyncStoreError::MemberEpochMismatch)
    ));
    let wraps = [
        SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3] },
        SharedVaultKey { epoch: 2, wrapped_vault_key: vec![4] },
    ];
    store.add_shared_sync_vault_member(vault, member, &wraps).await.expect("add member");
    assert_eq!(store.get_shared_sync_vault_keys(vault, member).await.expect("member wraps"), wraps);
    assert_eq!(
        store.list_shared_sync_vaults_for_account(member).await.expect("member vaults").len(),
        1
    );
    assert!(matches!(
        store.add_shared_sync_vault_member(vault, member, &wraps).await,
        Err(SyncStoreError::MemberAlreadyExists)
    ));
    let role: String = sqlx::query_scalar(
        "SELECT role FROM sync_vault_members WHERE vault_id = $1 AND account_id = $2",
    )
    .bind(vault.as_slice())
    .bind(member.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("member role");
    assert_eq!(role, "member");
    store.remove_shared_sync_vault_member(vault, member).await.expect("remove member");
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert_eq!(
        store.list_shared_sync_vaults_for_account(member).await.expect("removed member vaults"),
        Vec::new()
    );
    let key_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_vault_member_keys WHERE vault_id = $1 AND account_id = $2",
    )
    .bind(vault.as_slice())
    .bind(member.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("cascaded key rows");
    assert_eq!(key_rows, 0);
    assert!(
        store.list_shared_sync_vaults_for_account(admin).await.expect("admin vaults")[0]
            .rotation_pending
    );
    assert!(matches!(
        store.remove_shared_sync_vault_member(vault, member).await,
        Err(SyncStoreError::MemberNotFound)
    ));
    assert!(matches!(
        store.remove_shared_sync_vault_member(vault, admin).await,
        Err(SyncStoreError::LastAdmin)
    ));
    store
        .publish_shared_sync_vault_epoch(
            vault,
            3,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![5] }],
        )
        .await
        .expect("publish replacement epoch");
    assert!(
        !store.list_shared_sync_vaults_for_account(admin).await.expect("cleared rotation")[0]
            .rotation_pending
    );
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_shared_vault_member_quotas_serialize_competing_additions() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let limits = SyncCardinalityLimits {
        max_shared_vaults_per_account: 1,
        max_members_per_shared_vault: 2,
        ..Default::default()
    };
    let store = PostgresStore::connect_with_sync_limits(&database_url, limits)
        .await
        .expect("open PostgreSQL with quotas");
    let vault = uuid::Uuid::new_v4().into_bytes();
    store
        .create_shared_sync_vault(vault, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("seed vault");
    let left = uuid::Uuid::new_v4().into_bytes();
    let right = uuid::Uuid::new_v4().into_bytes();
    let wraps = [SharedVaultKey { epoch: 1, wrapped_vault_key: vec![2] }];
    let (left_result, right_result) = tokio::join!(
        store.add_shared_sync_vault_member(vault, left, &wraps),
        store.add_shared_sync_vault_member(vault, right, &wraps),
    );
    assert_eq!(usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()), 1);
    assert!(
        left_result.is_ok()
            || matches!(
                left_result,
                Err(SyncStoreError::QuotaExceeded("members per shared vault"))
            )
    );
    assert!(
        right_result.is_ok()
            || matches!(
                right_result,
                Err(SyncStoreError::QuotaExceeded("members per shared vault"))
            )
    );
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = $1")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("bounded membership count");
    assert_eq!(member_count, 2);

    let first = uuid::Uuid::new_v4().into_bytes();
    let second = uuid::Uuid::new_v4().into_bytes();
    store
        .create_shared_sync_vault(first, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("first vault");
    store
        .create_shared_sync_vault(second, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("second vault");
    let target = uuid::Uuid::new_v4().into_bytes();
    let (first_result, second_result) = tokio::join!(
        store.add_shared_sync_vault_member(first, target, &wraps),
        store.add_shared_sync_vault_member(second, target, &wraps),
    );
    assert_eq!(usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()), 1);
    assert!(
        first_result.is_ok()
            || matches!(
                first_result,
                Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
            )
    );
    assert!(
        second_result.is_ok()
            || matches!(
                second_result,
                Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
            )
    );
    assert_eq!(
        store.list_shared_sync_vaults_for_account(target).await.expect("one target vault").len(),
        1
    );

    let creation_target = uuid::Uuid::new_v4().into_bytes();
    let race_vault = uuid::Uuid::new_v4().into_bytes();
    let new_vault = uuid::Uuid::new_v4().into_bytes();
    store
        .create_shared_sync_vault(race_vault, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("create membership race vault");
    let (add_result, create_result) = tokio::join!(
        store.add_shared_sync_vault_member(race_vault, creation_target, &wraps),
        store.create_shared_sync_vault(new_vault, creation_target, &[3]),
    );
    assert_eq!(usize::from(add_result.is_ok()) + usize::from(create_result.is_ok()), 1);
    assert!(
        add_result.is_ok()
            || matches!(
                add_result,
                Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
            )
    );
    assert!(
        create_result.is_ok()
            || matches!(
                create_result,
                Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
            )
    );
    assert_eq!(
        store
            .list_shared_sync_vaults_for_account(creation_target)
            .await
            .expect("one membership after creation race")
            .len(),
        1
    );
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_shared_vault_mutations_roll_back_late_storage_failures() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    let admin = uuid::Uuid::new_v4().into_bytes();
    let member = uuid::Uuid::new_v4().into_bytes();
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create shared vault");

    let (trigger, function) = install_postgres_vault_failure_trigger(
        &store,
        vault,
        "sync_vault_members",
        "BEFORE UPDATE OF key_epoch",
    )
    .await;
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                2,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }]
            )
            .await,
        Err(SyncStoreError::Database(_))
    ));
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, admin).await.expect("publication rollback").len(),
        1
    );
    remove_postgres_vault_failure_trigger(&store, "sync_vault_members", &trigger, &function).await;
    store
        .publish_shared_sync_vault_epoch(
            vault,
            2,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
        )
        .await
        .expect("retry publication");

    let (trigger, function) = install_postgres_vault_failure_trigger(
        &store,
        vault,
        "sync_vault_member_keys",
        "BEFORE INSERT",
    )
    .await;
    let wraps = [
        SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3] },
        SharedVaultKey { epoch: 2, wrapped_vault_key: vec![4] },
    ];
    assert!(matches!(
        store.add_shared_sync_vault_member(vault, member, &wraps).await,
        Err(SyncStoreError::Constraint(_))
    ));
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let membership_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = $1 AND account_id = $2",
    )
    .bind(vault.as_slice())
    .bind(member.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("member insertion rollback");
    assert_eq!(membership_rows, 0);
    remove_postgres_vault_failure_trigger(&store, "sync_vault_member_keys", &trigger, &function)
        .await;
    store.add_shared_sync_vault_member(vault, member, &wraps).await.expect("retry member addition");

    let (trigger, function) = install_postgres_vault_failure_trigger(
        &store,
        vault,
        "sync_vault_retired_epochs",
        "BEFORE INSERT",
    )
    .await;
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 1).await,
        Err(SyncStoreError::Constraint(_))
    ));
    for account in [admin, member] {
        assert_eq!(
            store
                .get_shared_sync_vault_keys(vault, account)
                .await
                .expect("retirement rollback")
                .len(),
            2
        );
    }
    remove_postgres_vault_failure_trigger(&store, "sync_vault_retired_epochs", &trigger, &function)
        .await;
    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("retry retirement");

    let (trigger, function) = install_postgres_vault_failure_trigger(
        &store,
        vault,
        "sync_vaults",
        "BEFORE UPDATE OF rotation_pending",
    )
    .await;
    assert!(matches!(
        store.remove_shared_sync_vault_member(vault, member).await,
        Err(SyncStoreError::Database(_))
    ));
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, member).await.expect("removal rollback").len(),
        1
    );
    assert!(
        !store.list_shared_sync_vaults_for_account(admin).await.expect("pending rollback")[0]
            .rotation_pending
    );
    remove_postgres_vault_failure_trigger(&store, "sync_vaults", &trigger, &function).await;
    store.remove_shared_sync_vault_member(vault, member).await.expect("retry removal");
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert!(
        store.list_shared_sync_vaults_for_account(admin).await.expect("pending rotation")[0]
            .rotation_pending
    );
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_shared_vault_key_body_limit_rejects_publication_and_member_addition() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    let admin = uuid::Uuid::new_v4().into_bytes();
    let member = uuid::Uuid::new_v4().into_bytes();
    let rejected_member = uuid::Uuid::new_v4().into_bytes();
    let maximum_wrap = vec![1; MAX_SHARED_VAULT_KEY_BYTES];
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create shared vault");
    for epoch in 2..MAX_SHARED_VAULT_KEY_EPOCHS as u64 {
        store
            .publish_shared_sync_vault_epoch(
                vault,
                epoch,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![1] }],
            )
            .await
            .expect("publish below body limit");
    }
    let existing_wraps = (1..MAX_SHARED_VAULT_KEY_EPOCHS as u64)
        .map(|epoch| SharedVaultKey { epoch, wrapped_vault_key: maximum_wrap.clone() })
        .collect::<Vec<_>>();
    store
        .add_shared_sync_vault_member(vault, member, &existing_wraps)
        .await
        .expect("add large-wrap member");
    let next = MAX_SHARED_VAULT_KEY_EPOCHS as u64;
    let (first, second) = if admin < member { (admin, member) } else { (member, admin) };
    let oversized = [
        SharedVaultEpochWrap {
            account_id: first,
            wrapped_vault_key: if first == member { maximum_wrap.clone() } else { vec![2] },
        },
        SharedVaultEpochWrap {
            account_id: second,
            wrapped_vault_key: if second == member { maximum_wrap.clone() } else { vec![2] },
        },
    ];
    assert!(matches!(
        store.publish_shared_sync_vault_epoch(vault, next, &oversized).await,
        Err(SyncStoreError::VaultKeyResponseLimit)
    ));
    for account in [admin, member] {
        assert_eq!(
            store
                .get_shared_sync_vault_keys(vault, account)
                .await
                .expect("unchanged key set")
                .len(),
            MAX_SHARED_VAULT_KEY_EPOCHS - 1
        );
    }
    let fitting = [
        SharedVaultEpochWrap { account_id: first, wrapped_vault_key: vec![2] },
        SharedVaultEpochWrap { account_id: second, wrapped_vault_key: vec![2] },
    ];
    store.publish_shared_sync_vault_epoch(vault, next, &fitting).await.expect("small wraps fit");
    let rejected_wraps = (1..=next)
        .map(|epoch| SharedVaultKey { epoch, wrapped_vault_key: maximum_wrap.clone() })
        .collect::<Vec<_>>();
    assert!(matches!(
        store.add_shared_sync_vault_member(vault, rejected_member, &rejected_wraps).await,
        Err(SyncStoreError::VaultKeyResponseLimit)
    ));
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, rejected_member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_vault_provisioning_is_atomic_and_account_scoped() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let owner = uuid::Uuid::new_v4().into_bytes();
    let other = uuid::Uuid::new_v4().into_bytes();
    let mut shared = uuid::Uuid::new_v4().into_bytes();
    let mut personal = shared;
    shared[15] = 1;
    personal[15] = 2;
    store.create_personal_sync_vault(personal, owner, &[7, 8]).await.expect("personal vault");
    sqlx::query(
        "INSERT INTO sync_vaults (vault_id, kind, current_seq, rotation_pending)
         VALUES ($1, 'shared', 3, TRUE)",
    )
    .bind(shared.as_slice())
    .execute(store.pool())
    .await
    .expect("shared vault metadata");
    sqlx::query(
        "INSERT INTO sync_vault_members (vault_id, account_id, role, key_epoch, wrapped_vault_key)
         VALUES ($1, $2, 'admin', 2, $3)",
    )
    .bind(shared.as_slice())
    .bind(owner.as_slice())
    .bind([9_u8].as_slice())
    .execute(store.pool())
    .await
    .expect("shared membership");

    assert_eq!(
        store.get_personal_sync_vault_key(owner).await.expect("owner key"),
        (personal, vec![7, 8])
    );
    assert!(matches!(
        store.get_personal_sync_vault_key(other).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let listed = store.list_sync_vaults_for_account(owner).await.expect("owner vaults");
    assert_eq!(listed.iter().map(|item| item.vault_id).collect::<Vec<_>>(), vec![shared, personal]);
    assert_eq!(listed[0].kind, VaultKind::Shared);
    assert_eq!(listed[0].sequence, 3);
    assert_eq!(listed[0].key_epoch, 2);
    assert!(listed[0].rotation_pending);
    assert_eq!(listed[1].kind, VaultKind::Personal);
    assert_eq!(listed[1].sequence, 0);
    assert_eq!(listed[1].key_epoch, 1);
    assert!(!listed[1].rotation_pending);
    assert_eq!(store.list_sync_vaults_for_account(other).await.expect("other vaults"), Vec::new());

    let orphan = uuid::Uuid::new_v4().into_bytes();
    assert!(matches!(
        store.create_personal_sync_vault(orphan, owner, &[1]).await,
        Err(SyncStoreError::VaultAlreadyExists)
    ));
    let orphan_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_vaults WHERE vault_id = $1")
            .bind(orphan.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("check rolled-back vault row");
    assert_eq!(orphan_count, 0);
    assert!(matches!(
        store.create_personal_sync_vault(personal, other, &[1]).await,
        Err(SyncStoreError::VaultAlreadyExists)
    ));
    assert!(matches!(
        store.create_personal_sync_vault(orphan, other, &[]).await,
        Err(SyncStoreError::EmptyVaultKey)
    ));
    assert!(matches!(
        store
            .create_personal_sync_vault(orphan, other, &vec![1; MAX_SHARED_VAULT_KEY_BYTES + 1])
            .await,
        Err(SyncStoreError::VaultKeyTooLarge)
    ));
    assert!(matches!(
        store.get_personal_sync_vault_key(other).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_vault_concurrent_provisioning_has_one_winner() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let account = uuid::Uuid::new_v4().into_bytes();
    let left = uuid::Uuid::new_v4().into_bytes();
    let right = uuid::Uuid::new_v4().into_bytes();
    let (left_result, right_result) = tokio::join!(
        store.create_personal_sync_vault(left, account, &[1]),
        store.create_personal_sync_vault(right, account, &[2]),
    );
    assert_eq!(usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()), 1);
    assert!(left_result.is_ok() || matches!(left_result, Err(SyncStoreError::VaultAlreadyExists)));
    assert!(
        right_result.is_ok() || matches!(right_result, Err(SyncStoreError::VaultAlreadyExists))
    );
    let winner = if left_result.is_ok() { (left, vec![1]) } else { (right, vec![2]) };
    assert_eq!(store.get_personal_sync_vault_key(account).await.expect("winner key"), winner);
    let vaults = store.list_sync_vaults_for_account(account).await.expect("one owner vault");
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].vault_id, winner.0);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_vaults WHERE vault_id = $1 OR vault_id = $2")
            .bind(left.as_slice())
            .bind(right.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("check losing transaction rollback");
    assert_eq!(rows, 1);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_personal_sync_write_change_ack_round_trip() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let limits = SyncCardinalityLimits { max_objects_per_vault: 2, ..Default::default() };
    let store = PostgresStore::connect_with_sync_limits(&database_url, limits)
        .await
        .expect("open PostgreSQL with custom limits");
    assert_eq!(store.sync_cardinality_limits(), limits);
    let vault = uuid::Uuid::new_v4().into_bytes();
    let account = uuid::Uuid::new_v4().into_bytes();
    store.create_personal_sync_vault(vault, account, &[7]).await.expect("personal vault");
    assert_eq!(store.sync_vault_kind(vault).await.expect("vault kind"), VaultKind::Personal);
    assert!(matches!(store.sync_vault_kind([0; 16]).await, Err(SyncStoreError::VaultNotFound)));

    let receipts = store
        .write_sync_batch(vault, &[write(1, None, 10), write(2, None, 20)])
        .await
        .expect("initial batch");
    assert_eq!(receipts.iter().map(|receipt| receipt.sequence).collect::<Vec<_>>(), vec![1, 2]);
    let first_page = store.sync_changes(vault, 0, 1).await.expect("first page");
    assert_eq!(first_page.changes[0].object_id, [1; 16]);
    assert!(first_page.more);
    assert_eq!(first_page.next_cursor, 1);
    let second_page = store.sync_changes(vault, 1, 1).await.expect("second page");
    assert_eq!(second_page.changes[0].object_id, [2; 16]);
    assert!(!second_page.more);
    assert_eq!(second_page.next_cursor, 2);

    let updated = store.write_sync_batch(vault, &[write(1, Some(1), 30)]).await.expect("update");
    assert_eq!(updated[0].sequence, 3);
    let current = store.sync_changes(vault, 0, 10).await.expect("current versions");
    assert_eq!(
        current.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(current.next_cursor, 3);
    assert!(!current.more);
    assert_eq!(current.changes[1].signer_device_id, Some([9; 16]));
    let versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_object_versions WHERE vault_id = $1")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("version history");
    assert_eq!(versions, 3);
    assert!(matches!(
        store.write_sync_batch(vault, &[write(3, None, 40)]).await,
        Err(SyncStoreError::QuotaExceeded("objects per vault"))
    ));
    let current_seq: i64 =
        sqlx::query_scalar("SELECT current_seq FROM sync_vaults WHERE vault_id = $1")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("unchanged sequence");
    assert_eq!(current_seq, 3);

    let device = uuid::Uuid::new_v4().into_bytes();
    assert_eq!(store.ack_sync_cursor(vault, device, 3).await.expect("ack"), 3);
    assert_eq!(store.ack_sync_cursor(vault, device, 2).await.expect("lower ack"), 3);
    assert!(matches!(
        store.ack_sync_cursor(vault, device, 4).await,
        Err(SyncStoreError::CursorAhead { cursor: 4, current: 3 })
    ));
    assert!(matches!(
        store.ack_sync_cursor([0; 16], device, 0).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert!(matches!(store.sync_changes(vault, 0, 0).await, Err(SyncStoreError::InvalidPageSize)));
    assert!(matches!(store.sync_changes([0; 16], 0, 1).await, Err(SyncStoreError::VaultNotFound)));
    sqlx::query("UPDATE sync_vaults SET purge_horizon = 2 WHERE vault_id = $1")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("advance purge horizon");
    assert!(matches!(
        store.sync_changes(vault, 0, 10).await,
        Err(SyncStoreError::CursorExpired { purge_horizon: 2 })
    ));
    assert!(matches!(
        store.sync_changes(vault, 4, 10).await,
        Err(SyncStoreError::CursorAhead { cursor: 4, current: 3 })
    ));
    assert_eq!(store.sync_changes(vault, 3, 10).await.expect("caught up").next_cursor, 3);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_sync_conflicts_rollback_in_request_order() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    store
        .create_personal_sync_vault(vault, uuid::Uuid::new_v4().into_bytes(), &[7])
        .await
        .expect("personal vault");
    store
        .write_sync_batch(vault, &[write(1, None, 10), write(2, None, 20)])
        .await
        .expect("initial batch");
    let error = store
        .write_sync_batch(vault, &[write(2, Some(99), 30), write(1, None, 40), write(3, None, 50)])
        .await
        .expect_err("stale batch");
    let SyncStoreError::Conflict { conflicts } = error else { panic!("expected CAS conflict") };
    assert_eq!(
        conflicts.iter().map(|item| item.object_id).collect::<Vec<_>>(),
        vec![[2; 16], [1; 16]]
    );
    assert_eq!(conflicts[0].current.as_ref().map(|item| item.sequence), Some(2));
    assert_eq!(conflicts[1].current.as_ref().map(|item| item.sequence), Some(1));
    assert_eq!(
        store.write_sync_batch(vault, &[write(3, None, 50)]).await.expect("next write")[0].sequence,
        3
    );
    assert!(matches!(store.write_sync_batch(vault, &[]).await, Err(SyncStoreError::EmptyBatch)));
    assert!(matches!(
        store.write_sync_batch(vault, &[write(4, None, 60), write(4, None, 70)]).await,
        Err(SyncStoreError::DuplicateObject)
    ));
    sqlx::query("INSERT INTO sync_vault_retired_epochs (vault_id, epoch) VALUES ($1, 1)")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("retire test epoch");
    assert!(matches!(
        store.write_sync_batch(vault, &[write(4, None, 60)]).await,
        Err(SyncStoreError::EpochRetired { epoch: 1 })
    ));
    let page = store.sync_changes(vault, 0, 10).await.expect("unchanged state");
    assert_eq!(page.changes.iter().map(|item| item.sequence).collect::<Vec<_>>(), vec![1, 2, 3]);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_sync_concurrent_writes_and_acks_are_monotone() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    store
        .create_personal_sync_vault(vault, uuid::Uuid::new_v4().into_bytes(), &[7])
        .await
        .expect("personal vault");
    let left_write = [write(1, None, 10)];
    let right_write = [write(2, None, 20)];
    let (left, right) = tokio::join!(
        store.write_sync_batch(vault, &left_write),
        store.write_sync_batch(vault, &right_write),
    );
    let mut sequences = vec![left.expect("left")[0].sequence, right.expect("right")[0].sequence];
    sequences.sort_unstable();
    assert_eq!(sequences, vec![1, 2]);

    let left_write = [write(3, None, 30)];
    let right_write = [write(3, None, 40)];
    let (left, right) = tokio::join!(
        store.write_sync_batch(vault, &left_write),
        store.write_sync_batch(vault, &right_write),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    for result in [left, right] {
        match result {
            Ok(receipts) => assert_eq!(receipts[0].sequence, 3),
            Err(SyncStoreError::Conflict { conflicts }) => {
                assert_eq!(conflicts[0].current.as_ref().map(|item| item.sequence), Some(3));
            }
            Err(error) => panic!("unexpected concurrent write failure: {error}"),
        }
    }
    assert_eq!(
        store.write_sync_batch(vault, &[write(4, None, 50)]).await.expect("next")[0].sequence,
        4
    );
    let device = uuid::Uuid::new_v4().into_bytes();
    let (low, high) = tokio::join!(
        store.ack_sync_cursor(vault, device, 2),
        store.ack_sync_cursor(vault, device, 4),
    );
    assert!(low.is_ok());
    assert_eq!(high.expect("high ack"), 4);
    assert_eq!(store.ack_sync_cursor(vault, device, 1).await.expect("stored maximum"), 4);
    assert_eq!(store.sync_changes(vault, 0, 10).await.expect("all current").next_cursor, 4);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_personal_sync_snapshot_and_versions_are_vault_scoped() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let first = uuid::Uuid::new_v4().into_bytes();
    let second = uuid::Uuid::new_v4().into_bytes();
    store
        .create_personal_sync_vault(first, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("first account vault");
    store
        .create_personal_sync_vault(second, uuid::Uuid::new_v4().into_bytes(), &[2])
        .await
        .expect("second account vault");
    store
        .write_sync_batch(first, &[write(1, None, 10), write(2, None, 20), write(3, None, 30)])
        .await
        .expect("first vault objects");
    store.write_sync_batch(second, &[write(1, None, 90)]).await.expect("second vault object");
    store.write_sync_batch(first, &[write(1, Some(1), 40)]).await.expect("new first version");

    let first_page = store.sync_snapshot(first, 0, 1).await.expect("first page");
    assert_eq!(first_page.objects[0].object_id, [2; 16]);
    assert_eq!(first_page.objects[0].sequence, 2);
    assert!(first_page.more);
    assert_eq!(first_page.next_cursor, 2);
    let second_page = store.sync_snapshot(first, 2, 1).await.expect("second page");
    assert_eq!(second_page.objects[0].sequence, 3);
    assert!(second_page.more);
    assert_eq!(second_page.next_cursor, 3);
    let last_page = store.sync_snapshot(first, 3, 1).await.expect("last page");
    assert_eq!(last_page.objects[0].sequence, 4);
    assert_eq!(last_page.objects[0].envelope, vec![40, 41]);
    assert_eq!(last_page.objects[0].signer_device_id, Some([9; 16]));
    assert!(!last_page.more);
    assert_eq!(last_page.next_cursor, 4);
    let caught_up = store.sync_snapshot(first, 4, 1).await.expect("caught up");
    assert_eq!(caught_up.objects.len(), 0);
    assert!(!caught_up.more);
    assert_eq!(caught_up.next_cursor, 4);

    let first_versions = store.sync_versions(first, [1; 16]).await.expect("first history");
    assert_eq!(first_versions.iter().map(|item| item.sequence).collect::<Vec<_>>(), vec![1, 4]);
    assert_eq!(first_versions[0].envelope, vec![10, 11]);
    assert_eq!(first_versions[1].envelope, vec![40, 41]);
    let other_page = store.sync_snapshot(second, 0, 10).await.expect("other account snapshot");
    assert_eq!(other_page.objects.len(), 1);
    assert_eq!(other_page.objects[0].envelope, vec![90, 91]);
    assert_eq!(other_page.next_cursor, 1);
    let other_versions = store.sync_versions(second, [1; 16]).await.expect("other history");
    assert_eq!(other_versions.len(), 1);
    assert_eq!(other_versions[0].envelope, vec![90, 91]);

    for limit in [0, 1_001] {
        assert!(matches!(
            store.sync_snapshot(first, 0, limit).await,
            Err(SyncStoreError::InvalidPageSize)
        ));
    }
    assert!(matches!(
        store.sync_snapshot(first, 5, 1).await,
        Err(SyncStoreError::CursorAhead { cursor: 5, current: 4 })
    ));
    assert!(matches!(store.sync_snapshot([0; 16], 0, 1).await, Err(SyncStoreError::VaultNotFound)));
    assert!(matches!(
        store.sync_versions([0; 16], [1; 16]).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert!(matches!(
        store.sync_versions(first, [99; 16]).await,
        Err(SyncStoreError::ObjectNotFound)
    ));
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_sync_snapshot_recovers_after_retention() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    store
        .create_personal_sync_vault(vault, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("personal vault");
    for revision in 0..25_u64 {
        store
            .write_sync_batch(
                vault,
                &[write(
                    1,
                    (revision > 0).then_some(revision),
                    u8::try_from(revision).expect("bounded revision"),
                )],
            )
            .await
            .expect("write revision");
    }
    let report = store.purge_sync_history(vault, None, now_ms()).await.expect("retention");
    assert_eq!(report.pruned_versions, 4);
    assert_eq!(report.purge_horizon, 4);
    assert!(matches!(
        store.sync_changes(vault, 0, 10).await,
        Err(SyncStoreError::CursorExpired { purge_horizon: 4 })
    ));
    let snapshot = store.sync_snapshot(vault, 0, 10).await.expect("full reconciliation");
    assert_eq!(snapshot.objects.iter().map(|item| item.sequence).collect::<Vec<_>>(), vec![25]);
    assert_eq!(snapshot.next_cursor, 25);
    assert!(!snapshot.more);
    let versions = store.sync_versions(vault, [1; 16]).await.expect("retained history");
    assert_eq!(versions.len(), 21);
    assert_eq!(versions.first().expect("oldest").sequence, 5);
    assert_eq!(versions.last().expect("current").sequence, 25);

    store.write_sync_batch(vault, &[tombstone(1, 25)]).await.expect("tombstone");
    let report = store.purge_sync_history(vault, Some(26), now_ms()).await.expect("purge");
    assert_eq!(report.purged_tombstones, 1);
    assert_eq!(report.purge_horizon, 26);
    assert!(matches!(
        store.sync_versions(vault, [1; 16]).await,
        Err(SyncStoreError::ObjectNotFound)
    ));
    let snapshot = store.sync_snapshot(vault, 0, 10).await.expect("empty reconciliation");
    assert_eq!(snapshot.objects.len(), 0);
    assert_eq!(snapshot.next_cursor, 26);
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_personal_sync_snapshot_and_versions_remain_consistent_during_writes() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL");
    let vault = uuid::Uuid::new_v4().into_bytes();
    store
        .create_personal_sync_vault(vault, uuid::Uuid::new_v4().into_bytes(), &[1])
        .await
        .expect("personal vault");
    store.write_sync_batch(vault, &[write(1, None, 1)]).await.expect("initial object");
    let writer = store.clone();
    let reader = store.clone();
    tokio::join!(
        async move {
            for revision in 1..=60_u64 {
                writer
                    .write_sync_batch(
                        vault,
                        &[write(
                            1,
                            Some(revision),
                            u8::try_from(revision + 1).expect("bounded revision"),
                        )],
                    )
                    .await
                    .expect("concurrent revision");
                tokio::task::yield_now().await;
            }
        },
        async move {
            for _ in 0..100 {
                let snapshot = reader.sync_snapshot(vault, 0, 1).await.expect("snapshot");
                assert_eq!(snapshot.objects.len(), 1);
                assert_eq!(snapshot.next_cursor, snapshot.objects[0].sequence);
                assert!(!snapshot.more);
                let versions = reader.sync_versions(vault, [1; 16]).await.expect("versions");
                assert!((1..=21).contains(&versions.len()));
                assert!(versions.windows(2).all(|pair| pair[0].sequence + 1 == pair[1].sequence));
                assert!(versions.iter().all(|item| item.object_id == [1; 16]));
                tokio::task::yield_now().await;
            }
        },
    );
    let final_page = store.sync_snapshot(vault, 0, 1).await.expect("final snapshot");
    assert_eq!(final_page.next_cursor, 61);
    assert_eq!(final_page.objects[0].sequence, 61);
    store.pool().close().await;
}

#[tokio::test]
async fn shared_session_descriptors_follow_current_membership_and_rotation() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let first = [11; 16];
    let second = [12; 16];
    let admin = [21; 16];
    let member = [22; 16];
    let outsider = [23; 16];
    store.create_shared_sync_vault(second, admin, &[1]).await.expect("second vault");
    store.create_shared_sync_vault(first, admin, &[2]).await.expect("first vault");
    store
        .add_shared_sync_vault_member(
            first,
            member,
            &[SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3] }],
        )
        .await
        .expect("add member");
    store.write_sync_batch(first, &[write(31, None, 4)]).await.expect("advance sequence");

    let listed = store.list_shared_sync_vaults_for_account(admin).await.expect("admin vaults");
    assert_eq!(listed.iter().map(|vault| vault.vault_id).collect::<Vec<_>>(), vec![first, second]);
    assert_eq!(listed[0].sequence, 1);
    assert_eq!(listed[0].key_epoch, 1);
    assert!(!listed[0].rotation_pending);
    assert_eq!(
        store.list_shared_sync_vaults_for_account(member).await.expect("member vaults").len(),
        1
    );
    assert_eq!(
        store.list_shared_sync_vaults_for_account(outsider).await.expect("outsider vaults"),
        Vec::new()
    );

    store.remove_shared_sync_vault_member(first, member).await.expect("remove member");
    assert_eq!(
        store.list_shared_sync_vaults_for_account(member).await.expect("removed member vaults"),
        Vec::new()
    );
    assert!(
        store.list_shared_sync_vaults_for_account(admin).await.expect("pending vaults")[0]
            .rotation_pending
    );
    store
        .publish_shared_sync_vault_epoch(
            first,
            2,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![5] }],
        )
        .await
        .expect("publish epoch");
    let current = store.list_shared_sync_vaults_for_account(admin).await.expect("current vaults");
    assert_eq!(current[0].key_epoch, 2);
    assert!(!current[0].rotation_pending);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

fn write(object_id: u8, base_sequence: Option<u64>, envelope: u8) -> ObjectWrite {
    ObjectWrite {
        object_id: [object_id; 16],
        base_sequence,
        envelope: vec![envelope, envelope + 1],
        key_epoch: 1,
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
async fn shared_vault_epoch_retirement_is_safe_and_idempotent() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [41; 16];
    let account = [42; 16];
    store.create_shared_sync_vault(vault, account, &[1]).await.expect("create vault");
    store
        .publish_shared_sync_vault_epoch(
            vault,
            2,
            &[SharedVaultEpochWrap { account_id: account, wrapped_vault_key: vec![2] }],
        )
        .await
        .expect("publish epoch two");
    store.write_sync_batch(vault, &[write(1, None, 3)]).await.expect("write epoch one");
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 1).await,
        Err(SyncStoreError::EpochInUse { epoch: 1 })
    ));

    let mut rewritten = write(1, Some(1), 4);
    rewritten.key_epoch = 2;
    store.write_sync_batch(vault, &[rewritten]).await.expect("rewrite epoch two");
    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("retire epoch one");
    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("repeat retirement");
    let mut stale = write(2, None, 5);
    stale.key_epoch = 1;
    assert!(matches!(
        store.write_sync_batch(vault, &[stale]).await,
        Err(SyncStoreError::EpochRetired { epoch: 1 })
    ));
    assert_eq!(
        store.get_shared_sync_vault_keys(vault, account).await.expect("remaining key"),
        vec![SharedVaultKey { epoch: 2, wrapped_vault_key: vec![2] }]
    );
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 2).await,
        Err(SyncStoreError::EpochNewest { epoch: 2 })
    ));
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(vault, 3).await,
        Err(SyncStoreError::EpochNotFound { epoch: 3 })
    ));
    assert!(matches!(
        store.retire_shared_sync_vault_epoch([43; 16], 1).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let personal = [44; 16];
    store.create_personal_sync_vault(personal, account, &[5]).await.expect("personal vault");
    assert!(matches!(
        store.retire_shared_sync_vault_epoch(personal, 1).await,
        Err(SyncStoreError::UnsupportedVaultKind)
    ));

    let history = store.sync_versions(vault, [1; 16]).await.expect("history");
    assert_eq!(history[0].key_epoch, 1);
    assert_eq!(history[1].key_epoch, 2);
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn shared_vault_key_count_limit_rolls_back_and_retirement_reopens_capacity() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [51; 16];
    let admin = [52; 16];
    let new_member = [53; 16];
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create vault");
    for epoch in 2..=MAX_SHARED_VAULT_KEY_EPOCHS as u64 {
        store
            .publish_shared_sync_vault_epoch(
                vault,
                epoch,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![1] }],
            )
            .await
            .expect("publish within epoch limit");
    }
    let rejected_epoch = MAX_SHARED_VAULT_KEY_EPOCHS as u64 + 1;
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                rejected_epoch,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
            )
            .await,
        Err(SyncStoreError::VaultKeyResponseLimit)
    ));
    let keys = store.get_shared_sync_vault_keys(vault, admin).await.expect("unchanged keys");
    assert_eq!(keys.len(), MAX_SHARED_VAULT_KEY_EPOCHS);
    assert_eq!(keys.last().expect("latest key").epoch, rejected_epoch - 1);
    let state = sqlx::query("SELECT m.key_epoch, v.rotation_pending FROM sync_vault_members AS m JOIN sync_vaults AS v ON v.vault_id = m.vault_id WHERE m.vault_id = ? AND m.account_id = ?")
        .bind(vault.as_slice())
        .bind(admin.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("unchanged vault state");
    assert_eq!(
        state.get::<i64, _>("key_epoch"),
        i64::try_from(rejected_epoch - 1).expect("test epoch fits SQLite")
    );
    assert_eq!(state.get::<i64, _>("rotation_pending"), 0);

    store.retire_shared_sync_vault_epoch(vault, 1).await.expect("retire old epoch");
    store
        .publish_shared_sync_vault_epoch(
            vault,
            rejected_epoch,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
        )
        .await
        .expect("retirement reopens capacity");
    let keys = store.get_shared_sync_vault_keys(vault, admin).await.expect("current keys");
    assert_eq!(keys.len(), MAX_SHARED_VAULT_KEY_EPOCHS);
    assert_eq!(keys.first().expect("first key").epoch, 2);
    assert_eq!(keys.last().expect("last key").epoch, rejected_epoch);

    let oversized_member_keys = (2..=rejected_epoch)
        .map(|epoch| SharedVaultKey {
            epoch,
            wrapped_vault_key: vec![3; MAX_SHARED_VAULT_KEY_BYTES],
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        store.add_shared_sync_vault_member(vault, new_member, &oversized_member_keys).await,
        Err(SyncStoreError::VaultKeyResponseLimit)
    ));
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, new_member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_member_keys WHERE vault_id = ? AND account_id = ?"
        )
        .bind(vault.as_slice())
        .bind(new_member.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("new member wrap count"),
        0
    );

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn shared_vault_key_body_limit_rejects_oversized_publication() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [61; 16];
    let admin = [62; 16];
    let member = [63; 16];
    let maximum_wrap = vec![1; MAX_SHARED_VAULT_KEY_BYTES];
    store.create_shared_sync_vault(vault, admin, &[1]).await.expect("create vault");
    for epoch in 2..MAX_SHARED_VAULT_KEY_EPOCHS as u64 {
        store
            .publish_shared_sync_vault_epoch(
                vault,
                epoch,
                &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![1] }],
            )
            .await
            .expect("publish below body limit");
    }
    let member_keys = (1..MAX_SHARED_VAULT_KEY_EPOCHS as u64)
        .map(|epoch| SharedVaultKey { epoch, wrapped_vault_key: maximum_wrap.clone() })
        .collect::<Vec<_>>();
    store.add_shared_sync_vault_member(vault, member, &member_keys).await.expect("add member");
    let final_epoch = MAX_SHARED_VAULT_KEY_EPOCHS as u64;
    assert!(matches!(
        store
            .publish_shared_sync_vault_epoch(
                vault,
                final_epoch,
                &[
                    SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] },
                    SharedVaultEpochWrap { account_id: member, wrapped_vault_key: maximum_wrap },
                ],
            )
            .await,
        Err(SyncStoreError::VaultKeyResponseLimit)
    ));
    for account in [admin, member] {
        let keys = store.get_shared_sync_vault_keys(vault, account).await.expect("unchanged keys");
        assert_eq!(keys.len(), MAX_SHARED_VAULT_KEY_EPOCHS - 1);
        assert_eq!(keys.last().expect("last key").epoch, final_epoch - 1);
    }
    store
        .publish_shared_sync_vault_epoch(
            vault,
            final_epoch,
            &[
                SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] },
                SharedVaultEpochWrap { account_id: member, wrapped_vault_key: vec![2] },
            ],
        )
        .await
        .expect("smaller wrap fits body limit");
    for account in [admin, member] {
        assert_eq!(
            store.get_shared_sync_vault_keys(vault, account).await.expect("deliverable keys").len(),
            MAX_SHARED_VAULT_KEY_EPOCHS
        );
    }

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn shared_vault_quota_counts_creation_and_membership_atomically() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let account = [70; 16];
    let other = [71; 16];
    let target = [72; 16];
    sqlx::query(
        "WITH RECURSIVE ids(n) AS (
           SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < ?
         )
         INSERT INTO sync_vaults (vault_id, kind)
         SELECT CAST(printf('%016X', n) AS BLOB), 'shared' FROM ids",
    )
    .bind(i64::try_from(MAX_SHARED_VAULTS_PER_ACCOUNT).expect("test limit"))
    .execute(store.pool())
    .await
    .expect("seed shared vaults");
    sqlx::query(
        "INSERT INTO sync_vault_members (vault_id, account_id, role, key_epoch, wrapped_vault_key)
         SELECT vault_id, ?, 'member', 1, x'01' FROM sync_vaults WHERE kind = 'shared'",
    )
    .bind(account.as_slice())
    .execute(store.pool())
    .await
    .expect("seed account memberships");
    store.create_shared_sync_vault(target, other, &[1]).await.expect("target vault");

    let rejected = [73; 16];
    assert!(matches!(
        store.create_shared_sync_vault(rejected, account, &[2]).await,
        Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_vaults WHERE vault_id = ?")
            .bind(rejected.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("rejected vault count"),
        0
    );
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                target,
                account,
                &[SharedVaultKey { epoch: 1, wrapped_vault_key: vec![2] }],
            )
            .await,
        Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
    ));
    assert!(matches!(
        store.get_shared_sync_vault_keys(target, account).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    store
        .create_personal_sync_vault([74; 16], account, &[3])
        .await
        .expect("personal vault is independent");

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn member_quota_rejects_new_member_without_key_rows() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [75; 16];
    store.create_shared_sync_vault(vault, [76; 16], &[1]).await.expect("shared vault");
    sqlx::query(
        "WITH RECURSIVE ids(n) AS (
           SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < ?
         )
         INSERT INTO sync_vault_members (vault_id, account_id, role, key_epoch, wrapped_vault_key)
         SELECT ?, CAST(printf('%016X', n) AS BLOB), 'member', 1, x'01' FROM ids",
    )
    .bind(i64::try_from(MAX_MEMBERS_PER_SHARED_VAULT - 1).expect("test limit"))
    .bind(vault.as_slice())
    .execute(store.pool())
    .await
    .expect("seed members");
    let rejected = [77; 16];
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                vault,
                rejected,
                &[SharedVaultKey { epoch: 1, wrapped_vault_key: vec![2] }],
            )
            .await,
        Err(SyncStoreError::QuotaExceeded("members per shared vault"))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("member count"),
        i64::try_from(MAX_MEMBERS_PER_SHARED_VAULT).expect("test limit")
    );
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, rejected).await,
        Err(SyncStoreError::VaultNotFound)
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn invalid_cardinality_limits_are_rejected_before_opening_sqlite() {
    let directory = test_directory();
    let path = directory.join("scoplen.sqlite");
    for limits in [
        SyncCardinalityLimits { max_objects_per_vault: 0, ..Default::default() },
        SyncCardinalityLimits {
            max_shared_vaults_per_account: i64::MAX as u64 + 1,
            ..Default::default()
        },
        SyncCardinalityLimits {
            max_members_per_shared_vault: MAX_MEMBERS_PER_SHARED_VAULT + 1,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            SqliteStore::open_with_sync_limits(&path, limits).await,
            Err(StoreError::InvalidSyncLimits(_))
        ));
        assert!(!path.exists());
    }
    remove_test_directory(directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn lower_configured_cardinality_limits_reject_atomically_and_allow_updates() {
    let directory = test_directory();
    let limits = SyncCardinalityLimits {
        max_objects_per_vault: 1,
        max_shared_vaults_per_account: 1,
        max_members_per_shared_vault: 1,
    };
    let store = SqliteStore::open_with_sync_limits(&directory.join("scoplen.sqlite"), limits)
        .await
        .expect("open limited store");
    assert_eq!(store.sync_cardinality_limits(), limits);
    let account = [61; 16];
    let vault = [62; 16];
    store.create_shared_sync_vault(vault, account, &[1]).await.expect("first shared vault");
    assert!(matches!(
        store.create_shared_sync_vault([63; 16], account, &[1]).await,
        Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
    ));
    assert!(matches!(store.sync_vault_kind([63; 16]).await, Err(SyncStoreError::VaultNotFound)));
    assert!(matches!(
        store
            .add_shared_sync_vault_member(
                vault,
                [64; 16],
                &[SharedVaultKey { epoch: 1, wrapped_vault_key: vec![2] }],
            )
            .await,
        Err(SyncStoreError::QuotaExceeded("members per shared vault"))
    ));
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, [64; 16]).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    let first = store.write_sync_batch(vault, &[write(1, None, 1)]).await.expect("first object");
    assert!(matches!(
        store.write_sync_batch(vault, &[write(2, None, 2)]).await,
        Err(SyncStoreError::QuotaExceeded("objects per vault"))
    ));
    let updated = store
        .write_sync_batch(vault, &[write(1, Some(first[0].sequence), 3)])
        .await
        .expect("update existing object at the limit");
    assert_eq!(updated[0].sequence, first[0].sequence + 1);
    let changes = store.sync_changes(vault, 0, 10).await.expect("changes");
    assert_eq!(changes.changes.len(), 1);
    assert_eq!(changes.changes[0].sequence, updated[0].sequence);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn above_default_object_and_account_limits_are_enforced_at_configured_values() {
    let directory = test_directory();
    let limits = SyncCardinalityLimits {
        max_objects_per_vault: MAX_OBJECTS_PER_VAULT + 1,
        max_shared_vaults_per_account: MAX_SHARED_VAULTS_PER_ACCOUNT + 1,
        max_members_per_shared_vault: MAX_MEMBERS_PER_SHARED_VAULT,
    };
    let store = SqliteStore::open_with_sync_limits(&directory.join("scoplen.sqlite"), limits)
        .await
        .expect("open raised-limit store");
    let account = [65; 16];
    sqlx::query(
        "WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < ?)
         INSERT INTO sync_vaults (vault_id, kind)
         SELECT CAST(printf('%016X', n) AS BLOB), 'shared' FROM ids",
    )
    .bind(i64::try_from(MAX_SHARED_VAULTS_PER_ACCOUNT).expect("test limit"))
    .execute(store.pool())
    .await
    .expect("seed shared vaults");
    sqlx::query(
        "INSERT INTO sync_vault_members (vault_id, account_id, role, key_epoch, wrapped_vault_key)
         SELECT vault_id, ?, 'member', 1, x'01' FROM sync_vaults WHERE kind = 'shared'",
    )
    .bind(account.as_slice())
    .execute(store.pool())
    .await
    .expect("seed memberships");
    store.create_shared_sync_vault([66; 16], account, &[1]).await.expect("vault above default");
    assert!(matches!(
        store.create_shared_sync_vault([67; 16], account, &[1]).await,
        Err(SyncStoreError::QuotaExceeded("shared vaults per account"))
    ));

    let vault = [68; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("object vault");
    sqlx::query(
        "WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < ?)
         INSERT INTO sync_objects
           (vault_id, object_id, sequence, envelope, tombstone, written_at_ms)
         SELECT ?, CAST(printf('%016X', n) AS BLOB), n, x'01', 1, 0 FROM ids",
    )
    .bind(i64::try_from(MAX_OBJECTS_PER_VAULT).expect("test limit"))
    .bind(vault.as_slice())
    .execute(store.pool())
    .await
    .expect("seed objects");
    sqlx::query("UPDATE sync_vaults SET current_seq = ? WHERE vault_id = ?")
        .bind(i64::try_from(MAX_OBJECTS_PER_VAULT).expect("test limit"))
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("advance sequence");
    store.write_sync_batch(vault, &[write(1, None, 1)]).await.expect("object above default");
    assert!(matches!(
        store.write_sync_batch(vault, &[write(2, None, 2)]).await,
        Err(SyncStoreError::QuotaExceeded("objects per vault"))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT current_seq FROM sync_vaults WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("sequence after rejection"),
        i64::try_from(MAX_OBJECTS_PER_VAULT + 1).expect("test limit")
    );

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn shared_vault_member_removal_cascades_and_marks_rotation() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [31; 16];
    let admin = [32; 16];
    let member = [33; 16];
    store.create_shared_sync_vault(vault, admin, &[1, 2]).await.expect("create shared vault");
    store
        .add_shared_sync_vault_member(
            vault,
            member,
            &[SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3, 4] }],
        )
        .await
        .expect("add member");

    store.remove_shared_sync_vault_member(vault, member).await.expect("remove member");
    assert!(matches!(
        store.get_shared_sync_vault_keys(vault, member).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT rotation_pending FROM sync_vaults WHERE vault_id = ?",
        )
        .bind(vault.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("pending marker"),
        1
    );
    assert!(matches!(
        store.remove_shared_sync_vault_member(vault, member).await,
        Err(SyncStoreError::MemberNotFound)
    ));
    assert!(matches!(
        store.remove_shared_sync_vault_member(vault, admin).await,
        Err(SyncStoreError::LastAdmin)
    ));

    store
        .publish_shared_sync_vault_epoch(
            vault,
            2,
            &[SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![5, 6] }],
        )
        .await
        .expect("publish replacement epoch");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT rotation_pending FROM sync_vaults WHERE vault_id = ?",
        )
        .bind(vault.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("cleared pending marker"),
        0
    );

    let second_member = [34; 16];
    store
        .add_shared_sync_vault_member(
            vault,
            second_member,
            &[
                SharedVaultKey { epoch: 1, wrapped_vault_key: vec![7] },
                SharedVaultKey { epoch: 2, wrapped_vault_key: vec![8] },
            ],
        )
        .await
        .expect("add second member");
    sqlx::query(
        "CREATE TRIGGER reject_sync_vault_pending BEFORE UPDATE OF rotation_pending ON sync_vaults
         BEGIN SELECT RAISE(ABORT, 'injected pending marker failure'); END",
    )
    .execute(store.pool())
    .await
    .expect("install pending marker failure trigger");
    assert!(matches!(
        store.remove_shared_sync_vault_member(vault, second_member).await,
        Err(SyncStoreError::Database(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = ? AND account_id = ?",
        )
        .bind(vault.as_slice())
        .bind(second_member.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("rolled-back member"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_member_keys WHERE vault_id = ? AND account_id = ?",
        )
        .bind(vault.as_slice())
        .bind(second_member.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("rolled-back member keys"),
        2
    );
    sqlx::query("DROP TRIGGER reject_sync_vault_pending")
        .execute(store.pool())
        .await
        .expect("remove pending marker failure trigger");

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
async fn object_quota_counts_tombstones_and_preserves_batch_sequence() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [78; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("initial object");
    sqlx::query(
        "WITH RECURSIVE ids(n) AS (
           SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < ?
         )
         INSERT INTO sync_objects
           (vault_id, object_id, sequence, envelope, tombstone, written_at_ms)
         SELECT ?, CAST(printf('%016X', n) AS BLOB), n + 1, x'01', 1, 0 FROM ids",
    )
    .bind(i64::try_from(MAX_OBJECTS_PER_VAULT - 1).expect("test limit"))
    .bind(vault.as_slice())
    .execute(store.pool())
    .await
    .expect("seed tombstones");
    sqlx::query("UPDATE sync_vaults SET current_seq = ? WHERE vault_id = ?")
        .bind(i64::try_from(MAX_OBJECTS_PER_VAULT).expect("test limit"))
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("advance seeded sequence");

    assert!(matches!(
        store.write_sync_batch(vault, &[write(2, None, 20), write(3, None, 30)]).await,
        Err(SyncStoreError::QuotaExceeded("objects per vault"))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT current_seq FROM sync_vaults WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("unchanged sequence"),
        i64::try_from(MAX_OBJECTS_PER_VAULT).expect("test limit")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sync_objects WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("unchanged object count"),
        i64::try_from(MAX_OBJECTS_PER_VAULT).expect("test limit")
    );
    let updated =
        store.write_sync_batch(vault, &[write(1, Some(1), 40)]).await.expect("update at limit");
    assert_eq!(updated[0].sequence, MAX_OBJECTS_PER_VAULT + 1);
    assert!(matches!(
        store
            .write_sync_batch(vault, &[write(1, Some(updated[0].sequence), 50), write(2, None, 60)])
            .await,
        Err(SyncStoreError::QuotaExceeded("objects per vault"))
    ));

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
