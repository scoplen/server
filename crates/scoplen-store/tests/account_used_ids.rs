// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
mod support;

use scoplen_crypto::account_used_id_digest;
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_used_ids::{
        AccountIdPressure, AccountIdRetentionError as Error, DEFAULT_ACCOUNT_ID_CEILING,
        reserve_sqlite_account_id,
    },
};
use sqlx::QueryBuilder;
use uuid::Uuid;

#[cfg(feature = "postgres-integration")]
use scoplen_store::account_used_ids::reserve_postgres_account_id;

macro_rules! lifecycle {
    ($store:expr, $db:ty, $reserve:ident, $append:path, $postgres:literal) => {{
        let store = &$store;
        assert!(matches!(store.account_id_retention_summary().await, Err(Error::NotInitialized)));
        let mut tx = store.pool().begin().await.expect("uninitialized registration");
        assert!(matches!($reserve(&mut tx, Uuid::now_v7(), 2).await, Err(Error::NotInitialized)));
        tx.rollback().await.expect("no registration before upgrade reservation");
        for invalid in [0, u64::MAX] {
            assert!(matches!(
                store.initialize_account_id_retention(invalid).await,
                Err(Error::InvalidConfiguration)
            ));
        }
        let initialized = store.initialize_account_id_retention(2).await.expect("initialize");
        assert_eq!((initialized.used, initialized.ceiling, initialized.maintenance), (0, 2, false));
        assert_eq!(initialized.pressure, AccountIdPressure::Normal);
        assert_eq!(
            store.initialize_account_id_retention(2).await.expect("same config"),
            initialized
        );
        assert!(matches!(
            store.initialize_account_id_retention(3).await,
            Err(Error::ConfigurationMismatch)
        ));
        for invalid in [Uuid::nil(), Uuid::new_v4()] {
            let mut tx = store.pool().begin().await.expect("invalid registration");
            assert!(matches!(
                $reserve(&mut tx, invalid, 2).await,
                Err(Error::InvalidConfiguration)
            ));
            tx.rollback().await.expect("invalid id cannot consume capacity");
        }
        let old = Uuid::now_v7();
        let mut tx = store.pool().begin().await.expect("transaction");
        $reserve(&mut tx, old, 2).await.expect("staged digest");
        $append(&mut tx, b"owned registration audit", 1).await.expect("staged audit");
        tx.rollback().await.expect("rollback both");
        assert_eq!(store.account_id_retention_summary().await.expect("rollback summary").used, 0);
        assert_eq!(store.deployment_audit_head().await.expect("head").expect("init").sequence, 1);
        for id in [old, Uuid::now_v7()] {
            let mut tx = store.pool().begin().await.expect("transaction");
            $reserve(&mut tx, id, 2).await.expect("new digest");
            $append(&mut tx, b"owned registration audit", 2).await.expect("business audit");
            tx.commit().await.expect("confirmed commit");
        }
        let full = store.account_id_retention_summary().await.expect("full summary");
        assert_eq!((full.used, full.ceiling, full.pressure), (2, 2, AccountIdPressure::Exhausted));
        store.ping().await.expect("retention exhaustion does not affect readiness");
        let mut tx = store.pool().begin().await.expect("transaction");
        assert!(matches!($reserve(&mut tx, old, 2).await, Err(Error::Conflict)));
        tx.rollback().await.expect("rollback conflict");
        let mut tx = store.pool().begin().await.expect("transaction");
        assert!(matches!($reserve(&mut tx, Uuid::now_v7(), 2).await, Err(Error::QuotaExceeded)));
        tx.rollback().await.expect("rollback capacity denial");
        let old_digest = account_used_id_digest(old).unwrap();
        let mut expected =
            QueryBuilder::<$db>::new("SELECT COUNT(*) FROM account_used_ids WHERE digest = ");
        let retained: i64 = expected
            .push_bind(old_digest.as_slice())
            .build_query_scalar()
            .fetch_one(store.pool())
            .await
            .expect("canonical digest");
        assert_eq!(retained, 1);
        assert!(matches!(
            store.increase_account_id_retention_ceiling(2, 3).await,
            Err(Error::Maintenance)
        ));
        store.set_account_id_retention_maintenance(2, true).await.expect("quiesce");
        let mut tx = store.pool().begin().await.expect("transaction");
        assert!(matches!($reserve(&mut tx, Uuid::now_v7(), 2).await, Err(Error::Maintenance)));
        tx.rollback().await.expect("rollback maintenance denial");
        assert!(matches!(
            store.increase_account_id_retention_ceiling(2, 1).await,
            Err(Error::InvalidConfiguration)
        ));
        let raised =
            store.increase_account_id_retention_ceiling(2, 3).await.expect("explicit raise");
        assert_eq!((raised.used, raised.ceiling, raised.maintenance), (2, 3, true));
        assert!(matches!(
            store.initialize_account_id_retention(2).await,
            Err(Error::ConfigurationMismatch)
        ));
        store.set_account_id_retention_maintenance(3, false).await.expect("resume");
        let mut tx = store.pool().begin().await.expect("transaction");
        $reserve(&mut tx, Uuid::now_v7(), 3).await.expect("room after increase");
        $append(&mut tx, b"owned registration audit", 3).await.expect("audit");
        tx.commit().await.expect("commit");
        assert_eq!(store.account_id_retention_summary().await.expect("final summary").used, 3);
        for statement in [
            "UPDATE account_used_ids SET digest=digest",
            "DELETE FROM account_used_ids",
            "DELETE FROM account_id_retention_guard",
            "UPDATE account_id_retention_guard SET row_ceiling=NULL",
            "UPDATE account_id_retention_guard SET row_ceiling=1",
        ] {
            assert!(
                sqlx::query(statement).execute(store.pool()).await.is_err(),
                "retained state guard"
            );
        }
        if $postgres {
            for statement in ["TRUNCATE account_used_ids", "TRUNCATE account_id_retention_guard"] {
                assert!(
                    sqlx::query(statement).execute(store.pool()).await.is_err(),
                    "truncate guard"
                );
            }
        } else {
            assert!(
                sqlx::query("INSERT INTO account_used_ids (digest) VALUES ('01234567890123456789012345678901')")
                    .execute(store.pool())
                    .await
                    .is_err(),
                "SQLite retention admits bytes only"
            );
            assert!(
                sqlx::query(
                    "INSERT OR REPLACE INTO account_id_retention_guard (singleton) VALUES (1)"
                )
                .execute(store.pool())
                .await
                .is_err(),
                "replacement cannot reset the guard"
            );
        }
        assert_eq!(store.account_id_retention_summary().await.expect("preserved summary").used, 3);
    }};
}

macro_rules! upgrade {
    ($store:expr, $db:ty, $reserve:ident, $count:expr) => {{
        let store = &$store;
        let mut ids = Vec::new();
        for _ in 0..$count {
            let id = Uuid::now_v7();
            let mut insert = QueryBuilder::<$db>::new(
                "INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (",
            );
            insert.push_bind(id.as_bytes().as_slice()).push(", ").push_bind(vec![1_u8; 32])
                .push(", ").push_bind(vec![2_u8; 32]).push(", 1)").build()
                .execute(store.pool()).await.expect("owned legacy Account row");
            ids.push(id);
        }
        assert!(matches!(store.initialize_account_id_retention($count - 1).await, Err(Error::QuotaExceeded)));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_used_ids")
            .fetch_one(store.pool()).await.expect("rolled-back digest rows");
        assert_eq!(rows, 0);
        assert!(store.deployment_audit_head().await.expect("rolled-back audit").is_none());
        let summary = store.initialize_account_id_retention($count).await.expect("reserve existing identities");
        assert_eq!((summary.used, summary.ceiling), ($count, $count));
        for id in &ids {
            let expected_digest = account_used_id_digest(*id).unwrap();
            let mut digest = QueryBuilder::<$db>::new("SELECT COUNT(*) FROM account_used_ids WHERE digest = ");
            let count: i64 = digest.push_bind(expected_digest.as_slice())
                .build_query_scalar().fetch_one(store.pool()).await.expect("reserved legacy id");
            assert_eq!(count, 1);
        }
        sqlx::query("DELETE FROM identity_accounts").execute(store.pool()).await.expect("delete owned ordinary Accounts");
        assert_eq!(store.account_id_retention_summary().await.expect("deletion preserves set").used, $count);
        assert_eq!(store.initialize_account_id_retention($count).await.expect("restart admission").used, $count);
        for id in ids {
            let mut tx = store.pool().begin().await.expect("fresh registration transaction");
            assert!(matches!($reserve(&mut tx, id, $count).await, Err(Error::Conflict)));
            tx.rollback().await.expect("old Account cannot be recreated after deletion");
        }
    }};
}

macro_rules! audit_rollback {
    ($store:expr, $db:ty, $create:literal, $remove:literal) => {{
        let store = &$store;
        let id = Uuid::now_v7();
        let mut legacy = QueryBuilder::<$db>::new(
            "INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (",
        );
        legacy.push_bind(id.as_bytes().as_slice()).push(", ").push_bind(vec![1_u8; 32])
            .push(", ").push_bind(vec![2_u8; 32]).push(", 1)").build()
            .execute(store.pool()).await.expect("owned legacy Account before audit failure");
        let mut ddl = store.pool().acquire().await.expect("owned DDL connection");
        sqlx::raw_sql($create).execute(&mut *ddl).await.expect("inject audit failure");
        assert!(matches!(store.initialize_account_id_retention(10).await, Err(Error::Audit(_))));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_used_ids")
            .fetch_one(store.pool())
            .await
            .expect("no retained rows");
        assert_eq!(count, 0);
        assert!(matches!(store.account_id_retention_summary().await, Err(Error::NotInitialized)));
        sqlx::raw_sql($remove).execute(&mut *ddl).await.expect("remove audit failure");
        assert_eq!(store.initialize_account_id_retention(10).await.expect("initialize after rollback").used, 1);
        store.set_account_id_retention_maintenance(10, true).await.expect("quiesce");
        sqlx::raw_sql($create).execute(&mut *ddl).await.expect("inject maintenance audit failure");
        assert!(matches!(
            store.increase_account_id_retention_ceiling(10, 20).await,
            Err(Error::Audit(_))
        ));
        assert!(matches!(
            store.set_account_id_retention_maintenance(10, false).await,
            Err(Error::Audit(_))
        ));
        let summary =
            store.account_id_retention_summary().await.expect("rolled-back control state");
        assert_eq!((summary.used, summary.ceiling, summary.maintenance), (1, 10, true));
        sqlx::raw_sql($remove).execute(&mut *ddl).await.expect("remove maintenance fault");
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("head")
                .expect("init and maintenance")
                .sequence,
            2
        );
    }};
}

async fn sqlite_fixture() -> (std::path::PathBuf, SqliteStore) {
    let directory = std::env::temp_dir().join(format!("scoplen-used-accounts-{}", Uuid::now_v7()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("SQLite store");
    (directory, store)
}

#[tokio::test]
async fn sqlite_retention_is_atomic_bounded_immutable_and_explicitly_maintained() {
    let (directory, store) = sqlite_fixture().await;
    lifecycle!(
        store,
        sqlx::Sqlite,
        reserve_sqlite_account_id,
        scoplen_store::append_deployment_audit_event_in_transaction,
        false
    );
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_upgrade_reserves_every_current_account_in_bounded_pages() {
    let (directory, store) = sqlite_fixture().await;
    upgrade!(store, sqlx::Sqlite, reserve_sqlite_account_id, 300_u64);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_forward_upgrade_preserves_legacy_account_before_explicit_reservation() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-used-id-upgrade-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&directory).expect("owned fixture directory");
    let path = directory.join("store.sqlite");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(&path).create_if_missing(true),
        )
        .await
        .expect("previous SQLite database");
    let mut migrations = sqlx::migrate!("./migrations/sqlite");
    migrations.migrations.to_mut().retain(|migration| migration.version < 20_261_025_040_000);
    migrations.run(&pool).await.expect("previous migration history");
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, ?, ?, 1)")
        .bind(id.as_bytes().as_slice()).bind(vec![1_u8; 32]).bind(vec![2_u8; 32])
        .execute(&pool).await.expect("owned legacy Account");
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward upgrade");
    assert!(matches!(store.account_id_retention_summary().await, Err(Error::NotInitialized)));
    let preserved: Vec<u8> = sqlx::query_scalar("SELECT account_id FROM identity_accounts")
        .fetch_one(store.pool())
        .await
        .expect("legacy identity preserved");
    assert_eq!(preserved.as_slice(), id.as_bytes());
    assert_eq!(
        store.initialize_account_id_retention(1).await.expect("reserve upgraded Account").used,
        1
    );
    let mut tx = store.pool().begin().await.expect("fresh registration");
    assert!(matches!(reserve_sqlite_account_id(&mut tx, id, 1).await, Err(Error::Conflict)));
    tx.rollback().await.expect("existing Account denied");
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_retention_initialization_and_maintenance_require_atomic_audit() {
    let (directory, store) = sqlite_fixture().await;
    audit_rollback!(
        store,
        sqlx::Sqlite,
        "CREATE TRIGGER fail_retention_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
        "DROP TRIGGER fail_retention_audit"
    );
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_competing_instances_serialize_the_final_slot_and_backup_preserves_it() {
    let (directory, store) = sqlite_fixture().await;
    let second = SqliteStore::open(&directory.join("store.sqlite")).await.expect("second pool");
    store.initialize_account_id_retention(1).await.expect("one slot");
    let mut tasks = Vec::new();
    for instance in [store.clone(), second.clone()] {
        tasks.push(tokio::spawn(async move {
            let id = Uuid::now_v7();
            let mut tx = instance.pool().begin().await?;
            reserve_sqlite_account_id(&mut tx, id, 1).await?;
            scoplen_store::append_deployment_audit_event_in_transaction(
                &mut tx,
                b"owned registration",
                1,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, Error>(id)
        }));
    }
    let mut retained_ids = Vec::new();
    let mut denials = 0;
    for task in tasks {
        match task.await.expect("writer") {
            Ok(id) => retained_ids.push(id),
            Err(Error::QuotaExceeded) => denials += 1,
            error => panic!("unexpected final-slot result: {error:?}"),
        }
    }
    assert_eq!((retained_ids.len(), denials), (1, 1));
    let backup = directory.join("backup.sqlite");
    sqlx::query("VACUUM main INTO ?")
        .bind(backup.to_str().expect("backup path"))
        .execute(store.pool())
        .await
        .expect("consistent full backup");
    second.pool().close().await;
    store.pool().close().await;
    let restored = SqliteStore::open(&backup).await.expect("restore complete database");
    let summary = restored.initialize_account_id_retention(1).await.expect("retained budget");
    assert_eq!((summary.used, summary.pressure), (1, AccountIdPressure::Exhausted));
    assert_eq!(
        restored.deployment_audit_head().await.expect("audit").expect("two events").sequence,
        2
    );
    let mut tx = restored.pool().begin().await.expect("restored registration transaction");
    assert!(matches!(
        reserve_sqlite_account_id(&mut tx, retained_ids[0], 1).await,
        Err(Error::Conflict)
    ));
    tx.rollback().await.expect("restore preserves identity reuse denial");
    restored.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_legacy_non_blob_ids_cannot_be_skipped_by_upgrade_pagination() {
    let (directory, store) = sqlite_fixture().await;
    for value in ["'0123456789012345'", "1234567890123456"] {
        sqlx::query(&format!(
            "INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES ({value}, ?, ?, 1)"
        ))
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 32])
        .execute(store.pool())
        .await
        .expect("legacy SQLite affinity permits a non-blob id");
        assert!(matches!(store.initialize_account_id_retention(10).await, Err(Error::Integrity)));
        assert!(matches!(store.account_id_retention_summary().await, Err(Error::NotInitialized)));
        assert!(store.deployment_audit_head().await.expect("no partial audit").is_none());
        sqlx::query("DELETE FROM identity_accounts")
            .execute(store.pool())
            .await
            .expect("remove owned unsupported legacy fixture");
    }
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_pressure_and_invalid_legacy_identity_fail_without_partial_initialization() {
    let (directory, store) = sqlite_fixture().await;
    sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, ?, ?, 1)")
        .bind(Uuid::new_v4().as_bytes().as_slice()).bind(vec![1_u8; 32]).bind(vec![2_u8; 32])
        .execute(store.pool()).await.expect("owned unsupported legacy identity");
    assert!(matches!(store.initialize_account_id_retention(10).await, Err(Error::Integrity)));
    assert!(store.deployment_audit_head().await.expect("no partial audit").is_none());
    sqlx::query("DELETE FROM identity_accounts")
        .execute(store.pool())
        .await
        .expect("remove owned failure fixture");
    store.initialize_account_id_retention(10).await.expect("valid initialization");
    for _ in 0..9 {
        let mut tx = store.pool().begin().await.expect("writer");
        reserve_sqlite_account_id(&mut tx, Uuid::now_v7(), 10).await.expect("reserve");
        scoplen_store::append_deployment_audit_event_in_transaction(
            &mut tx,
            b"owned registration",
            1,
        )
        .await
        .expect("audit");
        tx.commit().await.expect("commit");
    }
    assert_eq!(
        store.account_id_retention_summary().await.expect("pressure").pressure,
        AccountIdPressure::Warning
    );
    assert_eq!(DEFAULT_ACCOUNT_ID_CEILING, 1_048_576);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (String, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("used_accounts_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    (url.to_string(), pool, schema)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(pool: sqlx::PgPool, schema: String) {
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_is_atomic_bounded_immutable_and_explicitly_maintained() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    lifecycle!(
        store,
        sqlx::Postgres,
        reserve_postgres_account_id,
        scoplen_store::append_deployment_audit_event_in_postgres_transaction,
        true
    );
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_upgrade_reserves_every_current_account_in_bounded_pages() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    upgrade!(store, sqlx::Postgres, reserve_postgres_account_id, 300_u64);
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_initialization_and_maintenance_require_atomic_audit() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    audit_rollback!(
        store,
        sqlx::Postgres,
        "CREATE FUNCTION fail_retention_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''audit unavailable''; END'; CREATE TRIGGER fail_retention_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_retention_audit()",
        "DROP TRIGGER fail_retention_audit ON deployment_audit_events; DROP FUNCTION fail_retention_audit()"
    );
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_competing_instances_serialize_the_final_slot() {
    let (url, pool, schema) = postgres_fixture().await;
    let first = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    let second = scoplen_store::PostgresStore::connect(&url).await.expect("second pool");
    first.initialize_account_id_retention(1).await.expect("one slot");
    let mut tasks = Vec::new();
    for instance in [first.clone(), second.clone()] {
        tasks.push(tokio::spawn(async move {
            let mut tx = instance.pool().begin().await?;
            reserve_postgres_account_id(&mut tx, Uuid::now_v7(), 1).await?;
            scoplen_store::append_deployment_audit_event_in_postgres_transaction(
                &mut tx,
                b"owned registration",
                1,
            )
            .await?;
            tx.commit().await?;
            Ok::<_, Error>(())
        }));
    }
    let results = [tasks.remove(0).await.expect("first"), tasks.remove(0).await.expect("second")];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|result| matches!(result, Err(Error::QuotaExceeded))).count(),
        1
    );
    first.pool().close().await;
    second.pool().close().await;
    let reopened = scoplen_store::PostgresStore::connect(&url).await.expect("restart");
    assert_eq!(
        reopened.initialize_account_id_retention(1).await.expect("retained ceiling").used,
        1
    );
    reopened.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_stale_repeatable_snapshots_cannot_overbook_the_final_slot() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    for isolation in ["REPEATABLE READ", "SERIALIZABLE"] {
        let ceiling = if isolation == "REPEATABLE READ" { 1 } else { 2 };
        if ceiling == 1 {
            store.initialize_account_id_retention(ceiling).await.expect("one slot");
        } else {
            store.set_account_id_retention_maintenance(1, true).await.expect("quiesce");
            store.increase_account_id_retention_ceiling(1, ceiling).await.expect("one more slot");
            store.set_account_id_retention_maintenance(ceiling, false).await.expect("resume");
        }
        let mut current = store.pool().begin().await.expect("current writer");
        let mut stale = store.pool().begin().await.expect("old snapshot writer");
        for tx in [&mut current, &mut stale] {
            sqlx::query(&format!("SET TRANSACTION ISOLATION LEVEL {isolation}"))
                .execute(&mut **tx)
                .await
                .expect("explicit stronger isolation");
            let used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_used_ids")
                .fetch_one(&mut **tx)
                .await
                .expect("pin snapshot before either writer");
            assert_eq!(used, i64::try_from(ceiling - 1).unwrap());
        }
        reserve_postgres_account_id(&mut current, Uuid::now_v7(), ceiling)
            .await
            .expect("reserve final slot");
        scoplen_store::append_deployment_audit_event_in_postgres_transaction(
            &mut current,
            b"owned registration",
            1,
        )
        .await
        .expect("atomic audit");
        current.commit().await.expect("first writer committed");
        let result = reserve_postgres_account_id(&mut stale, Uuid::now_v7(), ceiling).await;
        assert!(matches!(
            result,
            Err(Error::Storage(sqlx::Error::Database(error)))
                if error.code().as_deref() == Some("40001")
        ));
        stale.rollback().await.expect("discard stale snapshot");
        let summary = store.account_id_retention_summary().await.expect("preserved limit");
        assert_eq!((summary.used, summary.ceiling), (ceiling, ceiling));
    }
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_unknown_initialization_and_maintenance_commits_return_no_confirmation() {
    use std::sync::atomic::Ordering;
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    let proxy = lost_commit::LostCommitProxy::start(&url).await;
    let uncertain =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain.initialize_account_id_retention(10).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(
        store.account_id_retention_summary().await.expect("committed initialization").ceiling,
        10
    );
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain.set_account_id_retention_maintenance(10, true).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert!(store.account_id_retention_summary().await.expect("committed maintenance").maintenance);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain.increase_account_id_retention_ceiling(10, 20).await,
        Err(Error::CommitOutcomeUnknown)
    ));
    assert_eq!(store.account_id_retention_summary().await.expect("committed increase").ceiling, 20);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    uncertain.pool().close().await;
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}
