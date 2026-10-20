// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use support::remove_test_directory;

use std::path::PathBuf;

use scoplen_store::{RelationalStore, SqliteStore, StoreError};
use sqlx::Row;

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-store-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create isolated test directory");
    path
}

#[tokio::test]
async fn migration_is_idempotent_and_sqlite_uses_wal() {
    let directory = test_directory();
    let database = directory.join("nested").join("scoplen.sqlite");
    let store = SqliteStore::open(&database).await.expect("open and migrate database");
    store.ping().await.expect("database is ready");

    let mut connection = store.pool().acquire().await.expect("acquire database connection");
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .persistent(false)
        .fetch_one(&mut *connection)
        .await
        .expect("read journal mode");
    assert_eq!(journal_mode, "wal");
    drop(connection);
    let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(store.pool())
        .await
        .expect("migration history exists");
    assert!(migration_count >= 2);
    store.pool().close().await;
    drop(store);

    let reopened = SqliteStore::open(&database).await.expect("reopen migrated database");
    let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(reopened.pool())
        .await
        .expect("migration remains applied once");
    assert!(migration_count >= 2);
    reopened.pool().close().await;
    drop(reopened);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn transaction_rollback_preserves_data_and_commit_survives_reopen() {
    let directory = test_directory();
    let database = directory.join("scoplen.sqlite");
    let store = SqliteStore::open(&database).await.expect("open database");
    let organization_id = [7_u8; 16];

    let mut transaction = store.pool().begin().await.expect("begin transaction");
    sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, ?)")
        .bind(organization_id.as_slice())
        .bind("Operations")
        .bind(1_000_i64)
        .execute(&mut *transaction)
        .await
        .expect("insert inside transaction");
    transaction.rollback().await.expect("rollback transaction");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organizations")
        .fetch_one(store.pool())
        .await
        .expect("query after rollback");
    assert_eq!(count, 0);

    let mut transaction = store.pool().begin().await.expect("begin transaction");
    sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, ?)")
        .bind(organization_id.as_slice())
        .bind("Operations")
        .bind(1_000_i64)
        .execute(&mut *transaction)
        .await
        .expect("insert inside transaction");
    transaction.commit().await.expect("commit transaction");
    store.pool().close().await;
    drop(store);

    let reopened = SqliteStore::open(&database).await.expect("reopen database");
    let row = sqlx::query("SELECT name, created_at_ms FROM organizations WHERE id = ?")
        .bind(organization_id.as_slice())
        .fetch_one(reopened.pool())
        .await
        .expect("committed row survived reopen");
    assert_eq!(row.get::<String, _>("name"), "Operations");
    assert_eq!(row.get::<i64, _>("created_at_ms"), 1_000);
    drop(row);

    let duplicate =
        sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, ?)")
            .bind(organization_id.as_slice())
            .bind("Duplicate")
            .bind(2_000_i64)
            .execute(reopened.pool())
            .await;
    assert!(duplicate.is_err(), "duplicate identifier must fail");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organizations")
        .fetch_one(reopened.pool())
        .await
        .expect("query after rejected write");
    assert_eq!(count, 1);

    reopened.pool().close().await;
    drop(reopened);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn invalid_paths_and_schema_constraints_fail_closed() {
    assert!(matches!(
        SqliteStore::open(PathBuf::new().as_path()).await,
        Err(StoreError::EmptyPath)
    ));

    let directory = test_directory();
    let parent_file = directory.join("not-a-directory");
    std::fs::write(&parent_file, "occupied").expect("create parent file");
    let error = SqliteStore::open(&parent_file.join("scoplen.sqlite"))
        .await
        .err()
        .expect("non-directory parent must fail");
    assert!(matches!(error, StoreError::CreateDirectory(_)));

    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open database");
    for (id, name, timestamp) in [
        (vec![1_u8; 15], "Valid", 1_i64),
        (vec![2_u8; 16], "", 1_i64),
        (vec![3_u8; 16], "Valid", -1_i64),
    ] {
        let result =
            sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, ?)")
                .bind(id)
                .bind(name)
                .bind(timestamp)
                .execute(store.pool())
                .await;
        assert!(result.is_err(), "invalid organization row must be rejected");
    }
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn migration_checksum_mismatch_prevents_open() {
    let directory = test_directory();
    let database = directory.join("scoplen.sqlite");
    let store = SqliteStore::open(&database).await.expect("open database");
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00'")
        .execute(store.pool())
        .await
        .expect("corrupt migration history for failure test");
    store.pool().close().await;
    drop(store);

    let result = SqliteStore::open(&database).await;
    assert!(matches!(result, Err(StoreError::Migration(_))));
    remove_test_directory(directory).await;
}
