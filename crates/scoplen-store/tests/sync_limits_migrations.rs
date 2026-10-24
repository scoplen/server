// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_api::sync::SyncWriteLimits;
use scoplen_store::{RelationalStore, SqliteStore, sync::SyncCardinalityLimits};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use uuid::Uuid;

const NEW_MIGRATION: i64 = 20_261_024_040_000;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_sync_limit_forward_migration_preserves_populated_tables_and_constraints() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-limits-migration-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("isolated directory");
    let file = directory.join("scoplen.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new().filename(&file).create_if_missing(true).foreign_keys(true),
        )
        .await
        .expect("pre-migration pool");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("all historical migrations");
    let vault = Uuid::now_v7().into_bytes();
    let object = Uuid::now_v7().into_bytes();
    let signer = Uuid::now_v7().into_bytes();
    sqlx::query("INSERT INTO sync_vaults (vault_id, kind, current_seq) VALUES (?, 'personal', 2)")
        .bind(vault.as_slice())
        .execute(&pool)
        .await
        .expect("seed vault");
    for table in ["sync_objects", "sync_object_versions"] {
        sqlx::query(&format!("INSERT INTO {table} (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch) VALUES (?, ?, 2, ?, 1, ?, 123456, 7)"))
            .bind(vault.as_slice()).bind(object.as_slice()).bind(vec![5_u8; 266_240])
            .bind(signer.as_slice()).execute(&pool).await.expect("seed current and history");
    }
    sqlx::query("INSERT INTO sync_object_versions (vault_id, object_id, sequence, envelope, tombstone, written_at_ms, key_epoch) VALUES (?, ?, 1, ?, 0, 123455, 3)")
        .bind(vault.as_slice()).bind(object.as_slice()).bind(vec![4_u8; 256])
        .execute(&pool).await.expect("seed previous version");
    pool.close().await;
    let limits = SyncWriteLimits { max_envelope_bytes: 266_241, ..Default::default() };
    let store = SqliteStore::open_with_sync_limits(&file, SyncCardinalityLimits::default(), limits)
        .await
        .expect("apply new migration to populated database");
    let row = sqlx::query("SELECT * FROM sync_objects WHERE vault_id = ? AND object_id = ?")
        .bind(vault.as_slice())
        .bind(object.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("preserved object");
    assert_eq!(row.get::<Vec<u8>, _>("envelope"), vec![5; 266_240]);
    assert_eq!(row.get::<Vec<u8>, _>("signer_device_id"), signer);
    assert_eq!(row.get::<i64, _>("written_at_ms"), 123_456);
    assert_eq!(row.get::<i64, _>("key_epoch"), 7);
    assert_eq!(row.get::<i64, _>("tombstone"), 1);
    let versions = store.sync_versions(vault, object).await.expect("preserved history");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions.iter().map(|version| version.key_epoch).collect::<Vec<_>>(), vec![3, 7]);
    let indexes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('sync_objects_by_vault_sequence', 'sync_versions_by_vault_sequence')")
        .fetch_one(store.pool()).await.expect("preserved named indexes");
    assert_eq!(indexes, 2);
    for table in ["sync_objects", "sync_object_versions"] {
        for assignment in [
            "envelope = X''",
            "key_epoch = 0",
            "sequence = 0",
            "object_id = X'00'",
            "signer_device_id = X'00'",
            "tombstone = 2",
            "written_at_ms = -1",
        ] {
            assert!(
                sqlx::query(&format!("UPDATE {table} SET {assignment} WHERE vault_id = ?"))
                    .bind(vault.as_slice())
                    .execute(store.pool())
                    .await
                    .is_err(),
                "{table}: {assignment}"
            );
        }
        assert!(
            sqlx::query(&format!("UPDATE {table} SET vault_id = ? WHERE vault_id = ?"))
                .bind(Uuid::now_v7().as_bytes().as_slice())
                .bind(vault.as_slice())
                .execute(store.pool())
                .await
                .is_err(),
            "foreign key remains enforced"
        );
        sqlx::query(&format!(
            "UPDATE {table} SET envelope = ? WHERE vault_id = ? AND sequence = 2"
        ))
        .bind(vec![6_u8; 266_241])
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("fixed default ceiling was removed");
        assert!(
            sqlx::query(&format!("INSERT INTO {table} SELECT * FROM {table} WHERE vault_id = ?"))
                .bind(vault.as_slice())
                .execute(store.pool())
                .await
                .is_err(),
            "uniqueness remains enforced"
        );
    }
    assert_eq!(store.sync_changes(vault, 0, 10).await.expect("unchanged sequence").next_cursor, 2);
    store.pool().close().await;
    drop(store);
    let reopened = SqliteStore::open(&file).await.expect("migration replay");
    assert_eq!(
        reopened.sync_versions(vault, object).await.expect("retained larger history")[1]
            .envelope
            .len(),
        266_241
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(reopened.pool())
            .await
            .expect("foreign-key integrity"),
        0
    );
    sqlx::query("DELETE FROM sync_vaults WHERE vault_id = ?")
        .bind(vault.as_slice())
        .execute(reopened.pool())
        .await
        .expect("test cascade");
    for table in ["sync_objects", "sync_object_versions"] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(reopened.pool())
                .await
                .expect("cascade leaves no rows"),
            0
        );
    }
    reopened.pool().close().await;
    drop(reopened);
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_sync_limit_forward_migration_preserves_populated_tables_and_constraints() {
    use scoplen_store::PostgresStore;
    let database_url =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("isolated PostgreSQL test database");
    let admin = sqlx::PgPool::connect(&database_url).await.expect("test database");
    let schema = format!("scoplen_limits_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .expect("isolated migration schema");
    let mut scoped = url::Url::parse(&database_url).expect("test database URL");
    scoped.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(scoped.as_str()).await.expect("scoped pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("historical PostgreSQL migrations");
    let vault = Uuid::now_v7().into_bytes();
    let object = Uuid::now_v7().into_bytes();
    let signer = Uuid::now_v7().into_bytes();
    sqlx::query("INSERT INTO sync_vaults (vault_id, kind, current_seq) VALUES ($1, 'personal', 2)")
        .bind(vault.as_slice())
        .execute(&pool)
        .await
        .expect("seed vault");
    for table in ["sync_objects", "sync_object_versions"] {
        sqlx::query(&format!("INSERT INTO {table} (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch) VALUES ($1, $2, 2, $3, TRUE, $4, 123456, 7)"))
            .bind(vault.as_slice()).bind(object.as_slice()).bind(vec![5_u8; 266_240])
            .bind(signer.as_slice()).execute(&pool).await.expect("seed current and history");
    }
    sqlx::query("INSERT INTO sync_object_versions (vault_id, object_id, sequence, envelope, tombstone, written_at_ms, key_epoch) VALUES ($1, $2, 1, $3, FALSE, 123455, 3)")
        .bind(vault.as_slice()).bind(object.as_slice()).bind(vec![4_u8; 256])
        .execute(&pool).await.expect("seed previous version");
    pool.close().await;
    let store = PostgresStore::connect_with_sync_limits(
        scoped.as_str(),
        SyncCardinalityLimits::default(),
        SyncWriteLimits { max_envelope_bytes: 266_241, ..Default::default() },
    )
    .await
    .expect("forward migration on populated PostgreSQL");
    let row = sqlx::query("SELECT * FROM sync_objects WHERE vault_id = $1 AND object_id = $2")
        .bind(vault.as_slice())
        .bind(object.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("preserved object");
    assert_eq!(row.get::<Vec<u8>, _>("envelope"), vec![5; 266_240]);
    assert_eq!(row.get::<Vec<u8>, _>("signer_device_id"), signer);
    assert_eq!(row.get::<i64, _>("written_at_ms"), 123_456);
    assert_eq!(row.get::<i64, _>("key_epoch"), 7);
    assert!(row.get::<bool, _>("tombstone"));
    let versions = store.sync_versions(vault, object).await.expect("preserved history");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions.iter().map(|version| version.key_epoch).collect::<Vec<_>>(), vec![3, 7]);
    let indexes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname IN ('sync_objects_by_vault_sequence', 'sync_versions_by_vault_sequence')")
        .fetch_one(store.pool()).await.expect("preserved named indexes");
    assert_eq!(indexes, 2);
    for table in ["sync_objects", "sync_object_versions"] {
        for assignment in [
            "envelope = ''::bytea",
            "key_epoch = 0",
            "sequence = 0",
            "object_id = decode('00', 'hex')",
            "signer_device_id = decode('00', 'hex')",
            "written_at_ms = -1",
        ] {
            assert!(
                sqlx::query(&format!("UPDATE {table} SET {assignment} WHERE vault_id = $1"))
                    .bind(vault.as_slice())
                    .execute(store.pool())
                    .await
                    .is_err(),
                "{table}: {assignment}"
            );
        }
        assert!(
            sqlx::query(&format!("UPDATE {table} SET vault_id = $1 WHERE vault_id = $2"))
                .bind(Uuid::now_v7().as_bytes().as_slice())
                .bind(vault.as_slice())
                .execute(store.pool())
                .await
                .is_err(),
            "foreign key remains enforced"
        );
        sqlx::query(&format!(
            "UPDATE {table} SET envelope = $1 WHERE vault_id = $2 AND sequence = 2"
        ))
        .bind(vec![6_u8; 266_241])
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("raised envelope persisted");
        assert!(
            sqlx::query(&format!("INSERT INTO {table} SELECT * FROM {table} WHERE vault_id = $1"))
                .bind(vault.as_slice())
                .execute(store.pool())
                .await
                .is_err(),
            "uniqueness remains enforced"
        );
    }
    store.pool().close().await;
    drop(store);
    let reopened = PostgresStore::connect(scoped.as_str()).await.expect("migration replay");
    assert_eq!(
        reopened.sync_versions(vault, object).await.expect("retained larger history")[1]
            .envelope
            .len(),
        266_241
    );
    sqlx::query("DELETE FROM sync_vaults WHERE vault_id = $1")
        .bind(vault.as_slice())
        .execute(reopened.pool())
        .await
        .expect("test cascade");
    for table in ["sync_objects", "sync_object_versions"] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(reopened.pool())
                .await
                .expect("cascade leaves no rows"),
            0
        );
    }
    reopened.pool().close().await;
    drop(reopened);
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove isolated schema");
    admin.close().await;
}
