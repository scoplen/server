// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore, SqliteStore};

const NEW_MIGRATION: i64 = 20_261_025_000_000;

macro_rules! populate {
    ($pool:expr) => {{
        sqlx::query("INSERT INTO sync_vaults (vault_id,kind,current_seq) VALUES ($1,'personal',1)")
            .bind([1_u8;16].as_slice()).execute($pool).await.expect("populated vault");
        for table in ["sync_objects","sync_object_versions"] {
            sqlx::query(&format!("INSERT INTO {table} (vault_id,object_id,sequence,envelope,tombstone,written_at_ms,key_epoch) VALUES ($1,$2,1,$3,$4,123,7)"))
                .bind([1_u8;16].as_slice()).bind([2_u8;16].as_slice()).bind([3_u8;32].as_slice()).bind(true)
                .execute($pool).await.expect("populated object/history");
        }
        sqlx::query("INSERT INTO sync_acks (vault_id,device_id,cursor,acknowledged_at_ms) VALUES ($1,$2,1,123)")
            .bind([1_u8;16].as_slice()).bind([4_u8;16].as_slice()).execute($pool).await.expect("populated ACK");
    }};
}

macro_rules! upgraded {
    ($store:expr) => {{
        let store=&$store;
        assert_eq!(store.sync_changes([1;16],0,10).await.expect("retained changes").next_cursor,1);
        let versions=store.sync_versions([1;16],[2;16]).await.expect("retained history");
        assert_eq!(versions.len(),1);
        assert_eq!(versions[0].envelope,vec![3;32]);
        assert_eq!(versions[0].key_epoch,7);
        let ack:(i64,i64)=sqlx::query_as("SELECT cursor,acknowledged_at_ms FROM sync_acks").fetch_one(store.pool()).await.expect("retained ACK");
        assert_eq!(ack,(1,123));
        let clock:Vec<u8>=sqlx::query_scalar("SELECT retired_through_ns FROM sync_write_admission_clock WHERE singleton=1")
            .fetch_one(store.pool()).await.expect("initialized watermark");
        assert_eq!(clock,vec![0;16]);
        let max=scoplen_store::sync_write_admission::WriteRateLimits::new(u64::MAX,u64::MAX).expect("full unsigned range");
        store.admit_sync_write([4;16],max).await.expect("new durable operation");
        for value in [vec![0;8],vec![1;7]] {
            assert!(sqlx::query("UPDATE sync_write_admission SET requests_per_second=$1 WHERE device_id=$2")
                .bind(value).bind([4_u8;16].as_slice()).execute(store.pool()).await.is_err(),"positive fixed-width rate constraint");
        }
        assert!(sqlx::query("INSERT INTO sync_write_admission_clock (singleton,retired_through_ns) VALUES (2,$1)")
            .bind([0_u8;16].as_slice()).execute(store.pool()).await.is_err(),"one clock row only");
    }};
}

#[tokio::test]
async fn sqlite_sync_write_admission_upgrade_preserves_populated_store() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let directory =
        std::env::temp_dir().join(format!("scoplen-rate-migration-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("owned directory");
    let path = directory.join("scoplen.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new().filename(&path).create_if_missing(true).foreign_keys(true),
        )
        .await
        .expect("old pool");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("historical schema");
    populate!(&pool);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    upgraded!(store);
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("already migrated reopen");
    let balance: Vec<u8> = sqlx::query_scalar("SELECT burst FROM sync_write_admission")
        .fetch_one(reopened.pool())
        .await
        .expect("preserved unsigned bucket");
    assert_eq!(balance, u64::MAX.to_be_bytes());
    reopened.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_sync_write_admission_upgrade_preserves_populated_store() {
    use scoplen_store::PostgresStore;
    let database =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("disposable PostgreSQL fixture");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin pool");
    let schema = format!("rate_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("historical schema");
    populate!(&pool);
    pool.close().await;
    let store = PostgresStore::connect(url.as_str()).await.expect("forward migration");
    upgraded!(store);
    store.pool().close().await;
    let reopened = PostgresStore::connect(url.as_str()).await.expect("reopen");
    let balance: Vec<u8> = sqlx::query_scalar("SELECT burst FROM sync_write_admission")
        .fetch_one(reopened.pool())
        .await
        .expect("retained bucket");
    assert_eq!(balance, u64::MAX.to_be_bytes());
    reopened.pool().close().await;
    assert!(
        schema.starts_with("rate_migration_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
