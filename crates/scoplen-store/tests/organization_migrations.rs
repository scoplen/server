// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore, SqliteStore};

const NEW_MIGRATION: i64 = 20_261_026_000_000;

macro_rules! populate {
    ($pool:expr) => {{
        sqlx::query("INSERT INTO organizations (id,name,created_at_ms) VALUES ($1,'Existing team',1)")
            .bind([1_u8;16].as_slice()).execute($pool).await.expect("existing organization");
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
            .bind([2_u8;16].as_slice()).bind([3_u8;32].as_slice()).execute($pool).await.expect("existing Account");
        sqlx::query("INSERT INTO sync_vaults (vault_id,kind,current_seq) VALUES ($1,'personal',1)")
            .bind([4_u8;16].as_slice()).execute($pool).await.expect("existing Personal vault");
        sqlx::query("INSERT INTO sync_acks (vault_id,device_id,cursor,acknowledged_at_ms) VALUES ($1,$2,1,123)")
            .bind([4_u8;16].as_slice()).bind([5_u8;16].as_slice()).execute($pool).await.expect("existing ACK");
    }};
}

macro_rules! upgraded {
    ($store:expr) => {{
        let store=&$store;
        let name:String=sqlx::query_scalar("SELECT name FROM organizations WHERE id=$1")
            .bind([1_u8;16].as_slice()).fetch_one(store.pool()).await.expect("preserved organization");
        assert_eq!(name,"Existing team");
        let public:Vec<u8>=sqlx::query_scalar("SELECT account_signing_public_key FROM identity_accounts WHERE account_id=$1")
            .bind([2_u8;16].as_slice()).fetch_one(store.pool()).await.expect("preserved Account");
        assert_eq!(public,[3;32]);
        let ack:(i64,i64)=sqlx::query_as("SELECT cursor,acknowledged_at_ms FROM sync_acks")
            .fetch_one(store.pool()).await.expect("preserved Personal ACK");
        assert_eq!(ack,(1,123));
        let memberships:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_memberships")
            .fetch_one(store.pool()).await.expect("no invented memberships");
        assert_eq!(memberships,0);
        sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',1,1)")
            .bind([6_u8;16].as_slice()).bind([1_u8;16].as_slice()).bind([2_u8;16].as_slice())
            .execute(store.pool()).await.expect("new membership");
        assert!(sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',1,1)")
            .bind([7_u8;16].as_slice()).bind([1_u8;16].as_slice()).bind([2_u8;16].as_slice())
            .execute(store.pool()).await.is_err(),"unique team/Account binding");
        assert!(sqlx::query("UPDATE organization_memberships SET status='unsupported'")
            .execute(store.pool()).await.is_err(),"bounded membership status");
        assert!(sqlx::query("UPDATE organization_memberships SET account_id=$1")
            .bind([9_u8;16].as_slice()).execute(store.pool()).await.is_err(),"Account foreign key");
        let sql="INSERT INTO organization_creation_receipts (account_id,idempotency_key,organization_id,request_digest,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,1,$5)";
        assert!(sqlx::query(sql).bind([2_u8;16].as_slice()).bind([8_u8;16].as_slice())
            .bind([1_u8;16].as_slice()).bind([9_u8;32].as_slice()).bind(86_400_000_i64)
            .execute(store.pool()).await.is_err(),"exact 24-hour lifetime");
        sqlx::query(sql).bind([2_u8;16].as_slice()).bind([8_u8;16].as_slice())
            .bind([1_u8;16].as_slice()).bind([9_u8;32].as_slice()).bind(86_400_001_i64)
            .execute(store.pool()).await.expect("valid receipt");
    }};
}

#[tokio::test]
async fn sqlite_team_upgrade_preserves_existing_account_and_personal_state() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let directory =
        std::env::temp_dir().join(format!("scoplen-team-migration-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("owned directory");
    let path = directory.join("scoplen.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new().filename(&path).create_if_missing(true).foreign_keys(true),
        )
        .await
        .expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("historical schema");
    populate!(&pool);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    upgraded!(store);
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("idempotent reopen");
    let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_creation_receipts")
        .fetch_one(reopened.pool())
        .await
        .expect("persisted receipt");
    assert_eq!(receipts, 1);
    reopened.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_upgrade_preserves_existing_account_and_personal_state() {
    use scoplen_store::PostgresStore;
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let admin = sqlx::PgPool::connect(&database).await.expect("schema administration");
    let schema = format!("team_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
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
    let reopened = PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_creation_receipts")
        .fetch_one(reopened.pool())
        .await
        .expect("persisted receipt");
    assert_eq!(receipts, 1);
    reopened.pool().close().await;
    assert!(
        schema.starts_with("team_migration_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
