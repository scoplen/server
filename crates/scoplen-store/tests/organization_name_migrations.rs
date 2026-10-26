// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore, SqliteStore};

const NAME_MIGRATION: i64 = 20_261_026_010_000;

macro_rules! populate {
    ($pool:expr, $append:path) => {{
        sqlx::query("INSERT INTO organizations (id,name,created_at_ms) VALUES ($1,'Retained team',123)")
            .bind([1_u8;16].as_slice()).execute($pool).await.expect("retained organization");
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
            .bind([2_u8;16].as_slice()).bind([3_u8;32].as_slice()).execute($pool).await.expect("retained Account");
        sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',123,456)")
            .bind([4_u8;16].as_slice()).bind([1_u8;16].as_slice()).bind([2_u8;16].as_slice())
            .execute($pool).await.expect("retained membership");
        sqlx::query("INSERT INTO organization_creation_receipts (account_id,idempotency_key,organization_id,request_digest,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,123,86400123)")
            .bind([2_u8;16].as_slice()).bind([5_u8;16].as_slice()).bind([1_u8;16].as_slice())
            .bind([6_u8;32].as_slice()).execute($pool).await.expect("retained exact receipt");
        let mut tx = $pool.begin().await.expect("owned audit transaction");
        let audit = $append(&mut tx,[1;16],b"retained team creation",123).await.expect("retained chain");
        tx.commit().await.expect("retained audit commit");
        audit.event_hash
    }};
}

macro_rules! preserved {
    ($store:expr, $hash:expr) => {{
        let store = &$store;
        let row: (String, i64, i64) =
            sqlx::query_as("SELECT name,created_at_ms,updated_at_ms FROM organizations")
                .fetch_one(store.pool())
                .await
                .expect("forward-migrated organization");
        assert_eq!(row, ("Retained team".into(), 123, 123));
        let membership: (String, String, i64) =
            sqlx::query_as("SELECT status,roles_json,updated_at_ms FROM organization_memberships")
                .fetch_one(store.pool())
                .await
                .expect("preserved membership");
        assert_eq!(membership, ("active".into(), "[\"owner\"]".into(), 456));
        let receipt: (Vec<u8>, i64, i64) = sqlx::query_as(
            "SELECT request_digest,created_at_ms,expires_at_ms FROM organization_creation_receipts",
        )
        .fetch_one(store.pool())
        .await
        .expect("preserved receipt");
        assert_eq!(receipt, ([6_u8; 32].to_vec(), 123, 86400123));
        assert_eq!(store.verify_audit_chain([1; 16]).await.expect("unchanged audit chain"), $hash);
        assert!(
            sqlx::query("UPDATE organizations SET updated_at_ms=-1")
                .execute(store.pool())
                .await
                .is_err()
        );
    }};
}

#[tokio::test]
async fn sqlite_name_migration_preserves_creation_membership_receipt_and_audit() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let directory =
        std::env::temp_dir().join(format!("scoplen-name-migration-{}", uuid::Uuid::new_v4()));
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
    old.migrations.to_mut().retain(|migration| migration.version < NAME_MIGRATION);
    old.run(&pool).await.expect("existing team schema");
    let hash = populate!(&pool, scoplen_store::append_audit_event_in_transaction);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward name migration");
    preserved!(store, hash);
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("idempotent reopen");
    preserved!(reopened, hash);
    reopened.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_name_migration_preserves_creation_membership_receipt_and_audit() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let admin = sqlx::PgPool::connect(&database).await.expect("schema administration");
    let schema = format!("team_name_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < NAME_MIGRATION);
    old.run(&pool).await.expect("existing team schema");
    let hash = populate!(&pool, scoplen_store::append_audit_event_in_postgres_transaction);
    pool.close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward name migration");
    preserved!(store, hash);
    store.pool().close().await;
    let reopened =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    preserved!(reopened, hash);
    reopened.pool().close().await;
    assert!(
        schema.starts_with("team_name_migration_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
