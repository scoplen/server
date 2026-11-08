// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore as _, SqliteStore};

const MIGRATION: i64 = 20_261_103_000_000;

macro_rules! populate {
    ($pool:expr) => {{
        sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms) VALUES (38,1,$1,1000,7,2,1001,2001,1001,601001)")
            .bind([127_u8,0,0,1].as_slice()).execute($pool).await.expect("retained admission debt");
        let organization = uuid::Uuid::now_v7();
        sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms,view_revision) VALUES ($1,'Retained team',123,456,$2)")
            .bind(organization.as_bytes().as_slice()).bind(17_u64.to_be_bytes().as_slice())
            .execute($pool).await.expect("retained team");
        organization
    }};
}

macro_rules! preserved {
    ($pool:expr, $organization:expr) => {{
        let debt: (i64,i64,i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT endpoint,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms FROM account_entry_admission WHERE kind=1 AND bucket_key=$1")
            .bind([127_u8,0,0,1].as_slice()).fetch_one($pool).await.expect("retained debt");
        assert_eq!(debt,(38,1000,7,2,1001,2001,1001,601001));
        let organization = $organization;
        let metadata:(String,i64,i64,Vec<u8>) = sqlx::query_as("SELECT name,created_at_ms,updated_at_ms,view_revision FROM organizations WHERE id=$1")
            .bind(organization.as_bytes().as_slice()).fetch_one($pool).await.expect("retained metadata");
        assert_eq!(metadata,("Retained team".into(),123,456,17_u64.to_be_bytes().to_vec()));
        let ca:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_user_cas").fetch_one($pool).await.expect("new CA table");
        let certs:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_user_certificates").fetch_one($pool).await.expect("new certificate table");
        assert_eq!((ca,certs),(0,0));
        for endpoint in [39_i64,40] {
            sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms) VALUES ($1,1,$2,1000,1,0,NULL,NULL,1001,601001)")
                .bind(endpoint).bind([127_u8,0,0,1].as_slice()).execute($pool).await.expect("independent new endpoint");
        }
    }};
}

#[tokio::test]
async fn sqlite_organization_user_ca_upgrade_preserves_existing_team_and_admission_debt() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-user-ca-migration-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("owned directory");
    let path = directory.join("store.sqlite");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("historical SQLite");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("historical migrations");
    let organization = populate!(&pool);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    preserved!(store.pool(), organization);
    store.pool().close().await;
    let store = SqliteStore::open(&path).await.expect("idempotent reopen");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_entry_admission")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 3);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_organization_user_ca_upgrade_preserves_existing_team_and_admission_debt() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("organization_user_ca_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical PostgreSQL");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("historical migrations");
    let organization = populate!(&pool);
    pool.close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward migration");
    preserved!(store.pool(), organization);
    store.pool().close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_entry_admission")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 3);
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_user_ca_migration_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
