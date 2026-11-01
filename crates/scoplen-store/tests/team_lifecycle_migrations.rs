// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{
    RelationalStore, SqliteStore,
    account_entry_admission::{AccountEntryAdmissionDecision, AccountEntryEndpoint},
};

const MIGRATION: i64 = 20_261_101_000_000;
const NOW: i64 = 4_000_000_020_000;

macro_rules! populate {
    ($pool:expr,$append:path)=>{{
        sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms) VALUES ($1,'Retained team',123,456)")
            .bind([1_u8;16].as_slice()).execute($pool).await.expect("retained team");
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
            .bind([2_u8;16].as_slice()).bind([3_u8;32].as_slice()).execute($pool).await.expect("retained Account");
        sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',123,456)")
            .bind([4_u8;16].as_slice()).bind([1_u8;16].as_slice()).bind([2_u8;16].as_slice()).execute($pool).await.expect("retained membership");
        sqlx::query("INSERT INTO organization_creation_receipts (account_id,idempotency_key,organization_id,request_digest,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,123,86400123)")
            .bind([2_u8;16].as_slice()).bind([5_u8;16].as_slice()).bind([1_u8;16].as_slice()).bind([6_u8;32].as_slice())
            .execute($pool).await.expect("retained receipt");
        sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms) VALUES (4,1,$1,$2,30,1,$3,$2,$2,$4)")
            .bind([127_u8,0,0,1].as_slice()).bind(NOW).bind(NOW-1000).bind(NOW+600000).execute($pool).await.expect("retained source debt");
        sqlx::query("UPDATE account_entry_state SET rate_rows=1,time_high_water_ms=$1").bind(NOW).execute($pool).await.expect("retained capacity and clock");
        let mut tx=$pool.begin().await.expect("audit transaction");
        let event=$append(&mut tx,[1;16],b"retained team creation",123).await.expect("retained audit");
        tx.commit().await.expect("audit commit"); event.event_hash
    }};
}

macro_rules! preserved {
    ($store:expr,$hash:expr)=>{{
        let store=&$store;
        let row:(String,i64,i64,Option<i64>,Vec<u8>)=sqlx::query_as("SELECT name,created_at_ms,updated_at_ms,dissolved_at_ms,view_revision FROM organizations")
            .fetch_one(store.pool()).await.expect("migrated team");
        assert_eq!(row,("Retained team".into(),123,456,None,1_u64.to_be_bytes().to_vec()));
        let membership:(String,String,i64)=sqlx::query_as("SELECT status,roles_json,updated_at_ms FROM organization_memberships").fetch_one(store.pool()).await.expect("retained membership");
        assert_eq!(membership,("active".into(),"[\"owner\"]".into(),456));
        let receipt:(Vec<u8>,i64,i64)=sqlx::query_as("SELECT request_digest,created_at_ms,expires_at_ms FROM organization_creation_receipts").fetch_one(store.pool()).await.expect("retained receipt");
        assert_eq!(receipt,([6_u8;32].to_vec(),123,86400123));
        let debt:(i64,i64,i64,Option<i64>,Option<i64>,i64,i64)=sqlx::query_as("SELECT window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms FROM account_entry_admission WHERE endpoint=4")
            .fetch_one(store.pool()).await.expect("preserved admission debt");
        assert_eq!(debt,(NOW,30,1,Some(NOW-1000),Some(NOW),NOW,NOW+600000));
        let count:i64=sqlx::query_scalar("SELECT rate_rows FROM account_entry_state").fetch_one(store.pool()).await.expect("capacity count");
        assert_eq!(count,1);
        assert_eq!(store.verify_audit_chain([1;16]).await.expect("audit preserved"),$hash);
        let revision=u64::MAX.to_be_bytes();
        sqlx::query("UPDATE organizations SET view_revision=$1").bind(revision.as_slice()).execute(store.pool()).await.expect("full unsigned revision");
        let read:Vec<u8>=sqlx::query_scalar("SELECT view_revision FROM organizations").fetch_one(store.pool()).await.expect("revision bytes");
        assert_eq!(read,revision);
        sqlx::query("UPDATE organizations SET view_revision=$1").bind(1_u64.to_be_bytes().as_slice()).execute(store.pool()).await.expect("restore fixture revision");
    }};
}

macro_rules! admission {
    ($store:expr) => {{
        let store = &$store;
        assert!(matches!(
            store
                .admit_account_entry_source(
                    AccountEntryEndpoint::PasswordLogin,
                    "127.0.0.1".parse().expect("source")
                )
                .await
                .expect("retained old admission"),
            AccountEntryAdmissionDecision::RateLimited(_)
        ));
        assert_eq!(
            store
                .admit_account_entry_source(
                    AccountEntryEndpoint::TeamDissolve,
                    "127.0.0.1".parse().expect("source")
                )
                .await
                .expect("new independent namespace"),
            AccountEntryAdmissionDecision::Admitted
        );
        let count: i64 = sqlx::query_scalar("SELECT rate_rows FROM account_entry_state")
            .fetch_one(store.pool())
            .await
            .expect("capacity after new bucket");
        assert_eq!(count, 2);
    }};
}

#[tokio::test]
async fn sqlite_team_lifecycle_migration_preserves_identity_audit_and_admission_debt() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-team-migration-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("owned directory");
    let path = directory.join("scoplen.sqlite");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("historical migration");
    let hash = populate!(&pool, scoplen_store::append_audit_event_in_transaction);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    preserved!(store, hash);
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("idempotent reopen");
    preserved!(reopened, hash);
    admission!(reopened);
    reopened.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_lifecycle_migration_preserves_identity_audit_and_admission_debt() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let admin = sqlx::PgPool::connect(&database).await.expect("schema administration");
    let schema = format!("team_lifecycle_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("historical migration");
    let hash = populate!(&pool, scoplen_store::append_audit_event_in_postgres_transaction);
    pool.close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward migration");
    preserved!(store, hash);
    store.pool().close().await;
    let reopened =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    preserved!(reopened, hash);
    admission!(reopened);
    reopened.pool().close().await;
    assert!(
        schema.starts_with("team_lifecycle_migration_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
