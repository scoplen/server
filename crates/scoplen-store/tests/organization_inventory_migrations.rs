// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore as _, SqliteStore};
const MIGRATION: i64 = 20_261_102_000_000;

macro_rules! populate {($pool:expr)=>{{
    let organization=uuid::Uuid::now_v7().into_bytes();
    let account=uuid::Uuid::now_v7().into_bytes();
    let member=uuid::Uuid::now_v7().into_bytes();
    let personal=uuid::Uuid::now_v7().into_bytes();
    sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)").bind(account.as_slice()).bind([7_u8;32].as_slice()).execute($pool).await.expect("retained Account");
    sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms,view_revision) VALUES ($1,'Retained team',123,456,$2)").bind(organization.as_slice()).bind(17_u64.to_be_bytes().as_slice()).execute($pool).await.expect("retained team");
    sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',123,456)").bind(member.as_slice()).bind(organization.as_slice()).bind(account.as_slice()).execute($pool).await.expect("retained membership");
    sqlx::query("INSERT INTO sync_vaults (vault_id,kind) VALUES ($1,'personal')").bind(personal.as_slice()).execute($pool).await.expect("retained Personal vault");
    sqlx::query("INSERT INTO sync_personal_vaults (account_id,vault_id,wrapped_vault_key) VALUES ($1,$2,$3)").bind(account.as_slice()).bind(personal.as_slice()).bind([9_u8;32].as_slice()).execute($pool).await.expect("retained Personal owner");
    (organization,account,member,personal)
}};}

macro_rules! preserved {($store:expr,$ids:expr)=>{{
    let store=&$store;
    let (organization,account,member,personal)=$ids;
    let row:(String,i64,i64,Vec<u8>)=sqlx::query_as("SELECT name,created_at_ms,updated_at_ms,view_revision FROM organizations WHERE id=$1").bind(organization.as_slice()).fetch_one(store.pool()).await.expect("retained team");
    assert_eq!(row,("Retained team".into(),123,456,17_u64.to_be_bytes().to_vec()));
    let mapped:(Vec<u8>,String,i64)=sqlx::query_as("SELECT v.vault_id,s.kind,s.current_seq FROM organization_inventory_vaults v JOIN sync_vaults s ON s.vault_id=v.vault_id WHERE v.organization_id=$1").bind(organization.as_slice()).fetch_one(store.pool()).await.expect("backfilled owner");
    assert_eq!(mapped,(organization.to_vec(),"organization".into(),0));
    let own:(Vec<u8>,i64,Vec<u8>)=sqlx::query_as("SELECT vault_id,key_epoch,wrapped_vault_key FROM sync_personal_vaults WHERE account_id=$1").bind(account.as_slice()).fetch_one(store.pool()).await.expect("retained Personal owner");assert_eq!(own,(personal.to_vec(),1,[9_u8;32].to_vec()));
    let status:String=sqlx::query_scalar("SELECT status FROM organization_memberships WHERE id=$1").bind(member.as_slice()).fetch_one(store.pool()).await.expect("retained member");assert_eq!(status,"active");
    let groups:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_groups").fetch_one(store.pool()).await.expect("empty groups");assert_eq!(groups,0);
    let policies:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_policies").fetch_one(store.pool()).await.expect("empty policies");assert_eq!(policies,0);
}};}

macro_rules! retention_compatible {($store:expr,$ids:expr)=>{{
    let store=&$store;
    let (organization,_,_,_)=$ids;
    let object=uuid::Uuid::now_v7().into_bytes();
    sqlx::query("UPDATE sync_vaults SET current_seq=1 WHERE vault_id=$1").bind(organization.as_slice()).execute(store.pool()).await.expect("current sequence");
    sqlx::query("INSERT INTO sync_objects (vault_id,object_id,sequence,envelope,tombstone,written_at_ms,key_epoch) VALUES ($1,$2,1,$3,$4,1,1)").bind(organization.as_slice()).bind(object.as_slice()).bind([1_u8].as_slice()).bind(true).execute(store.pool()).await.expect("retained tombstone");
    sqlx::query("INSERT INTO organization_inventory_objects (organization_id,vault_id,object_id,object_type,response_json,created_at_ms,updated_at_ms) VALUES ($1,$1,$2,1,$3,1,1)").bind(organization.as_slice()).bind(object.as_slice()).bind(b"{}".as_slice()).execute(store.pool()).await.expect("used inventory id");
    let report=store.purge_sync_history(organization,None,15_552_000_002).await.expect("purge retained Organization tombstone");
    assert_eq!(report.purged_tombstones,1);
    let retained:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_inventory_objects WHERE organization_id=$1 AND object_id=$2").bind(organization.as_slice()).bind(object.as_slice()).fetch_one(store.pool()).await.expect("permanent used-id projection");
    assert_eq!(retained,1);
    let duplicate=sqlx::query("INSERT INTO organization_inventory_objects (organization_id,vault_id,object_id,object_type,response_json,created_at_ms,updated_at_ms) VALUES ($1,$1,$2,1,$3,1,1)").bind(organization.as_slice()).bind(object.as_slice()).bind(b"{}".as_slice()).execute(store.pool()).await;
    assert!(duplicate.is_err(),"purging cannot permit identifier reuse");
}};}

#[tokio::test]
async fn sqlite_organization_inventory_upgrade_retains_team_and_personal_state() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-inventory-migration-{}", uuid::Uuid::new_v4()));
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
        .expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("old migrations");
    let ids = populate!(&pool);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    preserved!(store, ids);
    store.pool().close().await;
    let store = SqliteStore::open(&path).await.expect("idempotent reopen");
    preserved!(store, ids);
    retention_compatible!(store, ids);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_organization_inventory_upgrade_retains_team_and_personal_state() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("organization_inventory_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("old migrations");
    let ids = populate!(&pool);
    pool.close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward migration");
    preserved!(store, ids);
    store.pool().close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    preserved!(store, ids);
    retention_compatible!(store, ids);
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_inventory_migration_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
