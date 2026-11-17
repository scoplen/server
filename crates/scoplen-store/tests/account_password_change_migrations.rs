// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use scoplen_store::{RelationalStore, SqliteStore};
use uuid::Uuid;
const MIGRATION: i64 = 20_261_117_020_000;

macro_rules! populate {
    ($pool:expr)=>{{
        let account=Uuid::now_v7();let vault=Uuid::now_v7();let device=Uuid::now_v7();let operation=Uuid::now_v7();let family=Uuid::now_v7();
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms,password_owned) VALUES ($1,$2,$3,1,TRUE)")
            .bind(account.as_bytes().as_slice()).bind([2_u8;32].as_slice()).bind([3_u8;32].as_slice()).execute($pool).await.expect("retained password Account");
        sqlx::query("INSERT INTO account_password_bootstrap (account_id,origin,username,credential_generation,password_profile,password_salt,verifier,password_ark,personal_vault_id,account_signing_public_key,account_kem_public_key) VALUES ($1,'https://password.example.test','retained-user',1,1,$2,$3,$4,$5,$6,$7)")
            .bind(account.as_bytes().as_slice()).bind([4_u8;16].as_slice()).bind([5_u8;32].as_slice()).bind([6_u8;73].as_slice()).bind(vault.as_bytes().as_slice()).bind([2_u8;32].as_slice()).bind([3_u8;32].as_slice()).execute($pool).await.expect("retained generation-one bootstrap");
        sqlx::query("INSERT INTO account_admission_capabilities (token_digest,account_id,credential_generation,snapshot_digest,issued_at_ms,expires_at_ms) VALUES ($1,$2,7,$3,1,300001)")
            .bind([7_u8;32].as_slice()).bind(account.as_bytes().as_slice()).bind([8_u8;32].as_slice()).execute($pool).await.expect("retained capability binding");
        sqlx::query("INSERT INTO account_browser_families (family_id,account_id,credential_generation,dpop_jkt,trusted_origin,scope,created_at_ms,expires_at_ms,revoked_at_ms) VALUES ($1,$2,1,$3,'https://password.example.test','account:read',1,2592000001,2)")
            .bind(family.as_bytes().as_slice()).bind(account.as_bytes().as_slice()).bind("a".repeat(43)).execute($pool).await.expect("retained revoked browser family");
        sqlx::query("INSERT INTO account_browser_access_tokens (token_digest,family_id,issued_at_ms,expires_at_ms) VALUES ($1,$2,1,600001)")
            .bind([9_u8;32].as_slice()).bind(family.as_bytes().as_slice()).execute($pool).await.expect("retained access child");
        sqlx::query("INSERT INTO account_browser_refresh_tokens (token_digest,family_id,issued_at_ms,spent_at_ms) VALUES ($1,$2,1,2)")
            .bind([10_u8;32].as_slice()).bind(family.as_bytes().as_slice()).execute($pool).await.expect("retained spent refresh child");
        sqlx::query("INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,17,3)")
            .bind(operation.as_bytes().as_slice()).bind(account.as_bytes().as_slice()).bind(vault.as_bytes().as_slice()).bind(device.as_bytes().as_slice()).bind([11_u8;32].as_slice()).bind([12_u8;65].as_slice()).bind([13_u8;65].as_slice()).bind([2_u8;32].as_slice()).execute($pool).await.expect("retained original receipt");
        sqlx::query("INSERT INTO account_request_challenges (attempt_digest,nonce_digest,origin_digest,kind,intent,operation_id,device_id,issued_at_ms,expires_at_ms) VALUES ($1,$2,$3,2,1,$4,$5,1,120001)")
            .bind([14_u8;32].as_slice()).bind([15_u8;32].as_slice()).bind([16_u8;32].as_slice()).bind(operation.as_bytes().as_slice()).bind(device.as_bytes().as_slice()).execute($pool).await.expect("retained challenge");
        sqlx::query("UPDATE account_entry_state SET challenge_rows=1,rate_rows=1").execute($pool).await.expect("retained shared capacity");
        sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_admitted_ms,retire_at_ms) VALUES (49,1,$1,0,7,0,1,600001)")
            .bind([192_u8,0,2,1].as_slice()).execute($pool).await.expect("retained rate debt");
        (account,device,operation,family)
    }};
}
macro_rules! preserved {
    ($pool:expr,$ids:expr)=>{{
        let (account,_,operation,family)=$ids;
        let bootstrap:(String,String,Vec<u8>,i64,Vec<u8>,Vec<u8>,Vec<u8>)=sqlx::query_as("SELECT origin,username,credential_generation,password_profile,password_salt,verifier,password_ark FROM account_password_bootstrap WHERE account_id=$1")
            .bind(account.as_bytes().as_slice()).fetch_one($pool).await.expect("retained bootstrap");
        assert_eq!(bootstrap,("https://password.example.test".into(),"retained-user".into(),1_u64.to_be_bytes().to_vec(),1,vec![4;16],vec![5;32],vec![6;73]));
        let capability:(Vec<u8>,Vec<u8>,i64,i64)=sqlx::query_as("SELECT credential_generation,snapshot_digest,issued_at_ms,expires_at_ms FROM account_admission_capabilities WHERE token_digest=$1")
            .bind([7_u8;32].as_slice()).fetch_one($pool).await.expect("retained capability");assert_eq!(capability,(7_u64.to_be_bytes().to_vec(),vec![8;32],1,300001));
        let browser:(Vec<u8>,String,String,String,i64,i64,i64)=sqlx::query_as("SELECT credential_generation,dpop_jkt,trusted_origin,scope,created_at_ms,expires_at_ms,revoked_at_ms FROM account_browser_families WHERE family_id=$1")
            .bind(family.as_bytes().as_slice()).fetch_one($pool).await.expect("retained browser family");assert_eq!(browser,(1_u64.to_be_bytes().to_vec(),"a".repeat(43),"https://password.example.test".into(),"account:read".into(),1,2592000001,2));
        let access:(Vec<u8>,i64,i64)=sqlx::query_as("SELECT family_id,issued_at_ms,expires_at_ms FROM account_browser_access_tokens WHERE token_digest=$1").bind([9_u8;32].as_slice()).fetch_one($pool).await.expect("access child survived");assert_eq!(access,(family.as_bytes().to_vec(),1,600001));
        let refresh:(Vec<u8>,i64,i64)=sqlx::query_as("SELECT family_id,issued_at_ms,spent_at_ms FROM account_browser_refresh_tokens WHERE token_digest=$1").bind([10_u8;32].as_slice()).fetch_one($pool).await.expect("spent refresh child survived");assert_eq!(refresh,(family.as_bytes().to_vec(),1,2));
        let receipt:(i64,i64,Option<Vec<u8>>,i64)=sqlx::query_as("SELECT kind,admitted_key_revision,credential_generation,committed_at_ms FROM account_operation_receipts WHERE operation_id=$1").bind(operation.as_bytes().as_slice()).fetch_one($pool).await.expect("original receipt survived");assert_eq!(receipt,(1,17,None,3));
        let debt:i64=sqlx::query_scalar("SELECT attempts FROM account_entry_admission WHERE endpoint=49").fetch_one($pool).await.expect("retained rate debt");assert_eq!(debt,7);
        let challenge:(i64,i64,i64)=sqlx::query_as("SELECT kind,issued_at_ms,expires_at_ms FROM account_request_challenges").fetch_one($pool).await.expect("retained challenge");assert_eq!(challenge,(2,1,120001));
    }};
}
macro_rules! constraints {
    ($pool:expr,$ids:expr)=>{{
        let (_,_,operation,_)=$ids;
        for generation in [2_u64,3] {
            sqlx::query("INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,credential_generation,committed_at_ms) SELECT $1,account_id,personal_vault_id,device_id,request_digest,3,device_signing_public_key,device_kem_public_key,account_signing_public_key,$2,4 FROM account_operation_receipts WHERE operation_id=$3")
                .bind(Uuid::now_v7().as_bytes().as_slice()).bind(generation.to_be_bytes().as_slice()).bind(operation.as_bytes().as_slice()).execute($pool).await.expect("same Device multiple password receipts");
        }
        let repeat=sqlx::query("INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) SELECT $1,account_id,personal_vault_id,device_id,request_digest,2,device_signing_public_key,device_kem_public_key,account_signing_public_key,17,4 FROM account_operation_receipts WHERE operation_id=$2")
            .bind(Uuid::now_v7().as_bytes().as_slice()).bind(operation.as_bytes().as_slice()).execute($pool).await;assert!(repeat.is_err(),"original Device admission uniqueness remains");
        assert!(sqlx::query("UPDATE account_password_bootstrap SET origin='https://changed.example.test'").execute($pool).await.is_err(),"identity binding remains immutable");
        assert!(sqlx::query("UPDATE account_password_bootstrap SET verifier=$1").bind([88_u8;32].as_slice()).execute($pool).await.is_err(),"credential update requires a positive generation transition");
        assert!(sqlx::query("UPDATE account_password_bootstrap SET credential_generation=$1").bind([0_u8;8].as_slice()).execute($pool).await.is_err(),"generation zero remains forbidden");
    }};
}

#[tokio::test]
async fn sqlite_password_change_upgrade_preserves_all_bindings_children_and_guards() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-password-migration-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
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
        .unwrap();
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.unwrap();
    let ids = populate!(&pool);
    let mut password_change = sqlx::migrate!("./migrations/sqlite");
    password_change.migrations.to_mut().retain(|migration| migration.version <= MIGRATION);
    password_change.run(&pool).await.expect("published password-change migration");
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    preserved!(store.pool(), ids);
    for (index, columns) in [
        ("account_browser_access_expiry", vec!["expires_at_ms"]),
        ("account_browser_access_family", vec!["family_id"]),
        ("account_browser_refresh_family", vec!["family_id"]),
    ] {
        let actual: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_index_info($1) ORDER BY seqno")
                .bind(index)
                .fetch_all(store.pool())
                .await
                .expect("restored browser token index");
        assert_eq!(actual, columns, "forward migration restores {index}");
    }
    constraints!(store.pool(), ids);
    store.pool().close().await;
    let store = SqliteStore::open(&path).await.expect("idempotent reopen");
    preserved!(store.pool(), ids);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_password_change_upgrade_preserves_all_bindings_children_and_guards() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned test database");
    let admin = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("password_change_migration_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.unwrap();
    let ids = populate!(&pool);
    pool.close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward migration");
    preserved!(store.pool(), ids);
    constraints!(store.pool(), ids);
    store.pool().close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    preserved!(store.pool(), ids);
    store.pool().close().await;
    assert!(
        schema.starts_with("password_change_migration_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}
