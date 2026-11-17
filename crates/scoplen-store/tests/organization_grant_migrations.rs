// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore as _, SqliteStore};
use uuid::Uuid;

const MIGRATION: i64 = 20_261_117_000_000;

macro_rules! populate {
    ($pool:expr) => {{
        let organization = Uuid::now_v7();
        let other = Uuid::now_v7();
        let account = Uuid::now_v7();
        let membership = Uuid::now_v7();
        let foreign_membership = Uuid::now_v7();
        let host = Uuid::now_v7();
        let foreign_host = Uuid::now_v7();
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
            .bind(account.as_bytes().as_slice()).bind([7_u8;32].as_slice())
            .execute($pool).await.expect("retained Account");
        for (org, member, object) in [(organization, membership, host), (other, foreign_membership, foreign_host)] {
            sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms,view_revision) VALUES ($1,'Retained team',123,456,$2)")
                .bind(org.as_bytes().as_slice()).bind(17_u64.to_be_bytes().as_slice())
                .execute($pool).await.expect("retained team");
            sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',123,456)")
                .bind(member.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
                .execute($pool).await.expect("retained Membership");
            sqlx::query("INSERT INTO sync_vaults (vault_id,kind) VALUES ($1,'organization')")
                .bind(org.as_bytes().as_slice()).execute($pool).await.expect("inventory vault");
            sqlx::query("INSERT INTO organization_inventory_vaults (organization_id,vault_id) VALUES ($1,$1)")
                .bind(org.as_bytes().as_slice()).execute($pool).await.expect("inventory owner");
            sqlx::query("INSERT INTO organization_inventory_objects (organization_id,vault_id,object_id,object_type,response_json,created_at_ms,updated_at_ms) VALUES ($1,$1,$2,1,$3,123,456)")
                .bind(org.as_bytes().as_slice()).bind(object.as_bytes().as_slice()).bind(b"{}".as_slice())
                .execute($pool).await.expect("retained used Host id");
        }
        sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms) VALUES (42,1,$1,1000,7,2,1001,2001,1001,601001)")
            .bind([127_u8,0,0,1].as_slice()).execute($pool).await.expect("retained admission debt");
        (organization, membership, host, foreign_membership, foreign_host)
    }};
}

macro_rules! preserved {
    ($pool:expr, $organization:expr) => {{
        let metadata: (String, i64, i64, Vec<u8>) = sqlx::query_as(
            "SELECT name,created_at_ms,updated_at_ms,view_revision FROM organizations WHERE id=$1",
        )
        .bind($organization.as_bytes().as_slice()).fetch_one($pool).await.expect("retained team");
        assert_eq!(metadata, ("Retained team".into(), 123, 456, 17_u64.to_be_bytes().to_vec()));
        let debt: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT attempts,failure_streak,last_failure_ms,cooldown_until_ms FROM account_entry_admission WHERE endpoint=42",
        ).fetch_one($pool).await.expect("retained endpoint debt");
        assert_eq!(debt, (7, 2, 1001, 2001));
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM organization_memberships),(SELECT COUNT(*) FROM organization_inventory_objects)",
        ).fetch_one($pool).await.expect("retained references");
        assert_eq!(counts, (2, 2));
    }};
}

macro_rules! constraints {
    ($pool:expr, $ids:expr) => {{
        let (organization, membership, host, foreign_membership, foreign_host) = $ids;
        let grant = Uuid::now_v7();
        let insert = "INSERT INTO organization_grants (organization_id,id,membership_id,host_id,response_json,created_at_ms,updated_at_ms,withdrawn_at_ms) VALUES ($1,$2,$3,$4,$5,123,456,$6)";
        for (member, target, bytes, withdrawn) in [
            (foreign_membership, host, b"{}".to_vec(), None),
            (membership, foreign_host, b"{}".to_vec(), None),
            (membership, host, Vec::new(), None),
            (membership, host, vec![b' '; 4097], None),
            (membership, host, b"{}".to_vec(), Some(0_i64)),
        ] {
            let result = sqlx::query(insert)
                .bind(organization.as_bytes().as_slice()).bind(grant.as_bytes().as_slice())
                .bind(member.as_bytes().as_slice()).bind(target.as_bytes().as_slice())
                .bind(bytes).bind(withdrawn).execute($pool).await;
            assert!(result.is_err(), "tenant, byte and withdrawal constraints must hold");
        }
        sqlx::query(insert)
            .bind(organization.as_bytes().as_slice()).bind(grant.as_bytes().as_slice())
            .bind(membership.as_bytes().as_slice()).bind(host.as_bytes().as_slice())
            .bind(vec![b' ';4096]).bind(Some(789_i64)).execute($pool).await.expect("bounded retained Grant");
        let duplicate = sqlx::query(insert)
            .bind(organization.as_bytes().as_slice()).bind(grant.as_bytes().as_slice())
            .bind(membership.as_bytes().as_slice()).bind(host.as_bytes().as_slice())
            .bind(b"{}".as_slice()).bind(None::<i64>).execute($pool).await;
        assert!(duplicate.is_err(), "withdrawal never frees a used identifier");
        let other: Vec<u8> = sqlx::query_scalar("SELECT organization_id FROM organization_memberships WHERE id=$1")
            .bind(foreign_membership.as_bytes().as_slice()).fetch_one($pool).await.expect("other owner");
        let cross_team = sqlx::query(insert)
            .bind(&other).bind(grant.as_bytes().as_slice())
            .bind(foreign_membership.as_bytes().as_slice()).bind(foreign_host.as_bytes().as_slice())
            .bind(b"{}".as_slice()).bind(None::<i64>).execute($pool).await;
        assert!(cross_team.is_err(), "withdrawn Grant identifiers remain globally used");
        for endpoint in [43_i64,44,45] {
            sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_admitted_ms,retire_at_ms) VALUES ($1,1,$2,1000,1,0,1001,601001)")
                .bind(endpoint).bind([127_u8,0,0,1].as_slice()).execute($pool).await.expect("independent Grant endpoint");
        }
        let rejected = sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_admitted_ms,retire_at_ms) VALUES (46,1,$1,1000,1,0,1001,601001)")
            .bind([127_u8,0,0,1].as_slice()).execute($pool).await;
        assert!(rejected.is_err(), "endpoint bound remains closed");
        grant
    }};
}

#[tokio::test]
async fn sqlite_grant_upgrade_preserves_state_and_enforces_tenant_bounds_after_reopen() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-grant-migration-{}", Uuid::new_v4()));
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
    old.run(&pool).await.expect("historical migrations");
    let ids = populate!(&pool);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward migration");
    preserved!(store.pool(), ids.0);
    let grant = constraints!(store.pool(), ids);
    store.pool().close().await;
    let store = SqliteStore::open(&path).await.expect("idempotent reopen");
    preserved!(store.pool(), ids.0);
    let retained: (i64, Vec<u8>) = sqlx::query_as(
        "SELECT withdrawn_at_ms,response_json FROM organization_grants WHERE organization_id=$1 AND id=$2",
    ).bind(ids.0.as_bytes().as_slice()).bind(grant.as_bytes().as_slice())
        .fetch_one(store.pool()).await.expect("retained used Grant");
    assert_eq!(retained, (789, vec![b' '; 4096]));
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_grant_upgrade_preserves_state_and_enforces_tenant_bounds_after_reopen() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("organization_grant_migration_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.expect("historical migrations");
    let ids = populate!(&pool);
    pool.close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward migration");
    preserved!(store.pool(), ids.0);
    let grant = constraints!(store.pool(), ids);
    store.pool().close().await;
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    preserved!(store.pool(), ids.0);
    let retained: (i64, Vec<u8>) = sqlx::query_as(
        "SELECT withdrawn_at_ms,response_json FROM organization_grants WHERE organization_id=$1 AND id=$2",
    ).bind(ids.0.as_bytes().as_slice()).bind(grant.as_bytes().as_slice())
        .fetch_one(store.pool()).await.expect("retained used Grant");
    assert_eq!(retained, (789, vec![b' '; 4096]));
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_grant_migration_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
