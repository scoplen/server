// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded expiry runs independently of requests and remains shutdown cancellable.

use super::*;
use scoplen_api::access_request::{
    AccessRequestFields, AccessRequestResource, AccessRequestStatus,
};
use uuid::Uuid;

macro_rules! seed_requests {
    ($store:expr,$count:expr) => {{
        let org = Uuid::now_v7();
        let account = Uuid::now_v7();
        let membership = Uuid::now_v7();
        let host = Uuid::now_v7();
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
            .bind(account.as_bytes().as_slice()).bind([1_u8;32].as_slice()).execute($store.pool()).await.unwrap();
        sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms) VALUES ($1,'Expiry worker',1,1)")
            .bind(org.as_bytes().as_slice()).execute($store.pool()).await.unwrap();
        sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"member\"]',1,1)")
            .bind(membership.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(account.as_bytes().as_slice()).execute($store.pool()).await.unwrap();
        sqlx::query("INSERT INTO sync_vaults (vault_id,kind) VALUES ($1,'organization')")
            .bind(org.as_bytes().as_slice()).execute($store.pool()).await.unwrap();
        sqlx::query("INSERT INTO organization_inventory_vaults (organization_id,vault_id) VALUES ($1,$1)")
            .bind(org.as_bytes().as_slice()).execute($store.pool()).await.unwrap();
        sqlx::query("INSERT INTO organization_inventory_objects (organization_id,vault_id,object_id,object_type,response_json,created_at_ms,updated_at_ms) VALUES ($1,$1,$2,1,$3,1,1)")
            .bind(org.as_bytes().as_slice()).bind(host.as_bytes().as_slice()).bind(b"{}".as_slice()).execute($store.pool()).await.unwrap();
        let expiry = worker_now_ms().unwrap()-1;
        let created = expiry-86_400_000;
        for _ in 0..$count {
            let resource = AccessRequestResource {id:Uuid::now_v7(),etag:"\"worker-fixture\"".into(),
                created_at:scoplen_api::audit::format_audit_timestamp(created).unwrap(),
                updated_at:scoplen_api::audit::format_audit_timestamp(created).unwrap(),
                requester_account_id:account,requester_membership_id:membership,
                fields:AccessRequestFields {host,remote_user:"ops".into(),duration_seconds:60,reason:"worker expiry".into()},
                expires_at:scoplen_api::audit::format_audit_timestamp(expiry).unwrap(),
                status:AccessRequestStatus::Pending,decision:None,grant:None};
            sqlx::query("INSERT INTO organization_access_requests (organization_id,id,requester_account_id,requester_membership_id,host_id,status,response_json,created_at_ms,updated_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$7,$8)")
                .bind(org.as_bytes().as_slice()).bind(resource.id.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
                .bind(membership.as_bytes().as_slice()).bind(host.as_bytes().as_slice()).bind(resource.to_json().unwrap())
                .bind(created).bind(expiry).execute($store.pool()).await.unwrap();
        }
        org
    }};
}

macro_rules! expiry_worker {
    ($store:expr,$directory:expr) => {{
        let store = Arc::new($store);
        let org = seed_requests!(store,101);
        assert_eq!(store.expire_organization_access_requests().await.unwrap(),100,"bounded indexed pass");
        let signer_path=$directory.join("audit-signing.key");
        fs::write(&signer_path,"11".repeat(32)).unwrap();
        let signer=LocalAuditSigner::load(&signer_path).unwrap();
        let (shutdown,receiver)=watch::channel(false);
        let worker=tokio::spawn(run_worker_role(store.clone(),Arc::new(signer),receiver));
        tokio::time::timeout(Duration::from_secs(10),async {
            loop {
                let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_access_requests WHERE status='pending'")
                    .fetch_one(store.pool()).await.unwrap();
                if pending==0 {break;}
                assert!(!worker.is_finished());
                sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("expiry proceeds without any HTTP traffic");
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2),worker).await.unwrap().unwrap().unwrap();
        assert_eq!(store.expire_organization_access_requests().await.unwrap(),0);
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT COUNT(*) FROM audit_events WHERE organization_id=$1),(SELECT COUNT(*) FROM organization_grants),(SELECT COUNT(*) FROM organization_inventory_receipts)")
            .bind(org.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
        assert_eq!(counts,(101,0,0));
        let revision:Vec<u8>=sqlx::query_scalar("SELECT view_revision FROM organizations WHERE id=$1")
            .bind(org.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
        assert_eq!(revision,1_u64.to_be_bytes());
        let rows:Vec<Vec<u8>>=sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1")
            .bind(org.as_bytes().as_slice()).fetch_all(store.pool()).await.unwrap();
        for bytes in rows {
            let event:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
            assert_eq!(event["action"],"organization.access_request_expired");
            assert!(event.get("account_id").is_none() && event.get("device_id").is_none() && event.get("browser_family_id").is_none());
        }
        store.pool().close().await;
    }};
}

#[tokio::test]
async fn sqlite_worker_access_request_expiry_is_bounded_and_needs_no_traffic() {
    let directory = std::env::temp_dir().join(format!("scoplen-request-worker-{}", Uuid::now_v7()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    expiry_worker!(store, directory);
    remove_test_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_worker_access_request_expiry_is_bounded_and_needs_no_traffic() {
    let (url, pool, schema) = postgres_fixture().await;
    let directory = std::env::temp_dir().join(format!("scoplen-request-worker-{}", Uuid::now_v7()));
    fs::create_dir(&directory).unwrap();
    let store = PostgresStore::connect(url.as_str()).await.unwrap();
    expiry_worker!(store, directory);
    cleanup_postgres_fixture(pool, schema).await;
    remove_test_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_worker_shutdown_interrupts_blocked_access_request_expiry() {
    let (mut url, pool, schema) = postgres_fixture().await;
    let marker = format!("request_shutdown_{}", Uuid::now_v7().simple());
    url.query_pairs_mut().append_pair("application_name", &marker);
    let store = Arc::new(PostgresStore::connect(url.as_str()).await.unwrap());
    let org = seed_requests!(store, 1);
    let mut blocker = store.pool().begin().await.unwrap();
    let pid: i32 =
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await.unwrap();
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(org.as_bytes().as_slice())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let directory =
        std::env::temp_dir().join(format!("scoplen-request-shutdown-{}", Uuid::now_v7()));
    fs::create_dir(&directory).unwrap();
    let signer_path = directory.join("audit-signing.key");
    fs::write(&signer_path, "11".repeat(32)).unwrap();
    let signer = LocalAuditSigner::load(&signer_path).unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let worker = tokio::spawn(run_worker_role(store.clone(), Arc::new(signer), receiver));
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$2 AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(pid).bind(&marker).fetch_one(store.pool()).await.unwrap();
            if waiting {break;}
            assert!(!worker.is_finished());
            sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("worker reached the request expiry lock");
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), worker).await.unwrap().unwrap().unwrap();
    blocker.rollback().await.unwrap();
    assert_eq!(
        store.expire_organization_access_requests().await.unwrap(),
        1,
        "pool and rolled-back request remain reusable"
    );
    store.pool().close().await;
    cleanup_postgres_fixture(pool, schema).await;
    remove_test_directory(&directory).await;
}
