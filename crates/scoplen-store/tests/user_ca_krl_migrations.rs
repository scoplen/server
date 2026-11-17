// SPDX-License-Identifier: AGPL-3.0-only
//! Forward activation verifies real historical certificates before publishing any KRL.

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
mod support;

use legacy_identity::LegacyIdentity;
use scoplen_api::{
    certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateTargets},
    krl::UserCaKrl,
    user_ca::{UserCaResource, user_ca_fingerprint},
};
use scoplen_ca::{LocalUserCa, UserCertificateContext};
use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
use scoplen_store::{RelationalStore as _, SqliteStore, organizations::OrganizationStoreError};
use uuid::Uuid;

const MIGRATION: i64 = 20_261_109_000_000;
const TIMESTAMP: &str = "2026-01-01T00:00:00Z";

struct Issuance {
    id: Uuid,
    response: Vec<u8>,
    expires: u64,
}

struct HistoricalCa {
    organization: Uuid,
    trust: UserCaResource,
    encrypted: Vec<u8>,
    membership: Option<&'static str>,
    dissolved: bool,
    certificates: Vec<Issuance>,
    corrupt_responses: Vec<Vec<u8>>,
}

fn identity() -> LegacyIdentity {
    let signing = Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account key");
    let mut scalar = [0; 32];
    scalar[31] = 1;
    LegacyIdentity::new(&signing, &P256SigningKey::from_bytes(&scalar).expect("Device key"))
}

fn historical(identity: &LegacyIdentity) -> Vec<HistoricalCa> {
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("clock");
    let subject = LocalUserCa::generate().unwrap().public_key().unwrap();
    let mut result = Vec::new();
    for (membership, dissolved) in
        [(Some("suspended"), false), (None, false), (Some("active"), true), (Some("active"), false)]
    {
        let organization = Uuid::now_v7();
        let ca = LocalUserCa::generate().unwrap();
        let public_key = ca.public_key().unwrap();
        let trust = UserCaResource {
            id: Uuid::now_v7(),
            etag: "\"historical-ca\"".into(),
            created_at: TIMESTAMP.into(),
            updated_at: TIMESTAMP.into(),
            fingerprint: user_ca_fingerprint(&public_key).unwrap(),
            public_key,
        };
        let request = CertificateIssuanceRequest::new(
            subject.clone(),
            CertificateTargets::Hosts(vec![Uuid::now_v7()]),
            "deploy",
            86_400,
        )
        .unwrap();
        let mut certificates = Vec::new();
        let mut corrupt_responses = Vec::new();
        for (serial, issued_at) in [(1, now - 7_200), (2, now)] {
            let id = Uuid::now_v7();
            let context = UserCertificateContext {
                organization,
                account: identity.account_id,
                device: identity.device_certificate.device_id,
                certificate: id,
                serial,
                now_seconds: issued_at,
                authorization_not_after: None,
            };
            let response = CertificateIssuanceResponse::new(
                id,
                "\"historical-certificate\"",
                TIMESTAMP,
                TIMESTAMP,
                ca.issue(&request, &context).unwrap(),
            )
            .unwrap();
            if serial == 2 {
                let mut foreign_ca = response.clone();
                foreign_ca.certificate =
                    LocalUserCa::generate().unwrap().issue(&request, &context).unwrap();
                corrupt_responses.push(foreign_ca.to_json().unwrap());
                let mut wrong_binding = response.clone();
                let wrong_context =
                    UserCertificateContext { certificate: Uuid::now_v7(), ..context };
                wrong_binding.certificate = ca.issue(&request, &wrong_context).unwrap();
                corrupt_responses.push(wrong_binding.to_json().unwrap());
                let mut wrong_resource = response.clone();
                wrong_resource.id = Uuid::now_v7();
                corrupt_responses.push(wrong_resource.to_json().unwrap());
            }
            certificates.push(Issuance {
                id,
                response: response.to_json().unwrap(),
                expires: issued_at + 1_800,
            });
        }
        let encrypted = ca.seal(&[7; 32], organization, trust.id).unwrap();
        result.push(HistoricalCa {
            organization,
            trust,
            encrypted,
            membership,
            dissolved,
            certificates,
            corrupt_responses,
        });
    }
    result.sort_by_key(|case| case.organization);
    result
}

macro_rules! populate {
    ($pool:expr, $identity:expr, $cases:expr, $append:path) => {{
        let identity = $identity;
        for case in $cases {
            let org = case.organization.as_bytes().as_slice();
            sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms,view_revision,dissolved_at_ms) VALUES ($1,'Retained team',123,456,$2,$3)")
                .bind(org).bind(17_u64.to_be_bytes().as_slice()).bind(case.dissolved.then_some(789_i64))
                .execute($pool).await.unwrap();
            if let Some(status) = case.membership {
                sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,'[\"member\"]',123,456)")
                    .bind(Uuid::now_v7().as_bytes().as_slice()).bind(org).bind(identity.account_id.as_bytes().as_slice()).bind(status)
                    .execute($pool).await.unwrap();
            }
            sqlx::query("INSERT INTO organization_user_cas (organization_id,id,encrypted_seed,response_json,last_serial,created_at_ms) VALUES ($1,$2,$3,$4,$5,1)")
                .bind(org).bind(case.trust.id.as_bytes().as_slice()).bind(&case.encrypted).bind(case.trust.to_json().unwrap()).bind(2_u64.to_be_bytes().as_slice())
                .execute($pool).await.unwrap();
            for (index, certificate) in case.certificates.iter().enumerate() {
                let serial = u64::try_from(index).unwrap() + 1;
                // Historical row time is deliberately unrelated to the signed, capped expiry.
                sqlx::query("INSERT INTO organization_user_certificates (organization_id,id,authority_id,account_id,device_id,serial,response_json,created_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,1)")
                    .bind(org).bind(certificate.id.as_bytes().as_slice()).bind(case.trust.id.as_bytes().as_slice())
                    .bind(identity.account_id.as_bytes().as_slice()).bind(identity.device_certificate.device_id.as_bytes().as_slice())
                    .bind(serial.to_be_bytes().as_slice()).bind(&certificate.response).execute($pool).await.unwrap();
                sqlx::query("INSERT INTO organization_inventory_receipts (account_id,idempotency_key,organization_id,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,1,86400001)")
                    .bind(identity.account_id.as_bytes().as_slice()).bind(certificate.id.as_bytes().as_slice()).bind(org)
                    .bind([8_u8;32].as_slice()).bind(&certificate.response).execute($pool).await.unwrap();
            }
            let mut tx = $pool.begin().await.unwrap();
            $append(&mut tx,case.organization.into_bytes(),b"retained issuance",123).await.unwrap();
            tx.commit().await.unwrap();
        }
    }};
}

macro_rules! pending {
    ($pool:expr) => {{
        let active: i64 =
            sqlx::query_scalar("SELECT activated FROM organization_user_ca_krl_activation")
                .fetch_one($pool)
                .await
                .unwrap();
        assert_eq!(active, 0);
        let verified: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_user_certificates WHERE valid_before IS NOT NULL",
        )
        .fetch_one($pool)
        .await
        .unwrap();
        assert_eq!(verified, 0);
        for table in ["organization_user_ca_revocations", "organization_user_ca_krls"] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one($pool)
                .await
                .unwrap();
            assert_eq!(count, 0);
        }
        let audit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one($pool).await.unwrap();
        assert_eq!(audit, 4);
    }};
}

macro_rules! activate {
    ($store:expr, $cases:expr) => {{
        let store = &$store;
        let last = $cases.last().unwrap();
        let certificate = &last.certificates[1];
        for corrupt in &last.corrupt_responses {
            sqlx::query("UPDATE organization_user_certificates SET response_json=$1 WHERE organization_id=$2 AND id=$3")
                .bind(corrupt).bind(last.organization.as_bytes().as_slice()).bind(certificate.id.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
            assert_eq!(store.initialize_organization_user_ca_krls().await,Err(OrganizationStoreError::StorageUnavailable));
            pending!(store.pool());
        }
        sqlx::query("UPDATE organization_user_certificates SET response_json=$1,serial=$2 WHERE organization_id=$3 AND id=$4")
            .bind(&certificate.response).bind(3_u64.to_be_bytes().as_slice()).bind(last.organization.as_bytes().as_slice()).bind(certificate.id.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE organization_user_cas SET last_serial=$1 WHERE organization_id=$2")
            .bind(3_u64.to_be_bytes().as_slice()).bind(last.organization.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
        assert_eq!(store.initialize_organization_user_ca_krls().await,Err(OrganizationStoreError::StorageUnavailable));
        pending!(store.pool());
        sqlx::query("UPDATE organization_user_certificates SET serial=$1 WHERE organization_id=$2 AND id=$3")
            .bind(2_u64.to_be_bytes().as_slice()).bind(last.organization.as_bytes().as_slice()).bind(certificate.id.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("UPDATE organization_user_cas SET last_serial=$1 WHERE organization_id=$2")
            .bind(2_u64.to_be_bytes().as_slice()).bind(last.organization.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
        store.initialize_organization_user_ca_krls().await.expect("repaired atomic activation");
    }};
}

macro_rules! preserved {
    ($store:expr, $identity:expr, $cases:expr) => {{
        let store = &$store;
        let identity = $identity;
        let active:i64 = sqlx::query_scalar("SELECT activated FROM organization_user_ca_krl_activation").fetch_one(store.pool()).await.unwrap();
        assert_eq!(active,1);
        let mut snapshots = Vec::new();
        for case in $cases {
            let org = case.organization.as_bytes().as_slice();
            let metadata:(String,i64,i64,Vec<u8>,Option<i64>) = sqlx::query_as("SELECT name,created_at_ms,updated_at_ms,view_revision,dissolved_at_ms FROM organizations WHERE id=$1")
                .bind(org).fetch_one(store.pool()).await.unwrap();
            assert_eq!(metadata,("Retained team".into(),123,456,17_u64.to_be_bytes().to_vec(),case.dissolved.then_some(789)));
            let ca:(Vec<u8>,Vec<u8>,Vec<u8>,i64) = sqlx::query_as("SELECT encrypted_seed,response_json,last_serial,created_at_ms FROM organization_user_cas WHERE organization_id=$1")
                .bind(org).fetch_one(store.pool()).await.unwrap();
            assert_eq!(ca,(case.encrypted.clone(),case.trust.to_json().unwrap(),2_u64.to_be_bytes().to_vec(),1));
            let membership:Option<String> = sqlx::query_scalar("SELECT status FROM organization_memberships WHERE organization_id=$1")
                .bind(org).fetch_optional(store.pool()).await.unwrap();
            assert_eq!(membership.as_deref(),case.membership);
            for certificate in &case.certificates {
                let issued:(Vec<u8>,Vec<u8>,i64) = sqlx::query_as("SELECT response_json,valid_before,created_at_ms FROM organization_user_certificates WHERE organization_id=$1 AND id=$2")
                    .bind(org).bind(certificate.id.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
                assert_eq!(issued,(certificate.response.clone(),certificate.expires.to_be_bytes().to_vec(),1));
                let receipt:(Vec<u8>,Vec<u8>,i64,i64) = sqlx::query_as("SELECT request_digest,response_json,created_at_ms,expires_at_ms FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2")
                    .bind(identity.account_id.as_bytes().as_slice()).bind(certificate.id.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
                assert_eq!(receipt,([8_u8;32].to_vec(),certificate.response.clone(),1,86_400_001));
            }
            let snapshot:(Vec<u8>,Vec<u8>,Vec<u8>) = sqlx::query_as("SELECT version,generated_at,snapshot FROM organization_user_ca_krls WHERE organization_id=$1")
                .bind(org).fetch_one(store.pool()).await.unwrap();
            let parsed = UserCaKrl::from_bytes(&snapshot.2,&case.trust.public_key).unwrap();
            let expected:Vec<u64> = if case.dissolved || case.membership!=Some("active") {vec![2]} else {vec![]};
            assert_eq!(parsed.revoked_serials(),expected);
            assert_eq!(parsed.version(),1);
            assert_eq!(snapshot.0,1_u64.to_be_bytes());
            assert_eq!(snapshot.1,parsed.generated_at_seconds().to_be_bytes());
            if !expected.is_empty() {
                let foreign = $cases.iter().find(|other|other.organization!=case.organization).unwrap();
                assert!(UserCaKrl::from_bytes(&snapshot.2,&foreign.trust.public_key).is_err(),"equal serials in independent CAs cannot transfer revocation trust");
            }
            let revoked:Vec<Vec<u8>> = sqlx::query_scalar("SELECT serial FROM organization_user_ca_revocations WHERE organization_id=$1 ORDER BY serial")
                .bind(org).fetch_all(store.pool()).await.unwrap();
            assert_eq!(revoked,expected.iter().map(|serial|serial.to_be_bytes().to_vec()).collect::<Vec<_>>());
            let events:Vec<Vec<u8>> = sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1 ORDER BY sequence")
                .bind(org).fetch_all(store.pool()).await.unwrap();
            assert_eq!(events.len(),2);
            assert_eq!(events[0],b"retained issuance");
            let activated:serde_json::Value = serde_json::from_slice(&events[1]).unwrap();
            assert_eq!(activated["action"],"organization.user_ca_krl_activated");
            store.verify_audit_chain(case.organization.into_bytes()).await.expect("preserved audit prefix");
            snapshots.push(snapshot);
        }
        let personal:Vec<u8> = sqlx::query_scalar("SELECT wrapped_vault_key FROM sync_personal_vaults WHERE account_id=$1")
            .bind(identity.account_id.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
        assert_eq!(personal,identity.wrapped_personal_vault_key);
        snapshots
    }};
}

macro_rules! retained {
    ($store:expr, $identity:expr, $snapshots:expr) => {{
        let store = &$store;
        sqlx::query("DELETE FROM identity_devices WHERE device_id=$1")
            .bind($identity.device_certificate.device_id.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
        let certificates:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_user_certificates").fetch_one(store.pool()).await.unwrap();
        assert_eq!(certificates,0,"Device-cascaded historical certificate rows");
        let revocations:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_user_ca_revocations").fetch_one(store.pool()).await.unwrap();
        assert_eq!(revocations,3,"CA-owned revocations outlive the issued Device");
        store.initialize_organization_user_ca_krls().await.unwrap();
        let snapshots:Vec<(Vec<u8>,Vec<u8>,Vec<u8>)> = sqlx::query_as("SELECT version,generated_at,snapshot FROM organization_user_ca_krls ORDER BY organization_id")
            .fetch_all(store.pool()).await.unwrap();
        assert_eq!(snapshots,$snapshots,"active stores never replay activation after identity deletion");
    }};
}

#[tokio::test]
async fn sqlite_krl_upgrade_verifies_signed_expiry_and_activates_atomically_once() {
    let directory = std::env::temp_dir().join(format!("scoplen-krl-migration-{}", Uuid::new_v4()));
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
    let identity = identity();
    legacy_identity::seed_sqlite(&pool, &identity, true).await;
    let cases = historical(&identity);
    populate!(&pool, &identity, &cases, scoplen_store::append_audit_event_in_transaction);
    pool.close().await;
    let store = SqliteStore::open(&path).await.unwrap();
    pending!(store.pool());
    activate!(store, cases);
    let snapshots = preserved!(store, &identity, &cases);
    store.initialize_organization_user_ca_krls().await.unwrap();
    assert_eq!(preserved!(store, &identity, &cases), snapshots);
    store.pool().close().await;
    let store = SqliteStore::open(&path).await.unwrap();
    assert_eq!(preserved!(store, &identity, &cases), snapshots);
    retained!(store, identity, snapshots);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_krl_upgrade_verifies_signed_expiry_and_activates_atomically_once() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let admin = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("user_ca_krl_migration_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < MIGRATION);
    old.run(&pool).await.unwrap();
    let identity = identity();
    legacy_identity::seed_postgres(&pool, &identity, true).await;
    let cases = historical(&identity);
    populate!(&pool, &identity, &cases, scoplen_store::append_audit_event_in_postgres_transaction);
    pool.close().await;
    let store = scoplen_store::PostgresStore::connect(url.as_str()).await.unwrap();
    pending!(store.pool());
    activate!(store, cases);
    let snapshots = preserved!(store, &identity, &cases);
    store.initialize_organization_user_ca_krls().await.unwrap();
    assert_eq!(preserved!(store, &identity, &cases), snapshots);
    store.pool().close().await;
    let store = scoplen_store::PostgresStore::connect(url.as_str()).await.unwrap();
    assert_eq!(preserved!(store, &identity, &cases), snapshots);
    retained!(store, identity, snapshots);
    store.pool().close().await;
    assert!(
        schema.starts_with("user_ca_krl_migration_")
            && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}
