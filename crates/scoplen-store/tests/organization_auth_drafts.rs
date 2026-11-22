// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
mod support;

use legacy_identity::LegacyIdentity;
use scoplen_api::{
    auth_connection_draft::{DraftCreate, DraftRequest},
    organization::OrganizationCreateRequest,
};
use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
#[cfg(feature = "postgres-integration")]
use scoplen_store::PostgresStore;
use scoplen_store::{
    RelationalStore as _, SqliteStore, organizations::OrganizationStoreError as Error,
};
use uuid::Uuid;

const ORIGIN: &str = "https://drafts.example.test";
const ISSUER: &str = "https://issuer.example.test/Tenant/%41/";

fn create(key: Uuid, issuer: &str) -> DraftRequest<'static> {
    DraftRequest::Create(key, DraftCreate { issuer: issuer.into() })
}

macro_rules! check_drafts {
    ($store:expr, $seed:ident, $postgres:literal) => {{
        let store = $store;
        let identity = LegacyIdentity::new(
            &Ed25519SigningKey::from_bytes(&[1; 32]).unwrap(),
            &P256SigningKey::from_bytes(&[2; 32]).unwrap(),
        );
        legacy_identity::$seed(store.pool(), &identity, true).await;
        let actor = store
            .current_device_principal(identity.device_certificate.device_id.into_bytes())
            .await
            .unwrap()
            .unwrap();
        let org = store
            .create_organization(
                &actor,
                u64::MAX,
                true,
                Uuid::now_v7(),
                &OrganizationCreateRequest::new("Draft team").unwrap(),
            )
            .await
            .unwrap()
            .id;

        for (generation, issuer) in [
            (Uuid::new_v4(), ISSUER.to_owned()),
            (Uuid::now_v7(), "é".repeat(1025)),
        ] {
            let error = sqlx::query("INSERT INTO organization_auth_drafts (organization_id,generation,issuer,created_at_ms) VALUES ($1,$2,$3,1)")
                .bind(org.as_bytes().as_slice()).bind(generation.as_bytes().as_slice()).bind(issuer)
                .execute(store.pool()).await.expect_err("invalid generation or issuer byte length");
            assert!(error.as_database_error().is_some_and(|e| e.is_check_violation()));
        }
        let read = DraftRequest::Read;
        let key = Uuid::now_v7();
        let create_original = create(key, ISSUER);
        let create_other = create(Uuid::now_v7(), ISSUER);
        macro_rules! request {
            ($req:expr) => {
                store.organization_auth_draft(&actor, u64::MAX, ORIGIN, org, $req)
            };
        }
        assert_eq!(request!(&read).await, Err(Error::NotFound));
        let (a, b) = tokio::join!(request!(&create_original), request!(&create_other));
        let (winner, original) = match (a, b) {
            (Ok(Some(value)), Err(Error::PreconditionFailed)) => (&create_original, value),
            (Err(Error::PreconditionFailed), Ok(Some(value))) => (&create_other, value),
            _ => panic!("exactly one racing create must commit"),
        };
        let DraftRequest::Create(winning_key, _) = winner else { unreachable!() };
        assert_eq!(original.issuer, ISSUER);
        assert_eq!(request!(&read).await.unwrap().as_ref(), Some(&original));
        let changed = create(*winning_key, "https://issuer.example.test/other");
        assert_eq!(request!(&changed).await, Err(Error::Conflict));
        let tag = original.etag();
        let cancel = DraftRequest::Cancel(Uuid::now_v7(), &tag);
        assert_eq!(request!(&DraftRequest::Cancel(*winning_key, &tag)).await, Err(Error::Conflict));
        assert_eq!(request!(&cancel).await, Ok(None));
        assert_eq!(request!(winner).await, Ok(Some(original.clone())));
        assert_eq!(request!(&read).await, Err(Error::NotFound));
        let replacement = request!(&create(Uuid::now_v7(), ISSUER)).await.unwrap().unwrap();
        assert_ne!(replacement.id, original.id);
        assert_eq!(request!(&cancel).await, Ok(None));
        assert_eq!(
            request!(&DraftRequest::Cancel(Uuid::now_v7(), &tag)).await,
            Err(Error::PreconditionFailed)
        );
        assert_eq!(request!(&read).await.unwrap().as_ref(), Some(&replacement));

        let policy = Uuid::now_v7();
        let permit = "permit(principal, action == Action::\"manage_organization\", resource);";
        let forbid = "forbid(principal, action == Action::\"manage_organization\", resource);";
        sqlx::query("INSERT INTO organization_policies (organization_id,id,name,source,enabled,response_json,created_at_ms,updated_at_ms) VALUES ($1,$2,'Draft policy',$3,1,$4,1,1)")
        .bind(org.as_bytes().as_slice()).bind(policy.as_bytes().as_slice()).bind(forbid).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        assert_eq!(request!(winner).await, Err(Error::PermissionDenied));
        sqlx::query("UPDATE organization_policies SET source=$1 WHERE id=$2")
            .bind(permit)
            .bind(policy.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .unwrap();
        for role in ["member", "security_auditor", "approver", "administrator"] {
            sqlx::query("UPDATE organization_memberships SET roles_json=$1 WHERE organization_id=$2 AND account_id=$3")
            .bind(serde_json::json!([role]).to_string()).bind(org.as_bytes().as_slice()).bind(actor.account_id.as_slice()).execute(store.pool()).await.unwrap();
            if role == "administrator" {
                assert_eq!(request!(winner).await, Ok(Some(original.clone())));
            } else {
                assert_eq!(request!(&read).await, Err(Error::PermissionDenied));
                assert_eq!(request!(winner).await, Err(Error::PermissionDenied));
            }
        }
        let foreign = Uuid::now_v7();
        assert_eq!(
            store.organization_auth_draft(&actor, u64::MAX, ORIGIN, foreign, winner).await,
            Err(Error::NotFound)
        );
        assert_eq!(
            store.organization_auth_draft(&actor, 1, ORIGIN, org, winner).await,
            Err(Error::AuthenticationRequired)
        );

        let replacement_tag = replacement.etag();
        let cancel_replacement = DraftRequest::Cancel(Uuid::now_v7(), &replacement_tag);
        if $postgres {
            sqlx::query("CREATE FUNCTION fail_draft_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END; $$").execute(store.pool()).await.unwrap();
            sqlx::query("CREATE TRIGGER fail_draft_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_draft_audit()").execute(store.pool()).await.unwrap();
        } else {
            sqlx::query("CREATE TRIGGER fail_draft_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture'); END").execute(store.pool()).await.unwrap();
        }
        assert_eq!(request!(&cancel_replacement).await, Err(Error::StorageUnavailable));
        assert_eq!(request!(&read).await.unwrap().as_ref(), Some(&replacement));
        let drop_trigger = if $postgres {
            "DROP TRIGGER fail_draft_audit ON audit_events"
        } else {
            "DROP TRIGGER fail_draft_audit"
        };
        sqlx::query(drop_trigger).execute(store.pool()).await.unwrap();
        assert_eq!(request!(&cancel_replacement).await, Ok(None));

        sqlx::query("UPDATE organization_auth_draft_receipts SET created_at_ms=1,expires_at_ms=86400001 WHERE idempotency_key=$1")
        .bind(winning_key.as_bytes().as_slice()).execute(store.pool()).await.unwrap();
        assert_eq!(request!(winner).await, Err(Error::Conflict));
        assert_eq!(store.cleanup_organization_creation_receipts().await.unwrap(), 1);
        assert_eq!(store.cleanup_organization_creation_receipts().await.unwrap(), 0);
        let removed: (Option<Vec<u8>>,Option<Vec<u8>>,Option<i64>) = sqlx::query_as("SELECT generation,request_digest,created_at_ms FROM organization_auth_draft_receipts WHERE idempotency_key=$1")
        .bind(winning_key.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
        assert_eq!(removed, (None, None, None));
        assert_eq!(request!(winner).await, Err(Error::Conflict));
        assert_eq!(request!(&read).await, Err(Error::NotFound));

        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event_bytes FROM audit_events WHERE organization_id=$1 ORDER BY sequence",
        )
        .bind(org.as_bytes().as_slice())
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert_eq!(rows.len(), 5, "team creation and four confirmed slot mutations");
        for (i, bytes) in rows[1..].iter().enumerate() {
            let event: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            let action = if i % 2 == 0 {
                "organization.auth_draft_created"
            } else {
                "organization.auth_draft_cancelled"
            };
            let generation = if i < 2 { original.id } else { replacement.id };
            assert_eq!(
                event,
                serde_json::json!({"action":action,"account_id":identity.account_id,
            "device_id":identity.device_certificate.device_id,"organization_id":org,"generation":generation})
            );
        }
        assert!(
            store
                .organization_auth_draft(&actor, u64::MAX, "https://another.example.test", org, winner)
                .await
                .unwrap()
                .is_some(),
            "the same key belongs to an independent trusted origin namespace"
        );
    }};
}

#[tokio::test]
async fn sqlite_drafts_serialize_authorize_replay_retire_and_roll_back() {
    let directory = std::env::temp_dir().join(format!("scoplen-draft-{}", Uuid::new_v4()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    check_drafts!(&store, seed_sqlite, false);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_drafts_serialize_authorize_replay_retire_and_roll_back() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned database");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin");
    let schema = format!("organization_draft_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.unwrap();
    check_drafts!(&store, seed_postgres, true);
    store.pool().close().await;
    assert!(
        schema.starts_with("organization_draft_")
            && schema.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    admin.close().await;
}
