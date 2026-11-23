// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate transitions retain no successful state without their Organization audit.

use scoplen_api::{
    auth_connection::{ActivationCandidate, ExpectedRevision},
    auth_connection_draft::{DraftCreate, DraftRequest, test_login::DraftLoginStatus},
};
use scoplen_store::organizations::{
    OrganizationStoreError as Error,
    auth_connection::{ActivationPreflight, ConnectionActivationStart},
    auth_draft_login::DraftLoginProvider,
};

use super::super::*;

async fn candidate_atomicity(f: &Fixture) {
    let owner = actor(f, "activation-atomic-owner").await;
    let organization = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let session = scope::current_session(f, &browser).await.unwrap();
    let kms = test_kms();
    let issuer = "https://identity.example.test/tenant";
    let provider = DraftLoginProvider {
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        userinfo_endpoint: format!("{issuer}/userinfo"),
        jwks_uri: format!("{issuer}/jwks"),
        response_issuer_required: true,
    };
    let fingerprint = [13; 32];
    let trust = |value: &str| (value == issuer).then_some(fingerprint);
    let draft = DraftRequest::Create(Uuid::now_v7(), DraftCreate { issuer: issuer.into() });
    let state = SecretBytes::new([21; 32]);
    let cookie = SecretBytes::new([22; 32]);
    let nonce = SecretBytes::new([23; 32]);
    let verifier = SecretBytes::new([24; 32]);
    macro_rules! verify {
        ($store:expr) => {{
            let store = $store;
            let draft_id = store.organization_auth_draft(&session, 0, ORIGIN, organization, &draft).await.unwrap().unwrap().id;
            let body = serde_json::json!({"draft_generation": draft_id,"space_id":"spc_Selected","client_id":"fixture-client","client_secret":"fixture-credential"});
            let candidate = ActivationCandidate::from_json(&serde_json::to_vec(&body).unwrap()).unwrap();
            let reserve = || store.reserve_organization_auth_activation(&session, organization, ExpectedRevision::Empty, draft_id);
            let initiate = async |preflight: &ActivationPreflight| {
                let start = ConnectionActivationStart {
                    preflight, candidate: &candidate, provider: &provider,
                    trust_fingerprint: fingerprint, state: &state, browser_binding: &cookie, nonce: &nonce, verifier: &verifier,
                };
                store.start_organization_auth_activation(&session, &start, trust, kms.as_ref()).await
            };
            let preflight = reserve().await.unwrap();
            let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
            f.audit_failure(true).await;
            assert_eq!(initiate(&preflight).await, Err(Error::StorageUnavailable));
            f.audit_failure(false).await;
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connection_activations").await, 0);
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_activation_preflights").await, 1);
            assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
            let active = initiate(&preflight).await.unwrap();
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_activation_preflights").await, 0);
            let abandon = || store.abandon_organization_auth_activation(&session, organization, active.id);
            let status = || store.organization_auth_activation_status(&session, organization, active.id, trust);
            let cleanup = || store.cleanup_organization_auth_activations();
            assert_eq!(cleanup().await, Ok(0));
            let obsolete = store.organization_auth_activation_status(&session, organization, active.id, |_|Some([3; 32])).await;
            assert_eq!(obsolete, Err(Error::NotFound));

            f.audit_failure(true).await;
            assert_eq!(abandon().await, Err(Error::StorageUnavailable));
            f.audit_failure(false).await;
            assert_eq!(status().await.unwrap().status, DraftLoginStatus::Pending);
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connection_activations WHERE credential IS NOT NULL AND verifier IS NOT NULL").await, 1);
            assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 1);
            abandon().await.unwrap();
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connection_activations").await, 0);
            assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 2);
            let event: Vec<u8> = sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1 ORDER BY sequence DESC LIMIT 1")
                .bind(organization.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&event).unwrap(), serde_json::json!({
                "action":"organization.auth_activation_abandoned","organization_id": organization,"account_id": Uuid::from_bytes(session.account_id),
                "browser_family_id": Uuid::from_bytes(session.family_id),"attempt_id": active.id,"draft_generation": draft_id,"expected_revision": null
            }));
            let abandoned_preflight = reserve().await.unwrap();
            f.execute("UPDATE organization_auth_activation_preflights SET expires_at_ms=1").await;
            let current_preflight = reserve().await.unwrap();
            store.release_organization_auth_activation(&abandoned_preflight).await.unwrap();
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_activation_preflights").await, 1);
            assert_eq!(initiate(&abandoned_preflight).await, Err(Error::Conflict));
            let expired = initiate(&current_preflight).await.unwrap();
            f.execute("UPDATE organization_auth_connection_activations SET created_at_ms=1,expires_at_ms=300001").await;
            assert_eq!(store.organization_auth_activation_status(&session, organization, expired.id, trust).await, Err(Error::NotFound));
            assert_eq!(store.abandon_organization_auth_activation(&session, organization, expired.id).await, Err(Error::NotFound));
            assert_eq!(cleanup().await, Ok(1));
            let _orphaned = reserve().await.unwrap();
            f.execute("UPDATE organization_auth_activation_preflights SET expires_at_ms=1").await;
            assert_eq!(cleanup().await, Ok(0));
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_activation_preflights").await, 0);
            assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connections").await, 0);
        }};
    }
    match &f.backend {
        AuthBackend::Sqlite(store) => verify!(store),
        AuthBackend::Postgres(store) => verify!(store),
    }
}

browser_tests!(
    sqlite_activation_candidate_audit_rollback_and_expired_material_cleanup,
    postgres_activation_candidate_audit_rollback_and_expired_material_cleanup,
    candidate_atomicity
);
