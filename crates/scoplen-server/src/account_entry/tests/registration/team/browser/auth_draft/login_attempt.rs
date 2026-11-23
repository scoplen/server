// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the durable draft login boundary with real Account-browser families.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::auth_connection_draft::{
    DraftRequest,
    callback::{Callback, callback_path},
    test_login::{DraftLoginCredentials, DraftLoginStatus},
};
use scoplen_store::organizations::{
    OrganizationStoreError as Error,
    auth_draft_login::{
        DraftLoginClaim, DraftLoginMaterial, DraftLoginOutcome, DraftLoginProvider, DraftLoginStart,
    },
};

use super::*;

const ISSUER: &str = "https://identity.example.test/tenant/";
const TRUST: [u8; 32] = [13; 32];

fn trust(issuer: &str) -> Option<[u8; 32]> {
    (issuer == ISSUER).then_some(TRUST)
}

fn callback<'a>(
    path: &'a str,
    state: &SecretBytes<32>,
    cookie: &SecretBytes<32>,
    result: &str,
) -> Callback<'a> {
    let state = URL_SAFE_NO_PAD.encode(state.as_bytes());
    let cookie = URL_SAFE_NO_PAD.encode(cookie.as_bytes());
    Callback::parse("GET", path, &format!("state={state}&{result}"), [&cookie].into_iter()).unwrap()
}

#[allow(clippy::too_many_lines)]
async fn lifecycle(f: &Fixture) {
    let owner = actor(f, "draft-login-owner").await;
    let organization = create_team(f, &owner).await.id;
    let other_org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let other_browser = login(f, &owner.registration).await;
    let kms = test_kms();
    let token = AccountBrowserAccessToken::parse(&browser.access).unwrap();
    let other_token = AccountBrowserAccessToken::parse(&other_browser.access).unwrap();
    let provider = DraftLoginProvider {
        authorization_endpoint: format!("{ISSUER}authorize"),
        token_endpoint: format!("{ISSUER}token"),
        userinfo_endpoint: format!("{ISSUER}userinfo"),
        jwks_uri: format!("{ISSUER}jwks"),
        response_issuer_required: false,
    };
    let material = DraftLoginMaterial {
        credentials: DraftLoginCredentials::from_json(
            br#"{"client_id":" test client ","client_secret":"fixture secret"}"#,
        )
        .unwrap(),
        verifier: SecretBytes::new([14; 32]),
    };
    let path = callback_path(ISSUER).unwrap();
    let browser_binding = SecretBytes::new([15; 32]);
    let nonce = SecretBytes::new([16; 32]);
    let state = SecretBytes::new([17; 32]);
    let other_state = SecretBytes::new([18; 32]);
    let code = "code=fixture-code";
    let revision = f.revision(organization).await;

    macro_rules! verify {
        ($store:expr) => {{
            let store = $store;
            let session = store.current_account_browser_session(&token, ORIGIN).await.unwrap().unwrap();
            let other_session = store.current_account_browser_session(&other_token, ORIGIN).await.unwrap().unwrap();
            let draft = DraftRequest::Create(Uuid::now_v7(), DraftCreate { issuer: ISSUER.into() });
            let selected = store.organization_auth_draft(&session, 0, ORIGIN, organization, &draft).await.unwrap().unwrap();
            let another = store.organization_auth_draft(&session, 0, ORIGIN, other_org, &DraftRequest::Create(Uuid::now_v7(), DraftCreate { issuer: ISSUER.into() })).await.unwrap().unwrap();
            let tag = selected.etag();
            let other_tag = another.etag();
            let start = DraftLoginStart { organization, if_match: &tag, issuer: ISSUER, provider: &provider,
                trust_fingerprint: TRUST, state: &state, browser_binding: &browser_binding, nonce: &nonce, material: &material };
            let sibling = DraftLoginStart { organization: other_org, if_match: &other_tag, state: &other_state, ..start };
            let status = |attempt| store.organization_auth_draft_login_status(&session, organization, attempt);
            let initiate = || store.start_organization_auth_draft_login(&session, &start, trust, kms.as_ref());
            let claim = || store.claim_organization_auth_draft_login(ORIGIN, callback(&path, &state, &browser_binding, code), trust, kms.as_ref());
            let audit_count = f.count("SELECT count(*) FROM audit_events").await;
            f.audit_failure(true).await;
            assert_eq!(initiate().await, Err(Error::StorageUnavailable));
            f.audit_failure(false).await;
            assert_eq!(f.count("SELECT count(*) FROM organization_auth_draft_tests").await, 0);
            let attempt = initiate().await.unwrap();
            assert_eq!(attempt.draft_generation, selected.id);
            assert_eq!(status(attempt.id).await.unwrap(), attempt);
            assert_eq!(store.organization_auth_draft_login_status(&other_session, organization, attempt.id).await, Err(Error::NotFound));
            assert_eq!(store.start_organization_auth_draft_login(&session, &sibling, trust, kms.as_ref()).await, Err(Error::Conflict));
            assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit_count + 1);
            let change_role = |role: &str| sqlx::query("UPDATE organization_memberships SET roles_json=$1 WHERE organization_id=$2")
                .bind(format!("[\"{role}\"]")).bind(organization.as_bytes().as_slice()).execute(store.pool());
            change_role("member").await.unwrap();
            assert_eq!(status(attempt.id).await, Err(Error::PermissionDenied));
            assert!(matches!(claim().await, Err(Error::PermissionDenied)));
            change_role("owner").await.unwrap();
            let encrypted: Vec<u8> = sqlx::query_scalar("SELECT credentials FROM organization_auth_draft_tests")
                .fetch_one(store.pool()).await.unwrap();
            for raw in [material.credentials.client_id.as_bytes(), material.credentials.client_secret.as_bytes(), material.verifier.as_bytes().as_slice()] {
                assert!(!encrypted.windows(raw.len()).any(|window| window == raw));
            }
            for bad in [callback(&path, &other_state, &browser_binding, code), callback(&path, &state, &other_state, code)] {
                assert!(matches!(store.claim_organization_auth_draft_login(ORIGIN, bad, trust, kms.as_ref()).await, Err(Error::NotFound)));
            }
            assert!(matches!(store.claim_organization_auth_draft_login(ORIGIN, callback(&path, &state, &browser_binding, code), |_| Some([11; 32]), kms.as_ref()).await, Err(Error::NotFound)));
            let (a, b) = tokio::join!(claim(), claim());
            let ((Ok(DraftLoginClaim::Exchange(claimed)), Err(Error::NotFound))
                | (Err(Error::NotFound), Ok(DraftLoginClaim::Exchange(claimed)))) = (a, b) else {
                panic!("one concurrent callback may exchange");
            };
            assert_eq!(claimed.material, material);
            assert_eq!(claimed.code.as_bytes(), b"fixture-code");
            assert!(claimed.matches_nonce(&nonce));
            assert!(!claimed.matches_nonce(&state));
            assert_eq!(status(attempt.id).await.unwrap().status, DraftLoginStatus::Pending);
            assert_eq!(f.count("SELECT count(*) FROM organization_auth_draft_tests WHERE credentials IS NOT NULL").await, 0);
            assert_eq!(store.finish_organization_auth_draft_login(ORIGIN, &claimed, |_| None, DraftLoginOutcome::Verified).await, Err(Error::NotFound));
            f.audit_failure(true).await;
            assert_eq!(store.finish_organization_auth_draft_login(ORIGIN, &claimed, trust, DraftLoginOutcome::Verified).await, Err(Error::StorageUnavailable));
            assert_eq!(status(attempt.id).await.unwrap().status, DraftLoginStatus::Pending);
            f.audit_failure(false).await;
            store.finish_organization_auth_draft_login(ORIGIN, &claimed, trust, DraftLoginOutcome::Verified).await.unwrap();
            assert_eq!(status(attempt.id).await.unwrap().status, DraftLoginStatus::Verified);
            assert_eq!(store.finish_organization_auth_draft_login(ORIGIN, &claimed, trust, DraftLoginOutcome::Verified).await, Err(Error::NotFound));

            let denied = store.start_organization_auth_draft_login(&session, &sibling, trust, kms.as_ref()).await.unwrap();
            let done = store.claim_organization_auth_draft_login(ORIGIN, callback(&path, &other_state, &browser_binding, "error=access_denied"), trust, kms.as_ref()).await.unwrap();
            assert!(matches!(done, DraftLoginClaim::Denied));
            assert_eq!(store.organization_auth_draft_login_status(&session, other_org, denied.id).await.unwrap().status, DraftLoginStatus::Failed);
            assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit_count + 4);
            let event: Vec<u8> = sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1 ORDER BY sequence DESC LIMIT 1")
                .bind(other_org.as_bytes().as_slice()).fetch_one(store.pool()).await.unwrap();
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&event).unwrap(), serde_json::json!({
                "action":"organization.auth_draft_test_finished", "organization_id":other_org, "generation":another.id,
                "attempt_id":denied.id, "account_id":Uuid::from_bytes(session.account_id), "browser_family_id":Uuid::from_bytes(session.family_id),
                "status":"failed", "outcome":"failure", "reason":"provider_denied"
            }));

            f.execute("UPDATE organization_auth_draft_tests SET created_at_ms=1,expires_at_ms=300001").await;
            assert_eq!(status(attempt.id).await, Err(Error::NotFound));
            assert_eq!(store.cleanup_organization_auth_draft_logins().await.unwrap(), 2);
            let revoked = initiate().await.unwrap();
            sqlx::query("UPDATE account_browser_families SET revoked_at_ms=created_at_ms WHERE family_id=$1")
                .bind(session.family_id.as_slice()).execute(store.pool()).await.unwrap();
            assert_eq!(status(revoked.id).await, Err(Error::AuthenticationRequired));
            assert!(matches!(claim().await, Err(Error::NotFound)));
            store.organization_auth_draft(&other_session, 0, ORIGIN, organization, &DraftRequest::Cancel(Uuid::now_v7(), &tag)).await.unwrap();
            assert_eq!(f.count("SELECT count(*) FROM organization_auth_draft_tests").await, 0);
            assert!(matches!(claim().await, Err(Error::NotFound)));
        }};
    }
    match &f.backend {
        AuthBackend::Sqlite(store) => verify!(store),
        AuthBackend::Postgres(store) => verify!(store),
    }
    assert_eq!(f.revision(organization).await, revision);
}

browser_tests!(
    sqlite_draft_login_attempt_is_durable_and_single_use,
    postgres_draft_login_attempt_is_durable_and_single_use,
    lifecycle
);
