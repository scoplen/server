// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::{account_profile::AccountProfile, auth::INITIAL_DEVICE_ACCESS_SCOPE};
use scoplen_crypto::{DeviceAccessToken, DeviceAccessTokenClaims, TrustedDeviceAccessTokenKeys};
use scoplen_store::device_authentication::{CurrentPrincipal, DeviceAuthenticationError};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const PATH: &str = "/api/v1/accounts/me";

fn decode(reply: &Reply) -> AccountProfile {
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    reply.privacy();
    let profile = AccountProfile::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("bounded account Resource and HTTP metadata");
    let value: serde_json::Value = serde_json::from_slice(&reply.body).expect("profile JSON");
    assert_eq!(value.as_object().expect("Resource").len(), 5);
    assert_eq!(value["data"].as_object().expect("account data").len(), 1);
    assert!(value["data"].get("email").is_some());
    profile
}

fn denied(reply: &Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "profile failure status");
    let problem: ProblemDetails = serde_json::from_slice(&reply.body).expect("profile problem");
    assert_eq!(problem.code.as_str(), code);
    assert!(!problem.changed);
    assert_eq!(problem.retryable, status == 503);
    assert!(reply.header("etag").is_none());
    assert!(!reply.text().contains("email"));
    assert!(!reply.text().contains("private@example.com"));
    reply.privacy();
}

pub(super) async fn signed_token(
    f: &Fixture,
    identity: &LegacyDeviceSession,
    account: Uuid,
    device: Uuid,
    scope: &str,
) -> String {
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let keyring = f.backend.keyring(&kms).await.expect("current signing keys");
    let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("verification key");
    }
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("clock");
    let claims = DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: account,
        did: device,
        jti: Uuid::now_v7(),
        cnf_jkt: dpop_jwk_thumbprint(&identity.client.public_key_sec1()).expect("JKT"),
        org: vec![],
        scope: scope.into(),
        iat: now,
        exp: now + 600,
    };
    DeviceAccessToken::sign(
        keyring.signing_key(),
        &trusted,
        keyring.signing_key().kid(),
        &identity.client.public_key_sec1(),
        &claims,
    )
    .expect("signed test credential")
    .as_str()
    .to_owned()
}

pub(super) fn proof_for(
    identity: &LegacyDeviceSession,
    method: &str,
    path: &str,
    token: &str,
) -> DpopProof {
    DpopProof::sign(
        &identity.client,
        &identity.client.public_key_sec1(),
        &DpopTarget::new(method, ORIGIN, path).expect("target"),
        DpopToken::Protected(token),
        u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("request proof")
}

async fn set_email(f: &Fixture, email: Option<&str>) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("UPDATE identity_accounts SET email=?")
                .bind(email)
                .execute(store.pool())
                .await
                .expect("stored email fixture");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("UPDATE identity_accounts SET email=$1")
                .bind(email)
                .execute(store.pool())
                .await
                .expect("stored email fixture");
        }
    }
}

async fn store_read(
    f: &Fixture,
    expected: &CurrentPrincipal,
) -> Result<AccountProfile, DeviceAuthenticationError> {
    match &f.backend {
        AuthBackend::Sqlite(store) => store.read_account_profile(expected).await,
        AuthBackend::Postgres(store) => store.read_account_profile(expected).await,
    }
}

async fn profile_roundtrip(f: &Fixture, identity: &LegacyDeviceSession) {
    let first = protected(f, "GET", PATH, &[], &identity.token, &identity.client).await;
    let profile = decode(&first);
    assert_eq!(profile.id, identity.receipt.account_id);
    assert!(profile.email.is_none());
    let created = f.count("SELECT created_at_ms FROM identity_accounts").await;
    let expected = OffsetDateTime::from_unix_timestamp_nanos(i128::from(created) * 1_000_000)
        .expect("persistent timestamp")
        .format(&Rfc3339)
        .expect("UTC timestamp");
    assert_eq!(profile.created_at, expected);
    assert_eq!(profile.updated_at, expected);
    let second = protected(f, "GET", PATH, &[], &identity.token, &identity.client).await;
    assert_eq!(first.body, second.body);
    let query = format!("{PATH}?account_id={}", Uuid::now_v7());
    let queried = protected(f, "GET", &query, &[], &identity.token, &identity.client).await;
    assert_eq!(decode(&queried).id, identity.receipt.account_id);
    let email = "Case+\u{00fc}@Example.COM";
    set_email(f, Some(email)).await;
    let reply = protected(f, "GET", PATH, &[], &identity.token, &identity.client).await;
    let populated = decode(&reply);
    assert!(populated.email.as_deref().is_some_and(|value| value == email));
    assert_ne!(populated.etag, profile.etag);
    assert!(!format!("{populated:?}").contains(email));
    for email in ["\u{00e9}".repeat(160), "\\\"".repeat(160)] {
        set_email(f, Some(&email)).await;
        let reply = protected(f, "GET", PATH, &[], &identity.token, &identity.client).await;
        assert!(decode(&reply).email.as_deref().is_some_and(|value| value == email));
    }
    set_email(f, None).await;
    let reply = protected(f, "GET", PATH, &[], &identity.token, &identity.client).await;
    assert_eq!(decode(&reply).etag, profile.etag);
}

async fn rejected_credentials(f: &Fixture, identity: &LegacyDeviceSession) {
    denied(
        &http_method(f.address, "GET", PATH, &[], &[]).await,
        401,
        "auth.authentication_required",
    );
    let operator =
        protected(f, "GET", PATH, &[], &identity.operator_token, &identity.operator_key).await;
    denied(&operator, 401, "auth.authentication_required");
    for (account, device, scope, status) in [
        (identity.receipt.account_id, identity.receipt.device_id, "sync:read", 403),
        (identity.receipt.account_id, identity.receipt.device_id, "sync:write", 403),
        (Uuid::now_v7(), identity.receipt.device_id, INITIAL_DEVICE_ACCESS_SCOPE, 401),
        (identity.receipt.account_id, Uuid::now_v7(), INITIAL_DEVICE_ACCESS_SCOPE, 401),
    ] {
        let token = signed_token(f, identity, account, device, scope).await;
        denied(
            &protected(f, "GET", PATH, &[], &token, &identity.client).await,
            status,
            if status == 403 { "policy.denied" } else { "auth.authentication_required" },
        );
    }
    let authorization = format!("DPoP {}", identity.token);
    for proof in [
        proof_for(identity, "POST", PATH, &identity.token),
        proof_for(identity, "GET", "/sync/v1/keys", &identity.token),
        proof_for(identity, "GET", PATH, "different-access-token"),
    ] {
        denied(
            &http_method(
                f.address,
                "GET",
                PATH,
                &[],
                &[("Authorization", &authorization), ("DPoP", proof.as_str())],
            )
            .await,
            401,
            "auth.authentication_required",
        );
    }
    let proof = proof_for(identity, "GET", PATH, &identity.token);
    let headers = [("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
    decode(&http_method(f.address, "GET", PATH, &[], &headers).await);
    denied(
        &http_method(f.address, "GET", PATH, &[], &headers).await,
        401,
        "auth.authentication_required",
    );
    for duplicate in ["Authorization", "DPoP"] {
        let proof = proof_for(identity, "GET", PATH, &identity.token);
        let mut submitted =
            vec![("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
        submitted.push((
            duplicate,
            if duplicate == "DPoP" { proof.as_str() } else { authorization.as_str() },
        ));
        denied(
            &http_method(f.address, "GET", PATH, &[], &submitted).await,
            401,
            "auth.authentication_required",
        );
    }
    for extra in [
        vec![("Origin", "null")],
        vec![("Origin", "https://other.example")],
        vec![("Origin", ORIGIN), ("Origin", ORIGIN)],
    ] {
        let mut headers = headers.to_vec();
        headers.extend(extra);
        denied(&http_method(f.address, "GET", PATH, &[], &headers).await, 403, "policy.denied");
    }
    denied(
        &protected(f, "GET", PATH, b"{}", &identity.token, &identity.client).await,
        400,
        "auth.invalid_request",
    );
}

async fn invalid_profile_data(f: &Fixture, identity: &LegacyDeviceSession) {
    for invalid in [
        String::new(),
        "bad address@example.com".into(),
        "bad\u{2003}address@example.com".into(),
        "bad\u{7f}address@example.com".into(),
        "x".repeat(321),
        "\u{00e9}".repeat(161),
    ] {
        set_email(f, Some(&invalid)).await;
        let reply = protected(f, "GET", PATH, &[], &identity.token, &identity.client).await;
        denied(&reply, 503, "auth.storage_unavailable");
        if !invalid.is_empty() {
            assert!(!reply.text().contains(&invalid));
        }
    }
    // Scope denial precedes reading even a corrupt profile.
    let narrow = signed_token(
        f,
        identity,
        identity.receipt.account_id,
        identity.receipt.device_id,
        "sync:read",
    )
    .await;
    denied(&protected(f, "GET", PATH, &[], &narrow, &identity.client).await, 403, "policy.denied");
    set_email(f, Some("private@example.com")).await;
    let created = f.count("SELECT created_at_ms FROM identity_accounts").await;
    f.execute("UPDATE identity_accounts SET created_at_ms=9223372036854775807").await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    f.execute(&format!("UPDATE identity_accounts SET created_at_ms={created}")).await;
    f.execute("ALTER TABLE identity_accounts RENAME COLUMN email TO unavailable_email").await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    denied(&protected(f, "GET", PATH, &[], &narrow, &identity.client).await, 403, "policy.denied");
    f.execute("ALTER TABLE identity_accounts RENAME COLUMN unavailable_email TO email").await;
}

async fn stale_identity(f: &Fixture, identity: &LegacyDeviceSession) {
    let mut principal = f
        .backend
        .current_principal(identity.receipt.device_id.into_bytes())
        .await
        .expect("current identity")
        .expect("enrolled");
    principal.account_id = Uuid::now_v7().into_bytes();
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    principal.account_id = identity.receipt.account_id.into_bytes();
    principal.jkt = "different-proof-key".into();
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    let principal = f
        .backend
        .current_principal(identity.receipt.device_id.into_bytes())
        .await
        .expect("current identity")
        .expect("enrolled");
    f.execute("UPDATE identity_devices SET active=false").await;
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
    f.execute("UPDATE identity_devices SET active=true").await;
    let revocation = scoplen_crypto::RevocationStatement::issue(
        &Ed25519SigningKey::from_bytes(&[7; 32]).expect("account signing key"),
        identity.receipt.device_id,
        1,
        "profile test revocation".into(),
    )
    .expect("signed revocation")
    .encode()
    .expect("revocation CBOR");
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            let certificate: Vec<u8> =
                sqlx::query_scalar("SELECT certificate FROM identity_devices")
                    .fetch_one(store.pool())
                    .await
                    .expect("enrolled certificate");
            store
                .replace_account_key_statements(
                    identity.receipt.account_id.into_bytes(),
                    &[certificate],
                    &[revocation],
                )
                .await
                .expect("publish revocation");
        }
        AuthBackend::Postgres(store) => {
            let certificate: Vec<u8> =
                sqlx::query_scalar("SELECT certificate FROM identity_devices")
                    .fetch_one(store.pool())
                    .await
                    .expect("enrolled certificate");
            store
                .replace_account_key_statements(
                    identity.receipt.account_id.into_bytes(),
                    &[certificate],
                    &[revocation],
                )
                .await
                .expect("publish revocation");
        }
    }
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    f.execute("DELETE FROM sync_account_key_certificates").await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
}

async fn profile_contract(mut f: Fixture) {
    let identity = legacy_device_session(&mut f).await;
    profile_roundtrip(&f, &identity).await;
    rejected_credentials(&f, &identity).await;
    invalid_profile_data(&f, &identity).await;
    stale_identity(&f, &identity).await;
    match &f.backend {
        AuthBackend::Sqlite(store) => store.pool().close().await,
        AuthBackend::Postgres(store) => store.pool().close().await,
    }
    denied(
        &protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_current_account_profile_contract() {
    profile_contract(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_current_account_profile_contract() {
    profile_contract(Fixture::postgres().await).await;
}
