// SPDX-License-Identifier: AGPL-3.0-only
//! Suspension commits authority, credential retirement, audit and its receipt together.

use axum::body::Body;
use scoplen_api::auth_connection::{ConnectionResource, ConnectionStatus};

use super::super::tls::TlsFixture;
use super::{auth_connection::seed_active_connection, *};

async fn suspend(tls: &TlsFixture, browser: &Browser, path: &str, tag: &str, key: Uuid) -> Reply {
    let request = TlsFixture::signed(&browser.key, &browser.access, "POST", path)
        .header("Origin", ORIGIN)
        .header("If-Match", tag)
        .header("Idempotency-Key", key.to_string())
        .body(Body::empty())
        .unwrap();
    tls.send(request).await
}

async fn read(tls: &TlsFixture, browser: &Browser, path: &str) -> Reply {
    let request =
        TlsFixture::signed(&browser.key, &browser.access, "GET", path).body(Body::empty()).unwrap();
    tls.send(request).await
}

fn connection(reply: &Reply, organization: Uuid, status: ConnectionStatus) -> ConnectionResource {
    assert_eq!(reply.status, 200);
    ConnectionResource::from_http_json(
        &reply.body,
        organization,
        Some(status),
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

#[allow(clippy::too_many_lines)]
async fn suspension_atomic(f: &Fixture) {
    let owner = actor(f, "connection-atomic-owner").await;
    let organization = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let tls = TlsFixture::start(f).await;
    let issuer = "https://issuer.example.test/tenant/";
    let original = seed_active_connection(f, organization, issuer).await;
    let path = format!("/api/v1/orgs/{organization}/auth-connection");
    let operation = format!("{path}/suspend");
    let tag = format!("\"{original}\"");
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();

    // A current replacement exists before suspension. Its secrets must survive rollback only.
    f.execute(
        "INSERT INTO organization_auth_drafts (organization_id,generation,issuer,created_at_ms)
        SELECT organization_id,revision,issuer,created_at_ms FROM organization_auth_connections",
    )
    .await;
    f.execute("INSERT INTO organization_auth_connection_activations
        (id,organization_id,draft_generation,expected_revision,family_id,state_digest,browser_digest,
         nonce_digest,trust_fingerprint,issuer,client_id,space_id,provider,phase,credential,verifier,
         created_at_ms,expires_at_ms)
        SELECT d.generation,d.organization_id,d.generation,a.revision,f.family_id,a.trust_fingerprint,
          a.trust_fingerprint,a.trust_fingerprint,a.trust_fingerprint,a.issuer,a.client_id,a.space_id,
          a.provider,'pending',a.credential,a.credential,f.created_at_ms,f.created_at_ms+300000
        FROM organization_auth_drafts d JOIN organization_auth_connections a USING (organization_id)
        CROSS JOIN account_browser_families f")
        .await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    f.audit_failure(true).await;
    problem(
        &suspend(&tls, &browser, &operation, &tag, first).await,
        503,
        "organization.storage_unavailable",
    );
    f.audit_failure(false).await;
    f.receipt_commit_failure(true, "organization_auth_connection_receipts").await;
    let unknown = suspend(&tls, &browser, &operation, &tag, first).await;
    changed_problem(&unknown, 503, "organization.commit_outcome_unknown", true);
    assert!(unknown.header("etag").is_none());
    f.receipt_commit_failure(false, "organization_auth_connection_receipts").await;
    assert_eq!(
        connection(&read(&tls, &browser, &path).await, organization, ConnectionStatus::Active).id,
        original
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connection_receipts").await, 0);
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM organization_auth_connection_activations
                 WHERE credential IS NOT NULL AND verifier IS NOT NULL"
        )
        .await,
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);

    let (a, b) = tokio::join!(
        suspend(&tls, &browser, &operation, &tag, first),
        suspend(&tls, &browser, &operation, &tag, second),
    );
    let (committed, stale, key) = if a.status == 200 { (a, b, first) } else { (b, a, second) };
    let suspended = connection(&committed, organization, ConnectionStatus::Suspended);
    assert_ne!(suspended.id, original);
    problem(&stale, 412, "organization.precondition_failed");
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connection_activations").await, 0);
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM organization_auth_connections
                 WHERE credential IS NULL AND trust_fingerprint IS NULL AND provider IS NULL"
        )
        .await,
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_connection_receipts").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 1);

    // A later fixture revision is visible to GET alone. Exact recovery returns only the
    // original suspension, provided the original writer still has authority.
    f.execute("DELETE FROM organization_auth_connections").await;
    let later = seed_active_connection(f, organization, issuer).await;
    let replay = suspend(&tls, &browser, &operation, &tag, key).await;
    assert_eq!(replay.body, committed.body);
    assert_eq!(replay.header("etag"), committed.header("etag"));
    let policy_payload = match &f.backend {
        AuthBackend::Sqlite(_) => "X'7b7d'",
        AuthBackend::Postgres(_) => "decode('7b7d','hex')",
    };
    f.execute(&format!(
        "INSERT INTO organization_policies
        (organization_id,id,name,source,enabled,response_json,created_at_ms,updated_at_ms)
        SELECT organization_id,generation,'Connection test forbid',
          'forbid(principal, action == Action::\"manage_organization\", resource);',
          1,{policy_payload},created_at_ms,created_at_ms FROM organization_auth_drafts"
    ))
    .await;
    problem(&read(&tls, &browser, &path).await, 403, "policy.denied");
    problem(&suspend(&tls, &browser, &operation, &tag, key).await, 403, "policy.denied");
    f.execute("DELETE FROM organization_policies").await;
    f.execute("UPDATE organization_memberships SET roles_json='[\"administrator\"]'").await;
    problem(&read(&tls, &browser, &path).await, 403, "policy.denied");
    problem(&suspend(&tls, &browser, &operation, &tag, key).await, 403, "policy.denied");
    f.execute("UPDATE organization_memberships SET roles_json='[\"owner\"]'").await;

    f.execute(
        "UPDATE organization_auth_connection_receipts SET created_at_ms=1,expires_at_ms=86400001",
    )
    .await;
    let retired = match &f.backend {
        AuthBackend::Sqlite(store) => store.cleanup_organization_creation_receipts().await,
        AuthBackend::Postgres(store) => store.cleanup_organization_creation_receipts().await,
    };
    assert_eq!(retired.unwrap(), 1);
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM organization_auth_connection_receipts
                 WHERE response_json IS NULL AND request_digest IS NULL AND expires_at_ms IS NULL"
        )
        .await,
        1
    );
    problem(&suspend(&tls, &browser, &operation, &tag, key).await, 409, "organization.conflict");
    let current =
        connection(&read(&tls, &browser, &path).await, organization, ConnectionStatus::Active);
    assert_eq!(current.id, later);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 1);
}

browser_tests!(
    sqlite_auth_connection_suspension_rolls_back_and_serializes,
    postgres_auth_connection_suspension_rolls_back_and_serializes,
    suspension_atomic
);
