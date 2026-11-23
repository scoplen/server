// SPDX-License-Identifier: AGPL-3.0-only
//! Member-link behavior after PostgreSQL commits and its acknowledgement is lost.

use super::super::confirm_recovery::lose_commit_ack_at_write;
use super::*;
use crate::{
    account_entry::tests::{postgres_cleanup, postgres_fixture},
    test_lost_commit::LostCommitProxy,
};

fn assert_unconfirmed(reply: &Reply, provider: &Provider, retryable: bool) {
    changed_problem(reply, 503, "organization.commit_outcome_unknown", retryable);
    assert_eq!(reply.header("content-type"), Some("application/problem+json"));
    assert!(reply.header("etag").is_none() && reply.header("location").is_none());
    let value: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 8);
    let body = std::str::from_utf8(&reply.body).unwrap();
    assert!(!body.contains("authorization_url") && !body.contains(&provider.issuer));
}

#[tokio::test]
async fn postgres_member_link_https_lost_commits_preserve_writer_contract() {
    let (store, admin, schema, mut database) = postgres_fixture().await;
    let application = format!("link_receipt_{}", Uuid::new_v4().simple());
    database.query_pairs_mut().append_pair("application_name", &application);
    let proxy = LostCommitProxy::start(database.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let f = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let provider = Provider::start(f.directory.join("member-link-recovery"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(&f, provider.settings.clone()).await;
    let owner = actor(&f, "member-link-recovery").await;
    let org = create_team(&f, &owner).await;
    let original = login(&f, &owner.registration).await;
    let other_family = login(&f, &owner.registration).await;
    install_provider(&tls, &original, &provider, org.id).await;
    let context = LinkMembership { organization_id: org.id, membership_id: org.membership.id };
    let root = format!("/api/v1/orgs/{}/auth-link", org.id);
    let state = send(&tls, &original, "GET", &root, &[], &[]).await;
    let connection = SelfLinkStatus::from_http_json(&state.body, context, metadata(&state))
        .unwrap()
        .connection
        .unwrap();
    let start = format!("{root}/attempts");
    let tag = connection.etag();
    let headers = [("Origin", ORIGIN), ("If-Match", tag.as_str())];
    let audit = "SELECT count(*) FROM audit_events";
    let receipts = "SELECT count(*) FROM organization_auth_connection_receipts";
    let before = f.count(audit).await;
    let receipt_count = f.count(receipts).await;
    let unconfirmed_start = lose_commit_ack_at_write(
        store.pool(),
        &application,
        &proxy,
        "LOCK TABLE organization_auth_link_attempts IN SHARE MODE",
        "DELETE FROM organization_auth_link_attempts WHERE family_id=",
        send(&tls, &original, "POST", &start, &headers, &[]),
    )
    .await;
    assert_unconfirmed(&unconfirmed_start, &provider, false);
    send(&tls, &original, "POST", &start, &headers, &[]).await.problem(
        409,
        "organization.conflict",
        false,
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts WHERE phase='pending' AND verifier IS NOT NULL").await, 1);
    assert_eq!(f.count(audit).await, before + 1);
    assert_eq!(f.count(receipts).await, receipt_count);
    assert_eq!(provider.discoveries(), 1);
    assert_eq!(provider.counts(), [1, 1, 0]);

    let navigation = begin_link(&tls, &other_family, &provider, context).await;
    let name = navigation.cookie.split_once('=').unwrap().0;
    check_callback(&visit(&tls, &navigation.target, &navigation.cookie).await, Some(name));
    let key = Uuid::now_v7().to_string();
    let unconfirmed_confirm = lose_commit_ack_at_write(
        store.pool(),
        &application,
        &proxy,
        "LOCK TABLE organization_auth_connection_receipts IN SHARE MODE",
        "INSERT INTO organization_auth_connection_receipts ",
        confirm_link(&tls, &other_family, &navigation.attempt, &key),
    )
    .await;
    assert_unconfirmed(&unconfirmed_confirm, &provider, true);
    let state = send(&tls, &original, "GET", &root, &[], &[]).await;
    let current = SelfLinkStatus::from_http_json(&state.body, context, metadata(&state)).unwrap();
    let installed = current.status.link.unwrap();
    confirm_link(&tls, &original, &navigation.attempt, &key).await.problem(
        409,
        "organization.conflict",
        false,
    );
    confirm_link(&tls, &other_family, &navigation.attempt, &Uuid::now_v7().to_string())
        .await
        .problem(404, "organization.not_found", false);
    let recovered = confirm_link(&tls, &other_family, &navigation.attempt, &key).await;
    assert_eq!(recovered.status, 201);
    assert_eq!(
        MemberLink::from_http_json(&recovered.body, context, metadata(&recovered)).unwrap(),
        installed,
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts").await, 0);
    assert_eq!(f.count(receipts).await, receipt_count + 1);
    assert_eq!(f.count(audit).await, before + 4);
    assert_eq!(provider.counts(), [2, 2, 0]);
    provider.close().await;
    drop(tls);
    f.close().await;
    store.pool().close().await;
    drop(proxy);
    postgres_cleanup(admin, schema).await;
}
