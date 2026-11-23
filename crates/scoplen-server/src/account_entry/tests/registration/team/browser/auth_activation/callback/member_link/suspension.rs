// SPDX-License-Identifier: AGPL-3.0-only
//! Suspension fences a member-link exchange which already reached the issuer.

use super::*;

async fn wait_for_exchange(gate: &TokenResponseGate) {
    tokio::time::timeout(Duration::from_secs(6), gate.request_received.notified())
        .await
        .expect("provider received the token exchange");
}

async fn suspend_during_exchange(f: &Fixture) {
    let gate = Arc::new(TokenResponseGate::default());
    let provider = Provider::start_with_token_gate(
        f.directory.join("member-link-suspension"),
        ORIGIN,
        Some(gate.clone()),
    )
    .await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "member-link-suspension").await;
    let org = create_team(f, &owner).await;
    let browser = login(f, &owner.registration).await;
    tokio::join!(install_provider(&tls, &browser, &provider, org.id), async {
        wait_for_exchange(&gate).await;
        gate.release_response.notify_one();
    });

    let context = LinkMembership { organization_id: org.id, membership_id: org.membership.id };
    let navigation = begin_link(&tls, &browser, &provider, context).await;
    let audit = "SELECT count(*) FROM audit_events";
    let before = f.count(audit).await;
    let (callback, ()) = tokio::join!(visit(&tls, &navigation.target, &navigation.cookie), async {
        wait_for_exchange(&gate).await;
        assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts WHERE phase='claimed' AND verifier IS NULL").await, 1);
        let tag = format!("\"{}\"", navigation.attempt.connection_revision);
        let suspended = send(
            &tls,
            &browser,
            "POST",
            &format!("/api/v1/orgs/{}/auth-connection/suspend", org.id),
            &[
                ("Origin", ORIGIN),
                ("If-Match", &tag),
                ("Idempotency-Key", &Uuid::now_v7().to_string()),
            ],
            &[],
        )
        .await;
        connection(&suspended, org.id, ConnectionStatus::Suspended);
        gate.release_response.notify_one();
    });
    let name = navigation.cookie.split_once('=').unwrap().0;
    check_callback(&callback, Some(name));
    check_callback(&visit(&tls, &navigation.target, &navigation.cookie).await, None);
    let status = attempt_path(&navigation.attempt);
    send(&tls, &browser, "GET", &status, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    confirm_link(&tls, &browser, &navigation.attempt, &Uuid::now_v7().to_string()).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let root = format!("/api/v1/orgs/{}/auth-link", org.id);
    let reply = send(&tls, &browser, "GET", &root, &[], &[]).await;
    assert_eq!(reply.status, 200);
    let link = SelfLinkStatus::from_http_json(&reply.body, context, metadata(&reply)).unwrap();
    assert!(link.status.link.is_none() && link.connection.is_none());
    let old_tag = format!("\"{}\"", navigation.attempt.connection_revision);
    send(
        &tls,
        &browser,
        "POST",
        &format!("{root}/attempts"),
        &[("Origin", ORIGIN), ("If-Match", &old_tag)],
        &[],
    )
    .await
    .problem(409, "organization.conflict", false);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);
    assert_eq!(f.count(audit).await, before + 1);
    assert_eq!(provider.counts()[0], 2);
    assert_eq!(current_team(f, &owner, org.id).await.membership.id, context.membership_id);
    provider.close().await;
}

browser_tests!(
    sqlite_member_link_https_suspension_fences_inflight_exchange,
    postgres_member_link_https_suspension_fences_inflight_exchange,
    suspend_during_exchange
);
