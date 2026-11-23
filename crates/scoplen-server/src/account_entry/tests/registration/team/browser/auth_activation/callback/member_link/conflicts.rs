// SPDX-License-Identifier: AGPL-3.0-only
//! Concurrent link confirmations for the same verified subject in one Organization.

use super::*;

async fn verify_link(
    tls: &TlsFixture,
    browser: &Browser,
    provider: &Provider,
    context: LinkMembership,
) -> LinkAttempt {
    let navigation = begin_link(tls, browser, provider, context).await;
    let name = navigation.cookie.split_once('=').unwrap().0;
    check_callback(&visit(tls, &navigation.target, &navigation.cookie).await, Some(name));
    let status = send(tls, browser, "GET", &attempt_path(&navigation.attempt), &[], &[]).await;
    assert_eq!(status.status, 200);
    let attempt =
        LinkAttempt::from_http_json(&status.body, &navigation.attempt, metadata(&status)).unwrap();
    assert_eq!(attempt.status, DraftLoginStatus::Verified);
    attempt
}

async fn single_subject_winner(f: &Fixture) {
    let provider = Provider::start(f.directory.join("member-link-conflict"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "member-link-conflict-owner").await;
    let member = actor(f, "member-link-conflict-member").await;
    let org = create_team(f, &owner).await;
    let (invitation, password, _, _) =
        issue(f, &owner, &member, org.id, vec![TeamRole::Member]).await;
    let accept = format!("/api/v1/orgs/{}/invitations/{}/accept", org.id, invitation.id);
    let body = TeamInvitationAcceptRequest { password }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let accepted =
        call(f, &member, "POST", &accept, body.as_bytes(), &[("Idempotency-Key", &key)]).await;
    assert_eq!(accepted.status, 200);
    let owner_context =
        LinkMembership { organization_id: org.id, membership_id: org.membership.id };
    let member_context = LinkMembership {
        organization_id: org.id,
        membership_id: current_team(f, &member, org.id).await.membership.id,
    };
    let owner_browser = login(f, &owner.registration).await;
    let member_browser = login(f, &member.registration).await;
    install_provider(&tls, &owner_browser, &provider, org.id).await;
    let audit = "SELECT count(*) FROM audit_events";
    let before = f.count(audit).await;
    // Both code exchanges return the fixture issuer's same opaque subject.
    let owner_attempt = verify_link(&tls, &owner_browser, &provider, owner_context).await;
    let member_attempt = verify_link(&tls, &member_browser, &provider, member_context).await;
    assert_eq!(provider.counts(), [3, 3, 0]);
    assert_eq!(f.count(audit).await, before + 4);

    let owner_key = Uuid::now_v7().to_string();
    let member_key = Uuid::now_v7().to_string();
    let (owner_result, member_result) = tokio::join!(
        confirm_link(&tls, &owner_browser, &owner_attempt, &owner_key),
        confirm_link(&tls, &member_browser, &member_attempt, &member_key),
    );
    let (won, context, lost) = if owner_result.status == 201 {
        (owner_result, owner_context, member_result)
    } else {
        (member_result, member_context, owner_result)
    };
    assert_eq!(won.status, 201);
    let link = MemberLink::from_http_json(&won.body, context, metadata(&won)).unwrap();
    lost.problem(409, "organization.conflict", false);
    let conflict = std::str::from_utf8(&lost.body).unwrap();
    assert!(!conflict.contains("opaque-human"));
    assert!(!conflict.contains(&link.id.to_string()));
    assert!(!conflict.contains(&link.membership.membership_id.to_string()));
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 1);
    assert_eq!(f.count(audit).await, before + 5);
    provider.close().await;
}

browser_tests!(
    sqlite_member_link_https_one_membership_per_verified_subject,
    postgres_member_link_https_one_membership_per_verified_subject,
    single_subject_winner
);
