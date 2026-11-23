// SPDX-License-Identifier: AGPL-3.0-only
//! Mounted D-170 HTTPS ceremonies backed by a separately running TLS issuer.

use scoplen_api::member_link::{
    LinkAttempt, LinkAttemptStarted, LinkMembership, LinkResponseHeaders, MemberLink,
    MemberLinkStatus, SelfLinkStatus,
};

use super::*;

fn metadata(reply: &Reply) -> LinkResponseHeaders<'_> {
    LinkResponseHeaders {
        etag: reply.header("etag"),
        cache_control: reply.header("cache-control"),
        pragma: reply.header("pragma"),
    }
}

async fn install_provider(tls: &TlsFixture, browser: &Browser, provider: &Provider, org: Uuid) {
    let draft = save_draft(tls, browser, org, &provider.issuer).await;
    let activation =
        start_navigation(tls, browser, provider, &draft, ExpectedRevision::Empty).await;
    let cookie_name = activation.cookie.split_once('=').unwrap().0;
    check_callback(&visit(tls, &activation.target, &activation.cookie).await, Some(cookie_name));
    let installed = confirm(
        tls,
        browser,
        &activation.attempt,
        ("If-None-Match", "*"),
        &Uuid::now_v7().to_string(),
    )
    .await;
    connection(&installed, org, ConnectionStatus::Active);
}

struct LinkNavigation {
    attempt: LinkAttempt,
    target: String,
    cookie: String,
}

async fn begin_link(
    tls: &TlsFixture,
    browser: &Browser,
    provider: &Provider,
    membership: LinkMembership,
) -> LinkNavigation {
    let root = format!("/api/v1/orgs/{}/auth-link", membership.organization_id);
    let status = send(tls, browser, "GET", &root, &[], &[]).await;
    assert_eq!(status.status, 200);
    let status =
        SelfLinkStatus::from_http_json(&status.body, membership, metadata(&status)).unwrap();
    assert!(status.status.link.is_none());
    let connection = status.connection.unwrap();
    let reply = send(
        tls,
        browser,
        "POST",
        &format!("{root}/attempts"),
        &[("Origin", ORIGIN), ("If-Match", &connection.etag())],
        &[],
    )
    .await;
    assert_eq!(reply.status, 201);
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert!(reply.header("location").is_none());
    let start =
        LinkAttemptStarted::from_http_json(&reply.body, membership, &connection, metadata(&reply))
            .unwrap();
    let url = std::str::from_utf8(start.authorization_url.as_bytes()).unwrap();
    let redirect = provider.navigate(url).await;
    let target = format!("{}?{}", redirect.path(), redirect.query().unwrap());
    let cookie = reply.header("set-cookie").unwrap();
    assert!(cookie.contains("; Path=/; HttpOnly; Secure; SameSite=Lax; Expires="));
    let cookie = cookie.split(';').next().unwrap().to_owned();
    assert!(cookie.starts_with("__Host-spl-auth-link-"));
    LinkNavigation { attempt: start.attempt, target, cookie }
}

fn attempt_path(attempt: &LinkAttempt) -> String {
    format!("/api/v1/orgs/{}/auth-link/attempts/{}", attempt.membership.organization_id, attempt.id)
}

async fn confirm_link(
    tls: &TlsFixture,
    browser: &Browser,
    attempt: &LinkAttempt,
    key: &str,
) -> Reply {
    let tag = format!("\"{}\"", attempt.connection_revision);
    send(
        tls,
        browser,
        "POST",
        &format!("{}/confirm", attempt_path(attempt)),
        &[("Origin", ORIGIN), ("If-Match", &tag), ("Idempotency-Key", key)],
        &[],
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn link_lifecycle(f: &Fixture) {
    let provider = Provider::start(f.directory.join("member-link-issuer"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "member-link-owner").await;
    let member = actor(f, "member-link-member").await;
    let org = create_team(f, &owner).await;
    let foreign = create_team(f, &member).await;
    let (invitation, password, _, _) =
        issue(f, &owner, &member, org.id, vec![TeamRole::Member]).await;
    let accept = format!("/api/v1/orgs/{}/invitations/{}/accept", org.id, invitation.id);
    let body = TeamInvitationAcceptRequest { password }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    assert_eq!(
        call(f, &member, "POST", &accept, body.as_bytes(), &[("Idempotency-Key", &key)])
            .await
            .status,
        200
    );
    let context = LinkMembership {
        organization_id: org.id,
        membership_id: current_team(f, &member, org.id).await.membership.id,
    };
    let owner_browser = login(f, &owner.registration).await;
    let original = login(f, &member.registration).await;
    let other_family = login(f, &member.registration).await;
    install_provider(&tls, &owner_browser, &provider, org.id).await;
    assert_eq!(provider.discoveries(), 1);
    assert_eq!(provider.counts(), [1, 1, 0]);
    let audit_before = f.count("SELECT count(*) FROM audit_events").await;
    let first = begin_link(&tls, &original, &provider, context).await;
    let status = attempt_path(&first.attempt);
    send(&tls, &other_family, "GET", &status, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let foreign_attempt =
        format!("/api/v1/orgs/{}/auth-link/attempts/{}", foreign.id, first.attempt.id);
    send(&tls, &original, "GET", &foreign_attempt, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let (name, binding) = first.cookie.split_once('=').unwrap();
    let wrong_purpose = name.replace("-link-", "-activate-");
    let wrong = format!("{wrong_purpose}={binding}");
    let ambiguous = format!("{}; {wrong}", first.cookie);
    for cookie in [wrong.as_str(), &ambiguous] {
        check_callback(&visit(&tls, &first.target, cookie).await, None);
    }
    assert_eq!(provider.discoveries(), 1);
    assert_eq!(provider.counts(), [1, 1, 0]);
    let with_diagnostic = format!("__Host-spl-auth-test={binding}; {}", first.cookie);
    check_callback(&visit(&tls, &first.target, &with_diagnostic).await, Some(name));
    check_callback(&visit(&tls, &first.target, &first.cookie).await, None);
    let second = begin_link(&tls, &other_family, &provider, context).await;
    let other_name = second.cookie.split_once('=').unwrap().0;
    check_callback(&visit(&tls, &second.target, &second.cookie).await, Some(other_name));
    assert_eq!(provider.counts(), [3, 3, 0]);
    let reply = send(&tls, &original, "GET", &status, &[], &[]).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        LinkAttempt::from_http_json(&reply.body, &first.attempt, metadata(&reply)).unwrap().status,
        DraftLoginStatus::Verified
    );
    assert!(reply.header("set-cookie").is_none());
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);

    let key = Uuid::now_v7().to_string();
    f.audit_failure(true).await;
    confirm_link(&tls, &original, &first.attempt, &key).await.problem(
        503,
        "organization.storage_unavailable",
        true,
    );
    f.audit_failure(false).await;
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);
    let confirmed = confirm_link(&tls, &original, &first.attempt, &key).await;
    assert_eq!(confirmed.status, 201);
    let public = std::str::from_utf8(&confirmed.body).unwrap();
    assert!(!public.contains("opaque-human") && !public.contains("fixture-access"));
    let link = MemberLink::from_http_json(&confirmed.body, context, metadata(&confirmed)).unwrap();
    let recovered = confirm_link(&tls, &original, &first.attempt, &key).await;
    assert_eq!(recovered.status, 201);
    assert_eq!(confirmed.body, recovered.body);
    confirm_link(&tls, &other_family, &first.attempt, &key).await.problem(
        409,
        "organization.conflict",
        false,
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit_before + 5);

    let named = format!("/api/v1/orgs/{}/members/{}/auth-link", org.id, context.membership_id);
    let denied = send(&tls, &original, "GET", &named, &[], &[]).await;
    denied.problem(403, "policy.denied", false);
    let owner_view = send(&tls, &owner_browser, "GET", &named, &[], &[]).await;
    assert_eq!(owner_view.status, 200);
    assert_eq!(
        MemberLinkStatus::from_http_json(&owner_view.body, context, metadata(&owner_view))
            .unwrap()
            .link,
        Some(link.clone())
    );
    let stale = format!("\"{}\"", Uuid::now_v7());
    send(&tls, &owner_browser, "DELETE", &named, &[("Origin", ORIGIN), ("If-Match", &stale)], &[])
        .await
        .problem(412, "organization.precondition_failed", false);
    let withdrawn = send(
        &tls,
        &owner_browser,
        "DELETE",
        &named,
        &[("Origin", ORIGIN), ("If-Match", &link.etag())],
        &[],
    )
    .await;
    assert_eq!(withdrawn.status, 204);
    metadata(&withdrawn).validate_empty(&withdrawn.body).unwrap();
    confirm_link(&tls, &other_family, &second.attempt, &Uuid::now_v7().to_string()).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);
    assert_eq!(current_team(f, &member, org.id).await.membership.id, context.membership_id);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit_before + 6);
    provider.close().await;
}

browser_tests!(
    sqlite_member_link_https_withdrawal_fences_prior_verification,
    postgres_member_link_https_withdrawal_fences_prior_verification,
    link_lifecycle
);

async fn original_scope_and_freshness(f: &Fixture) {
    let provider = Provider::start(f.directory.join("member-link-freshness"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "member-link-freshness").await;
    let org = create_team(f, &owner).await;
    let root = format!("/api/v1/orgs/{}/auth-link", org.id);
    let start = format!("{root}/attempts");
    let mut browser = login(f, &owner.registration).await;
    install_provider(&tls, &browser, &provider, org.id).await;
    let context = LinkMembership { organization_id: org.id, membership_id: org.membership.id };
    let reply = send(&tls, &browser, "GET", &root, &[], &[]).await;
    let connection = SelfLinkStatus::from_http_json(&reply.body, context, metadata(&reply))
        .unwrap()
        .connection
        .unwrap();
    let tag = connection.etag();
    let condition = [("Origin", ORIGIN), ("If-Match", tag.as_str())];
    for invalid_headers in [
        vec![("Origin", ORIGIN), ("Content-Type", "application/json"), ("If-Match", &tag)],
        vec![("Origin", ORIGIN), ("If-Match", &tag), ("If-Match", &tag)],
    ] {
        send(&tls, &browser, "POST", &start, &invalid_headers, &[]).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    send(&tls, &browser, "POST", &start, &[("Origin", ORIGIN)], &[]).await.problem(
        428,
        "organization.precondition_required",
        false,
    );
    let family = scope::current_session(f, &browser).await.unwrap().family_id;
    scope::set_scope(f, family, "auth-links:withdraw").await;
    send(&tls, &browser, "POST", &start, &condition, &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    let named = format!("/api/v1/orgs/{}/members/{}/auth-link", org.id, org.membership.id);
    assert_eq!(send(&tls, &browser, "GET", &named, &[], &[]).await.status, 200);
    scope::set_scope(f, family, "auth-links:self").await;
    send(&tls, &browser, "GET", &named, &[], &[]).await.problem(403, "policy.denied", false);
    let verified = begin_link(&tls, &browser, &provider, context).await;
    let name = verified.cookie.split_once('=').unwrap().0;
    check_callback(&visit(&tls, &verified.target, &verified.cookie).await, Some(name));
    let verified_path = attempt_path(&verified.attempt);
    let abandoned =
        send(&tls, &browser, "DELETE", &verified_path, &[("Origin", ORIGIN)], &[]).await;
    assert_eq!(abandoned.status, 204);
    metadata(&abandoned).validate_empty(&abandoned.body).unwrap();
    check_callback(&visit(&tls, &verified.target, &verified.cookie).await, None);
    assert_eq!(provider.counts(), [2, 2, 0]);
    let next = begin_link(&tls, &browser, &provider, context).await;
    let name = next.cookie.split_once('=').unwrap().0;
    check_callback(&visit(&tls, &next.target, &next.cookie).await, Some(name));
    let confirmed = confirm_link(&tls, &browser, &next.attempt, &Uuid::now_v7().to_string()).await;
    assert_eq!(confirmed.status, 201);
    let link = MemberLink::from_http_json(&confirmed.body, context, metadata(&confirmed)).unwrap();
    let unlinked = send(
        &tls,
        &browser,
        "DELETE",
        &root,
        &[("Origin", ORIGIN), ("If-Match", &link.etag())],
        &[],
    )
    .await;
    assert_eq!(unlinked.status, 204);
    metadata(&unlinked).validate_empty(&unlinked.body).unwrap();
    f.execute("UPDATE account_browser_families SET created_at_ms=created_at_ms-360000,expires_at_ms=expires_at_ms-360000").await;
    let refresh = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    (browser.access, browser.cookie) = session(&refresh, false);
    send(&tls, &browser, "POST", &start, &condition, &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    assert_eq!(provider.discoveries(), 1);
    provider.close().await;
}

browser_tests!(
    sqlite_member_link_https_requires_scope_and_recent_original_sign_in,
    postgres_member_link_https_requires_scope_and_recent_original_sign_in,
    original_scope_and_freshness
);
