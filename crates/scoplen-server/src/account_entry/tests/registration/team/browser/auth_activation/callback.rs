// SPDX-License-Identifier: AGPL-3.0-only
//! Real provider callback, fenced by its exact purpose, browser and candidate.

use axum::{body::Body, http::Request};

use super::super::auth_connection::seed_link_state;
use super::*;
use crate::oidc::provider_test::TokenResponseGate;

#[cfg(feature = "postgres-integration")]
mod confirm_recovery;

struct Navigation {
    attempt: Activation,
    target: String,
    cookie: String,
}

async fn begin(
    f: &Fixture,
    tls: &TlsFixture,
    browser: &Browser,
    provider: &Provider,
    org: Uuid,
) -> Navigation {
    let draft = save_draft(tls, browser, org, &provider.issuer).await;
    let navigation =
        start_navigation(tls, browser, provider, &draft, ExpectedRevision::Empty).await;
    assert_eq!(
        f.count(
            "SELECT count(*) FROM organization_auth_connection_activations WHERE phase='pending'"
        )
        .await,
        1
    );
    navigation
}

async fn start_navigation(
    tls: &TlsFixture,
    browser: &Browser,
    provider: &Provider,
    draft: &DraftResource,
    expected: ExpectedRevision,
) -> Navigation {
    let path = format!("/api/v1/orgs/{}/auth-connection/activations", draft.organization_id);
    let tag;
    let condition = match expected {
        ExpectedRevision::Empty => ("If-None-Match", "*"),
        ExpectedRevision::Current(revision) => {
            tag = format!("\"{revision}\"");
            ("If-Match", tag.as_str())
        }
    };
    let reply = send(
        tls,
        browser,
        "POST",
        &path,
        &start_headers(condition),
        candidate(draft.id).as_bytes(),
    )
    .await;
    let response = started(&reply, draft, expected);
    let navigation = std::str::from_utf8(response.authorization_url.as_bytes()).unwrap();
    let redirect = provider.navigate(navigation).await;
    let target = format!("{}?{}", redirect.path(), redirect.query().unwrap());
    let cookie = reply.header("set-cookie").unwrap().split(';').next().unwrap().into();
    Navigation { attempt: response.attempt, target, cookie }
}

async fn visit(tls: &TlsFixture, target: &str, cookie: &str) -> Reply {
    tls.send(
        Request::get(target)
            .header("Host", "example.com")
            .header("Cookie", cookie)
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Dest", "document")
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn status_path(attempt: &Activation) -> String {
    format!(
        "/api/v1/orgs/{}/auth-connection/activations/{}",
        attempt.context.organization_id, attempt.id
    )
}

async fn confirm(
    tls: &TlsFixture,
    browser: &Browser,
    attempt: &Activation,
    condition: (&str, &str),
    key: &str,
) -> Reply {
    send(
        tls,
        browser,
        "POST",
        &format!("{}/confirm", status_path(attempt)),
        &[("Origin", ORIGIN), condition, ("Idempotency-Key", key)],
        &[],
    )
    .await
}

fn check_callback(reply: &Reply, cleared_cookie: Option<&str>) {
    let status = if cleared_cookie.is_some() { 200 } else { 400 };
    assert_eq!(reply.status, status);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert!(reply.header("access-control-allow-origin").is_none());
    assert!(reply.header("access-control-allow-credentials").is_none());
    assert!(reply.header("location").is_none());
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(
        reply.header("content-security-policy"),
        Some("default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    );
    assert!(String::from_utf8_lossy(&reply.body).contains("Return to the original team tab"));
    let expected = cleared_cookie
        .map(|name| format!("{name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"));
    assert_eq!(reply.header("set-cookie"), expected.as_deref());
}

#[allow(clippy::too_many_lines)]
async fn verify_and_confirm(f: &Fixture) {
    let provider = Provider::start(f.directory.join("activation-verification"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-callback-owner").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let other_browser = login(f, &owner.registration).await;
    let draft = save_draft(&tls, &browser, org, &provider.issuer).await;
    let navigation =
        start_navigation(&tls, &browser, &provider, &draft, ExpectedRevision::Empty).await;
    let key = Uuid::now_v7().to_string();
    let empty = ("If-None-Match", "*");
    confirm(&tls, &browser, &navigation.attempt, empty, &key).await.problem(
        409,
        "organization.conflict",
        false,
    );
    confirm(&tls, &other_browser, &navigation.attempt, empty, &key).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    let (cookie_name, value) = navigation.cookie.split_once('=').unwrap();
    let wrong_purpose = format!("__Host-spl-auth-test={value}");
    let duplicate = format!("{}; {}", navigation.cookie, navigation.cookie);
    for wrong in [&wrong_purpose, &duplicate] {
        check_callback(&visit(&tls, &navigation.target, wrong).await, None);
    }
    assert_eq!(provider.counts(), [0, 0, 0]);
    let both_purposes = format!("{wrong_purpose}; {}", navigation.cookie);
    let (a, b) = tokio::join!(
        visit(&tls, &navigation.target, &both_purposes),
        visit(&tls, &navigation.target, &navigation.cookie),
    );
    let (claimed, ignored) = if a.status == 200 { (a, b) } else { (b, a) };
    check_callback(&claimed, Some(cookie_name));
    check_callback(&ignored, None);
    assert_eq!(provider.counts(), [1, 1, 0]);

    let status = send(&tls, &browser, "GET", &status_path(&navigation.attempt), &[], &[]).await;
    assert_eq!(status.status, 200);
    let result = Activation::from_http_json(
        &status.body,
        &navigation.attempt,
        status.header("etag"),
        status.header("cache-control"),
        status.header("pragma"),
    )
    .unwrap();
    assert_eq!(result.status, DraftLoginStatus::Verified);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations WHERE phase='verified' AND credential IS NOT NULL AND verifier IS NULL").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connections").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);

    let stale = format!("\"{}\"", Uuid::now_v7());
    confirm(&tls, &browser, &navigation.attempt, ("If-Match", &stale), &key).await.problem(
        412,
        "organization.precondition_failed",
        false,
    );
    f.audit_failure(true).await;
    confirm(&tls, &browser, &navigation.attempt, empty, &key).await.problem(
        503,
        "organization.storage_unavailable",
        true,
    );
    f.audit_failure(false).await;
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connections").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_receipts").await, 0);
    let installed = confirm(&tls, &browser, &navigation.attempt, empty, &key).await;
    let first = connection(&installed, org, ConnectionStatus::Active);
    assert_eq!(first.target, navigation.attempt.context.target);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_receipts").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 2);

    let family = scope::current_session(f, &browser).await.unwrap().family_id;
    let membership = current_team(f, &owner, org).await.membership.id;
    seed_link_state(f, org, membership, family, first.id).await;
    let root = format!("/api/v1/orgs/{org}/auth-connection");
    let next =
        start_navigation(&tls, &browser, &provider, &draft, ExpectedRevision::Current(first.id))
            .await;
    let before = send(&tls, &browser, "GET", &root, &[], &[]).await;
    assert_eq!(connection(&before, org, ConnectionStatus::Active), first);
    check_callback(
        &visit(&tls, &next.target, &next.cookie).await,
        Some(next.cookie.split_once('=').unwrap().0),
    );
    let replacement = confirm(
        &tls,
        &browser,
        &next.attempt,
        ("If-Match", &first.etag()),
        &Uuid::now_v7().to_string(),
    )
    .await;
    let second = connection(&replacement, org, ConnectionStatus::Active);
    assert_ne!(second.id, first.id);
    assert_eq!(second.target, first.target);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 1);
    assert_eq!(
        f.count("SELECT count(*) FROM organization_memberships WHERE auth_link_generation=1").await,
        1
    );
    let recovered = confirm(&tls, &browser, &navigation.attempt, empty, &key).await;
    assert_eq!(connection(&recovered, org, ConnectionStatus::Active), first);
    let current = send(&tls, &browser, "GET", &root, &[], &[]).await;
    assert_eq!(connection(&current, org, ConnectionStatus::Active), second);
    assert_eq!(provider.counts(), [2, 2, 0]);
    assert_eq!(
        f.count("SELECT count(*) FROM organization_auth_connections WHERE credential IS NOT NULL")
            .await,
        1
    );
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 5);
    assert_eq!(current_team(f, &owner, org).await.id, org);
    provider.close().await;
}

async fn replacement_retires_changed_context(f: &Fixture) {
    let provider = Provider::start(f.directory.join("activation-link-retirement"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-link-retirement").await;
    let org = create_team(f, &owner).await;
    let browser = login(f, &owner.registration).await;
    // The previous fixture uses a different client ID at the same issuer and Space.
    let previous = seed_active_connection(f, org.id, &provider.issuer).await;
    let family = scope::current_session(f, &browser).await.unwrap().family_id;
    seed_link_state(f, org.id, org.membership.id, family, previous).await;
    let draft = save_draft(&tls, &browser, org.id, &provider.issuer).await;
    let replacement =
        start_navigation(&tls, &browser, &provider, &draft, ExpectedRevision::Current(previous))
            .await;
    check_callback(
        &visit(&tls, &replacement.target, &replacement.cookie).await,
        Some(replacement.cookie.split_once('=').unwrap().0),
    );
    let tag = format!("\"{previous}\"");
    let key = Uuid::now_v7().to_string();
    let condition = ("If-Match", tag.as_str());
    f.audit_failure(true).await;
    confirm(&tls, &browser, &replacement.attempt, condition, &key).await.problem(
        503,
        "organization.storage_unavailable",
        true,
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts").await, 1);
    f.audit_failure(false).await;
    let installed = confirm(&tls, &browser, &replacement.attempt, condition, &key).await;
    let installed = connection(&installed, org.id, ConnectionStatus::Active);
    assert_ne!(installed.id, previous);
    assert_ne!(installed.target.client_id, "review-client");
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_link_attempts").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_memberships WHERE status='active' AND auth_link_generation=2").await, 1);
    provider.close().await;
}

async fn abandon_during_exchange(f: &Fixture) {
    let gate = Arc::new(TokenResponseGate::default());
    let provider = Provider::start_with_token_gate(
        f.directory.join("activation-abandonment"),
        ORIGIN,
        Some(gate.clone()),
    )
    .await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-abandon-owner").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let navigation = begin(f, &tls, &browser, &provider, org).await;
    let status = status_path(&navigation.attempt);
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    let (finished, ()) = tokio::join!(visit(&tls, &navigation.target, &navigation.cookie), async {
        tokio::time::timeout(Duration::from_secs(6), gate.request_received.notified())
            .await
            .unwrap();
        let pending = send(&tls, &browser, "GET", &status, &[], &[]).await;
        assert_pending(&pending, &navigation.attempt);
        assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations WHERE phase='claimed' AND verifier IS NULL").await, 1);
        let abandoned = send(&tls, &browser, "DELETE", &status, &[("Origin", ORIGIN)], &[]).await;
        assert_eq!(abandoned.status, 204);
        gate.release_response.notify_one();
    });
    check_callback(&finished, Some(navigation.cookie.split_once('=').unwrap().0));
    check_callback(&visit(&tls, &navigation.target, &navigation.cookie).await, None);
    send(&tls, &browser, "GET", &status, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert_eq!(provider.counts()[0], 1);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connections").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);
    provider.close().await;
}

async fn provider_denial(f: &Fixture) {
    let provider = Provider::start(f.directory.join("activation-denial"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-denial-owner").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let navigation = begin(f, &tls, &browser, &provider, org).await;
    let (path, query) = navigation.target.split_once('?').unwrap();
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if name == "code" {
            form.append_pair("error", "access_denied");
        } else {
            form.append_pair(&name, &value);
        }
    }
    let refusal = format!("{path}?{}", form.finish());
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    check_callback(
        &visit(&tls, &refusal, &navigation.cookie).await,
        Some(navigation.cookie.split_once('=').unwrap().0),
    );
    check_callback(&visit(&tls, &navigation.target, &navigation.cookie).await, None);
    let status = send(&tls, &browser, "GET", &status_path(&navigation.attempt), &[], &[]).await;
    assert_eq!(status.status, 200);
    let failure = Activation::from_http_json(
        &status.body,
        &navigation.attempt,
        status.header("etag"),
        status.header("cache-control"),
        status.header("pragma"),
    )
    .unwrap();
    assert_eq!(failure.status, DraftLoginStatus::Failed);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations WHERE phase='failed' AND credential IS NULL AND verifier IS NULL").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);
    assert_eq!(provider.counts(), [0, 0, 0]);
    provider.close().await;
}

browser_tests!(
    sqlite_auth_activation_https_verifies_installs_and_replaces,
    postgres_auth_activation_https_verifies_installs_and_replaces,
    verify_and_confirm
);
browser_tests!(
    sqlite_auth_activation_https_retires_changed_member_link_context,
    postgres_auth_activation_https_retires_changed_member_link_context,
    replacement_retires_changed_context
);
browser_tests!(
    sqlite_auth_activation_https_abandonment_fences_callback,
    postgres_auth_activation_https_abandonment_fences_callback,
    abandon_during_exchange
);
browser_tests!(
    sqlite_auth_activation_https_denial_retires_candidate_secret,
    postgres_auth_activation_https_denial_retires_candidate_secret,
    provider_denial
);
