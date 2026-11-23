// SPDX-License-Identifier: AGPL-3.0-only
//! Wire acceptance for Account-browser draft login against an independent HTTPS provider.

use scoplen_api::auth_connection_draft::test_login::{
    DraftLoginAttempt, DraftLoginStarted, DraftLoginStatus,
};

use super::*;
use crate::oidc::provider_test::{Provider, TokenResponseGate};

async fn callback(tls: &TlsFixture, target: &str, host: &str, cookie: &str, mode: &str) -> Reply {
    tls.send(
        Request::builder()
            .method("GET")
            .uri(target)
            .header("Host", host)
            .header("Cookie", cookie)
            .header("Sec-Fetch-Mode", mode)
            .header("Sec-Fetch-Dest", "document")
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn private_callback(reply: &Reply, status: u16, clear_cookie: bool) {
    assert_eq!(reply.status, status);
    bound_response(reply);
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(
        reply.header("content-security-policy"),
        Some("default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    );
    assert!(String::from_utf8_lossy(&reply.body).contains("Return to the original team tab"));
    assert!(!String::from_utf8_lossy(&reply.body).contains("browser-fixture"));
    assert_eq!(
        reply.header("set-cookie"),
        clear_cookie
            .then_some("__Host-spl-auth-test=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
    );
}

fn bound_response(reply: &Reply) {
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert!(reply.header("access-control-allow-origin").is_none());
    assert!(reply.header("access-control-allow-credentials").is_none());
    Uuid::parse_str(reply.header("x-request-id").unwrap()).unwrap();
}

async fn assess_callbacks(tls: &TlsFixture, provider: &Provider, target: &str, cookie: &str) {
    for (host, cookie, mode) in [
        ("foreign.example.test", cookie, "navigate"),
        ("example.com", "unrelated=ignored", "navigate"),
        ("example.com", cookie, "cors"),
    ] {
        private_callback(&callback(tls, target, host, cookie, mode).await, 400, false);
    }
    let duplicate = format!("{cookie}; {cookie}");
    private_callback(
        &callback(tls, target, "example.com", &duplicate, "navigate").await,
        400,
        false,
    );
    let without_issuer = target.split("&iss=").next().unwrap();
    private_callback(
        &callback(tls, without_issuer, "example.com", cookie, "navigate").await,
        400,
        false,
    );
    assert_eq!(provider.counts(), [0, 0, 0]);
    let (a, b) = tokio::join!(
        callback(tls, target, "example.com", cookie, "navigate"),
        callback(tls, target, "example.com", cookie, "navigate")
    );
    let (success, replay) = if a.status == 200 { (a, b) } else { (b, a) };
    private_callback(&success, 200, true);
    private_callback(&replay, 400, false);
    assert_eq!(provider.counts(), [1, 1, 0]);
}

async fn read_status(
    writer: &Writer<'_>,
    tls: &TlsFixture,
    path: &str,
    attempt: &DraftLoginAttempt,
) -> DraftLoginStatus {
    let reply = writer.send(tls, "GET", path, &[], &[]).await;
    assert_eq!(reply.status, 200);
    reply.private();
    assert!(reply.header("set-cookie").is_none());
    DraftLoginAttempt::from_http_json(
        &reply.body,
        (attempt.organization_id, attempt.draft_generation, attempt.id),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
    .status
}

fn started_draft(reply: &Reply, organization: Uuid, draft: &DraftResource) -> DraftLoginStarted {
    assert_eq!(reply.status, 201);
    bound_response(reply);
    DraftLoginStarted::from_http_json(
        &reply.body,
        (organization, draft.id),
        &draft.issuer,
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

async fn mounted_login(f: &Fixture) {
    let provider = Provider::start(f.directory.join("oidc-browser"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "mounted-login-owner").await;
    let organization = create_team(f, &owner).await.id;
    let session = login(f, &owner.registration).await;
    let another_family = login(f, &owner.registration).await;
    let browser = Writer::browser(&session);
    let other = Writer::browser(&another_family);
    let device = Writer::device(&owner);
    let path = format!("/api/v1/orgs/{organization}/auth-connection-draft");
    let body = DraftCreate { issuer: provider.issuer.clone() }.to_json().unwrap();
    let draft = resource(
        &device
            .send(&tls, "POST", &path, &body, &create_headers(&Uuid::now_v7().to_string()))
            .await,
        201,
        organization,
    );
    let audits_before = f.count("SELECT count(*) FROM audit_events").await;
    let start_path = format!("{path}/test-login");
    let tag = draft.etag();
    let headers =
        [("Origin", ORIGIN), ("If-Match", tag.as_str()), ("Content-Type", "application/json")];
    let request = Provider::login_material().credentials.to_json().unwrap();
    denied(
        &device.send(&tls, "POST", &start_path, request.as_bytes(), &headers).await,
        401,
        "auth.authentication_required",
    );
    denied(
        &browser.send(&tls, "POST", &start_path, request.as_bytes(), &headers[1..]).await,
        403,
        "policy.denied",
    );
    let stale = format!("\"{}\"", Uuid::now_v7());
    let stale_headers =
        [("Origin", ORIGIN), ("If-Match", stale.as_str()), ("Content-Type", "application/json")];
    denied(
        &browser.send(&tls, "POST", &start_path, request.as_bytes(), &stale_headers).await,
        412,
        "organization.precondition_failed",
    );
    assert_eq!(provider.discoveries(), 0);
    let response = browser.send(&tls, "POST", &start_path, request.as_bytes(), &headers).await;
    let started = started_draft(&response, organization, &draft);
    let cookie = response.header("set-cookie").unwrap();
    assert!(cookie.starts_with("__Host-spl-auth-test="));
    assert!(cookie.contains("; Path=/; HttpOnly; Secure; SameSite=Lax; Expires="));
    assert!(cookie.ends_with(" GMT"));
    let cookie = cookie.split(';').next().unwrap();
    let status_path = format!("{start_path}/{}", started.attempt.id);
    assert_eq!(
        read_status(&browser, &tls, &status_path, &started.attempt).await,
        DraftLoginStatus::Pending
    );
    denied(&other.send(&tls, "GET", &status_path, &[], &[]).await, 404, "organization.not_found");
    denied(
        &browser.send(&tls, "POST", &start_path, request.as_bytes(), &headers).await,
        409,
        "organization.conflict",
    );
    assert_eq!(provider.discoveries(), 1);
    let authorization_url = std::str::from_utf8(started.authorization_url.as_bytes()).unwrap();
    let returned = provider.navigate(authorization_url).await;
    let target = format!("{}?{}", returned.path(), returned.query().unwrap());
    assess_callbacks(&tls, &provider, &target, cookie).await;
    assert_eq!(
        read_status(&browser, &tls, &status_path, &started.attempt).await,
        DraftLoginStatus::Verified
    );
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audits_before + 2);
    provider.close().await;
}

async fn replacement_during_exchange(f: &Fixture) {
    let gate = Arc::new(TokenResponseGate::default());
    let provider = Provider::start_with_token_gate(
        f.directory.join("oidc-browser-replacement"),
        ORIGIN,
        Some(gate.clone()),
    )
    .await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "mounted-replacement-owner").await;
    let organization = create_team(f, &owner).await.id;
    let revision = f.revision(organization).await;
    let session = login(f, &owner.registration).await;
    let browser = Writer::browser(&session);
    let device = Writer::device(&owner);
    let path = format!("/api/v1/orgs/{organization}/auth-connection-draft");
    let body = DraftCreate { issuer: provider.issuer.clone() }.to_json().unwrap();
    let create = async |key: &str| {
        resource(
            &device.send(&tls, "POST", &path, &body, &create_headers(key)).await,
            201,
            organization,
        )
    };
    let draft = create(&Uuid::now_v7().to_string()).await;
    let audit_before = f.count("SELECT count(*) FROM audit_events").await;
    let request = Provider::login_material().credentials.to_json().unwrap();
    let start_path = format!("{path}/test-login");
    let tag = draft.etag();
    let reply = browser
        .send(
            &tls,
            "POST",
            &start_path,
            request.as_bytes(),
            &[("Origin", ORIGIN), ("If-Match", &tag), ("Content-Type", "application/json")],
        )
        .await;
    let started = started_draft(&reply, organization, &draft);
    let cookie = reply.header("set-cookie").unwrap().split(';').next().unwrap();
    let navigation = std::str::from_utf8(started.authorization_url.as_bytes()).unwrap();
    let redirected = provider.navigate(navigation).await;
    let target = format!("{}?{}", redirected.path(), redirected.query().unwrap());
    let status_path = format!("{start_path}/{}", started.attempt.id);

    let (response, replacement) = tokio::join!(
        callback(&tls, &target, "example.com", cookie, "navigate"),
        async {
            tokio::time::timeout(
                std::time::Duration::from_secs(6),
                gate.request_received.notified(),
            )
            .await
            .expect("provider received the claimed exchange");
            assert_eq!(provider.counts()[0], 1);
            assert_eq!(
                f.count("SELECT count(*) FROM organization_auth_draft_tests WHERE credentials IS NOT NULL")
                    .await,
                0,
            );
            cancelled(
                &device
                    .send(
                        &tls,
                        "DELETE",
                        &path,
                        &[],
                        &cancel_headers(&Uuid::now_v7().to_string(), &tag),
                    )
                    .await,
            );
            let replacement = create(&Uuid::now_v7().to_string()).await;
            assert_ne!(replacement.id, draft.id);
            gate.release_response.notify_one();
            replacement
        }
    );
    private_callback(&response, 200, true);
    denied(&browser.send(&tls, "GET", &status_path, &[], &[]).await, 404, "organization.not_found");
    private_callback(&callback(&tls, &target, "example.com", cookie, "navigate").await, 400, false);
    assert_eq!(provider.counts()[0], 1);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_draft_tests").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit_before + 3);
    assert_eq!(f.revision(organization).await, revision);
    assert_eq!(
        resource(&browser.send(&tls, "GET", &path, &[], &[]).await, 200, organization),
        replacement
    );
    provider.close().await;
}

browser_tests!(
    sqlite_draft_login_mounted_https_round_trip,
    postgres_draft_login_mounted_https_round_trip,
    mounted_login
);
browser_tests!(
    sqlite_draft_login_replacement_fences_in_flight_exchange,
    postgres_draft_login_replacement_fences_in_flight_exchange,
    replacement_during_exchange
);
