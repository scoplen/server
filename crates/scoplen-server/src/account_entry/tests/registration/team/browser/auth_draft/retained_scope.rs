// SPDX-License-Identifier: AGPL-3.0-only
//! The exact pre-D-166 family ceilings remain usable after the new scope ships.

use scoplen_api::{
    account_browser::INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE, auth::INITIAL_DEVICE_ACCESS_SCOPE,
};

use super::*;

fn previous_ceiling(current: &str) -> String {
    let mut scopes: Vec<_> = current.split(' ').collect();
    let draft = scopes.iter().position(|scope| *scope == "auth-drafts:manage").expect("new scope");
    scopes.remove(draft);
    scopes.join(" ")
}

async fn rotate_device(tls: &TlsFixture, owner: &mut Actor) {
    let path = "/api/v1/auth/refresh";
    let request = Request::post(path)
        .header("Host", "example.com")
        .header("Content-Type", "application/json")
        .header("DPoP", proof(&owner.registration.device, path, None))
        .body(Body::from(
            AuthRefreshRequest::new(owner.token.refresh_token.clone()).unwrap().to_json().unwrap(),
        ))
        .unwrap();
    let reply = tls.send(request).await;
    assert_eq!(reply.status, 200);
    owner.token = AuthTokenResponse::from_json(std::str::from_utf8(&reply.body).unwrap()).unwrap();
}

async fn rotate_browser(tls: &TlsFixture, browser: &mut Browser) {
    let request = Request::post(REFRESH)
        .header("Host", "example.com")
        .header("Content-Type", "application/json")
        .header("Origin", ORIGIN)
        .header("Cookie", &browser.cookie)
        .header("DPoP", proof(&browser.key, REFRESH, None))
        .body(Body::from("{}"))
        .unwrap();
    (browser.access, browser.cookie) = session(&tls.send(request).await, false);
}

async fn assert_old_writer(
    tls: &TlsFixture,
    writer: &Writer<'_>,
    org: Uuid,
    draft: &DraftResource,
) {
    let organization = format!("/api/v1/orgs/{org}");
    let team = writer.send(tls, "GET", &organization, &[], &[]).await;
    assert_eq!(team.status, 200);
    assert_eq!(OrganizationResource::from_json(&team.body).unwrap().id, org);
    let path = format!("{organization}/auth-connection-draft");
    denied(&writer.send(tls, "GET", &path, &[], &[]).await, 403, "policy.denied");
    let create_key = Uuid::now_v7().to_string();
    denied(
        &writer.send(tls, "POST", &path, CREATE, &create_headers(&create_key)).await,
        403,
        "policy.denied",
    );
    let cancel_key = Uuid::now_v7().to_string();
    denied(
        &writer.send(tls, "DELETE", &path, &[], &cancel_headers(&cancel_key, &draft.etag())).await,
        403,
        "policy.denied",
    );
}

async fn retained_ceiling(f: &Fixture) {
    let mut owner = actor(f, "issuer-ceiling").await;
    let org = create_team(f, &owner).await.id;
    let mut browser = login(f, &owner.registration).await;
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let key = Uuid::now_v7().to_string();
    let created =
        Writer::device(&owner).send(&tls, "POST", &path, CREATE, &create_headers(&key)).await;
    let expected = resource(&created, 201, org);

    // Model just the durable family ceilings written by the preceding release.
    let old_browser = previous_ceiling(INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE);
    let initial = scope::current_session(f, &browser).await.unwrap();
    assert_eq!(initial.scope, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE);
    scope::set_scope(f, initial.family_id, &old_browser).await;
    narrow(f, &mut owner, &previous_ceiling(INITIAL_DEVICE_ACCESS_SCOPE)).await;
    rotate_browser(&tls, &mut browser).await;
    for writer in [Writer::device(&owner), Writer::browser(&browser)] {
        assert_old_writer(&tls, &writer, org, &expected).await;
    }

    let fresh_device = authenticate(f, &owner.registration).await;
    let fresh_browser = login(f, &owner.registration).await;
    let fresh_family = scope::current_session(f, &fresh_browser).await.unwrap();
    assert_ne!(initial.family_id, fresh_family.family_id);
    assert_eq!(fresh_family.scope, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE);

    // A fresh login for the same Account and Device cannot grant new scopes on the old families.
    rotate_device(&tls, &mut owner).await;
    rotate_browser(&tls, &mut browser).await;
    let retained = scope::current_session(f, &browser).await.unwrap();
    assert_eq!(retained.family_id, initial.family_id);
    assert_eq!(retained.scope, old_browser);
    for writer in [Writer::device(&owner), Writer::browser(&browser)] {
        assert_old_writer(&tls, &writer, org, &expected).await;
    }
    for writer in [
        Writer { key: &owner.registration.device, token: &fresh_device.access_token },
        Writer::browser(&fresh_browser),
    ] {
        let reply = writer.send(&tls, "GET", &path, &[], &[]).await;
        assert_eq!(resource(&reply, 200, org), expected);
    }
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_draft_receipts").await, 1);
}

browser_tests!(
    sqlite_issuer_draft_https_refresh_preserves_pre_upgrade_scope,
    postgres_issuer_draft_https_refresh_preserves_pre_upgrade_scope,
    retained_ceiling
);
