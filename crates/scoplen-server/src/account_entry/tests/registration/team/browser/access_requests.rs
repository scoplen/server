// SPDX-License-Identifier: AGPL-3.0-only
//! Six production routes through genuine Device and Account-browser authentication.

use super::{
    business::{business, create_asset},
    *,
};
use scoplen_api::{
    access_request::{
        AccessRequestCheckRequest, AccessRequestCheckResponse, AccessRequestCreateRequest,
        AccessRequestFields, AccessRequestPage, AccessRequestResource, AccessRequestStatus,
    },
    inventory::InventoryType,
};
use serde_json::json;

async fn transport(
    f: &Fixture,
    native: &Actor,
    browser: Option<&Browser>,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Reply {
    if let Some(browser) = browser {
        business(f, browser, method, path, body, headers).await
    } else {
        call(f, native, method, path, body, headers).await
    }
}

fn resource(reply: &Reply, status: u16) -> AccessRequestResource {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert!(reply.header("x-request-id").is_some());
    AccessRequestResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

#[allow(clippy::too_many_lines)]
async fn lifecycle(f: &Fixture, use_browser: bool) {
    let owner = actor(f, "request-http-owner").await;
    let member = actor(f, "request-http-member").await;
    let owner_browser = login(f, &owner.registration).await;
    let member_browser = login(f, &member.registration).await;
    let other_family = login(f, &member.registration).await;
    let org = create_team(f, &owner).await.id;
    super::super::inventory::enroll_member(f, &owner, &member, org).await;
    let host = create_asset(
        f,
        &owner_browser,
        org,
        InventoryType::Host,
        json!({"name":"Request target","address":"request.example.test"}),
    )
    .await;
    let path = format!("/api/v1/orgs/{org}/access-requests");
    let check_path = format!("{path}/check");
    let fields = AccessRequestFields {
        host: host.id,
        remote_user: "deploy".into(),
        duration_seconds: 120,
        reason: "  scheduled\nmaintenance\t ".into(),
    };
    let check = AccessRequestCheckRequest { fields: fields.clone() }.to_json().unwrap();
    business(f, &member_browser, "POST", &check_path, &check, &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let view = json!({"id":Uuid::now_v7(),"data":{"name":"Visible target","source":format!("permit(principal, action == Action::\"view_inventory\", resource == Host::\"{}\");",host.id),"enabled":true}});
    assert_eq!(
        business(
            f,
            &owner_browser,
            "POST",
            &format!("/api/v1/orgs/{org}/policies"),
            &serde_json::to_vec(&view).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())]
        )
        .await
        .status,
        201
    );
    let denied = business(f, &member_browser, "POST", &check_path, &check, &[]).await;
    assert_eq!(denied.status, 200);
    assert!(!AccessRequestCheckResponse::from_json(&denied.body).unwrap().allowed);
    let policy = json!({"id":Uuid::now_v7(),"data":{"name":"Request target","source":format!("permit(principal, action == Action::\"request_access\", resource == Host::\"{}\") when {{ context.duration_seconds <= 120 }};",host.id),"enabled":true}});
    assert_eq!(
        business(
            f,
            &owner_browser,
            "POST",
            &format!("/api/v1/orgs/{org}/policies"),
            &serde_json::to_vec(&policy).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())]
        )
        .await
        .status,
        201
    );
    let requester = use_browser.then_some(&member_browser);
    let decision_browser = use_browser.then_some(&owner_browser);
    let allowed = transport(f, &member, requester, "POST", &check_path, &check, &[]).await;
    assert_eq!(allowed.status, 200);
    allowed.private();
    assert!(AccessRequestCheckResponse::from_json(&allowed.body).unwrap().allowed);
    for (suffix, headers) in [
        ("?extra=1", vec![]),
        ("", vec![("If-Match", "\"unused\"")]),
        ("", vec![("Idempotency-Key", "invalid")]),
    ] {
        transport(
            f,
            &member,
            requester,
            "POST",
            &format!("{check_path}{suffix}"),
            &check,
            &headers,
        )
        .await
        .problem(400, "organization.invalid_request", false);
    }
    let create = AccessRequestCreateRequest { id: Uuid::now_v7(), fields: fields.clone() };
    let body = create.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let before_revision = f.revision(org).await;
    let original =
        transport(f, &member, requester, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    let pending = resource(&original, 201);
    assert_eq!(pending.fields, fields, "reason preserved byte-for-byte");
    assert_eq!(f.revision(org).await, before_revision);
    let target = format!("{path}/{}", pending.id);
    assert_eq!(
        resource(&transport(f, &member, requester, "GET", &target, &[], &[]).await, 200),
        pending
    );
    for query in ["", "?view=unknown", "?view=mine&view=approvals", "?view=mine&limit=501"] {
        transport(f, &member, requester, "GET", &format!("{path}{query}"), &[], &[]).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    let mine =
        transport(f, &member, requester, "GET", &format!("{path}?view=mine&limit=1"), &[], &[])
            .await;
    assert_eq!(mine.status, 200);
    mine.private();
    assert_eq!(AccessRequestPage::from_json(&mine.body).unwrap().items.len(), 1);
    let inbox =
        transport(f, &owner, decision_browser, "GET", &format!("{path}?view=approvals"), &[], &[])
            .await;
    assert_eq!(inbox.status, 200);
    assert!(AccessRequestPage::from_json(&inbox.body).unwrap().items.contains(&pending));
    transport(f, &member, requester, "GET", &format!("{target}?view=mine"), &[], &[])
        .await
        .problem(400, "organization.invalid_request", false);
    let decide = format!("{target}/decisions");
    let decision_key = Uuid::now_v7().to_string();
    let approve = br#"{"decision":"approve"}"#;
    transport(
        f,
        &member,
        requester,
        "POST",
        &decide,
        approve,
        &[("Idempotency-Key", &decision_key)],
    )
    .await
    .problem(404, "organization.not_found", false);
    transport(
        f,
        &owner,
        decision_browser,
        "POST",
        &decide,
        approve,
        &[("Idempotency-Key", &decision_key)],
    )
    .await
    .problem(428, "organization.precondition_required", false);
    for headers in [
        vec![("If-Match", "W/\"weak\""), ("Idempotency-Key", decision_key.as_str())],
        vec![
            ("If-Match", pending.etag.as_str()),
            ("If-Match", pending.etag.as_str()),
            ("Idempotency-Key", decision_key.as_str()),
        ],
    ] {
        transport(f, &owner, decision_browser, "POST", &decide, approve, &headers).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    transport(
        f,
        &owner,
        decision_browser,
        "POST",
        &decide,
        approve,
        &[("Idempotency-Key", &decision_key), ("If-Match", "\"stale\"")],
    )
    .await
    .problem(412, "organization.precondition_failed", false);
    let headers = [("Idempotency-Key", decision_key.as_str()), ("If-Match", pending.etag.as_str())];
    let approved_reply =
        transport(f, &owner, decision_browser, "POST", &decide, approve, &headers).await;
    let approved = resource(&approved_reply, 200);
    assert_eq!(approved.status, AccessRequestStatus::Approved);
    assert_eq!(
        approved.grant.as_ref().unwrap().valid_until - approved.grant.as_ref().unwrap().valid_from,
        120
    );
    assert_eq!(f.revision(org).await, before_revision + 1);
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    assert_eq!(
        transport(f, &owner, decision_browser, "POST", &decide, approve, &headers).await.body,
        approved_reply.body
    );
    assert_eq!(
        transport(f, &member, requester, "POST", &path, &body, &[("Idempotency-Key", &key)])
            .await
            .body,
        original.body
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    if use_browser {
        business(f, &other_family, "POST", &path, &body, &[("Idempotency-Key", &key)])
            .await
            .problem(409, "organization.conflict", false);
    }
    let cancellable = AccessRequestCreateRequest { id: Uuid::now_v7(), fields: fields.clone() }
        .to_json()
        .unwrap();
    let pending = resource(
        &transport(
            f,
            &member,
            requester,
            "POST",
            &path,
            &cancellable,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let cancel = format!("{path}/{}/cancel", pending.id);
    let cancel_key = Uuid::now_v7().to_string();
    let headers = [("Idempotency-Key", cancel_key.as_str()), ("If-Match", pending.etag.as_str())];
    transport(f, &member, requester, "POST", &cancel, b"{}", &headers).await.problem(
        400,
        "organization.invalid_request",
        false,
    );
    let cancelled = transport(f, &member, requester, "POST", &cancel, &[], &headers).await;
    assert_eq!(resource(&cancelled, 200).status, AccessRequestStatus::Cancelled);
    assert_eq!(
        transport(f, &member, requester, "POST", &cancel, &[], &headers).await.body,
        cancelled.body
    );
    assert_eq!(f.revision(org).await, before_revision + 1);
    let denied_request = AccessRequestCreateRequest { id: Uuid::now_v7(), fields: fields.clone() }
        .to_json()
        .unwrap();
    let pending = resource(
        &transport(
            f,
            &member,
            requester,
            "POST",
            &path,
            &denied_request,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let denied = resource(
        &transport(
            f,
            &owner,
            decision_browser,
            "POST",
            &format!("{path}/{}/decisions", pending.id),
            br#"{"decision":"deny"}"#,
            &[("Idempotency-Key", &Uuid::now_v7().to_string()), ("If-Match", &pending.etag)],
        )
        .await,
        200,
    );
    assert_eq!(denied.status, AccessRequestStatus::Denied);
    assert!(denied.grant.is_none());
    assert_eq!(f.revision(org).await, before_revision + 1);
    business(f, &member_browser, "POST", &check_path, &vec![b' '; 4097], &[]).await.problem(
        413,
        "organization.invalid_request",
        false,
    );
    let duplicate = format!(
        "{{\"data\":{{\"host\":\"{}\",\"host\":\"{}\",\"remote_user\":\"deploy\",\"duration_seconds\":120,\"reason\":\"x\"}}}}",
        host.id, host.id
    );
    business(f, &member_browser, "POST", &check_path, duplicate.as_bytes(), &[]).await.problem(
        400,
        "organization.invalid_request",
        false,
    );
    let family = super::scope::current_session(f, &member_browser).await.unwrap().family_id;
    super::scope::set_scope(f, family, "account:read orgs:read").await;
    business(f, &member_browser, "POST", &check_path, &check, &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    business(f, &member_browser, "GET", &format!("{path}?view=mine"), &[], &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    for (method, route, body) in [
        ("POST", path.clone(), b"{}".as_slice()),
        ("GET", format!("{path}/{}", pending.id), b"".as_slice()),
        ("POST", format!("{path}/{}/decisions", pending.id), b"{}".as_slice()),
        ("POST", format!("{path}/{}/cancel", pending.id), b"".as_slice()),
    ] {
        business(f, &member_browser, method, &route, body, &[]).await.problem(
            403,
            "policy.denied",
            false,
        );
    }
    f.execute("UPDATE account_entry_admission SET attempts=30 WHERE endpoint=46 AND kind=1").await;
    http(f.address, "POST", &check_path, &vec![b' '; 4097], &[]).await.problem(
        429,
        "auth.rate_limited",
        true,
    );
}

async fn native_lifecycle(f: &Fixture) {
    lifecycle(f, false).await;
}
async fn browser_lifecycle(f: &Fixture) {
    lifecycle(f, true).await;
}

browser_tests!(
    sqlite_access_request_device_http,
    postgres_access_request_device_http,
    native_lifecycle
);
browser_tests!(
    sqlite_access_request_browser_http,
    postgres_access_request_browser_http,
    browser_lifecycle
);
