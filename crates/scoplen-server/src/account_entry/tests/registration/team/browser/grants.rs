// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine browser Grant CRUD, protected preconditions and membership withdrawal.

use super::business::{business, create_asset};
use super::*;
use scoplen_api::{
    grant::{GrantCreateRequest, GrantFields, GrantPage, GrantReplaceRequest, GrantResource},
    inventory::InventoryType,
};
use serde_json::json;

fn grant(reply: &Reply, status: u16) -> GrantResource {
    assert_eq!(reply.status, status, "Grant response status");
    reply.private();
    GrantResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

#[allow(clippy::too_many_lines)]
async fn management(f: &Fixture) {
    let owner = actor(f, "grant-browser-owner").await;
    let recipient = actor(f, "grant-browser-member").await;
    let browser = login(f, &owner.registration).await;
    let other_family = login(f, &owner.registration).await;
    let member_browser = login(f, &recipient.registration).await;
    let org = create_team(f, &owner).await.id;
    let membership = super::super::inventory::enroll_member(f, &owner, &recipient, org).await;
    let host = create_asset(
        f,
        &browser,
        org,
        InventoryType::Host,
        json!({"name":"Granted","address":"grant.example.test"}),
    )
    .await;
    let path = format!("/api/v1/orgs/{org}/grants");
    let fields = GrantFields {
        membership,
        host: host.id,
        remote_user: "deploy".into(),
        valid_from: 0,
        valid_until: None,
    };
    let request = GrantCreateRequest { id: Uuid::now_v7(), fields: fields.clone() };
    let body = request.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let original = business(f, &browser, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    let created = grant(&original, 201);
    let target = format!("{path}/{}", created.id);
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let replay = business(
        f,
        &browser,
        "POST",
        &path,
        &serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&body).unwrap())
            .unwrap(),
        &[("Idempotency-Key", &key)],
    )
    .await;
    assert_eq!(replay.status, 201);
    assert_eq!(replay.body, original.body);
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    business(f, &other_family, "POST", &path, &body, &[("Idempotency-Key", &key)]).await.problem(
        409,
        "organization.conflict",
        false,
    );
    assert_eq!(grant(&call(f, &owner, "GET", &target, &[], &[]).await, 200), created);
    let page = business(f, &browser, "GET", &format!("{path}?limit=1"), &[], &[]).await;
    assert_eq!(page.status, 200);
    let page = GrantPage::from_json(&page.body).unwrap();
    assert_eq!(page.items, vec![created.clone()]);
    assert_eq!(page.next_cursor, None);
    let replace =
        GrantReplaceRequest { fields: GrantFields { remote_user: "ops".into(), ..fields.clone() } }
            .to_json()
            .unwrap();
    // Current authority wins over missing or malformed protected version headers.
    for headers in [&[][..], &[("If-Match", "W/\"weak\"")][..]] {
        business(f, &member_browser, "PUT", &target, &replace, headers).await.problem(
            403,
            "policy.denied",
            false,
        );
    }
    business(f, &browser, "PUT", &target, &replace, &[]).await.problem(
        428,
        "organization.precondition_required",
        false,
    );
    business(f, &browser, "PUT", &target, &replace, &[("If-Match", "W/\"weak\"")]).await.problem(
        400,
        "organization.invalid_request",
        false,
    );
    business(
        f,
        &browser,
        "PUT",
        &target,
        &replace,
        &[("If-Match", &created.etag), ("If-Match", &created.etag)],
    )
    .await
    .problem(400, "organization.invalid_request", false);
    let updated = grant(
        &business(f, &browser, "PUT", &target, &replace, &[("If-Match", &created.etag)]).await,
        200,
    );
    assert_ne!(updated.etag, created.etag);
    business(f, &browser, "PUT", &target, &replace, &[("If-Match", &created.etag)]).await.problem(
        412,
        "organization.precondition_failed",
        false,
    );
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    assert_eq!(
        grant(
            &business(f, &browser, "PUT", &target, &replace, &[("If-Match", &updated.etag)]).await,
            200
        ),
        updated
    );
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    business(f, &member_browser, "DELETE", &target, &[], &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    business(f, &browser, "DELETE", &target, &[], &[("If-Match", &created.etag)]).await.problem(
        412,
        "organization.precondition_failed",
        false,
    );
    let deleted =
        business(f, &browser, "DELETE", &target, &[], &[("If-Match", &updated.etag)]).await;
    assert_eq!(deleted.status, 204);
    assert_eq!(deleted.body, [] as [u8; 0]);
    business(f, &browser, "GET", &target, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert_eq!(
        business(f, &browser, "POST", &path, &body, &[("Idempotency-Key", &key)]).await.body,
        original.body
    );
    business(
        f,
        &browser,
        "POST",
        &path,
        &body,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await
    .problem(409, "organization.conflict", false);
    let invalid = GrantCreateRequest {
        id: Uuid::now_v7(),
        fields: GrantFields { membership: Uuid::now_v7(), ..fields.clone() },
    }
    .to_json()
    .unwrap();
    business(
        f,
        &browser,
        "POST",
        &path,
        &invalid,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await
    .problem(400, "organization.invalid_request", false);
    business(
        f,
        &browser,
        "POST",
        &path,
        &vec![b' '; 4097],
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await
    .problem(413, "organization.invalid_request", false);
    business(f, &browser, "GET", &format!("{path}?filter=unused"), &[], &[]).await.problem(
        400,
        "organization.invalid_request",
        false,
    );
    let filter = format!("resource eq \"grant:{}\"", created.id);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("filter", &filter)
        .finish();
    let audit_path = format!("/api/v1/orgs/{org}/audit-events?{query}");
    let audit_reply = business(f, &browser, "GET", &audit_path, &[], &[]).await;
    assert_eq!(audit_reply.status, 200);
    let events = scoplen_api::audit::AuditPage::from_json(&audit_reply.body).unwrap();
    assert_eq!(events.items.len(), 3);
    for event in events.items {
        assert_eq!(event.resource.as_ref().unwrap().id, created.id);
        assert_eq!(
            event.resource.as_ref().unwrap().kind,
            scoplen_api::audit::AuditResourceKind::Grant
        );
        assert_eq!(event.actor_account_id, Some(owner.registration.payload.account_id));
        assert!(event.actor_browser_family_id.is_some());
        assert!(event.actor_device_id.is_none());
    }
}

#[allow(clippy::too_many_lines)]
async fn membership_withdrawal(f: &Fixture) {
    let owner = actor(f, "grant-life-owner").await;
    let member = actor(f, "grant-life-member").await;
    let browser = login(f, &owner.registration).await;
    let member_browser = login(f, &member.registration).await;
    let org = create_team(f, &owner).await.id;
    let membership = super::super::inventory::enroll_member(f, &owner, &member, org).await;
    let host = create_asset(
        f,
        &browser,
        org,
        InventoryType::Host,
        json!({"name":"Membership","address":"member.example.test"}),
    )
    .await;
    let root = format!("/api/v1/orgs/{org}");
    let path = format!("{root}/grants");
    let member_path = format!("{root}/members/{membership}");
    let fields = GrantFields {
        membership,
        host: host.id,
        remote_user: "deploy".into(),
        valid_from: 0,
        valid_until: None,
    };
    let body = GrantCreateRequest { id: Uuid::now_v7(), fields: fields.clone() }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let original = business(f, &browser, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    let created = grant(&original, 201);
    let initial_member = TeamMemberResource::from_json(
        &business(f, &browser, "GET", &member_path, &[], &[]).await.body,
    )
    .unwrap();
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let suspend = TeamMemberUpdateRequest {
        roles: initial_member.roles.clone(),
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    let suspended = business(
        f,
        &browser,
        "PATCH",
        &member_path,
        &suspend,
        &[("If-Match", &initial_member.etag)],
    )
    .await;
    assert_eq!(suspended.status, 200);
    let suspended = TeamMemberResource::from_json(&suspended.body).unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit_events").await,
        audit + 1,
        "withdrawal keeps a single lifecycle audit"
    );
    business(f, &browser, "GET", &format!("{path}/{}", created.id), &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert_eq!(
        business(f, &browser, "POST", &path, &body, &[("Idempotency-Key", &key)]).await.body,
        original.body
    );
    let restore = TeamMemberUpdateRequest {
        roles: initial_member.roles.clone(),
        status: TeamMemberStatus::Active,
    }
    .to_json()
    .unwrap();
    assert_eq!(
        business(f, &browser, "PATCH", &member_path, &restore, &[("If-Match", &suspended.etag)])
            .await
            .status,
        200
    );
    business(f, &browser, "GET", &format!("{path}/{}", created.id), &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let next = GrantCreateRequest { id: Uuid::now_v7(), fields: fields.clone() }.to_json().unwrap();
    let next = grant(
        &business(
            f,
            &browser,
            "POST",
            &path,
            &next,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let leaving = TeamMemberResource::from_json(
        &business(f, &browser, "GET", &member_path, &[], &[]).await.body,
    )
    .unwrap();
    assert_eq!(
        business(f, &member_browser, "DELETE", &member_path, &[], &[("If-Match", &leaving.etag)])
            .await
            .status,
        204
    );
    business(f, &browser, "GET", &format!("{path}/{}", next.id), &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert!(current(f, &member_browser).await, "leaving a team preserves personal Account login");
    let organization =
        OrganizationResource::from_json(&business(f, &browser, "GET", &root, &[], &[]).await.body)
            .unwrap();
    let owner_grant = GrantCreateRequest {
        id: Uuid::now_v7(),
        fields: GrantFields { membership: organization.membership.id, ..fields },
    }
    .to_json()
    .unwrap();
    grant(
        &business(
            f,
            &browser,
            "POST",
            &path,
            &owner_grant,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let organization =
        OrganizationResource::from_json(&business(f, &browser, "GET", &root, &[], &[]).await.body)
            .unwrap();
    let dissolve = TeamDissolveRequest { organization_id: org }.to_json().unwrap();
    assert_eq!(
        business(
            f,
            &browser,
            "POST",
            &format!("{root}/dissolve"),
            &dissolve,
            &[("If-Match", &organization.etag), ("Idempotency-Key", &Uuid::now_v7().to_string())]
        )
        .await
        .status,
        200
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM organization_grants WHERE withdrawn_at_ms IS NULL").await,
        0
    );
    assert!(current(f, &browser).await);
}

browser_tests!(
    sqlite_account_browser_host_grant_management,
    postgres_account_browser_host_grant_management,
    management
);
browser_tests!(
    sqlite_account_browser_host_grant_membership_withdrawal,
    postgres_account_browser_host_grant_membership_withdrawal,
    membership_withdrawal
);
