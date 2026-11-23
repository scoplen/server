// SPDX-License-Identifier: AGPL-3.0-only
//! Pending Host approvals stay bound to their original Organization and Membership.

use super::super::super::{
    inventory::enroll_member,
    tls::{TlsFixture, personal_sync_after_revocation},
};
use super::*;
use axum::body::Body;
use scoplen_api::{
    grant::GrantPage,
    group_policy::{SimpleRule, SimpleRuleInput, SimpleRuleSelector, SimpleRuleSubject},
};
use scoplen_model::ObjectType;

struct Pending {
    org: Uuid,
    resource: AccessRequestResource,
}

impl Pending {
    fn path(&self) -> String {
        format!("/api/v1/orgs/{}/access-requests/{}", self.org, self.resource.id)
    }

    async fn approve(&self, tls: &TlsFixture, browser: &Browser) -> Reply {
        let request = TlsFixture::signed(
            &browser.key,
            &browser.access,
            "POST",
            &format!("{}/decisions", self.path()),
        )
        .header("Origin", ORIGIN)
        .header("Content-Type", "application/json")
        .header("If-Match", &self.resource.etag)
        .header("Idempotency-Key", Uuid::now_v7().to_string())
        .body(Body::from(r#"{"decision":"approve"}"#))
        .unwrap();
        tls.send(request).await
    }

    async fn grants(&self, tls: &TlsFixture, owner: &Actor) -> GrantPage {
        let reply = tls.get(owner, &format!("/api/v1/orgs/{}/grants", self.org)).await;
        assert_eq!(reply.status, 200);
        reply.private();
        let page = GrantPage::from_json(&reply.body).unwrap();
        assert!(page.next_cursor.is_none());
        page
    }
}

async fn pending(
    f: &Fixture,
    tls: &TlsFixture,
    owner: &Actor,
    browser: &Browser,
    member: &Actor,
    remote_user: &str,
) -> Pending {
    let org = create_team(f, owner).await.id;
    let membership = enroll_member(f, owner, member, org).await;
    let host = create_asset(
        f,
        browser,
        org,
        InventoryType::Host,
        json!({"name":"Build host","address":"build.example.test"}),
    )
    .await
    .id;
    for rule in [
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host }],
        },
        SimpleRule::RequestAccess { hosts: vec![host] },
    ] {
        let source = SimpleRuleInput {
            organization: org,
            subject: SimpleRuleSubject::Membership(membership),
            rule,
        }
        .generate()
        .unwrap();
        let policy = json!({"id":Uuid::now_v7(),"data":{"name":"Scoped host access","source":source,"enabled":true}});
        let reply = business(
            f,
            browser,
            "POST",
            &format!("/api/v1/orgs/{org}/policies"),
            &serde_json::to_vec(&policy).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await;
        assert_eq!(reply.status, 201);
    }
    let create = AccessRequestCreateRequest {
        id: Uuid::now_v7(),
        fields: AccessRequestFields {
            host,
            remote_user: remote_user.into(),
            duration_seconds: 120,
            reason: "Scheduled maintenance".into(),
        },
    };
    let request = TlsFixture::signed(
        &member.registration.device,
        &member.token.access_token,
        "POST",
        &format!("/api/v1/orgs/{org}/access-requests"),
    )
    .header("Origin", ORIGIN)
    .header("Content-Type", "application/json")
    .header("Idempotency-Key", Uuid::now_v7().to_string())
    .body(Body::from(create.to_json().unwrap()))
    .unwrap();
    let resource = resource(&tls.send(request).await, 201);
    assert_eq!(resource.id, create.id);
    assert_eq!(resource.status, AccessRequestStatus::Pending);
    assert_eq!(resource.fields, create.fields);
    assert_eq!(resource.requester_membership_id, membership);
    assert_eq!(resource.requester_account_id, member.registration.payload.account_id);
    Pending { org, resource }
}

async fn offboarding(f: &Fixture) {
    let owner = actor(f, "offboarding-owner").await;
    let member = actor(f, "offboarding-member").await;
    let browser = login(f, &owner.registration).await;
    let tls = TlsFixture::start(f).await;
    let removed = pending(f, &tls, &owner, &browser, &member, "build").await;
    let retained = pending(f, &tls, &owner, &browser, &member, "deploy").await;
    let path = format!(
        "/api/v1/orgs/{}/members/{}",
        removed.org, removed.resource.requester_membership_id,
    );
    let current = tls.get(&owner, &path).await;
    assert_eq!(current.status, 200);
    let current = TeamMemberResource::from_json(&current.body).unwrap();
    let delete = TlsFixture::signed(&browser.key, &browser.access, "DELETE", &path)
        .header("Origin", ORIGIN)
        .header("Content-Type", "application/json")
        .header("If-Match", &current.etag)
        .body(Body::empty())
        .unwrap();
    assert_eq!(tls.send(delete).await.status, 204);

    removed.approve(&tls, &browser).await.problem(409, "organization.conflict", false);
    assert_eq!(resource(&tls.get(&owner, &removed.path()).await, 200), removed.resource);
    assert_eq!(removed.grants(&tls, &owner).await.items, []);
    tls.get(&member, &removed.path()).await.problem(404, "organization.not_found", false);
    let host_path = |pending: &Pending| {
        format!("/api/v1/orgs/{}/hosts/{}", pending.org, pending.resource.fields.host)
    };
    tls.get(&member, &host_path(&removed)).await.problem(404, "organization.not_found", false);
    assert_eq!(tls.get(&member, &host_path(&retained)).await.status, 200);
    assert_eq!(resource(&tls.get(&member, &retained.path()).await, 200), retained.resource);
    let approved = resource(&retained.approve(&tls, &browser).await, 200);
    assert_eq!(approved.status, AccessRequestStatus::Approved);
    assert_eq!(approved.id, retained.resource.id);
    assert_eq!(approved.fields, retained.resource.fields);
    let issued = approved.grant.unwrap();
    let page = retained.grants(&tls, &owner).await;
    let [grant] = page.items.as_slice() else { panic!("expected one Host grant") };
    assert_eq!(grant.id, issued.id);
    assert_eq!(grant.fields.membership, retained.resource.requester_membership_id);
    assert_eq!(grant.fields.host, retained.resource.fields.host);
    assert_eq!(grant.fields.remote_user, retained.resource.fields.remote_user);
    assert_eq!(grant.fields.valid_from, issued.valid_from);
    assert_eq!(grant.fields.valid_until, Some(issued.valid_until));
    assert_eq!(
        issued.valid_until - issued.valid_from,
        u64::from(retained.resource.fields.duration_seconds)
    );
    personal_sync_after_revocation(&tls, &member, &owner, &[retained.org]).await;
}

browser_tests!(
    sqlite_native_team_pending_request_offboarding_over_https,
    postgres_native_team_pending_request_offboarding_over_https,
    offboarding
);
