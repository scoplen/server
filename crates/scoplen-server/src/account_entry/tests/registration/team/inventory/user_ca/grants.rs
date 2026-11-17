// SPDX-License-Identifier: AGPL-3.0-only
//! Real HTTP Grant-derived issuance, independent policy coexistence and withdrawal.

use super::*;
use scoplen_api::grant::{GrantCreateRequest, GrantFields, GrantReplaceRequest, GrantResource};

fn grant(reply: &Reply, status: u16) -> GrantResource {
    assert_eq!(reply.status, status, "Grant request failed");
    reply.private();
    GrantResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("complete shared Grant")
}

async fn create_grant(f: &Fixture, owner: &Actor, org: Uuid, fields: GrantFields) -> GrantResource {
    let body = GrantCreateRequest { id: Uuid::now_v7(), fields }.to_json().unwrap();
    grant(
        &call(
            f,
            owner,
            "POST",
            &format!("/api/v1/orgs/{org}/grants"),
            &body,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    )
}

fn expiry(reply: &Reply) -> u64 {
    let response = issued(reply);
    let certificate = Certificate::from_openssh(&response.certificate).unwrap();
    certificate.verify_signature().unwrap();
    certificate.valid_before()
}

#[allow(clippy::too_many_lines)]
async fn bounded_delegation(f: &Fixture) {
    let owner = actor(f, "grant-owner").await;
    let member = actor(f, "grant-member").await;
    let org = create_team(f, &owner).await.id;
    let membership = enroll_member(f, &owner, &member, org).await;
    provision(f, &owner, org).await;
    let group =
        create_asset(f, &owner, org, InventoryType::HostGroup, json!({"name":"Targets"})).await;
    let first = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"First","address":"first.example.test","groups":{group.id.to_string():true}}),
    )
    .await;
    let second = create_asset(f, &owner, org, InventoryType::Host,
        json!({"name":"Second","address":"second.example.test","groups":{group.id.to_string():true}})).await;
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::View {
            resources: vec![
                SimpleRuleSelector { object_type: ObjectType::HOST, id: first.id },
                SimpleRuleSelector { object_type: ObjectType::HOST, id: second.id },
                SimpleRuleSelector { object_type: ObjectType::HOST_GROUP, id: group.id },
            ],
        },
    )
    .await;
    let single = request(CertificateTargets::Hosts(vec![first.id]), 86_400);
    problem(&sign(f, &member, org, &single, Uuid::now_v7()).await, 403, "policy.denied");
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap();
    let fields = GrantFields {
        membership,
        host: first.id,
        remote_user: "deploy".into(),
        valid_from: now - 1,
        valid_until: Some(now + 300),
    };
    create_grant(f, &owner, org, fields.clone()).await;
    let key = Uuid::now_v7();
    let response = sign(f, &member, org, &single, key).await;
    assert_eq!(expiry(&response), now + 300);
    assert_eq!(
        sign(f, &member, org, &single, key).await.body,
        response.body,
        "confirmation preserves the original certificate"
    );
    create_grant(f, &owner, org, GrantFields { valid_until: Some(now + 900), ..fields.clone() })
        .await;
    assert_eq!(expiry(&sign(f, &member, org, &single, Uuid::now_v7()).await), now + 900);
    create_grant(
        f,
        &owner,
        org,
        GrantFields { host: second.id, valid_until: Some(now + 600), ..fields },
    )
    .await;
    let multiple = request(CertificateTargets::Hosts(vec![first.id, second.id]), 86_400);
    assert_eq!(expiry(&sign(f, &member, org, &multiple, Uuid::now_v7()).await), now + 600);
    let grouped = request(CertificateTargets::HostGroups(vec![group.id]), 86_400);
    problem(&sign(f, &member, org, &grouped, Uuid::now_v7()).await, 403, "policy.denied");
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::Connect {
            hosts: vec![first.id, second.id],
            host_groups: vec![],
            remote_user: "deploy".into(),
        },
    )
    .await;
    assert!(expiry(&sign(f, &member, org, &grouped, Uuid::now_v7()).await) >= now + 1_800);
    assert!(
        expiry(&sign(f, &member, org, &single, Uuid::now_v7()).await) >= now + 1_800,
        "independent ordinary permission has no Grant-specific cap"
    );
    add_policy(f, &owner, org, "forbid(principal, action == Action::\"connect\", resource);").await;
    problem(&sign(f, &member, org, &single, key).await, 403, "policy.denied");
}

#[allow(clippy::too_many_lines)]
async fn current_intervals_and_withdrawal(f: &Fixture) {
    let owner = actor(f, "grant-time-owner").await;
    let member = actor(f, "grant-time-member").await;
    let org = create_team(f, &owner).await.id;
    let membership = enroll_member(f, &owner, &member, org).await;
    provision(f, &owner, org).await;
    let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"Timed","address":"timed.example.test"}),
    )
    .await;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap();
    let fields = GrantFields {
        membership,
        host: host.id,
        remote_user: "deploy".into(),
        valid_from: now - 1,
        valid_until: Some(now + 300),
    };
    let path = format!("/api/v1/orgs/{org}/grants");
    let body = GrantCreateRequest { id: Uuid::now_v7(), fields: fields.clone() }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let original = call(f, &owner, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    let current = grant(&original, 201);
    let single = request(CertificateTargets::Hosts(vec![host.id]), 86_400);
    problem(&sign(f, &member, org, &single, Uuid::now_v7()).await, 404, "organization.not_found");
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id }],
        },
    )
    .await;
    let cert_key = Uuid::now_v7();
    let certificate = sign(f, &member, org, &single, cert_key).await;
    assert_eq!(expiry(&certificate), now + 300);
    let target = format!("{path}/{}", current.id);
    let withdrawn = call(f, &owner, "DELETE", &target, &[], &[("If-Match", &current.etag)]).await;
    assert_eq!(withdrawn.status, 204);
    assert_eq!(withdrawn.body, [] as [u8; 0]);
    let replay = call(f, &owner, "POST", &path, &body, &[("Idempotency-Key", &key)]).await;
    assert_eq!(replay.status, 201);
    assert_eq!(replay.body, original.body);
    problem(&call(f, &owner, "GET", &target, &[], &[]).await, 404, "organization.not_found");
    problem(&sign(f, &member, org, &single, cert_key).await, 403, "policy.denied");
    // None of these unrelated or inactive intervals can supply current connection authority.
    for next in [
        GrantFields { valid_from: now + 300, valid_until: Some(now + 600), ..fields.clone() },
        GrantFields { valid_from: now - 300, valid_until: Some(now - 1), ..fields.clone() },
        GrantFields { remote_user: "Deploy".into(), ..fields.clone() },
    ] {
        create_grant(f, &owner, org, next).await;
    }
    problem(&sign(f, &member, org, &single, Uuid::now_v7()).await, 403, "policy.denied");
    let active =
        create_grant(f, &owner, org, GrantFields { valid_until: None, ..fields.clone() }).await;
    assert!(expiry(&sign(f, &member, org, &single, Uuid::now_v7()).await) >= now + 1_800);
    let replacement = GrantReplaceRequest {
        fields: GrantFields { valid_until: Some(now + 120), ..fields.clone() },
    }
    .to_json()
    .unwrap();
    grant(
        &call(
            f,
            &owner,
            "PUT",
            &format!("{path}/{}", active.id),
            &replacement,
            &[("If-Match", &active.etag)],
        )
        .await,
        200,
    );
    assert_eq!(expiry(&sign(f, &member, org, &single, Uuid::now_v7()).await), now + 120);
    let member_path = format!("/api/v1/orgs/{org}/members/{membership}");
    let mut current_member =
        TeamMemberResource::from_json(&call(f, &owner, "GET", &member_path, &[], &[]).await.body)
            .unwrap();
    for status in [TeamMemberStatus::Suspended, TeamMemberStatus::Active] {
        let body = TeamMemberUpdateRequest { roles: current_member.roles.clone(), status }
            .to_json()
            .unwrap();
        let updated =
            call(f, &owner, "PATCH", &member_path, &body, &[("If-Match", &current_member.etag)])
                .await;
        assert_eq!(updated.status, 200);
        current_member = TeamMemberResource::from_json(&updated.body).unwrap();
    }
    problem(&sign(f, &member, org, &single, Uuid::now_v7()).await, 403, "policy.denied");
    create_grant(f, &owner, org, GrantFields { valid_until: Some(now + 120), ..fields }).await;
    assert_eq!(expiry(&sign(f, &member, org, &single, Uuid::now_v7()).await), now + 120);
    assert_eq!(
        expiry(&certificate),
        now + 300,
        "withdrawal does not rewrite disclosed certificates"
    );
}

macro_rules! grants_tests {
    ($sqlite:ident,$postgres:ident,$scenario:ident) => {
        #[tokio::test]
        async fn $sqlite() {
            let directory = directory();
            let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
            let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
            $scenario(&fixture).await;
            fixture.close().await;
        }
        #[cfg(feature = "postgres-integration")]
        #[tokio::test]
        async fn $postgres() {
            let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
            let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
            $scenario(&fixture).await;
            fixture.close().await;
            crate::account_entry::tests::postgres_cleanup(admin, schema).await;
        }
    };
}
grants_tests!(
    sqlite_host_grant_bounded_certificates,
    postgres_host_grant_bounded_certificates,
    bounded_delegation
);
grants_tests!(
    sqlite_host_grant_current_intervals,
    postgres_host_grant_current_intervals,
    current_intervals_and_withdrawal
);
