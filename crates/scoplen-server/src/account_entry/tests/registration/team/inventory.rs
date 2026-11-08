// SPDX-License-Identifier: AGPL-3.0-only
//! Public Device HTTP acceptance for authored inventory and current tenant policies.

use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use scoplen_api::{
    group_policy::{
        GroupResource, PolicyResource, SimpleRule, SimpleRuleInput, SimpleRuleSelector,
        SimpleRuleSubject,
    },
    inventory::{InventoryPage, InventoryResource, InventoryType},
    sync::{
        SyncOrganizationAckRequest, SyncOrganizationAckResponse, SyncOrganizationViewResponse,
        SyncSessionRequest, SyncSessionResponse,
    },
};
use scoplen_model::{Object, ObjectType};
use serde_json::json;

mod user_ca;

pub(super) async fn cbor_call(
    f: &Fixture,
    a: &Actor,
    method: &str,
    path: &str,
    body: &[u8],
) -> Reply {
    let proof = DpopProof::sign(
        &a.registration.device,
        &a.registration.device.public_key_sec1(),
        &DpopTarget::new(method, ORIGIN, path.split('?').next().expect("path")).expect("target"),
        DpopToken::Protected(&a.token.access_token),
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("proof");
    http(
        f.address,
        method,
        path,
        body,
        &[
            ("Content-Type", "application/cbor"),
            ("Authorization", &format!("DPoP {}", a.token.access_token)),
            ("DPoP", proof.as_str()),
            ("Origin", ORIGIN),
        ],
    )
    .await
}

fn resource(reply: &Reply, kind: InventoryType, status: u16) -> InventoryResource {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    InventoryResource::from_http_json(
        kind,
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("shared Resource")
}
fn group(reply: &Reply, status: u16) -> GroupResource {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    GroupResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("shared Group")
}
fn policy(reply: &Reply, status: u16) -> PolicyResource {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    PolicyResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("shared Policy")
}
fn sync_problem(reply: &Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/problem+cbor"));
    let value = scoplen_api::ProblemDetails::from_cbor(&reply.body).expect("CBOR problem");
    assert_eq!(value.code.as_str(), code);
    assert!(!value.changed);
}
async fn create_asset(
    f: &Fixture,
    a: &Actor,
    org: Uuid,
    kind: InventoryType,
    fields: serde_json::Value,
) -> InventoryResource {
    let body = serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"fields":fields}}))
        .expect("request");
    resource(
        &call(
            f,
            a,
            "POST",
            &format!("/api/v1/orgs/{org}/{}", kind.segment()),
            &body,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        kind,
        201,
    )
}
async fn enroll_member(f: &Fixture, a: &Actor, b: &Actor, org: Uuid) -> Uuid {
    let (inv, password, _, _) = issue(f, a, b, org, vec![TeamRole::Member]).await;
    let body = TeamInvitationAcceptRequest { password }.to_json().expect("accept");
    let reply = call(
        f,
        b,
        "POST",
        &format!("/api/v1/orgs/{org}/invitations/{}/accept", inv.id),
        body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 200);
    TeamAcceptanceReceipt::from_json(&reply.body).expect("membership").membership_id
}
pub(super) async fn descriptor(
    f: &Fixture,
    a: &Actor,
    organization: Uuid,
) -> scoplen_api::sync::SessionVault {
    let body = SyncSessionRequest {
        client_version: "0.1.0".into(),
        model_version: 1,
        device_id: a.registration.payload.device_id,
    }
    .to_cbor()
    .expect("session");
    let reply = cbor_call(f, a, "POST", "/sync/v1/session", &body).await;
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    SyncSessionResponse::from_cbor(&reply.body)
        .expect("session response")
        .vaults
        .into_iter()
        .find(|vault| vault.organization.is_some_and(|owner| owner.organization == organization))
        .expect("current Organization descriptor")
}
pub(super) async fn view(
    f: &Fixture,
    a: &Actor,
    vault: Uuid,
    revision: u64,
    after: u64,
    limit: u16,
) -> Reply {
    cbor_call(
        f,
        a,
        "GET",
        &format!("/sync/v1/vaults/{vault}/view?revision={revision}&after={after}&limit={limit}"),
        &[],
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn authoring(f: &Fixture) {
    let a = actor(f, "inventory-owner").await;
    let outsider = actor(f, "inventory-outsider").await;
    let org = create_team(f, &a).await.id;
    let root = format!("/api/v1/orgs/{org}");
    let id = Uuid::now_v7();
    let key = Uuid::now_v7().to_string();
    let body = json!({"id":id,"data":{"fields":{"name":"Main host","address":"ssh.example.test","port":22}}});
    let request = serde_json::to_vec(&body).expect("create");
    let host = resource(
        &call(f, &a, "POST", &format!("{root}/hosts"), &request, &[("Idempotency-Key", &key)])
            .await,
        InventoryType::Host,
        201,
    );
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let confirmation = resource(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/hosts"),
            serde_json::to_string_pretty(&body).expect("equivalent JSON").as_bytes(),
            &[("Idempotency-Key", &key)],
        )
        .await,
        InventoryType::Host,
        201,
    );
    assert_eq!(confirmation, host);
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    let changed =
        json!({"id":id,"data":{"fields":{"name":"Different","address":"ssh.example.test"}}});
    problem(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/hosts"),
            &serde_json::to_vec(&changed).unwrap(),
            &[("Idempotency-Key", &key)],
        )
        .await,
        409,
        "organization.conflict",
    );
    let path = format!("{root}/hosts/{id}");
    let replace = serde_json::to_vec(
        &json!({"data":{"fields":{"name":"Main host","address":"ssh.example.test","port":22}}}),
    )
    .unwrap();
    let same = resource(
        &call(f, &a, "PUT", &path, &replace, &[("If-Match", &host.etag)]).await,
        InventoryType::Host,
        200,
    );
    assert_eq!(same, host);
    assert_eq!(f.revision(org).await, revision);
    problem(
        &call(f, &a, "PUT", &path, &replace, &[]).await,
        428,
        "organization.precondition_required",
    );
    problem(
        &call(f, &a, "PUT", &path, &replace, &[("If-Match", "\"wrong\"")]).await,
        412,
        "organization.precondition_failed",
    );
    problem(&call(f, &outsider, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    let profile = create_asset(
        f,
        &a,
        org,
        InventoryType::AccessProfile,
        json!({"host":id,"username":"deploy","route":0}),
    )
    .await;
    problem(
        &call(f, &a, "DELETE", &path, &[], &[("If-Match", &host.etag)]).await,
        409,
        "organization.conflict",
    );
    let group_a =
        create_asset(f, &a, org, InventoryType::HostGroup, json!({"name":"Parent"})).await;
    let group_b = create_asset(
        f,
        &a,
        org,
        InventoryType::HostGroup,
        json!({"name":"Child","parent":group_a.id}),
    )
    .await;
    let cycle =
        serde_json::to_vec(&json!({"data":{"fields":{"name":"Parent","parent":group_b.id}}}))
            .unwrap();
    problem(
        &call(
            f,
            &a,
            "PUT",
            &format!("{root}/host-groups/{}", group_a.id),
            &cycle,
            &[("If-Match", &group_a.etag)],
        )
        .await,
        409,
        "organization.conflict",
    );
    create_asset(
        f,
        &a,
        org,
        InventoryType::Route,
        json!({"name":"Jump","kind":1,"hops":[profile.id]}),
    )
    .await;
    create_asset(f, &a, org, InventoryType::Snippet, json!({"name":"Status","template":"uptime"}))
        .await;
    create_asset(f, &a, org, InventoryType::GatewayNetwork, json!({"name":"Private network"}))
        .await;
    let key = scoplen_crypto::generate_ed25519_signing_key().expect("host key");
    let mut blob = Vec::new();
    for field in [b"ssh-ed25519".as_slice(), key.public_key().as_slice()] {
        blob.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(field);
    }
    let public = format!("ssh-ed25519 {}", STANDARD.encode(&blob));
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)));
    let trust=create_asset(f,&a,org,InventoryType::TrustRecord,json!({"host":id,"key":public,"fingerprint":fingerprint,"provenance":1,"revoked":false,"ca":false})).await;
    let fields: serde_json::Value =
        serde_json::from_slice(&trust.fields.to_json().unwrap()).unwrap();
    assert_eq!(fields["accepted_by_account"], a.registration.payload.account_id.to_string());
    assert_eq!(fields["accepted_by_device"], a.registration.payload.device_id.to_string());
    assert!(fields["accepted_at"].as_str().is_some());
    for kind in InventoryType::ALL {
        let reply =
            call(f, &a, "GET", &format!("{root}/{}?limit=1", kind.segment()), &[], &[]).await;
        assert_eq!(reply.status, 200);
        InventoryPage::from_json(kind, &reply.body).expect("typed Page");
    }
    let before = f.revision(org).await;
    let count = f.count("SELECT COUNT(*) FROM sync_objects").await;
    f.audit_failure(true).await;
    let failed = json!({"id":Uuid::now_v7(),"data":{"fields":{"name":"Rollback","address":"rollback.example.test"}}});
    problem(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/hosts"),
            &serde_json::to_vec(&failed).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        503,
        "organization.storage_unavailable",
    );
    f.audit_failure(false).await;
    assert_eq!(f.revision(org).await, before);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_objects").await, count);
    let snippet = create_asset(
        f,
        &a,
        org,
        InventoryType::Snippet,
        json!({"name":"Disposable","template":"whoami"}),
    )
    .await;
    let reply = call(
        f,
        &a,
        "DELETE",
        &format!("{root}/snippets/{}", snippet.id),
        &[],
        &[("If-Match", &snippet.etag)],
    )
    .await;
    assert_eq!(reply.status, 204);
    assert_eq!(reply.body, [] as [u8; 0]);
    problem(
        &call(f, &a, "GET", &format!("{root}/snippets/{}", snippet.id), &[], &[]).await,
        404,
        "organization.not_found",
    );
    let descriptor = descriptor(f, &a, org).await;
    let history_path = format!("/sync/v1/vaults/{}/objects/{}/versions", descriptor.id, snippet.id);
    let history = cbor_call(f, &a, "GET", &history_path, &[]).await;
    assert_eq!(history.status, 200);
    let history = scoplen_api::sync::SyncVersionsResponse::from_cbor(&history.body)
        .expect("retained deleted-object history");
    assert_eq!(history.versions.len(), 2);
    assert!(!history.versions[0].tombstone);
    assert!(history.versions[1].tombstone);
    for version in history.versions {
        let object = Object::decode(&version.payload).expect("canonical retained object");
        assert_eq!(object.id, snippet.id);
        assert_eq!(object.tombstone.is_some(), version.tombstone);
        let mut projection = object;
        projection.tombstone = None;
        assert_eq!(
            scoplen_api::inventory::InventoryFields::from_object(&projection)
                .expect("retained authoring fields"),
            snippet.fields
        );
    }
    sync_problem(
        &cbor_call(f, &outsider, "GET", &history_path, &[]).await,
        404,
        "sync.object_not_found",
    );
    let listing = call(f, &a, "GET", &format!("{root}/snippets"), &[], &[]).await;
    assert_eq!(listing.status, 200);
    let listing =
        InventoryPage::from_json(InventoryType::Snippet, &listing.body).expect("live list");
    assert!(listing.items.iter().all(|item| item.id != snippet.id));
    let reply =
        view(f, &a, descriptor.id, descriptor.organization.unwrap().view_revision, 0, 100).await;
    assert_eq!(reply.status, 200);
    let view = SyncOrganizationViewResponse::from_cbor(&reply.body).expect("live view");
    assert!(!view.more);
    assert!(view.objects.iter().all(|object| object.object_id != snippet.id));
}

#[allow(clippy::too_many_lines)]
async fn visibility(f: &Fixture) {
    let a = actor(f, "visibility-owner").await;
    let b = actor(f, "visibility-member").await;
    let org = create_team(f, &a).await.id;
    let root = format!("/api/v1/orgs/{org}");
    let membership = enroll_member(f, &a, &b, org).await;
    let mut host = create_asset(
        f,
        &a,
        org,
        InventoryType::Host,
        json!({"name":"Selected","address":"selected.example.test"}),
    )
    .await;
    let hidden = create_asset(
        f,
        &a,
        org,
        InventoryType::Host,
        json!({"name":"Hidden","address":"hidden.example.test"}),
    )
    .await;
    let profile = create_asset(
        f,
        &a,
        org,
        InventoryType::AccessProfile,
        json!({"host":host.id,"username":"deploy"}),
    )
    .await;
    let link = json!({"data":{"fields":{"name":"Selected","address":"selected.example.test","default_profile":profile.id}}});
    host = resource(
        &call(
            f,
            &a,
            "PUT",
            &format!("{root}/hosts/{}", host.id),
            &serde_json::to_vec(&link).unwrap(),
            &[("If-Match", &host.etag)],
        )
        .await,
        InventoryType::Host,
        200,
    );
    let move_profile = json!({"data":{"fields":{"host":hidden.id,"username":"deploy"}}});
    problem(
        &call(
            f,
            &a,
            "PUT",
            &format!("{root}/access-profiles/{}", profile.id),
            &serde_json::to_vec(&move_profile).unwrap(),
            &[("If-Match", &profile.etag)],
        )
        .await,
        409,
        "organization.conflict",
    );
    let admin_descriptor = descriptor(f, &a, org).await;
    let admin_revision = admin_descriptor.organization.unwrap().view_revision;
    let mut after = 0;
    let mut ids = std::collections::BTreeSet::new();
    let mut pages = 0;
    loop {
        let reply = view(f, &a, admin_descriptor.id, admin_revision, after, 1).await;
        assert_eq!(reply.status, 200);
        let page = SyncOrganizationViewResponse::from_cbor(&reply.body).unwrap();
        pages += 1;
        for object in &page.objects {
            assert!(ids.insert(object.object_id));
        }
        if !page.more {
            break;
        }
        assert!(page.next_cursor > after);
        after = page.next_cursor;
        assert!(pages < 5);
    }
    assert_eq!(pages, 3);
    assert_eq!(ids.len(), 3);
    create_asset(
        f,
        &a,
        org,
        InventoryType::Snippet,
        json!({"name":"Revision boundary","template":"pwd"}),
    )
    .await;
    sync_problem(
        &view(f, &a, admin_descriptor.id, admin_revision, after, 1).await,
        409,
        "sync.view_changed",
    );
    let member_vault = descriptor(f, &b, org).await;
    let vault = member_vault.id;
    let old = member_vault.organization.unwrap().view_revision;
    let empty = view(f, &b, vault, old, 0, 100).await;
    assert_eq!(empty.status, 200);
    assert_eq!(
        SyncOrganizationViewResponse::from_cbor(&empty.body).expect("empty current view").objects,
        [] as [scoplen_api::sync::SyncChange; 0]
    );
    let group_id = Uuid::now_v7();
    let group_path = format!("{root}/groups/{group_id}");
    let create = json!({"id":group_id,"data":{"name":"Operators","members":[membership]}});
    let created = group(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/groups"),
            &serde_json::to_vec(&create).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let source = SimpleRuleInput {
        organization: org,
        subject: SimpleRuleSubject::Group(group_id),
        rule: SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id }],
        },
    }
    .generate()
    .expect("shared rule generator");
    let policy_id = Uuid::now_v7();
    let policy_path = format!("{root}/policies/{policy_id}");
    let create =
        json!({"id":policy_id,"data":{"name":"Selected host","source":source,"enabled":true}});
    let created_policy = policy(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/policies"),
            &serde_json::to_vec(&create).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    sync_problem(&view(f, &b, vault, old, 0, 100).await, 409, "sync.view_changed");
    let revision = descriptor(f, &b, org).await.organization.unwrap().view_revision;
    let reply = view(f, &b, vault, revision, 0, 1).await;
    assert_eq!(reply.status, 200);
    let current = SyncOrganizationViewResponse::from_cbor(&reply.body).expect("current view");
    assert!(!current.more);
    assert_eq!(current.objects.len(), 1);
    assert_eq!(Object::decode(&current.objects[0].payload).unwrap().id, host.id);
    let readable = resource(
        &call(f, &b, "GET", &format!("{root}/hosts/{}", host.id), &[], &[]).await,
        InventoryType::Host,
        200,
    );
    let fields: serde_json::Value =
        serde_json::from_slice(&readable.fields.to_json().unwrap()).unwrap();
    assert_eq!(fields["default_profile"], profile.id.to_string());
    for path in
        [format!("{root}/hosts/{}", hidden.id), format!("{root}/access-profiles/{}", profile.id)]
    {
        problem(&call(f, &b, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    }
    let reply = call(f, &b, "GET", &format!("{root}/hosts?limit=1"), &[], &[]).await;
    assert_eq!(reply.status, 200);
    let page = InventoryPage::from_json(InventoryType::Host, &reply.body).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, host.id);
    assert!(page.next_cursor.is_none());
    let ack = SyncOrganizationAckRequest { view_revision: revision, cursor: current.next_cursor }
        .to_cbor()
        .unwrap();
    let reply = cbor_call(f, &b, "POST", &format!("/sync/v1/vaults/{vault}/ack"), &ack).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        SyncOrganizationAckResponse::from_cbor(&reply.body).unwrap().view_revision,
        revision
    );
    let history = cbor_call(
        f,
        &b,
        "GET",
        &format!("/sync/v1/vaults/{vault}/objects/{}/versions", host.id),
        &[],
    )
    .await;
    assert_eq!(history.status, 200);
    assert_eq!(
        scoplen_api::sync::SyncVersionsResponse::from_cbor(&history.body).unwrap().versions.len(),
        2
    );
    sync_problem(
        &cbor_call(
            f,
            &b,
            "GET",
            &format!("/sync/v1/vaults/{vault}/objects/{}/versions", profile.id),
            &[],
        )
        .await,
        404,
        "sync.object_not_found",
    );
    for suffix in ["changes?after=0&limit=1", "snapshot?after=0&limit=1"] {
        sync_problem(
            &cbor_call(f, &b, "GET", &format!("/sync/v1/vaults/{vault}/{suffix}"), &[]).await,
            409,
            "sync.read_only",
        );
    }
    problem(
        &call(f, &a, "DELETE", &group_path, &[], &[("If-Match", &created.etag)]).await,
        409,
        "organization.conflict",
    );
    let disable = json!({"data":{"name":created_policy.fields.name,"source":created_policy.fields.source,"enabled":false}});
    let disabled = policy(
        &call(
            f,
            &a,
            "PUT",
            &policy_path,
            &serde_json::to_vec(&disable).unwrap(),
            &[("If-Match", &created_policy.etag)],
        )
        .await,
        200,
    );
    sync_problem(&view(f, &b, vault, revision, 0, 100).await, 409, "sync.view_changed");
    let revision = descriptor(f, &b, org).await.organization.unwrap().view_revision;
    let reply = view(f, &b, vault, revision, 0, 100).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        SyncOrganizationViewResponse::from_cbor(&reply.body).unwrap().objects,
        [] as [scoplen_api::sync::SyncChange; 0]
    );
    let mut owner_events = f.notifications.subscribe(scoplen_sync::http::AuthenticatedDevice {
        account_id: a.registration.payload.account_id.into_bytes(),
        device_id: a.registration.payload.device_id.into_bytes(),
    });
    assert_eq!(
        call(f, &a, "DELETE", &policy_path, &[], &[("If-Match", &disabled.etag)]).await.status,
        204
    );
    let committed_revision = f.revision(org).await;
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let event=scoplen_api::sync::SyncNotification::from_cbor(&owner_events.recv().await.expect("committed owner hint")).unwrap();
            if matches!(event,scoplen_api::sync::SyncNotification::OrganizationViewChanged{organization,view_revision,..} if organization==org&&view_revision==committed_revision){break;}
        }
    }).await.expect("ordered notification drain");
    let before = group(&call(f, &a, "GET", &group_path, &[], &[]).await, 200);
    let member_path = format!("{root}/members/{membership}");
    let member_reply = call(f, &a, "GET", &member_path, &[], &[]).await;
    let member = TeamMemberResource::from_json(&member_reply.body).unwrap();
    let suspend = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Member],
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    let mut member_events = f.notifications.subscribe(scoplen_sync::http::AuthenticatedDevice {
        account_id: b.registration.payload.account_id.into_bytes(),
        device_id: b.registration.payload.device_id.into_bytes(),
    });
    assert_eq!(
        call(f, &a, "PATCH", &member_path, &suspend, &[("If-Match", &member.etag)]).await.status,
        200
    );
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(5), member_events.recv())
        .await
        .expect("membership hint deadline")
        .expect("membership hint");
    assert_eq!(
        scoplen_api::sync::SyncNotification::from_cbor(&bytes).unwrap(),
        scoplen_api::sync::SyncNotification::MembershipsChanged
    );
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(5), owner_events.recv())
        .await
        .expect("owner hint deadline")
        .expect("owner hint");
    assert!(
        matches!(scoplen_api::sync::SyncNotification::from_cbor(&bytes).unwrap(),scoplen_api::sync::SyncNotification::OrganizationViewChanged{organization,..} if organization==org)
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), member_events.recv())
            .await
            .is_err(),
        "lost membership receives no Organization descriptor"
    );
    let after = group(&call(f, &a, "GET", &group_path, &[], &[]).await, 200);
    assert_eq!(after.fields.members, [] as [Uuid; 0]);
    assert_ne!(after.etag, before.etag);
    sync_problem(&view(f, &b, vault, revision, 0, 100).await, 404, "sync.object_not_found");
    let removed = call(f, &a, "DELETE", &group_path, &[], &[("If-Match", &after.etag)]).await;
    assert_eq!(removed.status, 204);
    let current = current_team(f, &a, org).await;
    let source = "forbid(principal is Account, action == Action::\"manage_organization\", resource is Organization);";
    let create = json!({"id":Uuid::now_v7(),"data":{"name":"Protected settings","source":source,"enabled":true}});
    policy(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/policies"),
            &serde_json::to_vec(&create).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let rename = scoplen_api::organization::OrganizationUpdateRequest::new("Denied rename")
        .unwrap()
        .to_json()
        .unwrap();
    problem(
        &call(f, &a, "PATCH", &root, &rename, &[("If-Match", &current.etag)]).await,
        403,
        "policy.denied",
    );
}

#[tokio::test]
async fn sqlite_public_organization_inventory_authoring_and_policy_views() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let mut fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    authoring(&fixture).await;
    visibility(&fixture).await;
    read_budgets(&mut fixture).await;
    admission(&fixture).await;
    fixture.close().await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_public_organization_inventory_authoring_and_policy_views() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let mut fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    authoring(&fixture).await;
    visibility(&fixture).await;
    read_budgets(&mut fixture).await;
    admission(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

async fn read_budgets(f: &mut Fixture) {
    use scoplen_sync::http::ReadBodyLimits;

    let actor = actor(f, "inventory-read-budgets").await;
    let org = create_team(f, &actor).await.id;
    let mut expected = Vec::new();
    for (name, size) in [("First", 1_024), ("Second", 1_024), ("Larger", 2_048)] {
        expected.push(
            create_asset(
                f,
                &actor,
                org,
                InventoryType::Snippet,
                json!({"name":name,"template":"x".repeat(size)}),
            )
            .await
            .id,
        );
    }
    let descriptor = descriptor(f, &actor, org).await;
    let revision = descriptor.organization.unwrap().view_revision;
    let limits = ReadBodyLimits::new(1_400, 1_500).expect("configured read budgets");
    f.restart_reads(limits).await;
    let mut after = 0;
    for id in &expected[..2] {
        let reply = view(f, &actor, descriptor.id, revision, after, 100).await;
        assert_eq!(reply.status, 200);
        assert!(reply.body.len() <= 1_500);
        let page = SyncOrganizationViewResponse::from_cbor_with_limits(
            &reply.body,
            scoplen_api::sync::SyncReadLimits { max_envelope_bytes: 1_400, max_body_bytes: 1_500 },
        )
        .expect("bounded prefix");
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].object_id, *id);
        assert!(page.more);
        assert!(page.next_cursor > after);
        after = page.next_cursor;
    }
    sync_problem(
        &view(f, &actor, descriptor.id, revision, after, 100).await,
        503,
        "sync.storage_unavailable",
    );
    f.restart_reads(ReadBodyLimits::new(4_096, 1).expect("body-only bound")).await;
    sync_problem(
        &view(f, &actor, descriptor.id, revision, 0, 100).await,
        503,
        "sync.storage_unavailable",
    );
    f.restart_reads(ReadBodyLimits::default()).await;
    let reply = view(f, &actor, descriptor.id, revision, after, 100).await;
    assert_eq!(reply.status, 200);
    let page = SyncOrganizationViewResponse::from_cbor(&reply.body).expect("resumed final entry");
    assert_eq!(page.objects.len(), 1);
    assert_eq!(page.objects[0].object_id, expected[2]);
    assert!(!page.more);
}

async fn admission(f: &Fixture) {
    let actor = actor(f, "inventory-admission").await;
    let org = create_team(f, &actor).await.id;
    let fields = json!({"name":"Readers","members":[]});
    let group_id = Uuid::now_v7();
    let created = group(
        &call(
            f,
            &actor,
            "POST",
            &format!("/api/v1/orgs/{org}/groups"),
            &serde_json::to_vec(&json!({"id":group_id,"data":fields})).unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    );
    let path = format!("/api/v1/orgs/{org}/groups/{group_id}");
    let body = serde_json::to_vec(&json!({"data":fields})).unwrap();
    let clock = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let admission_time = (clock / 60_000 + 3) * 60_000;
    f.execute(&format!(
        "UPDATE account_entry_state SET time_high_water_ms={admission_time} WHERE singleton=1"
    ))
    .await;
    let revision = f.revision(org).await;
    for _ in 0..10 {
        assert_eq!(
            group(&call(f, &actor, "PUT", &path, &body, &[("If-Match", &created.etag)]).await, 200),
            created
        );
    }
    let rejected = call(f, &actor, "PUT", &path, &body, &[("If-Match", &created.etag)]).await;
    rejected.problem(429, "auth.rate_limited", true);
    assert!(
        rejected
            .header("retry-after")
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|value| (1..=300).contains(&value))
    );
    assert_eq!(f.revision(org).await, revision);
    create_asset(
        f,
        &actor,
        org,
        InventoryType::Host,
        json!({"name":"Independent operation","address":"independent.example.test"}),
    )
    .await;
}
