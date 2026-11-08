// SPDX-License-Identifier: AGPL-3.0-only
//! Account-browser authoring consumed by real enrolled Devices on the public API.

use scoplen_api::{
    group_policy::{
        GroupCreateRequest, GroupResource, PolicyResource, SimpleRule, SimpleRuleInput,
        SimpleRuleSelector, SimpleRuleSubject,
    },
    inventory::{InventoryCreateRequest, InventoryResource, InventoryType},
    sync::SyncOrganizationViewResponse,
};
use scoplen_model::{Object, ObjectType};
use serde_json::json;

use super::*;

async fn business(
    f: &Fixture,
    browser: &Browser,
    method: &str,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Reply {
    let proof = DpopProof::sign(
        &browser.key,
        &browser.key.public_key_sec1(),
        &DpopTarget::new(method, ORIGIN, path.split('?').next().expect("route"))
            .expect("business target"),
        DpopToken::Protected(&browser.access),
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("business proof");
    let authorization = format!("DPoP {}", browser.access);
    let mut headers = vec![("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
    if method != "GET" {
        headers.extend([("Origin", ORIGIN), ("Content-Type", "application/json")]);
    }
    headers.extend_from_slice(extra);
    http(f.address, method, path, body, &headers).await
}

fn asset(reply: &Reply, kind: InventoryType, status: u16) -> InventoryResource {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert!(reply.header("x-request-id").is_some());
    InventoryResource::from_http_json(
        kind,
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("complete shared asset")
}

async fn create_asset(
    f: &Fixture,
    browser: &Browser,
    org: Uuid,
    kind: InventoryType,
    fields: serde_json::Value,
) -> InventoryResource {
    let body = serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"fields":fields}}))
        .expect("asset request");
    asset(
        &business(
            f,
            browser,
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

async fn receipt_digest(f: &Fixture, key: Uuid) -> Vec<u8> {
    match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query_scalar(
            "SELECT request_digest FROM organization_inventory_receipts WHERE idempotency_key=$1",
        )
        .bind(key.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await,
        AuthBackend::Postgres(store) => sqlx::query_scalar(
            "SELECT request_digest FROM organization_inventory_receipts WHERE idempotency_key=$1",
        )
        .bind(key.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await,
    }
    .expect("retained create digest")
}

async fn family(f: &Fixture, browser: &Browser) -> Uuid {
    let token = AccountBrowserAccessToken::parse(&browser.access).expect("access");
    let current = match &f.backend {
        AuthBackend::Sqlite(store) => store.current_account_browser_session(&token, ORIGIN).await,
        AuthBackend::Postgres(store) => store.current_account_browser_session(&token, ORIGIN).await,
    }
    .expect("family lookup")
    .expect("current family");
    Uuid::from_bytes(current.family_id)
}

async fn rotate(f: &Fixture, browser: &mut Browser) {
    let reply = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    let (access, cookie) = session(&reply, false);
    browser.access = access;
    browser.cookie = cookie;
}

#[allow(clippy::too_many_lines)]
async fn authoring_and_receipts(f: &Fixture) {
    let native = actor(f, "browser-author").await;
    let mut browser = login(f, &native.registration).await;
    let other = login(f, &native.registration).await;
    let family = family(f, &browser).await;
    let profile = business(f, &browser, "GET", "/api/v1/accounts/me", &[], &[]).await;
    assert_eq!(profile.status, 200);
    profile.private();
    assert!(profile.header("x-request-id").is_some());
    let profile = scoplen_api::account_profile::AccountProfile::from_json(&profile.body)
        .expect("current Account");
    assert_eq!(profile.id, native.registration.payload.account_id);
    let body = OrganizationCreateRequest::new("Browser team").unwrap().to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let reply =
        business(f, &browser, "POST", "/api/v1/orgs", &body, &[("Idempotency-Key", &key)]).await;
    assert_eq!(reply.status, 201);
    let team = OrganizationResource::from_json(&reply.body).expect("browser team");
    let confirmed =
        business(f, &other, "POST", "/api/v1/orgs", &body, &[("Idempotency-Key", &key)]).await;
    assert_eq!(confirmed.status, 201, "team receipts remain Account-scoped");
    assert_eq!(confirmed.body, reply.body);
    let root = format!("/api/v1/orgs/{}", team.id);
    let path = format!("{root}/hosts");
    let key = Uuid::now_v7();
    let body=serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"fields":{"name":"Browser host","address":"ssh.example.test","port":22}}})).unwrap();
    let created = asset(
        &business(f, &browser, "POST", &path, &body, &[("Idempotency-Key", &key.to_string())])
            .await,
        InventoryType::Host,
        201,
    );
    let revision = f.revision(team.id).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let canonical =
        InventoryCreateRequest::from_json(InventoryType::Host, &body).unwrap().to_json().unwrap();
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-inventory-create-v1".as_slice(),
        ORIGIN.as_bytes(),
        native.registration.payload.account_id.as_bytes(),
        b"account-browser",
        family.as_bytes(),
        b"POST",
        path.as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    assert_eq!(receipt_digest(f, key).await, hash.finalize().as_slice());
    rotate(f, &mut browser).await;
    let confirmation =
        business(f, &browser, "POST", &path, &body, &[("Idempotency-Key", &key.to_string())]).await;
    assert_eq!(asset(&confirmation, InventoryType::Host, 201), created);
    assert_eq!(f.revision(team.id).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    business(f, &other, "POST", &path, &body, &[("Idempotency-Key", &key.to_string())])
        .await
        .problem(409, "organization.conflict", false);
    call(f, &native, "POST", &path, &body, &[("Idempotency-Key", &key.to_string())]).await.problem(
        409,
        "organization.conflict",
        false,
    );

    // Native digests preserve the exact existing Device-bound byte sequence.
    let native_key = Uuid::now_v7();
    let native_body=serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"fields":{"name":"Native host","address":"native.example.test"}}})).unwrap();
    asset(
        &call(
            f,
            &native,
            "POST",
            &path,
            &native_body,
            &[("Idempotency-Key", &native_key.to_string())],
        )
        .await,
        InventoryType::Host,
        201,
    );
    let canonical = InventoryCreateRequest::from_json(InventoryType::Host, &native_body)
        .unwrap()
        .to_json()
        .unwrap();
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-inventory-create-v1".as_slice(),
        ORIGIN.as_bytes(),
        native.registration.payload.account_id.as_bytes(),
        native.registration.payload.device_id.as_bytes(),
        b"POST",
        path.as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    assert_eq!(receipt_digest(f, native_key).await, hash.finalize().as_slice());

    let control_path = format!("{root}/groups");
    let control_key = Uuid::now_v7();
    let control_body = serde_json::to_vec(
        &json!({"id":Uuid::now_v7(),"data":{"name":"Browser readers","members":[]}}),
    )
    .unwrap();
    let created = business(
        f,
        &browser,
        "POST",
        &control_path,
        &control_body,
        &[("Idempotency-Key", &control_key.to_string())],
    )
    .await;
    assert_eq!(created.status, 201);
    GroupResource::from_json(&created.body).expect("browser Group");
    let canonical = GroupCreateRequest::from_json(&control_body).unwrap().to_json().unwrap();
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-control-create-v1".as_slice(),
        ORIGIN.as_bytes(),
        native.registration.payload.account_id.as_bytes(),
        b"account-browser",
        family.as_bytes(),
        b"POST",
        control_path.as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    assert_eq!(receipt_digest(f, control_key).await, hash.finalize().as_slice());
    rotate(f, &mut browser).await;
    let confirmed = business(
        f,
        &browser,
        "POST",
        &control_path,
        &control_body,
        &[("Idempotency-Key", &control_key.to_string())],
    )
    .await;
    assert_eq!(confirmed.status, 201);
    assert_eq!(confirmed.body, created.body);
    business(
        f,
        &other,
        "POST",
        &control_path,
        &control_body,
        &[("Idempotency-Key", &control_key.to_string())],
    )
    .await
    .problem(409, "organization.conflict", false);
    call(
        f,
        &native,
        "POST",
        &control_path,
        &control_body,
        &[("Idempotency-Key", &control_key.to_string())],
    )
    .await
    .problem(409, "organization.conflict", false);

    let native_control_key = Uuid::now_v7();
    let native_control = serde_json::to_vec(
        &json!({"id":Uuid::now_v7(),"data":{"name":"Native readers","members":[]}}),
    )
    .unwrap();
    assert_eq!(
        call(
            f,
            &native,
            "POST",
            &control_path,
            &native_control,
            &[("Idempotency-Key", &native_control_key.to_string())]
        )
        .await
        .status,
        201
    );
    let canonical = GroupCreateRequest::from_json(&native_control).unwrap().to_json().unwrap();
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-control-create-v1".as_slice(),
        ORIGIN.as_bytes(),
        native.registration.payload.account_id.as_bytes(),
        native.registration.payload.device_id.as_bytes(),
        b"POST",
        control_path.as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    assert_eq!(receipt_digest(f, native_control_key).await, hash.finalize().as_slice());

    let descriptor = super::super::inventory::descriptor(f, &native, team.id).await;
    let revision = descriptor.organization.expect("Organization").view_revision;
    let view = super::super::inventory::view(f, &native, descriptor.id, revision, 0, 100).await;
    assert_eq!(view.status, 200);
    let view = SyncOrganizationViewResponse::from_cbor(&view.body).unwrap();
    let object = view
        .objects
        .iter()
        .find(|item| item.object_id == created_asset_id(&body))
        .expect("browser Host visible to Device");
    let object = Object::decode(&object.payload).expect("K-1");
    assert!(object.fields.values().all(|entry| entry.origin == family));
    assert_ne!(family, native.registration.payload.device_id);
    let events: Vec<Vec<u8>> = match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1")
                .bind(team.id.as_bytes().as_slice())
                .fetch_all(store.pool())
                .await
        }
        AuthBackend::Postgres(store) => {
            sqlx::query_scalar("SELECT event_bytes FROM audit_events WHERE organization_id=$1")
                .bind(team.id.as_bytes().as_slice())
                .fetch_all(store.pool())
                .await
        }
    }
    .unwrap();
    assert!(
        events
            .iter()
            .map(|event| serde_json::from_slice::<serde_json::Value>(event).unwrap())
            .any(|event| event["browser_family_id"] == family.to_string()
                && event.get("device_id").is_none())
    );
    // The browser never gains Device sync, CA or the excluded inventory families.
    for path in [
        format!("{root}/trust-records"),
        format!("{root}/snippets"),
        format!("{root}/gateway-networks"),
    ] {
        business(f, &browser, "GET", &path, &[], &[]).await.problem(403, "policy.denied", false);
    }
    business(f, &browser, "GET", &format!("{root}/certificate-authorities"), &[], &[])
        .await
        .problem(401, "auth.authentication_required", false);
    let denied = business(
        f,
        &browser,
        "GET",
        &format!("/sync/v1/vaults/{}/view?revision={revision}&after=0&limit=100", descriptor.id),
        &[],
        &[],
    )
    .await;
    assert_eq!(denied.status, 401);
}

fn created_asset_id(body: &[u8]) -> Uuid {
    InventoryCreateRequest::from_json(InventoryType::Host, body).unwrap().id
}

#[allow(clippy::too_many_lines)]
async fn invitation_inventory_and_withdrawal(f: &Fixture) {
    let owner = actor(f, "browser-owner").await;
    let recipient = actor(f, "browser-recipient").await;
    let outsider = actor(f, "browser-outsider").await;
    let owner_browser = login(f, &owner.registration).await;
    let recipient_browser = login(f, &recipient.registration).await;
    let outsider_browser = login(f, &outsider.registration).await;
    let team_body = OrganizationCreateRequest::new("Browser managed").unwrap().to_json().unwrap();
    let reply = business(
        f,
        &owner_browser,
        "POST",
        "/api/v1/orgs",
        &team_body,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 201);
    let team = OrganizationResource::from_json(&reply.body).unwrap();
    let org = team.id;
    let root = format!("/api/v1/orgs/{org}");
    let id = Uuid::now_v7();
    let password = TeamInvitationPassword::generate().unwrap();
    let invitation_body = TeamInvitationCreateRequest {
        invitation_id: id,
        recipient_username: recipient.registration.payload.username.clone(),
        roles: vec![TeamRole::Member],
        password_verifier: password.verifier(ORIGIN, &org, &id).unwrap(),
    }
    .to_json()
    .unwrap();
    let issued = business(
        f,
        &owner_browser,
        "POST",
        &format!("{root}/invitations"),
        invitation_body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    invitation(&issued, 201);
    let accept_path = format!("{root}/invitations/{id}/accept");
    let accept_body = TeamInvitationAcceptRequest { password }.to_json().unwrap();
    business(
        f,
        &outsider_browser,
        "POST",
        &accept_path,
        accept_body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await
    .problem(404, "organization.not_found", false);
    let accepted = business(
        f,
        &recipient_browser,
        "POST",
        &accept_path,
        accept_body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(accepted.status, 200);
    let membership = TeamAcceptanceReceipt::from_json(&accepted.body).unwrap().membership_id;
    let host = create_asset(
        f,
        &owner_browser,
        org,
        InventoryType::Host,
        json!({"name":"Deployment","address":"ssh.example.test","port":22}),
    )
    .await;
    let profile = create_asset(
        f,
        &owner_browser,
        org,
        InventoryType::AccessProfile,
        json!({"host":host.id,"username":"deploy","route":0}),
    )
    .await;
    let fields = json!({"data":{"fields":{"name":"Deployment","address":"ssh.example.test","port":22,"default_profile":profile.id}}});
    let host = asset(
        &business(
            f,
            &owner_browser,
            "PUT",
            &format!("{root}/hosts/{}", host.id),
            &serde_json::to_vec(&fields).unwrap(),
            &[("If-Match", &host.etag)],
        )
        .await,
        InventoryType::Host,
        200,
    );
    let group_id = Uuid::now_v7();
    let group = business(
        f,
        &owner_browser,
        "POST",
        &format!("{root}/groups"),
        &serde_json::to_vec(
            &json!({"id":group_id,"data":{"name":"Deployers","members":[membership]}}),
        )
        .unwrap(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(group.status, 201);
    for (name, rule) in [
        (
            "View deployment",
            SimpleRule::View {
                resources: vec![
                    SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id },
                    SimpleRuleSelector { object_type: ObjectType::ACCESS_PROFILE, id: profile.id },
                ],
            },
        ),
        (
            "Connect deployment",
            SimpleRule::Connect {
                hosts: vec![host.id],
                host_groups: vec![],
                remote_user: "deploy".into(),
            },
        ),
    ] {
        let source = SimpleRuleInput {
            organization: org,
            subject: SimpleRuleSubject::Group(group_id),
            rule,
        }
        .generate()
        .unwrap();
        let reply = business(
            f,
            &owner_browser,
            "POST",
            &format!("{root}/policies"),
            &serde_json::to_vec(
                &json!({"id":Uuid::now_v7(),"data":{"name":name,"source":source,"enabled":true}}),
            )
            .unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await;
        assert_eq!(reply.status, 201);
        PolicyResource::from_json(&reply.body).unwrap();
    }
    assert_eq!(
        business(f, &recipient_browser, "GET", &format!("{root}/hosts/{}", host.id), &[], &[])
            .await
            .status,
        200
    );
    assert_eq!(
        business(
            f,
            &recipient_browser,
            "GET",
            &format!("{root}/access-profiles/{}", profile.id),
            &[],
            &[]
        )
        .await
        .status,
        200
    );
    business(f, &outsider_browser, "GET", &format!("{root}/hosts/{}", host.id), &[], &[])
        .await
        .problem(404, "organization.not_found", false);
    business(f,&recipient_browser,"POST",&format!("{root}/hosts"),&serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"fields":{"name":"Denied host","address":"denied.example.test"}}})).unwrap(),&[("Idempotency-Key",&Uuid::now_v7().to_string())]).await
        .problem(403,"policy.denied",false);
    let descriptor = super::super::inventory::descriptor(f, &recipient, org).await;
    let revision = descriptor.organization.unwrap().view_revision;
    let reply = super::super::inventory::view(f, &recipient, descriptor.id, revision, 0, 100).await;
    assert_eq!(reply.status, 200);
    let page = SyncOrganizationViewResponse::from_cbor(&reply.body).unwrap();
    assert_eq!(page.objects.len(), 2);
    let profile = page
        .objects
        .iter()
        .map(|item| Object::decode(&item.payload).unwrap())
        .find(|object| object.id == profile.id)
        .unwrap();
    assert_eq!(profile.required_text(3).unwrap(), "deploy");
    let member_path = format!("{root}/members/{membership}");
    let member = business(f, &owner_browser, "GET", &member_path, &[], &[]).await;
    let member = TeamMemberResource::from_json(&member.body).unwrap();
    let removed =
        business(f, &owner_browser, "DELETE", &member_path, &[], &[("If-Match", &member.etag)])
            .await;
    assert_eq!(removed.status, 204);
    business(f, &recipient_browser, "GET", &root, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert_eq!(
        super::super::inventory::view(f, &recipient, descriptor.id, revision, 0, 100).await.status,
        404
    );
    assert!(
        current(f, &recipient_browser).await,
        "membership withdrawal preserves personal Account login"
    );
    let current_team = business(f, &owner_browser, "GET", &root, &[], &[]).await;
    let current_team = OrganizationResource::from_json(&current_team.body).unwrap();
    let dissolve = TeamDissolveRequest { organization_id: org }.to_json().unwrap();
    let reply = business(
        f,
        &owner_browser,
        "POST",
        &format!("{root}/dissolve"),
        &dissolve,
        &[("If-Match", &current_team.etag), ("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 200);
    TeamDissolutionReceipt::from_json(&reply.body).unwrap();
    assert!(current(f, &owner_browser).await);
    business(f, &owner_browser, "GET", &root, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
}

browser_tests!(
    sqlite_account_browser_writer_receipts_and_device_consumption,
    postgres_account_browser_writer_receipts_and_device_consumption,
    authoring_and_receipts
);
browser_tests!(
    sqlite_account_browser_team_inventory_and_withdrawal,
    postgres_account_browser_team_inventory_and_withdrawal,
    invitation_inventory_and_withdrawal
);
