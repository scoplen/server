// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine browser Snippet authoring, current authority and native view consumption.

use super::{
    business::{asset, business, create_asset},
    *,
};
use scoplen_api::{
    inventory::{InventoryCreateRequest, InventoryPage, InventoryType},
    sync::{SyncOrganizationAckRequest, SyncOrganizationAckResponse, SyncOrganizationViewResponse},
};
use scoplen_model::{Object, ObjectType};
use serde_json::{Value, json};

fn fields() -> Value {
    json!({"name":"Deploy","template":"echo {{text}} {{count}} {{target}} {{token}}",
        "variables":{"text":{"kind":1,"default":""},"count":{"kind":2,"default":"-9223372036854775808"},
        "target":{"kind":3,"choices":["staging","production"],"default":"staging"},"token":{"kind":4}},
        "tags":{"deployment":true},"folder":"Operations"})
}

fn body(id: Uuid, fields: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"id":id,"data":{"fields":fields}})).unwrap()
}

async fn changed(events: &mut tokio::sync::broadcast::Receiver<Vec<u8>>, org: Uuid, revision: u64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let bytes = events.recv().await.expect("committed view notification");
            let notification = scoplen_api::sync::SyncNotification::from_cbor(&bytes).unwrap();
            if matches!(notification, scoplen_api::sync::SyncNotification::OrganizationViewChanged { organization, view_revision, .. } if organization == org && view_revision == revision) { break; }
        }
    }).await.expect("changed notification deadline");
}

async fn set_receipt_expiry(f: &Fixture, key: Uuid) {
    let query = "UPDATE organization_inventory_receipts SET created_at_ms=1,expires_at_ms=86400001 WHERE idempotency_key=$1";
    let result = match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query(query)
            .bind(key.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .map(|result| result.rows_affected()),
        AuthBackend::Postgres(store) => sqlx::query(query)
            .bind(key.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .map(|result| result.rows_affected()),
    }
    .unwrap();
    assert_eq!(result, 1);
}

#[allow(clippy::too_many_lines)]
async fn authoring(f: &Fixture) {
    let owner = actor(f, "snippet-browser-owner").await;
    let mut browser = login(f, &owner.registration).await;
    let other = login(f, &owner.registration).await;
    let family = scope::current_session(f, &browser).await.unwrap().family_id;
    let org = create_team(f, &owner).await.id;
    let path = format!("/api/v1/orgs/{org}/snippets");
    let id = Uuid::now_v7();
    let key = Uuid::now_v7().to_string();
    let original_body = body(id, &fields());
    let mut events = f.notifications.subscribe(scoplen_sync::http::AuthenticatedDevice {
        account_id: owner.registration.payload.account_id.into_bytes(),
        device_id: owner.registration.payload.device_id.into_bytes(),
    });
    let original =
        business(f, &browser, "POST", &path, &original_body, &[("Idempotency-Key", &key)]).await;
    let created = asset(&original, InventoryType::Snippet, 201);
    let canonical = InventoryCreateRequest::from_json(InventoryType::Snippet, &original_body)
        .unwrap()
        .to_json()
        .unwrap();
    let mut digest = Sha256::new();
    for part in [
        b"spl-organization-inventory-create-v1".as_slice(),
        ORIGIN.as_bytes(),
        owner.registration.payload.account_id.as_bytes(),
        b"account-browser",
        family.as_slice(),
        b"POST",
        path.as_bytes(),
    ] {
        digest.update(part);
        digest.update([0]);
    }
    digest.update(canonical);
    assert_eq!(
        business::receipt_digest(f, Uuid::parse_str(&key).unwrap()).await,
        digest.finalize().as_slice()
    );
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let versions = f.count("SELECT COUNT(*) FROM sync_object_versions").await;
    changed(&mut events, org, revision).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&created.fields.to_json().unwrap()).unwrap(),
        fields()
    );
    let target = format!("{path}/{id}");
    assert_eq!(
        asset(&business(f, &browser, "GET", &target, &[], &[]).await, InventoryType::Snippet, 200),
        created
    );
    let page = business(f, &browser, "GET", &format!("{path}?limit=1"), &[], &[]).await;
    assert_eq!(page.status, 200);
    let page = InventoryPage::from_json(InventoryType::Snippet, &page.body).unwrap();
    assert_eq!(page.items, vec![created.clone()]);
    assert_eq!(page.next_cursor, None);
    let deployment_audit = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    let rotated = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    (browser.access, browser.cookie) = session(&rotated, false);
    assert_eq!(scope::current_session(f, &browser).await.unwrap().family_id, family);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, deployment_audit + 1);
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&original_body).unwrap())
            .unwrap();
    let replay = business(f, &browser, "POST", &path, &pretty, &[("Idempotency-Key", &key)]).await;
    assert_eq!(replay.status, 201);
    assert_eq!(replay.body, original.body);
    let mut different_fields = fields();
    different_fields["template"] = json!("echo changed");
    business(
        f,
        &browser,
        "POST",
        &path,
        &body(id, &different_fields),
        &[("Idempotency-Key", &key)],
    )
    .await
    .problem(409, "organization.conflict", false);
    business(f, &other, "POST", &path, &original_body, &[("Idempotency-Key", &key)]).await.problem(
        409,
        "organization.conflict",
        false,
    );
    call(f, &owner, "POST", &path, &original_body, &[("Idempotency-Key", &key)]).await.problem(
        409,
        "organization.conflict",
        false,
    );
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_object_versions").await, versions);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_inventory_receipts WHERE expires_at_ms-created_at_ms=86400000").await, 1);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv()).await.is_err()
    );

    let descriptor = super::super::inventory::descriptor(f, &owner, org).await;
    let current_revision = descriptor.organization.unwrap().view_revision;
    let view =
        super::super::inventory::view(f, &owner, descriptor.id, current_revision, 0, 100).await;
    assert_eq!(view.status, 200);
    let view = SyncOrganizationViewResponse::from_cbor(&view.body).unwrap();
    assert_eq!(view.objects.len(), 1);
    let object = Object::decode(&view.objects[0].payload).unwrap();
    assert_eq!(object.id, id);
    assert_eq!(object.object_type, ObjectType::SNIPPET);
    assert!(object.fields.values().all(|entry| entry.origin == Uuid::from_bytes(family)));
    let ack_request =
        SyncOrganizationAckRequest { view_revision: current_revision, cursor: view.next_cursor };
    let ack = ack_request.to_cbor().unwrap();
    let ack = super::super::inventory::cbor_call(
        f,
        &owner,
        "POST",
        &format!("/sync/v1/vaults/{}/ack", descriptor.id),
        &ack,
    )
    .await;
    assert_eq!(ack.status, 200);
    let ack = SyncOrganizationAckResponse::from_cbor(&ack.body).unwrap();
    ack.validate_for_request(&ack_request).unwrap();
    assert_eq!(ack.cursor, ack_request.cursor);

    let mut replacement_fields = fields();
    replacement_fields["name"] = json!("Deploy updated");
    let replacement = serde_json::to_vec(&json!({"data":{"fields":replacement_fields}})).unwrap();
    business(f, &browser, "PUT", &target, &replacement, &[]).await.problem(
        428,
        "organization.precondition_required",
        false,
    );
    business(f, &browser, "PUT", &target, &replacement, &[("If-Match", "W/\"weak\"")])
        .await
        .problem(400, "organization.invalid_request", false);
    let updated = asset(
        &business(f, &browser, "PUT", &target, &replacement, &[("If-Match", &created.etag)]).await,
        InventoryType::Snippet,
        200,
    );
    assert_ne!(updated.etag, created.etag);
    changed(&mut events, org, f.revision(org).await).await;
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let versions = f.count("SELECT COUNT(*) FROM sync_object_versions").await;
    assert_eq!(
        asset(
            &business(f, &browser, "PUT", &target, &replacement, &[("If-Match", &updated.etag)])
                .await,
            InventoryType::Snippet,
            200
        ),
        updated
    );
    business(f, &browser, "PUT", &target, &replacement, &[("If-Match", &created.etag)])
        .await
        .problem(412, "organization.precondition_failed", false);
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_object_versions").await, versions);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv()).await.is_err()
    );
    f.audit_failure(true).await;
    business(
        f,
        &browser,
        "POST",
        &path,
        &body(Uuid::now_v7(), &fields()),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await
    .problem(503, "organization.storage_unavailable", true);
    f.audit_failure(false).await;
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_object_versions").await, versions);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv()).await.is_err()
    );
    business(f, &browser, "DELETE", &target, &[], &[("If-Match", &created.etag)]).await.problem(
        412,
        "organization.precondition_failed",
        false,
    );
    assert_eq!(
        business(f, &browser, "DELETE", &target, &[], &[("If-Match", &updated.etag)]).await.status,
        204
    );
    changed(&mut events, org, f.revision(org).await).await;
    business(f, &browser, "GET", &target, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let history = super::super::inventory::cbor_call(
        f,
        &owner,
        "GET",
        &format!("/sync/v1/vaults/{}/objects/{id}/versions", descriptor.id),
        &[],
    )
    .await;
    assert_eq!(history.status, 200);
    let history = scoplen_api::sync::SyncVersionsResponse::from_cbor(&history.body).unwrap();
    assert_eq!(history.versions.len(), 3);
    let tombstone = Object::decode(&history.versions[2].payload).unwrap().tombstone.unwrap();
    assert_eq!(tombstone.origin, Uuid::from_bytes(family));
    assert_eq!(
        business(f, &browser, "POST", &path, &original_body, &[("Idempotency-Key", &key)])
            .await
            .body,
        original.body
    );
    set_receipt_expiry(f, Uuid::parse_str(&key).unwrap()).await;
    business(f, &browser, "POST", &path, &original_body, &[("Idempotency-Key", &key)])
        .await
        .problem(409, "organization.conflict", false);
}

#[allow(clippy::too_many_lines)]
async fn authority(f: &Fixture) {
    let owner = actor(f, "snippet-authority-owner").await;
    let member = actor(f, "snippet-authority-member").await;
    let outsider = actor(f, "snippet-authority-outsider").await;
    let browser = login(f, &owner.registration).await;
    let mut member_browser = login(f, &member.registration).await;
    let outsider_browser = login(f, &outsider.registration).await;
    let org = create_team(f, &owner).await.id;
    let foreign_org = create_team(f, &outsider).await.id;
    let membership = super::super::inventory::enroll_member(f, &owner, &member, org).await;
    let root = format!("/api/v1/orgs/{org}");
    let path = format!("{root}/snippets");
    let created = create_asset(f, &browser, org, InventoryType::Snippet, fields()).await;
    let target = format!("{path}/{}", created.id);
    business(f, &outsider_browser, "GET", &target, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    business(
        f,
        &outsider_browser,
        "GET",
        &format!("/api/v1/orgs/{foreign_org}/snippets/{}", created.id),
        &[],
        &[],
    )
    .await
    .problem(404, "organization.not_found", false);
    business(f, &member_browser, "GET", &target, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let source = scoplen_api::group_policy::SimpleRuleInput {
        organization: org,
        subject: scoplen_api::group_policy::SimpleRuleSubject::Membership(membership),
        rule: scoplen_api::group_policy::SimpleRule::View {
            resources: vec![scoplen_api::group_policy::SimpleRuleSelector {
                object_type: ObjectType::SNIPPET,
                id: created.id,
            }],
        },
    }
    .generate()
    .unwrap();
    let policy_path = format!("{root}/policies");
    let policy = business(f, &browser, "POST", &policy_path,
        &serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"name":"View Snippet","source":source,"enabled":true}})).unwrap(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())]).await;
    assert_eq!(policy.status, 201);
    let policy = scoplen_api::group_policy::PolicyResource::from_json(&policy.body).unwrap();
    assert_eq!(business(f, &member_browser, "GET", &target, &[], &[]).await.status, 200);
    assert_eq!(
        business(
            f,
            &browser,
            "DELETE",
            &format!("{policy_path}/{}", policy.id),
            &[],
            &[("If-Match", &policy.etag)]
        )
        .await
        .status,
        204
    );
    business(f, &member_browser, "GET", &target, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    business(
        f,
        &member_browser,
        "POST",
        &path,
        &body(Uuid::now_v7(), &fields()),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await
    .problem(403, "policy.denied", false);
    let member_path = format!("{root}/members/{membership}");
    let current = TeamMemberResource::from_json(
        &business(f, &browser, "GET", &member_path, &[], &[]).await.body,
    )
    .unwrap();
    let promote = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Administrator],
        status: TeamMemberStatus::Active,
    }
    .to_json()
    .unwrap();
    let promoted =
        business(f, &browser, "PATCH", &member_path, &promote, &[("If-Match", &current.etag)])
            .await;
    assert_eq!(promoted.status, 200);
    let promoted = TeamMemberResource::from_json(&promoted.body).unwrap();
    let member_id = Uuid::now_v7();
    let original = body(member_id, &fields());
    let key = Uuid::now_v7().to_string();
    asset(
        &business(f, &member_browser, "POST", &path, &original, &[("Idempotency-Key", &key)]).await,
        InventoryType::Snippet,
        201,
    );
    let family = scope::current_session(f, &member_browser).await.unwrap();
    let no_write = family
        .scope
        .split(' ')
        .filter(|scope| *scope != "inventory:write")
        .collect::<Vec<_>>()
        .join(" ");
    scope::set_scope(f, family.family_id, &no_write).await;
    let replacement = serde_json::to_vec(&json!({"data":{"fields":fields()}})).unwrap();
    for rotated in [false, true] {
        if rotated {
            let reply =
                request(f, &member_browser.key, REFRESH, b"{}", None, Some(&member_browser.cookie))
                    .await;
            (member_browser.access, member_browser.cookie) = session(&reply, false);
        }
        assert_eq!(scope::current_session(f, &member_browser).await.unwrap().scope, no_write);
        assert_eq!(business(f, &member_browser, "GET", &target, &[], &[]).await.status, 200);
        for (method, route, bytes, headers) in [
            ("POST", path.as_str(), original.as_slice(), vec![("Idempotency-Key", key.as_str())]),
            (
                "PUT",
                target.as_str(),
                replacement.as_slice(),
                vec![("If-Match", created.etag.as_str())],
            ),
            ("DELETE", target.as_str(), &[][..], vec![("If-Match", created.etag.as_str())]),
        ] {
            business(f, &member_browser, method, route, bytes, &headers).await.problem(
                403,
                "policy.denied",
                false,
            );
        }
    }
    scope::set_scope(f, family.family_id, &family.scope).await;
    let no_read = family
        .scope
        .split(' ')
        .filter(|scope| *scope != "inventory:read")
        .collect::<Vec<_>>()
        .join(" ");
    scope::set_scope(f, family.family_id, &no_read).await;
    for route in [&path, &target] {
        business(f, &member_browser, "GET", route, &[], &[]).await.problem(
            403,
            "policy.denied",
            false,
        );
    }
    scope::set_scope(f, family.family_id, &family.scope).await;
    let deny = format!(
        "forbid(principal == Account::\"{}\", action == Action::\"view_inventory\", resource == Snippet::\"{}\");",
        member.registration.payload.account_id, created.id
    );
    let policy = business(f, &browser, "POST", &policy_path,
        &serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{"name":"Hide Snippet","source":deny,"enabled":true}})).unwrap(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())]).await;
    assert_eq!(policy.status, 201);
    let policy = scoplen_api::group_policy::PolicyResource::from_json(&policy.body).unwrap();
    for (method, bytes, headers) in [
        ("GET", &[][..], vec![]),
        ("PUT", replacement.as_slice(), vec![("If-Match", created.etag.as_str())]),
        ("DELETE", &[][..], vec![("If-Match", created.etag.as_str())]),
    ] {
        business(f, &member_browser, method, &target, bytes, &headers).await.problem(
            404,
            "organization.not_found",
            false,
        );
    }
    assert_eq!(
        business(
            f,
            &browser,
            "DELETE",
            &format!("{policy_path}/{}", policy.id),
            &[],
            &[("If-Match", &policy.etag)]
        )
        .await
        .status,
        204
    );
    let suspend = TeamMemberUpdateRequest {
        roles: promoted.roles.clone(),
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    let suspended =
        business(f, &browser, "PATCH", &member_path, &suspend, &[("If-Match", &promoted.etag)])
            .await;
    assert_eq!(suspended.status, 200);
    let suspended = TeamMemberResource::from_json(&suspended.body).unwrap();
    business(f, &member_browser, "POST", &path, &original, &[("Idempotency-Key", &key)])
        .await
        .problem(404, "organization.not_found", false);
    business(f, &member_browser, "GET", &target, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert!(super::current(f, &member_browser).await);
    let restore =
        TeamMemberUpdateRequest { roles: vec![TeamRole::Member], status: TeamMemberStatus::Active }
            .to_json()
            .unwrap();
    assert_eq!(
        business(f, &browser, "PATCH", &member_path, &restore, &[("If-Match", &suspended.etag)])
            .await
            .status,
        200
    );
    business(f, &member_browser, "POST", &path, &original, &[("Idempotency-Key", &key)])
        .await
        .problem(403, "policy.denied", false);
    for segment in ["trust-records", "gateway-networks"] {
        let collection = format!("{root}/{segment}");
        let item = format!("{collection}/{}", created.id);
        for (method, route) in [
            ("GET", &collection),
            ("POST", &collection),
            ("GET", &item),
            ("PUT", &item),
            ("DELETE", &item),
        ] {
            business(f, &browser, method, route, &[], &[]).await.problem(
                403,
                "policy.denied",
                false,
            );
        }
    }
    let current = scope::current_session(f, &browser).await.unwrap();
    let expires = u64::try_from(current.expires_at_ms.div_euclid(1000)).unwrap();
    let principal = scoplen_store::organizations::OrganizationActor::AccountBrowser(current);
    for kind in [InventoryType::TrustRecord, InventoryType::GatewayNetwork] {
        macro_rules! excluded {
            ($store:expr) => {{
                use scoplen_store::organizations::{
                    OrganizationStoreError,
                    inventory::{InventoryTarget, InventoryWrite},
                };
                assert!(matches!(
                    $store
                        .read_organization_inventory(&principal, expires, org, kind, created.id)
                        .await,
                    Err(OrganizationStoreError::PermissionDenied)
                ));
                assert!(matches!(
                    $store
                        .list_organization_inventory(
                            &principal,
                            expires,
                            org,
                            kind,
                            &scoplen_api::organization::OrganizationListQuery {
                                limit: 1,
                                cursor: None
                            }
                        )
                        .await,
                    Err(OrganizationStoreError::PermissionDenied)
                ));
                assert!(matches!(
                    $store
                        .write_organization_inventory(
                            &principal,
                            expires,
                            ORIGIN,
                            InventoryTarget { org, kind, id: created.id },
                            InventoryWrite::Delete { if_match: &created.etag }
                        )
                        .await,
                    Err(OrganizationStoreError::PermissionDenied)
                ));
            }};
        }
        match &f.backend {
            AuthBackend::Sqlite(store) => excluded!(store),
            AuthBackend::Postgres(store) => excluded!(store),
        }
    }
    for variables in [
        json!({"token":{"kind":4,"default":""}}),
        json!({"count":{"kind":2,"default":"01"}}),
        json!({"target":{"kind":3,"choices":["a","a"]}}),
    ] {
        let mut invalid = fields();
        invalid["variables"] = variables;
        business(
            f,
            &browser,
            "POST",
            &path,
            &body(Uuid::now_v7(), &invalid),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await
        .problem(400, "organization.invalid_request", false);
    }
}

browser_tests!(
    sqlite_account_browser_snippet_authoring,
    postgres_account_browser_snippet_authoring,
    authoring
);
browser_tests!(
    sqlite_account_browser_snippet_current_authority,
    postgres_account_browser_snippet_current_authority,
    authority
);
