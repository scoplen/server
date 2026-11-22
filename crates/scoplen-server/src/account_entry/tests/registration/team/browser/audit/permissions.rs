// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_api::group_policy::PolicyResource;

use super::*;

async fn both(
    f: &Fixture,
    native: &Actor,
    browser: &Browser,
    organization: Uuid,
    status: u16,
    code: &str,
) {
    for path in [timeline(organization), verify_path(organization, 1, 1)] {
        for reply in [
            call(f, native, "GET", &path, &[], &[]).await,
            business(f, browser, "GET", &path, &[], &[]).await,
        ] {
            if status == 200 {
                assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
                reply.private();
            } else {
                reply.problem(status, code, false);
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn authority(f: &Fixture) {
    let owner = actor(f, "audit-owner").await;
    let owner_browser = login(f, &owner.registration).await;
    let member = actor(f, "audit-member").await;
    let member_browser = login(f, &member.registration).await;
    let organization = create_team(f, &owner).await.id;
    both(f, &owner, &owner_browser, organization, 200, "").await;
    both(f, &member, &member_browser, organization, 404, "organization.not_found").await;
    both(f, &owner, &owner_browser, Uuid::now_v7(), 404, "organization.not_found").await;
    let foreign = create_team(f, &member).await.id;
    both(f, &owner, &owner_browser, foreign, 404, "organization.not_found").await;
    let (invitation, password, _, _) =
        issue(f, &owner, &member, organization, vec![TeamRole::Member]).await;
    let accepted = call(
        f,
        &member,
        "POST",
        &format!("/api/v1/orgs/{organization}/invitations/{}/accept", invitation.id),
        TeamInvitationAcceptRequest { password }.to_json().unwrap().as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(accepted.status, 200);
    let membership = TeamAcceptanceReceipt::from_json(&accepted.body).unwrap().membership_id;
    for (role, permitted) in [
        (TeamRole::Member, false),
        (TeamRole::Administrator, false),
        (TeamRole::Approver, false),
        (TeamRole::SecurityAuditor, true),
    ] {
        change_member(f, &owner, organization, membership, role, TeamMemberStatus::Active).await;
        both(
            f,
            &member,
            &member_browser,
            organization,
            if permitted { 200 } else { 403 },
            "policy.denied",
        )
        .await;
    }
    change_member(f, &owner, organization, membership, TeamRole::Member, TeamMemberStatus::Active)
        .await;
    let policy_id = Uuid::now_v7();
    let source = format!(
        "permit(principal == Account::\"{}\", action == Action::\"view_audit\", resource == Organization::\"{organization}\");",
        member.registration.payload.account_id
    );
    let body = serde_json::to_vec(
        &json!({"id":policy_id,"data":{"name":"Audit reader","source":source,"enabled":true}}),
    )
    .unwrap();
    let created = call(
        f,
        &owner,
        "POST",
        &format!("/api/v1/orgs/{organization}/policies"),
        &body,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(created.status, 201, "{}", String::from_utf8_lossy(&created.body));
    let policy = PolicyResource::from_json(&created.body).unwrap();
    both(f, &member, &member_browser, organization, 200, "").await;
    // A custom permit remains subordinate to current active membership.
    change_member(
        f,
        &owner,
        organization,
        membership,
        TeamRole::Member,
        TeamMemberStatus::Suspended,
    )
    .await;
    both(f, &member, &member_browser, organization, 404, "organization.not_found").await;
    change_member(f, &owner, organization, membership, TeamRole::Member, TeamMemberStatus::Active)
        .await;
    let changed = call(
        f,
        &owner,
        "PUT",
        &format!("/api/v1/orgs/{organization}/policies/{policy_id}"),
        &serde_json::to_vec(
            &json!({"data":{"name":"Audit reader","source":source,"enabled":false}}),
        )
        .unwrap(),
        &[("If-Match", &policy.etag)],
    )
    .await;
    assert_eq!(changed.status, 200);
    both(f, &member, &member_browser, organization, 403, "policy.denied").await;
    let member_path = format!("/api/v1/orgs/{organization}/members/{membership}");
    let current = call(f, &owner, "GET", &member_path, &[], &[]).await;
    let current = TeamMemberResource::from_json(&current.body).unwrap();
    assert_eq!(
        call(f, &owner, "DELETE", &member_path, &[], &[("If-Match", &current.etag)]).await.status,
        204
    );
    both(f, &member, &member_browser, organization, 404, "organization.not_found").await;
    for path in [timeline(organization), verify_path(organization, 1, 1)] {
        http(f.address, "GET", &path, &[], &[("Cookie", &owner_browser.cookie)]).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
        business(f, &owner_browser, "GET", &path, &[], &[("Origin", "https://other.example.test")])
            .await
            .problem(403, "policy.denied", false);
    }
    let logout =
        request(f, &owner_browser.key, LOGOUT, b"{}", Some(&owner_browser.access), None).await;
    assert_eq!(logout.status, 200);
    for path in [timeline(organization), verify_path(organization, 1, 1)] {
        business(f, &owner_browser, "GET", &path, &[], &[]).await.problem(
            401,
            "auth.authentication_required",
            false,
        );
    }
    let owner_browser = login(f, &owner.registration).await;
    let dissolved = call(
        f,
        &owner,
        "POST",
        &format!("/api/v1/orgs/{organization}/dissolve"),
        &TeamDissolveRequest { organization_id: organization }.to_json().unwrap(),
        &[
            ("Idempotency-Key", &Uuid::now_v7().to_string()),
            ("If-Match", &current_team(f, &owner, organization).await.etag),
        ],
    )
    .await;
    assert_eq!(dissolved.status, 200, "{}", String::from_utf8_lossy(&dissolved.body));
    both(f, &owner, &owner_browser, organization, 404, "organization.not_found").await;
}

async fn scope_ceiling(f: &Fixture) {
    let mut native = actor(f, "audit-ceiling").await;
    let organization = create_team(f, &native).await.id;
    let mut browser = login(f, &native.registration).await;
    let old_browser = scoplen_api::account_browser::INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
        .split(' ')
        .filter(|scope| *scope != "audit:read")
        .collect::<Vec<_>>()
        .join(" ");
    let family = super::super::scope::current_session(f, &browser).await.unwrap().family_id;
    super::super::scope::set_scope(f, family, &old_browser).await;
    let old_device = scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE
        .split(' ')
        .filter(|scope| *scope != "audit:read")
        .collect::<Vec<_>>()
        .join(" ");
    narrow(f, &mut native, &old_device).await;
    for rotated in [false, true] {
        if rotated {
            let reply = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
            (browser.access, browser.cookie) = session(&reply, false);
            // Refresh the retained native family again without changing its stored ceiling.
            let path = "/api/v1/auth/refresh";
            let proof = DpopProof::sign(
                &native.registration.device,
                &native.registration.device.public_key_sec1(),
                &DpopTarget::new("POST", ORIGIN, path).unwrap(),
                DpopToken::Refresh,
                u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
                None,
            )
            .unwrap();
            let reply = http(
                f.address,
                "POST",
                path,
                AuthRefreshRequest::new(native.token.refresh_token.clone())
                    .unwrap()
                    .to_json()
                    .unwrap()
                    .as_bytes(),
                &[("Content-Type", "application/json"), ("DPoP", proof.as_str())],
            )
            .await;
            assert_eq!(reply.status, 200);
            native.token =
                AuthTokenResponse::from_json(std::str::from_utf8(&reply.body).unwrap()).unwrap();
        }
        assert_eq!(
            super::super::scope::current_session(f, &browser).await.unwrap().scope,
            old_browser
        );
        both(f, &native, &browser, organization, 403, "policy.denied").await;
    }
    native.token = authenticate(f, &native.registration).await;
    browser = login(f, &native.registration).await;
    both(f, &native, &browser, organization, 200, "").await;
}

browser_tests!(
    sqlite_organization_audit_current_authority,
    postgres_organization_audit_current_authority,
    authority
);
browser_tests!(
    sqlite_organization_audit_scope_ceiling,
    postgres_organization_audit_scope_ceiling,
    scope_ceiling
);
