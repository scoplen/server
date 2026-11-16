// SPDX-License-Identifier: AGPL-3.0-only
//! Public Device KRL reads and atomic team revocation on both production stores.

use super::*;
use scoplen_api::krl::UserCaKrl;

fn path(org: Uuid, ca: Uuid) -> String {
    format!("/api/v1/orgs/{org}/certificate-authorities/{ca}/krl")
}

fn krl(reply: &Reply, trust: &UserCaResource) -> UserCaKrl {
    assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    assert!(reply.header("etag").is_none());
    assert!(reply.header("x-request-id").and_then(|value| Uuid::parse_str(value).ok()).is_some());
    UserCaKrl::from_http_bytes(
        &reply.body,
        &trust.public_key,
        reply.header("content-type"),
        reply.header("cache-control"),
        reply.header("pragma"),
        reply.header("x-request-id"),
    )
    .expect("complete CA-bound shared KRL")
}

async fn read(f: &Fixture, actor: &Actor, org: Uuid, trust: &UserCaResource) -> Reply {
    call(f, actor, "GET", &path(org, trust.id), &[], &[]).await
}

async fn member(f: &Fixture, owner: &Actor, org: Uuid, id: Uuid) -> TeamMemberResource {
    let reply = call(f, owner, "GET", &format!("/api/v1/orgs/{org}/members/{id}"), &[], &[]).await;
    assert_eq!(reply.status, 200);
    TeamMemberResource::from_json(&reply.body).expect("current member")
}

async fn update(
    f: &Fixture,
    owner: &Actor,
    org: Uuid,
    current: &TeamMemberResource,
    status: TeamMemberStatus,
) -> Reply {
    let body = TeamMemberUpdateRequest { roles: current.roles.clone(), status }.to_json().unwrap();
    call(
        f,
        owner,
        "PATCH",
        &format!("/api/v1/orgs/{org}/members/{}", current.id),
        &body,
        &[("If-Match", &current.etag)],
    )
    .await
}

async fn stored(f: &Fixture, org: Uuid, authority: Uuid) -> Vec<u8> {
    let sql = "SELECT snapshot FROM organization_user_ca_krls WHERE organization_id=$1 AND authority_id=$2";
    match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query_scalar(sql)
            .bind(org.as_bytes().as_slice())
            .bind(authority.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .unwrap(),
        AuthBackend::Postgres(store) => sqlx::query_scalar(sql)
            .bind(org.as_bytes().as_slice())
            .bind(authority.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .unwrap(),
    }
}

async fn replace_snapshot(f: &Fixture, org: Uuid, authority: Uuid, bytes: &[u8]) {
    let sql = "UPDATE organization_user_ca_krls SET snapshot=$1 WHERE organization_id=$2 AND authority_id=$3";
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(sql)
                .bind(bytes)
                .bind(org.as_bytes().as_slice())
                .bind(authority.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(sql)
                .bind(bytes)
                .bind(org.as_bytes().as_slice())
                .bind(authority.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }
}

async fn device_active(f: &Fixture, actor: &Actor, active: bool) {
    let sql = "UPDATE identity_devices SET active=$1 WHERE device_id=$2";
    let device = actor.registration.payload.device_id;
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(sql)
                .bind(active)
                .bind(device.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(sql)
                .bind(active)
                .bind(device.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }
}

async fn allocation(f: &Fixture, org: Uuid) -> (Vec<u8>, i64, i64) {
    let sql = "SELECT last_serial FROM organization_user_cas WHERE organization_id=$1";
    let serial = match &f.backend {
        AuthBackend::Sqlite(store) => sqlx::query_scalar::<_, Vec<u8>>(sql)
            .bind(org.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .unwrap(),
        AuthBackend::Postgres(store) => sqlx::query_scalar::<_, Vec<u8>>(sql)
            .bind(org.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .unwrap(),
    };
    (
        serial,
        f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await,
        f.count("SELECT COUNT(*) FROM audit_events").await,
    )
}

// These are trusted post-activation index-pressure rows, not 100,000 verified signatures.
// Production issuance only reads their verified-expiry metadata; receipt verification selects
// the one genuinely issued Resource. No old-store over-cap activation claim follows from this.
async fn pressure(f: &Fixture, owner: &Actor, org: Uuid, authority: Uuid, expires: u64) {
    macro_rules! seed {
        ($store:expr,$db:ty) => {{
            let mut tx = $store.pool().begin().await.unwrap();
            for start in (2_u64..=100_000).step_by(512) {
                let mut query = sqlx::QueryBuilder::<$db>::new("INSERT INTO organization_user_certificates (organization_id,id,authority_id,account_id,device_id,serial,response_json,created_at_ms,valid_before) ");
                query.push_values(start..=(start+511).min(100_000),|mut row,serial| {
                    row.push_bind(org.as_bytes().to_vec())
                        .push_bind(Uuid::now_v7().as_bytes().to_vec())
                        .push_bind(authority.as_bytes().to_vec())
                        .push_bind(owner.registration.payload.account_id.as_bytes().to_vec())
                        .push_bind(owner.registration.payload.device_id.as_bytes().to_vec())
                        .push_bind(serial.to_be_bytes().to_vec())
                        .push_bind(b"{}".to_vec()).push_bind(1_i64)
                        .push_bind(expires.to_be_bytes().to_vec());
                });
                query.build().execute(&mut *tx).await.unwrap();
            }
            sqlx::query("UPDATE organization_user_cas SET last_serial=$1 WHERE organization_id=$2")
                .bind(100_000_u64.to_be_bytes().as_slice()).bind(org.as_bytes().as_slice()).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        }};
    }
    match &f.backend {
        AuthBackend::Sqlite(store) => seed!(store, sqlx::Sqlite),
        AuthBackend::Postgres(store) => seed!(store, sqlx::Postgres),
    }
}

#[allow(clippy::too_many_lines)]
async fn downloads(f: &mut Fixture) {
    let owner = actor(f, "krl-reader-owner").await;
    let mut reader = actor(f, "krl-reader-member").await;
    let mut outsider = actor(f, "krl-reader-outsider").await;
    let org = create_team(f, &owner).await.id;
    enroll_member(f, &owner, &reader, org).await;
    let trust = provision(f, &owner, org).await;
    let foreign_org = create_team(f, &owner).await.id;
    let foreign_trust = provision(f, &owner, foreign_org).await;
    let endpoint = path(org, trust.id);
    let first = read(f, &owner, org, &trust).await;
    let snapshot = krl(&first, &trust);
    assert_eq!(snapshot.version(), 1);
    assert_eq!(snapshot.revoked_serials(), [] as [u64; 0]);
    assert_eq!(first.body.len(), 44);
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    narrow(f, &mut reader, "ca:read").await;
    assert_eq!(read(f, &reader, org, &trust).await.body, first.body);
    problem(
        &sign(
            f,
            &reader,
            org,
            &request(CertificateTargets::Hosts(vec![Uuid::now_v7()]), 30),
            Uuid::now_v7(),
        )
        .await,
        403,
        "policy.denied",
    );
    for (caller, selected) in [
        (&outsider, endpoint.clone()),
        (&reader, path(foreign_org, foreign_trust.id)),
        (&owner, path(org, foreign_trust.id)),
        (&owner, path(org, Uuid::now_v7())),
        (&owner, path(Uuid::now_v7(), trust.id)),
    ] {
        problem(&call(f, caller, "GET", &selected, &[], &[]).await, 404, "organization.not_found");
    }
    for (selected, body, headers) in [
        (format!("{endpoint}?unused=1"), Vec::new(), vec![]),
        (endpoint.clone(), b"{}".to_vec(), vec![]),
        (endpoint.clone(), Vec::new(), vec![("If-Match", "\"unused\"")]),
        (endpoint.clone(), Vec::new(), vec![("Idempotency-Key", "unused")]),
    ] {
        problem(
            &call(f, &reader, "GET", &selected, &body, &headers).await,
            400,
            "organization.invalid_request",
        );
    }
    let conditional = call(f, &reader, "GET", &endpoint, &[], &[("If-None-Match", "*")]).await;
    assert_eq!(krl(&conditional, &trust), snapshot);
    problem(
        &http(f.address, "GET", &endpoint, &[], &[]).await,
        401,
        "auth.authentication_required",
    );
    let proof = DpopProof::sign(
        &reader.registration.device,
        &reader.registration.device.public_key_sec1(),
        &DpopTarget::new("GET", ORIGIN, &endpoint).unwrap(),
        DpopToken::Protected(&reader.token.access_token),
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        None,
    )
    .unwrap();
    let authorization = format!("DPoP {}", reader.token.access_token);
    problem(
        &http(
            f.address,
            "GET",
            &endpoint,
            &[],
            &[
                ("Authorization", &authorization),
                ("DPoP", proof.as_str()),
                ("Origin", "https://other.example.test"),
            ],
        )
        .await,
        403,
        "policy.denied",
    );
    device_active(f, &reader, false).await;
    problem(&read(f, &reader, org, &trust).await, 401, "auth.authentication_required");
    device_active(f, &reader, true).await;
    assert_eq!(read(f, &reader, org, &trust).await.body, first.body);
    narrow(f, &mut outsider, "orgs:read").await;
    problem(&read(f, &outsider, org, &trust).await, 403, "policy.denied");
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    f.restart_reads(scoplen_sync::http::ReadBodyLimits::default()).await;
    assert_eq!(read(f, &reader, org, &trust).await.body, first.body);

    let mut corrupt = first.body.clone();
    corrupt[0] ^= 1;
    replace_snapshot(f, org, trust.id, &corrupt).await;
    problem(&read(f, &reader, org, &trust).await, 503, "organization.storage_unavailable");
    assert_eq!(stored(f, org, trust.id).await, corrupt);
    replace_snapshot(f, org, trust.id, &first.body).await;
    assert_eq!(read(f, &reader, org, &trust).await.body, first.body);
    let sql = "DELETE FROM organization_user_ca_krls WHERE organization_id=$1 AND authority_id=$2";
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(sql)
                .bind(org.as_bytes().as_slice())
                .bind(trust.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(sql)
                .bind(org.as_bytes().as_slice())
                .bind(trust.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }
    problem(&read(f, &reader, org, &trust).await, 503, "organization.storage_unavailable");
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_ca_krls").await, 1);
    assert_eq!(
        krl(&read(f, &owner, foreign_org, &foreign_trust).await, &foreign_trust).revoked_serials(),
        [] as [u64; 0]
    );
}

#[allow(clippy::too_many_lines)]
async fn lifecycle(f: &mut Fixture) {
    let owner = actor(f, "krl-lifecycle-owner").await;
    let recipient = actor(f, "krl-lifecycle-member").await;
    let org = create_team(f, &owner).await.id;
    let membership = enroll_member(f, &owner, &recipient, org).await;
    let trust = provision(f, &owner, org).await;
    let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"KRL host","address":"krl.example.test"}),
    )
    .await;
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
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::Connect {
            hosts: vec![host.id],
            host_groups: vec![],
            remote_user: "deploy".into(),
        },
    )
    .await;
    let issuance = request(CertificateTargets::Hosts(vec![host.id]), 300);
    let original_key = Uuid::now_v7();
    let original = issued(&sign(f, &recipient, org, &issuance, original_key).await);
    let unaffected_key = Uuid::now_v7();
    let unaffected = issued(&sign(f, &owner, org, &issuance, unaffected_key).await);
    assert_eq!(Certificate::from_openssh(&original.certificate).unwrap().serial(), 1);
    assert_eq!(Certificate::from_openssh(&unaffected.certificate).unwrap().serial(), 2);
    let initial = read(f, &owner, org, &trust).await.body;
    let owner_membership = current_team(f, &owner, org).await.membership.id;
    let only_owner = member(f, &owner, org, owner_membership).await;
    problem(
        &update(f, &owner, org, &only_owner, TeamMemberStatus::Suspended).await,
        409,
        "organization.conflict",
    );
    assert_eq!(read(f, &owner, org, &trust).await.body, initial);
    let current = member(f, &owner, org, membership).await;
    let stale = TeamMemberUpdateRequest {
        roles: current.roles.clone(),
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .unwrap();
    problem(
        &call(
            f,
            &owner,
            "PATCH",
            &format!("/api/v1/orgs/{org}/members/{membership}"),
            &stale,
            &[("If-Match", "\"stale\"")],
        )
        .await,
        412,
        "organization.precondition_failed",
    );
    assert_eq!(read(f, &owner, org, &trust).await.body, initial);
    f.audit_failure(true).await;
    problem(
        &update(f, &owner, org, &current, TeamMemberStatus::Suspended).await,
        503,
        "organization.storage_unavailable",
    );
    f.audit_failure(false).await;
    assert_eq!(member(f, &owner, org, membership).await, current);
    assert_eq!(read(f, &owner, org, &trust).await.body, initial);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_ca_revocations").await, 0);

    let suspended = update(f, &owner, org, &current, TeamMemberStatus::Suspended).await;
    assert_eq!(suspended.status, 200);
    let suspended = TeamMemberResource::from_json(&suspended.body).unwrap();
    let revoked_reply = read(f, &owner, org, &trust).await;
    let revoked = krl(&revoked_reply, &trust);
    assert_eq!(revoked.revoked_serials(), [1]);
    assert_eq!(revoked.version(), 2);
    problem(&read(f, &recipient, org, &trust).await, 404, "organization.not_found");
    problem(
        &sign(f, &recipient, org, &issuance, original_key).await,
        404,
        "organization.not_found",
    );
    assert_eq!(issued(&sign(f, &owner, org, &issuance, unaffected_key).await), unaffected);
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let revision = f.revision(org).await;
    assert_eq!(update(f, &owner, org, &suspended, TeamMemberStatus::Suspended).await.status, 200);
    assert_eq!(read(f, &owner, org, &trust).await.body, revoked_reply.body);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(update(f, &owner, org, &suspended, TeamMemberStatus::Active).await.status, 200);
    problem(&sign(f, &recipient, org, &issuance, original_key).await, 409, "certificate.revoked");
    let fresh = issued(&sign(f, &recipient, org, &issuance, Uuid::now_v7()).await);
    assert_eq!(Certificate::from_openssh(&fresh.certificate).unwrap().serial(), 3);
    assert_eq!(read(f, &recipient, org, &trust).await.body, revoked_reply.body);
    f.restart_reads(scoplen_sync::http::ReadBodyLimits::default()).await;
    assert_eq!(read(f, &recipient, org, &trust).await.body, revoked_reply.body);
    problem(&sign(f, &recipient, org, &issuance, original_key).await, 409, "certificate.revoked");

    let current = member(f, &owner, org, membership).await;
    let member_path = format!("/api/v1/orgs/{org}/members/{membership}");
    assert_eq!(
        call(f, &owner, "DELETE", &member_path, &[], &[("If-Match", &current.etag)]).await.status,
        204
    );
    assert_eq!(krl(&read(f, &owner, org, &trust).await, &trust).revoked_serials(), [1, 3]);
    problem(&read(f, &recipient, org, &trust).await, 404, "organization.not_found");
    assert_eq!(enroll_member(f, &owner, &recipient, org).await, membership);
    problem(&sign(f, &recipient, org, &issuance, original_key).await, 409, "certificate.revoked");
    let fourth = issued(&sign(f, &recipient, org, &issuance, Uuid::now_v7()).await);
    assert_eq!(Certificate::from_openssh(&fourth.certificate).unwrap().serial(), 4);
    let current = current_team(f, &recipient, org).await;
    assert_eq!(
        call(f, &recipient, "DELETE", &member_path, &[], &[("If-Match", &current.etag)])
            .await
            .status,
        204
    );
    assert_eq!(krl(&read(f, &owner, org, &trust).await, &trust).revoked_serials(), [1, 3, 4]);
    assert_eq!(enroll_member(f, &owner, &recipient, org).await, membership);

    let team = current_team(f, &owner, org).await;
    let key = Uuid::now_v7().to_string();
    let body = TeamDissolveRequest { organization_id: org }.to_json().unwrap();
    let headers = [("If-Match", team.etag.as_str()), ("Idempotency-Key", key.as_str())];
    let endpoint = format!("/api/v1/orgs/{org}/dissolve");
    let before = read(f, &owner, org, &trust).await.body;
    f.commit_failure(true).await;
    unknown(&call(f, &owner, "POST", &endpoint, &body, &headers).await);
    f.commit_failure(false).await;
    assert_eq!(read(f, &owner, org, &trust).await.body, before);
    assert_eq!(current_team(f, &owner, org).await, team);
    let completed = call(f, &owner, "POST", &endpoint, &body, &headers).await;
    assert_eq!(completed.status, 200);
    let final_bytes = stored(f, org, trust.id).await;
    let final_krl = UserCaKrl::from_bytes(&final_bytes, &trust.public_key).unwrap();
    assert_eq!(final_krl.revoked_serials(), [1, 2, 3, 4]);
    assert_eq!(final_krl.version(), 5);
    for caller in [&owner, &recipient] {
        problem(&read(f, caller, org, &trust).await, 404, "organization.not_found");
    }
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    assert_eq!(call(f, &owner, "POST", &endpoint, &body, &headers).await.body, completed.body);
    assert_eq!(stored(f, org, trust.id).await, final_bytes);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
}

#[allow(clippy::too_many_lines)]
async fn issuance_cap(f: &Fixture) {
    let owner = actor(f, "krl-cap-owner").await;
    let recipient = actor(f, "krl-cap-member").await;
    let org = create_team(f, &owner).await.id;
    let membership = enroll_member(f, &owner, &recipient, org).await;
    let trust = provision(f, &owner, org).await;
    let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"Capacity host","address":"capacity.example.test"}),
    )
    .await;
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
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::Connect {
            hosts: vec![host.id],
            host_groups: vec![],
            remote_user: "deploy".into(),
        },
    )
    .await;
    let request = request(CertificateTargets::Hosts(vec![host.id]), 1_800);
    let key = Uuid::now_v7();
    let original = issued(&sign(f, &recipient, org, &request, key).await);
    let parsed = Certificate::from_openssh(&original.certificate).unwrap();
    assert_eq!(parsed.serial(), 1);
    pressure(f, &owner, org, trust.id, parsed.valid_before()).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_certificates").await, 100_000);
    let before = allocation(f, org).await;
    let snapshot = read(f, &owner, org, &trust).await.body;
    assert_eq!(issued(&sign(f, &recipient, org, &request, key).await), original);
    problem(
        &sign(f, &recipient, org, &request, Uuid::now_v7()).await,
        413,
        "certificate.quota_exceeded",
    );
    assert_eq!(allocation(f, org).await, before);
    assert_eq!(read(f, &owner, org, &trust).await.body, snapshot);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_certificates").await, 100_000);

    let current = member(f, &owner, org, membership).await;
    let suspended = update(f, &owner, org, &current, TeamMemberStatus::Suspended).await;
    assert_eq!(suspended.status, 200);
    let suspended = TeamMemberResource::from_json(&suspended.body).unwrap();
    assert_eq!(krl(&read(f, &owner, org, &trust).await, &trust).revoked_serials(), [1]);
    assert_eq!(update(f, &owner, org, &suspended, TeamMemberStatus::Active).await.status, 200);
    let before = allocation(f, org).await;
    let snapshot = read(f, &owner, org, &trust).await.body;
    problem(&sign(f, &recipient, org, &request, key).await, 409, "certificate.revoked");
    problem(
        &sign(f, &recipient, org, &request, Uuid::now_v7()).await,
        413,
        "certificate.quota_exceeded",
    );
    assert_eq!(allocation(f, org).await, before);
    assert_eq!(read(f, &owner, org, &trust).await.body, snapshot);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM organization_user_certificates").await,
        100_000,
        "revocation does not free unexpired issuance capacity"
    );
    // The synthetic Device removal must first release its non-cascading login family.
    for sql in [
        "DELETE FROM device_refresh_families WHERE device_id=$1",
        "DELETE FROM identity_devices WHERE device_id=$1",
    ] {
        match &f.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query(sql)
                    .bind(recipient.registration.payload.device_id.as_bytes().as_slice())
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            AuthBackend::Postgres(store) => {
                sqlx::query(sql)
                    .bind(recipient.registration.payload.device_id.as_bytes().as_slice())
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
        }
    }
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_certificates").await, 99_999);
    problem(
        &sign(f, &owner, org, &request, Uuid::now_v7()).await,
        413,
        "certificate.quota_exceeded",
    );
    assert_eq!(allocation(f, org).await, before);
    assert_eq!(read(f, &owner, org, &trust).await.body, snapshot);
}

#[tokio::test]
async fn sqlite_krl_download_requires_exact_current_device_authority_and_persisted_snapshot() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    let mut fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    downloads(&mut fixture).await;
    fixture.close().await;
}

#[tokio::test]
async fn sqlite_krl_team_transitions_are_atomic_and_receipts_never_restore_revoked_serials() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    let mut fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    lifecycle(&mut fixture).await;
    fixture.close().await;
}

#[tokio::test]
async fn sqlite_krl_issuance_capacity_preserves_receipts_and_counts_revoked_serials() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    issuance_cap(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_krl_download_requires_exact_current_device_authority_and_persisted_snapshot() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let mut fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    downloads(&mut fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_krl_team_transitions_are_atomic_and_receipts_never_restore_revoked_serials() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let mut fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    lifecycle(&mut fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_krl_issuance_capacity_preserves_receipts_and_counts_revoked_serials() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    issuance_cap(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_krl_committed_lost_ack_preserves_revocation_and_original_dissolution_confirmation()
 {
    use scoplen_store::organizations::OrganizationStoreError;
    use std::sync::atomic::Ordering;
    let (store, admin, schema, database) = crate::account_entry::tests::postgres_fixture().await;
    let store = Arc::new(store);
    let f = Fixture::start(AuthBackend::Postgres(store.clone()), directory()).await;
    let owner = actor(&f, "krl-lost-owner").await;
    let recipient = actor(&f, "krl-lost-member").await;
    let org = create_team(&f, &owner).await.id;
    let membership = enroll_member(&f, &owner, &recipient, org).await;
    let trust = provision(&f, &owner, org).await;
    let host = create_asset(
        &f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"Lost acknowledgment host","address":"lost.example.test"}),
    )
    .await;
    rule(
        &f,
        &owner,
        org,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id }],
        },
    )
    .await;
    rule(
        &f,
        &owner,
        org,
        membership,
        SimpleRule::Connect {
            hosts: vec![host.id],
            host_groups: vec![],
            remote_user: "deploy".into(),
        },
    )
    .await;
    let request = request(CertificateTargets::Hosts(vec![host.id]), 300);
    let receipt_key = Uuid::now_v7();
    issued(&sign(&f, &recipient, org, &request, receipt_key).await);
    issued(&sign(&f, &owner, org, &request, Uuid::now_v7()).await);
    let principal = store
        .current_device_principal(owner.registration.payload.device_id.into_bytes())
        .await
        .unwrap()
        .unwrap();
    let expires = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap() + 600;
    let proxy = crate::test_lost_commit::LostCommitProxy::start(database.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let current = member(&f, &owner, org, membership).await;
    let mutation =
        TeamMemberUpdateRequest { roles: current.roles, status: TeamMemberStatus::Suspended };
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        proxied
            .change_team_member(
                &principal,
                expires,
                org,
                membership,
                &current.etag,
                true,
                true,
                Some(&mutation)
            )
            .await,
        Err(OrganizationStoreError::UpdateCommitOutcomeUnknown)
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(member(&f, &owner, org, membership).await.status, TeamMemberStatus::Suspended);
    assert_eq!(krl(&read(&f, &owner, org, &trust).await, &trust).revoked_serials(), [1]);
    let suspended = member(&f, &owner, org, membership).await;
    assert_eq!(update(&f, &owner, org, &suspended, TeamMemberStatus::Active).await.status, 200);
    problem(&sign(&f, &recipient, org, &request, receipt_key).await, 409, "certificate.revoked");
    let team = current_team(&f, &owner, org).await;
    let key = Uuid::now_v7();
    let mutation = TeamDissolveRequest { organization_id: org };
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        proxied.dissolve_team(&principal, expires, org, key, &team.etag, &mutation).await,
        Err(OrganizationStoreError::CommitOutcomeUnknown)
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    let final_bytes = stored(&f, org, trust.id).await;
    assert_eq!(
        UserCaKrl::from_bytes(&final_bytes, &trust.public_key).unwrap().revoked_serials(),
        [1, 2]
    );
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let confirmed = call(
        &f,
        &owner,
        "POST",
        &format!("/api/v1/orgs/{org}/dissolve"),
        &mutation.to_json().unwrap(),
        &[("If-Match", &team.etag), ("Idempotency-Key", &key.to_string())],
    )
    .await;
    assert_eq!(confirmed.status, 200);
    assert_eq!(stored(&f, org, trust.id).await, final_bytes);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    proxied.pool().close().await;
    drop(proxy);
    f.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
