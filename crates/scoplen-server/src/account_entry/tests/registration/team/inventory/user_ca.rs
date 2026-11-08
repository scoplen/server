// SPDX-License-Identifier: AGPL-3.0-only
//! Real Device HTTP acceptance of local CA trust and current scoped SSH issuance.

use super::*;
use scoplen_api::{
    certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateTargets},
    user_ca::{UserCaCreateRequest, UserCaPage, UserCaResource, user_ca_fingerprint},
};
use ssh_key::{Certificate, PublicKey, certificate::CertType, private::Ed25519Keypair};

fn ca(reply: &Reply, status: u16) -> UserCaResource {
    assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    UserCaResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("shared CA Resource")
}

fn issued(reply: &Reply) -> CertificateIssuanceResponse {
    assert_eq!(reply.status, 201, "{}", String::from_utf8_lossy(&reply.body));
    reply.private();
    CertificateIssuanceResponse::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("shared certificate Resource")
}

fn request(targets: CertificateTargets, ttl: u32) -> CertificateIssuanceRequest {
    let public = PublicKey::new(Ed25519Keypair::from_seed(&[9; 32]).public.into(), "")
        .to_openssh()
        .expect("subject public key");
    CertificateIssuanceRequest::new(public, targets, "deploy", ttl).expect("shared request")
}

async fn provision(f: &Fixture, owner: &Actor, org: Uuid) -> UserCaResource {
    let request = UserCaCreateRequest { id: Uuid::now_v7() }.to_json().expect("CA request");
    ca(
        &call(
            f,
            owner,
            "POST",
            &format!("/api/v1/orgs/{org}/certificate-authorities"),
            &request,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    )
}

async fn sign(
    f: &Fixture,
    actor: &Actor,
    org: Uuid,
    request: &CertificateIssuanceRequest,
    key: Uuid,
) -> Reply {
    call(
        f,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/certificates"),
        &request.to_json().expect("D-88 request"),
        &[("Idempotency-Key", &key.to_string())],
    )
    .await
}

async fn add_policy(f: &Fixture, owner: &Actor, org: Uuid, source: &str) -> PolicyResource {
    policy(
        &call(
            f,
            owner,
            "POST",
            &format!("/api/v1/orgs/{org}/policies"),
            &serde_json::to_vec(&json!({"id":Uuid::now_v7(),"data":{
                "name":"Certificate authorization","source":source,"enabled":true
            }}))
            .expect("policy request"),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        201,
    )
}

async fn rule(
    f: &Fixture,
    owner: &Actor,
    org: Uuid,
    membership: Uuid,
    value: SimpleRule,
) -> PolicyResource {
    let source = SimpleRuleInput {
        organization: org,
        subject: SimpleRuleSubject::Membership(membership),
        rule: value,
    }
    .generate()
    .expect("shared policy generator");
    add_policy(f, owner, org, &source).await
}

fn verify(
    response: &CertificateIssuanceResponse,
    request: &CertificateIssuanceRequest,
    trust: &UserCaResource,
    owner: &Actor,
    org: Uuid,
    serial: u64,
) -> Certificate {
    response.validate_request_subject(request).expect("exact request subject");
    let certificate = Certificate::from_openssh(&response.certificate).expect("SSH certificate");
    certificate.verify_signature().expect("real CA signature");
    assert_eq!(certificate.cert_type(), CertType::User);
    assert_eq!(certificate.serial(), serial);
    assert_eq!(
        certificate.signature_key(),
        PublicKey::from_openssh(&trust.public_key).expect("trusted CA").key_data()
    );
    assert_eq!(
        certificate.key_id(),
        format!(
            "spl:{org}:{}:{}:{}",
            owner.registration.payload.account_id,
            owner.registration.payload.device_id,
            response.id
        )
    );
    let (kind, ids) = match &request.targets {
        CertificateTargets::Hosts(ids) => ("h", ids),
        CertificateTargets::HostGroups(ids) => ("g", ids),
    };
    assert_eq!(
        certificate.valid_principals(),
        ids.iter()
            .map(|id| format!("spl:{org}:{kind}:{id}:{}", request.remote_user))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        certificate.valid_before() - certificate.valid_after(),
        u64::from(request.ttl_seconds.min(1_800)) + 60
    );
    assert!(certificate.critical_options().is_empty());
    assert_eq!(certificate.extensions().len(), 2);
    assert_eq!(certificate.extensions().get("permit-pty").map(String::as_str), Some(""));
    assert_eq!(certificate.extensions().get("org@scoplen.com"), Some(&org.to_string()));
    certificate
}

#[allow(clippy::too_many_lines)]
async fn trust_and_issuance(f: &Fixture) {
    let mut owner = actor(f, "ca-owner").await;
    let outsider = actor(f, "ca-outsider").await;
    let org = create_team(f, &owner).await.id;
    let root = format!("/api/v1/orgs/{org}");
    let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"SSH host","address":"ssh.example.test"}),
    )
    .await;
    let ca_create = UserCaCreateRequest { id: Uuid::now_v7() };
    let bytes = ca_create.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let revision = f.revision(org).await;
    let trust = ca(
        &call(
            f,
            &owner,
            "POST",
            &format!("{root}/certificate-authorities"),
            &bytes,
            &[("Idempotency-Key", &key)],
        )
        .await,
        201,
    );
    assert_eq!(trust.fingerprint, user_ca_fingerprint(&trust.public_key).unwrap());
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let replay = ca(
        &call(
            f,
            &owner,
            "POST",
            &format!("{root}/certificate-authorities"),
            &serde_json::to_vec_pretty(
                &serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
            .unwrap(),
            &[("Idempotency-Key", &key)],
        )
        .await,
        201,
    );
    assert_eq!(replay, trust);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_cas").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    assert_eq!(f.revision(org).await, revision);
    let path = format!("{root}/certificate-authorities/{}", trust.id);
    assert_eq!(ca(&call(f, &owner, "GET", &path, &[], &[]).await, 200), trust);
    let list =
        call(f, &owner, "GET", &format!("{root}/certificate-authorities?limit=1"), &[], &[]).await;
    assert_eq!(list.status, 200);
    list.private();
    let page = UserCaPage::from_json(&list.body).expect("shared CA Page");
    assert_eq!(page.items, vec![trust.clone()]);
    assert_eq!(page.next_cursor, None);
    problem(&call(f, &outsider, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    problem(
        &call(f, &owner, "GET", &format!("{path}?unused=1"), &[], &[]).await,
        400,
        "organization.invalid_request",
    );
    problem(
        &call(
            f,
            &owner,
            "POST",
            &format!("{root}/certificate-authorities"),
            &UserCaCreateRequest { id: Uuid::now_v7() }.to_json().unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        409,
        "organization.conflict",
    );
    let issuance = request(CertificateTargets::Hosts(vec![host.id]), 86_400);
    let operation = Uuid::now_v7();
    let response = issued(&sign(f, &owner, org, &issuance, operation).await);
    verify(&response, &issuance, &trust, &owner, org, 1);
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    assert_eq!(issued(&sign(f, &owner, org, &issuance, operation).await), response);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_certificates").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
    let changed = request(CertificateTargets::Hosts(vec![host.id]), 30);
    problem(&sign(f, &owner, org, &changed, operation).await, 409, "organization.conflict");
    let foreign = request(CertificateTargets::Hosts(vec![Uuid::now_v7()]), 30);
    problem(&sign(f, &owner, org, &foreign, Uuid::now_v7()).await, 404, "organization.not_found");
    problem(
        &sign(f, &outsider, org, &issuance, Uuid::now_v7()).await,
        404,
        "organization.not_found",
    );
    assert_eq!(f.revision(org).await, revision);
    add_policy(
        f,
        &owner,
        org,
        "forbid(principal, action == Action::\"connect\", resource) when { !(context has sso_age_seconds) };",
    )
    .await;
    problem(&sign(f, &owner, org, &issuance, operation).await, 403, "policy.denied");
    narrow(f, &mut owner, "ca:read").await;
    assert_eq!(ca(&call(f, &owner, "GET", &path, &[], &[]).await, 200), trust);
    problem(&sign(f, &owner, org, &issuance, Uuid::now_v7()).await, 403, "policy.denied");
}

#[allow(clippy::too_many_lines)]
async fn current_authority(f: &Fixture) {
    let owner = actor(f, "ca-policy-owner").await;
    let member = actor(f, "ca-policy-member").await;
    let org = create_team(f, &owner).await.id;
    let membership = enroll_member(f, &owner, &member, org).await;
    let trust = provision(f, &owner, org).await;
    let root = format!("/api/v1/orgs/{org}");
    let group =
        create_asset(f, &owner, org, InventoryType::HostGroup, json!({"name":"Production"})).await;
    let empty =
        create_asset(f, &owner, org, InventoryType::HostGroup, json!({"name":"Empty"})).await;
    let host = create_asset(f, &owner, org, InventoryType::Host,
        json!({"name":"Selected host","address":"selected.example.test","groups":{group.id.to_string():true}})).await;
    let issuance = request(CertificateTargets::Hosts(vec![host.id]), 30);
    let key = Uuid::now_v7();
    assert_eq!(
        ca(
            &call(
                f,
                &member,
                "GET",
                &format!("{root}/certificate-authorities/{}", trust.id),
                &[],
                &[]
            )
            .await,
            200
        ),
        trust
    );
    problem(&sign(f, &member, org, &issuance, key).await, 404, "organization.not_found");
    rule(
        f,
        &owner,
        org,
        membership,
        SimpleRule::View {
            resources: vec![
                SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id },
                SimpleRuleSelector { object_type: ObjectType::HOST_GROUP, id: group.id },
                SimpleRuleSelector { object_type: ObjectType::HOST_GROUP, id: empty.id },
            ],
        },
    )
    .await;
    problem(&sign(f, &member, org, &issuance, key).await, 403, "policy.denied");
    let permit = rule(
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
    let response = issued(&sign(f, &member, org, &issuance, key).await);
    verify(&response, &issuance, &trust, &member, org, 1);
    let selected = request(CertificateTargets::HostGroups(vec![group.id]), 30);
    let grouped = issued(&sign(f, &member, org, &selected, Uuid::now_v7()).await);
    verify(&grouped, &selected, &trust, &member, org, 2);
    problem(
        &sign(
            f,
            &member,
            org,
            &request(CertificateTargets::HostGroups(vec![empty.id]), 30),
            Uuid::now_v7(),
        )
        .await,
        403,
        "policy.denied",
    );
    let disabled = serde_json::to_vec(&json!({"data":{"name":permit.fields.name,
        "source":permit.fields.source,"enabled":false}}))
    .unwrap();
    policy(
        &call(
            f,
            &owner,
            "PUT",
            &format!("{root}/policies/{}", permit.id),
            &disabled,
            &[("If-Match", &permit.etag)],
        )
        .await,
        200,
    );
    problem(&sign(f, &member, org, &issuance, key).await, 403, "policy.denied");
    problem(&sign(f, &member, org, &selected, Uuid::now_v7()).await, 403, "policy.denied");
    let ca_request = UserCaCreateRequest { id: Uuid::now_v7() }.to_json().unwrap();
    problem(
        &call(
            f,
            &member,
            "POST",
            &format!("{root}/certificate-authorities"),
            &ca_request,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        403,
        "policy.denied",
    );
    let foreign = create_team(f, &owner).await.id;
    let foreign_host = create_asset(
        f,
        &owner,
        foreign,
        InventoryType::Host,
        json!({"name":"Other team","address":"foreign.example.test"}),
    )
    .await;
    problem(
        &sign(
            f,
            &owner,
            org,
            &request(CertificateTargets::Hosts(vec![foreign_host.id]), 30),
            Uuid::now_v7(),
        )
        .await,
        404,
        "organization.not_found",
    );
    let member_path = format!("{root}/members/{membership}");
    let current =
        TeamMemberResource::from_json(&call(f, &owner, "GET", &member_path, &[], &[]).await.body)
            .unwrap();
    assert_eq!(
        call(f, &owner, "DELETE", &member_path, &[], &[("If-Match", &current.etag)]).await.status,
        204
    );
    problem(&sign(f, &member, org, &issuance, key).await, 404, "organization.not_found");
}

#[allow(clippy::too_many_lines)]
async fn unsupported_source_ip_rules(f: &Fixture) {
    for (effect, address, delete) in [("permit", "127.0.0.1", false), ("forbid", "192.0.2.1", true)]
    {
        let owner = actor(f, &format!("ca-source-{effect}")).await;
        let org = create_team(f, &owner).await.id;
        let trust = provision(f, &owner, org).await;
        let root = format!("/api/v1/orgs/{org}");
        let group = create_asset(
            f,
            &owner,
            org,
            InventoryType::HostGroup,
            json!({"name":"Selected group"}),
        )
        .await;
        let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"Selected host","address":"source.example.test","groups":{group.id.to_string():true}}),
    )
    .await;
        add_policy(
        f,
        &owner,
        org,
        "permit(principal, action == Action::\"connect\", resource) when { context.remote_user != \"context.source_ip\" }; // context.source_ip",
    )
    .await;
        add_policy(
        f,
        &owner,
        org,
        "permit(principal, action == Action::\"manage_ca\", resource) when { context == context };",
    )
    .await;
        let issuance = request(CertificateTargets::Hosts(vec![host.id]), 30);
        let grouped = request(CertificateTargets::HostGroups(vec![group.id]), 30);
        let key = Uuid::now_v7();
        let original = issued(&sign(f, &owner, org, &issuance, key).await);
        verify(&original, &issuance, &trust, &owner, org, 1);
        let unsupported = add_policy(
            f,
            &owner,
            org,
            &format!(
                "{effect}(principal, action == Action::\"connect\", resource) when {{ context.source_ip == \"{address}\" }};"
            ),
        )
        .await;
        let certificates = f.count("SELECT COUNT(*) FROM organization_user_certificates").await;
        let receipts = f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await;
        let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
        problem(&sign(f, &owner, org, &issuance, Uuid::now_v7()).await, 403, "policy.denied");
        problem(&sign(f, &owner, org, &issuance, key).await, 403, "policy.denied");
        problem(&sign(f, &owner, org, &grouped, Uuid::now_v7()).await, 403, "policy.denied");
        assert_eq!(
            f.count("SELECT COUNT(*) FROM organization_user_certificates").await,
            certificates
        );
        assert_eq!(f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await, receipts);
        assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit);
        let path = format!("{root}/policies/{}", unsupported.id);
        if delete {
            assert_eq!(
                call(f, &owner, "DELETE", &path, &[], &[("If-Match", &unsupported.etag)])
                    .await
                    .status,
                204
            );
        } else {
            let disabled = serde_json::to_vec(&json!({"data":{
                "name":unsupported.fields.name,"source":unsupported.fields.source,"enabled":false
            }}))
            .unwrap();
            policy(
                &call(f, &owner, "PUT", &path, &disabled, &[("If-Match", &unsupported.etag)]).await,
                200,
            );
        }
        assert_eq!(issued(&sign(f, &owner, org, &issuance, key).await), original);
        let restored = issued(&sign(f, &owner, org, &issuance, Uuid::now_v7()).await);
        verify(&restored, &issuance, &trust, &owner, org, 2);
    }
}

#[allow(clippy::too_many_lines)]
async fn atomic_failure_and_input(f: &Fixture) {
    let owner = actor(f, "ca-rollback-owner").await;
    let org = create_team(f, &owner).await.id;
    let root = format!("/api/v1/orgs/{org}");
    let ca_request = UserCaCreateRequest { id: Uuid::now_v7() }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    let ca_count = f.count("SELECT COUNT(*) FROM organization_user_cas").await;
    let receipts = f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await;
    f.audit_failure(true).await;
    problem(
        &call(
            f,
            &owner,
            "POST",
            &format!("{root}/certificate-authorities"),
            &ca_request,
            &[("Idempotency-Key", &key)],
        )
        .await,
        503,
        "organization.storage_unavailable",
    );
    f.audit_failure(false).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_cas").await, ca_count);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await, receipts);
    let trust = ca(
        &call(
            f,
            &owner,
            "POST",
            &format!("{root}/certificate-authorities"),
            &ca_request,
            &[("Idempotency-Key", &key)],
        )
        .await,
        201,
    );
    let host = create_asset(
        f,
        &owner,
        org,
        InventoryType::Host,
        json!({"name":"Rollback host","address":"rollback.example.test"}),
    )
    .await;
    let issuance = request(CertificateTargets::Hosts(vec![host.id]), 30);
    let key = Uuid::now_v7();
    let certs = f.count("SELECT COUNT(*) FROM organization_user_certificates").await;
    let receipts = f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await;
    f.audit_failure(true).await;
    problem(&sign(f, &owner, org, &issuance, key).await, 503, "organization.storage_unavailable");
    f.audit_failure(false).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_certificates").await, certs);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_inventory_receipts").await, receipts);
    let response = issued(&sign(f, &owner, org, &issuance, key).await);
    verify(&response, &issuance, &trust, &owner, org, 1);
    for (body, status) in [(b"{}".to_vec(), 400), (vec![b' '; 16_385], 413)] {
        problem(
            &call(
                f,
                &owner,
                "POST",
                &format!("{root}/certificates"),
                &body,
                &[("Idempotency-Key", &Uuid::now_v7().to_string())],
            )
            .await,
            status,
            "certificate.invalid_request",
        );
    }
    problem(
        &call(
            f,
            &owner,
            "POST",
            &format!("{root}/certificates"),
            &issuance.to_json().unwrap(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string()), ("If-Match", "\"unexpected\"")],
        )
        .await,
        400,
        "organization.invalid_request",
    );
    let corrupt = match &f.backend {
        AuthBackend::Sqlite(_) => {
            "UPDATE organization_user_cas SET encrypted_seed=zeroblob(73) WHERE organization_id=$1"
        }
        AuthBackend::Postgres(_) => {
            "UPDATE organization_user_cas SET encrypted_seed=decode(repeat('00',73),'hex') WHERE organization_id=$1"
        }
    };
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(corrupt)
                .bind(org.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(corrupt)
                .bind(org.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }
    problem(
        &sign(f, &owner, org, &issuance, Uuid::now_v7()).await,
        503,
        "organization.storage_unavailable",
    );
    assert_eq!(
        ca(
            &call(
                f,
                &owner,
                "GET",
                &format!("{root}/certificate-authorities/{}", trust.id),
                &[],
                &[]
            )
            .await,
            200
        ),
        trust
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_user_certificates").await, certs + 1);
}

#[tokio::test]
async fn sqlite_public_organization_user_ca_and_certificates() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    trust_and_issuance(&fixture).await;
    current_authority(&fixture).await;
    atomic_failure_and_input(&fixture).await;
    fixture.close().await;
}

#[tokio::test]
async fn sqlite_initial_user_ca_refuses_current_source_ip_connect_policies() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    unsupported_source_ip_rules(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_public_organization_user_ca_and_certificates() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    trust_and_issuance(&fixture).await;
    current_authority(&fixture).await;
    atomic_failure_and_input(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_initial_user_ca_refuses_current_source_ip_connect_policies() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    unsupported_source_ip_rules(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
