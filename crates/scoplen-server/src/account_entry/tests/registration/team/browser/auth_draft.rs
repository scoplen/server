// SPDX-License-Identifier: AGPL-3.0-only
//! D-166 through verified HTTPS, native Device and independent Account-browser sessions.

use axum::{body::Body, http::Request};
use scoplen_api::auth_connection_draft::{DraftCreate, DraftResource};

use super::super::tls::TlsFixture;
use super::*;

mod retained_scope;

struct Writer<'a> {
    key: &'a P256SigningKey,
    token: &'a str,
}

impl<'a> Writer<'a> {
    fn device(actor: &'a Actor) -> Self {
        Self { key: &actor.registration.device, token: &actor.token.access_token }
    }

    fn browser(browser: &'a Browser) -> Self {
        Self { key: &browser.key, token: &browser.access }
    }

    fn signed(&self, method: &str, path: &str) -> axum::http::request::Builder {
        TlsFixture::signed(self.key, self.token, method, path)
    }

    async fn send(
        &self,
        tls: &TlsFixture,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut request = self.signed(method, path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        tls.send(request.body(Body::from(body.to_vec())).unwrap()).await
    }
}

fn create_headers(key: &str) -> [(&str, &str); 4] {
    [
        ("Idempotency-Key", key),
        ("If-None-Match", "*"),
        ("Content-Type", "application/json"),
        ("Origin", ORIGIN),
    ]
}

fn cancel_headers<'a>(key: &'a str, tag: &'a str) -> [(&'a str, &'a str); 3] {
    [("Idempotency-Key", key), ("If-Match", tag), ("Origin", ORIGIN)]
}

fn resource(reply: &Reply, status: u16, org: Uuid) -> DraftResource {
    assert_eq!(reply.status, status);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    Uuid::parse_str(reply.header("x-request-id").unwrap()).unwrap();
    DraftResource::from_http_json(
        &reply.body,
        org,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

fn cancelled(reply: &Reply) {
    assert_eq!(reply.status, 204);
    reply.private();
    Uuid::parse_str(reply.header("x-request-id").unwrap()).unwrap();
    assert_eq!(reply.body.len(), 0);
    assert!(reply.header("etag").is_none());
}

fn denied(reply: &Reply, status: u16, code: &str) {
    problem(reply, status, code);
    let json: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(json["instance"], reply.header("x-request-id").unwrap());
    assert!(reply.header("location").is_none());
    assert!(!String::from_utf8_lossy(&reply.body).contains("issuer.example.test"));
}

async fn add_admin(f: &Fixture, owner: &Actor, admin: &Actor, org: Uuid) -> Uuid {
    let (invitation, password, _, _) =
        issue(f, owner, admin, org, vec![TeamRole::Administrator]).await;
    let body = TeamInvitationAcceptRequest { password }.to_json().unwrap();
    let reply = call(
        f,
        admin,
        "POST",
        &format!("/api/v1/orgs/{org}/invitations/{}/accept", invitation.id),
        body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 200);
    TeamAcceptanceReceipt::from_json(&reply.body).unwrap().membership_id
}

async fn lifecycle(f: &Fixture) {
    let owner = actor(f, "draft-owner").await;
    let admin = actor(f, "draft-admin").await;
    let org = create_team(f, &owner).await.id;
    let other = create_team(f, &admin).await.id;
    add_admin(f, &owner, &admin, org).await;
    let session = login(f, &admin.registration).await;
    let other_writer = login(f, &owner.registration).await;
    let browser = Writer::browser(&session);
    let device = Writer::device(&owner);
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let foreign = format!("/api/v1/orgs/{other}/auth-connection-draft");
    let create = Uuid::now_v7().to_string();
    let cancel = Uuid::now_v7().to_string();
    let revision = f.revision(org).await;
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    let issuer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("https://{}/tenant/", issuer_listener.local_addr().unwrap());
    let body = DraftCreate { issuer: issuer.clone() }.to_json().unwrap();
    let reply = device.send(&tls, "POST", &path, &body, &create_headers(&create)).await;
    let first = resource(&reply, 201, org);
    assert_eq!(first.issuer, issuer);
    assert_eq!(resource(&browser.send(&tls, "GET", &path, &[], &[]).await, 200, org), first);
    denied(&device.send(&tls, "GET", &foreign, &[], &[]).await, 404, "organization.not_found");
    denied(
        &Writer::browser(&other_writer)
            .send(&tls, "POST", &path, &body, &create_headers(&create))
            .await,
        409,
        "organization.conflict",
    );
    let tag = first.etag();
    cancelled(&browser.send(&tls, "DELETE", &path, &[], &cancel_headers(&cancel, &tag)).await);
    denied(&device.send(&tls, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&body).unwrap())
            .unwrap();
    let confirmation = device.send(&tls, "POST", &path, &pretty, &create_headers(&create)).await;
    assert_eq!(resource(&confirmation, 201, org), first);
    denied(&device.send(&tls, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    let reply = browser
        .send(&tls, "POST", &path, &body, &create_headers(&Uuid::now_v7().to_string()))
        .await;
    let replacement = resource(&reply, 201, org);
    assert_ne!(replacement.etag(), tag);
    cancelled(&browser.send(&tls, "DELETE", &path, &[], &cancel_headers(&cancel, &tag)).await);
    denied(
        &browser.send(&tls, "DELETE", &foreign, &[], &cancel_headers(&cancel, &tag)).await,
        409,
        "organization.conflict",
    );
    denied(
        &browser
            .send(&tls, "DELETE", &path, &[], &cancel_headers(&cancel, &replacement.etag()))
            .await,
        409,
        "organization.conflict",
    );
    denied(
        &browser
            .send(&tls, "DELETE", &path, &[], &cancel_headers(&Uuid::now_v7().to_string(), &tag))
            .await,
        412,
        "organization.precondition_failed",
    );
    assert_eq!(resource(&device.send(&tls, "GET", &path, &[], &[]).await, 200, org), replacement);
    assert_eq!(f.revision(org).await, revision);
    f.execute("UPDATE organization_auth_draft_receipts SET created_at_ms=1,expires_at_ms=86400001")
        .await;
    denied(
        &device.send(&tls, "POST", &path, &body, &create_headers(&create)).await,
        409,
        "organization.conflict",
    );
    denied(
        &browser.send(&tls, "DELETE", &path, &[], &cancel_headers(&cancel, &tag)).await,
        409,
        "organization.conflict",
    );
    assert_eq!(resource(&device.send(&tls, "GET", &path, &[], &[]).await, 200, org), replacement);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 3);
    assert_eq!(current_team(f, &admin, other).await.id, other);
    assert_eq!(current_team(f, &owner, org).await.id, org);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), issuer_listener.accept()).await.is_err()
    );
}

browser_tests!(
    sqlite_issuer_draft_https_generation_and_original_writer_confirmation,
    postgres_issuer_draft_https_generation_and_original_writer_confirmation,
    lifecycle
);

const CREATE: &[u8] = br#"{"data":{"issuer":"https://issuer.example.test/tenant/"}}"#;

async fn policy(f: &Fixture, owner: &Actor, target: &Actor, org: Uuid, effect: &str) {
    let source = format!(
        "{effect}(principal == Account::\"{}\", action == Action::\"manage_organization\", resource == Organization::\"{org}\");",
        target.registration.payload.account_id
    );
    let body = serde_json::to_vec(&serde_json::json!({
        "id": Uuid::now_v7(), "data": { "name": "Draft governance", "source": source, "enabled": true }
    })).unwrap();
    let reply = call(
        f,
        owner,
        "POST",
        &format!("/api/v1/orgs/{org}/policies"),
        &body,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 201);
}

async fn current_authority(f: &Fixture) {
    let owner = actor(f, "draft-authority-owner").await;
    let admin = actor(f, "draft-authority-admin").await;
    let org = create_team(f, &owner).await.id;
    let membership = add_admin(f, &owner, &admin, org).await;
    let session = login(f, &admin.registration).await;
    let browser = Writer::browser(&session);
    let device = Writer::device(&admin);
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let key = Uuid::now_v7().to_string();
    policy(f, &owner, &admin, org, "permit").await;
    for occupied in [false, true] {
        if occupied {
            change_member(
                f,
                &owner,
                org,
                membership,
                TeamRole::Administrator,
                TeamMemberStatus::Active,
            )
            .await;
            resource(
                &browser.send(&tls, "POST", &path, CREATE, &create_headers(&key)).await,
                201,
                org,
            );
        }
        for role in [TeamRole::Member, TeamRole::SecurityAuditor, TeamRole::Approver] {
            change_member(f, &owner, org, membership, role, TeamMemberStatus::Active).await;
            for writer in [&device, &browser] {
                denied(&writer.send(&tls, "GET", &path, &[], &[]).await, 403, "policy.denied");
            }
        }
        denied(
            &browser.send(&tls, "POST", &path, CREATE, &create_headers(&key)).await,
            403,
            "policy.denied",
        );
    }
    change_member(f, &owner, org, membership, TeamRole::Administrator, TeamMemberStatus::Active)
        .await;
    policy(f, &owner, &admin, org, "forbid").await;
    denied(
        &browser.send(&tls, "POST", &path, CREATE, &create_headers(&key)).await,
        403,
        "policy.denied",
    );
    denied(&device.send(&tls, "GET", &path, &[], &[]).await, 403, "policy.denied");
    change_member(f, &owner, org, membership, TeamRole::Administrator, TeamMemberStatus::Suspended)
        .await;
    denied(
        &browser.send(&tls, "POST", &path, CREATE, &create_headers(&key)).await,
        404,
        "organization.not_found",
    );
}

browser_tests!(
    sqlite_issuer_draft_https_current_role_and_cedar_precede_receipts,
    postgres_issuer_draft_https_current_role_and_cedar_precede_receipts,
    current_authority
);

async fn credentials(f: &Fixture) {
    let mut actor = actor(f, "draft-credential-owner").await;
    let org = create_team(f, &actor).await.id;
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let mut browser = login(f, &actor.registration).await;
    let tls = TlsFixture::start(f).await;
    let b = Writer::browser(&browser);
    let read = b.signed("GET", &path).body(Body::empty()).unwrap();
    let (parts, body) = read.into_parts();
    denied(
        &tls.send(Request::from_parts(parts.clone(), body)).await,
        404,
        "organization.not_found",
    );
    denied(
        &tls.send(Request::from_parts(parts, Body::empty())).await,
        401,
        "auth.authentication_required",
    );
    let wrong_path = b.signed("GET", "/api/v1/orgs").uri(&path).body(Body::empty()).unwrap();
    denied(&tls.send(wrong_path).await, 401, "auth.authentication_required");
    let wrong_method = b.signed("POST", &path).method("GET").body(Body::empty()).unwrap();
    denied(&tls.send(wrong_method).await, 401, "auth.authentication_required");
    denied(
        &b.send(&tls, "GET", &path, &[], &[("Origin", "https://other.example.test")]).await,
        403,
        "policy.denied",
    );
    let key = Uuid::now_v7().to_string();
    denied(
        &b.send(&tls, "POST", &path, CREATE, &create_headers(&key)[..3]).await,
        403,
        "policy.denied",
    );
    let cookie_only = Request::get(&path)
        .header("Host", "example.com")
        .header("Cookie", &browser.cookie)
        .body(Body::empty())
        .unwrap();
    denied(&tls.send(cookie_only).await, 401, "auth.authentication_required");
    let family = scope::current_session(f, &browser).await.unwrap().family_id;
    scope::set_scope(f, family, "orgs:read").await;
    narrow(f, &mut actor, "orgs:read").await;
    let refresh = request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
    (browser.access, browser.cookie) = session(&refresh, false);
    for writer in [Writer::device(&actor), Writer::browser(&browser)] {
        denied(&writer.send(&tls, "GET", &path, &[], &[]).await, 403, "policy.denied");
    }
    actor.token = authenticate(f, &actor.registration).await;
    let fresh = login(f, &actor.registration).await;
    for writer in [Writer::device(&actor), Writer::browser(&fresh)] {
        denied(&writer.send(&tls, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    }
    f.execute("UPDATE account_browser_families SET created_at_ms=created_at_ms-2592000000,expires_at_ms=expires_at_ms-2592000000").await;
    f.execute("UPDATE identity_devices SET active=false").await;
    for writer in [Writer::device(&actor), Writer::browser(&fresh)] {
        denied(
            &writer.send(&tls, "GET", &path, &[], &[]).await,
            401,
            "auth.authentication_required",
        );
    }
}

browser_tests!(
    sqlite_issuer_draft_https_proof_origin_and_retained_scope,
    postgres_issuer_draft_https_proof_origin_and_retained_scope,
    credentials
);

async fn source_limit_after_eleven_attempts(tls: &TlsFixture, path: &str) {
    for attempt in 12..=31 {
        let anonymous =
            Request::post(path).header("Host", "example.com").body(Body::empty()).unwrap();
        let reply = tls.send(anonymous).await;
        if attempt == 31 {
            reply.problem(429, "auth.rate_limited", true);
        } else {
            denied(&reply, 401, "auth.authentication_required");
        }
    }
}

async fn wire(f: &Fixture) {
    let owner = actor(f, "draft-wire-owner").await;
    let org = create_team(f, &owner).await.id;
    let device = Writer::device(&owner);
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let key = Uuid::now_v7().to_string();
    let headers = create_headers(&key);
    let noncanonical = format!("/api/v1/orgs/{}/auth-connection-draft", Uuid::new_v4());
    denied(
        &device.send(&tls, "GET", &noncanonical, &[], &[]).await,
        400,
        "organization.invalid_request",
    );
    denied(
        &device.send(&tls, "GET", &path, &[], &[("If-None-Match", "*")]).await,
        400,
        "organization.invalid_request",
    );
    denied(
        &device.send(&tls, "GET", &path, &[], &[("Idempotency-Key", &key)]).await,
        400,
        "organization.invalid_request",
    );
    denied(&device.send(&tls, "GET", &path, b"x", &[]).await, 400, "organization.invalid_request");
    denied(
        &device.send(&tls, "GET", &format!("{path}?issuer=ignored"), &[], &[]).await,
        400,
        "organization.invalid_request",
    );
    denied(
        &device.send(&tls, "DELETE", &path, &[], &[("Idempotency-Key", &key)]).await,
        428,
        "organization.precondition_required",
    );
    f.execute("UPDATE account_entry_state SET time_high_water_ms=4000000020000").await;
    let missing = [headers[0], headers[2]];
    denied(
        &device.send(&tls, "POST", &path, CREATE, &missing).await,
        428,
        "organization.precondition_required",
    );
    let wrong_media = [headers[0], headers[1], ("Content-Type", "text/plain")];
    denied(
        &device.send(&tls, "POST", &path, CREATE, &wrong_media).await,
        415,
        "organization.invalid_request",
    );
    let duplicate = [headers[0], headers[1], headers[2], headers[1]];
    denied(
        &device.send(&tls, "POST", &path, CREATE, &duplicate).await,
        400,
        "organization.invalid_request",
    );
    denied(
        &device.send(&tls, "POST", &path, &vec![b' '; 4097], &headers).await,
        413,
        "organization.invalid_request",
    );
    let oversized_issuer = serde_json::to_vec(&serde_json::json!({
        "data": {"issuer": format!("https://issuer.example.test/{}", "a".repeat(2048))}
    }))
    .unwrap();
    for invalid in [
        br#"{"data":{"issuer":"http://issuer.example.test"}}"#.as_slice(),
        br#"{"data":{"issuer":"https://issuer.example.test","issuer":"https://second.example.test"}}"#,
        br#"{"data":{"issuer":"https://issuer.example.test","client_secret":"unused"}}"#,
        br#"{"data":{"issuer":"https://issuer.example.test"},"activate":true}"#,
        &oversized_issuer,
        &[0xff],
    ] {
        denied(&device.send(&tls, "POST", &path, invalid, &headers).await, 400, "organization.invalid_request");
    }
    let limited = device.send(&tls, "POST", &path, CREATE, &headers).await;
    limited.problem(429, "auth.rate_limited", true);
    for header in ["retry-after", "ratelimit", "ratelimit-policy", "x-request-id"] {
        assert!(limited.header(header).is_some());
    }
    source_limit_after_eleven_attempts(&tls, &path).await;
    denied(&device.send(&tls, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    denied(
        &device
            .send(
                &tls,
                "DELETE",
                &path,
                &[],
                &cancel_headers(&key, &format!("\"{}\"", Uuid::now_v7())),
            )
            .await,
        412,
        "organization.precondition_failed",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_draft_receipts").await, 0);
}

browser_tests!(
    sqlite_issuer_draft_https_wire_errors_and_mutation_admission,
    postgres_issuer_draft_https_wire_errors_and_mutation_admission,
    wire
);

async fn serialized_writes(f: &Fixture) {
    let owner = actor(f, "draft-concurrency-owner").await;
    let org = create_team(f, &owner).await.id;
    let session = login(f, &owner.registration).await;
    let native = Writer::device(&owner);
    let browser = Writer::browser(&session);
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let first_key = Uuid::now_v7().to_string();
    let second_key = Uuid::now_v7().to_string();
    let first_headers = create_headers(&first_key);
    let second_headers = create_headers(&second_key);
    let audit = f.count("SELECT COUNT(*) FROM audit_events").await;
    f.audit_failure(true).await;
    denied(
        &native.send(&tls, "POST", &path, CREATE, &first_headers).await,
        503,
        "organization.storage_unavailable",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_draft_receipts").await, 0);
    denied(&native.send(&tls, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    f.audit_failure(false).await;
    f.receipt_commit_failure(true, "organization_auth_draft_receipts").await;
    let unconfirmed = native.send(&tls, "POST", &path, CREATE, &first_headers).await;
    changed_problem(&unconfirmed, 503, "organization.commit_outcome_unknown", true);
    assert!(unconfirmed.header("etag").is_none());
    assert!(unconfirmed.header("x-request-id").is_some());
    assert!(!String::from_utf8_lossy(&unconfirmed.body).contains("issuer.example.test"));
    f.receipt_commit_failure(false, "organization_auth_draft_receipts").await;
    let (a, b) = tokio::join!(
        native.send(&tls, "POST", &path, CREATE, &first_headers),
        browser.send(&tls, "POST", &path, CREATE, &second_headers)
    );
    let (won, lost, writer, headers) = if a.status == 201 {
        (a, b, &native, &first_headers)
    } else {
        (b, a, &browser, &second_headers)
    };
    let original = resource(&won, 201, org);
    denied(&lost, 412, "organization.precondition_failed");
    denied(
        &writer
            .send(
                &tls,
                "POST",
                &path,
                br#"{"data":{"issuer":"https://other.example.test/"}}"#,
                headers,
            )
            .await,
        409,
        "organization.conflict",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_auth_draft_receipts").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 1);
    let tag = original.etag();
    let cancel = Uuid::now_v7().to_string();
    let replacement_key = Uuid::now_v7().to_string();
    let cancel_headers = cancel_headers(&cancel, &tag);
    let create_headers = create_headers(&replacement_key);
    let (cancelled_reply, created) = tokio::join!(
        native.send(&tls, "DELETE", &path, &[], &cancel_headers),
        browser.send(&tls, "POST", &path, CREATE, &create_headers)
    );
    cancelled(&cancelled_reply);
    let current = native.send(&tls, "GET", &path, &[], &[]).await;
    if created.status == 201 {
        let replacement = resource(&created, 201, org);
        assert_ne!(replacement.id, original.id);
        assert_eq!(resource(&current, 200, org), replacement);
        assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 3);
    } else {
        denied(&created, 412, "organization.precondition_failed");
        denied(&current, 404, "organization.not_found");
        assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit + 2);
    }
}

browser_tests!(
    sqlite_issuer_draft_https_rollback_and_concurrent_generations,
    postgres_issuer_draft_https_rollback_and_concurrent_generations,
    serialized_writes
);

#[cfg(feature = "postgres-integration")]
async fn waiting_at_draft(pool: &sqlx::PgPool, application: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT o.id FROM organizations o JOIN organization_memberships %')",
            ).bind(application).fetch_one(pool).await.unwrap();
            if waiting { return; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("draft is waiting for the Organization lock after proof and admission");
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_issuer_draft_https_lost_commit_and_membership_change_while_waiting() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, mut database) =
        crate::account_entry::tests::postgres_fixture().await;
    let application = format!("draft_commit_{}", Uuid::new_v4().simple());
    database.query_pairs_mut().append_pair("application_name", &application);
    let proxy = crate::test_lost_commit::LostCommitProxy::start(database.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let owner = actor(&fixture, "draft-commit-owner").await;
    let administrator = actor(&fixture, "draft-commit-admin").await;
    let org = create_team(&fixture, &owner).await.id;
    let membership = add_admin(&fixture, &owner, &administrator, org).await;
    let session = login(&fixture, &administrator.registration).await;
    let browser = Writer::browser(&session);
    let tls = TlsFixture::start(&fixture).await;
    let key = Uuid::now_v7().to_string();
    let headers = create_headers(&key);
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let audit = fixture.count("SELECT COUNT(*) FROM audit_events").await;
    for demote in [false, true] {
        let mut held = store.pool().begin().await.unwrap();
        sqlx::query("SELECT o.id FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id WHERE o.id=$1 AND m.id=$2 FOR UPDATE OF o,m")
            .bind(org.as_bytes().as_slice())
            .bind(membership.as_bytes().as_slice())
            .fetch_one(&mut *held)
            .await
            .unwrap();
        let pending = browser.send(&tls, "POST", &path, CREATE, &headers);
        let release = async {
            waiting_at_draft(store.pool(), &application).await;
            if demote {
                sqlx::query("UPDATE organization_memberships SET roles_json='[\"member\"]', updated_at_ms=updated_at_ms+1 WHERE id=$1")
                    .bind(membership.as_bytes().as_slice()).execute(&mut *held).await.unwrap();
            } else {
                proxy.armed.store(true, Ordering::SeqCst);
            }
            held.commit().await.unwrap();
        };
        let (reply, ()) = tokio::join!(pending, release);
        if demote {
            denied(&reply, 403, "policy.denied");
        } else {
            changed_problem(&reply, 503, "organization.commit_outcome_unknown", true);
            assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
            let current = resource(&browser.send(&tls, "GET", &path, &[], &[]).await, 200, org);
            let confirmed =
                resource(&browser.send(&tls, "POST", &path, CREATE, &headers).await, 201, org);
            assert_eq!(confirmed, current);
        }
        assert_eq!(fixture.count("SELECT COUNT(*) FROM audit_events").await, audit + 1);
        assert_eq!(fixture.count("SELECT COUNT(*) FROM organization_auth_draft_receipts").await, 1);
    }
    drop(tls);
    fixture.close().await;
    store.pool().close().await;
    drop(proxy);
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
