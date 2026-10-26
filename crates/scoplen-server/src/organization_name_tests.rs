// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use notifications::Listener;
use scoplen_api::organization::OrganizationUpdateRequest;
use tokio::net::TcpStream;

async fn https(
    listener: &Listener,
    identity: &LegacyDeviceSession,
    token: &str,
    method: &str,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Reply {
    let tls = listener.tls(b"http/1.1").await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("trusted HTTPS handshake");
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let proof =
        account_profile::proof_for(identity, method, path.split('?').next().expect("path"), token);
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "setup.example.com:9443")
        .header("Origin", ORIGIN)
        .header("Authorization", format!("DPoP {token}"))
        .header("DPoP", proof.as_str());
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let reply = sender
        .send_request(builder.body(Body::from(body.to_vec())).expect("HTTPS request"))
        .await
        .expect("HTTPS response");
    let status = reply.status().as_u16();
    let mut headers = String::new();
    for (name, value) in reply.headers() {
        writeln!(headers, "{}: {}", name.as_str(), value.to_str().expect("header"))
            .expect("header text");
    }
    let body = reply.into_body().collect().await.expect("HTTPS body").to_bytes().to_vec();
    drop(sender);
    task.abort();
    Reply { status, headers, body }
}

async fn rename(
    listener: &Listener,
    identity: &LegacyDeviceSession,
    team: &OrganizationResource,
    name: &str,
) -> Reply {
    let body = OrganizationUpdateRequest::new(name).expect("name").to_json().expect("update JSON");
    https(
        listener,
        identity,
        &identity.token,
        "PATCH",
        &format!("{COLLECTION}/{}", team.id),
        &body,
        &[("Content-Type", "application/json"), ("If-Match", &team.etag)],
    )
    .await
}

async fn read(listener: &Listener, identity: &LegacyDeviceSession, id: Uuid) -> Reply {
    https(listener, identity, &identity.token, "GET", &format!("{COLLECTION}/{id}"), &[], &[]).await
}

async fn pending(
    listener: &Listener,
    identity: &LegacyDeviceSession,
    team: &OrganizationResource,
    body: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tls = listener.tls(b"http/1.1").await;
    let path = format!("{COLLECTION}/{}", team.id);
    let proof = account_profile::proof_for(identity, "PATCH", &path, &identity.token);
    let headers = format!(
        "PATCH {path} HTTP/1.1\r\nHost: setup.example.com:9443\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nExpect: 100-continue\r\nIf-Match: {}\r\nAuthorization: DPoP {}\r\nDPoP: {}\r\n\r\n",
        body.len(),
        team.etag,
        identity.token,
        proof.as_str(),
    );
    tls.write_all(headers.as_bytes()).await.expect("authenticated PATCH headers");
    let mut interim = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !interim.ends_with(b"\r\n\r\n") {
            interim.push(tls.read_u8().await.expect("100 Continue"));
            assert!(interim.len() <= 256);
        }
    })
    .await
    .expect("authenticated body poll");
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue\r\n"));
    tls
}

async fn release(mut tls: tokio_rustls::client::TlsStream<TcpStream>, body: &[u8]) -> Reply {
    tls.write_all(body).await.expect("release authenticated PATCH");
    let mut bytes = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(15), tls.read_to_end(&mut bytes))
        .await
        .expect("bounded PATCH response")
        .expect("TLS response");
    let boundary = bytes.windows(4).position(|part| part == b"\r\n\r\n").expect("headers");
    let headers = std::str::from_utf8(&bytes[..boundary]).expect("header text").to_owned();
    let status =
        headers.split_whitespace().nth(1).expect("status").parse().expect("numeric status");
    Reply { status, headers, body: bytes[boundary + 4..].to_vec() }
}

async fn roles(f: &Fixture, team: &OrganizationResource, roles: &str) {
    let sql = "UPDATE organization_memberships SET roles_json=$1,updated_at_ms=updated_at_ms+1 WHERE id=$2";
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(sql)
                .bind(roles)
                .bind(team.membership.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("current tenant roles");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(sql)
                .bind(roles)
                .bind(team.membership.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("current tenant roles");
        }
    }
}

async fn membership_account(f: &Fixture, team: &OrganizationResource, account: Uuid) {
    let sql = "UPDATE organization_memberships SET account_id=$1 WHERE id=$2";
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(sql)
                .bind(account.as_bytes().as_slice())
                .bind(team.membership.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("owned membership binding");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(sql)
                .bind(account.as_bytes().as_slice())
                .bind(team.membership.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("owned membership binding");
        }
    }
}

async fn contract(mut f: Fixture) {
    let mut a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let key = Uuid::now_v7();
    let original = resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201);
    a.token = authenticate_device(&f, a.receipt.device_id, &a.client).await;
    let listener = Listener::start(&mut f).await;
    let updated =
        resource(&rename(&listener, &a, &original, "Production").await, a.receipt.account_id, 200);
    assert_eq!(updated.id, original.id);
    assert_eq!(updated.membership, original.membership);
    assert_eq!(updated.created_at, original.created_at);
    assert!(updated.updated_at >= original.updated_at);
    assert_ne!(updated.etag, original.etag);
    assert_eq!(updated.name, "Production");
    assert_eq!(
        resource(&read(&listener, &a, updated.id).await, a.receipt.account_id, 200),
        updated
    );
    let discovered = page(
        &https(&listener, &a, &a.token, "GET", COLLECTION, &[], &[]).await,
        a.receipt.account_id,
        OrganizationListQuery::default(),
    );
    assert_eq!(discovered.items.as_slice(), std::slice::from_ref(&updated));
    assert_eq!(
        resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201),
        updated
    );
    create(&f, &a, key, "Production").await.problem(409, "organization.conflict", false, false);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    assert_eq!(
        resource(&rename(&listener, &a, &updated, "Production").await, a.receipt.account_id, 200),
        updated
    );
    for name in ["Another name", "Production"] {
        rename(&listener, &a, &original, name).await.problem(
            412,
            "organization.precondition_failed",
            false,
            false,
        );
    }
    for table in ["organizations", "organization_memberships", "organization_creation_receipts"] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 1);
    }
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    session_and_keys(&f, &a.receipt, &a.token, &a.client).await;
    drop(listener);
    f.cleanup().await;
}

async fn authorization(mut f: Fixture) {
    let mut a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let team = resource(&create(&f, &a, Uuid::now_v7(), "First").await, a.receipt.account_id, 201);
    let other =
        resource(&create(&f, &a, Uuid::now_v7(), "Second").await, a.receipt.account_id, 201);
    a.token = authenticate_device(&f, a.receipt.device_id, &a.client).await;
    assert_eq!(token_claims(&f, &a.token).await.org.len(), 2);
    let listener = Listener::start(&mut f).await;
    for role in ["member", "security_auditor", "approver", "unknown_role"] {
        roles(&f, &team, &format!("[\"{role}\"]")).await;
        rename(&listener, &a, &team, "Denied").await.problem(403, "policy.denied", false, false);
        let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
        rename(&listener, &a, &current, "Denied").await.problem(403, "policy.denied", false, false);
    }
    for role in ["administrator", "owner"] {
        roles(&f, &team, &format!("[\"{role}\"]")).await;
        let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
        let updated =
            resource(&rename(&listener, &a, &current, role).await, a.receipt.account_id, 200);
        assert_eq!(updated.name, role);
    }
    assert_eq!(resource(&read(&listener, &a, other.id).await, a.receipt.account_id, 200), other);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 4);
    for state in ["suspended", "deprovisioned"] {
        membership_status(&f, team.membership.id, state).await;
        rename(&listener, &a, &team, "Hidden").await.problem(
            404,
            "organization.not_found",
            false,
            false,
        );
    }
    membership_status(&f, team.membership.id, "active").await;
    let foreign = Uuid::now_v7();
    https(
        &listener,
        &a,
        &a.token,
        "PATCH",
        &format!("{COLLECTION}/{foreign}"),
        b"{\"data\":{\"name\":\"Hidden\"}}",
        &[("Content-Type", "application/json"), ("If-Match", &team.etag)],
    )
    .await
    .problem(404, "organization.not_found", false, false);
    let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
    let narrow = account_profile::signed_token(
        &f,
        &a,
        a.receipt.account_id,
        a.receipt.device_id,
        "account:read keys:read keys:write orgs:create orgs:read sync:read sync:write",
    )
    .await;
    https(
        &listener,
        &a,
        &narrow,
        "PATCH",
        &format!("{COLLECTION}/{}", team.id),
        b"{\"data\":{\"name\":\"Narrow\"}}",
        &[("Content-Type", "application/json"), ("If-Match", &current.etag)],
    )
    .await
    .problem(403, "policy.denied", false, false);
    let outsider = seed_legacy_device(&f, &key(9)).await;
    membership_account(&f, &team, outsider.account_id).await;
    rename(&listener, &a, &current, "Hidden").await.problem(
        404,
        "organization.not_found",
        false,
        false,
    );
    membership_account(&f, &team, a.receipt.account_id).await;
    f.execute("UPDATE identity_devices SET active=false").await;
    rename(&listener, &a, &current, "Revoked").await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 4);
    drop(listener);
    f.cleanup().await;
}

async fn invalid_requests(mut f: Fixture) {
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let team =
        resource(&create(&f, &a, Uuid::now_v7(), "Operations").await, a.receipt.account_id, 201);
    let listener = Listener::start(&mut f).await;
    let path = format!("{COLLECTION}/{}", team.id);
    let body = b"{\"data\":{\"name\":\"Production\"}}";
    https(&listener, &a, &a.token, "PATCH", &path, body, &[("Content-Type", "application/json")])
        .await
        .problem(428, "organization.precondition_required", false, false);
    for etag in ["W/\"tag\"", "*", "\"a\",\"b\"", "invalid", ""] {
        https(
            &listener,
            &a,
            &a.token,
            "PATCH",
            &path,
            body,
            &[("Content-Type", "application/json"), ("If-Match", etag)],
        )
        .await
        .problem(400, "organization.invalid_request", false, false);
    }
    for extra in [("If-Match", team.etag.as_str()), ("Idempotency-Key", "invalid")] {
        let headers =
            [("Content-Type", "application/json"), ("If-Match", team.etag.as_str()), extra];
        https(&listener, &a, &a.token, "PATCH", &path, body, &headers).await.problem(
            400,
            "organization.invalid_request",
            false,
            false,
        );
    }
    let headers = [("Content-Type", "application/json"), ("If-Match", team.etag.as_str())];
    for bad in [
        b"{}".as_slice(),
        b"{\"data\":{\"name\":\"one\",\"name\":\"two\"}}",
        b"{\"data\":{\"name\":\"one\",\"owner\":true}}",
        b"{\"data\":{\"name\":\" trailing \"}}",
        b"{\"data\":{\"name\":\"\"}}",
    ] {
        https(&listener, &a, &a.token, "PATCH", &path, bad, &headers).await.problem(
            400,
            "organization.invalid_request",
            false,
            false,
        );
    }
    https(&listener, &a, &a.token, "PATCH", &path, &vec![b' '; 1025], &headers).await.problem(
        400,
        "organization.invalid_request",
        false,
        false,
    );
    let oversized = serde_json::to_vec(&serde_json::json!({"data":{"name":"\u{e9}".repeat(65)}}))
        .expect("oversized UTF-8 name");
    https(&listener, &a, &a.token, "PATCH", &path, &oversized, &headers).await.problem(
        400,
        "organization.invalid_request",
        false,
        false,
    );
    https(&listener, &a, &a.token, "PATCH", &format!("{path}?unused=1"), body, &headers)
        .await
        .problem(400, "organization.invalid_request", false, false);
    https(&listener, &a, &a.token, "PATCH", "/api/v1/orgs/invalid", body, &headers).await.problem(
        400,
        "organization.invalid_request",
        false,
        false,
    );
    https(
        &listener,
        &a,
        &a.token,
        "PATCH",
        &path,
        body,
        &[("Content-Type", "text/plain"), ("If-Match", &team.etag)],
    )
    .await
    .problem(415, "organization.invalid_request", false, false);
    assert_eq!(resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200), team);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    let boundary = "\u{e9}".repeat(64);
    let updated =
        resource(&rename(&listener, &a, &team, &boundary).await, a.receipt.account_id, 200);
    assert_eq!(updated.name, boundary);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    drop(listener);
    f.cleanup().await;
}

async fn current_after_body(mut f: Fixture) {
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let team =
        resource(&create(&f, &a, Uuid::now_v7(), "Operations").await, a.receipt.account_id, 201);
    let listener = Listener::start(&mut f).await;
    let body = b"{\"data\":{\"name\":\"Production\"}}";
    let tls = pending(&listener, &a, &team, body).await;
    roles(&f, &team, "[\"member\"]").await;
    release(tls, body).await.problem(403, "policy.denied", false, false);
    roles(&f, &team, "[\"owner\"]").await;
    let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
    let tls = pending(&listener, &a, &current, body).await;
    membership_status(&f, team.membership.id, "suspended").await;
    release(tls, body).await.problem(404, "organization.not_found", false, false);
    membership_status(&f, team.membership.id, "active").await;
    let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
    let tls = pending(&listener, &a, &current, body).await;
    f.execute("UPDATE identity_devices SET active=false").await;
    release(tls, body).await.problem(401, "auth.authentication_required", false, false);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    let names: i64 = f.count("SELECT COUNT(*) FROM organizations WHERE name='Operations'").await;
    assert_eq!(names, 1);
    drop(listener);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_team_name_https_updates_all_projections_and_preserves_noop_and_personal_state() {
    contract(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_team_name_https_uses_current_cedar_roles_and_device_scope() {
    authorization(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_team_name_https_enforces_exact_request_and_preconditions() {
    invalid_requests(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_team_name_https_rechecks_current_authority_after_authenticated_body_admission() {
    current_after_body(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_name_https_updates_all_projections_and_preserves_noop_and_personal_state() {
    contract(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_name_https_uses_current_cedar_roles_and_device_scope() {
    authorization(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_name_https_enforces_exact_request_and_preconditions() {
    invalid_requests(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_name_https_rechecks_current_authority_after_authenticated_body_admission() {
    current_after_body(Fixture::postgres().await).await;
}

async fn audit_failure(mut f: Fixture) {
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let team =
        resource(&create(&f, &a, Uuid::now_v7(), "Operations").await, a.receipt.account_id, 201);
    let listener = Listener::start(&mut f).await;
    let (install, remove) = match &f.backend {
        AuthBackend::Sqlite(_) => (
            "CREATE TRIGGER team_name_audit_failure BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'owned audit failure'); END;",
            "DROP TRIGGER team_name_audit_failure;",
        ),
        AuthBackend::Postgres(_) => (
            "CREATE FUNCTION team_name_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END $$; CREATE TRIGGER team_name_audit_failure BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION team_name_audit_failure();",
            "DROP TRIGGER team_name_audit_failure ON audit_events; DROP FUNCTION team_name_audit_failure();",
        ),
    };
    f.execute(install).await;
    rename(&listener, &a, &team, "Production").await.problem(
        503,
        "organization.storage_unavailable",
        false,
        true,
    );
    assert_eq!(resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200), team);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    f.execute(remove).await;
    resource(&rename(&listener, &a, &team, "Production").await, a.receipt.account_id, 200);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    drop(listener);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_team_name_https_rolls_back_the_name_time_and_audit_together() {
    audit_failure(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_name_https_rolls_back_the_name_time_and_audit_together() {
    audit_failure(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_team_name_unconfirmed_commit_requires_read_before_another_explicit_edit() {
    let mut f = Fixture::sqlite().await;
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let team =
        resource(&create(&f, &a, Uuid::now_v7(), "Operations").await, a.receipt.account_id, 201);
    let listener = Listener::start(&mut f).await;
    f.execute("CREATE TABLE team_name_parent (id INTEGER PRIMARY KEY); CREATE TABLE team_name_child (id INTEGER REFERENCES team_name_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER team_name_commit_failure AFTER UPDATE OF name ON organizations BEGIN INSERT INTO team_name_child VALUES(1); END;").await;
    rename(&listener, &a, &team, "Production").await.problem(
        503,
        "organization.commit_outcome_unknown",
        true,
        false,
    );
    let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
    assert_eq!(current, team);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    f.execute("DROP TRIGGER team_name_commit_failure;").await;
    resource(&rename(&listener, &a, &current, "Reviewed name").await, a.receipt.account_id, 200);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    drop(listener);
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_name_lost_commit_reply_is_not_replayed_and_explicit_read_observes_update() {
    use std::sync::atomic::Ordering;
    let mut f = Fixture::postgres().await;
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let creation_key = Uuid::now_v7();
    let team =
        resource(&create(&f, &a, creation_key, "Operations").await, a.receipt.account_id, 201);
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PG URL");
    let (_, schema) = f.postgres.as_ref().expect("owned schema");
    let application = format!("team_name_commit_{}", Uuid::new_v4().simple());
    let mut url = Url::parse(&database).expect("fixture URL");
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"))
        .append_pair("application_name", &application);
    let proxy = crate::test_lost_commit::LostCommitProxy::start(url.as_str()).await;
    let store =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    let original = match &f.backend {
        AuthBackend::Postgres(store) => store.clone(),
        AuthBackend::Sqlite(_) => unreachable!(),
    };
    f.backend = AuthBackend::Postgres(Arc::new(store));
    let listener = Listener::start(&mut f).await;
    let mut held = original.pool().begin().await.expect("hold original row");
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(team.id.as_bytes().as_slice())
        .fetch_one(&mut *held)
        .await
        .expect("hold team row");
    let pending = rename(&listener, &a, &team, "Production");
    let release = async {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            loop {
                let waiting:bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT m.status,o.updated_at_ms%FOR UPDATE OF o,m%')")
                    .bind(&application).fetch_one(original.pool()).await.expect("observe protected update");
                if waiting { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("update waits after authentication/replay commits");
        proxy.armed.store(true, Ordering::SeqCst);
        held.commit().await.expect("release team row");
    };
    let (reply, ()) = tokio::join!(pending, release);
    reply.problem(503, "organization.commit_outcome_unknown", true, false);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let current = resource(&read(&listener, &a, team.id).await, a.receipt.account_id, 200);
    assert_eq!(current.name, "Production");
    assert_ne!(current.etag, team.etag);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    assert_eq!(
        resource(&create(&f, &a, creation_key, "Operations").await, a.receipt.account_id, 201),
        current
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 2);
    drop(listener);
    original.pool().close().await;
    f.cleanup().await;
    drop(proxy);
}
