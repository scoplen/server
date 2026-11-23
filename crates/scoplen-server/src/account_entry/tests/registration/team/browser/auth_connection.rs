// SPDX-License-Identifier: AGPL-3.0-only
//! D-169 public connection read and original browser family suspension over real HTTPS.

use axum::{body::Body, http::Request};
use scoplen_api::{
    account_browser::INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
    audit::{AuditCategory, AuditListQuery, AuditPage, AuditResource, AuditResourceKind},
    auth_connection::{ConnectionResource, ConnectionStatus},
};

use super::{super::tls::TlsFixture, *};

pub(super) async fn seed_active_connection(f: &Fixture, organization: Uuid, issuer: &str) -> Uuid {
    let revision = Uuid::now_v7();
    // The active head is an authorized public-read fixture. Neither operation may decrypt its credential.
    let sql = "INSERT INTO organization_auth_connections(organization_id,revision,status,issuer,client_id,space_id,provider,trust_fingerprint,credential,created_at_ms)
        VALUES($1,$2,'active',$3,'review-client','spc_Review','unused-provider',$4,$5,1750000000000)";
    macro_rules! seed {
        ($pool:expr) => {
            sqlx::query(sql)
                .bind(organization.as_bytes().as_slice())
                .bind(revision.as_bytes().as_slice())
                .bind(issuer)
                .bind([0x11_u8; 32].as_slice())
                .bind([0x22_u8; 80].as_slice())
                .execute($pool)
                .await
                .unwrap()
        };
    }
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            seed!(store.pool());
        }
        AuthBackend::Postgres(store) => {
            seed!(store.pool());
        }
    }
    revision
}

async fn send(
    tls: &TlsFixture,
    browser: &Browser,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut request = TlsFixture::signed(&browser.key, &browser.access, method, path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    tls.send(request.body(Body::from(body.to_vec())).unwrap()).await
}

fn suspension_headers<'a>(key: &'a str, tag: &'a str) -> [(&'a str, &'a str); 3] {
    [("Origin", ORIGIN), ("If-Match", tag), ("Idempotency-Key", key)]
}

fn connection(reply: &Reply, organization: Uuid, status: ConnectionStatus) -> ConnectionResource {
    assert_eq!(reply.status, 200);
    reply.private();
    Uuid::parse_str(reply.header("x-request-id").unwrap()).unwrap();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    ConnectionResource::from_http_json(
        &reply.body,
        organization,
        Some(status),
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

async fn lifecycle(f: &Fixture) {
    let owner = actor(f, "connection-owner").await;
    let outsider = actor(f, "connection-outsider").await;
    let org = create_team(f, &owner).await.id;
    let foreign = create_team(f, &outsider).await.id;
    let browser = login(f, &owner.registration).await;
    let origin_session = scope::current_session(f, &browser).await.unwrap();
    let other_family = login(f, &owner.registration).await;
    let other_owner = login(f, &outsider.registration).await;
    let tls = TlsFixture::start(f).await;
    let root = format!("/api/v1/orgs/{org}");
    let path = format!("{root}/auth-connection");
    let suspend = format!("{path}/suspend");
    let empty = send(&tls, &browser, "GET", &path, &[], &[]).await;
    empty.problem(404, "organization.not_found", false);
    let other = format!("/api/v1/orgs/{foreign}/auth-connection");
    send(&tls, &browser, "GET", &other, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("https://{}/tenant", listener.local_addr().unwrap());
    let revision = seed_active_connection(f, org, &issuer).await;
    let active = connection(
        &send(&tls, &browser, "GET", &path, &[], &[]).await,
        org,
        ConnectionStatus::Active,
    );
    assert_eq!(active.id, revision);
    assert_eq!(active.target.issuer, issuer);
    assert_eq!(active.target.client_id, "review-client");
    assert_eq!(active.target.space_id, "spc_Review");
    send(&tls, &other_owner, "GET", &path, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    tls.get(&owner, &path).await.problem(401, "auth.authentication_required", false);

    let original_tag = active.etag();
    let key = Uuid::now_v7().to_string();
    let headers = suspension_headers(&key, &original_tag);
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    let before = f.revision(org).await;
    let result = send(&tls, &browser, "POST", &suspend, &headers, &[]).await;
    let suspended = connection(&result, org, ConnectionStatus::Suspended);
    assert_ne!(suspended.id, revision);
    assert_eq!(suspended.target, active.target);
    let current = send(&tls, &other_family, "GET", &path, &[("Origin", ORIGIN)], &[]).await;
    assert_eq!(connection(&current, org, ConnectionStatus::Suspended), suspended);
    let replay = send(&tls, &browser, "POST", &suspend, &headers, &[]).await;
    assert_eq!(connection(&replay, org, ConnectionStatus::Suspended), suspended);
    assert_eq!(replay.body, result.body);
    let denied = send(&tls, &other_family, "POST", &suspend, &headers, &[]).await;
    denied.problem(409, "organization.conflict", false);
    assert!(!String::from_utf8_lossy(&denied.body).contains(&issuer));
    let new_key = Uuid::now_v7().to_string();
    send(&tls, &browser, "POST", &suspend, &suspension_headers(&new_key, &original_tag), &[])
        .await
        .problem(412, "organization.precondition_failed", false);
    send(&tls, &browser, "POST", &suspend, &suspension_headers(&new_key, &suspended.etag()), &[])
        .await
        .problem(409, "organization.conflict", false);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connections WHERE status='suspended' AND credential IS NULL AND provider IS NULL AND trust_fingerprint IS NULL").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_receipts").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);
    assert_eq!(f.revision(org).await, before);
    assert_eq!(current_team(f, &owner, org).await.id, org);

    let audit_page = send(&tls, &browser, "GET", &format!("{root}/audit-events"), &[], &[]).await;
    assert_suspension_event(
        &audit_page,
        org,
        owner.registration.payload.account_id,
        Uuid::from_bytes(origin_session.family_id),
        &issuer,
    );
    assert!(tokio::time::timeout(Duration::from_millis(150), listener.accept()).await.is_err());

    let retained = INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
        .split(' ')
        .filter(|scope| *scope != "auth-connection:manage")
        .collect::<Vec<_>>()
        .join(" ");
    scope::set_scope(f, origin_session.family_id, &retained).await;
    send(&tls, &browser, "GET", &path, &[], &[]).await.problem(403, "policy.denied", false);
    send(&tls, &browser, "POST", &suspend, &headers, &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    assert_eq!(send(&tls, &browser, "GET", &root, &[], &[]).await.status, 200);
}

browser_tests!(
    sqlite_auth_connection_https_owner_suspends_once_with_original_family,
    postgres_auth_connection_https_owner_suspends_once_with_original_family,
    lifecycle
);

fn assert_suspension_event(reply: &Reply, org: Uuid, account: Uuid, family: Uuid, issuer: &str) {
    assert_eq!(reply.status, 200);
    reply.private();
    for hidden in [issuer, "review-client", "spc_Review", "unused-provider"] {
        assert!(!String::from_utf8_lossy(&reply.body).contains(hidden));
    }
    let page = AuditPage::from_json_for(&reply.body, org, &AuditListQuery::default()).unwrap();
    let events: Vec<_> = page
        .items
        .iter()
        .filter(|event| {
            event.event_class.as_deref() == Some("organization.auth_connection_suspended")
        })
        .collect();
    assert_eq!(events.len(), 1);
    let event = events[0];
    assert_eq!(event.category, AuditCategory::AccountChange);
    assert_eq!(
        event.resource,
        Some(AuditResource { kind: AuditResourceKind::Organization, id: org })
    );
    assert_eq!(event.actor_account_id, Some(account));
    assert_eq!(event.actor_browser_family_id, Some(family));
    assert!(event.actor_device_id.is_none());
}

async fn wire(f: &Fixture) {
    let owner = actor(f, "connection-wire-owner").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let tls = TlsFixture::start(f).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection");
    let suspend = format!("{path}/suspend");
    let revision = seed_active_connection(f, org, "https://issuer.example.test").await;
    let tag = format!("\"{revision}\"");
    let key = Uuid::now_v7().to_string();
    let headers = suspension_headers(&key, &tag);
    f.execute("UPDATE account_entry_state SET time_high_water_ms=4000000020000").await;

    let unsigned = Request::get(&path).header("Host", "example.com").body(Body::empty()).unwrap();
    tls.send(unsigned).await.problem(401, "auth.authentication_required", false);
    let valid = TlsFixture::signed(&browser.key, &browser.access, "GET", &path)
        .body(Body::empty())
        .unwrap();
    let (parts, _) = valid.into_parts();
    let accepted = tls.send(Request::from_parts(parts.clone(), Body::empty())).await;
    assert_eq!(connection(&accepted, org, ConnectionStatus::Active).id, revision);
    tls.send(Request::from_parts(parts, Body::empty())).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    send(&tls, &browser, "GET", &path, &[("Origin", "https://foreign.example")], &[])
        .await
        .problem(403, "policy.denied", false);
    for (target, extra) in [
        (format!("{path}?mode=all"), vec![]),
        (path.clone(), vec![("If-None-Match", "*")]),
        (path.clone(), vec![("Idempotency-Key", key.as_str())]),
        (path.clone(), vec![("Content-Encoding", "gzip")]),
        (format!("/api/v1/orgs/{}/auth-connection", Uuid::new_v4()), vec![]),
    ] {
        send(&tls, &browser, "GET", &target, &extra, &[]).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    send(&tls, &browser, "POST", &suspend, &[headers[1], headers[2]], &[]).await.problem(
        403,
        "policy.denied",
        false,
    );
    send(&tls, &browser, "POST", &suspend, &[headers[0], headers[2]], &[]).await.problem(
        428,
        "organization.precondition_required",
        false,
    );
    let no_key = vec![headers[0], headers[1]];
    for (extra, body) in [
        (no_key, &[][..]),
        (vec![headers[0], headers[2], ("If-Match", "*")], &[][..]),
        (vec![headers[0], headers[2], ("If-Match", "W/\"weak\"")], &[][..]),
        (vec![headers[0], headers[2], ("If-None-Match", "*")], &[][..]),
        (vec![headers[0], headers[1], headers[2], headers[1]], &[][..]),
        (vec![headers[0], headers[1], headers[2], ("Content-Type", "application/json")], &[][..]),
        (headers.to_vec(), b"x".as_slice()),
    ] {
        send(&tls, &browser, "POST", &suspend, &extra, body).await.problem(
            400,
            "organization.invalid_request",
            false,
        );
    }
    // The first eight admitted malformed writes spent the private budget. Source-only denials cannot spend it.
    for _ in 0..2 {
        send(&tls, &browser, "POST", &suspend, &[headers[0]], &[]).await.problem(
            428,
            "organization.precondition_required",
            false,
        );
    }
    let limited = send(&tls, &browser, "POST", &suspend, &headers, &[]).await;
    limited.problem(429, "auth.rate_limited", true);
    for name in ["retry-after", "ratelimit", "ratelimit-policy", "x-request-id"] {
        assert!(limited.header(name).is_some());
    }
    assert_source_limit(&tls, &suspend).await;
    assert_eq!(
        connection(
            &send(&tls, &browser, "GET", &path, &[], &[]).await,
            org,
            ConnectionStatus::Active
        )
        .id,
        revision
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_receipts").await, 0);
}

browser_tests!(
    sqlite_auth_connection_https_proof_conditions_and_before_work_admission,
    postgres_auth_connection_https_proof_conditions_and_before_work_admission,
    wire
);

async fn assert_source_limit(tls: &TlsFixture, suspend: &str) {
    // Twelve writes have reached source admission (one invalid Origin, ten admitted, one private refusal).
    for attempt in 13..=31 {
        let anonymous =
            Request::post(suspend).header("Host", "example.com").body(Body::empty()).unwrap();
        let reply = tls.send(anonymous).await;
        if attempt == 31 {
            reply.problem(429, "auth.rate_limited", true);
        } else {
            reply.problem(401, "auth.authentication_required", false);
        }
    }
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_auth_connection_https_lost_suspend_commit_confirms_original_family() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, mut database) =
        crate::account_entry::tests::postgres_fixture().await;
    let application = format!("suspend_commit_{}", Uuid::new_v4().simple());
    database.query_pairs_mut().append_pair("application_name", &application);
    let proxy = crate::test_lost_commit::LostCommitProxy::start(database.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let owner = actor(&fixture, "suspend-commit-owner").await;
    let org = create_team(&fixture, &owner).await.id;
    let browser = login(&fixture, &owner.registration).await;
    let revision = seed_active_connection(&fixture, org, "https://issuer.example.test").await;
    let tls = TlsFixture::start(&fixture).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection");
    let suspend = format!("{path}/suspend");
    let tag = format!("\"{revision}\"");
    let key = Uuid::now_v7().to_string();
    let headers = suspension_headers(&key, &tag);
    let audit = fixture.count("SELECT count(*) FROM audit_events").await;
    let mut lock = store.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE organization_auth_connections IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let release = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%FROM organization_auth_connections%')"
                ).bind(&application).fetch_one(store.pool()).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("suspension reached the head after proof and write admission");
        proxy.armed.store(true, Ordering::SeqCst);
        lock.commit().await.unwrap();
    };
    let (unknown, ()) =
        tokio::join!(send(&tls, &browser, "POST", &suspend, &headers, &[]), release);
    changed_problem(&unknown, 503, "organization.commit_outcome_unknown", true);
    assert!(!String::from_utf8_lossy(&unknown.body).contains("issuer.example.test"));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let current = connection(
        &send(&tls, &browser, "GET", &path, &[], &[]).await,
        org,
        ConnectionStatus::Suspended,
    );
    let retry = send(&tls, &browser, "POST", &suspend, &headers, &[]).await;
    assert_eq!(connection(&retry, org, ConnectionStatus::Suspended), current);
    assert_eq!(fixture.count("SELECT count(*) FROM audit_events").await, audit + 1);
    assert_eq!(
        fixture.count("SELECT count(*) FROM organization_auth_connection_receipts").await,
        1
    );
    fixture.close().await;
    store.pool().close().await;
    drop(proxy);
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
