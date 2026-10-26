// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::{
    auth::{AuthRefreshRequest, INITIAL_DEVICE_ACCESS_SCOPE},
    organization::{OrganizationListQuery, OrganizationPage, OrganizationResource},
};
use scoplen_crypto::{DeviceAccessToken, TrustedDeviceAccessTokenKeys};

const COLLECTION: &str = "/api/v1/orgs";
const OLD_SCOPE: &str = "account:read keys:read keys:write sync:read sync:write";

#[path = "organization_name_tests.rs"]
mod name;

async fn mount(f: &mut Fixture, allow_creation: bool) {
    f.server.abort();
    let _ = (&mut f.server).await;
    let storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
        root: f.directory.join("objects"),
    })
    .expect("owned object storage");
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let database = match &f.backend {
        AuthBackend::Sqlite(store) => ListenerDatabase::Sqlite(store.clone()),
        AuthBackend::Postgres(store) => ListenerDatabase::Postgres(store.clone()),
    };
    let app = crate::runtime::api_router_with_notifications(
        database,
        Arc::new(storage),
        Arc::new(kms),
        ORIGIN.into(),
        true,
        scoplen_sync::http::WriteRateLimits::default(),
        scoplen_sync::http::WriteBodyLimits::default(),
        scoplen_sync::http::ReadBodyLimits::default(),
        scoplen_sync::notify::NotificationHub::default(),
        crate::AccountSettings::default(),
        crate::OrganizationSettings { allow_creation },
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    f.address = listener.local_addr().expect("address");
    f.server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("team API");
    });
}

async fn request(
    f: &Fixture,
    identity: &LegacyDeviceSession,
    method: &str,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Reply {
    let proof = account_profile::proof_for(
        identity,
        method,
        path.split('?').next().expect("path"),
        &identity.token,
    );
    let authorization = format!("DPoP {}", identity.token);
    let mut headers = vec![
        ("Origin", ORIGIN),
        ("Authorization", authorization.as_str()),
        ("DPoP", proof.as_str()),
    ];
    headers.extend_from_slice(extra);
    http_method(f.address, method, path, body, &headers).await
}

async fn create(f: &Fixture, identity: &LegacyDeviceSession, key: Uuid, name: &str) -> Reply {
    let body = scoplen_api::organization::OrganizationCreateRequest::new(name)
        .expect("team name")
        .to_json()
        .expect("create JSON");
    request(
        f,
        identity,
        "POST",
        COLLECTION,
        &body,
        &[("Content-Type", "application/json"), ("Idempotency-Key", &key.to_string())],
    )
    .await
}

fn resource(reply: &Reply, account: Uuid, status: u16) -> OrganizationResource {
    assert_eq!(reply.status, status, "{}", reply.text());
    reply.privacy();
    assert!(reply.header("x-request-id").is_some());
    let value = OrganizationResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("bounded Resource and metadata");
    value.validate_for_account(account).expect("caller Account");
    assert!(!reply.text().contains("email"));
    value
}

fn page(reply: &Reply, account: Uuid, query: OrganizationListQuery) -> OrganizationPage {
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.privacy();
    assert!(reply.header("x-request-id").is_some());
    let value = OrganizationPage::from_http_json(
        &reply.body,
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("bounded Page and metadata");
    value.validate_for_account(account, query).expect("caller and continuation");
    value
}

async fn membership_status(f: &Fixture, id: Uuid, status: &str) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("UPDATE organization_memberships SET status=$1 WHERE id=$2")
                .bind(status)
                .bind(id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("membership status");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("UPDATE organization_memberships SET status=$1 WHERE id=$2")
                .bind(status)
                .bind(id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("membership status");
        }
    }
}

async fn token_claims(f: &Fixture, token: &str) -> scoplen_crypto::DeviceAccessTokenClaims {
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let keyring = f.backend.keyring(&kms).await.expect("current signing keys");
    let mut keys = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in keyring.verification_keys() {
        keys.insert(&key.kid, &key.public_key).expect("key");
    }
    DeviceAccessToken::parse(token)
        .expect("JWT")
        .verify(&keys, SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs())
        .expect("verified JWT")
        .claims()
        .clone()
}

async fn old_family_refresh(f: &Fixture, a: &LegacyDeviceSession, scope: &str) {
    let issued = authenticate_tokens(f, a.receipt.device_id, &a.client).await;
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("UPDATE device_refresh_families SET scope=$1 WHERE account_id=$2")
                .bind(scope)
                .bind(a.receipt.account_id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("old family ceiling");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("UPDATE device_refresh_families SET scope=$1 WHERE account_id=$2")
                .bind(scope)
                .bind(a.receipt.account_id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("old family ceiling");
        }
    }
    let proof = DpopProof::sign(
        &a.client,
        &a.client.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, "/api/v1/auth/refresh").expect("target"),
        DpopToken::Refresh,
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs(),
        None,
    )
    .expect("refresh proof");
    let body =
        AuthRefreshRequest::new(issued.refresh_token).expect("refresh").to_json().expect("JSON");
    let reply = http(
        f.address,
        "/api/v1/auth/refresh",
        body.as_bytes(),
        &[("Content-Type", "application/json"), ("DPoP", proof.as_str())],
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let rotated = AuthTokenResponse::from_json(reply.text()).expect("refresh result");
    let claims = token_claims(f, &rotated.access_token).await;
    assert_eq!(claims.scope, scope);
    assert_eq!(claims.org.len(), 2);
    let discovery = protected(f, "GET", COLLECTION, &[], &rotated.access_token, &a.client).await;
    if scope == OLD_SCOPE {
        discovery.problem(403, "policy.denied", false, false);
    } else {
        assert_eq!(discovery.status, 200);
    }
    let path = format!("{COLLECTION}/{}", claims.org[0].id);
    protected(
        f,
        "PATCH",
        &path,
        b"{\"data\":{\"name\":\"Denied\"}}",
        &rotated.access_token,
        &a.client,
    )
    .await
    .problem(403, "policy.denied", false, false);
    let scope =
        token_claims(f, &authenticate_device(f, a.receipt.device_id, &a.client).await).await.scope;
    assert_eq!(scope, INITIAL_DEVICE_ACCESS_SCOPE);
}

#[allow(clippy::too_many_lines)]
async fn contract(mut f: Fixture) {
    let a = legacy_device_session(&mut f).await;
    let key = Uuid::now_v7();
    assert_eq!(
        page(
            &request(&f, &a, "GET", COLLECTION, &[], &[]).await,
            a.receipt.account_id,
            OrganizationListQuery::default()
        )
        .items,
        []
    );
    create(&f, &a, key, "Operations").await.problem(403, "policy.denied", false, false);
    assert_eq!(f.count("SELECT COUNT(*) FROM organizations").await, 0);
    mount(&mut f, true).await;
    let mut first = resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201);
    assert_eq!(first.name, "Operations");
    assert_eq!(first.membership.roles, ["owner"]);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_memberships").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_creation_receipts").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    let replay = request(
        &f,
        &a,
        "POST",
        COLLECTION,
        b"{ \"data\": { \"name\": \"Operations\" } }",
        &[("Content-Type", "application/json"), ("Idempotency-Key", &key.to_string())],
    )
    .await;
    assert_eq!(resource(&replay, a.receipt.account_id, 201), first);
    let sql = "UPDATE organization_memberships SET roles_json='[\"owner\",\"future_role\"]',updated_at_ms=updated_at_ms+1 WHERE id=$1";
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(sql)
                .bind(first.membership.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("owned membership projection");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(sql)
                .bind(first.membership.id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("owned membership projection");
        }
    }
    let current = resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201);
    assert_ne!(current.etag, first.etag);
    assert_eq!(current.membership.roles, ["future_role", "owner"]);
    first = current;
    create(&f, &a, key, "Changed").await.problem(409, "organization.conflict", false, false);
    assert_eq!(f.count("SELECT COUNT(*) FROM organizations").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    let second =
        resource(&create(&f, &a, Uuid::now_v7(), "Network").await, a.receipt.account_id, 201);
    let one = page(
        &request(&f, &a, "GET", "/api/v1/orgs?limit=1", &[], &[]).await,
        a.receipt.account_id,
        OrganizationListQuery { limit: 1, cursor: None },
    );
    assert_eq!(one.items.len(), 1);
    assert_eq!(one.next_cursor, Some(one.items[0].id));
    let cursor = one.next_cursor.expect("continuation");
    let two = page(
        &request(&f, &a, "GET", &format!("/api/v1/orgs?limit=1&cursor={cursor}"), &[], &[]).await,
        a.receipt.account_id,
        OrganizationListQuery { limit: 1, cursor: Some(cursor) },
    );
    assert_eq!(two.items.len(), 1);
    assert!(two.next_cursor.is_none());
    assert!(one.items[0].id < two.items[0].id);
    let b_key = super::key(3);
    let b_receipt = seed_legacy_device(&f, &b_key).await;
    let b_token = authenticate_device(&f, b_receipt.device_id, &b_key).await;
    let b = LegacyDeviceSession {
        receipt: b_receipt,
        token: b_token,
        client: b_key,
        operator_token: String::new(),
        operator_key: super::key(4),
    };
    assert_eq!(
        page(
            &request(&f, &b, "GET", COLLECTION, &[], &[]).await,
            b.receipt.account_id,
            OrganizationListQuery::default()
        )
        .items,
        []
    );
    let foreign = request(&f, &b, "GET", &format!("{COLLECTION}/{}", first.id), &[], &[]).await;
    let absent =
        request(&f, &b, "GET", &format!("{COLLECTION}/{}", Uuid::now_v7()), &[], &[]).await;
    for reply in [&foreign, &absent] {
        reply.problem(404, "organization.not_found", false, false);
    }
    let mut foreign_problem: serde_json::Value =
        serde_json::from_slice(&foreign.body).expect("problem");
    let mut absent_problem: serde_json::Value =
        serde_json::from_slice(&absent.body).expect("problem");
    foreign_problem.as_object_mut().expect("object").remove("instance");
    absent_problem.as_object_mut().expect("object").remove("instance");
    assert_eq!(foreign_problem, absent_problem);
    let b_team = resource(&create(&f, &b, key, "Independent").await, b.receipt.account_id, 201);
    assert_ne!(b_team.id, first.id);
    assert_eq!(
        page(
            &request(&f, &a, "GET", COLLECTION, &[], &[]).await,
            a.receipt.account_id,
            OrganizationListQuery::default()
        )
        .items
        .len(),
        2
    );
    let current = authenticate_device(&f, a.receipt.device_id, &a.client).await;
    let claims = token_claims(&f, &current).await;
    let mut expected = vec![first.id, second.id];
    expected.sort();
    assert_eq!(claims.org.iter().map(|entry| entry.id).collect::<Vec<_>>(), expected);
    assert!(claims.org.iter().all(|entry| entry.sso_authenticated_at.is_none()));
    session_and_keys(&f, &a.receipt, &current, &a.client).await;
    sync_object(&f, &a.receipt, &current, &a.client).await;
    old_family_refresh(&f, &a, OLD_SCOPE).await;
    old_family_refresh(
        &f,
        &a,
        "account:read keys:read keys:write orgs:create orgs:read sync:read sync:write",
    )
    .await;
    invalid_requests(&f, &a).await;
    mount(&mut f, false).await;
    assert_eq!(
        resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201),
        first
    );
    create(&f, &a, Uuid::now_v7(), "Closed").await.problem(403, "policy.denied", false, false);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 3);
    membership_status(&f, first.membership.id, "suspended").await;
    create(&f, &a, key, "Operations").await.problem(404, "organization.not_found", false, false);
    protected(&f, "GET", &format!("{COLLECTION}/{}", first.id), &[], &current, &a.client)
        .await
        .problem(404, "organization.not_found", false, false);
    assert_eq!(
        page(
            &protected(&f, "GET", COLLECTION, &[], &current, &a.client).await,
            a.receipt.account_id,
            OrganizationListQuery::default()
        )
        .items
        .len(),
        1
    );
    let current = authenticate_device(&f, a.receipt.device_id, &a.client).await;
    assert_eq!(
        token_claims(&f, &current).await.org.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        [second.id]
    );
    let checked = match &f.backend {
        AuthBackend::Sqlite(store) => store.verify_audit_chain(first.id.into_bytes()).await,
        AuthBackend::Postgres(store) => store.verify_audit_chain(first.id.into_bytes()).await,
    };
    assert_ne!(checked.expect("organization audit chain"), [0; 32]);
    f.cleanup().await;
}

async fn invalid_requests(f: &Fixture, a: &LegacyDeviceSession) {
    for (method, path, body, headers, status) in [
        ("POST", COLLECTION, b"{}".as_slice(), vec![("Content-Type", "application/json")], 400),
        ("GET", "/api/v1/orgs?limit=0", b"".as_slice(), vec![], 400),
        ("GET", "/api/v1/orgs?limit=1&limit=2", b"".as_slice(), vec![], 400),
        ("GET", "/api/v1/orgs?filter=all", b"".as_slice(), vec![], 400),
        ("GET", "/api/v1/orgs?cursor=bad", b"".as_slice(), vec![], 400),
        ("GET", "/api/v1/orgs/not-a-uuid", b"".as_slice(), vec![], 400),
        ("GET", COLLECTION, b"{}".as_slice(), vec![], 400),
        ("GET", COLLECTION, b"".as_slice(), vec![("If-Match", "\"x\"")], 400),
    ] {
        request(f, a, method, path, body, &headers).await.problem(
            status,
            "organization.invalid_request",
            false,
            false,
        );
    }
    let id = Uuid::now_v7().to_string();
    for body in [
        b"{\"data\":{\"name\":\"one\",\"name\":\"two\"}}".as_slice(),
        b"{\"data\":{\"name\":\"one\",\"owner\":true}}",
        b"{\"data\":{\"name\":\" trailing \"}}",
        b"{\"data\":{\"name\":\"\"}}",
    ] {
        request(
            f,
            a,
            "POST",
            COLLECTION,
            body,
            &[("Content-Type", "application/json"), ("Idempotency-Key", &id)],
        )
        .await
        .problem(400, "organization.invalid_request", false, false);
    }
    request(
        f,
        a,
        "POST",
        COLLECTION,
        b"{}",
        &[("Content-Type", "text/plain"), ("Idempotency-Key", &id)],
    )
    .await
    .problem(415, "organization.invalid_request", false, false);
    request(
        f,
        a,
        "POST",
        COLLECTION,
        &vec![b' '; 1025],
        &[("Content-Type", "application/json"), ("Idempotency-Key", &id)],
    )
    .await
    .problem(400, "organization.invalid_request", false, false);
    let narrow = account_profile::signed_token(
        f,
        a,
        a.receipt.account_id,
        a.receipt.device_id,
        "account:read",
    )
    .await;
    protected(f, "GET", COLLECTION, &[], &narrow, &a.client).await.problem(
        403,
        "policy.denied",
        false,
        false,
    );
    let proof = account_profile::proof_for(a, "GET", COLLECTION, &a.token);
    let auth = format!("DPoP {}", a.token);
    let headers = [("Authorization", auth.as_str()), ("DPoP", proof.as_str())];
    assert_eq!(http_method(f.address, "GET", COLLECTION, &[], &headers).await.status, 200);
    http_method(f.address, "GET", COLLECTION, &[], &headers).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    http_method(f.address, "GET", COLLECTION, &[], &[]).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    protected(f, "GET", COLLECTION, &[], &a.operator_token, &a.operator_key).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
}

#[tokio::test]
async fn sqlite_team_creation_and_current_membership_http() {
    contract(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_creation_and_current_membership_http() {
    contract(Fixture::postgres().await).await;
}

async fn receipt_retention(mut f: Fixture) {
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let team =
        resource(&create(&f, &a, Uuid::now_v7(), "Operations").await, a.receipt.account_id, 201);
    let sql = "INSERT INTO organization_creation_receipts (account_id,idempotency_key,organization_id,request_digest,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,1,86400001)";
    for _ in 0..101 {
        let key = Uuid::now_v7();
        match &f.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query(sql)
                    .bind(a.receipt.account_id.as_bytes().as_slice())
                    .bind(key.as_bytes().as_slice())
                    .bind(team.id.as_bytes().as_slice())
                    .bind([1_u8; 32].as_slice())
                    .execute(store.pool())
                    .await
                    .expect("owned expired receipt");
            }
            AuthBackend::Postgres(store) => {
                sqlx::query(sql)
                    .bind(a.receipt.account_id.as_bytes().as_slice())
                    .bind(key.as_bytes().as_slice())
                    .bind(team.id.as_bytes().as_slice())
                    .bind([1_u8; 32].as_slice())
                    .execute(store.pool())
                    .await
                    .expect("owned expired receipt");
            }
        }
    }
    for expected in [100, 1, 0] {
        let removed = match &f.backend {
            AuthBackend::Sqlite(store) => {
                crate::runtime::WorkerStoreBackend::cleanup_organization_creation_receipts(
                    store.as_ref(),
                )
                .await
            }
            AuthBackend::Postgres(store) => {
                crate::runtime::WorkerStoreBackend::cleanup_organization_creation_receipts(
                    store.as_ref(),
                )
                .await
            }
        }
        .expect("bounded worker receipt cleanup");
        assert_eq!(removed, expected);
    }
    for table in [
        "organizations",
        "organization_memberships",
        "organization_creation_receipts",
        "audit_events",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 1);
    }
    let read = request(&f, &a, "GET", &format!("{COLLECTION}/{}", team.id), &[], &[]).await;
    assert_eq!(resource(&read, a.receipt.account_id, 200), team);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_team_receipt_retention_is_bounded_and_preserves_live_team_state() {
    receipt_retention(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_receipt_retention_is_bounded_and_preserves_live_team_state() {
    receipt_retention(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_team_creation_rolls_back_audit_failure_and_confirms_original_unknown_operation() {
    let mut f = Fixture::sqlite().await;
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let key = Uuid::now_v7();
    f.execute("CREATE TRIGGER organization_audit_failure BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'owned audit failure'); END;").await;
    create(&f, &a, key, "Operations").await.problem(
        503,
        "organization.storage_unavailable",
        false,
        true,
    );
    for table in [
        "organizations",
        "organization_memberships",
        "organization_creation_receipts",
        "audit_events",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 0);
    }
    f.execute("DROP TRIGGER organization_audit_failure;").await;
    resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201);
    f.execute("CREATE TABLE organization_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE organization_commit_child (id INTEGER REFERENCES organization_commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER organization_commit_failure AFTER INSERT ON organization_creation_receipts BEGIN INSERT INTO organization_commit_child VALUES(1); END;").await;
    let uncertain = Uuid::now_v7();
    create(&f, &a, uncertain, "Network").await.problem(
        503,
        "organization.commit_outcome_unknown",
        true,
        true,
    );
    for table in [
        "organizations",
        "organization_memberships",
        "organization_creation_receipts",
        "audit_events",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 1);
    }
    f.execute("DROP TRIGGER organization_commit_failure;").await;
    let confirmed =
        resource(&create(&f, &a, uncertain, "Network").await, a.receipt.account_id, 201);
    assert_eq!(
        resource(&create(&f, &a, uncertain, "Network").await, a.receipt.account_id, 201),
        confirmed
    );
    for table in [
        "organizations",
        "organization_memberships",
        "organization_creation_receipts",
        "audit_events",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 2);
    }
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_creation_rolls_back_audit_failure() {
    let mut f = Fixture::postgres().await;
    let a = legacy_device_session(&mut f).await;
    mount(&mut f, true).await;
    let key = Uuid::now_v7();
    f.execute("CREATE FUNCTION organization_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned audit failure'; END $$; CREATE TRIGGER organization_audit_failure BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION organization_audit_failure();").await;
    create(&f, &a, key, "Operations").await.problem(
        503,
        "organization.storage_unavailable",
        false,
        true,
    );
    for table in [
        "organizations",
        "organization_memberships",
        "organization_creation_receipts",
        "audit_events",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 0);
    }
    f.execute("DROP TRIGGER organization_audit_failure ON audit_events; DROP FUNCTION organization_audit_failure();").await;
    resource(&create(&f, &a, key, "Operations").await, a.receipt.account_id, 201);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, 1);
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_team_creation_lost_commit_ack_confirms_one_team_with_the_same_key() {
    use std::sync::atomic::Ordering;
    let mut f = Fixture::postgres().await;
    let a = legacy_device_session(&mut f).await;
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("dedicated PG URL");
    let (_, schema) = f.postgres.as_ref().expect("owned schema");
    let application = format!("team_commit_{}", Uuid::new_v4().simple());
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
    mount(&mut f, true).await;
    let mut held = original.pool().begin().await.expect("hold Account transaction");
    sqlx::query("SELECT account_id FROM identity_accounts WHERE account_id=$1 FOR UPDATE")
        .bind(a.receipt.account_id.as_bytes().as_slice())
        .fetch_one(&mut *held)
        .await
        .expect("hold business row");
    let create_key = Uuid::now_v7();
    let body = scoplen_api::organization::OrganizationCreateRequest::new("Operations")
        .expect("name")
        .to_json()
        .expect("body");
    let proof = account_profile::proof_for(&a, "POST", COLLECTION, &a.token);
    let authorization = format!("DPoP {}", a.token);
    let address = f.address;
    let idempotency = create_key.to_string();
    let pending = tokio::spawn(async move {
        http_method(
            address,
            "POST",
            COLLECTION,
            &body,
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &authorization),
                ("DPoP", proof.as_str()),
                ("Idempotency-Key", &idempotency),
            ],
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT account_id FROM identity_accounts%FOR UPDATE%')")
                .bind(&application).fetch_one(original.pool()).await.expect("observe create business lock");
            if waiting {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("business transaction waits after auth/replay commits");
    proxy.armed.store(true, Ordering::SeqCst);
    held.commit().await.expect("release business row");
    let reply = pending.await.expect("creation task");
    reply.problem(503, "organization.commit_outcome_unknown", true, true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let confirmed =
        resource(&create(&f, &a, create_key, "Operations").await, a.receipt.account_id, 201);
    assert_eq!(confirmed.name, "Operations");
    for table in [
        "organizations",
        "organization_memberships",
        "organization_creation_receipts",
        "audit_events",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")).await, 1);
    }
    original.pool().close().await;
    f.cleanup().await;
    drop(proxy);
}
