// SPDX-License-Identifier: AGPL-3.0-only
//! D-169 activation initiation across the mounted HTTPS and independent OIDC boundaries.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::{
    account_browser::INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
    auth_connection::{
        Activation, ActivationCandidate, ActivationContext, ActivationStarted, ConnectionStatus,
        ConnectionTarget, ExpectedRevision,
    },
    auth_connection_draft::{DraftCreate, DraftResource, test_login::DraftLoginStatus},
};
use time::format_description::well_known::{Rfc2822, Rfc3339};

use super::{
    super::tls::TlsFixture,
    auth_connection::{connection, seed_active_connection, send},
    auth_draft::{create_headers, resource},
    *,
};
use crate::oidc::provider_test::Provider;

mod callback;

async fn save_draft(tls: &TlsFixture, browser: &Browser, org: Uuid, issuer: &str) -> DraftResource {
    let path = format!("/api/v1/orgs/{org}/auth-connection-draft");
    let body = DraftCreate { issuer: issuer.into() }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    resource(&send(tls, browser, "POST", &path, &create_headers(&key), &body).await, 201, org)
}

fn candidate(draft: Uuid) -> SecretVec {
    ActivationCandidate {
        draft_generation: draft,
        space_id: "spc_Review".into(),
        credentials: Provider::login_material().credentials,
    }
    .to_json()
    .unwrap()
}

fn start_headers<'a>(condition: (&'a str, &'a str)) -> [(&'a str, &'a str); 3] {
    [("Origin", ORIGIN), ("Content-Type", "application/json"), condition]
}

fn started(
    reply: &Reply,
    draft: &DraftResource,
    expected_revision: ExpectedRevision,
) -> ActivationStarted {
    assert_eq!(reply.status, 201);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.header("access-control-allow-origin").is_none());
    assert!(reply.header("access-control-allow-credentials").is_none());
    assert!(reply.header("location").is_none());
    Uuid::parse_str(reply.header("x-request-id").unwrap()).unwrap();
    let credentials = Provider::login_material().credentials;
    let secret = std::str::from_utf8(credentials.client_secret.as_bytes()).unwrap();
    assert!(!std::str::from_utf8(&reply.body).unwrap().contains(secret));
    ActivationStarted::from_http_json(
        &reply.body,
        &ActivationContext {
            organization_id: draft.organization_id,
            draft_generation: draft.id,
            expected_revision,
            target: ConnectionTarget {
                issuer: draft.issuer.clone(),
                client_id: std::str::from_utf8(credentials.client_id.as_bytes()).unwrap().into(),
                space_id: "spc_Review".into(),
            },
        },
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap()
}

#[allow(
    clippy::manual_assert_eq,
    reason = "keep navigation and per-attempt binding out of diagnostics"
)]
async fn verify_navigation(provider: &Provider, reply: &Reply, start: &ActivationStarted) {
    let navigation = std::str::from_utf8(start.authorization_url.as_bytes()).unwrap();
    let url = url::Url::parse(navigation).unwrap();
    assert!(navigation.split_once('?').unwrap().0 == provider.metadata().authorization_endpoint);
    assert!(url.fragment().is_none());
    assert_eq!(url.query_pairs().count(), 8);
    let params: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
    let state = URL_SAFE_NO_PAD.decode(params["state"].as_bytes()).unwrap();
    let nonce = URL_SAFE_NO_PAD.decode(params["nonce"].as_bytes()).unwrap();
    let challenge = URL_SAFE_NO_PAD.decode(params["code_challenge"].as_bytes()).unwrap();
    assert_eq!((state.len(), nonce.len(), challenge.len()), (32, 32, 32));
    assert!(state != nonce && nonce != challenge && state != challenge);
    let cookies = reply
        .headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .count();
    assert_eq!(cookies, 1);
    let cookie = reply.header("set-cookie").unwrap();
    let (pair, expires) =
        cookie.split_once("; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=").unwrap();
    let (name, value) = pair.split_once('=').unwrap();
    assert!(name == format!("__Host-spl-auth-activate-{:x}", Sha256::digest(&state)));
    let binding = URL_SAFE_NO_PAD.decode(value.as_bytes()).unwrap();
    assert_eq!(binding.len(), 32);
    assert!(binding != state && binding != nonce && binding != challenge);
    let cookie_expiry = time::OffsetDateTime::parse(expires, &Rfc2822).unwrap();
    let expiry = time::OffsetDateTime::parse(&start.attempt.expires_at, &Rfc3339).unwrap();
    assert!(cookie_expiry > time::OffsetDateTime::now_utc() && cookie_expiry <= expiry);

    // The independent provider checks the exact client, callback, scope, response type and S256.
    let callback = provider.navigate(navigation).await;
    assert!(
        callback.query_pairs().any(|(name, value)| name == "state" && value == params["state"])
    );
}

fn assert_pending(reply: &Reply, original: &Activation) {
    assert_eq!(reply.status, 200);
    reply.private();
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let value = Activation::from_http_json(
        &reply.body,
        original,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap();
    assert_eq!(value.status, DraftLoginStatus::Pending);
    let json: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert!(json.get("authorization_url").is_none());
    assert_eq!(json.as_object().unwrap().len(), 9);
}

async fn lifecycle(f: &Fixture) {
    let provider = Provider::start(f.directory.join("activation-issuer"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-lifecycle").await;
    let org = create_team(f, &owner).await.id;
    let other_org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let foreign = login(f, &owner.registration).await;
    let draft = save_draft(&tls, &browser, org, &provider.issuer).await;
    let other = save_draft(&tls, &browser, other_org, &provider.issuer).await;
    let head = seed_active_connection(f, org, &provider.issuer).await;
    let root = format!("/api/v1/orgs/{org}/auth-connection");
    let path = format!("{root}/activations");
    let other_path = format!("/api/v1/orgs/{other_org}/auth-connection/activations");
    let original = connection(
        &send(&tls, &browser, "GET", &root, &[], &[]).await,
        org,
        ConnectionStatus::Active,
    );
    assert_eq!(original.id, head);
    let revision = f.revision(org).await;
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    let tag = original.etag();
    let headers = start_headers(("If-Match", &tag));
    let empty = start_headers(("If-None-Match", "*"));
    let reply = send(&tls, &browser, "POST", &path, &headers, candidate(draft.id).as_bytes()).await;
    let start = started(&reply, &draft, ExpectedRevision::Current(head));
    assert_eq!(provider.discoveries(), 1);
    verify_navigation(&provider, &reply, &start).await;
    let pending = "SELECT count(*) FROM organization_auth_connection_activations WHERE phase='pending' AND credential IS NOT NULL AND verifier IS NOT NULL";
    assert_eq!(f.count(pending).await, 1);
    let status = format!("{path}/{}", start.attempt.id);
    assert_pending(&send(&tls, &browser, "GET", &status, &[], &[]).await, &start.attempt);
    for method in ["GET", "DELETE"] {
        send(&tls, &foreign, method, &status, &[("Origin", ORIGIN)], &[]).await.problem(
            404,
            "organization.not_found",
            false,
        );
    }
    send(&tls, &browser, "POST", &other_path, &empty, candidate(other.id).as_bytes())
        .await
        .problem(409, "organization.conflict", false);
    assert_eq!(provider.discoveries(), 1);
    assert_eq!(provider.counts(), [0, 0, 0]);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);
    let abandoned = send(&tls, &browser, "DELETE", &status, &[("Origin", ORIGIN)], &[]).await;
    assert_eq!(abandoned.status, 204);
    abandoned.private();
    assert!(abandoned.body.is_empty() && abandoned.header("etag").is_none());
    assert_eq!(f.count(pending).await, 0);
    send(&tls, &browser, "GET", &status, &[], &[]).await.problem(
        404,
        "organization.not_found",
        false,
    );
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 2);
    assert_eq!(
        connection(
            &send(&tls, &browser, "GET", &root, &[], &[]).await,
            org,
            ConnectionStatus::Active
        ),
        original
    );
    assert_eq!(f.revision(org).await, revision);
    assert_eq!(current_team(f, &owner, org).await.id, org);
    let next =
        send(&tls, &browser, "POST", &other_path, &empty, candidate(other.id).as_bytes()).await;
    let next = started(&next, &other, ExpectedRevision::Empty);
    assert_ne!(start.attempt.id, next.attempt.id);
    assert_eq!(provider.discoveries(), 2);
    provider.close().await;
}

browser_tests!(
    sqlite_auth_activation_https_lifecycle_and_family_isolation,
    postgres_auth_activation_https_lifecycle_and_family_isolation,
    lifecycle
);

async fn freshness(f: &Fixture) {
    let provider = Provider::start(f.directory.join("activation-freshness"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-freshness").await;
    let org = create_team(f, &owner).await.id;
    let mut browser = login(f, &owner.registration).await;
    let draft = save_draft(&tls, &browser, org, &provider.issuer).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection/activations");
    let body = candidate(draft.id);
    let headers = start_headers(("If-None-Match", "*"));
    let family = scope::current_session(f, &browser).await.unwrap().family_id;
    let ceiling = INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
        .split(' ')
        .filter(|scope| *scope != "auth-connection:manage")
        .collect::<Vec<_>>()
        .join(" ");
    scope::set_scope(f, family, &ceiling).await;
    for stale in [false, true] {
        if stale {
            browser = login(f, &owner.registration).await;
            // Shift both endpoints of the original password family lifetime, preserving its length.
            f.execute("UPDATE account_browser_families SET created_at_ms=created_at_ms-360000,expires_at_ms=expires_at_ms-360000").await;
        }
        for rotate in [false, true] {
            if rotate {
                let reply =
                    request(f, &browser.key, REFRESH, b"{}", None, Some(&browser.cookie)).await;
                (browser.access, browser.cookie) = session(&reply, false);
            }
            send(&tls, &browser, "POST", &path, &headers, body.as_bytes()).await.problem(
                403,
                "policy.denied",
                false,
            );
        }
    }
    assert_eq!(provider.discoveries(), 0);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations").await, 0);
    let fresh = login(f, &owner.registration).await;
    // The validity ceiling is the original sign-in window, even when the commit occurs later.
    f.execute("UPDATE account_browser_families SET created_at_ms=created_at_ms-60000,expires_at_ms=expires_at_ms-60000").await;
    let reply = send(&tls, &fresh, "POST", &path, &headers, body.as_bytes()).await;
    started(&reply, &draft, ExpectedRevision::Empty);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_activations a JOIN account_browser_families f ON f.family_id=a.family_id WHERE a.expires_at_ms<=f.created_at_ms+300000 AND a.expires_at_ms>a.created_at_ms").await, 1);
    assert_eq!(provider.discoveries(), 1);
    provider.close().await;
}

browser_tests!(
    sqlite_auth_activation_https_scope_and_original_password_after_refresh,
    postgres_auth_activation_https_scope_and_original_password_after_refresh,
    freshness
);

async fn preflight(f: &Fixture) {
    use scoplen_api::auth_connection_draft::test_login::{DraftLoginAttempt, DraftLoginStarted};

    let provider = Provider::start(f.directory.join("activation-preflight"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(f, provider.settings.clone()).await;
    let owner = actor(f, "activation-preflight").await;
    let org = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    let draft = save_draft(&tls, &browser, org, &provider.issuer).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection/activations");
    let body = candidate(draft.id);
    let headers = start_headers(("If-None-Match", "*"));
    let mut device =
        TlsFixture::signed(&owner.registration.device, &owner.token.access_token, "POST", &path);
    for (name, value) in &headers {
        device = device.header(*name, *value);
    }
    tls.send(device.body(axum::body::Body::from(body.as_bytes().to_vec())).unwrap()).await.problem(
        401,
        "auth.authentication_required",
        false,
    );
    send(&tls, &browser, "POST", &path, &headers[1..], body.as_bytes()).await.problem(
        403,
        "policy.denied",
        false,
    );
    send(&tls, &browser, "POST", &path, &headers[..2], body.as_bytes()).await.problem(
        428,
        "organization.precondition_required",
        false,
    );
    let wrong = format!("\"{}\"", Uuid::now_v7());
    send(&tls, &browser, "POST", &path, &start_headers(("If-Match", &wrong)), body.as_bytes())
        .await
        .problem(412, "organization.precondition_failed", false);
    send(&tls, &browser, "POST", &path, &headers, candidate(Uuid::now_v7()).as_bytes())
        .await
        .problem(412, "organization.precondition_failed", false);
    assert_eq!(provider.discoveries(), 0);

    let diagnostic = format!("/api/v1/orgs/{org}/auth-connection-draft/test-login");
    let credentials = Provider::login_material().credentials.to_json().unwrap();
    let tag = draft.etag();
    let test = send(
        &tls,
        &browser,
        "POST",
        &diagnostic,
        &start_headers(("If-Match", &tag)),
        credentials.as_bytes(),
    )
    .await;
    assert_eq!(test.status, 201);
    let diagnostic_cookie = test.header("set-cookie").unwrap().split(';').next().unwrap();
    assert!(diagnostic_cookie.starts_with("__Host-spl-auth-test="));
    let test_start = DraftLoginStarted::from_http_json(
        &test.body,
        (org, draft.id),
        &draft.issuer,
        test.header("cache-control"),
        test.header("pragma"),
    )
    .unwrap();
    let reply = send(&tls, &browser, "POST", &path, &headers, body.as_bytes()).await;
    let activation = started(&reply, &draft, ExpectedRevision::Empty);
    assert!(reply.header("set-cookie").unwrap().starts_with("__Host-spl-auth-activate-"));
    assert_eq!(provider.discoveries(), 2);
    let status = format!("{path}/{}", activation.attempt.id);
    send(&tls, &browser, "GET", &format!("{path}/{}", test_start.attempt.id), &[], &[])
        .await
        .problem(404, "organization.not_found", false);
    send(&tls, &browser, "GET", &status, &[("Origin", "https://foreign.example")], &[])
        .await
        .problem(403, "policy.denied", false);
    let abandoned = send(&tls, &browser, "DELETE", &status, &[("Origin", ORIGIN)], &[]).await;
    assert_eq!(abandoned.status, 204);
    abandoned.private();
    let result =
        send(&tls, &browser, "GET", &format!("{diagnostic}/{}", test_start.attempt.id), &[], &[])
            .await;
    result.private();
    assert_eq!(result.status, 200);
    let attempt = DraftLoginAttempt::from_http_json(
        &result.body,
        (org, draft.id, test_start.attempt.id),
        result.header("cache-control"),
        result.header("pragma"),
    )
    .unwrap();
    assert_eq!(attempt.status, DraftLoginStatus::Pending);
    assert_eq!(provider.counts(), [0, 0, 0]);
    provider.close().await;
}

browser_tests!(
    sqlite_auth_activation_https_preconditions_and_diagnostic_isolation,
    postgres_auth_activation_https_preconditions_and_diagnostic_isolation,
    preflight
);

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_auth_activation_https_lost_start_commit_withholds_navigation() {
    use std::sync::atomic::Ordering;
    let (store, admin, schema, mut database) =
        crate::account_entry::tests::postgres_fixture().await;
    let application = format!("activation_commit_{}", Uuid::new_v4().simple());
    database.query_pairs_mut().append_pair("application_name", &application);
    let proxy = crate::test_lost_commit::LostCommitProxy::start(database.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let f = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let provider = Provider::start(f.directory.join("activation-lost-start"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(&f, provider.settings.clone()).await;
    let owner = actor(&f, "activation-lost-start").await;
    let org = create_team(&f, &owner).await.id;
    let browser = login(&f, &owner.registration).await;
    let draft = save_draft(&tls, &browser, org, &provider.issuer).await;
    let path = format!("/api/v1/orgs/{org}/auth-connection/activations");
    let body = candidate(draft.id);
    let headers = start_headers(("If-None-Match", "*"));
    let audit = f.count("SELECT count(*) FROM audit_events").await;

    // Only the final candidate INSERT waits on the fixture table. Discovery and admission
    // transactions finish before the proxy is armed for the business COMMIT acknowledgement.
    f.execute("CREATE TABLE activation_commit_gate(id INTEGER); CREATE FUNCTION hold_activation_start() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM id FROM activation_commit_gate; RETURN NEW; END $$; CREATE TRIGGER hold_activation_start BEFORE INSERT ON organization_auth_connection_activations FOR EACH ROW EXECUTE FUNCTION hold_activation_start();").await;
    let mut lock = store.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE activation_commit_gate IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let holder: i32 =
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *lock).await.unwrap();
    let release = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND $2=ANY(pg_blocking_pids(pid)))")
                    .bind(&application).bind(holder).fetch_one(store.pool()).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("activation reached its business transaction after discovery");
        proxy.armed.store(true, Ordering::SeqCst);
        lock.commit().await.unwrap();
    };
    let (unknown, ()) =
        tokio::join!(send(&tls, &browser, "POST", &path, &headers, body.as_bytes()), release);
    changed_problem(&unknown, 503, "organization.commit_outcome_unknown", false);
    let problem = std::str::from_utf8(&unknown.body).unwrap();
    assert!(!problem.contains(&provider.issuer) && !problem.contains("authorization_url"));
    assert!(unknown.header("location").is_none());
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.count(
            "SELECT count(*) FROM organization_auth_connection_activations WHERE phase='pending'"
        )
        .await,
        1
    );
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);
    send(&tls, &browser, "POST", &path, &headers, body.as_bytes()).await.problem(
        409,
        "organization.conflict",
        false,
    );
    assert_eq!(provider.discoveries(), 1);
    assert_eq!(provider.counts(), [0, 0, 0]);
    provider.close().await;
    drop(tls);
    f.close().await;
    store.pool().close().await;
    drop(proxy);
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
