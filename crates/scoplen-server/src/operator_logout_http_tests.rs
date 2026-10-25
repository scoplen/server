// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use personal_flow::notifications::Listener;
use scoplen_api::operator_auth::OperatorLogoutResponse;
use std::fmt::Write as _;

const LOGOUT: &str = "/api/v1/auth/operator/logout";

fn protected_proof(client: &P256SigningKey, token: &str, path: &str) -> String {
    DpopProof::sign(
        client,
        &client.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, path).expect("exact target"),
        DpopToken::Protected(token),
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs(),
        None,
    )
    .expect("protected proof")
    .as_str()
    .to_owned()
}

async fn send(
    f: &Fixture,
    token: &str,
    signed: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Reply {
    let authorization = format!("DPoP {token}");
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Origin", ORIGIN),
        ("Authorization", authorization.as_str()),
        ("DPoP", signed),
    ];
    headers.extend_from_slice(extra);
    http(f.address, LOGOUT, body, &headers).await
}

fn confirmed(reply: &Reply) {
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(reply.body, b"{\"revoked\":true}");
    assert_eq!(OperatorLogoutResponse::from_json(&reply.body), Ok(OperatorLogoutResponse));
    reply.privacy();
    assert_eq!(reply.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(reply.header("access-control-allow-credentials"), None);
}

async fn lifecycle(f: Fixture) {
    let a_key = key(1);
    let b_key = key(2);
    let (mut auth, _) = f.enroll(&a_key).await;
    let a = f.login(&mut auth, &a_key).await;
    let b = f.login(&mut auth, &b_key).await;
    let token = a.session();
    let other = b.session();
    let keys = f.trusted_operator_keys().await;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs();
    let verified =
        OperatorAccessToken::parse(&token.access_token).unwrap().verify(&keys, now).unwrap();
    let other_verified =
        OperatorAccessToken::parse(&other.access_token).unwrap().verify(&keys, now).unwrap();
    let digests = f.count("SELECT COUNT(*) FROM operator_refresh_tokens").await;
    let signed = protected_proof(&a_key, &token.access_token, LOGOUT);
    let body = [vec![b' '; 254], b"{}".to_vec()].concat();
    // B has replaced A's shared cookie. Neither that credential nor malformed incidental cookies matter.
    let reply = send(
        &f,
        &token.access_token,
        &signed,
        &body,
        &[("Cookie", &b.cookie()), ("Cookie", "broken; __Secure-spl-refresh=,invalid")],
    )
    .await;
    confirmed(&reply);
    assert!(!f.current(&verified).await);
    assert!(f.current(&other_verified).await);
    assert_eq!(f.count("SELECT COUNT(*) FROM operator_refresh_tokens").await, digests);
    send(&f, &token.access_token, &signed, b"{}", &[]).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    f.reset_admission().await;
    let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    confirmed(
        &send(
            &f,
            &token.access_token,
            &protected_proof(&a_key, &token.access_token, LOGOUT),
            b"{}",
            &[],
        )
        .await,
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM deployment_audit_events").await,
        audits,
        "terminal confirmation emits no second revocation audit"
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM operator_refresh_tokens").await, digests);
    f.refresh(&b.cookie(), &b_key).await.session();
    f.refresh(&a.cookie(), &a_key).await.problem(401, "auth.authentication_required", false, false);
    assert!(!f.current(&verified).await);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        1
    );
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_logout_exact_confirmation_replay_and_shared_cookie_isolation() {
    lifecycle(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_exact_confirmation_replay_and_shared_cookie_isolation() {
    lifecycle(Fixture::postgres().await).await;
}

async fn tls_send(listener: &Listener, token: &str, signed: &str, cookie: &str) -> Reply {
    let tls = listener.tls(b"http/1.1").await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("verified HTTPS handshake");
    let connection = tokio::spawn(connection);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(LOGOUT)
        .header("Host", "setup.example.com:9443")
        .header("Content-Type", "application/json")
        .header("Origin", ORIGIN)
        .header("Authorization", format!("DPoP {token}"))
        .header("DPoP", signed)
        .header("Cookie", cookie)
        .body(Body::from("{}"))
        .expect("logout HTTPS request");
    let response = sender.send_request(request).await.expect("HTTPS logout response");
    let status = response.status().as_u16();
    let mut headers = String::new();
    for (name, value) in response.headers() {
        writeln!(headers, "{name}: {}", value.to_str().expect("HTTP header")).expect("header text");
    }
    let body = response.into_body().collect().await.expect("logout body").to_bytes().to_vec();
    drop(sender);
    connection.abort();
    let _ = connection.await;
    Reply { status, headers, body }
}

async fn tls_lifecycle(mut f: Fixture) {
    let a_key = key(1);
    let b_key = key(2);
    let (mut authenticator, _) = f.enroll(&a_key).await;
    let a = f.login(&mut authenticator, &a_key).await;
    let b = f.login(&mut authenticator, &b_key).await;
    let token = a.session().access_token;
    let listener = Listener::start(&mut f).await;
    let digests = f.count("SELECT COUNT(*) FROM operator_refresh_tokens").await;
    let signed = protected_proof(&a_key, &token, LOGOUT);
    confirmed(&tls_send(&listener, &token, &signed, &b.cookie()).await);
    let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    tls_send(&listener, &token, &signed, &b.cookie()).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    f.reset_admission().await;
    let after_denial = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    assert!(after_denial > audits);
    confirmed(
        &tls_send(&listener, &token, &protected_proof(&a_key, &token, LOGOUT), &b.cookie()).await,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, after_denial);
    assert_eq!(f.count("SELECT COUNT(*) FROM operator_refresh_tokens").await, digests);
    f.refresh(&b.cookie(), &b_key).await.session();
    f.refresh(&a.cookie(), &a_key).await.problem(401, "auth.authentication_required", false, false);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        1
    );
    drop(listener);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_logout_verified_https_preserves_other_browser_family() {
    tls_lifecycle(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_verified_https_preserves_other_browser_family() {
    tls_lifecycle(Fixture::postgres().await).await;
}

#[allow(clippy::too_many_lines)]
async fn request_guards(f: Fixture) {
    let client = key(1);
    let (mut auth, _) = f.enroll(&client).await;
    let token = f.login(&mut auth, &client).await.session().access_token;
    let authorization = format!("DPoP {token}");
    let oversized_authorization = format!("DPoP {}", "x".repeat(4_097));
    for authorization in [None, Some("Bearer invalid"), Some(oversized_authorization.as_str())] {
        let signed = protected_proof(&client, &token, LOGOUT);
        let mut headers = vec![
            ("Origin", ORIGIN),
            ("Content-Type", "application/json"),
            ("DPoP", signed.as_str()),
        ];
        if let Some(authorization) = authorization {
            headers.push(("Authorization", authorization));
        }
        http(f.address, LOGOUT, b"{}", &headers).await.problem(
            401,
            "auth.authentication_required",
            false,
            false,
        );
        f.reset_admission().await;
    }
    for origin in
        [None, Some("null"), Some("https://other.example"), Some("https://setup.example.com")]
    {
        let signed = protected_proof(&client, &token, LOGOUT);
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Authorization", authorization.as_str()),
            ("DPoP", signed.as_str()),
        ];
        if let Some(origin) = origin {
            headers.push(("Origin", origin));
        }
        http(f.address, LOGOUT, b"{}", &headers).await.problem(403, "policy.denied", false, false);
        f.reset_admission().await;
    }
    for (name, value, status, code) in [
        ("Origin", ORIGIN, 403, "policy.denied"),
        ("Authorization", authorization.as_str(), 401, "auth.authentication_required"),
        ("DPoP", "malformed", 400, "auth.invalid_dpop_proof"),
        ("Content-Type", "application/json", 415, "auth.invalid_request"),
        ("Idempotency-Key", "prohibited", 400, "auth.invalid_request"),
    ] {
        send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[(name, value)])
            .await
            .problem(status, code, false, false);
        f.reset_admission().await;
    }
    for media in [
        None,
        Some("text/plain"),
        Some("application/json; charset=iso-8859-1"),
        Some("application/json; charset=utf-8; charset=utf-8"),
    ] {
        let signed = protected_proof(&client, &token, LOGOUT);
        let mut headers = vec![
            ("Origin", ORIGIN),
            ("Authorization", authorization.as_str()),
            ("DPoP", signed.as_str()),
        ];
        if let Some(media) = media {
            headers.push(("Content-Type", media));
        }
        http(f.address, LOGOUT, b"{}", &headers).await.problem(
            415,
            "auth.invalid_request",
            false,
            false,
        );
        f.reset_admission().await;
    }
    for body in [b"null".as_slice(), b"[]", b"{\"sid\":null}", b"{}{}", b"{\"x\":\"\xff\"}"] {
        send(&f, &token, &protected_proof(&client, &token, LOGOUT), body, &[]).await.problem(
            400,
            "auth.invalid_request",
            false,
            false,
        );
        f.reset_admission().await;
    }
    send(&f, &token, &protected_proof(&client, &token, LOGOUT), &[b' '; 257], &[]).await.problem(
        413,
        "auth.invalid_request",
        false,
        false,
    );
    f.reset_admission().await;
    for (signed, reason) in [
        (proof(&client, LOGOUT), "missing ath"),
        (protected_proof(&key(2), &token, LOGOUT), "wrong proof key"),
        (protected_proof(&client, &token, LOGIN_FINISH_PATH), "wrong exact URL"),
        (protected_proof(&client, "different-token", LOGOUT), "wrong ath"),
        (
            DpopProof::sign(
                &client,
                &client.public_key_sec1(),
                &DpopTarget::new("GET", ORIGIN, LOGOUT).unwrap(),
                DpopToken::Protected(&token),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                None,
            )
            .unwrap()
            .as_str()
            .to_owned(),
            "wrong method",
        ),
        ("x".repeat(8_193), "oversized proof"),
    ] {
        let reply = send(&f, &token, &signed, b"{}", &[]).await;
        assert_eq!(reply.status, 400, "{reason}: {}", reply.text());
        reply.problem(400, "auth.invalid_dpop_proof", false, false);
        f.reset_admission().await;
    }
    let query = http(
        f.address,
        "/api/v1/auth/operator/logout?sid=other",
        b"{}",
        &[("Origin", ORIGIN), ("Content-Type", "application/json")],
    )
    .await;
    query.problem(400, "auth.invalid_request", false, false);
    f.reset_admission().await;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let trusted = f.trusted_operator_keys().await;
    let verified = OperatorAccessToken::parse(&token).unwrap().verify(&trusted, now).unwrap();
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).unwrap();
    let keyring = f.backend.operator_keyring(&kms).await.unwrap();
    let mut expired = verified.claims().clone();
    expired.exp = now - 1;
    expired.iat = expired.exp - 600;
    let mut unknown_family = verified.claims().clone();
    unknown_family.sid = Uuid::now_v7();
    for claims in [expired, unknown_family] {
        let token = OperatorAccessToken::sign(
            keyring.signing_key(),
            &trusted,
            keyring.signing_key().kid(),
            &claims,
        )
        .unwrap();
        send(&f, token.as_str(), &protected_proof(&client, token.as_str(), LOGOUT), b"{}", &[])
            .await
            .problem(401, "auth.authentication_required", false, false);
        f.reset_admission().await;
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        0
    );
    confirmed(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    f.cleanup().await;
}

async fn complete_api_profile(f: &mut Fixture) {
    personal_flow::mount_complete_api(f).await;
    let browser = key(1);
    let (mut authenticator, _) = f.enroll(&browser).await;
    let token = f.login(&mut authenticator, &browser).await.session().access_token;
    let device_key = key(2);
    let receipt = personal_flow::seed_legacy_device(f, &device_key).await;
    let device_token = personal_flow::authenticate_device(f, receipt.device_id, &device_key).await;
    send(f, &device_token, &protected_proof(&device_key, &device_token, LOGOUT), b"{}", &[])
        .await
        .problem(403, "policy.denied", false, false);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        0
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_auth_admission WHERE endpoint=6 AND kind=4").await,
        0,
        "a Device profile cannot select an Operator bucket"
    );
    f.reset_admission().await;
    confirmed(&send(f, &token, &protected_proof(&browser, &token, LOGOUT), b"{}", &[]).await);
    assert_eq!(f.count("SELECT COUNT(*) FROM identity_devices WHERE active=true").await, 1);
    let challenge =
        scoplen_api::auth::AuthChallengeRequest::new(receipt.device_id).unwrap().to_json().unwrap();
    assert_eq!(
        http(
            f.address,
            "/api/v1/auth/challenge",
            challenge.as_bytes(),
            &[("Content-Type", "application/json")]
        )
        .await
        .status,
        200
    );
}

#[tokio::test]
async fn sqlite_logout_public_api_rejects_device_profile_and_preserves_existing_device() {
    let mut f = Fixture::sqlite().await;
    complete_api_profile(&mut f).await;
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_public_api_rejects_device_profile_and_preserves_existing_device() {
    let mut f = Fixture::postgres().await;
    complete_api_profile(&mut f).await;
    f.cleanup().await;
}

fn limited(reply: &Reply) {
    reply.problem(429, "auth.rate_limited", false, true);
    let delay = reply.header("retry-after").unwrap();
    assert!((1..=300).contains(&delay.parse::<u16>().unwrap()));
    assert_eq!(
        reply.header("ratelimit"),
        Some(format!("\"authentication\";r=0;t={delay}").as_str())
    );
    assert_eq!(reply.header("ratelimit-policy"), Some("\"authentication\";q=30;w=60"));
}

async fn quotas(f: Fixture) {
    let client = key(1);
    let (mut auth, _) = f.enroll(&client).await;
    let token = f.login(&mut auth, &client).await.session().access_token;
    f.reset_admission().await;
    http(f.address, LOGOUT, b"invalid", &[]).await.problem(403, "policy.denied", false, false);
    f.exhaust_admission(1, 30).await;
    let mut stream = tokio::net::TcpStream::connect(f.address).await.unwrap();
    // Do not send the promised body: admission must reply before reading it.
    stream.write_all(b"POST /api/v1/auth/operator/logout HTTP/1.1\r\nHost: setup.example.com:9443\r\nConnection: close\r\nContent-Length: 256\r\n\r\n").await.unwrap();
    let mut response = vec![0; 8192];
    let length =
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut response))
            .await
            .expect("source admission must not await body")
            .unwrap();
    assert!(response[..length].starts_with(b"HTTP/1.1 429"));
    drop(stream);
    limited(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_auth_admission WHERE endpoint=6 AND kind=4").await,
        0
    );
    let login = f.post(LOGIN_OPTIONS_PATH, b"{}", &client).await;
    assert_eq!(login.status, 200, "logout source admission is independent: {}", login.text());
    f.reset_admission().await;
    confirmed(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    f.exhaust_admission(4, 10).await;
    limited(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    assert_eq!(
        f.count("SELECT attempts FROM operator_auth_admission WHERE endpoint=6 AND kind=4").await,
        10
    );
    f.execute("DELETE FROM operator_auth_admission WHERE kind=1").await;
    send(&f, "invalid", &protected_proof(&client, "invalid", LOGOUT), b"{}", &[]).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    assert_eq!(
        f.count("SELECT attempts FROM operator_auth_admission WHERE endpoint=6 AND kind=4").await,
        10,
        "unverified identity cannot charge a private bucket"
    );
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_logout_source_before_body_and_private_quota_headers() {
    quotas(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_source_before_body_and_private_quota_headers() {
    quotas(Fixture::postgres().await).await;
}

async fn discarded_response(f: Fixture) {
    let client = key(1);
    let (mut auth, _) = f.enroll(&client).await;
    let token = f.login(&mut auth, &client).await.session().access_token;
    let signed = protected_proof(&client, &token, LOGOUT);
    let mut stream = tokio::net::TcpStream::connect(f.address).await.unwrap();
    stream.write_all(format!("POST {LOGOUT} HTTP/1.1\r\nHost: setup.example.com:9443\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\nOrigin: {ORIGIN}\r\nAuthorization: DPoP {token}\r\nDPoP: {signed}\r\n\r\n{{}}").as_bytes()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while f
            .count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await
            != 1
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("revocation commits without reading HTTP confirmation");
    drop(stream);
    let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    confirmed(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_logout_discarded_http_response_can_confirm_with_fresh_proof() {
    discarded_response(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_discarded_http_response_can_confirm_with_fresh_proof() {
    discarded_response(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_logout_origin_body_header_and_protected_proof_guards() {
    request_guards(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_origin_body_header_and_protected_proof_guards() {
    request_guards(Fixture::postgres().await).await;
}

async fn cors(f: Fixture) {
    let reply = http_method(
        f.address,
        "OPTIONS",
        LOGOUT,
        b"",
        &[
            ("Origin", ORIGIN),
            ("Access-Control-Request-Method", "POST"),
            ("Access-Control-Request-Headers", "authorization, dpop, content-type"),
            ("Cookie", "unparsed"),
        ],
    )
    .await;
    assert_eq!(reply.status, 204);
    reply.privacy();
    assert_eq!(reply.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(reply.header("access-control-allow-methods"), Some("POST"));
    assert_eq!(
        reply.header("access-control-allow-headers"),
        Some("Authorization, DPoP, Content-Type")
    );
    assert_eq!(reply.header("access-control-allow-credentials"), None);
    for (origin, method, headers) in [
        ("https://other.example", "POST", "dpop"),
        (ORIGIN, "DELETE", "dpop"),
        (ORIGIN, "POST", "dpop,cookie"),
        (ORIGIN, "POST", "*"),
    ] {
        let reply = http_method(
            f.address,
            "OPTIONS",
            LOGOUT,
            b"",
            &[
                ("Origin", origin),
                ("Access-Control-Request-Method", method),
                ("Access-Control-Request-Headers", headers),
            ],
        )
        .await;
        reply.problem(403, "policy.denied", false, false);
        assert_eq!(reply.header("access-control-allow-origin"), None);
    }
    http_method(f.address, "GET", LOGOUT, b"", &[]).await.problem(
        405,
        "auth.invalid_request",
        false,
        false,
    );
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_logout_cors_is_exact_and_never_credentialed() {
    cors(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_cors_is_exact_and_never_credentialed() {
    cors(Fixture::postgres().await).await;
}

async fn audit_rollback(f: Fixture) {
    let client = key(1);
    let (mut auth, _) = f.enroll(&client).await;
    let token = f.login(&mut auth, &client).await.session().access_token;
    audit_trigger(&f, true).await;
    send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await.problem(
        503,
        "auth.storage_unavailable",
        false,
        true,
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        0
    );
    audit_trigger(&f, false).await;
    confirmed(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_logout_audit_failure_rolls_back_without_cookie_change() {
    audit_rollback(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_audit_failure_rolls_back_without_cookie_change() {
    audit_rollback(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_logout_unknown_commit_is_retryable_only_with_fresh_proof() {
    let f = Fixture::sqlite().await;
    let client = key(1);
    let (mut auth, _) = f.enroll(&client).await;
    let token = f.login(&mut auth, &client).await.session().access_token;
    f.execute("CREATE TABLE logout_parent (id INTEGER PRIMARY KEY); CREATE TABLE logout_child (id INTEGER REFERENCES logout_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER logout_commit_failure AFTER UPDATE OF revoked_at_ms ON operator_refresh_families BEGIN INSERT INTO logout_child VALUES (1); END;").await;
    let signed = protected_proof(&client, &token, LOGOUT);
    send(&f, &token, &signed, b"{}", &[]).await.problem(
        503,
        "auth.commit_outcome_unknown",
        true,
        true,
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        0
    );
    f.execute("DROP TRIGGER logout_commit_failure").await;
    send(&f, &token, &signed, b"{}", &[]).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    f.reset_admission().await;
    confirmed(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_actual_lost_commit_keeps_true_true_and_terminal_retry() {
    use std::sync::atomic::Ordering;
    let f = Fixture::postgres().await;
    let client = key(1);
    let (mut auth, _) = f.enroll(&client).await;
    let token = f.login(&mut auth, &client).await.session().access_token;
    let AuthBackend::Postgres(direct) = &f.backend else { unreachable!() };
    let mut url = Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").unwrap()).unwrap();
    let schema = &f.postgres.as_ref().unwrap().1;
    let application = format!("operator_logout_http_lost_{}", Uuid::new_v4().simple());
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"))
        .append_pair("application_name", &application);
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let adapter = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let mut barrier = direct.pool().begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048,1397052243)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    let address = adapter.address;
    let access = token.clone();
    let signed = protected_proof(&client, &token, LOGOUT);
    let request = tokio::spawn(async move {
        http(
            address,
            LOGOUT,
            b"{}",
            &[
                ("Content-Type", "application/json"),
                ("Origin", ORIGIN),
                ("Authorization", &format!("DPoP {access}")),
                ("DPoP", &signed),
            ],
        )
        .await
    });
    wait_for_business_lock(direct.pool(), &application, 1_397_052_243).await;
    proxy.armed.store(true, Ordering::SeqCst);
    barrier.commit().await.unwrap();
    let reply =
        tokio::time::timeout(std::time::Duration::from_secs(10), request).await.unwrap().unwrap();
    reply.problem(503, "auth.commit_outcome_unknown", true, true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        1
    );
    confirmed(&send(&f, &token, &protected_proof(&client, &token, LOGOUT), b"{}", &[]).await);
    adapter.cleanup().await;
    drop(proxy);
    f.cleanup().await;
}
