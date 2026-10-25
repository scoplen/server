// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

type Authenticator = webauthn_authenticator_rs::WebauthnAuthenticator<passkey::ResidentPasskey>;

#[path = "operator_personal_flow_tests.rs"]
mod personal_flow;

#[path = "operator_logout_http_tests.rs"]
mod logout;

impl Fixture {
    async fn enroll(&self, client: &P256SigningKey) -> (Authenticator, Uuid) {
        let token = self.token().await;
        let options = self.options(token, client).await;
        let mut authenticator = passkey::ResidentPasskey::authenticator();
        let registration = authenticator
            .do_registration(
                Url::parse(ORIGIN).expect("origin"),
                passkey::creation(&options["public_key"]),
            )
            .expect("real resident registration");
        let input = OperatorSetupFinishRequest {
            setup_token: token,
            ceremony_id: Uuid::parse_str(options["ceremony_id"].as_str().expect("ceremony"))
                .expect("UUID"),
            credential_id: registration.raw_id.as_ref().to_vec(),
            client_data_json: registration.response.client_data_json.as_ref().to_vec(),
            attestation_object: registration.response.attestation_object.as_ref().to_vec(),
        };
        let reply = self.post(FINISH_PATH, &input.to_json().expect("setup"), client).await;
        assert_eq!(reply.status, 201, "{}", reply.text());
        reply.privacy();
        let operator =
            OperatorSetupFinishResponse::from_json(&reply.body).expect("operator").operator_id;
        (authenticator, operator)
    }

    async fn assertion(
        &self,
        auth: &mut Authenticator,
        client: &P256SigningKey,
    ) -> OperatorLoginFinishRequest {
        let reply = self.post(LOGIN_OPTIONS_PATH, b"{}", client).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        reply.privacy();
        OperatorLoginOptionsResponse::from_json(&reply.body).expect("strict public login options");
        let options: serde_json::Value = serde_json::from_slice(&reply.body).expect("options");
        assert_eq!(options["public_key"]["allowCredentials"], serde_json::json!([]));
        assert_eq!(options["public_key"]["timeout"], 300_000);
        let result = auth
            .do_authentication(
                Url::parse(ORIGIN).expect("origin"),
                passkey::authentication(&options["public_key"]),
            )
            .expect("real discoverable assertion");
        OperatorLoginFinishRequest {
            ceremony_id: Uuid::parse_str(options["ceremony_id"].as_str().expect("ceremony"))
                .expect("UUID"),
            credential_id: result.raw_id.as_ref().to_vec(),
            client_data_json: result.response.client_data_json.as_ref().to_vec(),
            authenticator_data: result.response.authenticator_data.as_ref().to_vec(),
            signature: result.response.signature.as_ref().to_vec(),
            user_handle: result
                .response
                .user_handle
                .expect("discoverable handle")
                .as_ref()
                .try_into()
                .expect("handle16"),
        }
    }

    async fn login(&self, auth: &mut Authenticator, client: &P256SigningKey) -> Reply {
        let input = self.assertion(auth, client).await;
        let reply =
            self.post(LOGIN_FINISH_PATH, &input.to_json().expect("assertion"), client).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        reply.session();
        reply
    }

    async fn refresh(&self, cookie: &str, client: &P256SigningKey) -> Reply {
        http(
            self.address,
            REFRESH_PATH,
            b"{}",
            &[
                ("Content-Type", "application/json"),
                ("Origin", ORIGIN),
                ("Cookie", cookie),
                ("DPoP", &proof(client, REFRESH_PATH)),
            ],
        )
        .await
    }

    async fn current(&self, verified: &scoplen_crypto::VerifiedOperatorAccessToken) -> bool {
        match &self.backend {
            AuthBackend::Sqlite(store) => store.current_operator_session(verified).await,
            AuthBackend::Postgres(store) => store.current_operator_session(verified).await,
        }
        .expect("current durable family")
        .is_some()
    }

    async fn trusted_operator_keys(&self) -> TrustedOperatorAccessTokenKeys {
        let reply =
            http_method(self.address, "GET", "/.well-known/operator-jwks.json", b"", &[]).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        let keys: serde_json::Value = serde_json::from_slice(&reply.body).expect("public JWKS");
        let mut trusted = TrustedOperatorAccessTokenKeys::new(ORIGIN).expect("issuer");
        for key in keys["keys"].as_array().expect("keys") {
            let public: [u8; 32] = URL_SAFE_NO_PAD
                .decode(key["x"].as_str().expect("public key"))
                .expect("base64")
                .try_into()
                .expect("key32");
            trusted.insert(key["kid"].as_str().expect("key id"), &public).expect("trusted key");
        }
        trusted
    }
}

impl Reply {
    fn session(&self) -> BrowserAuthTokenResponse {
        assert_eq!(self.status, 200, "{}", self.text());
        assert_eq!(self.header("content-type"), Some("application/json"));
        assert_eq!(self.header("cache-control"), Some("no-store"));
        assert_eq!(self.header("pragma"), Some("no-cache"));
        assert_eq!(self.header("referrer-policy"), Some("no-referrer"));
        assert!(self.body.len() <= 8_192);
        let value: serde_json::Value = serde_json::from_slice(&self.body).expect("JSON");
        assert_eq!(value.as_object().expect("object").len(), 4);
        assert!(value.get("refresh_token").is_none());
        let response =
            BrowserAuthTokenResponse::from_json(self.text()).expect("four-field browser response");
        assert_eq!(response.token_type, "DPoP");
        assert_eq!(response.expires_in, 600);
        let cookie = self.header("set-cookie").expect("refresh cookie");
        let credential = self.cookie();
        let secret = credential.strip_prefix("__Secure-spl-refresh=").expect("cookie name");
        assert_eq!(secret.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(secret).expect("canonical bytes").len(), 32);
        assert_eq!(
            cookie,
            format!(
                "{credential}; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
                response.refresh_expires_in
            )
        );
        response
    }

    fn cookie(&self) -> String {
        self.header("set-cookie").expect("cookie").split(';').next().expect("credential").into()
    }
}

async fn session_lifecycle(fixture: Fixture) {
    let client = key(1);
    let (mut auth, operator) = fixture.enroll(&client).await;
    let keys = fixture.trusted_operator_keys().await;
    let login = fixture.login(&mut auth, &client).await;
    let token = login.session();
    assert_eq!(token.refresh_expires_in, 2_592_000);
    let verified = OperatorAccessToken::parse(&token.access_token)
        .expect("Operator JWT")
        .verify(&keys, SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs())
        .expect("actual signature and claims");
    assert_eq!(verified.claims().sub, operator);
    assert_eq!(verified.claims().scope, "personal-invitation:issue");
    assert_eq!(
        verified.claims().cnf_jkt,
        dpop_jwk_thumbprint(&client.public_key_sec1()).expect("JKT")
    );
    assert!(fixture.current(&verified).await);
    for table in ["identity_accounts", "identity_devices", "sync_vaults", "device_refresh_families"]
    {
        assert_eq!(fixture.count(&format!("SELECT COUNT(*) FROM {table}")).await, 0);
    }
    let refresh = fixture.refresh(&login.cookie(), &client).await;
    let rotated = refresh.session();
    assert_eq!(refresh.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(refresh.header("access-control-allow-credentials"), Some("true"));
    assert_ne!(refresh.cookie(), login.cookie());
    let next = OperatorAccessToken::parse(&rotated.access_token)
        .expect("rotated JWT")
        .verify(&keys, SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs())
        .expect("rotated signature");
    assert_eq!(next.claims().sid, verified.claims().sid);
    assert!(fixture.current(&next).await);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_refresh_tokens").await, 2);
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL")
            .await,
        1
    );
    fixture.execute("UPDATE deployment_operators SET active=0").await;
    assert!(!fixture.current(&verified).await);
    fixture.refresh(&refresh.cookie(), &client).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_operator_login_and_cookie_refresh() {
    session_lifecycle(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_operator_login_and_cookie_refresh() {
    session_lifecycle(Fixture::postgres().await).await;
}

#[allow(clippy::too_many_lines)]
async fn session_guards(fixture: Fixture) {
    let client = key(1);
    let (mut auth, _) = fixture.enroll(&client).await;
    for body in [b"{\"operator_id\":null}".as_slice(), b"[]", b"{\"x\":1,\"x\":2}", b"\xff"] {
        fixture.post(LOGIN_OPTIONS_PATH, body, &client).await.problem(
            400,
            "auth.invalid_request",
            false,
            false,
        );
    }
    let input = fixture.assertion(&mut auth, &client).await;
    let body = input.to_json().expect("assertion");
    fixture.post(LOGIN_FINISH_PATH, &body, &key(2)).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    let invalid = serde_json::from_slice::<serde_json::Value>(&body).expect("JSON");
    for (field, value) in [
        ("user_handle", serde_json::Value::Null),
        ("signature", serde_json::json!("bad=")),
        ("unrequested", serde_json::json!(true)),
    ] {
        let mut wire = invalid.clone();
        wire[field] = value;
        fixture
            .post(LOGIN_FINISH_PATH, &serde_json::to_vec(&wire).expect("JSON"), &client)
            .await
            .problem(400, "auth.invalid_request", false, false);
    }
    let signed = proof(&client, LOGIN_FINISH_PATH);
    for forbidden in [
        ("Authorization", "Bearer forbidden"),
        ("Idempotency-Key", "forbidden"),
        ("Cookie", "__Secure-spl-refresh=forbidden"),
    ] {
        http(
            fixture.address,
            LOGIN_FINISH_PATH,
            &body,
            &[
                ("Content-Type", "application/json"),
                ("Origin", ORIGIN),
                ("DPoP", &signed),
                forbidden,
            ],
        )
        .await
        .problem(400, "auth.invalid_request", false, false);
    }
    http(
        fixture.address,
        LOGIN_FINISH_PATH,
        &body,
        &[("Content-Type", "application/json"), ("DPoP", &signed)],
    )
    .await
    .problem(403, "policy.denied", false, false);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_ceremonies WHERE purpose=2 AND consumed_at_s IS NOT NULL").await, 0);
    let login = fixture.post(LOGIN_FINISH_PATH, &body, &client).await;
    login.session();
    http(
        fixture.address,
        LOGIN_FINISH_PATH,
        &body,
        &[("Content-Type", "application/json"), ("Origin", ORIGIN), ("DPoP", &signed)],
    )
    .await
    .problem(401, "auth.authentication_required", false, false);
    fixture.reset_admission().await;
    let cookie = login.cookie();
    for invalid_body in
        [b"{\"refresh_token\":\"forbidden\"}".as_slice(), b"[]", b"{\"x\":1,\"x\":2}"]
    {
        http(
            fixture.address,
            REFRESH_PATH,
            invalid_body,
            &[
                ("Content-Type", "application/json"),
                ("Origin", ORIGIN),
                ("Cookie", &cookie),
                ("DPoP", &proof(&client, REFRESH_PATH)),
            ],
        )
        .await
        .problem(400, "auth.invalid_request", false, false);
    }
    for origin in [None, Some("null"), Some("https://other.example.com")] {
        let mut headers =
            vec![("Content-Type", "application/json"), ("Cookie", &cookie), ("DPoP", &signed)];
        if let Some(origin) = origin {
            headers.push(("Origin", origin));
        }
        http(fixture.address, REFRESH_PATH, b"{}", &headers).await.problem(
            403,
            "policy.denied",
            false,
            false,
        );
    }
    fixture.refresh(&cookie, &key(2)).await.problem(400, "auth.invalid_dpop_proof", false, false);
    let token = cookie.strip_prefix("__Secure-spl-refresh=").expect("cookie");
    let native =
        serde_json::to_vec(&serde_json::json!({"refresh_token": token})).expect("native body");
    http(
        fixture.address,
        REFRESH_PATH,
        &native,
        &[("Content-Type", "application/json"), ("DPoP", &proof(&client, REFRESH_PATH))],
    )
    .await
    .problem(401, "auth.authentication_required", false, false);
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL")
            .await,
        0
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        0
    );
    let signed = proof(&client, REFRESH_PATH);
    let headers = [
        ("Content-Type", "application/json"),
        ("Origin", ORIGIN),
        ("Cookie", &cookie),
        ("DPoP", &signed),
    ];
    let next = http(fixture.address, REFRESH_PATH, b"{}", &headers).await;
    next.session();
    http(fixture.address, REFRESH_PATH, b"{}", &headers).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    fixture.refresh(&cookie, &key(2)).await.problem(400, "auth.invalid_dpop_proof", false, false);
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        0
    );
    let audits = fixture.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    fixture.refresh(&cookie, &client).await.problem(
        401,
        "auth.authentication_required",
        true,
        false,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits + 1);
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_families WHERE revoked_at_ms IS NOT NULL")
            .await,
        1
    );
    fixture.reset_admission().await;
    fixture.refresh(&next.cookie(), &client).await.problem(
        401,
        "auth.authentication_required",
        false,
        false,
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_operator_guards_replay_and_reuse() {
    session_guards(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_operator_guards_replay_and_reuse() {
    session_guards(Fixture::postgres().await).await;
}

async fn audit_trigger(fixture: &Fixture, enabled: bool) {
    match (&fixture.backend, enabled) {
        (AuthBackend::Sqlite(_), true) => fixture.execute("CREATE TRIGGER reject_operator_session_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END").await,
        (AuthBackend::Sqlite(_), false) => fixture.execute("DROP TRIGGER reject_operator_session_audit").await,
        (AuthBackend::Postgres(_), true) => fixture.execute("CREATE FUNCTION reject_operator_session_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END; $$; CREATE TRIGGER reject_operator_session_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_operator_session_audit();").await,
        (AuthBackend::Postgres(_), false) => fixture.execute("DROP TRIGGER reject_operator_session_audit ON deployment_audit_events; DROP FUNCTION reject_operator_session_audit();").await,
    }
}

async fn session_audit(fixture: Fixture) {
    let client = key(1);
    let (mut auth, _) = fixture.enroll(&client).await;
    fixture.trusted_operator_keys().await;
    let input = fixture.assertion(&mut auth, &client).await;
    let body = input.to_json().expect("assertion");
    audit_trigger(&fixture, true).await;
    fixture.post(LOGIN_FINISH_PATH, &body, &client).await.problem(
        503,
        "auth.storage_unavailable",
        false,
        true,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_ceremonies WHERE purpose=2 AND consumed_at_s IS NOT NULL").await, 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_refresh_families").await, 0);
    audit_trigger(&fixture, false).await;
    let mut invalid = input;
    invalid.client_data_json = b"{".to_vec();
    let audits = fixture.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    fixture
        .post(LOGIN_FINISH_PATH, &invalid.to_json().expect("opaque embedded bytes"), &client)
        .await
        .problem(401, "auth.authentication_required", true, false);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits + 1);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_refresh_families").await, 0);
    fixture.post(LOGIN_FINISH_PATH, &body, &client).await.problem(
        429,
        "auth.rate_limited",
        false,
        true,
    );
    fixture.reset_admission().await;
    let login = fixture.login(&mut auth, &client).await;
    audit_trigger(&fixture, true).await;
    fixture.refresh(&login.cookie(), &client).await.problem(
        503,
        "auth.storage_unavailable",
        false,
        true,
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL")
            .await,
        0
    );
    audit_trigger(&fixture, false).await;
    fixture.refresh(&login.cookie(), &client).await.session();
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_operator_login_audit_and_consuming_denial() {
    session_audit(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_operator_login_audit_and_consuming_denial() {
    session_audit(Fixture::postgres().await).await;
}

async fn session_quota(fixture: Fixture) {
    let client = key(1);
    let (mut auth, _) = fixture.enroll(&client).await;
    let input = fixture.assertion(&mut auth, &client).await;
    let body = input.to_json().expect("assertion");
    fixture.post(LOGIN_FINISH_PATH, &body, &key(2)).await.problem(
        400,
        "auth.invalid_dpop_proof",
        false,
        false,
    );
    fixture.execute("UPDATE operator_auth_admission SET attempts=5 WHERE kind=3").await;
    fixture.post(LOGIN_FINISH_PATH, &body, &client).await.problem(
        429,
        "auth.rate_limited",
        false,
        true,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_refresh_families").await, 0);
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_ceremonies WHERE purpose=2 AND consumed_at_s IS NOT NULL").await, 0);
    fixture.reset_admission().await;
    let (first, second) = tokio::join!(
        fixture.post(LOGIN_FINISH_PATH, &body, &client),
        fixture.post(LOGIN_FINISH_PATH, &body, &client)
    );
    assert_eq!([first.status, second.status].iter().filter(|&&status| status == 200).count(), 1);
    for reply in [&first, &second] {
        if reply.status == 200 {
            reply.session();
        } else {
            reply.problem(401, "auth.authentication_required", false, false);
        }
    }
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_refresh_families").await, 1);
    fixture.reset_admission().await;
    fixture.post(LOGIN_OPTIONS_PATH, b"[]", &client).await.problem(
        400,
        "auth.invalid_request",
        false,
        false,
    );
    fixture.execute("UPDATE operator_auth_admission SET attempts=30 WHERE kind=1").await;
    http(fixture.address, LOGIN_OPTIONS_PATH, b"bad JSON", &[]).await.problem(
        429,
        "auth.rate_limited",
        false,
        true,
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_operator_login_quota_and_single_winner() {
    session_quota(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_operator_login_quota_and_single_winner() {
    session_quota(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_real_http_operator_login_uncertain_commit_discloses_no_session() {
    let fixture = Fixture::sqlite().await;
    let client = key(1);
    let (mut auth, _) = fixture.enroll(&client).await;
    fixture.trusted_operator_keys().await;
    let input = fixture.assertion(&mut auth, &client).await;
    fixture.execute("CREATE TABLE operator_login_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE operator_login_commit_child (id INTEGER REFERENCES operator_login_commit_parent (id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER operator_login_commit_failure AFTER UPDATE OF consumed_at_s ON operator_ceremonies WHEN NEW.purpose=2 BEGIN INSERT INTO operator_login_commit_child VALUES (1); END;").await;
    fixture.post(LOGIN_FINISH_PATH, &input.to_json().expect("assertion"), &client).await.problem(
        503,
        "auth.commit_outcome_unknown",
        true,
        false,
    );
    assert_eq!(fixture.count("SELECT COUNT(*) FROM operator_refresh_families").await, 0);
    fixture.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_operator_refresh_uncertain_commit_discloses_no_session() {
    let fixture = Fixture::sqlite().await;
    let client = key(1);
    let (mut auth, _) = fixture.enroll(&client).await;
    let login = fixture.login(&mut auth, &client).await;
    fixture.execute("CREATE TABLE operator_refresh_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE operator_refresh_commit_child (id INTEGER REFERENCES operator_refresh_commit_parent (id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER operator_refresh_commit_failure AFTER UPDATE OF spent_at_ms ON operator_refresh_tokens BEGIN INSERT INTO operator_refresh_commit_child VALUES (1); END;").await;
    fixture.refresh(&login.cookie(), &client).await.problem(
        503,
        "auth.commit_outcome_unknown",
        true,
        false,
    );
    assert_eq!(
        fixture
            .count("SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL")
            .await,
        0
    );
    fixture.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[allow(clippy::too_many_lines)]
async fn session_lost_ack(refresh: bool) {
    use std::sync::atomic::Ordering;
    let fixture = Fixture::postgres().await;
    let client = key(1);
    let (mut auth, _) = fixture.enroll(&client).await;
    fixture.trusted_operator_keys().await;
    let (path, body, cookie) = if refresh {
        let login = fixture.login(&mut auth, &client).await;
        (REFRESH_PATH, b"{}".to_vec(), Some(login.cookie()))
    } else {
        let input = fixture.assertion(&mut auth, &client).await;
        (LOGIN_FINISH_PATH, input.to_json().expect("assertion"), None)
    };
    let AuthBackend::Postgres(direct) = &fixture.backend else { unreachable!() };
    let schema = &fixture.postgres.as_ref().expect("isolated schema").1;
    let mut url =
        Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("fixture URL")).expect("URL");
    let application = format!("operator_session_http_lost_{}", Uuid::new_v4().simple());
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"))
        .append_pair("application_name", &application);
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let proxied =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    let http_fixture = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let mut barrier = direct.pool().begin().await.expect("session barrier");
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048,1397052243)")
        .execute(&mut *barrier)
        .await
        .expect("hold session lock");
    let address = http_fixture.address;
    let signed = proof(&client, path);
    let request = tokio::spawn(async move {
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Origin", ORIGIN),
            ("DPoP", signed.as_str()),
        ];
        if let Some(cookie) = &cookie {
            headers.push(("Cookie", cookie));
        }
        http(address, path, &body, &headers).await
    });
    wait_for_business_lock(direct.pool(), &application, 1_397_052_243).await;
    proxy.armed.store(true, Ordering::SeqCst);
    barrier.commit().await.expect("release lock");
    let reply = tokio::time::timeout(std::time::Duration::from_secs(10), request)
        .await
        .expect("HTTP finishes")
        .expect("HTTP task");
    reply.problem(503, "auth.commit_outcome_unknown", true, false);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let durable = if refresh {
        "SELECT COUNT(*) FROM operator_refresh_tokens WHERE spent_at_ms IS NOT NULL"
    } else {
        "SELECT COUNT(*) FROM operator_refresh_families"
    };
    assert_eq!(
        fixture.count(durable).await,
        1,
        "business commit is durable despite withheld acknowledgement"
    );
    http_fixture.cleanup().await;
    drop(proxy);
    fixture.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_operator_login_lost_commit_ack_discloses_no_session() {
    session_lost_ack(false).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_operator_refresh_lost_commit_ack_discloses_no_session() {
    session_lost_ack(true).await;
}
