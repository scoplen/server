// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::pairing::{
    PairingClaimResponse, PairingCompleteRequest, PairingContext, PairingCreateRequest,
    PairingCreateResponse, PairingMessageAck, PairingMessageRequest, PairingReceipt,
    PairingSnapshot, PairingState, PairingStep, encode_pairing_authorization,
    validate_pairing_response_metadata,
};
use scoplen_crypto::{
    PairingApplicationContext, PairingCompletionContext, PairingContext as CryptoContext,
};

const PATH: &str = "/api/v1/auth/pairings";

fn privacy(reply: &Reply) {
    reply.privacy();
    validate_pairing_response_metadata(
        reply.header("cache-control"),
        reply.header("pragma"),
        reply.header("referrer-policy"),
        reply.header("etag").is_some(),
    )
    .expect("pairing private response metadata");
    for name in ["access-control-allow-origin", "access-control-allow-credentials", "set-cookie"] {
        assert!(reply.header(name).is_none(), "no browser credential surface");
    }
}

fn success(reply: &Reply, status: u16) {
    assert_eq!(reply.status, status, "{}", reply.text());
    privacy(reply);
}

fn denied(reply: &Reply, status: u16, code: &str) {
    reply.problem(status, code, false, status == 429 || status == 503);
    privacy(reply);
    for field in
        ["new_device_token", "device_certificate", "key_bundle_update", "payload", "signature"]
    {
        assert!(!reply.text().contains(field), "safe problem fields");
    }
}

async fn responder(
    f: &Fixture,
    created: &PairingCreateResponse,
    method: &str,
    suffix: &str,
    body: &[u8],
) -> Reply {
    let authorization = encode_pairing_authorization(&created.new_device_token);
    http_method(
        f.address,
        method,
        &format!("{PATH}/{}{suffix}", created.context.pairing_id),
        body,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
            ("Origin", ORIGIN),
        ],
    )
    .await
}

pub(super) async fn create(f: &Fixture) -> PairingCreateResponse {
    let body = PairingCreateRequest { device_id: Uuid::now_v7() }.to_json().expect("create JSON");
    let reply = http(f.address, PATH, &body, &[("Content-Type", "application/json")]).await;
    success(&reply, 201);
    let created = PairingCreateResponse::from_json(&reply.body).expect("one-time response");
    assert_eq!(created.context.origin, ORIGIN);
    assert_eq!(created.context.initiator_device_id, None);
    created
}

fn complete_request(
    identity: &PersonalBootstrap,
    context: &PairingContext,
) -> PairingCompleteRequest {
    let signing = Ed25519SigningKey::from_bytes(&[7; 32]).expect("account signing key");
    let certificate = DeviceCertificate::issue(
        &signing,
        context.responder_device_id,
        identity.receipt.account_id,
        key(4).public_key_sec1(),
        DeviceKemKeyPair::from_private_bytes(&[9; 32]).expect("new KEM").public_key().to_vec(),
        "Second Personal device".into(),
        "windows".into(),
        1,
    )
    .expect("certificate")
    .encode()
    .expect("canonical certificate");
    let mut update = SyncAccountKeyBundleUpdate {
        revision: 2,
        device_wraps: vec![
            SyncAccountDeviceWrap { device_id: identity.receipt.device_id, wrapped_ark: vec![5] },
            SyncAccountDeviceWrap { device_id: context.responder_device_id, wrapped_ark: vec![10] },
        ],
        account_signing_key: vec![6],
        account_kem_key: vec![7],
        recovery_blob: vec![8],
        signature: vec![0; 64],
    };
    update.device_wraps.sort_by_key(|wrap| wrap.device_id);
    update.signature = signing.sign(&update.signature_input().expect("signature input")).to_vec();
    let update = update.to_cbor().expect("canonical update");
    let application = PairingApplicationContext::new(
        ORIGIN,
        CryptoContext::new(
            context.pairing_id,
            context.initiator_device_id.expect("claimed"),
            context.responder_device_id,
        )
        .expect("pairing context"),
    )
    .expect("application context");
    let signature = PairingCompletionContext::new(
        &application,
        identity.receipt.account_id,
        &[2; 41],
        &certificate,
        &update,
    )
    .expect("completion context")
    .sign(&key(4))
    .expect("new-device signature");
    PairingCompleteRequest {
        device_certificate: certificate,
        key_bundle_update: update,
        new_device_signature: signature,
    }
}

async fn claimed(
    f: &Fixture,
    identity: &PersonalBootstrap,
    created: &PairingCreateResponse,
) -> PairingContext {
    let path = format!("{PATH}/{}/claim", created.context.pairing_id);
    let reply = protected(f, "POST", &path, b"{}", &identity.token, &identity.client).await;
    success(&reply, 200);
    let context = PairingClaimResponse::from_json(&reply.body).expect("claim context").context;
    assert_eq!(context.initiator_device_id, Some(identity.receipt.device_id));
    context
}

pub(super) async fn ready(
    f: &Fixture,
    identity: &PersonalBootstrap,
    created: &PairingCreateResponse,
) -> PairingCompleteRequest {
    let context = claimed(f, identity, created).await;
    let request = complete_request(identity, &context);
    for step in PairingStep::ALL {
        let payload = match step {
            PairingStep::NewDevice => vec![1; 41],
            PairingStep::Handoff => vec![2; 41],
            PairingStep::Acceptance => request.new_device_signature.to_vec(),
            _ => vec![3; 32],
        };
        let body = PairingMessageRequest { step, payload }.to_json().expect("message JSON");
        let reply = if step.role() == scoplen_api::pairing::PairingRole::Initiator {
            protected(
                f,
                "POST",
                &format!("{PATH}/{}/messages", context.pairing_id),
                &body,
                &identity.token,
                &identity.client,
            )
            .await
        } else {
            responder(f, created, "POST", "/messages", &body).await
        };
        success(&reply, 200);
        assert_eq!(PairingMessageAck::from_json(&reply.body).expect("ack").step, step);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&reply.body)
                .expect("ack JSON")
                .as_object()
                .expect("object")
                .len(),
            1
        );
    }
    let reply = responder(f, created, "GET", "", &[]).await;
    success(&reply, 200);
    let snapshot = PairingSnapshot::from_json(&reply.body).expect("ready snapshot");
    assert_eq!(snapshot.state, PairingState::Ready);
    assert_eq!(snapshot.messages.len(), 7);
    request
}

async fn complete_flow(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let created = create(&f).await;
    let request = ready(&f, &identity, &created).await;
    let path = format!("{PATH}/{}/complete", created.context.pairing_id);
    let body = request.to_json().expect("complete JSON");
    let mut invalid = request.clone();
    invalid.new_device_signature[0] ^= 1;
    denied(
        &protected(
            &f,
            "POST",
            &path,
            &invalid.to_json().expect("invalid proof JSON"),
            &identity.token,
            &identity.client,
        )
        .await,
        400,
        "auth.invalid_request",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM identity_devices").await, 1);
    let reply = protected(&f, "POST", &path, &body, &identity.token, &identity.client).await;
    success(&reply, 200);
    let receipt = PairingReceipt::from_json(&reply.body).expect("receipt");
    assert_eq!(receipt.account_id, identity.receipt.account_id);
    assert_eq!(receipt.device_id, created.context.responder_device_id);
    assert_eq!(receipt.revision, 2);
    let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    let repeated = protected(&f, "POST", &path, &body, &identity.token, &identity.client).await;
    success(&repeated, 200);
    assert_eq!(repeated.body, reply.body);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits);
    denied(
        &protected(
            &f,
            "POST",
            &path,
            &invalid.to_json().expect("changed approval JSON"),
            &identity.token,
            &identity.client,
        )
        .await,
        409,
        "auth.pairing_conflict",
    );
    let snapshot = responder(&f, &created, "GET", "", &[]).await;
    success(&snapshot, 200);
    let snapshot = PairingSnapshot::from_json(&snapshot.body).expect("terminal snapshot");
    assert_eq!(snapshot.state, PairingState::Completed);
    assert_eq!(snapshot.messages, []);
    assert_eq!(snapshot.receipt, Some(receipt));
    denied(&responder(&f, &created, "DELETE", "", &[]).await, 409, "auth.pairing_conflict");
    let new_token = authenticate_device(&f, created.context.responder_device_id, &key(4)).await;
    let bundle = protected(&f, "GET", "/sync/v1/keys", &[], &new_token, &key(4)).await;
    assert_eq!(bundle.status, 200);
    let bundle = SyncAccountKeyBundle::from_cbor(&bundle.body).expect("new-device bundle");
    assert_eq!(bundle.revision, 2);
    assert_eq!(bundle.wrapped_ark, vec![10]);
    assert_eq!(f.count("SELECT COUNT(*) FROM identity_accounts").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_vaults").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM identity_devices").await, 2);
    f.cleanup().await;
}

#[allow(clippy::too_many_lines)]
async fn strict_requests(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let created = create(&f).await;
    let path = format!("{PATH}/{}", created.context.pairing_id);
    let body = PairingCreateRequest { device_id: Uuid::now_v7() }.to_json().expect("create JSON");
    for extra in [
        vec![("Authorization", "Bearer invalid")],
        vec![("DPoP", "invalid")],
        vec![("Cookie", "test=1")],
        vec![("Idempotency-Key", "1")],
        vec![("If-Match", "*")],
        vec![("If-None-Match", "*")],
        vec![("If-Modified-Since", "now")],
        vec![("If-Unmodified-Since", "now")],
        vec![("If-Range", "*")],
        vec![("Cache-Control", "no-cache")],
        vec![("Pragma", "no-cache")],
    ] {
        let mut headers = extra;
        headers.push(("Content-Type", "application/json"));
        denied(&http(f.address, PATH, &body, &headers).await, 400, "auth.invalid_request");
    }
    for headers in [vec![("Origin", "null")], vec![("Origin", ORIGIN), ("Origin", ORIGIN)]] {
        denied(&http(f.address, PATH, &body, &headers).await, 403, "policy.denied");
    }
    for input in [
        b"{}".as_slice(),
        b"{\"device_id\":1}",
        b"{\"device_id\":null}",
        b"{\"device_id\":1,\"device_id\":1}",
        b"{\"extra\":1}",
    ] {
        denied(
            &http(f.address, PATH, input, &[("Content-Type", "application/json")]).await,
            400,
            "auth.invalid_request",
        );
    }
    denied(
        &http(f.address, PATH, &[b' '; 257], &[("Content-Type", "application/json")]).await,
        413,
        "auth.invalid_request",
    );
    denied(
        &http(f.address, &format!("{PATH}?"), &body, &[("Content-Type", "application/json")]).await,
        400,
        "auth.invalid_request",
    );
    let count = f.count("SELECT COUNT(*) FROM pairing_sessions").await;
    assert_eq!(count, 1);
    denied(
        &http_method(f.address, "GET", &format!("{PATH}/{}", Uuid::new_v4()), &[], &[]).await,
        400,
        "auth.invalid_request",
    );
    denied(
        &http_method(
            f.address,
            "GET",
            &format!("{PATH}/{}", created.context.pairing_id.simple()),
            &[],
            &[],
        )
        .await,
        400,
        "auth.invalid_request",
    );
    denied(&responder(&f, &created, "GET", "?query=1", &[]).await, 400, "auth.invalid_request");
    denied(&responder(&f, &created, "GET", "", b"x").await, 400, "auth.invalid_request");
    denied(&responder(&f, &created, "DELETE", "", b"x").await, 400, "auth.invalid_request");
    denied(&http_method(f.address, "PUT", &path, &[], &[]).await, 405, "auth.invalid_request");
    let authorization = encode_pairing_authorization(&created.new_device_token);
    for extra in [
        vec![("DPoP", "invalid")],
        vec![("Cookie", "test=1")],
        vec![("Authorization", authorization.as_str())],
    ] {
        let mut headers = vec![("Authorization", authorization.as_str())];
        headers.extend(extra);
        denied(
            &http_method(f.address, "GET", &path, &[], &headers).await,
            400,
            "auth.invalid_request",
        );
    }
    denied(&responder(&f, &created, "POST", "/claim", b"{}").await, 401, "auth.pairing_denied");
    f.execute("DELETE FROM pairing_admission WHERE endpoint=2").await;
    let claim = format!("{path}/claim");
    denied(
        &http(f.address, &claim, b"{}", &[("Content-Type", "application/json")]).await,
        401,
        "auth.authentication_required",
    );
    denied(
        &protected(&f, "POST", &claim, b"{}", &identity.operator_token, &identity.operator_key)
            .await,
        401,
        "auth.authentication_required",
    );
    let limited = account_profile::signed_token(
        &f,
        &identity,
        identity.receipt.account_id,
        identity.receipt.device_id,
        "keys:read",
    )
    .await;
    denied(
        &protected(&f, "POST", &claim, b"{}", &limited, &identity.client).await,
        403,
        "policy.denied",
    );
    let proof = account_profile::proof_for(&identity, "POST", &claim, &identity.token);
    let auth = format!("DPoP {}", identity.token);
    for field in ["Authorization", "DPoP"] {
        let duplicate = [
            ("Content-Type", "application/json"),
            ("Authorization", auth.as_str()),
            ("DPoP", proof.as_str()),
            (field, if field == "Authorization" { auth.as_str() } else { proof.as_str() }),
        ];
        denied(
            &http(f.address, &claim, b"{}", &duplicate).await,
            401,
            "auth.authentication_required",
        );
    }
    let proof = account_profile::proof_for(&identity, "POST", &claim, &identity.token);
    let headers = [
        ("Content-Type", "application/json"),
        ("Authorization", auth.as_str()),
        ("DPoP", proof.as_str()),
    ];
    success(&http(f.address, &claim, b"{}", &headers).await, 200);
    denied(&http(f.address, &claim, b"{}", &headers).await, 401, "auth.authentication_required");
    let message = format!("{path}/messages");
    let mut small =
        PairingMessageRequest { step: PairingStep::InitiatorShare, payload: vec![3; 32] }
            .to_json()
            .expect("small message");
    small.resize(257, b' ');
    denied(
        &protected(&f, "POST", &message, &small, &identity.token, &identity.client).await,
        413,
        "auth.invalid_request",
    );
    let oversized = format!(
        "{{\"step\":\"new_device\",\"payload\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode(vec![1; 131_073])
    );
    denied(
        &responder(&f, &created, "POST", "/messages", oversized.as_bytes()).await,
        413,
        "auth.invalid_request",
    );
    let reply = responder(&f, &created, "DELETE", "", &[]).await;
    success(&reply, 204);
    assert_eq!(reply.body, [] as [u8; 0]);
    assert!(reply.header("content-type").is_none());
    success(&responder(&f, &created, "DELETE", "", &[]).await, 204);
    f.execute("UPDATE identity_devices SET active=false").await;
    denied(
        &protected(&f, "GET", &path, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
    f.cleanup().await;
}

fn rate(reply: &Reply, read: bool) {
    denied(reply, 429, "auth.rate_limited");
    assert_eq!(
        reply.header("ratelimit-policy"),
        Some(if read { "\"pairing\";q=120;w=60" } else { "\"pairing\";q=30;w=60" })
    );
    let delay: u16 =
        reply.header("retry-after").expect("rate delay").parse().expect("integer delay");
    assert!((1..=300).contains(&delay));
    assert_eq!(reply.header("ratelimit"), Some(format!("\"pairing\";r=0;t={delay}").as_str()));
}

#[allow(clippy::too_many_lines)]
async fn admission_and_audit(mut f: Fixture) {
    mount_complete_api(&mut f).await;
    for headers in [vec![], vec![("Origin", ORIGIN)]] {
        let landing = http_method(f.address, "GET", "/pair", &[], &headers).await;
        success(&landing, 200);
        assert_eq!(landing.header("content-type"), Some("text/html; charset=utf-8"));
        assert!(
            landing
                .header("content-security-policy")
                .expect("landing CSP")
                .contains("form-action 'none'")
        );
        assert!(landing.text().contains("Open this link in Scoplen"));
        for element in ["<script", "<form", "<input", "fetch("] {
            assert!(!landing.text().contains(element));
        }
    }
    denied(
        &http_method(f.address, "GET", "/pair?password=private", &[], &[]).await,
        400,
        "auth.invalid_request",
    );
    denied(
        &http_method(f.address, "GET", "/pair", &[], &[("Origin", "null")]).await,
        403,
        "policy.denied",
    );
    for header in ["Authorization", "DPoP", "Cookie", "If-None-Match", "Idempotency-Key"] {
        denied(
            &http_method(f.address, "GET", "/pair", &[], &[(header, "private")]).await,
            400,
            "auth.invalid_request",
        );
    }
    denied(
        &http_method(f.address, "POST", "/pair", b"private", &[]).await,
        405,
        "auth.invalid_request",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM pairing_sessions").await, 0);
    let created = create(&f).await;
    success(&responder(&f, &created, "GET", "", &[]).await, 200);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis();
    f.execute(&format!("UPDATE pairing_admission SET attempts=60,window_start_ms={now},retain_until_ms={} WHERE endpoint=3 AND kind=2", now + 60_000)).await;
    rate(&responder(&f, &created, "GET", "", &[]).await, true);
    assert_eq!(f.count("SELECT COUNT(*) FROM pairing_admission WHERE kind=2").await, 1);
    f.execute("DELETE FROM pairing_admission").await;
    let bad = format!("Pairing {}", URL_SAFE_NO_PAD.encode([99; 32]));
    let path = format!("{PATH}/{}", created.context.pairing_id);
    denied(
        &http_method(f.address, "GET", &path, &[], &[("Authorization", &bad)]).await,
        401,
        "auth.pairing_denied",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM pairing_admission WHERE kind=2").await, 0);
    rate(&responder(&f, &created, "GET", "", &[]).await, true);
    f.execute("DELETE FROM pairing_admission").await;
    // A forged proxy header cannot select a different source bucket.
    denied(
        &http(
            f.address,
            PATH,
            b"{}",
            &[("Content-Type", "application/json"), ("X-Forwarded-For", "192.0.2.77")],
        )
        .await,
        400,
        "auth.invalid_request",
    );
    f.execute(&format!("UPDATE pairing_admission SET attempts=30,window_start_ms={now},retain_until_ms={} WHERE endpoint=1 AND kind=1", now + 60_000)).await;
    rate(
        &http(
            f.address,
            PATH,
            b"invalid",
            &[("Origin", "null"), ("X-Forwarded-For", "192.0.2.78")],
        )
        .await,
        false,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM pairing_sessions").await, 1);
    f.execute("DELETE FROM pairing_admission").await;
    let fail = match &f.backend {
        AuthBackend::Sqlite(_) => {
            "CREATE TRIGGER fail_pairing_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'unavailable'); END"
        }
        AuthBackend::Postgres(_) => {
            "CREATE FUNCTION fail_pairing_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unavailable'; END $$; CREATE TRIGGER fail_pairing_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_pairing_audit()"
        }
    };
    f.execute(fail).await;
    denied(
        &http(f.address, PATH, b"{}", &[("Content-Type", "application/json")]).await,
        503,
        "auth.storage_unavailable",
    );
    let body = PairingCreateRequest { device_id: Uuid::now_v7() }.to_json().expect("create JSON");
    denied(
        &http(f.address, PATH, &body, &[("Content-Type", "application/json")]).await,
        503,
        "auth.storage_unavailable",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM pairing_sessions").await, 1);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_http_pairing_complete_and_device_authentication() {
    complete_flow(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_pairing_strict_requests_and_credentials() {
    strict_requests(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_http_pairing_admission_and_audit_precedence() {
    admission_and_audit(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_pairing_complete_and_device_authentication() {
    complete_flow(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_pairing_strict_requests_and_credentials() {
    strict_requests(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_pairing_admission_and_audit_precedence() {
    admission_and_audit(Fixture::postgres().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_http_pairing_lost_create_commit_discloses_no_capability() {
    use std::sync::atomic::Ordering;

    let mut f = Fixture::postgres().await;
    let (_, schema) = f.postgres.as_ref().expect("owned schema");
    let mut url = Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PG URL"))
        .expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    // The first COMMIT charges source admission. Only the business COMMIT loses its reply.
    let proxy = lost_commit::LostCommitProxy::start_skipping(url.as_str(), 1).await;
    let proxied = Arc::new(
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store"),
    );
    f.server.abort();
    let _ = (&mut f.server).await;
    let kms = Arc::new(LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS"));
    let app = crate::pairing::router(ORIGIN.into(), AuthBackend::Postgres(proxied.clone()), kms);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    f.address = listener.local_addr().expect("address");
    f.server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("pairing HTTP");
    });
    proxy.armed.store(true, Ordering::SeqCst);
    let body = PairingCreateRequest { device_id: Uuid::now_v7() }.to_json().expect("create JSON");
    let reply = http(f.address, PATH, &body, &[("Content-Type", "application/json")]).await;
    reply.problem(503, "auth.commit_outcome_unknown", true, false);
    privacy(&reply);
    assert!(!reply.text().contains("new_device_token"));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM pairing_sessions").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, 1);
    proxied.pool().close().await;
    drop(proxied);
    f.cleanup().await;
}
