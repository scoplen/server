// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use account_profile::{proof_for, signed_token};
use axum::{body::Body, http::Request};
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use notifications::Listener;
use scoplen_api::sync::SyncAccountKeyBundlePutResponse;
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, RevocationStatement, TrustedDeviceAccessTokenKeys,
};
use tokio::net::TcpStream;

const PATH: &str = "/sync/v1/keys";
type Tls = tokio_rustls::client::TlsStream<TcpStream>;

async fn accepted_put(f: &Fixture, identity: &LegacyDeviceSession) -> Option<Vec<u8>> {
    let account = identity.receipt.account_id.into_bytes();
    match &f.backend {
        AuthBackend::Sqlite(store) => store.read_accepted_account_key_put(account).await,
        AuthBackend::Postgres(store) => store.read_accepted_account_key_put(account).await,
    }
    .expect("consistent accepted key PUT")
}

fn signing() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[7; 32]).expect("account signing key")
}

fn sign(update: &mut SyncAccountKeyBundleUpdate, root: &Ed25519SigningKey) {
    update.device_wraps.sort_by_key(|wrap| wrap.device_id);
    update.signature =
        root.sign(&update.signature_input().expect("canonical signing input")).to_vec();
}

fn update(identity: &LegacyDeviceSession, revision: u64) -> SyncAccountKeyBundleUpdate {
    let mut update = SyncAccountKeyBundleUpdate {
        revision,
        device_wraps: vec![SyncAccountDeviceWrap {
            device_id: identity.receipt.device_id,
            wrapped_ark: vec![20],
        }],
        account_signing_key: vec![21],
        account_kem_key: vec![22],
        recovery_blob: vec![23],
        signature: vec![0; 64],
    };
    sign(&mut update, &signing());
    update
}

fn privacy(reply: &Reply) {
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert_eq!(reply.header("set-cookie"), None);
    assert_eq!(reply.header("etag"), None);
}

fn success(reply: &Reply, revision: u64) {
    assert_eq!(reply.status, 200);
    privacy(reply);
    assert_eq!(reply.header("content-type"), Some("application/cbor"));
    assert_eq!(
        SyncAccountKeyBundlePutResponse::from_cbor(&reply.body)
            .expect("publication receipt")
            .revision,
        revision
    );
}

fn denied(reply: &Reply, status: u16, code: &str, changed: bool, retryable: bool) {
    assert_eq!(reply.status, status);
    privacy(reply);
    assert_eq!(reply.header("content-type"), Some("application/problem+cbor"));
    let problem = ProblemDetails::from_cbor(&reply.body).expect("bounded typed CBOR problem");
    assert_eq!(problem.code.as_str(), code);
    assert_eq!(problem.changed, changed);
    assert_eq!(problem.retryable, retryable);
    assert!(reply.body.len() <= 4096);
}

async fn request(
    listener: &Listener,
    identity: &LegacyDeviceSession,
    method: &str,
    body: &[u8],
    token: &str,
) -> Reply {
    let tls = listener.tls(b"http/1.1").await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("TLS HTTP/1 handshake");
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let proof = proof_for(identity, method, PATH, token);
    let request = Request::builder()
        .method(method)
        .uri(PATH)
        .header("Host", "setup.example.com:9443")
        .header("Content-Type", "application/cbor")
        .header("Authorization", format!("DPoP {token}"))
        .header("DPoP", proof.as_str())
        .body(Body::from(body.to_vec()))
        .expect("TLS request");
    let response = sender.send_request(request).await.expect("TLS API response");
    let status = response.status().as_u16();
    let mut headers = String::new();
    for (field, value) in response.headers() {
        write!(headers, "{field}: {}\r\n", value.to_str().expect("HTTP header"))
            .expect("header text");
    }
    let body = response.into_body().collect().await.expect("bounded response").to_bytes().to_vec();
    drop(sender);
    task.abort();
    Reply { status, headers, body }
}

async fn put(
    listener: &Listener,
    identity: &LegacyDeviceSession,
    update: &SyncAccountKeyBundleUpdate,
) -> Reply {
    request(listener, identity, "PUT", &update.to_cbor().expect("canonical PUT"), &identity.token)
        .await
}

async fn pending(listener: &Listener, identity: &LegacyDeviceSession, body: &[u8]) -> Tls {
    pending_with_token(listener, identity, body, &identity.token).await
}

async fn pending_with_token(
    listener: &Listener,
    identity: &LegacyDeviceSession,
    body: &[u8],
    token: &str,
) -> Tls {
    let mut tls = listener.tls(b"http/1.1").await;
    let proof = proof_for(identity, "PUT", PATH, token);
    let headers = format!(
        "PUT {PATH} HTTP/1.1\r\nHost: setup.example.com:9443\r\nConnection: close\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nExpect: 100-continue\r\nAuthorization: DPoP {}\r\nDPoP: {}\r\n\r\n",
        body.len(),
        token,
        proof.as_str()
    );
    tls.write_all(headers.as_bytes()).await.expect("TLS streaming headers");
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

async fn release(mut tls: Tls, body: &[u8]) -> Reply {
    tls.write_all(body).await.expect("release streamed PUT");
    let mut bytes = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(15), tls.read_to_end(&mut bytes))
        .await
        .expect("bounded transaction")
        .expect("TLS response");
    let boundary = bytes.windows(4).position(|part| part == b"\r\n\r\n").expect("HTTP headers");
    let headers = std::str::from_utf8(&bytes[..boundary]).expect("header text").to_owned();
    let status =
        headers.split_whitespace().nth(1).expect("status").parse().expect("numeric status");
    Reply { status, headers, body: bytes[boundary + 4..].to_vec() }
}

async fn own(f: &Fixture, identity: &LegacyDeviceSession) -> Vec<u8> {
    f.backend
        .current_principal(identity.receipt.device_id.into_bytes())
        .await
        .expect("principal")
        .expect("active")
        .certificate
}

fn certificate(
    identity: &LegacyDeviceSession,
    device: Uuid,
    root: &Ed25519SigningKey,
    name: &str,
    client: &P256SigningKey,
) -> Vec<u8> {
    DeviceCertificate::issue(
        root,
        device,
        identity.receipt.account_id,
        client.public_key_sec1(),
        DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("KEM").public_key().to_vec(),
        name.into(),
        "windows".into(),
        1,
    )
    .expect("signed certificate")
    .encode()
    .expect("canonical certificate")
}

async fn statements(
    f: &Fixture,
    identity: &LegacyDeviceSession,
    certificates: &[Vec<u8>],
    revocations: &[Vec<u8>],
) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            store
                .replace_account_key_statements(
                    identity.receipt.account_id.into_bytes(),
                    certificates,
                    revocations,
                )
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .replace_account_key_statements(
                    identity.receipt.account_id.into_bytes(),
                    certificates,
                    revocations,
                )
                .await
        }
    }
    .expect("bounded account statements");
}

async fn identity_certificate(
    f: &Fixture,
    identity: &LegacyDeviceSession,
    certificate: &[u8],
    root: &Ed25519SigningKey,
) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("UPDATE identity_devices SET certificate=? WHERE device_id=?")
                .bind(certificate)
                .bind(identity.receipt.device_id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("certificate fixture");
            sqlx::query(
                "UPDATE identity_accounts SET account_signing_public_key=? WHERE account_id=?",
            )
            .bind(root.public_key().as_slice())
            .bind(identity.receipt.account_id.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("root fixture");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("UPDATE identity_devices SET certificate=$1 WHERE device_id=$2")
                .bind(certificate)
                .bind(identity.receipt.device_id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("certificate fixture");
            sqlx::query(
                "UPDATE identity_accounts SET account_signing_public_key=$1 WHERE account_id=$2",
            )
            .bind(root.public_key().as_slice())
            .bind(identity.receipt.account_id.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("root fixture");
        }
    }
    statements(f, identity, &[certificate.to_vec()], &[]).await;
}

#[allow(clippy::too_many_lines)]
async fn contract(mut f: Fixture) {
    let identity = legacy_device_session(&mut f).await;
    let listener = Listener::start(&mut f).await;
    let mut candidate = update(&identity, 2);
    let before = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    success(&put(&listener, &identity, &candidate).await, 2);
    assert_eq!(accepted_put(&f, &identity).await, Some(candidate.to_cbor().expect("accepted PUT")));
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before + 1);
    success(&put(&listener, &identity, &candidate).await, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before + 1);
    let mut different = candidate.clone();
    different.signature[0] ^= 1;
    denied(&put(&listener, &identity, &different).await, 409, "sync.conflict", false, true);
    different = candidate.clone();
    different.device_wraps[0].wrapped_ark.push(1);
    sign(&mut different, &signing());
    denied(&put(&listener, &identity, &different).await, 409, "sync.conflict", false, true);
    for revision in [1, 4, u64::MAX] {
        denied(
            &put(&listener, &identity, &update(&identity, revision)).await,
            409,
            "sync.conflict",
            false,
            true,
        );
    }
    candidate = update(&identity, 3);
    candidate.signature[0] ^= 1;
    denied(&put(&listener, &identity, &candidate).await, 400, "sync.invalid_request", false, false);
    let narrow = signed_token(
        &f,
        &identity,
        identity.receipt.account_id,
        identity.receipt.device_id,
        "keys:read",
    )
    .await;
    denied(
        &request(
            &listener,
            &identity,
            "PUT",
            &update(&identity, 3).to_cbor().expect("PUT"),
            &narrow,
        )
        .await,
        403,
        "policy.denied",
        false,
        false,
    );
    denied(
        &request(&listener, &identity, "PUT", &[], &identity.token).await,
        400,
        "sync.invalid_request",
        false,
        false,
    );
    let own = own(&f, &identity).await;
    let mut invalid_signature =
        certificate(&identity, Uuid::now_v7(), &signing(), "bad signature", &key(3));
    *invalid_signature.last_mut().expect("signature byte") ^= 1;
    for invalid in [vec![1], invalid_signature] {
        statements(&f, &identity, &[own.clone(), invalid], &[]).await;
        denied(
            &put(&listener, &identity, &update(&identity, 3)).await,
            503,
            "sync.storage_unavailable",
            false,
            true,
        );
    }
    statements(&f, &identity, std::slice::from_ref(&own), &[]).await;
    let inactive = Uuid::now_v7();
    let revoked = Uuid::now_v7();
    let inactive_cert = certificate(&identity, inactive, &signing(), "inactive recipient", &key(3));
    let revoked_cert = certificate(&identity, revoked, &signing(), "revoked recipient", &key(4));
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES (?,?,?,0,1)").bind(inactive.as_bytes().as_slice()).bind(identity.receipt.account_id.as_bytes().as_slice()).bind(&inactive_cert).execute(store.pool()).await.expect("inactive admission");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES ($1,$2,$3,false,1)").bind(inactive.as_bytes().as_slice()).bind(identity.receipt.account_id.as_bytes().as_slice()).bind(&inactive_cert).execute(store.pool()).await.expect("inactive admission");
        }
    }
    let revocation = RevocationStatement::issue(&signing(), revoked, 2, "removed".into())
        .expect("revocation")
        .encode()
        .expect("canonical revocation");
    statements(&f, &identity, &[own, inactive_cert, revoked_cert], &[revocation]).await;
    candidate = update(&identity, 3);
    denied(&put(&listener, &identity, &candidate).await, 400, "sync.invalid_request", false, false);
    candidate
        .device_wraps
        .push(SyncAccountDeviceWrap { device_id: inactive, wrapped_ark: vec![24] });
    sign(&mut candidate, &signing());
    let mut extra = candidate.clone();
    extra.device_wraps.push(SyncAccountDeviceWrap { device_id: revoked, wrapped_ark: vec![25] });
    sign(&mut extra, &signing());
    denied(&put(&listener, &identity, &extra).await, 400, "sync.invalid_request", false, false);
    success(&put(&listener, &identity, &candidate).await, 3);
    let reply = request(&listener, &identity, "GET", &[], &identity.token).await;
    assert_eq!(reply.status, 200);
    privacy(&reply);
    let bundle =
        SyncAccountKeyBundle::from_cbor(&reply.body).expect("device-scoped K-4 projection");
    assert_eq!(bundle.revision, 3);
    assert_eq!(bundle.wrapped_ark, vec![20]);
    assert_eq!(bundle.certificates.len(), 3);
    f.execute("UPDATE identity_devices SET active=false").await;
    denied(
        &put(&listener, &identity, &candidate).await,
        401,
        "auth.authentication_required",
        false,
        false,
    );
    drop(listener);
    f.cleanup().await;
}

async fn original_binding_and_roots(mut f: Fixture) {
    let identity = legacy_device_session(&mut f).await;
    let listener = Listener::start(&mut f).await;
    let original = own(&f, &identity).await;
    let candidate = update(&identity, 2);
    let body = candidate.to_cbor().expect("PUT");
    let tls = pending(&listener, &identity, &body).await;
    f.execute("UPDATE identity_devices SET active=false").await;
    denied(&release(tls, &body).await, 401, "auth.authentication_required", false, false);
    f.execute("UPDATE identity_devices SET active=true").await;
    for client in [&identity.client, &key(3)] {
        let tls = pending(&listener, &identity, &body).await;
        let replacement = certificate(
            &identity,
            identity.receipt.device_id,
            &signing(),
            "replacement certificate",
            client,
        );
        identity_certificate(&f, &identity, &replacement, &signing()).await;
        denied(&release(tls, &body).await, 401, "auth.authentication_required", false, false);
        identity_certificate(&f, &identity, &original, &signing()).await;
    }
    let tls = pending(&listener, &identity, &body).await;
    let peer =
        certificate(&identity, Uuid::now_v7(), &signing(), "new certified recipient", &key(3));
    statements(&f, &identity, &[original.clone(), peer], &[]).await;
    denied(&release(tls, &body).await, 400, "sync.invalid_request", false, false);
    statements(&f, &identity, std::slice::from_ref(&original), &[]).await;
    assert_eq!(f.count("SELECT revision FROM sync_account_key_bundles").await, 1);
    success(&put(&listener, &identity, &candidate).await, 2);
    let root = Ed25519SigningKey::from_bytes(&[8; 32]).expect("later root");
    let certificate = certificate(
        &identity,
        identity.receipt.device_id,
        &root,
        "later root certificate",
        &identity.client,
    );
    identity_certificate(&f, &identity, &certificate, &root).await;
    let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    success(&put(&listener, &identity, &candidate).await, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits);
    let mut next = update(&identity, 3);
    denied(&put(&listener, &identity, &next).await, 400, "sync.invalid_request", false, false);
    sign(&mut next, &root);
    success(&put(&listener, &identity, &next).await, 3);
    let mut left = update(&identity, 4);
    sign(&mut left, &root);
    let mut right = left.clone();
    right.recovery_blob.push(24);
    sign(&mut right, &root);
    let before = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    let (left, right) =
        tokio::join!(put(&listener, &identity, &left), put(&listener, &identity, &right));
    assert!(
        (left.status == 200 && right.status == 409) || (left.status == 409 && right.status == 200)
    );
    assert_eq!(f.count("SELECT revision FROM sync_account_key_bundles").await, 4);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before + 1);
    drop(listener);
    f.cleanup().await;
}

async fn rollback(mut f: Fixture) {
    let identity = legacy_device_session(&mut f).await;
    let original_put = accepted_put(&f, &identity).await.expect("seeded legacy accepted PUT");
    let listener = Listener::start(&mut f).await;
    let candidate = update(&identity, 2);
    let before = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    let (trigger, remove) = match &f.backend {
        AuthBackend::Sqlite(_) => (
            "CREATE TRIGGER publication_reject_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END",
            "DROP TRIGGER publication_reject_audit",
        ),
        AuthBackend::Postgres(_) => (
            "CREATE FUNCTION publication_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unavailable'; END $$; CREATE TRIGGER publication_reject_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION publication_reject_audit()",
            "DROP TRIGGER publication_reject_audit ON deployment_audit_events; DROP FUNCTION publication_reject_audit()",
        ),
    };
    f.execute(trigger).await;
    denied(
        &put(&listener, &identity, &candidate).await,
        503,
        "sync.storage_unavailable",
        false,
        true,
    );
    f.execute(remove).await;
    assert_eq!(f.count("SELECT revision FROM sync_account_key_bundles").await, 1);
    assert_eq!(accepted_put(&f, &identity).await, Some(original_put.clone()));
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before);
    let mut certificates = vec![own(&f, &identity).await];
    let mut candidate = candidate;
    for _ in 0..63 {
        let device = Uuid::now_v7();
        certificates.push(certificate(&identity, device, &signing(), &"x".repeat(65000), &key(3)));
        candidate
            .device_wraps
            .push(SyncAccountDeviceWrap { device_id: device, wrapped_ark: vec![24] });
    }
    statements(&f, &identity, &certificates, &[]).await;
    candidate.account_signing_key = vec![21; 65536];
    candidate.account_kem_key = vec![22; 65536];
    candidate.recovery_blob = vec![23; 65536];
    sign(&mut candidate, &signing());
    denied(&put(&listener, &identity, &candidate).await, 413, "sync.quota_exceeded", false, false);
    assert_eq!(f.count("SELECT revision FROM sync_account_key_bundles").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_account_key_device_wraps").await, 1);
    assert_eq!(accepted_put(&f, &identity).await, Some(original_put));
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before);
    drop(listener);
    f.cleanup().await;
}

async fn expiring_token(f: &Fixture, identity: &LegacyDeviceSession, expires_at: u64) -> String {
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let keyring = f.backend.keyring(&kms).await.expect("signing keys");
    let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("verification key");
    }
    let claims = DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: identity.receipt.account_id,
        did: identity.receipt.device_id,
        jti: Uuid::now_v7(),
        cnf_jkt: dpop_jwk_thumbprint(&identity.client.public_key_sec1()).expect("JKT"),
        org: vec![],
        scope: "keys:write".into(),
        iat: expires_at - 600,
        exp: expires_at,
    };
    DeviceAccessToken::sign(
        keyring.signing_key(),
        &trusted,
        keyring.signing_key().kid(),
        &identity.client.public_key_sec1(),
        &claims,
    )
    .expect("bounded expiring access token")
    .as_str()
    .to_owned()
}

async fn wait_for_expiry(expires_at: u64) {
    let deadline = UNIX_EPOCH + std::time::Duration::from_secs(expires_at);
    tokio::time::sleep(deadline.duration_since(SystemTime::now()).unwrap_or_default()).await;
    assert!(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() >= expires_at);
}

async fn body_expiry(mut f: Fixture) {
    let identity = legacy_device_session(&mut f).await;
    let listener = Listener::start(&mut f).await;
    let candidate = update(&identity, 2);
    let body = candidate.to_cbor().expect("PUT");
    for replay in [false, true] {
        if replay {
            success(&put(&listener, &identity, &candidate).await, 2);
        }
        let before = request(&listener, &identity, "GET", &[], &identity.token).await;
        let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
        let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() + 5;
        let token = expiring_token(&f, &identity, expires_at).await;
        let tls = pending_with_token(&listener, &identity, &body, &token).await;
        wait_for_expiry(expires_at).await;
        denied(&release(tls, &body).await, 401, "auth.authentication_required", false, false);
        let after = request(&listener, &identity, "GET", &[], &identity.token).await;
        assert_eq!(after.body, before.body);
        assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits);
    }
    drop(listener);
    f.cleanup().await;
}

#[cfg(feature = "postgres-integration")]
async fn locked_expiry(mut f: Fixture) {
    let identity = legacy_device_session(&mut f).await;
    let listener = Listener::start(&mut f).await;
    let AuthBackend::Postgres(store) = &f.backend else { unreachable!() };
    let candidate = update(&identity, 2);
    let body = candidate.to_cbor().expect("PUT");
    for replay in [false, true] {
        if replay {
            success(&put(&listener, &identity, &candidate).await, 2);
        }
        let before = request(&listener, &identity, "GET", &[], &identity.token).await;
        let audits = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
        let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() + 5;
        let token = expiring_token(&f, &identity, expires_at).await;
        let tls = pending_with_token(&listener, &identity, &body, &token).await;
        let mut lock = store.pool().begin().await.expect("owned lock transaction");
        let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await
            .expect("holder PID");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind(identity.receipt.account_id.as_bytes().as_slice())
            .execute(&mut *lock)
            .await
            .expect("hold account publication lock");
        let task_body = body.clone();
        let response = tokio::spawn(async move { release(tls, &task_body).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND (classid,objid,objsubid) IN (SELECT classid,objid,objsubid FROM pg_locks WHERE pid=$1 AND granted AND locktype='advisory')")
                    .bind(holder).fetch_one(store.pool()).await.expect("observe blocked publication");
                if waiting > 0 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("PUT must wait on this account lock before expiry");
        wait_for_expiry(expires_at).await;
        lock.commit().await.expect("release owned lock");
        denied(
            &response.await.expect("blocked PUT task"),
            401,
            "auth.authentication_required",
            false,
            false,
        );
        let after = request(&listener, &identity, "GET", &[], &identity.token).await;
        assert_eq!(after.body, before.body);
        assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, audits);
    }
    drop(listener);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_https_personal_key_body_expiry_denies_new_update_and_exact_replay() {
    body_expiry(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_https_personal_key_body_expiry_denies_new_update_and_exact_replay() {
    body_expiry(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_https_personal_key_lock_wait_expiry_denies_new_update_and_exact_replay() {
    locked_expiry(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_https_personal_key_publication_contract() {
    contract(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_https_personal_key_original_binding_and_old_root_replay() {
    original_binding_and_roots(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_https_personal_key_audit_and_capacity_rollback() {
    rollback(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_https_personal_key_publication_contract() {
    contract(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_https_personal_key_original_binding_and_old_root_replay() {
    original_binding_and_roots(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_https_personal_key_audit_and_capacity_rollback() {
    rollback(Fixture::postgres().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_https_personal_key_lost_commit_ack_and_explicit_replay() {
    use std::sync::atomic::Ordering;
    let mut f = Fixture::postgres().await;
    let identity = legacy_device_session(&mut f).await;
    let (_, schema) = f.postgres.as_ref().expect("owned schema");
    let mut url =
        Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PG database"))
            .expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let proxied = Arc::new(
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store"),
    );
    let original = f.backend.clone();
    f.backend = AuthBackend::Postgres(proxied.clone());
    let listener = Listener::start(&mut f).await;
    f.backend = original;
    let candidate = update(&identity, 2);
    let body = candidate.to_cbor().expect("PUT");
    let before = f.count("SELECT COUNT(*) FROM deployment_audit_events").await;
    let tls = pending(&listener, &identity, &body).await;
    proxy.armed.store(true, Ordering::SeqCst);
    denied(&release(tls, &body).await, 503, "sync.storage_unavailable", true, false);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(accepted_put(&f, &identity).await, Some(body.clone()));
    assert_eq!(f.count("SELECT revision FROM sync_account_key_bundles").await, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before + 1);
    let projection = request(&listener, &identity, "GET", &[], &identity.token).await;
    assert_eq!(
        SyncAccountKeyBundle::from_cbor(&projection.body)
            .expect("verified projection codec")
            .revision,
        2
    );
    success(&put(&listener, &identity, &candidate).await, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before + 1);
    let tls = pending(&listener, &identity, &body).await;
    proxy.armed.store(true, Ordering::SeqCst);
    denied(&release(tls, &body).await, 503, "sync.storage_unavailable", false, true);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    assert_eq!(accepted_put(&f, &identity).await, Some(body));
    assert_eq!(f.count("SELECT COUNT(*) FROM deployment_audit_events").await, before + 1);
    success(&put(&listener, &identity, &candidate).await, 2);
    let mut altered = candidate;
    altered.signature[0] ^= 1;
    denied(&put(&listener, &identity, &altered).await, 409, "sync.conflict", false, true);
    drop(listener);
    proxied.pool().close().await;
    drop(proxied);
    drop(proxy);
    f.cleanup().await;
}
