// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use account_profile::{proof_for, signed_token};
use scoplen_api::{
    account_devices::{AccountDeviceStatements, MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES},
    auth::INITIAL_DEVICE_ACCESS_SCOPE,
};
use scoplen_crypto::RevocationStatement;
use scoplen_store::device_authentication::{CurrentPrincipal, DeviceAuthenticationError};

const PATH: &str = "/api/v1/accounts/me/devices";

fn decode(reply: &Reply) -> AccountDeviceStatements {
    assert_eq!(reply.status, 200, "device snapshot status");
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.header("etag").is_none());
    reply.privacy();
    let result = AccountDeviceStatements::from_http_json(
        &reply.body,
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("complete bounded signed snapshot");
    let json: serde_json::Value = serde_json::from_slice(&reply.body).expect("JSON");
    assert_eq!(json.as_object().expect("snapshot object").len(), 3);
    assert!(!format!("{result:?}").contains("Personal device"));
    result
}

fn denied(reply: &Reply, status: u16, code: &str) {
    reply.problem(status, code, false, status == 503);
    assert!(reply.header("etag").is_none());
    for private in ["account_id", "device_id", "certificates", "revocations", "private device"] {
        assert!(!reply.text().contains(private));
    }
}

fn certificate(account: Uuid, device: Uuid, name: &str) -> Vec<u8> {
    DeviceCertificate::issue(
        &Ed25519SigningKey::from_bytes(&[7; 32]).expect("account key"),
        device,
        account,
        key(3).public_key_sec1(),
        DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("KEM").public_key().to_vec(),
        name.into(),
        "windows".into(),
        1,
    )
    .expect("signed certificate")
    .encode()
    .expect("canonical certificate")
}

fn revocation(device: Uuid, reason: &str) -> Vec<u8> {
    RevocationStatement::issue(
        &Ed25519SigningKey::from_bytes(&[7; 32]).expect("account key"),
        device,
        2,
        reason.into(),
    )
    .expect("signed revocation")
    .encode()
    .expect("canonical revocation")
}

async fn replace(f: &Fixture, account: Uuid, certificates: &[Vec<u8>], revocations: &[Vec<u8>]) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            store
                .replace_account_key_statements(account.into_bytes(), certificates, revocations)
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .replace_account_key_statements(account.into_bytes(), certificates, revocations)
                .await
        }
    }
    .expect("replace bounded statement fixture");
}

async fn store_read(
    f: &Fixture,
    expected: &CurrentPrincipal,
) -> Result<AccountDeviceStatements, DeviceAuthenticationError> {
    match &f.backend {
        AuthBackend::Sqlite(store) => store.read_account_device_statements(expected).await,
        AuthBackend::Postgres(store) => store.read_account_device_statements(expected).await,
    }
}

async fn roundtrip(f: &Fixture, identity: &PersonalBootstrap) -> Vec<u8> {
    let initial = decode(&protected(f, "GET", PATH, &[], &identity.token, &identity.client).await);
    assert_eq!(initial.account_id, identity.receipt.account_id);
    assert_eq!(initial.certificates.len(), 1);
    assert_eq!(initial.revocations, Vec::<Vec<u8>>::new());
    let own = initial.certificates[0].clone();
    let inactive = Uuid::now_v7();
    let revoked = Uuid::now_v7();
    let inactive_certificate = certificate(identity.receipt.account_id, inactive, "private device");
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES (?,?,?,0,1)")
                .bind(inactive.as_bytes().as_slice()).bind(identity.receipt.account_id.as_bytes().as_slice())
                .bind(&inactive_certificate).execute(store.pool()).await.expect("inactive peer fixture");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES ($1,$2,$3,false,1)")
                .bind(inactive.as_bytes().as_slice()).bind(identity.receipt.account_id.as_bytes().as_slice())
                .bind(&inactive_certificate).execute(store.pool()).await.expect("inactive peer fixture");
        }
    }
    let mut certificates = vec![
        own.clone(),
        inactive_certificate,
        certificate(identity.receipt.account_id, revoked, "revoked peer"),
    ];
    let mut revocations =
        vec![revocation(revoked, "lost"), revocation(Uuid::now_v7(), "old device")];
    certificates.sort();
    revocations.sort();
    replace(f, identity.receipt.account_id, &certificates, &revocations).await;
    let other = Uuid::now_v7();
    replace(f, other, &[certificate(other, Uuid::now_v7(), "other account")], &[]).await;
    let snapshot = decode(&protected(f, "GET", PATH, &[], &identity.token, &identity.client).await);
    assert_eq!(snapshot.account_id, identity.receipt.account_id);
    assert_eq!(snapshot.certificates, certificates);
    assert_eq!(snapshot.revocations, revocations);
    assert_eq!(
        protected(f, "GET", PATH, &[], &identity.token, &identity.client).await.body,
        snapshot.to_json().expect("deterministic JSON")
    );
    let proof = proof_for(identity, "GET", PATH, &identity.token);
    let conditional = http_method(
        f.address,
        "GET",
        PATH,
        &[],
        &[
            ("Authorization", &format!("DPoP {}", identity.token)),
            ("DPoP", proof.as_str()),
            ("If-None-Match", "*"),
        ],
    )
    .await;
    decode(&conditional);
    assert_eq!(conditional.body, snapshot.to_json().expect("unconditional complete body"));
    replace(f, identity.receipt.account_id, std::slice::from_ref(&own), &[]).await;
    own
}

async fn rejected_requests(f: &Fixture, identity: &PersonalBootstrap) {
    denied(
        &http_method(f.address, "GET", PATH, &[], &[]).await,
        401,
        "auth.authentication_required",
    );
    denied(
        &protected(f, "GET", PATH, &[], &identity.operator_token, &identity.operator_key).await,
        401,
        "auth.authentication_required",
    );
    for (account, device, scope, status) in [
        (identity.receipt.account_id, identity.receipt.device_id, "sync:read", 403),
        (identity.receipt.account_id, identity.receipt.device_id, "keys:write", 403),
        (identity.receipt.account_id, identity.receipt.device_id, "Account:read", 403),
        (Uuid::now_v7(), identity.receipt.device_id, INITIAL_DEVICE_ACCESS_SCOPE, 401),
        (identity.receipt.account_id, Uuid::now_v7(), INITIAL_DEVICE_ACCESS_SCOPE, 401),
    ] {
        let token = signed_token(f, identity, account, device, scope).await;
        denied(
            &protected(f, "GET", PATH, &[], &token, &identity.client).await,
            status,
            if status == 403 { "policy.denied" } else { "auth.authentication_required" },
        );
    }
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &key(4)).await,
        401,
        "auth.authentication_required",
    );
    let authorization = format!("DPoP {}", identity.token);
    for proof in [
        proof_for(identity, "POST", PATH, &identity.token),
        proof_for(identity, "GET", "/api/v1/accounts/me", &identity.token),
        proof_for(identity, "GET", PATH, "different-token"),
    ] {
        denied(
            &http_method(
                f.address,
                "GET",
                PATH,
                &[],
                &[("Authorization", &authorization), ("DPoP", proof.as_str())],
            )
            .await,
            401,
            "auth.authentication_required",
        );
    }
    let proof = proof_for(identity, "GET", PATH, &identity.token);
    let headers = [("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
    decode(&http_method(f.address, "GET", PATH, &[], &headers).await);
    denied(
        &http_method(f.address, "GET", PATH, &[], &headers).await,
        401,
        "auth.authentication_required",
    );
    for duplicate in ["Authorization", "DPoP"] {
        let proof = proof_for(identity, "GET", PATH, &identity.token);
        let mut headers = vec![("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
        headers.push((
            duplicate,
            if duplicate == "DPoP" { proof.as_str() } else { authorization.as_str() },
        ));
        denied(
            &http_method(f.address, "GET", PATH, &[], &headers).await,
            401,
            "auth.authentication_required",
        );
    }
    for (extra, status) in [
        (vec![("Origin", "null")], 403),
        (vec![("Origin", "https://other.example")], 403),
        (vec![("Origin", ORIGIN), ("Origin", ORIGIN)], 403),
        (vec![("Idempotency-Key", "test")], 400),
        (vec![("If-Match", "\"test\"")], 400),
    ] {
        let proof = proof_for(identity, "GET", PATH, &identity.token);
        let mut headers = vec![("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
        headers.extend(extra);
        denied(
            &http_method(f.address, "GET", PATH, &[], &headers).await,
            status,
            if status == 403 { "policy.denied" } else { "auth.invalid_request" },
        );
    }
    for query in ["?", "?limit=1", "?cursor=x", "?account_id=x", "?filter=x", "?sort=x"] {
        denied(
            &protected(f, "GET", &format!("{PATH}{query}"), &[], &identity.token, &identity.client)
                .await,
            400,
            "auth.invalid_request",
        );
    }
    denied(
        &protected(f, "GET", PATH, b"{}", &identity.token, &identity.client).await,
        400,
        "auth.invalid_request",
    );
}

async fn invalid_statements(f: &Fixture, identity: &PersonalBootstrap, own: &[u8]) {
    let peer = Uuid::now_v7();
    let good = certificate(identity.receipt.account_id, peer, "private device");
    let mut signature = good.clone();
    *signature.last_mut().expect("signature byte") ^= 1;
    for extra in [vec![1], signature, certificate(Uuid::now_v7(), peer, "different account")] {
        replace(f, identity.receipt.account_id, &[own.to_vec(), extra], &[]).await;
        denied(
            &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
            503,
            "auth.storage_unavailable",
        );
        let narrow = signed_token(
            f,
            identity,
            identity.receipt.account_id,
            identity.receipt.device_id,
            "sync:read",
        )
        .await;
        denied(
            &protected(f, "GET", PATH, &[], &narrow, &identity.client).await,
            403,
            "policy.denied",
        );
    }
    replace(
        f,
        identity.receipt.account_id,
        &[
            own.to_vec(),
            good.clone(),
            certificate(identity.receipt.account_id, peer, "second certificate"),
        ],
        &[],
    )
    .await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    let mut invalid_signature = revocation(peer, "invalid signature");
    *invalid_signature.last_mut().expect("signature byte") ^= 1;
    for revocations in [
        vec![vec![1]],
        vec![invalid_signature],
        vec![revocation(peer, "one"), revocation(peer, "two")],
    ] {
        replace(f, identity.receipt.account_id, &[own.to_vec(), good.clone()], &revocations).await;
        denied(
            &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
            503,
            "auth.storage_unavailable",
        );
    }
    replace(f, identity.receipt.account_id, &[own.to_vec()], &[]).await;
}

async fn stale_identity(f: &Fixture, identity: &PersonalBootstrap, own: &[u8]) {
    let mut principal = f
        .backend
        .current_principal(identity.receipt.device_id.into_bytes())
        .await
        .expect("principal")
        .expect("enrolled");
    principal.account_id = Uuid::now_v7().into_bytes();
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    principal.account_id = identity.receipt.account_id.into_bytes();
    principal.jkt = "different-key".into();
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    let principal = f
        .backend
        .current_principal(identity.receipt.device_id.into_bytes())
        .await
        .expect("principal")
        .expect("enrolled");
    f.execute("UPDATE identity_devices SET active=false").await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    f.execute("UPDATE identity_devices SET active=true").await;
    replace(
        f,
        identity.receipt.account_id,
        &[own.to_vec()],
        &[revocation(identity.receipt.device_id, "lost")],
    )
    .await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    replace(f, identity.receipt.account_id, &[own.to_vec()], &[]).await;
    replace(f, identity.receipt.account_id, &[], &[]).await;
    denied(
        &protected(f, "GET", PATH, &[], &identity.token, &identity.client).await,
        401,
        "auth.authentication_required",
    );
    assert!(matches!(
        store_read(f, &principal).await,
        Err(DeviceAuthenticationError::Denied { changed: false })
    ));
    replace(f, identity.receipt.account_id, &[own.to_vec()], &[]).await;
}

async fn admission_changes_during_request(f: &Fixture, identity: &PersonalBootstrap) {
    let mut stream = tokio::net::TcpStream::connect(f.address).await.expect("TCP");
    let proof = proof_for(identity, "GET", PATH, &identity.token);
    let request = format!(
        "GET {PATH} HTTP/1.1\r\nHost: setup.example.com:9443\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nAuthorization: DPoP {}\r\nDPoP: {}\r\n\r\n",
        identity.token,
        proof.as_str(),
    );
    stream.write_all(request.as_bytes()).await.expect("pending headers");
    // Hyper emits 100 only when the authenticated handler starts polling the request body.
    let mut interim = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !interim.ends_with(b"\r\n\r\n") {
            interim.push(stream.read_u8().await.expect("interim response"));
            assert!(interim.len() <= 256);
        }
    })
    .await
    .expect("authentication must finish before the body is released");
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue\r\n"));
    f.execute("UPDATE identity_devices SET active=false").await;
    stream.write_all(b"0\r\n\r\n").await.expect("complete empty body");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("HTTP denial");
    let boundary = bytes.windows(4).position(|part| part == b"\r\n\r\n").expect("headers");
    let headers = std::str::from_utf8(&bytes[..boundary]).expect("HTTP headers").to_owned();
    let status =
        headers.split_whitespace().nth(1).expect("HTTP status").parse().expect("numeric status");
    let reply = Reply { status, headers, body: bytes[boundary + 4..].to_vec() };
    denied(&reply, 401, "auth.authentication_required");
    f.execute("UPDATE identity_devices SET active=true").await;
}

async fn contract(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let own = roundtrip(&f, &identity).await;
    rejected_requests(&f, &identity).await;
    invalid_statements(&f, &identity, &own).await;
    stale_identity(&f, &identity, &own).await;
    admission_changes_during_request(&f, &identity).await;
    f.execute("DELETE FROM sync_account_key_bundles").await;
    denied(
        &protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    match &f.backend {
        AuthBackend::Sqlite(store) => store.pool().close().await,
        AuthBackend::Postgres(store) => store.pool().close().await,
    }
    denied(
        &protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    f.cleanup().await;
}

async fn concurrent_snapshots(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let initial = decode(&protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await);
    let own = initial.certificates[0].clone();
    let account = identity.receipt.account_id;
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    let mut a = vec![own.clone(), certificate(account, first, "first snapshot")];
    let mut b = vec![own.clone(), certificate(account, second, "second snapshot")];
    a.sort();
    b.sort();
    let ar = vec![revocation(first, "first snapshot")];
    let br = vec![revocation(second, "second snapshot")];
    replace(&f, account, &a, &ar).await;
    let principal = f
        .backend
        .current_principal(identity.receipt.device_id.into_bytes())
        .await
        .expect("current")
        .expect("enrolled");
    let writer = async {
        for index in 0..32 {
            let (certificates, revocations) = if index % 2 == 0 { (&b, &br) } else { (&a, &ar) };
            replace(&f, account, certificates, revocations).await;
            // This shares the production account-key lock with the statement replacement.
            let update = scoplen_store::account_keys::AccountKeyBundleUpdate {
                revision: index + 2,
                device_wraps: vec![scoplen_store::account_keys::DeviceWrap {
                    device_id: identity.receipt.device_id.into_bytes(),
                    wrapped_ark: vec![5],
                }],
                account_signing_key: vec![6],
                account_kem_key: vec![7],
                recovery_blob: vec![8],
                signature: [0; 64],
            };
            match &f.backend {
                AuthBackend::Sqlite(store) => {
                    store.put_account_key_bundle(account.into_bytes(), &update).await
                }
                AuthBackend::Postgres(store) => {
                    store.put_account_key_bundle(account.into_bytes(), &update).await
                }
            }
            .expect("concurrent bundle revision");
            tokio::task::yield_now().await;
        }
    };
    let reader = async {
        for _ in 0..64 {
            let snapshot = store_read(&f, &principal).await.expect("complete concurrent snapshot");
            assert!(
                (snapshot.certificates == a && snapshot.revocations == ar)
                    || (snapshot.certificates == b && snapshot.revocations == br),
                "mixed statement generations"
            );
            tokio::task::yield_now().await;
        }
    };
    tokio::join!(writer, reader);
    f.cleanup().await;
}

fn sized_certificate(account: Uuid, size: usize) -> Vec<u8> {
    let device = Uuid::now_v7();
    let mut name = String::new();
    for _ in 0..5 {
        let result = certificate(account, device, &name);
        match result.len().cmp(&size) {
            std::cmp::Ordering::Equal => return result,
            std::cmp::Ordering::Less => name.push_str(&"x".repeat(size - result.len())),
            std::cmp::Ordering::Greater => name.truncate(name.len() - (result.len() - size)),
        }
    }
    panic!("could not build exact artifact boundary");
}

async fn insert_certificate(f: &Fixture, account: Uuid, bytes: &[u8]) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query(
                "INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES (?,?)",
            )
            .bind(account.as_bytes().as_slice())
            .bind(bytes)
            .execute(store.pool())
            .await
            .expect("persist boundary fixture");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query(
                "INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES ($1,$2)",
            )
            .bind(account.as_bytes().as_slice())
            .bind(bytes)
            .execute(store.pool())
            .await
            .expect("persist boundary fixture");
        }
    }
}

async fn bounds(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let initial = decode(&protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await);
    let account = identity.receipt.account_id;
    let large = sized_certificate(account, MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES);
    insert_certificate(&f, account, &large).await;
    let snapshot =
        decode(&protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await);
    assert!(snapshot.certificates.contains(&large));
    // Simulate a damaged/externally-written database that bypassed K-4's mutation capacity gate.
    for _ in 0..63 {
        insert_certificate(
            &f,
            account,
            &sized_certificate(account, MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES),
        )
        .await;
    }
    denied(
        &protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    replace(&f, account, &initial.certificates, &[]).await;
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            let mut connection = store.pool().acquire().await.expect("owned fixture connection");
            sqlx::query("PRAGMA ignore_check_constraints=ON")
                .execute(&mut *connection)
                .await
                .expect("allow corruption fixture");
            sqlx::query(
                "INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES (?,?)",
            )
            .bind(account.as_bytes().as_slice())
            .bind(vec![1; MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES + 1])
            .execute(&mut *connection)
            .await
            .expect("oversized stored artifact");
            sqlx::query("PRAGMA ignore_check_constraints=OFF")
                .execute(&mut *connection)
                .await
                .expect("restore checks");
        }
        AuthBackend::Postgres(store) => {
            // The schema belongs exclusively to this fixture and is dropped by cleanup.
            sqlx::query("ALTER TABLE sync_account_key_certificates DROP CONSTRAINT sync_account_key_certificates_certificate_check")
                .execute(store.pool()).await.expect("allow corruption fixture");
            insert_certificate(&f, account, &vec![1; MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES + 1]).await;
        }
    }
    denied(
        &protected(&f, "GET", PATH, &[], &identity.token, &identity.client).await,
        503,
        "auth.storage_unavailable",
    );
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_current_account_device_statements_contract() {
    contract(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_current_account_device_statements_contract() {
    contract(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_current_account_device_statements_concurrent_snapshots() {
    concurrent_snapshots(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_current_account_device_statements_concurrent_snapshots() {
    concurrent_snapshots(Fixture::postgres().await).await;
}

#[tokio::test]
async fn sqlite_current_account_device_statements_bounds() {
    bounds(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_current_account_device_statements_bounds() {
    bounds(Fixture::postgres().await).await;
}
