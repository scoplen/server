// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::{
    auth::{AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthTokenResponse},
    personal_enrollment::{
        PersonalEnrollmentRequest, PersonalEnrollmentResponse, PersonalInvitationResponse,
    },
    sync::{
        SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundleUpdate, SyncAckRequest,
        SyncAckResponse, SyncChangesResponse, SyncSessionRequest, SyncSessionResponse,
        SyncVaultKeysResponse, SyncWrite, SyncWriteBatch, SyncWriteBatchResponse,
    },
};
use scoplen_crypto::{
    DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, ObjectEnvelope,
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext, SecretBytes,
};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};
use scoplen_store::{ObjectStorage, ObjectStorageConfig};
use std::fmt::Write as _;

use crate::runtime::{ListenerDatabase, api_router};

#[path = "account_devices_tests.rs"]
mod account_devices;
#[path = "account_profile_tests.rs"]
mod account_profile;

async fn mount_complete_api(f: &mut Fixture) {
    f.server.abort();
    let _ = (&mut f.server).await;
    let storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
        root: f.directory.join("objects"),
    })
    .expect("object storage");
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let database = match &f.backend {
        AuthBackend::Sqlite(store) => ListenerDatabase::Sqlite(store.clone()),
        AuthBackend::Postgres(store) => ListenerDatabase::Postgres(store.clone()),
    };
    let app = api_router(database, Arc::new(storage), Arc::new(kms), ORIGIN.into(), true);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    f.address = listener.local_addr().expect("address");
    f.server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("complete API");
    });
}

async fn protected(
    f: &Fixture,
    method: &str,
    path: &str,
    body: &[u8],
    token: &str,
    client: &P256SigningKey,
) -> Reply {
    let target = DpopTarget::new(method, ORIGIN, path.split('?').next().expect("path"))
        .expect("protected target");
    let proof = DpopProof::sign(
        client,
        &client.public_key_sec1(),
        &target,
        DpopToken::Protected(token),
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs(),
        None,
    )
    .expect("protected proof");
    http_method(
        f.address,
        method,
        path,
        body,
        &[
            (
                "Content-Type",
                if path.starts_with("/sync/") { "application/cbor" } else { "application/json" },
            ),
            ("Origin", ORIGIN),
            ("Authorization", &format!("DPoP {token}")),
            ("DPoP", proof.as_str()),
        ],
    )
    .await
}

fn enrollment(token: [u8; 32], client: &P256SigningKey) -> PersonalEnrollmentRequest {
    let account = Uuid::now_v7();
    let device = Uuid::now_v7();
    let signing = Ed25519SigningKey::from_bytes(&[7; 32]).expect("account signing key");
    let kem = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("device KEM");
    let mut request = PersonalEnrollmentRequest {
        invitation_token: token,
        account_id: account,
        personal_vault_id: Uuid::now_v7(),
        account_signing_public_key: signing.public_key(),
        account_kem_public_key: [4; 32],
        key_bundle_update: SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![SyncAccountDeviceWrap { device_id: device, wrapped_ark: vec![5] }],
            account_signing_key: vec![6],
            account_kem_key: vec![7],
            recovery_blob: vec![8],
            signature: vec![0; 64],
        },
        device_certificate: DeviceCertificate::issue(
            &signing,
            device,
            account,
            client.public_key_sec1(),
            kem.public_key().to_vec(),
            "first Personal device".into(),
            "windows".into(),
            1,
        )
        .expect("account-signed device certificate"),
        wrapped_personal_vault_key: vec![9],
        device_signature: [0; 64],
    };
    request.key_bundle_update.signature = signing
        .sign(&request.key_bundle_update.signature_input().expect("K-4 signing input"))
        .to_vec();
    let bundle = request.key_bundle_update.to_cbor().expect("canonical K-4 bundle");
    let certificate = request.device_certificate.encode().expect("canonical K-2 certificate");
    request.device_signature = PersonalEnrollmentContext::new(
        ORIGIN,
        &token,
        account,
        request.personal_vault_id,
        PersonalEnrollmentArtifacts {
            account_signing_public_key: &request.account_signing_public_key,
            account_kem_public_key: &request.account_kem_public_key,
            key_bundle_update: &bundle,
            device_certificate: &certificate,
            wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
        },
    )
    .expect("enrollment possession context")
    .sign(client)
    .expect("device possession proof");
    request
}

async fn authenticate_device(f: &Fixture, device: Uuid, client: &P256SigningKey) -> String {
    let body = AuthChallengeRequest::new(device).expect("challenge").to_json().expect("JSON");
    let reply = http(
        f.address,
        "/api/v1/auth/challenge",
        body.as_bytes(),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(reply.status, 200);
    let challenge = AuthChallengeResponse::from_json(reply.text()).expect("challenge response");
    let context = DeviceAuthContext::new(ORIGIN, &challenge.nonce, device).expect("auth context");
    let mut signature = String::new();
    for byte in client.sign(&context.signature_input()) {
        write!(signature, "{byte:02x}").expect("hex signature");
    }
    let body = AuthDeviceRequest::new(device, &challenge.nonce, signature)
        .expect("device request")
        .to_json()
        .expect("JSON");
    let reply = http(
        f.address,
        "/api/v1/auth/device",
        body.as_bytes(),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(reply.status, 200);
    assert!(reply.header("set-cookie").is_none());
    AuthTokenResponse::from_json(reply.text()).expect("native device token").access_token
}

async fn session_and_keys(
    f: &Fixture,
    receipt: &PersonalEnrollmentResponse,
    token: &str,
    client: &P256SigningKey,
) {
    let device = receipt.device_id;
    let vault = receipt.personal_vault_id;
    let session =
        SyncSessionRequest { client_version: "0.1.0".into(), model_version: 1, device_id: device }
            .to_cbor()
            .expect("session");
    let reply = protected(f, "POST", "/sync/v1/session", &session, token, client).await;
    assert_eq!(reply.status, 200);
    let session = SyncSessionResponse::from_cbor(&reply.body).expect("session response");
    assert_eq!(session.vaults.len(), 1);
    assert_eq!(session.vaults[0].id, vault);
    let reply = protected(f, "GET", "/sync/v1/keys", &[], token, client).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        SyncAccountKeyBundle::from_cbor(&reply.body).expect("persisted K-4").wrapped_ark,
        vec![5]
    );
    let reply =
        protected(f, "GET", &format!("/sync/v1/vaults/{vault}/keys"), &[], token, client).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        SyncVaultKeysResponse::from_cbor(&reply.body).expect("vault key").keys[0].wrapped_vault_key,
        vec![9]
    );
}

async fn sync_object(
    f: &Fixture,
    receipt: &PersonalEnrollmentResponse,
    token: &str,
    client: &P256SigningKey,
) {
    let device = receipt.device_id;
    let vault = receipt.personal_vault_id;
    let id = Uuid::now_v7();
    let mut object = Object::new(id, ObjectType::HOST, 1).expect("host");
    for (field, value) in [(1, "Production"), (2, "host.example.com")] {
        object
            .insert(
                FieldPath::field(field).expect("field"),
                FieldEntry::new(
                    cbor::Value::Text(value.into()),
                    Hlc::at(1).expect("clock"),
                    device,
                )
                .expect("field entry"),
            )
            .expect("host field");
    }
    let vault_key = SecretBytes::new([8; 32]);
    let payload = ObjectEnvelope::encrypt(vault, 1, &object, &vault_key, device, client)
        .expect("encrypted signed host")
        .encode()
        .expect("envelope");
    let body = SyncWriteBatch {
        writes: vec![SyncWrite {
            object_id: id,
            base_seq: None,
            payload: payload.clone(),
            tombstone: false,
        }],
    }
    .to_cbor()
    .expect("write");
    let reply =
        protected(f, "POST", &format!("/sync/v1/vaults/{vault}/objects"), &body, token, client)
            .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        SyncWriteBatchResponse::from_cbor(&reply.body).expect("assignment").assignments[0].seq,
        1
    );
    let reply = protected(
        f,
        "GET",
        &format!("/sync/v1/vaults/{vault}/changes?after=0&limit=10"),
        &[],
        token,
        client,
    )
    .await;
    assert_eq!(reply.status, 200);
    let changes = SyncChangesResponse::from_cbor(&reply.body).expect("changes");
    assert_eq!(changes.changes.len(), 1);
    assert_eq!(changes.next_cursor, 1);
    assert_eq!(changes.changes[0].payload, payload);
    let decrypted = ObjectEnvelope::decode(&changes.changes[0].payload)
        .expect("stored envelope")
        .decrypt(vault, id, &vault_key, &client.public_key_sec1())
        .expect("verify signature and decrypt downloaded host");
    assert_eq!(
        decrypted.encode().expect("downloaded object"),
        object.encode().expect("original object")
    );
    let body = SyncAckRequest { cursor: changes.next_cursor }.to_cbor().expect("ACK");
    let reply =
        protected(f, "POST", &format!("/sync/v1/vaults/{vault}/ack"), &body, token, client).await;
    assert_eq!(reply.status, 200);
    assert_eq!(SyncAckResponse::from_cbor(&reply.body).expect("durable ACK").cursor, 1);
    assert_eq!(f.count("SELECT cursor FROM sync_acks").await, 1);
}

struct PersonalBootstrap {
    receipt: PersonalEnrollmentResponse,
    token: String,
    client: P256SigningKey,
    operator_token: String,
    operator_key: P256SigningKey,
}

async fn bootstrap_personal(f: &mut Fixture) -> PersonalBootstrap {
    mount_complete_api(f).await;
    let browser = key(1);
    let (mut authenticator, _) = f.enroll(&browser).await;
    let session = f.login(&mut authenticator, &browser).await.session();
    let reply = protected(
        f,
        "POST",
        "/api/v1/admin/personal-invitations",
        b"{}",
        &session.access_token,
        &browser,
    )
    .await;
    assert_eq!(reply.status, 201);
    reply.privacy();
    let invitation =
        PersonalInvitationResponse::from_json(&reply.body).expect("one-time invitation");
    let token = URL_SAFE_NO_PAD
        .decode(invitation.invitation_url.split("#token=").nth(1).expect("fragment"))
        .expect("canonical token")
        .try_into()
        .expect("32-byte invitation");
    let client = key(2);
    let request = enrollment(token, &client);
    let body = request.to_json().expect("enrollment JSON");
    let reply = http(
        f.address,
        "/api/v1/auth/personal-enroll",
        &body,
        &[("Content-Type", "application/json"), ("Origin", ORIGIN)],
    )
    .await;
    assert_eq!(reply.status, 201);
    assert!(reply.header("set-cookie").is_none());
    let receipt = PersonalEnrollmentResponse::from_json(&reply.body).expect("enrollment result");
    assert_eq!(receipt.account_id, request.account_id);
    assert_eq!(receipt.device_id, request.device_certificate.device_id);
    assert_eq!(receipt.personal_vault_id, request.personal_vault_id);
    assert_eq!(f.count("SELECT COUNT(*) FROM identity_accounts").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM identity_devices").await, 1);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM personal_invitations WHERE consumed_at_ms IS NOT NULL").await,
        1
    );
    let token = authenticate_device(f, receipt.device_id, &client).await;
    PersonalBootstrap {
        receipt,
        token,
        client,
        operator_token: session.access_token,
        operator_key: browser,
    }
}

async fn complete_flow(mut f: Fixture) {
    let PersonalBootstrap { receipt, token, client, .. } = bootstrap_personal(&mut f).await;
    let reply = protected(&f, "GET", "/api/v1/accounts/me", &[], &token, &client).await;
    assert_eq!(reply.status, 200);
    let profile = scoplen_api::account_profile::AccountProfile::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("bounded authenticated account profile");
    assert_eq!(profile.id, receipt.account_id);
    assert_eq!(profile.email, None);
    let reply = protected(&f, "GET", "/api/v1/accounts/me/devices", &[], &token, &client).await;
    assert_eq!(reply.status, 200);
    let devices = scoplen_api::account_devices::AccountDeviceStatements::from_http_json(
        &reply.body,
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("complete authenticated device statements");
    assert_eq!(devices.account_id, receipt.account_id);
    assert_eq!(devices.certificates.len(), 1);
    assert_eq!(devices.revocations, Vec::<Vec<u8>>::new());
    assert_eq!(
        DeviceCertificate::decode(&devices.certificates[0]).expect("signed certificate").device_id,
        receipt.device_id
    );
    session_and_keys(&f, &receipt, &token, &client).await;
    sync_object(&f, &receipt, &token, &client).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM operator_refresh_families").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM device_refresh_families").await, 1);
    let audit = match &f.backend {
        AuthBackend::Sqlite(store) => store.verify_deployment_audit_chain().await,
        AuthBackend::Postgres(store) => store.verify_deployment_audit_chain().await,
    };
    audit.expect("verified full deployment audit").expect("nonempty audit chain");
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_public_personal_bootstrap_and_sync() {
    complete_flow(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_public_personal_bootstrap_and_sync() {
    complete_flow(Fixture::postgres().await).await;
}
