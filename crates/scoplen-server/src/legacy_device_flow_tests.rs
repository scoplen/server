// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::{
    auth::{AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthTokenResponse},
    sync::{
        SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundleUpdate, SyncAckRequest,
        SyncAckResponse, SyncChangesResponse, SyncSessionRequest, SyncSessionResponse,
        SyncVaultKeysResponse, SyncWrite, SyncWriteBatch, SyncWriteBatchResponse,
    },
};
use scoplen_crypto::{
    DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, ObjectEnvelope,
    SecretBytes,
};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};
use scoplen_store::{ObjectStorage, ObjectStorageConfig};
use std::fmt::Write as _;

use crate::runtime::{ListenerDatabase, api_router};

#[path = "account_devices_tests.rs"]
mod account_devices;
#[path = "account_profile_tests.rs"]
mod account_profile;
#[path = "personal_key_tests.rs"]
mod key_publication;
#[path = "personal_notify_tests.rs"]
pub(super) mod notifications;
#[path = "organization_tests.rs"]
mod organizations;
#[path = "personal_retention_tests.rs"]
mod retention;

pub(super) async fn mount_complete_api(f: &mut Fixture) {
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

#[expect(
    clippy::struct_field_names,
    reason = "Retained tests use explicit protocol identifier names"
)]
pub(super) struct LegacyReceipt {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub personal_vault_id: Uuid,
}

pub(super) async fn seed_legacy_device(f: &Fixture, client: &P256SigningKey) -> LegacyReceipt {
    let signing = Ed25519SigningKey::from_bytes(&[7; 32]).expect("Account signing key");
    let identity = crate::test_legacy_identity::LegacyIdentity::new(&signing, client);
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            crate::test_legacy_identity::seed_sqlite(store.pool(), &identity, true).await;
        }
        AuthBackend::Postgres(store) => {
            crate::test_legacy_identity::seed_postgres(store.pool(), &identity, true).await;
        }
    }
    LegacyReceipt {
        account_id: identity.account_id,
        device_id: identity.device_certificate.device_id,
        personal_vault_id: identity.personal_vault_id,
    }
}

pub(super) async fn authenticate_device(
    f: &Fixture,
    device: Uuid,
    client: &P256SigningKey,
) -> String {
    authenticate_tokens(f, device, client).await.access_token
}

async fn authenticate_tokens(
    f: &Fixture,
    device: Uuid,
    client: &P256SigningKey,
) -> AuthTokenResponse {
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
    AuthTokenResponse::from_json(reply.text()).expect("native device token")
}

async fn session_and_keys(
    f: &Fixture,
    receipt: &LegacyReceipt,
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
    let bundle = SyncAccountKeyBundle::from_cbor(&reply.body).expect("persisted K-4");
    scoplen_crypto::DeviceArkWrap::decode(&bundle.wrapped_ark)
        .expect("real legacy Device ARK wrap");
    let reply =
        protected(f, "GET", &format!("/sync/v1/vaults/{vault}/keys"), &[], token, client).await;
    assert_eq!(reply.status, 200);
    let keys = SyncVaultKeysResponse::from_cbor(&reply.body).expect("vault key");
    scoplen_crypto::PersonalVaultKeyWrap::decode(&keys.keys[0].wrapped_vault_key)
        .expect("real legacy Personal key wrap");
}

async fn sync_object(f: &Fixture, receipt: &LegacyReceipt, token: &str, client: &P256SigningKey) {
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

struct LegacyDeviceSession {
    receipt: LegacyReceipt,
    token: String,
    client: P256SigningKey,
    operator_token: String,
    operator_key: P256SigningKey,
}

async fn legacy_device_session(f: &mut Fixture) -> LegacyDeviceSession {
    mount_complete_api(f).await;
    let browser = key(1);
    let (mut authenticator, _) = f.enroll(&browser).await;
    let session = f.login(&mut authenticator, &browser).await.session();
    let client = key(2);
    let receipt = seed_legacy_device(f, &client).await;
    let token = authenticate_device(f, receipt.device_id, &client).await;
    LegacyDeviceSession {
        receipt,
        token,
        client,
        operator_token: session.access_token,
        operator_key: browser,
    }
}

async fn complete_flow(mut f: Fixture) {
    let LegacyDeviceSession { receipt, token, client, .. } = legacy_device_session(&mut f).await;
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
async fn sqlite_existing_device_public_authentication_and_sync() {
    complete_flow(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_existing_device_public_authentication_and_sync() {
    complete_flow(Fixture::postgres().await).await;
}
