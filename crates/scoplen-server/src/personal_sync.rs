// SPDX-License-Identifier: AGPL-3.0-only
//! Production enrolled-device boundary for Personal synchronization.

use std::{collections::BTreeMap, sync::Arc};

use axum::http::{HeaderMap, Method, StatusCode, Uri, header::AUTHORIZATION};
use scoplen_api::auth::DeviceAccessOperation;
use scoplen_crypto::{
    DeviceAccessToken, DpopProof, DpopTarget, DpopToken, ObjectEnvelope,
    TrustedDeviceAccessTokenKeys,
};
use scoplen_store::{
    device_authentication::{CurrentPrincipal, DeviceAuthenticationError},
    kms::LocalKeyFile,
    sync::{ObjectWrite, PersonalMutation, PersonalSigner, SyncStoreError, WriteReceipt},
};
use scoplen_sync::http::{
    AuthFailure, AuthenticatedDevice, AuthenticatedNotification, KeyUpdateError, SyncAuthenticator,
    SyncBackend, SyncKeysOperation, SyncOperation,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::device_auth::AuthBackend;

#[derive(Clone)]
pub(crate) struct PersonalSyncAuthenticator {
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
    trusted_origin: String,
}

pub(crate) struct KeyUpdateAuthorization {
    principal: CurrentPrincipal,
    expires_at: u64,
}

impl PersonalSyncAuthenticator {
    pub(crate) fn new(
        backend: AuthBackend,
        kms: Arc<LocalKeyFile>,
        trusted_origin: String,
    ) -> Self {
        Self { backend, kms, trusted_origin }
    }

    async fn current(
        &self,
        identity: AuthenticatedDevice,
    ) -> Result<CurrentPrincipal, AuthFailure> {
        let principal = self
            .backend
            .current_principal(identity.device_id)
            .await
            .map_err(|error| current_error(&error))?
            .ok_or_else(authentication_required)?;
        if principal.account_id != identity.account_id {
            return Err(authentication_required());
        }
        Ok(principal)
    }

    async fn verified_envelope(
        &self,
        identity: AuthenticatedDevice,
        vault: [u8; 16],
        object: [u8; 16],
        payload: &[u8],
    ) -> Result<(u64, PersonalSigner), AuthFailure> {
        let envelope = ObjectEnvelope::decode(payload).map_err(|_| invalid_envelope())?;
        let signer_device_id = envelope.signer_device_id.into_bytes();
        let signer = self
            .backend
            .current_principal(signer_device_id)
            .await
            .map_err(|error| current_error(&error))?
            .ok_or_else(policy_denied)?;
        if signer.account_id != identity.account_id {
            return Err(policy_denied());
        }
        envelope
            .verify_signature(
                Uuid::from_bytes(vault),
                Uuid::from_bytes(object),
                &signer.signing_public_key,
            )
            .map_err(|_| invalid_envelope())?;
        Ok((
            u64::from(envelope.key_epoch),
            PersonalSigner { device_id: signer_device_id, dpop_jkt: signer.jkt },
        ))
    }
}

impl PersonalSyncAuthenticator {
    pub(crate) async fn authenticate_operation(
        &self,
        operation: DeviceAccessOperation,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<CurrentPrincipal, AuthFailure> {
        self.authenticate_request(operation, method, uri, headers)
            .await
            .map(|(principal, _)| principal)
    }

    async fn authenticate_request(
        &self,
        operation: DeviceAccessOperation,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<(CurrentPrincipal, u64), AuthFailure> {
        let raw_token = single_header(headers, AUTHORIZATION.as_str(), 4_101)?
            .strip_prefix("DPoP ")
            .ok_or_else(authentication_required)?;
        self.authenticate_credentials(
            operation,
            method,
            uri,
            raw_token,
            single_header(headers, "dpop", 8_192)?,
        )
        .await
    }

    async fn authenticate_credentials(
        &self,
        operation: DeviceAccessOperation,
        method: &Method,
        uri: &Uri,
        raw_token: &str,
        raw_proof: &str,
    ) -> Result<(CurrentPrincipal, u64), AuthFailure> {
        let token = DeviceAccessToken::parse(raw_token).map_err(|_| authentication_required())?;
        let keyring = self.backend.keyring(&self.kms).await.map_err(|_| storage_unavailable())?;
        let mut trusted = TrustedDeviceAccessTokenKeys::new(&self.trusted_origin)
            .map_err(|_| storage_unavailable())?;
        for key in keyring.verification_keys() {
            trusted.insert(&key.kid, &key.public_key).map_err(|_| storage_unavailable())?;
        }
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| storage_unavailable())?;
        let verified = token.verify(&trusted, now).map_err(|_| authentication_required())?;
        let claims = verified.claims();
        let target = DpopTarget::new(method.as_str(), &self.trusted_origin, uri.path())
            .map_err(|_| authentication_required())?;
        let proof = DpopProof::parse(raw_proof).map_err(|_| authentication_required())?;
        self.backend
            .claim_dpop(&proof, &target, DpopToken::Protected(raw_token), &claims.cnf_jkt)
            .await
            .map_err(|error| current_error(&error))?;
        let identity = AuthenticatedDevice {
            device_id: claims.did.into_bytes(),
            account_id: claims.sub.into_bytes(),
        };
        let principal = self.current(identity).await?;
        if principal.jkt != claims.cnf_jkt {
            return Err(authentication_required());
        }
        if !operation.required_scope().is_present_in(&claims.scope) {
            return Err(policy_denied());
        }
        Ok((principal, claims.exp))
    }
}

#[async_trait::async_trait]
impl SyncAuthenticator for PersonalSyncAuthenticator {
    type KeyUpdateAuthorization = KeyUpdateAuthorization;

    async fn authenticate_key_update(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<(AuthenticatedDevice, Self::KeyUpdateAuthorization), AuthFailure> {
        let (principal, expires_at) = self
            .authenticate_request(DeviceAccessOperation::AccountKeysWrite, method, uri, headers)
            .await?;
        let identity = AuthenticatedDevice {
            account_id: principal.account_id,
            device_id: principal.device_id,
        };
        Ok((identity, KeyUpdateAuthorization { principal, expires_at }))
    }

    async fn authenticate_notification(
        &self,
        method: &Method,
        uri: &Uri,
        credentials: &scoplen_api::sync::SyncNotificationAuth,
    ) -> Result<AuthenticatedNotification, AuthFailure> {
        let operation = DeviceAccessOperation::from_route(method.as_str(), uri.path())
            .filter(|operation| *operation == DeviceAccessOperation::Notifications)
            .ok_or_else(authentication_required)?;
        let (principal, expires_at) = self
            .authenticate_credentials(
                operation,
                method,
                uri,
                &credentials.access_token,
                &credentials.dpop_proof,
            )
            .await?;
        Ok(AuthenticatedNotification {
            identity: AuthenticatedDevice {
                account_id: principal.account_id,
                device_id: principal.device_id,
            },
            expires_at,
        })
    }

    async fn authorize_notifications(
        &self,
        identity: AuthenticatedDevice,
    ) -> Result<(), AuthFailure> {
        self.current(identity).await.map(|_| ())
    }

    async fn authenticate(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedDevice, AuthFailure> {
        let operation = operation_for(method, uri).ok_or_else(policy_denied)?;
        let principal = self.authenticate_operation(operation, method, uri, headers).await?;
        Ok(AuthenticatedDevice { account_id: principal.account_id, device_id: principal.device_id })
    }

    async fn authorize(
        &self,
        identity: AuthenticatedDevice,
        vault: [u8; 16],
        operation: SyncOperation,
    ) -> Result<(), AuthFailure> {
        if !matches!(
            operation,
            SyncOperation::Read
                | SyncOperation::Snapshot
                | SyncOperation::Versions
                | SyncOperation::Write
                | SyncOperation::Acknowledge
        ) {
            return Err(policy_denied());
        }
        self.current(identity).await?;
        let owned_vault =
            self.backend.personal_vault(identity.account_id).await.map_err(|error| {
                if matches!(error, SyncStoreError::VaultNotFound) {
                    policy_denied()
                } else {
                    storage_unavailable()
                }
            })?;
        if owned_vault != vault {
            return Err(policy_denied());
        }
        Ok(())
    }

    async fn validate_write(
        &self,
        identity: AuthenticatedDevice,
        vault: [u8; 16],
        writes: &[scoplen_api::sync::SyncWrite],
    ) -> Result<Vec<u64>, AuthFailure> {
        let mut epochs = Vec::with_capacity(writes.len());
        for write in writes {
            let (epoch, _) = self
                .verified_envelope(identity, vault, write.object_id.into_bytes(), &write.payload)
                .await?;
            epochs.push(epoch);
        }
        Ok(epochs)
    }

    async fn commit_write(
        &self,
        identity: AuthenticatedDevice,
        vault: [u8; 16],
        writes: &[ObjectWrite],
        store: &SyncBackend,
    ) -> Result<Vec<WriteReceipt>, SyncStoreError> {
        let principal = self.current(identity).await.map_err(|error| mutation_error(&error))?;
        let mut signers = BTreeMap::new();
        let mut writes = writes.to_vec();
        for write in &mut writes {
            let (epoch, signer) = self
                .verified_envelope(identity, vault, write.object_id, &write.envelope)
                .await
                .map_err(|error| mutation_error(&error))?;
            if write.key_epoch != epoch {
                return Err(SyncStoreError::AccessDenied);
            }
            write.signer_device_id = Some(signer.device_id);
            match signers.entry(signer.device_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(signer.dpop_jkt);
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get() != &signer.dpop_jkt =>
                {
                    return Err(SyncStoreError::AccessDenied);
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        let signers = signers
            .into_iter()
            .map(|(device_id, dpop_jkt)| PersonalSigner { device_id, dpop_jkt })
            .collect::<Vec<_>>();
        let authorization = PersonalMutation {
            account_id: identity.account_id,
            device_id: identity.device_id,
            dpop_jkt: &principal.jkt,
            signers: &signers,
        };
        match store {
            SyncBackend::Sqlite(store) => {
                store.write_personal_sync_batch(vault, &authorization, &writes).await
            }
            SyncBackend::Postgres(store) => {
                store.write_personal_sync_batch(vault, &authorization, &writes).await
            }
        }
    }

    async fn commit_ack(
        &self,
        identity: AuthenticatedDevice,
        vault: [u8; 16],
        cursor: u64,
        store: &SyncBackend,
    ) -> Result<u64, SyncStoreError> {
        let principal = self.current(identity).await.map_err(|error| mutation_error(&error))?;
        let authorization = PersonalMutation {
            account_id: identity.account_id,
            device_id: identity.device_id,
            dpop_jkt: &principal.jkt,
            signers: &[],
        };
        match store {
            SyncBackend::Sqlite(store) => {
                store.ack_personal_sync_cursor(vault, &authorization, cursor).await
            }
            SyncBackend::Postgres(store) => {
                store.ack_personal_sync_cursor(vault, &authorization, cursor).await
            }
        }
    }

    async fn account_id(&self, identity: AuthenticatedDevice) -> Result<[u8; 16], AuthFailure> {
        Ok(identity.account_id)
    }

    async fn authorize_session(&self, identity: AuthenticatedDevice) -> Result<(), AuthFailure> {
        self.current(identity).await.map(|_| ())
    }

    async fn authorize_keys(
        &self,
        identity: AuthenticatedDevice,
        account_id: [u8; 16],
        _operation: SyncKeysOperation,
    ) -> Result<(), AuthFailure> {
        if identity.account_id != account_id {
            return Err(policy_denied());
        }
        self.current(identity).await.map(|_| ())
    }

    async fn commit_key_update(
        &self,
        identity: AuthenticatedDevice,
        account_id: [u8; 16],
        authorization: &Self::KeyUpdateAuthorization,
        update: &scoplen_api::sync::SyncAccountKeyBundleUpdate,
        store: &SyncBackend,
    ) -> Result<scoplen_store::account_keys::AccountKeyBundlePut, KeyUpdateError> {
        if authorization.principal.account_id != account_id
            || identity.account_id != account_id
            || authorization.principal.device_id != identity.device_id
        {
            return Err(authentication_required().into());
        }
        Ok(match store {
            SyncBackend::Sqlite(store) => {
                store
                    .publish_account_key_bundle(
                        &authorization.principal,
                        authorization.expires_at,
                        update,
                    )
                    .await?
            }
            SyncBackend::Postgres(store) => {
                store
                    .publish_account_key_bundle(
                        &authorization.principal,
                        authorization.expires_at,
                        update,
                    )
                    .await?
            }
        })
    }
}

fn operation_for(method: &Method, uri: &Uri) -> Option<DeviceAccessOperation> {
    let path = uri.path();
    let segments: Vec<_> = path.split('/').collect();
    let template = match segments.as_slice() {
        ["", "sync", "v1", "session"] => "/sync/v1/session",
        ["", "sync", "v1", "keys"] => "/sync/v1/keys",
        ["", "sync", "v1", "vaults", vault, leaf] if canonical_id(vault) => match *leaf {
            "keys" => "/sync/v1/vaults/{vault}/keys",
            "changes" => "/sync/v1/vaults/{vault}/changes",
            "snapshot" => "/sync/v1/vaults/{vault}/snapshot",
            "objects" => "/sync/v1/vaults/{vault}/objects",
            "ack" => "/sync/v1/vaults/{vault}/ack",
            _ => return None,
        },
        ["", "sync", "v1", "vaults", vault, "objects", object, "versions"]
            if canonical_id(vault) && canonical_id(object) =>
        {
            "/sync/v1/vaults/{vault}/objects/{object}/versions"
        }
        _ => return None,
    };
    DeviceAccessOperation::from_route(method.as_str(), template)
}

fn canonical_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == value)
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    max_bytes: usize,
) -> Result<&'a str, AuthFailure> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or_else(authentication_required)?;
    if values.next().is_some() || value.as_bytes().len() > max_bytes {
        return Err(authentication_required());
    }
    value.to_str().map_err(|_| authentication_required())
}

fn current_error(error: &DeviceAuthenticationError) -> AuthFailure {
    match error {
        DeviceAuthenticationError::Denied { .. }
        | DeviceAuthenticationError::InvalidDpopProof
        | DeviceAuthenticationError::InvalidInput => authentication_required(),
        _ => storage_unavailable(),
    }
}

fn mutation_error(error: &AuthFailure) -> SyncStoreError {
    if error.status.is_server_error() {
        SyncStoreError::AuthorizationUnavailable
    } else {
        SyncStoreError::AccessDenied
    }
}

fn authentication_required() -> AuthFailure {
    AuthFailure::new(
        StatusCode::UNAUTHORIZED,
        "auth.authentication_required",
        "Authentication required",
        "Authenticate this enrolled device and create a fresh DPoP proof for the request.",
        false,
    )
    .expect("static authentication problem")
}

fn policy_denied() -> AuthFailure {
    AuthFailure::new(
        StatusCode::FORBIDDEN,
        "policy.denied",
        "Access denied",
        "This device cannot perform the requested Personal sync operation.",
        false,
    )
    .expect("static authorization problem")
}

fn invalid_envelope() -> AuthFailure {
    AuthFailure::new(
        StatusCode::BAD_REQUEST,
        "sync.invalid_request",
        "Invalid object envelope",
        "The object envelope or its device signature is invalid; no data changed.",
        false,
    )
    .expect("static envelope problem")
}

fn storage_unavailable() -> AuthFailure {
    AuthFailure::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "sync.storage_unavailable",
        "Sync service unavailable",
        "The server could not verify current device access. Retry with a fresh proof.",
        true,
    )
    .expect("static storage problem")
}

#[cfg(test)]
mod tests {
    mod limits;
    use super::*;
    use std::{fmt::Write as _, net::SocketAddr, path::PathBuf, time::Duration};

    use scoplen_api::{
        ProblemDetails,
        auth::{AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthTokenResponse},
        sync::{
            SyncAccountKeyBundle, SyncAckRequest, SyncAckResponse, SyncChangesResponse,
            SyncSessionRequest, SyncSessionResponse, SyncSnapshotResponse, SyncVaultKeysResponse,
            SyncVersionsResponse, SyncWrite, SyncWriteBatch, SyncWriteBatchResponse,
        },
    };
    use scoplen_crypto::{
        DeviceAccessTokenClaims, DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair,
        Ed25519SigningKey, P256SigningKey, SecretBytes, dpop_jwk_thumbprint,
    };
    use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};
    #[cfg(feature = "postgres-integration")]
    use scoplen_store::PostgresStore;
    use scoplen_store::{
        ObjectStorage, ObjectStorageConfig, RelationalStore, SqliteStore,
        account_keys::{AccountKeyBundleUpdate, DeviceWrap},
        device_token_keys::DeviceTokenKeyring,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[cfg(feature = "postgres-integration")]
    use crate::runtime::api_router;
    use crate::runtime::{ListenerDatabase, api_router_with_limits};
    use scoplen_sync::http::{ReadBodyLimits, WriteBodyLimits, WriteRateLimits};

    const ORIGIN: &str = "https://example.com";

    fn account_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[7; 32]).expect("account key")
    }

    fn device_key() -> P256SigningKey {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        P256SigningKey::from_bytes(&scalar).expect("device key")
    }

    fn certificate(account: Uuid, device: Uuid) -> Vec<u8> {
        let kem = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("KEM");
        DeviceCertificate::issue(
            &account_key(),
            device,
            account,
            device_key().public_key_sec1(),
            kem.public_key().to_vec(),
            "sync test device".into(),
            "windows".into(),
            1,
        )
        .expect("certificate")
        .encode()
        .expect("canonical certificate")
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("scoplen-personal-sync-{}", Uuid::now_v7()));
        std::fs::create_dir(&path).expect("test directory");
        path
    }

    fn kms(path: &std::path::Path) -> Arc<LocalKeyFile> {
        let key_file = path.join("deployment.key");
        std::fs::write(&key_file, "09".repeat(32)).expect("test key file");
        Arc::new(LocalKeyFile::load(&key_file).expect("KMS"))
    }

    struct Reply {
        status: u16,
        body: Vec<u8>,
    }

    async fn http(
        address: SocketAddr,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut stream = tokio::net::TcpStream::connect(address).await.expect("connect");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.expect("headers");
        stream.write_all(body).await.expect("body");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("response");
        let split = response.windows(4).position(|part| part == b"\r\n\r\n").expect("HTTP head");
        let head = std::str::from_utf8(&response[..split]).expect("HTTP header UTF-8");
        let status = head
            .lines()
            .next()
            .expect("status line")
            .split_whitespace()
            .nth(1)
            .expect("code")
            .parse()
            .expect("numeric status");
        Reply { status, body: response[split + 4..].to_vec() }
    }

    fn problem(reply: &Reply, status: u16, code: &str) {
        assert_eq!(reply.status, status, "{}", String::from_utf8_lossy(&reply.body));
        let decoded = ProblemDetails::from_cbor(&reply.body).expect("CBOR problem");
        assert_eq!(decoded.code.as_str(), code);
        assert!(!decoded.changed);
    }

    fn auth_signature(device: Uuid, nonce: &str) -> String {
        let context = DeviceAuthContext::new(ORIGIN, nonce, device).expect("context");
        let bytes = device_key().sign(&context.signature_input());
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(encoded, "{byte:02x}").expect("hex encoding");
        }
        encoded
    }

    async fn issue_token(address: SocketAddr, device: Uuid) -> String {
        let challenge_body =
            AuthChallengeRequest::new(device).expect("challenge request").to_json().expect("JSON");
        let challenge = http(
            address,
            "POST",
            "/api/v1/auth/challenge",
            challenge_body.as_bytes(),
            &[("Content-Type", "application/json")],
        )
        .await;
        assert_eq!(challenge.status, 200);
        let challenge = AuthChallengeResponse::from_json(
            std::str::from_utf8(&challenge.body).expect("JSON body"),
        )
        .expect("challenge");
        let request = AuthDeviceRequest::new(
            device,
            &challenge.nonce,
            auth_signature(device, &challenge.nonce),
        )
        .expect("device request")
        .to_json()
        .expect("JSON");
        let response = http(
            address,
            "POST",
            "/api/v1/auth/device",
            request.as_bytes(),
            &[("Content-Type", "application/json")],
        )
        .await;
        assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
        AuthTokenResponse::from_json(std::str::from_utf8(&response.body).expect("JSON"))
            .expect("token")
            .access_token
    }

    fn proof(method: &str, path: &str, token: &str) -> String {
        let target = DpopTarget::new(method, ORIGIN, path).expect("target");
        DpopProof::sign(
            &device_key(),
            &device_key().public_key_sec1(),
            &target,
            DpopToken::Protected(token),
            u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
            None,
        )
        .expect("proof")
        .as_str()
        .to_owned()
    }

    fn read_only_token(keyring: &DeviceTokenKeyring, account: Uuid, device: Uuid) -> String {
        let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
        for key in keyring.verification_keys() {
            trusted.insert(&key.kid, &key.public_key).expect("verification key");
        }
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("clock");
        let claims = DeviceAccessTokenClaims {
            iss: ORIGIN.into(),
            sub: account,
            did: device,
            jti: Uuid::now_v7(),
            cnf_jkt: dpop_jwk_thumbprint(&device_key().public_key_sec1()).expect("thumbprint"),
            org: vec![],
            scope: "sync:read".into(),
            iat: now,
            exp: now + 600,
        };
        DeviceAccessToken::sign(
            keyring.signing_key(),
            &trusted,
            keyring.signing_key().kid(),
            &device_key().public_key_sec1(),
            &claims,
        )
        .expect("read-only token")
        .as_str()
        .to_owned()
    }

    fn signed_write(vault: Uuid, device: Uuid, object_id: Uuid) -> SyncWrite {
        let mut object = Object::new(object_id, ObjectType::HOST, 1).expect("object");
        object
            .insert(
                FieldPath::field(1).expect("field"),
                FieldEntry::new(cbor::Value::Text("host".into()), Hlc::at(1).expect("HLC"), device)
                    .expect("entry"),
            )
            .expect("insert field");
        object
            .insert(
                FieldPath::field(2).expect("field"),
                FieldEntry::new(
                    cbor::Value::Text("host.example".into()),
                    Hlc::at(2).expect("HLC"),
                    device,
                )
                .expect("entry"),
            )
            .expect("insert hostname");
        let envelope = ObjectEnvelope::encrypt(
            vault,
            1,
            &object,
            &SecretBytes::new([8; 32]),
            device,
            &device_key(),
        )
        .expect("signed envelope");
        SyncWrite {
            object_id,
            base_seq: None,
            payload: envelope.encode().expect("encoded envelope"),
            tombstone: false,
        }
    }

    async fn reject_invalid_proofs(address: SocketAddr, token: &str, body: &[u8]) {
        let path = "/sync/v1/session";
        let authorization = format!("DPoP {token}");
        for invalid_proof in [
            proof("GET", path, token),
            proof("POST", "/sync/v1/keys", token),
            proof("POST", path, "different-access-token"),
        ] {
            let headers = [
                ("Content-Type", "application/cbor"),
                ("Authorization", authorization.as_str()),
                ("DPoP", invalid_proof.as_str()),
            ];
            problem(
                &http(address, "POST", path, body, &headers).await,
                401,
                "auth.authentication_required",
            );
        }
    }

    async fn reject_unmounted_routes(address: SocketAddr) {
        assert_eq!(http(address, "POST", "/sync/v1/vaults", &[], &[]).await.status, 404);
        assert_eq!(http(address, "GET", "/sync/v1/notify", &[], &[]).await.status, 400);
        assert_eq!(http(address, "PUT", "/sync/v1/keys", &[], &[]).await.status, 400);
    }

    async fn reject_read_only_write(address: SocketAddr, token: &str, path: &str, body: &[u8]) {
        let authorization = format!("DPoP {token}");
        let proof = proof("POST", path, token);
        let headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", proof.as_str()),
        ];
        problem(&http(address, "POST", path, body, &headers).await, 403, "policy.denied");
    }

    async fn remove_directory(path: &std::path::Path) {
        for _ in 0..20 {
            if std::fs::remove_dir_all(path).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("owned test directory could not be removed");
    }

    async fn seed_sqlite(store: &SqliteStore) -> (Uuid, Uuid, Uuid) {
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let vault = Uuid::now_v7();
        let cert = certificate(account, device);
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, ?, ?, ?)")
            .bind(account.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
            .bind([4_u8; 32].as_slice()).bind(1_i64)
            .execute(store.pool()).await.expect("account");
        sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES (?, ?, ?, 1, ?)")
            .bind(device.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
            .bind(&cert).bind(1_i64).execute(store.pool()).await.expect("device");
        let update = AccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![DeviceWrap { device_id: device.into_bytes(), wrapped_ark: vec![1] }],
            account_signing_key: vec![2],
            account_kem_key: vec![3],
            recovery_blob: vec![4],
            signature: [5; 64],
        };
        store.put_account_key_bundle(account.into_bytes(), &update).await.expect("bundle");
        store
            .replace_account_key_statements(account.into_bytes(), &[cert], &[])
            .await
            .expect("certificate publication");
        store
            .create_personal_sync_vault(vault.into_bytes(), account.into_bytes(), &[6])
            .await
            .expect("Personal vault");
        (account, device, vault)
    }

    #[cfg(feature = "postgres-integration")]
    async fn seed_postgres(store: &PostgresStore) -> (Uuid, Uuid, Uuid) {
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let vault = Uuid::now_v7();
        let cert = certificate(account, device);
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES ($1, $2, $3, $4)")
            .bind(account.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
            .bind([4_u8; 32].as_slice()).bind(1_i64)
            .execute(store.pool()).await.expect("account");
        sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES ($1, $2, $3, true, $4)")
            .bind(device.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
            .bind(&cert).bind(1_i64).execute(store.pool()).await.expect("device");
        let update = AccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![DeviceWrap { device_id: device.into_bytes(), wrapped_ark: vec![1] }],
            account_signing_key: vec![2],
            account_kem_key: vec![3],
            recovery_blob: vec![4],
            signature: [5; 64],
        };
        store.put_account_key_bundle(account.into_bytes(), &update).await.expect("bundle");
        store
            .replace_account_key_statements(account.into_bytes(), &[cert], &[])
            .await
            .expect("certificate publication");
        store
            .create_personal_sync_vault(vault.into_bytes(), account.into_bytes(), &[6])
            .await
            .expect("Personal vault");
        (account, device, vault)
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn sqlite_listener_personal_sync_authentication_and_denial() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = kms(&directory);
        let (account, device, vault) = seed_sqlite(&store).await;
        let read_only = read_only_token(
            &store.ensure_device_token_keyring(&*kms).await.expect("keyring"),
            account,
            device,
        );
        let foreign = Uuid::now_v7();
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, ?, ?, ?)")
            .bind(foreign.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
            .bind([4_u8; 32].as_slice()).bind(1_i64)
            .execute(store.pool()).await.expect("foreign account");
        let foreign_vault = Uuid::now_v7();
        store
            .create_personal_sync_vault(foreign_vault.into_bytes(), foreign.into_bytes(), &[7])
            .await
            .expect("foreign Personal vault");
        let object_storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: directory.join("objects"),
        })
        .expect("object storage");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                api_router_with_limits(
                    ListenerDatabase::Sqlite(Arc::new(server_store)),
                    Arc::new(object_storage),
                    kms,
                    ORIGIN.into(),
                    true,
                    WriteRateLimits::new(7, 9).expect("rate limits"),
                    WriteBodyLimits::new(266_240, 1, 4_194_304).expect("body limits"),
                    ReadBodyLimits::default(),
                )
                .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve");
        });
        let token = issue_token(address, device).await;
        reject_unmounted_routes(address).await;
        let authorization = format!("DPoP {token}");
        let session_path = "/sync/v1/session";
        let session_body = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: device,
        }
        .to_cbor()
        .expect("CBOR session");
        let session_proof = proof("POST", session_path, &token);
        reject_invalid_proofs(address, &token, &session_body).await;
        let headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", session_proof.as_str()),
        ];
        let session = http(address, "POST", session_path, &session_body, &headers).await;
        assert_eq!(session.status, 200, "{}", String::from_utf8_lossy(&session.body));
        let session_decoded =
            SyncSessionResponse::from_cbor(&session.body).expect("session response");
        assert_eq!(session_decoded.vaults.len(), 1);
        assert_eq!(session_decoded.vaults[0].id, vault);
        assert_eq!(session_decoded.limits.write_requests_per_second, 7);
        assert_eq!(session_decoded.limits.write_burst, 9);
        assert_eq!(session_decoded.limits.max_batch_objects, 1);
        let replay = http(address, "POST", session_path, &session_body, &headers).await;
        problem(&replay, 401, "auth.authentication_required");
        let wrong_body = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: Uuid::now_v7(),
        }
        .to_cbor()
        .expect("wrong device request");
        let wrong_proof = proof("POST", session_path, &token);
        let wrong_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", wrong_proof.as_str()),
        ];
        let wrong = http(address, "POST", session_path, &wrong_body, &wrong_headers).await;
        problem(&wrong, 401, "auth.authentication_required");
        let keys_path = "/sync/v1/keys";
        let keys_proof = proof("GET", keys_path, &token);
        let keys_headers =
            [("Authorization", authorization.as_str()), ("DPoP", keys_proof.as_str())];
        let keys = http(address, "GET", keys_path, &[], &keys_headers).await;
        assert_eq!(keys.status, 200);
        assert_eq!(SyncAccountKeyBundle::from_cbor(&keys.body).expect("keys").wrapped_ark, vec![1]);
        let vault_path = format!("/sync/v1/vaults/{vault}/keys");
        let vault_proof = proof("GET", &vault_path, &token);
        let vault_headers =
            [("Authorization", authorization.as_str()), ("DPoP", vault_proof.as_str())];
        let vault_keys = http(address, "GET", &vault_path, &[], &vault_headers).await;
        assert_eq!(vault_keys.status, 200);
        assert_eq!(
            SyncVaultKeysResponse::from_cbor(&vault_keys.body).expect("vault keys").keys.len(),
            1
        );
        let object_id = Uuid::now_v7();
        let write = signed_write(vault, device, object_id);
        let objects_path = format!("/sync/v1/vaults/{vault}/objects");
        let batch = SyncWriteBatch { writes: vec![write.clone()] }.to_cbor().expect("write CBOR");
        reject_read_only_write(address, &read_only, &objects_path, &batch).await;
        let write_proof = proof("POST", &objects_path, &token);
        let write_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", write_proof.as_str()),
        ];
        let written = http(address, "POST", &objects_path, &batch, &write_headers).await;
        assert_eq!(written.status, 200, "{}", String::from_utf8_lossy(&written.body));
        let receipts = SyncWriteBatchResponse::from_cbor(&written.body).expect("write response");
        assert_eq!(receipts.assignments[0].seq, 1);
        problem(
            &http(address, "POST", &objects_path, &batch, &write_headers).await,
            401,
            "auth.authentication_required",
        );
        let changes_path = format!("/sync/v1/vaults/{vault}/changes");
        let changes_proof = proof("GET", &changes_path, &token);
        let changes_headers =
            [("Authorization", authorization.as_str()), ("DPoP", changes_proof.as_str())];
        let changes = http(
            address,
            "GET",
            &format!("{changes_path}?after=0&limit=10"),
            &[],
            &changes_headers,
        )
        .await;
        assert_eq!(changes.status, 200);
        assert_eq!(
            SyncChangesResponse::from_cbor(&changes.body).expect("changes").changes.len(),
            1
        );
        let snapshot_path = format!("/sync/v1/vaults/{vault}/snapshot");
        let snapshot_proof = proof("GET", &snapshot_path, &token);
        let snapshot_headers =
            [("Authorization", authorization.as_str()), ("DPoP", snapshot_proof.as_str())];
        let snapshot = http(
            address,
            "GET",
            &format!("{snapshot_path}?after=0&limit=10"),
            &[],
            &snapshot_headers,
        )
        .await;
        assert_eq!(snapshot.status, 200);
        assert_eq!(
            SyncSnapshotResponse::from_cbor(&snapshot.body).expect("snapshot").objects.len(),
            1
        );
        let versions_path = format!("/sync/v1/vaults/{vault}/objects/{object_id}/versions");
        let versions_proof = proof("GET", &versions_path, &token);
        let versions_headers =
            [("Authorization", authorization.as_str()), ("DPoP", versions_proof.as_str())];
        let versions = http(address, "GET", &versions_path, &[], &versions_headers).await;
        assert_eq!(versions.status, 200);
        assert_eq!(
            SyncVersionsResponse::from_cbor(&versions.body).expect("versions").versions.len(),
            1
        );
        let ack_path = format!("/sync/v1/vaults/{vault}/ack");
        let ack_body = SyncAckRequest { cursor: 1 }.to_cbor().expect("ack CBOR");
        let ack_proof = proof("POST", &ack_path, &token);
        let ack_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", ack_proof.as_str()),
        ];
        let ack = http(address, "POST", &ack_path, &ack_body, &ack_headers).await;
        assert_eq!(ack.status, 200);
        assert_eq!(SyncAckResponse::from_cbor(&ack.body).expect("ack").cursor, 1);
        let mut bad_write = signed_write(vault, device, Uuid::now_v7());
        let last = bad_write.payload.len() - 1;
        bad_write.payload[last] ^= 1;
        let bad_batch = SyncWriteBatch { writes: vec![bad_write] }.to_cbor().expect("bad batch");
        let bad_proof = proof("POST", &objects_path, &token);
        let bad_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", bad_proof.as_str()),
        ];
        problem(
            &http(address, "POST", &objects_path, &bad_batch, &bad_headers).await,
            400,
            "sync.invalid_request",
        );
        let foreign_path = format!("/sync/v1/vaults/{foreign_vault}/keys");
        let foreign_proof = proof("GET", &foreign_path, &token);
        let foreign_headers =
            [("Authorization", authorization.as_str()), ("DPoP", foreign_proof.as_str())];
        problem(
            &http(address, "GET", &foreign_path, &[], &foreign_headers).await,
            403,
            "policy.denied",
        );
        sqlx::query("UPDATE identity_devices SET active = 0 WHERE device_id = ?")
            .bind(device.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("revoke device");
        let revoked_proof = proof("GET", keys_path, &token);
        let revoked_headers =
            [("Authorization", authorization.as_str()), ("DPoP", revoked_proof.as_str())];
        problem(
            &http(address, "GET", keys_path, &[], &revoked_headers).await,
            401,
            "auth.authentication_required",
        );
        let jkt = dpop_jwk_thumbprint(&device_key().public_key_sec1()).expect("thumbprint");
        let signer = PersonalSigner { device_id: device.into_bytes(), dpop_jkt: jkt.clone() };
        let mutation = PersonalMutation {
            account_id: account.into_bytes(),
            device_id: device.into_bytes(),
            dpop_jkt: &jkt,
            signers: &[signer],
        };
        let late_write = signed_write(vault, device, Uuid::now_v7());
        let stored = ObjectWrite {
            object_id: late_write.object_id.into_bytes(),
            base_sequence: None,
            envelope: late_write.payload,
            key_epoch: 1,
            tombstone: false,
            signer_device_id: Some(device.into_bytes()),
        };
        assert!(matches!(
            store.write_personal_sync_batch(vault.into_bytes(), &mutation, &[stored]).await,
            Err(SyncStoreError::AccessDenied)
        ));
        assert!(matches!(
            store.ack_personal_sync_cursor(vault.into_bytes(), &mutation, 1).await,
            Err(SyncStoreError::AccessDenied)
        ));
        assert_eq!(
            store.list_sync_vaults_for_account(account.into_bytes()).await.expect("vaults")[0]
                .sequence,
            1
        );
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        drop(store);
        remove_directory(&directory).await;
    }

    #[tokio::test]
    async fn sqlite_listener_enforces_write_limits_across_connections() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let (account, device, vault) = seed_sqlite(&store).await;
        let object_storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: directory.join("objects"),
        })
        .expect("object storage");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = api_router_with_limits(
            ListenerDatabase::Sqlite(Arc::new(store.clone())),
            Arc::new(object_storage),
            kms(&directory),
            ORIGIN.into(),
            true,
            WriteRateLimits::new(1, 1).expect("rate limits"),
            WriteBodyLimits::new(266_240, 1, 4_194_304).expect("body limits"),
            ReadBodyLimits::default(),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve");
        });
        let token = issue_token(address, device).await;
        let authorization = format!("DPoP {token}");
        let path = format!("/sync/v1/vaults/{vault}/objects");
        let oversized = SyncWriteBatch {
            writes: vec![
                signed_write(vault, device, Uuid::now_v7()),
                signed_write(vault, device, Uuid::now_v7()),
            ],
        }
        .to_cbor()
        .expect("two-object batch");
        let first_proof = proof("POST", &path, &token);
        let second_proof = proof("POST", &path, &token);
        let first_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", first_proof.as_str()),
        ];
        let second_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", second_proof.as_str()),
        ];
        problem(
            &http(address, "POST", &path, &oversized, &first_headers).await,
            413,
            "sync.invalid_request",
        );
        problem(
            &http(address, "POST", &path, &[], &second_headers).await,
            429,
            "sync.rate_limited",
        );
        assert_eq!(
            store.list_sync_vaults_for_account(account.into_bytes()).await.expect("vaults")[0]
                .sequence,
            0,
        );
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        drop(store);
        remove_directory(&directory).await;
    }

    #[tokio::test]
    async fn sqlite_personal_writes_preserve_the_verified_envelope_signer() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let (account, uploader, vault) = seed_sqlite(&store).await;
        let signer = Uuid::now_v7();
        let signer_certificate = certificate(account, signer);
        sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES (?, ?, ?, 1, ?)")
            .bind(signer.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
            .bind(&signer_certificate).bind(1_i64)
            .execute(store.pool()).await.expect("other enrolled device");
        store
            .replace_account_key_statements(
                account.into_bytes(),
                &[certificate(account, uploader), signer_certificate],
                &[],
            )
            .await
            .expect("publish both certificates");
        let backend = SyncBackend::Sqlite(Arc::new(store.clone()));
        let authenticator = PersonalSyncAuthenticator::new(
            AuthBackend::Sqlite(Arc::new(store.clone())),
            kms(&directory),
            ORIGIN.into(),
        );
        let identity = AuthenticatedDevice {
            account_id: account.into_bytes(),
            device_id: uploader.into_bytes(),
        };
        let write = signed_write(vault, signer, Uuid::now_v7());
        let writes = [ObjectWrite {
            object_id: write.object_id.into_bytes(),
            base_sequence: None,
            envelope: write.payload,
            key_epoch: 1,
            tombstone: false,
            signer_device_id: Some(uploader.into_bytes()),
        }];
        authenticator
            .commit_write(identity, vault.into_bytes(), &writes, &backend)
            .await
            .expect("upload another enrolled device's signed envelope");
        let changes = store.sync_changes(vault.into_bytes(), 0, 10).await.expect("readback");
        assert_eq!(changes.changes[0].signer_device_id, Some(signer.into_bytes()));
        sqlx::query("UPDATE identity_devices SET active = 0 WHERE device_id = ?")
            .bind(signer.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("revoke signer");
        assert!(matches!(
            authenticator.commit_write(identity, vault.into_bytes(), &writes, &backend).await,
            Err(SyncStoreError::AccessDenied),
        ));
        assert_eq!(
            store.list_sync_vaults_for_account(account.into_bytes()).await.expect("vaults")[0]
                .sequence,
            1,
        );
        drop(authenticator);
        drop(backend);
        store.pool().close().await;
        drop(store);
        remove_directory(&directory).await;
    }

    #[tokio::test]
    async fn sqlite_authorization_failures_preserve_storage_errors() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let (account, device, vault) = seed_sqlite(&store).await;
        let object_storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: directory.join("objects"),
        })
        .expect("object storage");
        let kms = kms(&directory);
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let authenticator = PersonalSyncAuthenticator::new(backend, kms.clone(), ORIGIN.into());
        let identity = AuthenticatedDevice {
            device_id: device.into_bytes(),
            account_id: account.into_bytes(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = api_router_with_limits(
            ListenerDatabase::Sqlite(Arc::new(store.clone())),
            Arc::new(object_storage),
            kms,
            ORIGIN.into(),
            true,
            WriteRateLimits::default(),
            WriteBodyLimits::default(),
            ReadBodyLimits::default(),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve");
        });
        let token = issue_token(address, device).await;
        let mut connection = store.pool().acquire().await.expect("SQLite connection");
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .expect("allow legacy corrupt row");
        sqlx::query("UPDATE sync_personal_vaults SET wrapped_vault_key = ? WHERE account_id = ?")
            .bind(Vec::<u8>::new())
            .bind(account.as_bytes().as_slice())
            .execute(&mut *connection)
            .await
            .expect("corrupt stored vault key");
        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *connection)
            .await
            .expect("restore constraints");
        drop(connection);
        let path = format!("/sync/v1/vaults/{vault}/keys");
        let authorization = format!("DPoP {token}");
        let proof = proof("GET", &path, &token);
        let headers = [("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
        let response = http(address, "GET", &path, &[], &headers).await;
        problem(&response, 503, "sync.storage_unavailable");
        assert!(ProblemDetails::from_cbor(&response.body).expect("problem").retryable);
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        let sync_backend = SyncBackend::Sqlite(Arc::new(store.clone()));
        assert!(matches!(
            authenticator.commit_write(identity, vault.into_bytes(), &[], &sync_backend).await,
            Err(SyncStoreError::AuthorizationUnavailable),
        ));
        assert!(matches!(
            authenticator.commit_ack(identity, vault.into_bytes(), 0, &sync_backend).await,
            Err(SyncStoreError::AuthorizationUnavailable),
        ));
        drop(authenticator);
        drop(sync_backend);
        drop(store);
        remove_directory(&directory).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn postgres_listener_personal_sync_authentication_and_denial() {
        let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
            .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
        let directory = directory();
        let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
        let kms = kms(&directory);
        let (account, device, vault) = seed_postgres(&store).await;
        let read_only = read_only_token(
            &store.ensure_device_token_keyring(&*kms).await.expect("keyring"),
            account,
            device,
        );
        let foreign = Uuid::now_v7();
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES ($1, $2, $3, $4)")
            .bind(foreign.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
            .bind([4_u8; 32].as_slice()).bind(1_i64)
            .execute(store.pool()).await.expect("foreign account");
        let foreign_vault = Uuid::now_v7();
        store
            .create_personal_sync_vault(foreign_vault.into_bytes(), foreign.into_bytes(), &[7])
            .await
            .expect("foreign Personal vault");
        let object_storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: directory.join("objects"),
        })
        .expect("object storage");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                api_router(
                    ListenerDatabase::Postgres(Arc::new(server_store)),
                    Arc::new(object_storage),
                    kms,
                    ORIGIN.into(),
                    true,
                )
                .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve PostgreSQL");
        });
        let token = issue_token(address, device).await;
        reject_unmounted_routes(address).await;
        let authorization = format!("DPoP {token}");
        let session_path = "/sync/v1/session";
        let session_body = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: device,
        }
        .to_cbor()
        .expect("session request");
        let session_proof = proof("POST", session_path, &token);
        reject_invalid_proofs(address, &token, &session_body).await;
        let session_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", session_proof.as_str()),
        ];
        let session = http(address, "POST", session_path, &session_body, &session_headers).await;
        assert_eq!(session.status, 200);
        assert_eq!(
            SyncSessionResponse::from_cbor(&session.body).expect("session").vaults[0].id,
            vault
        );
        problem(
            &http(address, "POST", session_path, &session_body, &session_headers).await,
            401,
            "auth.authentication_required",
        );
        let wrong_body = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: Uuid::now_v7(),
        }
        .to_cbor()
        .expect("wrong device");
        let wrong_proof = proof("POST", session_path, &token);
        let wrong_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", wrong_proof.as_str()),
        ];
        problem(
            &http(address, "POST", session_path, &wrong_body, &wrong_headers).await,
            401,
            "auth.authentication_required",
        );
        let keys_proof = proof("GET", "/sync/v1/keys", &token);
        let keys_headers =
            [("Authorization", authorization.as_str()), ("DPoP", keys_proof.as_str())];
        let keys = http(address, "GET", "/sync/v1/keys", &[], &keys_headers).await;
        assert_eq!(keys.status, 200);
        assert_eq!(SyncAccountKeyBundle::from_cbor(&keys.body).expect("keys").wrapped_ark, vec![1]);
        let objects_path = format!("/sync/v1/vaults/{vault}/objects");
        let object_id = Uuid::now_v7();
        let batch = SyncWriteBatch { writes: vec![signed_write(vault, device, object_id)] }
            .to_cbor()
            .expect("write batch");
        reject_read_only_write(address, &read_only, &objects_path, &batch).await;
        let write_proof = proof("POST", &objects_path, &token);
        let write_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", write_proof.as_str()),
        ];
        let write = http(address, "POST", &objects_path, &batch, &write_headers).await;
        assert_eq!(write.status, 200, "{}", String::from_utf8_lossy(&write.body));
        assert_eq!(
            SyncWriteBatchResponse::from_cbor(&write.body).expect("receipt").assignments[0].seq,
            1
        );
        let ack_path = format!("/sync/v1/vaults/{vault}/ack");
        let ack_body = SyncAckRequest { cursor: 1 }.to_cbor().expect("ack");
        let ack_proof = proof("POST", &ack_path, &token);
        let ack_headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", ack_proof.as_str()),
        ];
        let ack = http(address, "POST", &ack_path, &ack_body, &ack_headers).await;
        assert_eq!(ack.status, 200);
        assert_eq!(SyncAckResponse::from_cbor(&ack.body).expect("ack").cursor, 1);
        let foreign_path = format!("/sync/v1/vaults/{foreign_vault}/snapshot");
        let foreign_proof = proof("GET", &foreign_path, &token);
        let foreign_headers =
            [("Authorization", authorization.as_str()), ("DPoP", foreign_proof.as_str())];
        problem(
            &http(
                address,
                "GET",
                &format!("{foreign_path}?after=0&limit=10"),
                &[],
                &foreign_headers,
            )
            .await,
            403,
            "policy.denied",
        );
        sqlx::query("UPDATE identity_devices SET active = false WHERE device_id = $1")
            .bind(device.as_bytes().as_slice())
            .execute(store.pool())
            .await
            .expect("revoke device");
        let revoked_proof = proof("GET", "/sync/v1/keys", &token);
        let revoked_headers =
            [("Authorization", authorization.as_str()), ("DPoP", revoked_proof.as_str())];
        problem(
            &http(address, "GET", "/sync/v1/keys", &[], &revoked_headers).await,
            401,
            "auth.authentication_required",
        );
        let jkt = dpop_jwk_thumbprint(&device_key().public_key_sec1()).expect("thumbprint");
        let signer = PersonalSigner { device_id: device.into_bytes(), dpop_jkt: jkt.clone() };
        let mutation = PersonalMutation {
            account_id: account.into_bytes(),
            device_id: device.into_bytes(),
            dpop_jkt: &jkt,
            signers: &[signer],
        };
        let late = signed_write(vault, device, Uuid::now_v7());
        let stored = ObjectWrite {
            object_id: late.object_id.into_bytes(),
            base_sequence: None,
            envelope: late.payload,
            key_epoch: 1,
            tombstone: false,
            signer_device_id: Some(device.into_bytes()),
        };
        assert!(matches!(
            store.write_personal_sync_batch(vault.into_bytes(), &mutation, &[stored]).await,
            Err(SyncStoreError::AccessDenied)
        ));
        assert!(matches!(
            store.ack_personal_sync_cursor(vault.into_bytes(), &mutation, 1).await,
            Err(SyncStoreError::AccessDenied)
        ));
        assert_eq!(
            store.list_sync_vaults_for_account(account.into_bytes()).await.expect("vaults")[0]
                .sequence,
            1
        );
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        drop(store);
        remove_directory(&directory).await;
    }
}
