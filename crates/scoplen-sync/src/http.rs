// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated HTTP/CBOR adapter for the K-4 sync service.
//!
//! This module owns request validation, wire decoding, storage error mapping, and response
//! encoding. It deliberately does not implement identity. A deployment must provide an
//! authenticator that validates the DPoP-bound access token and authorizes the requested vault
//! operation before this router is mounted on the public listener.

#![forbid(unsafe_code)]

use std::{sync::Arc, time::Duration};

use crate::notify::NotificationHub;
use axum::{
    Router,
    body::Bytes,
    extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use scoplen_api::{ErrorCode, ProblemDetails, sync as api};
use scoplen_model::cbor::{self, Value};
use scoplen_store::{SqliteStore, account_keys as key_storage, sync as storage};
use tokio::sync::broadcast;
use uuid::{Uuid, Variant};

/// The maximum request body accepted by the write endpoint. The CBOR codec applies the same
/// limit before decoding, and the router applies it before allocating a handler body.
pub const MAX_REQUEST_BYTES: usize = storage::MAX_BATCH_BYTES;

/// Maximum size of the first WebSocket message handed to the notification authenticator.
pub const MAX_NOTIFICATION_AUTH_BYTES: usize = 16 * 1024;

const NOTIFICATION_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// The operation requested from the authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncOperation {
    /// Create a shared vault owned by the authenticated account.
    CreateVault,
    /// Publish a new shared-vault key epoch.
    PublishVaultEpoch,
    /// Add a member to a shared vault.
    AddVaultMember,
    /// Remove a member from a shared vault.
    RemoveVaultMember,
    /// Read the current change feed.
    Read,
    /// Read a full reconciliation snapshot.
    Snapshot,
    /// Read retained object versions.
    Versions,
    /// Write object envelopes.
    Write,
    /// Advance a device acknowledgement cursor.
    Acknowledge,
}

/// Account-key operation requested from the authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncKeysOperation {
    /// Read the bundle visible to the authenticated device.
    Read,
    /// Publish a rotated account-key bundle.
    Write,
}

/// An authenticated device identity supplied by the identity service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    /// `UUIDv7` of the enrolled device.
    pub device_id: storage::DeviceId,
}

/// A problem returned by an authenticator at the request boundary.
#[derive(Clone, Debug)]
pub struct AuthFailure {
    /// HTTP status to return.
    pub status: StatusCode,
    /// Registered or syntactically valid future error code.
    pub code: ErrorCode,
    /// Human-readable title for diagnostics.
    pub title: String,
    /// Human-readable detail; clients must not parse it.
    pub detail: String,
    /// Whether retrying with the same request may succeed.
    pub retryable: bool,
}

impl AuthFailure {
    /// Construct an authentication failure after validating the code and text fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the code is not a valid dotted lower-case code or a required text
    /// field is empty. The identity service should use a code from the K-3 registry.
    pub fn new(
        status: StatusCode,
        code: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
        retryable: bool,
    ) -> Result<Self, String> {
        let code = ErrorCode::new(code.into()).map_err(|error| error.to_string())?;
        let title = title.into();
        let detail = detail.into();
        if title.trim().is_empty() || detail.trim().is_empty() {
            return Err("authentication problem text must not be empty".into());
        }
        Ok(Self { status, code, title, detail, retryable })
    }
}

/// Identity and authorization boundary required by the sync HTTP adapter.
///
/// Implementations MUST validate the Authorization `DPoP` access token and its accompanying
/// `DPoP` proof before returning an identity. The proof's `htm` and `htu` claims MUST be checked
/// against the supplied request method and URI, in addition to rejecting missing, malformed,
/// expired, or revoked credentials. Implementations also enforce vault membership for the
/// requested operation. This trait has no default implementation so the server cannot
/// accidentally ship an unauthenticated endpoint.
pub trait SyncAuthenticator: Clone + Send + Sync + 'static {
    /// Authenticate one request as an enrolled device, including its `DPoP` method and URI binding.
    ///
    /// # Errors
    ///
    /// Returns an authentication problem when the access token or proof is missing, invalid,
    /// expired, or revoked.
    fn authenticate(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedDevice, AuthFailure>;

    /// Authorize the device for one vault operation.
    ///
    /// # Errors
    ///
    /// Returns a policy or authentication problem when the device cannot perform the operation.
    fn authorize(
        &self,
        identity: AuthenticatedDevice,
        vault: storage::VaultId,
        operation: SyncOperation,
    ) -> Result<(), AuthFailure>;

    /// Validate the decoded write envelopes before storage.
    ///
    /// Implementations MUST validate the envelope structure, key epoch, signer certificate,
    /// membership, and signature for every write. The adapter only enforces wire shape and size;
    /// this hook is the required cryptographic and policy validation boundary.
    ///
    /// # Errors
    ///
    /// Returns an authentication or policy problem when a write is not valid for the vault.
    fn validate_write(
        &self,
        identity: AuthenticatedDevice,
        vault: storage::VaultId,
        writes: &[api::SyncWrite],
    ) -> Result<(), AuthFailure>;

    /// Resolve the account that owns an authenticated device.
    ///
    /// This is kept separate from [`AuthenticatedDevice`] because vault synchronization only
    /// needs a device identifier. Account-key routes must use this method before touching key
    /// storage, and implementations must not derive the account from caller-controlled input.
    ///
    /// # Errors
    ///
    /// Returns an authentication failure when the device is not associated with an account.
    fn account_id(
        &self,
        identity: AuthenticatedDevice,
    ) -> Result<key_storage::AccountId, AuthFailure>;

    /// Authorize an account-key operation after `DPoP` authentication.
    ///
    /// # Errors
    ///
    /// Returns an authentication or policy failure when the device cannot access account keys.
    fn authorize_keys(
        &self,
        identity: AuthenticatedDevice,
        account_id: key_storage::AccountId,
        operation: SyncKeysOperation,
    ) -> Result<(), AuthFailure>;

    /// Validate the account-key update before storage.
    ///
    /// Implementations MUST verify the signature over `update.signature_input()` with the
    /// current account signing key and require exactly one wrap for every enrolled, unrevoked
    /// device. The storage layer only enforces opaque bounds and revision replay semantics.
    ///
    /// # Errors
    ///
    /// Returns an authentication or request failure when the signature or active-device set is
    /// invalid.
    fn validate_key_bundle_update(
        &self,
        identity: AuthenticatedDevice,
        account_id: key_storage::AccountId,
        update: &api::SyncAccountKeyBundleUpdate,
    ) -> Result<(), AuthFailure>;

    /// Authenticate the first binary message on a notification WebSocket.
    ///
    /// The message is intentionally opaque to this adapter because the identity service owns the
    /// DPoP-bound token and proof encoding. Implementations MUST bind the credentials to `uri`,
    /// reject missing, malformed, expired, or revoked credentials, and return an enrolled device.
    /// The adapter limits the message to [`MAX_NOTIFICATION_AUTH_BYTES`] before calling this
    /// method.
    ///
    /// # Errors
    ///
    /// Returns an authentication problem when the first message is not valid credentials.
    fn authenticate_notification(
        &self,
        _uri: &Uri,
        _first_message: &[u8],
    ) -> Result<AuthenticatedDevice, AuthFailure> {
        Err(notification_authentication_required())
    }

    /// Authorize an authenticated device to receive content-free notifications.
    ///
    /// Implementations MUST apply account and device lifecycle policy before allowing the socket
    /// to remain open. The default fails closed until identity V3 supplies this boundary.
    ///
    /// # Errors
    ///
    /// Returns an authentication or policy problem when notifications are not allowed.
    fn authorize_notifications(&self, _identity: AuthenticatedDevice) -> Result<(), AuthFailure> {
        Err(notification_authentication_required())
    }
}

/// Build the K-4 router with an explicit authentication implementation.
///
/// The returned router is not mounted by the baseline server listener until identity V3 is
/// available. Tests and a future identity service can mount it with their own authenticator.
pub fn router<A: SyncAuthenticator>(store: Arc<SqliteStore>, authenticator: A) -> Router {
    router_with_notifications(store, authenticator, NotificationHub::default())
}

/// Build the sync router with a caller-owned local notification hub.
///
/// A deployment publishes content-free events to this hub after committing a change. The hub is
/// intentionally local to one process; PostgreSQL fan-out for multi-instance deployments remains
/// a V5 operation-layer concern.
pub fn router_with_notifications<A: SyncAuthenticator>(
    store: Arc<SqliteStore>,
    authenticator: A,
    notifications: NotificationHub,
) -> Router {
    let state = SyncHttpState { store, authenticator, notifications };
    Router::new()
        .route("/sync/v1/keys", get(keys_get::<A>).put(keys_put::<A>))
        .route("/sync/v1/notify", get(notify::<A>))
        .route("/sync/v1/vaults", post(create_vault::<A>))
        .route("/sync/v1/vaults/{vault}/keys", get(vault_keys::<A>))
        .route("/sync/v1/vaults/{vault}/epochs", post(publish_vault_epoch::<A>))
        .route("/sync/v1/vaults/{vault}/members", post(add_vault_member::<A>))
        .route("/sync/v1/vaults/{vault}/members/{account}", delete(remove_vault_member::<A>))
        .route("/sync/v1/vaults/{vault}/changes", get(changes::<A>))
        .route("/sync/v1/vaults/{vault}/snapshot", get(snapshot::<A>))
        .route("/sync/v1/vaults/{vault}/objects/{object}/versions", get(versions::<A>))
        .route("/sync/v1/vaults/{vault}/objects", post(objects::<A>))
        .route("/sync/v1/vaults/{vault}/ack", post(ack::<A>))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

#[derive(Clone)]
struct SyncHttpState<A> {
    store: Arc<SqliteStore>,
    authenticator: A,
    notifications: NotificationHub,
}

async fn notify<A: SyncAuthenticator>(
    ws: WebSocketUpgrade,
    State(state): State<SyncHttpState<A>>,
    uri: Uri,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| notification_session(socket, state, uri))
}

async fn notification_session<A: SyncAuthenticator>(
    mut socket: WebSocket,
    state: SyncHttpState<A>,
    uri: Uri,
) {
    let first_message = match tokio::time::timeout(NOTIFICATION_AUTH_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Binary(message)))) if message.len() <= MAX_NOTIFICATION_AUTH_BYTES => {
            message
        }
        Ok(Some(Ok(Message::Binary(_)))) => {
            close_notification(&mut socket, "sync.invalid_request").await;
            return;
        }
        Ok(Some(Ok(_) | Err(_)) | None) | Err(_) => {
            close_notification(&mut socket, "auth.authentication_required").await;
            return;
        }
    };
    let identity = match state.authenticator.authenticate_notification(&uri, &first_message) {
        Ok(identity) => identity,
        Err(error) => {
            close_notification(&mut socket, error.code.as_str()).await;
            return;
        }
    };
    if let Err(error) = state.authenticator.authorize_notifications(identity) {
        close_notification(&mut socket, error.code.as_str()).await;
        return;
    }

    let mut events = state.notifications.subscribe(identity.device_id);
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(payload) => {
                    if socket.send(Message::Binary(payload.into())).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    close_notification(&mut socket, "sync.notification_lagged").await;
                    return;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                Some(Ok(_)) => {}
            },
        }
    }
}

async fn close_notification(socket: &mut WebSocket, code: &str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame { code: 1008, reason: code.to_owned().into() })))
        .await;
}

fn notification_authentication_required() -> AuthFailure {
    AuthFailure::new(
        StatusCode::UNAUTHORIZED,
        "auth.authentication_required",
        "Authentication required",
        "The notification socket credentials are missing or invalid; reconnect after authenticating.",
        false,
    )
    .expect("static notification authentication failure is valid")
}

async fn create_vault<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let identity = state
        .authenticator
        .authenticate(&method, &uri, &headers)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let request = api::SyncCreateVaultRequest::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid shared-vault creation request: {error}"))
    })?;
    let vault = request.vault_id.into_bytes();
    state
        .authenticator
        .authorize(identity, vault, SyncOperation::CreateVault)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let account_id = state
        .authenticator
        .account_id(identity)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    state
        .store
        .create_shared_sync_vault(vault, account_id, &request.wrapped_vault_key)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncCreateVaultResponse {
        vault: api::SessionVault {
            id: request.vault_id,
            kind: api::VaultKind::Shared,
            seq: 0,
            key_epoch: 1,
            rotation_pending: false,
        },
    };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(
            &instance,
            format!("could not encode shared-vault response: {error}"),
        )
    })?))
}

async fn vault_keys<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Read, &instance)?;
    let account_id = state
        .authenticator
        .account_id(identity)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let keys = state
        .store
        .get_shared_sync_vault_keys(vault, account_id)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncVaultKeysResponse {
        keys: keys
            .into_iter()
            .map(|key| api::SyncVaultKey {
                epoch: key.epoch,
                wrapped_vault_key: key.wrapped_vault_key,
            })
            .collect(),
    };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode shared-vault keys: {error}"))
    })?))
}

async fn publish_vault_epoch<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let _identity = authorize(
        &state,
        &method,
        &uri,
        &headers,
        vault,
        SyncOperation::PublishVaultEpoch,
        &instance,
    )?;
    let request = api::SyncPublishVaultEpochRequest::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid shared-vault epoch request: {error}"))
    })?;
    let wraps = request
        .wrapped_keys
        .iter()
        .map(|wrap| storage::SharedVaultEpochWrap {
            account_id: wrap.account_id.into_bytes(),
            wrapped_vault_key: wrap.wrapped_vault_key.clone(),
        })
        .collect::<Vec<_>>();
    state
        .store
        .publish_shared_sync_vault_epoch(vault, request.epoch, &wraps)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncPublishVaultEpochResponse { epoch: request.epoch };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(
            &instance,
            format!("could not encode shared-vault epoch response: {error}"),
        )
    })?))
}

async fn add_vault_member<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let _identity = authorize(
        &state,
        &method,
        &uri,
        &headers,
        vault,
        SyncOperation::AddVaultMember,
        &instance,
    )?;
    let request = api::SyncAddVaultMemberRequest::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid shared-vault member request: {error}"))
    })?;
    let wraps = request
        .wrapped_keys
        .iter()
        .map(|key| storage::SharedVaultKey {
            epoch: key.epoch,
            wrapped_vault_key: key.wrapped_vault_key.clone(),
        })
        .collect::<Vec<_>>();
    state
        .store
        .add_shared_sync_vault_member(vault, request.account_id.into_bytes(), &wraps)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncAddVaultMemberResponse { account_id: request.account_id };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(
            &instance,
            format!("could not encode shared-vault member response: {error}"),
        )
    })?))
}

async fn remove_vault_member<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path((vault, account)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let account_id = parse_uuid(&account, "account", &instance)?;
    let _identity = authorize(
        &state,
        &method,
        &uri,
        &headers,
        vault,
        SyncOperation::RemoveVaultMember,
        &instance,
    )?;
    if !body.is_empty() {
        return Err(SyncHttpError::invalid(
            &instance,
            "shared-vault member removal does not accept a request body",
        ));
    }
    state
        .store
        .remove_shared_sync_vault_member(vault, account_id)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncRemoveVaultMemberResponse {
        account_id: Uuid::from_bytes(account_id),
        rotation_pending: true,
    };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(
            &instance,
            format!("could not encode shared-vault member removal response: {error}"),
        )
    })?))
}

async fn keys_get<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let identity = state
        .authenticator
        .authenticate(&method, &uri, &headers)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let account_id = state
        .authenticator
        .account_id(identity)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    state
        .authenticator
        .authorize_keys(identity, account_id, SyncKeysOperation::Read)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let bundle = state
        .store
        .get_account_key_bundle(account_id, identity.device_id)
        .await
        .map_err(|error| SyncHttpError::from_account_key_store(&error, &instance))?;
    let response = api::SyncAccountKeyBundle {
        revision: bundle.revision,
        wrapped_ark: bundle.wrapped_ark,
        account_signing_key: bundle.account_signing_key,
        account_kem_key: bundle.account_kem_key,
        recovery_blob: bundle.recovery_blob,
        certificates: bundle.certificates,
        revocations: bundle.revocations,
    };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode account key bundle: {error}"))
    })?))
}

async fn keys_put<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let identity = state
        .authenticator
        .authenticate(&method, &uri, &headers)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let account_id = state
        .authenticator
        .account_id(identity)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    state
        .authenticator
        .authorize_keys(identity, account_id, SyncKeysOperation::Write)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    if body.len() > key_storage::MAX_KEY_BUNDLE_BYTES {
        return Err(SyncHttpError::too_large(&instance, "account key bundle exceeds 4 MiB"));
    }
    let update = api::SyncAccountKeyBundleUpdate::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid account key bundle: {error}"))
    })?;
    state
        .authenticator
        .validate_key_bundle_update(identity, account_id, &update)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let update = account_key_update_to_storage(update, &instance)?;
    let result = state
        .store
        .put_account_key_bundle(account_id, &update)
        .await
        .map_err(|error| SyncHttpError::from_account_key_store(&error, &instance))?;
    let revision = match result {
        key_storage::AccountKeyBundlePut::Applied { revision }
        | key_storage::AccountKeyBundlePut::Replay { revision } => revision,
    };
    Ok(cbor_response(api::SyncAccountKeyBundlePutResponse { revision }.to_cbor().map_err(
        |error| {
            SyncHttpError::invalid(
                &instance,
                format!("could not encode account key update response: {error}"),
            )
        },
    )?))
}

async fn changes<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    RawQuery(query): RawQuery,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Read, &instance)?;
    let query = parse_query(query, &instance)?;
    let page = state
        .store
        .sync_changes(vault, query.after, query.limit)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncChangesResponse {
        changes: page.changes.into_iter().map(change_to_api).collect(),
        next_cursor: page.next_cursor,
        more: page.more,
    };
    response.validate_for_query(&query).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid change page: {error}"))
    })?;
    let _ = identity;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode change page: {error}"))
    })?))
}

async fn snapshot<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    RawQuery(query): RawQuery,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Snapshot, &instance)?;
    let query = parse_query(query, &instance)?;
    let page = state
        .store
        .sync_snapshot(vault, query.after, query.limit)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncSnapshotResponse {
        objects: page.objects.into_iter().map(change_to_api).collect(),
        next_cursor: page.next_cursor,
        more: page.more,
    };
    response.validate_for_query(&query).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid snapshot page: {error}"))
    })?;
    let _ = identity;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode snapshot page: {error}"))
    })?))
}

async fn versions<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path((vault, object)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let object = parse_uuid(&object, "object", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Versions, &instance)?;
    let versions = state
        .store
        .sync_versions(vault, object)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response =
        api::SyncVersionsResponse { versions: versions.into_iter().map(change_to_api).collect() };
    response.validate_for_object(Uuid::from_bytes(object)).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid version response: {error}"))
    })?;
    let _ = identity;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode versions: {error}"))
    })?))
}

async fn objects<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Write, &instance)?;
    if state
        .store
        .sync_vault_kind(vault)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?
        == storage::VaultKind::Organization
    {
        return Err(SyncHttpError::known(
            &instance,
            StatusCode::FORBIDDEN,
            "sync.read_only",
            "Vault is read-only",
            "Organization vaults are authored by the server; no data changed and retrying will not help.",
            false,
            false,
        ));
    }
    if body.len() > MAX_REQUEST_BYTES {
        return Err(SyncHttpError::invalid(&instance, "write batch exceeds 4 MiB"));
    }
    let batch = api::SyncWriteBatch::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid write batch: {error}"))
    })?;
    let total_bytes = batch.writes.iter().try_fold(0_usize, |total, write| {
        if write.payload.is_empty() || write.payload.len() > storage::MAX_ENVELOPE_BYTES {
            return None;
        }
        total.checked_add(write.payload.len())
    });
    if total_bytes.is_none_or(|total| total > storage::MAX_BATCH_BYTES) {
        return Err(SyncHttpError::invalid(&instance, "write envelopes exceed the sync limits"));
    }
    state
        .authenticator
        .validate_write(identity, vault, &batch.writes)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let writes = batch
        .writes
        .iter()
        .map(|write| storage::ObjectWrite {
            object_id: write.object_id.into_bytes(),
            base_sequence: write.base_seq,
            envelope: write.payload.clone(),
            tombstone: write.tombstone,
            signer_device_id: Some(identity.device_id),
        })
        .collect::<Vec<_>>();
    let receipts = state
        .store
        .write_sync_batch(vault, &writes)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncWriteBatchResponse {
        assignments: receipts
            .into_iter()
            .map(|receipt| api::SyncWriteAssignment {
                object_id: Uuid::from_bytes(receipt.object_id),
                seq: receipt.sequence,
            })
            .collect(),
    };
    response.validate_for_batch(&batch).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid write assignment: {error}"))
    })?;
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode write assignment: {error}"))
    })?))
}

async fn ack<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Acknowledge, &instance)?;
    let request = api::SyncAckRequest::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid acknowledgement: {error}"))
    })?;
    let cursor = state
        .store
        .ack_sync_cursor(vault, identity.device_id, request.cursor)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    Ok(cbor_response(api::SyncAckResponse { cursor }.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode acknowledgement: {error}"))
    })?))
}

fn authorize<A: SyncAuthenticator>(
    state: &SyncHttpState<A>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    vault: storage::VaultId,
    operation: SyncOperation,
    instance: &str,
) -> SyncResult<AuthenticatedDevice> {
    let identity = state
        .authenticator
        .authenticate(method, uri, headers)
        .map_err(|error| SyncHttpError::from_auth(error, instance))?;
    state
        .authenticator
        .authorize(identity, vault, operation)
        .map_err(|error| SyncHttpError::from_auth(error, instance))?;
    Ok(identity)
}

fn parse_query(raw: Option<String>, instance: &str) -> SyncResult<api::SyncChangesQuery> {
    let raw =
        raw.ok_or_else(|| SyncHttpError::invalid(instance, "after and limit are required"))?;
    api::SyncChangesQuery::from_query(&raw)
        .map_err(|error| SyncHttpError::invalid(instance, format!("invalid sync query: {error}")))
}

fn parse_uuid(value: &str, field: &str, instance: &str) -> SyncResult<storage::VaultId> {
    let id = Uuid::parse_str(value).map_err(|_| {
        SyncHttpError::invalid(instance, format!("{field} must be a canonical UUIDv7"))
    })?;
    if id.to_string() != value || id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122
    {
        return Err(SyncHttpError::invalid(
            instance,
            format!("{field} must be a canonical UUIDv7"),
        ));
    }
    Ok(*id.as_bytes())
}

fn require_cbor(headers: &HeaderMap, instance: &str) -> SyncResult<()> {
    let content_type =
        headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or_default();
    if content_type != "application/cbor" {
        return Err(SyncHttpError::invalid(
            instance,
            "request Content-Type must be application/cbor",
        ));
    }
    Ok(())
}

fn change_to_api(change: storage::SyncChange) -> api::SyncChange {
    api::SyncChange {
        object_id: Uuid::from_bytes(change.object_id),
        seq: change.sequence,
        payload: change.envelope,
        tombstone: change.tombstone,
        signer_device_id: change.signer_device_id.map(Uuid::from_bytes),
    }
}

fn account_key_update_to_storage(
    update: api::SyncAccountKeyBundleUpdate,
    instance: &str,
) -> SyncResult<key_storage::AccountKeyBundleUpdate> {
    let signature: [u8; api::SYNC_KEY_SIGNATURE_BYTES] =
        update.signature.try_into().map_err(|_| {
            SyncHttpError::invalid(instance, "account key signature must be exactly 64 bytes")
        })?;
    Ok(key_storage::AccountKeyBundleUpdate {
        revision: update.revision,
        device_wraps: update
            .device_wraps
            .into_iter()
            .map(|wrap| key_storage::DeviceWrap {
                device_id: wrap.device_id.into_bytes(),
                wrapped_ark: wrap.wrapped_ark,
            })
            .collect(),
        account_signing_key: update.account_signing_key,
        account_kem_key: update.account_kem_key,
        recovery_blob: update.recovery_blob,
        signature,
    })
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| byte.is_ascii_graphic() && byte != b' ')
        })
        .map_or_else(|| Uuid::new_v4().to_string(), ToOwned::to_owned)
}

fn cbor_response(body: Vec<u8>) -> Response {
    let content_type = HeaderValue::from_static("application/cbor");
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

type SyncResult<T> = Result<T, Box<SyncHttpError>>;

#[derive(Debug)]
struct SyncHttpError {
    status: StatusCode,
    problem: ProblemDetails,
    body: Option<Vec<u8>>,
}

impl SyncHttpError {
    fn from_auth(error: AuthFailure, instance: &str) -> Box<Self> {
        Self::known(
            instance,
            error.status,
            error.code.as_str(),
            error.title,
            error.detail,
            false,
            error.retryable,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn from_store(error: storage::SyncStoreError, instance: &str) -> Box<Self> {
        match error {
            storage::SyncStoreError::VaultAlreadyExists => Self::known(
                instance,
                StatusCode::CONFLICT,
                "sync.conflict",
                "Sync vault already exists",
                "The requested vault identifier is already present; no data changed and retrying with the same identifier will not help.",
                false,
                false,
            ),
            storage::SyncStoreError::EpochConflict { current_epoch } => Self::known(
                instance,
                StatusCode::CONFLICT,
                "sync.conflict",
                "Sync vault epoch conflict",
                format!(
                    "The requested vault epoch follows neither the current epoch {current_epoch} nor an exact replay; no data changed and fetch current keys before retrying."
                ),
                false,
                true,
            ),
            storage::SyncStoreError::MemberSetMismatch => Self::invalid(
                instance,
                "shared-vault epoch wraps must contain exactly one entry for every current member",
            ),
            storage::SyncStoreError::InvalidEpochWraps => {
                Self::invalid(instance, "shared-vault epoch wraps are invalid")
            }
            error @ (storage::SyncStoreError::MemberAlreadyExists
            | storage::SyncStoreError::MemberEpochMismatch
            | storage::SyncStoreError::InvalidMemberWraps
            | storage::SyncStoreError::LastAdmin) => Self::from_member_store(&error, instance),
            storage::SyncStoreError::VaultNotFound
            | storage::SyncStoreError::MemberNotFound
            | storage::SyncStoreError::ObjectNotFound => Self::known(
                instance,
                StatusCode::NOT_FOUND,
                "sync.object_not_found",
                "Sync object not found",
                "The requested sync resource does not exist; no data changed and retrying will not help.",
                false,
                false,
            ),
            storage::SyncStoreError::CursorExpired { purge_horizon } => Self::known(
                instance,
                StatusCode::GONE,
                "sync.cursor_expired",
                "Sync cursor expired",
                format!(
                    "The cursor is below the purge horizon ({purge_horizon}); no data changed and a full snapshot is required."
                ),
                false,
                false,
            ),
            storage::SyncStoreError::CursorAhead { cursor, current } => Self::known(
                instance,
                StatusCode::BAD_REQUEST,
                "sync.cursor_ahead",
                "Sync cursor is ahead",
                format!(
                    "Cursor {cursor} is ahead of the current sequence {current}; no data changed and retrying without a lower cursor will not help."
                ),
                false,
                false,
            ),
            storage::SyncStoreError::Conflict { conflicts } => {
                let problem = Self::known(
                    instance,
                    StatusCode::CONFLICT,
                    "sync.conflict",
                    "Sync write conflict",
                    "One or more objects changed; no data changed and merge the returned current versions before retrying.",
                    false,
                    true,
                );
                problem.with_conflicts(&conflicts)
            }
            storage::SyncStoreError::EmptyBatch
            | storage::SyncStoreError::BatchObjectLimit
            | storage::SyncStoreError::BatchByteLimit
            | storage::SyncStoreError::InvalidEnvelope
            | storage::SyncStoreError::DuplicateObject
            | storage::SyncStoreError::InvalidPageSize
            | storage::SyncStoreError::InvalidRetentionTime => {
                Self::invalid(instance, error.to_string())
            }
            storage::SyncStoreError::EmptyVaultKey => Self::invalid(instance, error.to_string()),
            storage::SyncStoreError::VaultKeyTooLarge => {
                Self::too_large(instance, error.to_string())
            }
            storage::SyncStoreError::Constraint(_)
            | storage::SyncStoreError::SequenceExhausted
            | storage::SyncStoreError::CorruptRow(_)
            | storage::SyncStoreError::Database(_) => Self::known(
                instance,
                StatusCode::SERVICE_UNAVAILABLE,
                "sync.storage_unavailable",
                "Sync service unavailable",
                "The server could not complete the sync request; no data changed and retrying may help.",
                false,
                true,
            ),
        }
    }

    fn from_member_store(error: &storage::SyncStoreError, instance: &str) -> Box<Self> {
        match error {
            storage::SyncStoreError::MemberAlreadyExists => Self::known(
                instance,
                StatusCode::CONFLICT,
                "sync.conflict",
                "Sync vault member already exists",
                "The account is already a member of this vault; no data changed and retrying will not help.",
                false,
                false,
            ),
            storage::SyncStoreError::MemberEpochMismatch => Self::invalid(
                instance,
                "shared-vault member wraps must contain exactly one entry for every current epoch",
            ),
            storage::SyncStoreError::InvalidMemberWraps => {
                Self::invalid(instance, "shared-vault member wraps are invalid")
            }
            storage::SyncStoreError::LastAdmin => Self::known(
                instance,
                StatusCode::CONFLICT,
                "sync.conflict",
                "Sync vault must retain an administrator",
                "The last vault administrator cannot be removed; no data changed and retrying will not help.",
                false,
                false,
            ),
            _ => unreachable!("non-member storage error passed to member mapper"),
        }
    }

    fn from_account_key_store(
        error: &key_storage::AccountKeyStoreError,
        instance: &str,
    ) -> Box<Self> {
        match error {
            key_storage::AccountKeyStoreError::BundleNotFound => Self::known(
                instance,
                StatusCode::NOT_FOUND,
                "sync.object_not_found",
                "Account key bundle not found",
                "The account key bundle is unavailable for this device; no data changed and retrying will not help.",
                false,
                false,
            ),
            key_storage::AccountKeyStoreError::Conflict { current_revision } => Self::known(
                instance,
                StatusCode::CONFLICT,
                "sync.conflict",
                "Account key bundle conflict",
                format!(
                    "The account key revision conflicts with the current revision {current_revision}; no data changed and fetch the current bundle before retrying."
                ),
                false,
                true,
            ),
            key_storage::AccountKeyStoreError::ArtifactTooLarge(_)
            | key_storage::AccountKeyStoreError::DeviceWrapLimit => {
                Self::too_large(instance, "account key bundle exceeds the configured limits")
            }
            key_storage::AccountKeyStoreError::InvalidRevision
            | key_storage::AccountKeyStoreError::EmptyArtifact(_)
            | key_storage::AccountKeyStoreError::InvalidDeviceWraps
            | key_storage::AccountKeyStoreError::InvalidSignature => {
                Self::invalid(instance, "account key bundle fields are invalid")
            }
            key_storage::AccountKeyStoreError::RevisionExhausted
            | key_storage::AccountKeyStoreError::Constraint(_)
            | key_storage::AccountKeyStoreError::CorruptRow(_)
            | key_storage::AccountKeyStoreError::Database(_) => Self::known(
                instance,
                StatusCode::SERVICE_UNAVAILABLE,
                "sync.storage_unavailable",
                "Sync service unavailable",
                "The server could not complete the account key request; no data changed and retrying may help.",
                false,
                true,
            ),
        }
    }

    fn invalid(instance: &str, detail: impl Into<String>) -> Box<Self> {
        Self::known(
            instance,
            StatusCode::BAD_REQUEST,
            "sync.invalid_request",
            "Invalid sync request",
            detail,
            false,
            false,
        )
    }

    fn too_large(instance: &str, detail: impl Into<String>) -> Box<Self> {
        Self::known(
            instance,
            StatusCode::PAYLOAD_TOO_LARGE,
            "sync.invalid_request",
            "Sync request is too large",
            detail,
            false,
            false,
        )
    }

    fn known(
        instance: &str,
        status: StatusCode,
        code: &str,
        title: impl Into<String>,
        detail: impl Into<String>,
        changed: bool,
        retryable: bool,
    ) -> Box<Self> {
        let code = ErrorCode::new(code).expect("sync HTTP error code must be syntactically valid");
        let problem =
            ProblemDetails::new(code, status.as_u16(), title, detail, instance, changed, retryable)
                .expect("sync HTTP problem details must be valid");
        Box::new(Self { status, problem, body: None })
    }

    fn with_conflicts(mut self: Box<Self>, conflicts: &[storage::ConflictEntry]) -> Box<Self> {
        self.body = encode_conflicts(&self.problem, conflicts).ok();
        self
    }
}

impl IntoResponse for Box<SyncHttpError> {
    fn into_response(self) -> Response {
        let body = self.body.clone().unwrap_or_else(|| {
            self.problem.to_cbor().expect("validated sync HTTP problem must encode")
        });
        (
            self.status,
            [(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+cbor"))],
            body,
        )
            .into_response()
    }
}

fn encode_conflicts(
    problem: &ProblemDetails,
    conflicts: &[storage::ConflictEntry],
) -> Result<Vec<u8>, String> {
    let Value::Map(mut fields) =
        cbor::decode(&problem.to_cbor().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?
    else {
        return Err("problem details did not encode as a map".into());
    };
    // The pre-Stable extension keeps every stale object identifiable. A missing current row is
    // represented by null so clients can distinguish it from a truncated conflict response.
    let entries = conflicts
        .iter()
        .map(|conflict| {
            let current = conflict.current.as_ref().map(|change| {
                Value::Map(vec![
                    (Value::UInt(1), Value::Bytes(change.object_id.to_vec())),
                    (Value::UInt(2), Value::UInt(change.sequence)),
                    (Value::UInt(3), Value::Bytes(change.envelope.clone())),
                    (Value::UInt(4), Value::Bool(change.tombstone)),
                    (
                        Value::UInt(5),
                        change.signer_device_id.map_or(Value::Null, |id| Value::Bytes(id.to_vec())),
                    ),
                ])
            });
            Value::Map(vec![
                (Value::Text("object_id".into()), Value::Bytes(conflict.object_id.to_vec())),
                (Value::Text("current".into()), current.unwrap_or(Value::Null)),
            ])
        })
        .collect();
    fields.push((Value::Text("conflicts".into()), Value::Array(entries)));
    cbor::encode(&Value::Map(fields)).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header::AUTHORIZATION};
    use futures_util::{SinkExt, StreamExt};
    use scoplen_api::sync::{
        SyncAckRequest, SyncChangesResponse, SyncWriteBatch, SyncWriteBatchResponse,
    };
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    use tower::ServiceExt;

    use super::*;

    #[derive(Clone)]
    struct TestAuthenticator {
        device_id: storage::DeviceId,
        allowed: bool,
        /// Test-only stand-in for the crypto and membership validator injected in production.
        reject_writes: bool,
        seen_requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl TestAuthenticator {
        fn new(device_id: storage::DeviceId, allowed: bool) -> Self {
            Self {
                device_id,
                allowed,
                reject_writes: false,
                seen_requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn account_id() -> key_storage::AccountId {
            [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 42]
        }
    }

    impl SyncAuthenticator for TestAuthenticator {
        fn authenticate(
            &self,
            method: &Method,
            uri: &Uri,
            headers: &HeaderMap,
        ) -> Result<AuthenticatedDevice, AuthFailure> {
            self.seen_requests
                .lock()
                .expect("request recorder lock")
                .push((method.to_string(), uri.to_string()));
            if headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok())
                != Some("DPoP test-token")
                || headers.get("dpop").is_none()
            {
                return Err(AuthFailure::new(
                    StatusCode::UNAUTHORIZED,
                    "auth.authentication_required",
                    "Authentication required",
                    "A DPoP-bound access token and proof are required; no data changed and retry after authentication.",
                    false,
                )
                .expect("test auth failure"));
            }
            Ok(AuthenticatedDevice { device_id: self.device_id })
        }

        fn authorize(
            &self,
            _identity: AuthenticatedDevice,
            _vault: storage::VaultId,
            _operation: SyncOperation,
        ) -> Result<(), AuthFailure> {
            if self.allowed {
                Ok(())
            } else {
                Err(AuthFailure::new(
                    StatusCode::FORBIDDEN,
                    "policy.denied",
                    "Sync access denied",
                    "The device is not authorized for this vault; no data changed and retrying will not help.",
                    false,
                )
                .expect("test policy failure"))
            }
        }

        fn validate_write(
            &self,
            _identity: AuthenticatedDevice,
            _vault: storage::VaultId,
            _writes: &[api::SyncWrite],
        ) -> Result<(), AuthFailure> {
            if self.reject_writes {
                Err(AuthFailure::new(
                    StatusCode::BAD_REQUEST,
                    "sync.invalid_request",
                    "Invalid sync envelope",
                    "The injected envelope validator rejected this write; no data changed and retrying will not help.",
                    false,
                )
                .expect("test envelope failure"))
            } else {
                Ok(())
            }
        }

        fn account_id(
            &self,
            _identity: AuthenticatedDevice,
        ) -> Result<key_storage::AccountId, AuthFailure> {
            Ok(Self::account_id())
        }

        fn authorize_keys(
            &self,
            _identity: AuthenticatedDevice,
            _account_id: key_storage::AccountId,
            _operation: SyncKeysOperation,
        ) -> Result<(), AuthFailure> {
            if self.allowed {
                Ok(())
            } else {
                Err(AuthFailure::new(
                    StatusCode::FORBIDDEN,
                    "policy.denied",
                    "Account key access denied",
                    "The device is not authorized for account keys; no data changed and retrying will not help.",
                    false,
                )
                .expect("test policy failure"))
            }
        }

        fn validate_key_bundle_update(
            &self,
            _identity: AuthenticatedDevice,
            _account_id: key_storage::AccountId,
            _update: &api::SyncAccountKeyBundleUpdate,
        ) -> Result<(), AuthFailure> {
            if self.reject_writes {
                Err(AuthFailure::new(
                    StatusCode::BAD_REQUEST,
                    "sync.invalid_request",
                    "Invalid account key bundle",
                    "The injected account key validator rejected this update; no data changed and retrying will not help.",
                    false,
                )
                .expect("test key validation failure"))
            } else {
                Ok(())
            }
        }

        fn authenticate_notification(
            &self,
            _uri: &Uri,
            first_message: &[u8],
        ) -> Result<AuthenticatedDevice, AuthFailure> {
            if first_message == b"notify-test-token" {
                Ok(AuthenticatedDevice { device_id: self.device_id })
            } else {
                Err(AuthFailure::new(
                    StatusCode::UNAUTHORIZED,
                    "auth.authentication_required",
                    "Authentication required",
                    "A valid notification credential is required; reconnect after authentication.",
                    false,
                )
                .expect("test notification auth failure"))
            }
        }

        fn authorize_notifications(
            &self,
            _identity: AuthenticatedDevice,
        ) -> Result<(), AuthFailure> {
            if self.allowed {
                Ok(())
            } else {
                Err(AuthFailure::new(
                    StatusCode::FORBIDDEN,
                    "policy.denied",
                    "Notification access denied",
                    "The device is not authorized for sync notifications; reconnect after policy changes.",
                    false,
                )
                .expect("test notification policy failure"))
            }
        }
    }

    async fn test_store() -> (Arc<SqliteStore>, storage::VaultId, storage::DeviceId) {
        let path = std::env::temp_dir().join(format!("scoplen-http-{}", Uuid::new_v4()));
        let store = SqliteStore::open(&path).await.expect("open store");
        let vault = Uuid::now_v7().into_bytes();
        let device = Uuid::now_v7().into_bytes();
        store.create_sync_vault(vault, storage::VaultKind::Personal).await.expect("create vault");
        (Arc::new(store), vault, device)
    }

    fn path(id: storage::VaultId) -> String {
        Uuid::from_bytes(id).to_string()
    }

    fn request_headers(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header(AUTHORIZATION, "DPoP test-token").header("dpop", "test-proof")
    }

    #[tokio::test]
    async fn shared_vault_creation_round_trips_and_rejects_duplicates() {
        let (store, _vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let vault = Uuid::now_v7();
        let body =
            api::SyncCreateVaultRequest { vault_id: vault, wrapped_vault_key: vec![1, 2, 3] }
                .to_cbor()
                .expect("create request");
        let make_request = || {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri("/sync/v1/vaults")
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(body.clone()))
            .expect("create request builder")
        };

        let response = app.clone().oneshot(make_request()).await.expect("create response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("create response body");
        let created =
            api::SyncCreateVaultResponse::from_cbor(&response_body).expect("create response cbor");
        assert_eq!(created.vault.id, vault);
        assert_eq!(created.vault.kind, api::VaultKind::Shared);
        assert_eq!(created.vault.seq, 0);
        assert_eq!(created.vault.key_epoch, 1);
        assert!(!created.vault.rotation_pending);

        let response = app
            .clone()
            .oneshot(
                request_headers(
                    Request::builder()
                        .uri(format!("/sync/v1/vaults/{}/keys", path(vault.into_bytes()))),
                )
                .body(Body::empty())
                .expect("keys request"),
            )
            .await
            .expect("keys response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("keys response body");
        let keys =
            api::SyncVaultKeysResponse::from_cbor(&response_body).expect("keys response cbor");
        assert_eq!(keys.keys.len(), 1);
        assert_eq!(keys.keys[0].epoch, 1);
        assert_eq!(keys.keys[0].wrapped_vault_key, vec![1, 2, 3]);

        let epoch_body = api::SyncPublishVaultEpochRequest {
            epoch: 2,
            wrapped_keys: vec![api::SyncVaultEpochWrap {
                account_id: Uuid::from_bytes(TestAuthenticator::account_id()),
                wrapped_vault_key: vec![4, 5, 6],
            }],
        }
        .to_cbor()
        .expect("epoch request");
        let epoch_request = || {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri(format!("/sync/v1/vaults/{}/epochs", path(vault.into_bytes())))
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(epoch_body.clone()))
            .expect("epoch request builder")
        };
        let response = app.clone().oneshot(epoch_request()).await.expect("epoch response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("epoch response body");
        assert_eq!(
            api::SyncPublishVaultEpochResponse::from_cbor(&response_body)
                .expect("epoch response cbor")
                .epoch,
            2
        );
        let response = app.clone().oneshot(epoch_request()).await.expect("epoch conflict");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("epoch conflict body");
        assert_eq!(
            ProblemDetails::from_cbor(&response_body)
                .expect("epoch conflict problem")
                .code
                .as_str(),
            "sync.conflict"
        );

        let response = app.clone().oneshot(make_request()).await.expect("duplicate response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("duplicate body");
        let problem = ProblemDetails::from_cbor(&response_body).expect("duplicate problem");
        assert_eq!(problem.code.as_str(), "sync.conflict");
        assert!(!problem.changed);
        assert!(!problem.retryable);
    }

    #[tokio::test]
    async fn shared_vault_member_addition_routes_and_maps_conflicts() {
        let (store, _personal_vault, device) = test_store().await;
        let vault = Uuid::now_v7();
        let admin = TestAuthenticator::account_id();
        store
            .create_shared_sync_vault(vault.into_bytes(), admin, &[1, 2, 3])
            .await
            .expect("create shared vault");
        store
            .publish_shared_sync_vault_epoch(
                vault.into_bytes(),
                2,
                &[storage::SharedVaultEpochWrap {
                    account_id: admin,
                    wrapped_vault_key: vec![7, 8, 9],
                }],
            )
            .await
            .expect("publish second epoch");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let member = Uuid::now_v7();
        let body = api::SyncAddVaultMemberRequest {
            account_id: member,
            wrapped_keys: vec![
                api::SyncVaultKey { epoch: 1, wrapped_vault_key: vec![4, 5, 6] },
                api::SyncVaultKey { epoch: 2, wrapped_vault_key: vec![10, 11, 12] },
            ],
        }
        .to_cbor()
        .expect("member request");
        let make_request = || {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri(format!("/sync/v1/vaults/{}/members", path(vault.into_bytes())))
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(body.clone()))
            .expect("member request builder")
        };

        let response = app.clone().oneshot(make_request()).await.expect("member response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("member response body");
        assert_eq!(
            api::SyncAddVaultMemberResponse::from_cbor(&response_body)
                .expect("member response cbor")
                .account_id,
            member
        );
        assert_eq!(
            store
                .get_shared_sync_vault_keys(vault.into_bytes(), member.into_bytes())
                .await
                .expect("stored member keys"),
            vec![
                storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![4, 5, 6] },
                storage::SharedVaultKey { epoch: 2, wrapped_vault_key: vec![10, 11, 12] },
            ]
        );

        let response =
            app.clone().oneshot(make_request()).await.expect("duplicate member response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("duplicate member body");
        assert_eq!(
            ProblemDetails::from_cbor(&response_body)
                .expect("duplicate member problem")
                .code
                .as_str(),
            "sync.conflict"
        );

        let missing_epoch_account = Uuid::now_v7();
        let missing_epoch_body = api::SyncAddVaultMemberRequest {
            account_id: missing_epoch_account,
            wrapped_keys: vec![api::SyncVaultKey { epoch: 1, wrapped_vault_key: vec![10] }],
        }
        .to_cbor()
        .expect("missing epoch member request");
        let response = app
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/sync/v1/vaults/{}/members", path(vault.into_bytes())))
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(missing_epoch_body))
                .expect("missing epoch request builder"),
            )
            .await
            .expect("missing epoch response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("missing epoch body");
        assert_eq!(
            ProblemDetails::from_cbor(&response_body).expect("missing epoch problem").code.as_str(),
            "sync.invalid_request"
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn shared_vault_member_removal_routes_and_marks_rotation() {
        let (store, _personal_vault, device) = test_store().await;
        let vault = Uuid::now_v7();
        let admin = TestAuthenticator::account_id();
        let member = Uuid::now_v7();
        store
            .create_shared_sync_vault(vault.into_bytes(), admin, &[1, 2, 3])
            .await
            .expect("create shared vault");
        store
            .add_shared_sync_vault_member(
                vault.into_bytes(),
                member.into_bytes(),
                &[storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![4, 5] }],
            )
            .await
            .expect("add member");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let removal_request = || {
            request_headers(Request::builder().method("DELETE").uri(format!(
                "/sync/v1/vaults/{}/members/{}",
                path(vault.into_bytes()),
                member
            )))
            .body(Body::empty())
            .expect("removal request builder")
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/sync/v1/vaults/{}/members/{}", path(vault.into_bytes()), member))
                    .body(Body::from(vec![1]))
                    .expect("unauthenticated removal request"),
            )
            .await
            .expect("unauthenticated removal response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let denied = router(store.clone(), TestAuthenticator::new(device, false));
        let response = denied.oneshot(removal_request()).await.expect("denied removal response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app.clone().oneshot(removal_request()).await.expect("removal response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("removal response body");
        assert_eq!(
            api::SyncRemoveVaultMemberResponse::from_cbor(&response_body)
                .expect("removal response cbor"),
            api::SyncRemoveVaultMemberResponse { account_id: member, rotation_pending: true }
        );
        let response = app.clone().oneshot(removal_request()).await.expect("missing removal");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("missing removal body");
        assert_eq!(
            ProblemDetails::from_cbor(&response_body)
                .expect("missing removal problem")
                .code
                .as_str(),
            "sync.object_not_found"
        );

        let response = app
            .clone()
            .oneshot(
                request_headers(Request::builder().method("DELETE").uri(format!(
                    "/sync/v1/vaults/{}/members/{}",
                    path(vault.into_bytes()),
                    Uuid::from_bytes(admin)
                )))
                .body(Body::empty())
                .expect("last admin request builder"),
            )
            .await
            .expect("last admin response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("last admin body");
        assert_eq!(
            ProblemDetails::from_cbor(&response_body).expect("last admin problem").code.as_str(),
            "sync.conflict"
        );

        let response = app
            .clone()
            .oneshot(
                request_headers(Request::builder().method("DELETE").uri(format!(
                    "/sync/v1/vaults/{}/members/{}",
                    path(vault.into_bytes()),
                    Uuid::now_v7()
                )))
                .body(Body::from(vec![1]))
                .expect("body request builder"),
            )
            .await
            .expect("body response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                request_headers(Request::builder().method("DELETE").uri(format!(
                    "/sync/v1/vaults/{}/members/not-a-uuid",
                    path(vault.into_bytes())
                )))
                .body(Body::empty())
                .expect("malformed account request builder"),
            )
            .await
            .expect("malformed account response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn shared_vault_creation_preserves_auth_and_request_boundaries() {
        let (store, _vault, device) = test_store().await;
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/sync/v1/vaults")
                .header(header::CONTENT_TYPE, "application/cbor")
        };
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let response = app
            .clone()
            .oneshot(request().body(Body::from(vec![0xf6])).expect("malformed request"))
            .await
            .expect("malformed response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body =
            api::SyncCreateVaultRequest { vault_id: Uuid::now_v7(), wrapped_vault_key: vec![1] }
                .to_cbor()
                .expect("valid request");
        let denied = router(store.clone(), TestAuthenticator::new(device, false));
        let response = denied
            .oneshot(request_headers(request()).body(Body::from(body)).expect("denied request"))
            .await
            .expect("denied response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let missing_member = router(store, TestAuthenticator::new(device, true));
        let response = missing_member
            .oneshot(
                request_headers(
                    Request::builder()
                        .uri(format!("/sync/v1/vaults/{}/keys", path(Uuid::now_v7().into_bytes()))),
                )
                .body(Body::empty())
                .expect("missing keys request"),
            )
            .await
            .expect("missing keys response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn key_update(device_ids: [storage::DeviceId; 2]) -> api::SyncAccountKeyBundleUpdate {
        api::SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![
                api::SyncAccountDeviceWrap {
                    device_id: Uuid::from_bytes(device_ids[0]),
                    wrapped_ark: vec![1, 2],
                },
                api::SyncAccountDeviceWrap {
                    device_id: Uuid::from_bytes(device_ids[1]),
                    wrapped_ark: vec![3, 4],
                },
            ],
            account_signing_key: vec![5, 6],
            account_kem_key: vec![7, 8],
            recovery_blob: vec![9, 10],
            signature: vec![0x11; api::SYNC_KEY_SIGNATURE_BYTES],
        }
    }

    async fn notification_server(
        app: Router,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind notification listener");
        let address = listener.local_addr().expect("notification listener address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve notification router");
        });
        (address, server)
    }

    #[tokio::test]
    async fn notification_socket_authenticates_and_receives_targeted_events() {
        let (store, _vault, device) = test_store().await;
        let hub = NotificationHub::default();
        let app =
            router_with_notifications(store, TestAuthenticator::new(device, true), hub.clone());
        let (address, server) = notification_server(app).await;
        let (mut socket, _) = connect_async(format!("ws://{address}/sync/v1/notify"))
            .await
            .expect("notification websocket");
        socket
            .send(ClientMessage::Binary(b"notify-test-token".to_vec().into()))
            .await
            .expect("send notification credentials");

        let event = api::SyncNotification::VaultAdvanced { vault: Uuid::now_v7(), seq: 4 };
        for _ in 0..100 {
            if hub.receiver_count(device) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(hub.publish(device, &event).expect("encode event"), 1);
        let message = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("notification delivery timeout")
            .expect("notification socket message")
            .expect("notification websocket frame");
        let ClientMessage::Binary(payload) = message else {
            panic!("notification payload is not binary");
        };
        assert_eq!(api::SyncNotification::from_cbor(&payload).expect("notification cbor"), event);
        socket.close(None).await.expect("close notification websocket");
        server.abort();
    }

    #[tokio::test]
    async fn notification_socket_closes_on_invalid_first_message() {
        let (store, _vault, device) = test_store().await;
        let app = router_with_notifications(
            store,
            TestAuthenticator::new(device, true),
            NotificationHub::default(),
        );
        let (address, server) = notification_server(app).await;
        let (mut socket, _) = connect_async(format!("ws://{address}/sync/v1/notify"))
            .await
            .expect("notification websocket");
        socket
            .send(ClientMessage::Binary(b"bad-token".to_vec().into()))
            .await
            .expect("send invalid credentials");
        let message = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("close timeout")
            .expect("close frame")
            .expect("notification websocket frame");
        let ClientMessage::Close(Some(frame)) = message else {
            panic!("invalid credentials did not close the socket");
        };
        assert_eq!(frame.reason, "auth.authentication_required");
        server.abort();
    }

    #[tokio::test]
    async fn account_key_get_put_replay_and_conflict_round_trip_through_cbor() {
        let (store, _vault, _) = test_store().await;
        let mut ids = [Uuid::now_v7(), Uuid::now_v7()];
        ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let device_ids = [ids[0].into_bytes(), ids[1].into_bytes()];
        let device = device_ids[0];
        let authenticator = TestAuthenticator::new(device, true);
        let app = router(store.clone(), authenticator);
        store
            .replace_account_key_statements(
                TestAuthenticator::account_id(),
                &[vec![3], vec![1], vec![3]],
                &[vec![2]],
            )
            .await
            .expect("statements");
        let update = key_update(device_ids);
        let body = update.to_cbor().expect("key update");
        let request = request_headers(
            Request::builder()
                .method("PUT")
                .uri("/sync/v1/keys")
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(body.clone()))
        .expect("put request");
        let response = app.clone().oneshot(request).await.expect("put response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("put body");
        assert_eq!(
            api::SyncAccountKeyBundlePutResponse::from_cbor(&response_body)
                .expect("put response cbor")
                .revision,
            1
        );

        let request = request_headers(Request::builder().uri("/sync/v1/keys"))
            .body(Body::empty())
            .expect("get request");
        let response = app.clone().oneshot(request).await.expect("get response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("get body");
        let bundle = api::SyncAccountKeyBundle::from_cbor(&response_body).expect("get cbor");
        assert_eq!(bundle.revision, 1);
        assert_eq!(bundle.wrapped_ark, vec![1, 2]);
        assert_eq!(bundle.certificates, vec![vec![1], vec![3]]);
        assert_eq!(bundle.revocations, vec![vec![2]]);

        let request = request_headers(
            Request::builder()
                .method("PUT")
                .uri("/sync/v1/keys")
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(body))
        .expect("replay request");
        let response = app.clone().oneshot(request).await.expect("replay response");
        assert_eq!(response.status(), StatusCode::OK);

        let mut changed = update;
        changed.account_kem_key = vec![99];
        let request = request_headers(
            Request::builder()
                .method("PUT")
                .uri("/sync/v1/keys")
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(changed.to_cbor().expect("changed update")))
        .expect("conflict request");
        let response = app.oneshot(request).await.expect("conflict response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("conflict body");
        let problem = ProblemDetails::from_cbor(&response_body).expect("conflict problem");
        assert_eq!(problem.code.as_str(), "sync.conflict");
    }

    #[tokio::test]
    async fn account_key_errors_preserve_auth_and_not_found_boundaries() {
        let (store, _vault, _) = test_store().await;
        let device = Uuid::now_v7().into_bytes();
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let request = Request::builder()
            .uri("/sync/v1/keys")
            .body(Body::empty())
            .expect("unauthenticated request");
        let response = app.clone().oneshot(request).await.expect("auth response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth body");
        assert_eq!(
            ProblemDetails::from_cbor(&body).expect("auth problem").code.as_str(),
            "auth.authentication_required"
        );

        let unknown = Uuid::now_v7().into_bytes();
        let app = router(store, TestAuthenticator::new(unknown, true));
        let request = request_headers(Request::builder().uri("/sync/v1/keys"))
            .body(Body::empty())
            .expect("missing bundle request");
        let response = app.oneshot(request).await.expect("missing bundle response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("missing bundle body");
        assert_eq!(
            ProblemDetails::from_cbor(&body).expect("missing bundle problem").code.as_str(),
            "sync.object_not_found"
        );
    }

    #[tokio::test]
    async fn passes_dpop_request_target_to_authenticator() {
        let (store, vault, device) = test_store().await;
        let authenticator = TestAuthenticator::new(device, true);
        let seen_requests = authenticator.seen_requests.clone();
        let app = router(store, authenticator);
        let uri = format!("/sync/v1/vaults/{}/ack", path(vault));
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(SyncAckRequest { cursor: 0 }.to_cbor().expect("ack")))
        .expect("request");
        let response = app.oneshot(request).await.expect("ack response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            seen_requests.lock().expect("request recorder lock").as_slice(),
            &[("POST".into(), uri)]
        );
    }

    #[tokio::test]
    async fn changes_ack_and_write_round_trip_through_cbor() {
        let (store, vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let object = Uuid::now_v7();
        let write = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: object,
                base_seq: None,
                payload: vec![1, 2, 3],
                tombstone: false,
            }],
        };
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(write.to_cbor().expect("encode write")))
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("write response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("write body");
        let assignments =
            SyncWriteBatchResponse::from_cbor(&body).expect("write assignments response");
        assert_eq!(assignments.assignments[0].object_id, object);

        let request = request_headers(
            Request::builder()
                .uri(format!("/sync/v1/vaults/{}/changes?after=0&limit=10", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("changes response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("changes body");
        let changes = SyncChangesResponse::from_cbor(&body).expect("changes response");
        assert_eq!(changes.changes.len(), 1);
        assert_eq!(changes.changes[0].object_id, object);

        let ack = SyncAckRequest { cursor: changes.next_cursor }.to_cbor().expect("ack");
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/ack", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(ack))
        .expect("request");
        let response = app.oneshot(request).await.expect("ack response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(store.ping().await.is_ok());
    }

    #[tokio::test]
    async fn rejects_auth_content_type_query_and_ahead_cursor() {
        let (store, vault, device) = test_store().await;
        let app = router(store, TestAuthenticator::new(device, true));
        let request = Request::builder()
            .uri(format!("/sync/v1/vaults/{}/changes?after=00&limit=1", path(vault)))
            .body(Body::empty())
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("auth response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth body");
        let problem = ProblemDetails::from_cbor(&body).expect("auth problem details");
        assert_eq!(problem.code.as_str(), "auth.authentication_required");

        let request = request_headers(
            Request::builder().uri(format!("/sync/v1/vaults/{}/changes?after=0", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("query response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("query body");
        let problem = ProblemDetails::from_cbor(&body).expect("query problem");
        assert_eq!(problem.code.as_str(), "sync.invalid_request");

        let request = request_headers(
            Request::builder().method("POST").uri(format!("/sync/v1/vaults/{}/ack", path(vault))),
        )
        .body(Body::from(SyncAckRequest { cursor: 0 }.to_cbor().expect("ack")))
        .expect("request");
        let response = app.clone().oneshot(request).await.expect("content type response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/ack", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(SyncAckRequest { cursor: 1 }.to_cbor().expect("ack")))
        .expect("request");
        let response = app.oneshot(request).await.expect("ahead response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("ahead body");
        let problem = ProblemDetails::from_cbor(&body).expect("ahead problem");
        assert_eq!(problem.code.as_str(), "sync.cursor_ahead");
    }

    #[tokio::test]
    async fn conflict_problem_contains_current_change_extension() {
        let (store, vault, device) = test_store().await;
        let app = router(store, TestAuthenticator::new(device, true));
        let object = Uuid::now_v7();
        let make_request = |batch: SyncWriteBatch| {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(batch.to_cbor().expect("encode batch")))
            .expect("request")
        };
        let first = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: object,
                base_seq: None,
                payload: vec![1],
                tombstone: false,
            }],
        };
        assert_eq!(
            app.clone().oneshot(make_request(first)).await.expect("first").status(),
            StatusCode::OK
        );
        let stale = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: object,
                base_seq: None,
                payload: vec![2],
                tombstone: false,
            }],
        };
        let response = app.clone().oneshot(make_request(stale)).await.expect("conflict");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("conflict body");
        let Value::Map(fields) = cbor::decode(&body).expect("problem cbor") else {
            panic!("problem is map");
        };
        let conflicts = fields
            .into_iter()
            .find_map(|(key, value)| (key == Value::Text("conflicts".into())).then_some(value));
        assert!(matches!(conflicts, Some(Value::Array(values)) if values.len() == 1));

        let absent_object = Uuid::now_v7();
        let absent = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: absent_object,
                base_seq: Some(1),
                payload: vec![3],
                tombstone: false,
            }],
        };
        let response = app.oneshot(make_request(absent)).await.expect("absent conflict");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("absent conflict body");
        let Value::Map(fields) = cbor::decode(&body).expect("absent conflict cbor") else {
            panic!("problem is map");
        };
        let Some(Value::Array(entries)) = fields
            .into_iter()
            .find_map(|(key, value)| (key == Value::Text("conflicts".into())).then_some(value))
        else {
            panic!("conflict extension is missing");
        };
        assert_eq!(entries.len(), 1);
        let Value::Map(entry) = &entries[0] else {
            panic!("conflict entry is not a map");
        };
        assert!(entry.iter().any(|(key, value)| {
            key == &Value::Text("current".into()) && value == &Value::Null
        }));
    }

    #[tokio::test]
    async fn injected_write_validator_rejects_before_storage() {
        let (store, vault, device) = test_store().await;
        let mut authenticator = TestAuthenticator::new(device, true);
        authenticator.reject_writes = true;
        let app = router(store.clone(), authenticator);
        let write = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![0xff],
                tombstone: false,
            }],
        };
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(write.to_cbor().expect("encode write")))
        .expect("request");
        let response = app.oneshot(request).await.expect("validator response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem body");
        let problem = ProblemDetails::from_cbor(&body).expect("validator problem");
        assert_eq!(problem.code.as_str(), "sync.invalid_request");

        let app = router(store, TestAuthenticator::new(device, true));
        let request = request_headers(
            Request::builder()
                .uri(format!("/sync/v1/vaults/{}/changes?after=0&limit=10", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.oneshot(request).await.expect("changes response");
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("changes body");
        let changes = SyncChangesResponse::from_cbor(&body).expect("changes response");
        assert_eq!(changes.changes.len(), 0);
    }

    #[tokio::test]
    async fn policy_denied_before_storage_and_organization_is_read_only() {
        let (store, vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator::new(device, false));
        let request = request_headers(
            Request::builder()
                .uri(format!("/sync/v1/vaults/{}/changes?after=0&limit=1", path(vault))),
        )
        .body(Body::empty())
        .expect("request");
        let response = app.oneshot(request).await.expect("denied response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let organization_vault = Uuid::now_v7().into_bytes();
        store
            .create_sync_vault(organization_vault, storage::VaultKind::Organization)
            .await
            .expect("create organization vault");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let write = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![1],
                tombstone: false,
            }],
        };
        let request = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(organization_vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(write.to_cbor().expect("encode write")))
        .expect("request");
        let response = app.oneshot(request).await.expect("read-only response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("read-only body");
        let problem = ProblemDetails::from_cbor(&body).expect("read-only problem");
        assert_eq!(problem.code.as_str(), "sync.read_only");
        assert!(store.ping().await.is_ok());
    }
}
