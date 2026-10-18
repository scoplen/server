// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated HTTP/CBOR adapter for the K-4 sync service.
//!
//! This module owns request validation, wire decoding, storage error mapping, and response
//! encoding. It deliberately does not implement identity. A deployment must provide an
//! authenticator that validates the DPoP-bound access token and authorizes the requested vault
//! operation before this router is mounted on the public listener.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use crate::notify::NotificationHub;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use scoplen_api::{ErrorCode, ProblemDetails, sync as api};
use scoplen_model::CURRENT_SCHEMA_VERSION;
use scoplen_store::{SqliteStore, account_keys as key_storage, sync as storage};
use tokio::sync::broadcast;
use uuid::{Uuid, Variant};

/// The hard protocol ceiling for write bodies. A deployment may enforce a lower limit on the
/// write endpoint; other routes use their fixed K-4 bounds or this router ceiling.
pub const MAX_REQUEST_BYTES: usize = storage::MAX_BATCH_BYTES;

/// Maximum size of the first WebSocket message handed to the notification authenticator.
pub const MAX_NOTIFICATION_AUTH_BYTES: usize = 16 * 1024;
/// Maximum encoded session handshake request size.
pub const MAX_SESSION_REQUEST_BYTES: usize = 4 * 1024;
// A one-entry CBOR map, the text key "cursor", and the largest encoded u64.
const MAX_ACK_REQUEST_BYTES: usize = 1 + 7 + 9;
// "after=" + 20-digit u64 + "&" + "limit=" + four-digit 1000, in either order.
const MAX_SYNC_PAGE_QUERY_BYTES: usize = 6 + 20 + 1 + 6 + 4;
/// Default authenticated object-write refill rate advertised by the session handshake.
pub const WRITE_REQUESTS_PER_SECOND: u64 = 50;
/// Default authenticated object-write burst advertised by the session handshake.
pub const WRITE_BURST: u64 = 200;

const NOTIFICATION_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN_SCALE: u128 = 1_000_000_000;

/// Positive per-device object-write token bucket settings for one router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteRateLimits {
    requests_per_second: u64,
    burst: u64,
}

impl WriteRateLimits {
    /// Validate and construct the effective write rate advertised to clients.
    ///
    /// # Errors
    ///
    /// Returns the invalid setting when either value is zero.
    pub fn new(requests_per_second: u64, burst: u64) -> Result<Self, String> {
        if requests_per_second == 0 {
            return Err("sync.write_requests_per_second must be positive".into());
        }
        if burst == 0 {
            return Err("sync.write_burst must be positive".into());
        }
        Ok(Self { requests_per_second, burst })
    }

    /// Requests added to one device's bucket per second.
    #[must_use]
    pub fn requests_per_second(self) -> u64 {
        self.requests_per_second
    }

    /// Maximum requests that one device may spend without refilling.
    #[must_use]
    pub fn burst(self) -> u64 {
        self.burst
    }
}

impl Default for WriteRateLimits {
    fn default() -> Self {
        Self { requests_per_second: WRITE_REQUESTS_PER_SECOND, burst: WRITE_BURST }
    }
}

/// Configurable write bounds within the current K-4 codec and SQLite storage ceilings.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteBodyLimits {
    max_envelope_bytes: usize,
    max_batch_objects: usize,
    max_batch_bytes: usize,
}

impl WriteBodyLimits {
    /// Validate and construct the write bounds advertised to clients.
    ///
    /// # Errors
    ///
    /// Returns the invalid setting when it is zero or exceeds the current codec or storage bound.
    pub fn new(
        max_envelope_bytes: u64,
        max_batch_objects: u64,
        max_batch_bytes: u64,
    ) -> Result<Self, String> {
        fn bounded(name: &str, value: u64, maximum: usize) -> Result<usize, String> {
            if value == 0 || value > maximum as u64 {
                return Err(format!("sync.{name} must be between 1 and {maximum}"));
            }
            usize::try_from(value).map_err(|_| format!("sync.{name} cannot fit this platform"))
        }

        Ok(Self {
            max_envelope_bytes: bounded(
                "max_envelope_bytes",
                max_envelope_bytes,
                storage::MAX_ENVELOPE_BYTES,
            )?,
            max_batch_objects: bounded(
                "max_batch_objects",
                max_batch_objects,
                storage::MAX_BATCH_OBJECTS,
            )?,
            max_batch_bytes: bounded("max_batch_bytes", max_batch_bytes, storage::MAX_BATCH_BYTES)?,
        })
    }

    /// Maximum opaque envelope bytes in one object write.
    #[must_use]
    pub fn max_envelope_bytes(self) -> u64 {
        self.max_envelope_bytes as u64
    }

    /// Maximum objects in one write batch.
    #[must_use]
    pub fn max_batch_objects(self) -> u64 {
        self.max_batch_objects as u64
    }

    /// Maximum encoded CBOR bytes in one write batch.
    #[must_use]
    pub fn max_batch_bytes(self) -> u64 {
        self.max_batch_bytes as u64
    }
}

impl Default for WriteBodyLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: storage::MAX_ENVELOPE_BYTES,
            max_batch_objects: storage::MAX_BATCH_OBJECTS,
            max_batch_bytes: storage::MAX_BATCH_BYTES,
        }
    }
}

#[derive(Clone)]
struct WriteRateLimiter {
    buckets: Arc<Mutex<HashMap<storage::DeviceId, WriteBucket>>>,
    limits: WriteRateLimits,
}

#[derive(Clone, Copy)]
struct WriteBucket {
    tokens: u128,
    last_refill: Instant,
}

impl WriteRateLimiter {
    fn new(limits: WriteRateLimits) -> Self {
        Self { buckets: Arc::new(Mutex::new(HashMap::new())), limits }
    }

    fn try_acquire(&self, device_id: storage::DeviceId) -> Result<(), u64> {
        self.try_acquire_at(device_id, Instant::now())
    }

    fn try_acquire_at(&self, device_id: storage::DeviceId, now: Instant) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = buckets.entry(device_id).or_insert(WriteBucket {
            tokens: u128::from(self.limits.burst).saturating_mul(TOKEN_SCALE),
            last_refill: now,
        });
        let elapsed_nanos = now.duration_since(bucket.last_refill).as_nanos();
        let refill = elapsed_nanos.saturating_mul(u128::from(self.limits.requests_per_second));
        let capacity = u128::from(self.limits.burst).saturating_mul(TOKEN_SCALE);
        bucket.tokens = bucket.tokens.saturating_add(refill).min(capacity);
        bucket.last_refill = now;
        if bucket.tokens >= TOKEN_SCALE {
            bucket.tokens -= TOKEN_SCALE;
            return Ok(());
        }
        let deficit = TOKEN_SCALE - bucket.tokens;
        let rate = u128::from(self.limits.requests_per_second);
        let refill_per_second = rate.saturating_mul(TOKEN_SCALE);
        let wait_seconds = deficit.saturating_add(refill_per_second - 1) / refill_per_second;
        Err(u64::try_from(wait_seconds).unwrap_or(u64::MAX).max(1))
    }
}

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
    /// Retire a previously served shared-vault key epoch.
    RetireVaultEpoch,
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
    ) -> Result<Vec<u64>, AuthFailure>;

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

    /// Authorize an enrolled device to list the vaults of its own account.
    ///
    /// # Errors
    ///
    /// Returns an authentication or policy failure if the device may not start sync.
    fn authorize_session(&self, identity: AuthenticatedDevice) -> Result<(), AuthFailure>;

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
    router_with_write_rate_limits(store, authenticator, notifications, WriteRateLimits::default())
}

/// Build a sync router whose session advertises its enforced per-device write rate.
///
/// `write_rate_limits` must be constructed with [`WriteRateLimits::new`] or its default. Each
/// router owns a process-local bucket map; cross-instance admission is not provided here.
pub fn router_with_write_rate_limits<A: SyncAuthenticator>(
    store: Arc<SqliteStore>,
    authenticator: A,
    notifications: NotificationHub,
    write_rate_limits: WriteRateLimits,
) -> Router {
    router_with_limits(
        store,
        authenticator,
        notifications,
        write_rate_limits,
        WriteBodyLimits::default(),
    )
}

/// Build an authenticated sync router with the configured write rate and body bounds.
///
/// The session advertises the same bounds that the write endpoint enforces. Both settings must
/// be validated with their constructors before this router is mounted.
pub fn router_with_limits<A: SyncAuthenticator>(
    store: Arc<SqliteStore>,
    authenticator: A,
    notifications: NotificationHub,
    write_rate_limits: WriteRateLimits,
    write_body_limits: WriteBodyLimits,
) -> Router {
    let state = SyncHttpState {
        store,
        authenticator,
        notifications,
        write_rate_limiter: WriteRateLimiter::new(write_rate_limits),
        write_body_limits,
    };
    Router::new()
        .route("/sync/v1/session", post(session::<A>))
        .route("/sync/v1/keys", get(keys_get::<A>).put(keys_put::<A>))
        .route("/sync/v1/notify", get(notify::<A>))
        .route("/sync/v1/vaults", post(create_vault::<A>))
        .route("/sync/v1/vaults/{vault}/keys", get(vault_keys::<A>))
        .route("/sync/v1/vaults/{vault}/epochs", post(publish_vault_epoch::<A>))
        .route("/sync/v1/vaults/{vault}/members", post(add_vault_member::<A>))
        .route("/sync/v1/vaults/{vault}/members/{account}", delete(remove_vault_member::<A>))
        .route("/sync/v1/vaults/{vault}/epochs/{epoch}/retire", post(retire_vault_epoch::<A>))
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
    write_rate_limiter: WriteRateLimiter,
    write_body_limits: WriteBodyLimits,
}

async fn session<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let identity = state
        .authenticator
        .authenticate(&method, &uri, &headers)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let body = to_bytes(body, MAX_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| SyncHttpError::too_large(&instance, "sync session request is too large"))?;
    let request = api::SyncSessionRequest::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid session request: {error}"))
    })?;
    if request.device_id.as_bytes() != &identity.device_id {
        return Err(SyncHttpError::known(
            &instance,
            StatusCode::UNAUTHORIZED,
            "auth.authentication_required",
            "Authentication required",
            "The session device does not match the authenticated device; no data changed and authenticate again.",
            false,
            false,
        ));
    }
    let client_version = semver::Version::parse(&request.client_version).map_err(|_| {
        SyncHttpError::invalid(&instance, "client_version must be a semantic release version")
    })?;
    let server_version =
        semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("package version is semantic");
    if client_version.major != server_version.major
        || client_version.minor > server_version.minor
        || server_version.minor - client_version.minor > 2
        || request.model_version > CURRENT_SCHEMA_VERSION
    {
        return Err(SyncHttpError::known(
            &instance,
            StatusCode::UPGRADE_REQUIRED,
            "sync.client_unsupported",
            "Client version unsupported",
            "The client or object-model version is outside this server's compatibility window; no data changed and update the client before syncing.",
            false,
            false,
        ));
    }
    state
        .authenticator
        .authorize_session(identity)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let account_id = state
        .authenticator
        .account_id(identity)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let vaults = state
        .store
        .list_sync_vaults_for_account(account_id)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?
        .into_iter()
        .map(|vault| api::SessionVault {
            id: Uuid::from_bytes(vault.vault_id),
            kind: match vault.kind {
                storage::VaultKind::Personal => api::VaultKind::Personal,
                storage::VaultKind::Shared => api::VaultKind::Shared,
                storage::VaultKind::Organization => api::VaultKind::Organization,
            },
            seq: vault.sequence,
            key_epoch: vault.key_epoch,
            rotation_pending: vault.rotation_pending,
        })
        .collect();
    let cardinality_limits = state.store.sync_cardinality_limits();
    let response = api::SyncSessionResponse {
        server_version: server_version.to_string(),
        max_model_version: CURRENT_SCHEMA_VERSION,
        limits: api::SyncLimits {
            max_envelope_bytes: state.write_body_limits.max_envelope_bytes(),
            max_batch_objects: state.write_body_limits.max_batch_objects(),
            max_batch_bytes: state.write_body_limits.max_batch_bytes(),
            max_objects_per_vault: cardinality_limits.max_objects_per_vault,
            max_shared_vaults_per_account: cardinality_limits.max_shared_vaults_per_account,
            max_members_per_shared_vault: cardinality_limits.max_members_per_shared_vault,
            write_requests_per_second: state.write_rate_limiter.limits.requests_per_second(),
            write_burst: state.write_rate_limiter.limits.burst(),
        },
        vaults,
    };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode sync session: {error}"))
    })?))
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
    body: Body,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let identity = state
        .authenticator
        .authenticate(&method, &uri, &headers)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    let body = to_bytes(body, api::MAX_SYNC_VAULT_CREATE_BODY_BYTES).await.map_err(|_| {
        SyncHttpError::too_large(&instance, "shared-vault creation body is too large")
    })?;
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
    let keys = match state
        .store
        .sync_vault_kind(vault)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?
    {
        storage::VaultKind::Shared => state
            .store
            .get_shared_sync_vault_keys(vault, account_id)
            .await
            .map_err(|error| SyncHttpError::from_store(error, &instance))?,
        storage::VaultKind::Personal => {
            let (owned_vault, wrapped_vault_key) = state
                .store
                .get_personal_sync_vault_key(account_id)
                .await
                .map_err(|error| SyncHttpError::from_store(error, &instance))?;
            if owned_vault != vault {
                return Err(SyncHttpError::from_store(
                    storage::SyncStoreError::VaultNotFound,
                    &instance,
                ));
            }
            vec![storage::SharedVaultKey { epoch: 1, wrapped_vault_key }]
        }
        storage::VaultKind::Organization => {
            return Err(SyncHttpError::from_store(
                storage::SyncStoreError::VaultNotFound,
                &instance,
            ));
        }
    };
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
        SyncHttpError::invalid(&instance, format!("could not encode vault keys: {error}"))
    })?))
}

async fn publish_vault_epoch<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
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
    let body = to_bytes(body, api::MAX_SYNC_VAULT_EPOCH_BODY_BYTES).await.map_err(|_| {
        SyncHttpError::too_large(&instance, "shared-vault epoch body exceeds 4 MiB")
    })?;
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

async fn retire_vault_epoch<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path((vault, epoch)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let epoch = parse_epoch(&epoch, &instance)?;
    let _identity = authorize(
        &state,
        &method,
        &uri,
        &headers,
        vault,
        SyncOperation::RetireVaultEpoch,
        &instance,
    )?;
    to_bytes(body, 0).await.map_err(|_| {
        SyncHttpError::invalid(
            &instance,
            "shared-vault epoch retirement does not accept a request body",
        )
    })?;
    state
        .store
        .retire_shared_sync_vault_epoch(vault, epoch)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncRetireVaultEpochResponse { epoch };
    Ok(cbor_response(response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(
            &instance,
            format!("could not encode shared-vault epoch retirement response: {error}"),
        )
    })?))
}

async fn add_vault_member<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
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
    let body = to_bytes(body, api::MAX_SYNC_VAULT_MEMBER_BODY_BYTES).await.map_err(|_| {
        SyncHttpError::too_large(&instance, "shared-vault member body exceeds 4 MiB")
    })?;
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
    body: Body,
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
    to_bytes(body, 0).await.map_err(|_| {
        SyncHttpError::invalid(
            &instance,
            "shared-vault member removal does not accept a request body",
        )
    })?;
    state
        .store
        .remove_shared_sync_vault_member(vault, account_id)
        .await
        .map_err(|error| SyncHttpError::from_store(error, &instance))?;
    let response = api::SyncRemoveVaultMemberResponse {
        account_id: Uuid::from_bytes(account_id),
        rotation_pending: true,
    };
    let response_body = response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(
            &instance,
            format!("could not encode shared-vault member removal response: {error}"),
        )
    })?;
    publish_vault_notification(
        &state,
        vault,
        &api::SyncNotification::RotationPending { vault: Uuid::from_bytes(vault) },
        "rotation_pending",
    );
    Ok(cbor_response(response_body))
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
    body: Body,
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
    let body = to_bytes(body, api::MAX_SYNC_KEY_BODY_BYTES)
        .await
        .map_err(|_| SyncHttpError::too_large(&instance, "account key bundle exceeds 4 MiB"))?;
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
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Read, &instance)?;
    let query = parse_query(uri.query(), &instance)?;
    let page = state
        .store
        .sync_changes(vault, query.after, query.limit)
        .await
        .map_err(|error| SyncHttpError::from_page_store(error, &instance))?;
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
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Snapshot, &instance)?;
    let query = parse_query(uri.query(), &instance)?;
    let page = state
        .store
        .sync_snapshot(vault, query.after, query.limit)
        .await
        .map_err(|error| SyncHttpError::from_page_store(error, &instance))?;
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
    request: Request<Body>,
) -> SyncResult<Response> {
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Write, &instance)?;
    state
        .write_rate_limiter
        .try_acquire(identity.device_id)
        .map_err(|seconds| SyncHttpError::rate_limited(&instance, seconds))?;
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
    let body = to_bytes(body, state.write_body_limits.max_batch_bytes).await.map_err(|_| {
        SyncHttpError::too_large(
            &instance,
            format!("write batch exceeds {} bytes", state.write_body_limits.max_batch_bytes),
        )
    })?;
    let batch = api::SyncWriteBatch::from_cbor(&body).map_err(|error| {
        SyncHttpError::invalid(&instance, format!("invalid write batch: {error}"))
    })?;
    validate_write_body_limits(&batch, state.write_body_limits, &instance)?;
    let key_epochs = state
        .authenticator
        .validate_write(identity, vault, &batch.writes)
        .map_err(|error| SyncHttpError::from_auth(error, &instance))?;
    if key_epochs.len() != batch.writes.len() || key_epochs.contains(&0) {
        return Err(SyncHttpError::known(
            &instance,
            StatusCode::SERVICE_UNAVAILABLE,
            "sync.storage_unavailable",
            "Sync service unavailable",
            "The envelope validator returned an invalid key-epoch set; no data changed and retrying may help.",
            false,
            true,
        ));
    }
    let writes = batch
        .writes
        .iter()
        .zip(key_epochs)
        .map(|(write, key_epoch)| storage::ObjectWrite {
            object_id: write.object_id.into_bytes(),
            base_sequence: write.base_seq,
            envelope: write.payload.clone(),
            key_epoch,
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
    let response_body = response.to_cbor().map_err(|error| {
        SyncHttpError::invalid(&instance, format!("could not encode write assignment: {error}"))
    })?;
    if let Some(seq) = response.assignments.iter().map(|assignment| assignment.seq).max() {
        publish_vault_advanced(&state, vault, seq);
    }
    Ok(cbor_response(response_body))
}

fn validate_write_body_limits(
    batch: &api::SyncWriteBatch,
    limits: WriteBodyLimits,
    instance: &str,
) -> SyncResult<()> {
    if batch.writes.len() > limits.max_batch_objects {
        return Err(SyncHttpError::too_large(
            instance,
            format!("write batch exceeds {} objects", limits.max_batch_objects),
        ));
    }
    for write in &batch.writes {
        if write.payload.is_empty() {
            return Err(SyncHttpError::invalid(instance, "write envelope must not be empty"));
        }
        if write.payload.len() > limits.max_envelope_bytes {
            return Err(SyncHttpError::too_large(
                instance,
                format!("write envelope exceeds {} bytes", limits.max_envelope_bytes),
            ));
        }
    }
    Ok(())
}

fn publish_vault_advanced<A: SyncAuthenticator>(
    state: &SyncHttpState<A>,
    vault: storage::VaultId,
    seq: u64,
) {
    publish_vault_notification(
        state,
        vault,
        &api::SyncNotification::VaultAdvanced { vault: Uuid::from_bytes(vault), seq },
        "vault_advanced",
    );
}

fn publish_vault_notification<A: SyncAuthenticator>(
    state: &SyncHttpState<A>,
    vault: storage::VaultId,
    event: &api::SyncNotification,
    event_type: &'static str,
) {
    for device_id in state.notifications.active_devices() {
        let recipient = AuthenticatedDevice { device_id };
        if state.authenticator.authorize_notifications(recipient).is_err()
            || state.authenticator.authorize(recipient, vault, SyncOperation::Read).is_err()
        {
            continue;
        }
        if state.notifications.publish(device_id, event).is_err() {
            tracing::warn!(event_type, "could not encode sync notification");
        }
    }
}

async fn ack<A: SyncAuthenticator>(
    State(state): State<SyncHttpState<A>>,
    Path(vault): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> SyncResult<Response> {
    let instance = request_id(&headers);
    require_cbor(&headers, &instance)?;
    let vault = parse_uuid(&vault, "vault", &instance)?;
    let identity =
        authorize(&state, &method, &uri, &headers, vault, SyncOperation::Acknowledge, &instance)?;
    let body = to_bytes(body, MAX_ACK_REQUEST_BYTES)
        .await
        .map_err(|_| SyncHttpError::invalid(&instance, "acknowledgement request is too large"))?;
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

fn parse_query(raw: Option<&str>, instance: &str) -> SyncResult<api::SyncChangesQuery> {
    let raw =
        raw.ok_or_else(|| SyncHttpError::invalid(instance, "after and limit are required"))?;
    if raw.len() > MAX_SYNC_PAGE_QUERY_BYTES {
        return Err(SyncHttpError::invalid(instance, "sync page query is too long"));
    }
    api::SyncChangesQuery::from_query(raw)
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

fn parse_epoch(value: &str, instance: &str) -> SyncResult<u64> {
    if value.is_empty() || value == "0" || (value.starts_with('0') && value.len() > 1) {
        return Err(SyncHttpError::invalid(instance, "epoch must be a canonical positive integer"));
    }
    value
        .parse::<u64>()
        .map_err(|_| SyncHttpError::invalid(instance, "epoch must be a canonical positive integer"))
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
    retry_after: Option<HeaderValue>,
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
            storage::SyncStoreError::EpochNotFound { .. }
            | storage::SyncStoreError::UnsupportedVaultKind => Self::known(
                instance,
                StatusCode::NOT_FOUND,
                "sync.object_not_found",
                "Sync epoch not found",
                "The requested shared-vault epoch is not available; no data changed and retrying will not help.",
                false,
                false,
            ),
            storage::SyncStoreError::EpochNewest { epoch }
            | storage::SyncStoreError::EpochInUse { epoch }
            | storage::SyncStoreError::EpochRetired { epoch } => Self::known(
                instance,
                StatusCode::CONFLICT,
                "sync.conflict",
                "Sync vault epoch cannot be retired",
                format!(
                    "The shared-vault epoch {epoch} is still required; no data changed and re-encrypt objects or publish a newer epoch before retrying."
                ),
                false,
                false,
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
            storage::SyncStoreError::QuotaExceeded(_) => Self::known(
                instance,
                StatusCode::PAYLOAD_TOO_LARGE,
                "sync.quota_exceeded",
                "Sync quota exceeded",
                "The sync quota would be exceeded; no data changed and reduce usage or ask the operator to raise the limit.",
                false,
                false,
            ),
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

    fn from_page_store(error: storage::SyncStoreError, instance: &str) -> Box<Self> {
        match error {
            storage::SyncStoreError::CursorAhead { cursor, current } => Self::known(
                instance,
                StatusCode::GONE,
                "sync.cursor_expired",
                "Sync cursor expired",
                format!(
                    "Cursor {cursor} is ahead of the current sequence {current}; no data changed and restart full reconciliation from after=0."
                ),
                false,
                false,
            ),
            error => Self::from_store(error, instance),
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

    fn rate_limited(instance: &str, seconds: u64) -> Box<Self> {
        let mut error = Self::known(
            instance,
            StatusCode::TOO_MANY_REQUESTS,
            "sync.rate_limited",
            "Sync write rate exceeded",
            "The device write rate is exhausted; no data changed and retry after the indicated delay.",
            false,
            true,
        );
        error.retry_after = Some(HeaderValue::from_str(&seconds.to_string()).expect("valid delay"));
        error
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
        Box::new(Self { status, problem, body: None, retry_after: None })
    }

    fn with_conflicts(mut self: Box<Self>, conflicts: &[storage::ConflictEntry]) -> Box<Self> {
        let response = api::SyncConflictProblem {
            problem: self.problem.clone(),
            conflicts: conflicts
                .iter()
                .map(|conflict| api::SyncConflictEntry {
                    object_id: Uuid::from_bytes(conflict.object_id),
                    current: conflict.current.clone().map(change_to_api),
                })
                .collect(),
        };
        match response.to_cbor() {
            Ok(body) => {
                self.body = Some(body);
                self
            }
            Err(_) => Self::known(
                &self.problem.instance,
                StatusCode::SERVICE_UNAVAILABLE,
                "sync.storage_unavailable",
                "Sync service unavailable",
                "The server could not construct the complete conflict response; no data changed and retrying may help.",
                false,
                true,
            ),
        }
    }
}

impl IntoResponse for Box<SyncHttpError> {
    fn into_response(self) -> Response {
        let SyncHttpError { status, problem, body, retry_after } = *self;
        let body = body
            .unwrap_or_else(|| problem.to_cbor().expect("validated sync HTTP problem must encode"));
        let mut response = (
            status,
            [(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+cbor"))],
            body,
        )
            .into_response();
        if let Some(retry_after) = retry_after {
            response.headers_mut().insert(header::RETRY_AFTER, retry_after);
        }
        response
    }
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
    use scoplen_store::RelationalStore;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    use tower::ServiceExt;

    use super::*;

    #[derive(Clone)]
    struct TestAuthenticator {
        device_id: storage::DeviceId,
        allowed: bool,
        denied_read: Option<(storage::DeviceId, storage::VaultId)>,
        denied_notifications: Option<storage::DeviceId>,
        /// Test-only stand-in for the crypto and membership validator injected in production.
        reject_writes: bool,
        seen_requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl TestAuthenticator {
        fn new(device_id: storage::DeviceId, allowed: bool) -> Self {
            Self {
                device_id,
                allowed,
                denied_read: None,
                denied_notifications: None,
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
            identity: AuthenticatedDevice,
            vault: storage::VaultId,
            operation: SyncOperation,
        ) -> Result<(), AuthFailure> {
            if self.allowed
                && !(operation == SyncOperation::Read
                    && self.denied_read == Some((identity.device_id, vault)))
            {
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
            writes: &[api::SyncWrite],
        ) -> Result<Vec<u64>, AuthFailure> {
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
                Ok(vec![1; writes.len()])
            }
        }

        fn account_id(
            &self,
            _identity: AuthenticatedDevice,
        ) -> Result<key_storage::AccountId, AuthFailure> {
            Ok(Self::account_id())
        }

        fn authorize_session(&self, _identity: AuthenticatedDevice) -> Result<(), AuthFailure> {
            if self.allowed {
                Ok(())
            } else {
                Err(AuthFailure::new(
                    StatusCode::FORBIDDEN,
                    "policy.denied",
                    "Sync session denied",
                    "The device cannot start a sync session; no data changed and contact the operator.",
                    false,
                )
                .expect("test session policy failure"))
            }
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
            identity: AuthenticatedDevice,
        ) -> Result<(), AuthFailure> {
            if self.allowed && self.denied_notifications != Some(identity.device_id) {
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

    async fn remove_test_directory(path: &std::path::Path) {
        for attempt in 0..20 {
            match std::fs::remove_dir_all(path) {
                Ok(()) => return,
                Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("remove test directory {}: {error}", path.display()),
            }
        }
    }

    fn path(id: storage::VaultId) -> String {
        Uuid::from_bytes(id).to_string()
    }

    fn request_headers(builder: axum::http::request::Builder) -> axum::http::request::Builder {
        builder.header(AUTHORIZATION, "DPoP test-token").header("dpop", "test-proof")
    }

    fn write_request(vault: storage::VaultId, batch: &SyncWriteBatch) -> Request<Body> {
        request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(batch.to_cbor().expect("encode write batch")))
        .expect("write request")
    }

    #[test]
    fn write_rate_bucket_enforces_burst_refill_and_device_isolation() {
        let limiter = WriteRateLimiter::new(WriteRateLimits::new(2, 3).expect("valid rate limits"));
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.try_acquire_at([1; 16], now), Ok(()));
        }
        assert_eq!(limiter.try_acquire_at([1; 16], now), Err(1));
        assert_eq!(limiter.try_acquire_at([2; 16], now), Ok(()));
        assert_eq!(limiter.try_acquire_at([1; 16], now + Duration::from_millis(500)), Ok(()));
        assert_eq!(limiter.try_acquire_at([1; 16], now + Duration::from_millis(500)), Err(1));
        assert_eq!(limiter.try_acquire_at([1; 16], now + Duration::from_secs(10)), Ok(()));
    }

    #[test]
    fn write_rate_limits_reject_zero_and_support_positive_boundaries() {
        assert!(WriteRateLimits::new(0, 1).unwrap_err().contains("write_requests_per_second"));
        assert!(WriteRateLimits::new(1, 0).unwrap_err().contains("write_burst"));
        let minimum = WriteRateLimits::new(1, 1).expect("minimum limits");
        let now = Instant::now();
        let limiter = WriteRateLimiter::new(minimum);
        assert_eq!(limiter.try_acquire_at([1; 16], now), Ok(()));
        assert_eq!(limiter.try_acquire_at([1; 16], now), Err(1));
        assert_eq!(limiter.try_acquire_at([1; 16], now + Duration::from_secs(1)), Ok(()));

        let maximum = WriteRateLimits::new(u64::MAX, u64::MAX).expect("unsigned limits");
        assert_eq!(maximum.requests_per_second(), u64::MAX);
        assert_eq!(maximum.burst(), u64::MAX);
        let limiter =
            WriteRateLimiter::new(WriteRateLimits::new(u64::MAX, 1).expect("maximum refill rate"));
        assert_eq!(limiter.try_acquire_at([2; 16], now), Ok(()));
        assert_eq!(limiter.try_acquire_at([2; 16], now), Err(1));
        assert_eq!(limiter.try_acquire_at([2; 16], now + Duration::from_nanos(1)), Ok(()));
    }

    #[test]
    fn write_body_limits_reject_zero_and_codec_excess() {
        let minimum = WriteBodyLimits::new(1, 1, 1).expect("positive minimum");
        assert_eq!(minimum.max_envelope_bytes(), 1);
        assert_eq!(minimum.max_batch_objects(), 1);
        assert_eq!(minimum.max_batch_bytes(), 1);
        let default = WriteBodyLimits::default();
        assert_eq!(default.max_envelope_bytes(), storage::MAX_ENVELOPE_BYTES as u64);
        assert_eq!(default.max_batch_objects(), storage::MAX_BATCH_OBJECTS as u64);
        assert_eq!(default.max_batch_bytes(), storage::MAX_BATCH_BYTES as u64);
        for (name, values) in [
            ("max_envelope_bytes", [0, 1, 1]),
            ("max_batch_objects", [1, 0, 1]),
            ("max_batch_bytes", [1, 1, 0]),
            ("max_envelope_bytes", [storage::MAX_ENVELOPE_BYTES as u64 + 1, 1, 1]),
            ("max_batch_objects", [1, storage::MAX_BATCH_OBJECTS as u64 + 1, 1]),
            ("max_batch_bytes", [1, 1, storage::MAX_BATCH_BYTES as u64 + 1]),
        ] {
            assert!(
                WriteBodyLimits::new(values[0], values[1], values[2])
                    .expect_err("unsupported write bound")
                    .contains(name)
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn configured_write_body_limits_are_advertised_and_reject_before_storage() {
        let directory = std::env::temp_dir().join(format!("scoplen-http-body-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create isolated test directory");
        let store = Arc::new(
            SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store"),
        );
        let vault = Uuid::now_v7().into_bytes();
        let device = Uuid::now_v7();
        store.create_sync_vault(vault, storage::VaultKind::Personal).await.expect("create vault");
        let limits = WriteBodyLimits::new(2, 1, 100).expect("configured write bounds");
        let app = router_with_limits(
            store.clone(),
            TestAuthenticator::new(device.into_bytes(), true),
            NotificationHub::default(),
            WriteRateLimits::default(),
            limits,
        );

        let session_body = api::SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: CURRENT_SCHEMA_VERSION,
            device_id: device,
        }
        .to_cbor()
        .expect("session request");
        let session = app
            .clone()
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/sync/v1/session")
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(session_body))
                .expect("session request builder"),
            )
            .await
            .expect("session response");
        assert_eq!(session.status(), StatusCode::OK);
        let session_body = to_bytes(session.into_body(), MAX_REQUEST_BYTES).await.expect("body");
        let advertised =
            api::SyncSessionResponse::from_cbor(&session_body).expect("session cbor").limits;
        assert_eq!(advertised.max_envelope_bytes, limits.max_envelope_bytes());
        assert_eq!(advertised.max_batch_objects, limits.max_batch_objects());
        assert_eq!(advertised.max_batch_bytes, limits.max_batch_bytes());

        let write = |payload: Vec<u8>| api::SyncWrite {
            object_id: Uuid::now_v7(),
            base_seq: None,
            payload,
            tombstone: false,
        };
        let too_many = SyncWriteBatch { writes: vec![write(vec![1]), write(vec![2])] };
        let oversized_envelope = SyncWriteBatch { writes: vec![write(vec![1, 2, 3])] };
        assert!(too_many.to_cbor().expect("count body").len() <= 100);
        assert!(oversized_envelope.to_cbor().expect("envelope body").len() <= 100);
        let oversized_body = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(vec![0xff; 101]))
        .expect("oversized body request");
        for request in [
            write_request(vault, &too_many),
            write_request(vault, &oversized_envelope),
            oversized_body,
        ] {
            let response = app.clone().oneshot(request).await.expect("write limit response");
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem");
            let problem = ProblemDetails::from_cbor(&body).expect("problem cbor");
            assert_eq!(problem.code.as_str(), "sync.invalid_request");
            assert!(!problem.changed);
            assert!(!problem.retryable);
        }
        assert_eq!(store.sync_changes(vault, 0, 10).await.expect("changes").changes.len(), 0);

        let at_limit = SyncWriteBatch { writes: vec![write(vec![1, 2])] };
        assert_eq!(
            app.oneshot(write_request(vault, &at_limit)).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(store.sync_changes(vault, 0, 10).await.expect("changes").changes.len(), 1);
        let exact_bytes = at_limit.to_cbor().expect("boundary batch").len();
        let exact_limits =
            WriteBodyLimits::new(2, 1, exact_bytes as u64).expect("exact byte bound");
        let exact_app = router_with_limits(
            store.clone(),
            TestAuthenticator::new(device.into_bytes(), true),
            NotificationHub::default(),
            WriteRateLimits::default(),
            exact_limits,
        );
        let exact_batch = SyncWriteBatch { writes: vec![write(vec![1, 2])] };
        assert_eq!(exact_batch.to_cbor().expect("exact batch").len(), exact_bytes);
        assert_eq!(
            exact_app.oneshot(write_request(vault, &exact_batch)).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(store.sync_changes(vault, 0, 10).await.expect("changes").changes.len(), 2);
        store.pool().close().await;
        drop(store);
        remove_test_directory(&directory).await;
    }

    #[tokio::test]
    async fn key_and_membership_requests_bound_bodies_before_decoding() {
        let (store, _, device) = test_store().await;
        let vault = Uuid::now_v7().into_bytes();
        let account = TestAuthenticator::account_id();
        store.create_shared_sync_vault(vault, account, &[1]).await.expect("shared vault");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let routes = [
            (Method::PUT, String::from("/sync/v1/keys"), api::MAX_SYNC_KEY_BODY_BYTES),
            (
                Method::POST,
                format!("/sync/v1/vaults/{}/epochs", path(vault)),
                api::MAX_SYNC_VAULT_EPOCH_BODY_BYTES,
            ),
            (
                Method::POST,
                format!("/sync/v1/vaults/{}/members", path(vault)),
                api::MAX_SYNC_VAULT_MEMBER_BODY_BYTES,
            ),
        ];
        for (method, uri, limit) in routes {
            for (size, expected_status) in
                [(limit, StatusCode::BAD_REQUEST), (limit + 1, StatusCode::PAYLOAD_TOO_LARGE)]
            {
                let request = request_headers(
                    Request::builder()
                        .method(method.clone())
                        .uri(&uri)
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(vec![0xff; size]))
                .expect("bounded request");
                let response = app.clone().oneshot(request).await.expect("bounded response");
                assert_eq!(response.status(), expected_status, "{method} {uri} at {size} bytes");
                assert_eq!(
                    response.headers().get(header::CONTENT_TYPE).unwrap(),
                    "application/problem+cbor"
                );
                let body =
                    to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem body");
                let problem = ProblemDetails::from_cbor(&body).expect("problem cbor");
                assert_eq!(problem.code.as_str(), "sync.invalid_request");
                assert!(!problem.changed);
                assert!(!problem.retryable);
            }
        }
        assert!(store.get_account_key_bundle(account, device).await.is_err());
        assert_eq!(
            store.get_shared_sync_vault_keys(vault, account).await.expect("owner keys").len(),
            1
        );
    }

    #[tokio::test]
    async fn object_write_rate_rejects_before_reading_body_and_preserves_state() {
        let directory = std::env::temp_dir().join(format!("scoplen-http-rate-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create isolated test directory");
        let store = Arc::new(
            SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store"),
        );
        let vault = Uuid::now_v7().into_bytes();
        let device = Uuid::now_v7().into_bytes();
        store.create_sync_vault(vault, storage::VaultKind::Personal).await.expect("create vault");
        let limits = WriteRateLimits::new(1, 2).expect("valid rate limits");
        let app = router_with_write_rate_limits(
            store.clone(),
            TestAuthenticator::new(device, true),
            NotificationHub::default(),
            limits,
        );
        let session_request = api::SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: CURRENT_SCHEMA_VERSION,
            device_id: Uuid::from_bytes(device),
        }
        .to_cbor()
        .expect("session request");
        let session_response = app
            .clone()
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/sync/v1/session")
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(session_request))
                .expect("session request builder"),
            )
            .await
            .expect("session response");
        assert_eq!(session_response.status(), StatusCode::OK);
        let body = to_bytes(session_response.into_body(), MAX_REQUEST_BYTES).await.unwrap();
        let advertised = api::SyncSessionResponse::from_cbor(&body).expect("session cbor").limits;
        assert_eq!(advertised.write_requests_per_second, limits.requests_per_second());
        assert_eq!(advertised.write_burst, limits.burst());
        let make_request = |authorized: bool, body: Vec<u8>| {
            let builder = Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor");
            let builder = if authorized { request_headers(builder) } else { builder };
            builder.body(Body::from(body)).expect("write request")
        };
        let rejected_auth = app
            .clone()
            .oneshot(make_request(false, vec![0xff]))
            .await
            .expect("unauthorized response");
        assert_eq!(rejected_auth.status(), StatusCode::UNAUTHORIZED);
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(make_request(true, vec![0xff]))
                .await
                .expect("invalid body response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let response = app.oneshot(make_request(true, vec![0xff])).await.expect("rate response");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).expect("retry header"), "1");
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("rate body");
        let problem = ProblemDetails::from_cbor(&bytes).expect("rate problem");
        assert_eq!(problem.code.as_str(), "sync.rate_limited");
        assert!(!problem.changed);
        assert!(problem.retryable);
        assert_eq!(store.sync_changes(vault, 0, 1).await.expect("changes").changes.len(), 0);
        store.pool().close().await;
        drop(store);
        remove_test_directory(&directory).await;
    }

    #[tokio::test]
    async fn session_lists_only_authenticated_accounts_personal_vault() {
        let (store, _fixture, device) = test_store().await;
        let owner = TestAuthenticator::account_id();
        let personal = Uuid::now_v7();
        let outsider = Uuid::now_v7();
        store
            .create_personal_sync_vault(personal.into_bytes(), owner, &[1, 2])
            .await
            .expect("owner personal vault");
        store
            .create_personal_sync_vault(outsider.into_bytes(), Uuid::now_v7().into_bytes(), &[3])
            .await
            .expect("other personal vault");
        let body = api::SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: CURRENT_SCHEMA_VERSION,
            device_id: Uuid::from_bytes(device),
        }
        .to_cbor()
        .expect("session body");
        let response = router(store, TestAuthenticator::new(device, true))
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/sync/v1/session")
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(body))
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("session bytes");
        let session = api::SyncSessionResponse::from_cbor(&bytes).expect("session cbor");
        assert_eq!(session.vaults.len(), 1);
        assert_eq!(session.vaults[0].id, personal);
        assert_eq!(session.vaults[0].kind, api::VaultKind::Personal);
        assert_eq!(session.vaults[0].seq, 0);
        assert_eq!(session.vaults[0].key_epoch, 1);
        assert!(!session.vaults[0].rotation_pending);
    }

    #[tokio::test]
    async fn session_reports_shared_vault_rotation_to_current_members() {
        let (store, _personal, device) = test_store().await;
        let admin = TestAuthenticator::account_id();
        let vault = Uuid::now_v7();
        let removed = Uuid::now_v7();
        store
            .create_shared_sync_vault(vault.into_bytes(), admin, &[1])
            .await
            .expect("create shared vault");
        store
            .add_shared_sync_vault_member(
                vault.into_bytes(),
                removed.into_bytes(),
                &[storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![2] }],
            )
            .await
            .expect("add member");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let body = api::SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: CURRENT_SCHEMA_VERSION,
            device_id: Uuid::from_bytes(device),
        }
        .to_cbor()
        .expect("session body");
        let request = || {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri("/sync/v1/session")
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(body.clone()))
            .expect("session request")
        };
        let response = app.clone().oneshot(request()).await.expect("session response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("session bytes");
        let session = api::SyncSessionResponse::from_cbor(&bytes).expect("session cbor");
        assert_eq!(session.server_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(session.max_model_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(session.limits.max_objects_per_vault, storage::MAX_OBJECTS_PER_VAULT);
        assert_eq!(
            session.limits.max_shared_vaults_per_account,
            storage::MAX_SHARED_VAULTS_PER_ACCOUNT
        );
        assert_eq!(
            session.limits.max_members_per_shared_vault,
            storage::MAX_MEMBERS_PER_SHARED_VAULT
        );
        assert_eq!(session.vaults.len(), 1);
        assert_eq!(session.vaults[0].id, vault);
        assert_eq!(session.vaults[0].kind, api::VaultKind::Shared);
        assert!(!session.vaults[0].rotation_pending);

        store
            .remove_shared_sync_vault_member(vault.into_bytes(), removed.into_bytes())
            .await
            .expect("remove member");
        let response = app.clone().oneshot(request()).await.expect("pending session");
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("pending bytes");
        let session = api::SyncSessionResponse::from_cbor(&bytes).expect("pending cbor");
        assert!(session.vaults[0].rotation_pending);
        store
            .publish_shared_sync_vault_epoch(
                vault.into_bytes(),
                2,
                &[storage::SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![3] }],
            )
            .await
            .expect("rotate epoch");
        let response = app.oneshot(request()).await.expect("rotated session");
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("rotated bytes");
        let session = api::SyncSessionResponse::from_cbor(&bytes).expect("rotated cbor");
        assert_eq!(session.vaults[0].key_epoch, 2);
        assert!(!session.vaults[0].rotation_pending);
    }

    #[tokio::test]
    async fn session_advertises_the_cardinality_limits_enforced_by_its_store() {
        let directory =
            std::env::temp_dir().join(format!("scoplen-http-limits-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create isolated test directory");
        let path = directory.join("scoplen.sqlite");
        let limits = storage::SyncCardinalityLimits {
            max_objects_per_vault: storage::MAX_OBJECTS_PER_VAULT + 1,
            max_shared_vaults_per_account: storage::MAX_SHARED_VAULTS_PER_ACCOUNT + 1,
            max_members_per_shared_vault: 2,
        };
        let store = Arc::new(
            SqliteStore::open_with_sync_limits(&path, limits).await.expect("open limited store"),
        );
        let device = Uuid::now_v7();
        let app = router(store.clone(), TestAuthenticator::new(device.into_bytes(), true));
        let body = api::SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: CURRENT_SCHEMA_VERSION,
            device_id: device,
        }
        .to_cbor()
        .expect("session request");
        let response = app
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/sync/v1/session")
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(body))
                .expect("session request builder"),
            )
            .await
            .expect("session response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("session body");
        let advertised = api::SyncSessionResponse::from_cbor(&bytes).expect("session cbor").limits;
        assert_eq!(advertised.max_objects_per_vault, limits.max_objects_per_vault);
        assert_eq!(advertised.max_shared_vaults_per_account, limits.max_shared_vaults_per_account);
        assert_eq!(advertised.max_members_per_shared_vault, limits.max_members_per_shared_vault);
        assert_eq!(advertised.max_batch_objects, storage::MAX_BATCH_OBJECTS as u64);
        assert_eq!(advertised.write_requests_per_second, WRITE_REQUESTS_PER_SECOND);
        assert_eq!(advertised.write_burst, WRITE_BURST);
        store.pool().close().await;
        drop(store);
        remove_test_directory(&directory).await;
    }

    #[tokio::test]
    async fn session_rejects_bad_identity_version_and_body() {
        let (store, _vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let session_request = |client_version: &str, model_version: u64, device_id: Uuid| {
            api::SyncSessionRequest {
                client_version: client_version.into(),
                model_version,
                device_id,
            }
            .to_cbor()
            .expect("session body")
        };
        let send = |body: Vec<u8>| {
            let app = app.clone();
            async move {
                app.oneshot(
                    request_headers(
                        Request::builder()
                            .method("POST")
                            .uri("/sync/v1/session")
                            .header(header::CONTENT_TYPE, "application/cbor"),
                    )
                    .body(Body::from(body))
                    .expect("session request"),
                )
                .await
                .expect("session response")
            }
        };
        for (body, expected_status, expected_code) in [
            (
                session_request("0.1.0", 1, Uuid::now_v7()),
                StatusCode::UNAUTHORIZED,
                "auth.authentication_required",
            ),
            (
                session_request("0.2.0", 1, Uuid::from_bytes(device)),
                StatusCode::UPGRADE_REQUIRED,
                "sync.client_unsupported",
            ),
            (
                session_request("0.1.0", CURRENT_SCHEMA_VERSION + 1, Uuid::from_bytes(device)),
                StatusCode::UPGRADE_REQUIRED,
                "sync.client_unsupported",
            ),
            (
                session_request("bad-version", 1, Uuid::from_bytes(device)),
                StatusCode::BAD_REQUEST,
                "sync.invalid_request",
            ),
            (vec![0xff], StatusCode::BAD_REQUEST, "sync.invalid_request"),
            (
                vec![0; MAX_SESSION_REQUEST_BYTES + 1],
                StatusCode::PAYLOAD_TOO_LARGE,
                "sync.invalid_request",
            ),
        ] {
            let response = send(body).await;
            assert_eq!(response.status(), expected_status);
            let bytes =
                to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem bytes");
            assert_eq!(
                ProblemDetails::from_cbor(&bytes).expect("problem cbor").code.as_str(),
                expected_code
            );
        }

        let valid = session_request("0.1.0", 1, Uuid::from_bytes(device));
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync/v1/session")
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::from(valid.clone()))
                    .expect("unauthenticated request"),
            )
            .await
            .expect("unauthenticated response");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let denied_app = router(store, TestAuthenticator::new(device, false));
        let denied = denied_app
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/sync/v1/session")
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(valid))
                .expect("denied request"),
            )
            .await
            .expect("denied response");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn session_bounds_body_before_decoding_and_preserves_vault_state() {
        let (store, _personal_vault, device) = test_store().await;
        let account = TestAuthenticator::account_id();
        store
            .create_shared_sync_vault(Uuid::now_v7().into_bytes(), account, &[1])
            .await
            .expect("shared vault");
        let before = store.list_sync_vaults_for_account(account).await.expect("vault list");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let request = |body| {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri("/sync/v1/session")
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(body))
            .expect("session request")
        };

        for (size, status) in [
            (MAX_SESSION_REQUEST_BYTES, StatusCode::BAD_REQUEST),
            (MAX_SESSION_REQUEST_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
            (MAX_REQUEST_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let response = app
                .clone()
                .oneshot(request(vec![0xff; size]))
                .await
                .expect("bounded session response");
            assert_eq!(response.status(), status, "body size {size}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/problem+cbor"
            );
            let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem");
            let problem = ProblemDetails::from_cbor(&bytes).expect("CBOR problem");
            assert_eq!(problem.code.as_str(), "sync.invalid_request");
            assert!(!problem.changed);
            assert!(!problem.retryable);
            assert_eq!(
                store.list_sync_vaults_for_account(account).await.expect("vault list"),
                before
            );
        }

        let unauthenticated = Request::builder()
            .method("POST")
            .uri("/sync/v1/session")
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(Body::from(vec![0xff; MAX_REQUEST_BYTES + 1]))
            .expect("unauthenticated session request");
        let response = app.oneshot(unauthenticated).await.expect("auth response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth problem");
        assert_eq!(
            ProblemDetails::from_cbor(&bytes).expect("auth problem CBOR").code.as_str(),
            "auth.authentication_required"
        );
        assert_eq!(store.list_sync_vaults_for_account(account).await.expect("vault list"), before);
    }

    #[tokio::test]
    async fn personal_vault_keys_are_owner_scoped_and_use_shared_response_shape() {
        let (store, unrelated_personal, device) = test_store().await;
        let owner = TestAuthenticator::account_id();
        let personal = Uuid::now_v7();
        let other_owner = Uuid::now_v7();
        store
            .create_personal_sync_vault(personal.into_bytes(), owner, &[7, 8, 9])
            .await
            .expect("owner personal vault");
        store
            .create_personal_sync_vault(other_owner.into_bytes(), Uuid::now_v7().into_bytes(), &[1])
            .await
            .expect("other personal vault");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let request = |vault: Uuid| {
            request_headers(
                Request::builder()
                    .uri(format!("/sync/v1/vaults/{}/keys", path(vault.into_bytes()))),
            )
            .body(Body::empty())
            .expect("vault keys request")
        };
        let response = app.clone().oneshot(request(personal)).await.expect("personal keys");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("key body");
        let keys = api::SyncVaultKeysResponse::from_cbor(&body).expect("key response");
        assert_eq!(
            keys.keys,
            vec![api::SyncVaultKey { epoch: 1, wrapped_vault_key: vec![7, 8, 9] }]
        );

        let response =
            app.clone().oneshot(request(other_owner)).await.expect("other personal keys");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("not-found body");
        assert_eq!(
            ProblemDetails::from_cbor(&body).expect("not-found problem").code.as_str(),
            "sync.object_not_found"
        );

        let response = app
            .oneshot(request(Uuid::from_bytes(unrelated_personal)))
            .await
            .expect("unowned personal keys");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("unowned body");
        assert_eq!(
            ProblemDetails::from_cbor(&body).expect("unowned problem").code.as_str(),
            "sync.object_not_found"
        );
        assert_eq!(
            store.get_personal_sync_vault_key(owner).await.expect("owner key remains").1,
            vec![7, 8, 9]
        );
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
    async fn shared_vault_creation_bounds_body_before_decoding_or_storage() {
        let (store, _vault, device) = test_store().await;
        let account = TestAuthenticator::account_id();
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let request = |body| {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri("/sync/v1/vaults")
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(body))
            .expect("vault creation request")
        };

        for (size, status) in [
            (api::MAX_SYNC_VAULT_CREATE_BODY_BYTES, StatusCode::BAD_REQUEST),
            (api::MAX_SYNC_VAULT_CREATE_BODY_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
            (MAX_REQUEST_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let response =
                app.clone().oneshot(request(vec![0xff; size])).await.expect("bounded response");
            assert_eq!(response.status(), status, "body size {size}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/problem+cbor"
            );
            let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem");
            let problem = ProblemDetails::from_cbor(&body).expect("CBOR problem");
            assert_eq!(problem.code.as_str(), "sync.invalid_request");
            assert!(!problem.changed);
            assert!(!problem.retryable);
            assert_eq!(
                store.list_sync_vaults_for_account(account).await.expect("vault list").len(),
                0
            );
        }

        let vault = Uuid::now_v7();
        let valid = api::SyncCreateVaultRequest {
            vault_id: vault,
            wrapped_vault_key: vec![1; api::MAX_SYNC_VAULT_KEY_BYTES],
        }
        .to_cbor()
        .expect("maximum valid wrap");
        assert!(valid.len() <= api::MAX_SYNC_VAULT_CREATE_BODY_BYTES);
        let response = app.oneshot(request(valid)).await.expect("maximum valid response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            store
                .get_shared_sync_vault_keys(vault.into_bytes(), account)
                .await
                .expect("vault keys")[0]
                .wrapped_vault_key
                .len(),
            api::MAX_SYNC_VAULT_KEY_BYTES
        );
    }

    #[tokio::test]
    async fn shared_vault_quota_returns_non_retryable_problem_without_creating_vault() {
        let (store, _vault, device) = test_store().await;
        for _ in 0..storage::MAX_SHARED_VAULTS_PER_ACCOUNT {
            store
                .create_shared_sync_vault(
                    Uuid::now_v7().into_bytes(),
                    TestAuthenticator::account_id(),
                    &[1],
                )
                .await
                .expect("seed account vault quota");
        }
        let rejected = Uuid::now_v7();
        let body = api::SyncCreateVaultRequest { vault_id: rejected, wrapped_vault_key: vec![2] }
            .to_cbor()
            .expect("create request");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let response = app
            .oneshot(
                request_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/sync/v1/vaults")
                        .header(header::CONTENT_TYPE, "application/cbor"),
                )
                .body(Body::from(body))
                .expect("create request builder"),
            )
            .await
            .expect("quota response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("quota body");
        let problem = ProblemDetails::from_cbor(&bytes).expect("quota problem");
        assert_eq!(problem.code.as_str(), "sync.quota_exceeded");
        assert!(!problem.changed);
        assert!(!problem.retryable);
        assert!(matches!(
            store.sync_vault_kind(rejected.into_bytes()).await,
            Err(storage::SyncStoreError::VaultNotFound)
        ));
    }

    #[tokio::test]
    async fn shared_vault_epoch_retirement_routes_success_and_conflicts() {
        let (store, _personal_vault, device) = test_store().await;
        let vault = Uuid::now_v7();
        let account = TestAuthenticator::account_id();
        store
            .create_shared_sync_vault(vault.into_bytes(), account, &[1])
            .await
            .expect("create shared vault");
        store
            .publish_shared_sync_vault_epoch(
                vault.into_bytes(),
                2,
                &[storage::SharedVaultEpochWrap {
                    account_id: account,
                    wrapped_vault_key: vec![2],
                }],
            )
            .await
            .expect("publish epoch two");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let request =
            |epoch: &str, body: Body| {
                request_headers(Request::builder().method("POST").uri(format!(
                    "/sync/v1/vaults/{}/epochs/{epoch}/retire",
                    path(vault.into_bytes())
                )))
                .body(body)
                .expect("retirement request")
            };

        let response =
            app.clone().oneshot(request("01", Body::empty())).await.expect("invalid epoch");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response =
            app.clone().oneshot(request("3", Body::empty())).await.expect("unknown epoch");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response =
            app.clone().oneshot(request("2", Body::empty())).await.expect("newest epoch");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response =
            app.clone().oneshot(request("1", Body::empty())).await.expect("retire epoch");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body =
            to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("retire response body");
        assert_eq!(
            api::SyncRetireVaultEpochResponse::from_cbor(&response_body)
                .expect("retire response cbor")
                .epoch,
            1
        );
        let response =
            app.clone().oneshot(request("1", Body::empty())).await.expect("repeat retire");
        assert_eq!(response.status(), StatusCode::OK);
        let response =
            app.oneshot(request("1", Body::from(vec![1]))).await.expect("body rejection");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let keys =
            store.get_shared_sync_vault_keys(vault.into_bytes(), account).await.expect("keys");
        assert_eq!(keys, vec![storage::SharedVaultKey { epoch: 2, wrapped_vault_key: vec![2] }]);
    }

    #[tokio::test]
    async fn bodyless_vault_mutations_reject_data_without_changing_state() {
        let (store, _personal_vault, device) = test_store().await;
        let vault = Uuid::now_v7();
        let admin = TestAuthenticator::account_id();
        let member = Uuid::now_v7();
        store.create_shared_sync_vault(vault.into_bytes(), admin, &[1]).await.expect("vault");
        store
            .publish_shared_sync_vault_epoch(
                vault.into_bytes(),
                2,
                &[storage::SharedVaultEpochWrap { account_id: admin, wrapped_vault_key: vec![2] }],
            )
            .await
            .expect("second epoch");
        store
            .add_shared_sync_vault_member(
                vault.into_bytes(),
                member.into_bytes(),
                &[
                    storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3] },
                    storage::SharedVaultKey { epoch: 2, wrapped_vault_key: vec![4] },
                ],
            )
            .await
            .expect("member");
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let routes = [
            (Method::POST, format!("/sync/v1/vaults/{vault}/epochs/1/retire")),
            (Method::DELETE, format!("/sync/v1/vaults/{vault}/members/{member}")),
        ];

        for (method, uri) in routes {
            for size in [1, MAX_REQUEST_BYTES + 1] {
                let request = request_headers(Request::builder().method(method.clone()).uri(&uri))
                    .body(Body::from(vec![1; size]))
                    .expect("non-empty request");
                let response = app.clone().oneshot(request).await.expect("body rejection");
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "{method} {uri}, {size} bytes"
                );
                assert_eq!(
                    response.headers().get(header::CONTENT_TYPE).unwrap(),
                    "application/problem+cbor"
                );
                let bytes =
                    to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem body");
                let problem = ProblemDetails::from_cbor(&bytes).expect("CBOR problem");
                assert_eq!(problem.code.as_str(), "sync.invalid_request");
                assert!(!problem.changed);
                assert!(!problem.retryable);
            }

            let unauthenticated = Request::builder()
                .method(method.clone())
                .uri(&uri)
                .body(Body::from(vec![1; MAX_REQUEST_BYTES + 1]))
                .expect("unauthenticated request");
            let response = app.clone().oneshot(unauthenticated).await.expect("auth response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth body");
            assert_eq!(
                ProblemDetails::from_cbor(&bytes).expect("auth problem").code.as_str(),
                "auth.authentication_required"
            );

            assert_eq!(
                store
                    .get_shared_sync_vault_keys(vault.into_bytes(), member.into_bytes())
                    .await
                    .expect("member keys"),
                vec![
                    storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3] },
                    storage::SharedVaultKey { epoch: 2, wrapped_vault_key: vec![4] },
                ]
            );
            let vaults = store.list_sync_vaults_for_account(admin).await.expect("admin vaults");
            assert_eq!(vaults.len(), 1);
            assert_eq!(vaults[0].key_epoch, 2);
            assert!(!vaults[0].rotation_pending);
        }
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
    #[allow(clippy::too_many_lines)]
    async fn committed_member_removal_notifies_only_current_vault_readers() {
        let (store, _personal_vault, admin_device) = test_store().await;
        let vault = Uuid::now_v7();
        let member = Uuid::now_v7();
        store
            .create_shared_sync_vault(vault.into_bytes(), TestAuthenticator::account_id(), &[1])
            .await
            .expect("create shared vault");
        store
            .add_shared_sync_vault_member(
                vault.into_bytes(),
                member.into_bytes(),
                &[storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![2] }],
            )
            .await
            .expect("add member");

        let remaining_reader = Uuid::now_v7().into_bytes();
        let removed_reader = Uuid::now_v7().into_bytes();
        let revoked_reader = Uuid::now_v7().into_bytes();
        let hub = NotificationHub::default();
        let mut admin_events = hub.subscribe(admin_device);
        let mut remaining_events = hub.subscribe(remaining_reader);
        let mut removed_events = hub.subscribe(removed_reader);
        let mut revoked_events = hub.subscribe(revoked_reader);
        let mut authenticator = TestAuthenticator::new(admin_device, true);
        authenticator.denied_read = Some((removed_reader, vault.into_bytes()));
        authenticator.denied_notifications = Some(revoked_reader);
        let app = router_with_notifications(store.clone(), authenticator, hub);
        let removal_request = |account: Uuid| {
            request_headers(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/sync/v1/vaults/{}/members/{account}", path(vault.into_bytes()))),
            )
            .body(Body::empty())
            .expect("removal request builder")
        };

        let response = app
            .clone()
            .oneshot(removal_request(Uuid::from_bytes(TestAuthenticator::account_id())))
            .await
            .expect("last admin response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = app
            .clone()
            .oneshot(removal_request(Uuid::now_v7()))
            .await
            .expect("missing member response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(matches!(admin_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));

        let response = app.clone().oneshot(removal_request(member)).await.expect("remove member");
        assert_eq!(response.status(), StatusCode::OK);
        let expected = api::SyncNotification::RotationPending { vault };
        assert_eq!(
            api::SyncNotification::from_cbor(&admin_events.try_recv().expect("admin event")),
            Ok(expected.clone())
        );
        assert_eq!(
            api::SyncNotification::from_cbor(&remaining_events.try_recv().expect("reader event")),
            Ok(expected)
        );
        assert!(matches!(removed_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
        assert!(matches!(revoked_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));

        let response = app.clone().oneshot(removal_request(member)).await.expect("repeat removal");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(matches!(admin_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));

        let next_member = Uuid::now_v7();
        store
            .add_shared_sync_vault_member(
                vault.into_bytes(),
                next_member.into_bytes(),
                &[storage::SharedVaultKey { epoch: 1, wrapped_vault_key: vec![3] }],
            )
            .await
            .expect("add next member");
        drop(admin_events);
        drop(remaining_events);
        drop(removed_events);
        drop(revoked_events);
        let response =
            app.oneshot(removal_request(next_member)).await.expect("remove without peers");
        assert_eq!(response.status(), StatusCode::OK);
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
    async fn committed_writes_notify_only_current_readers_of_the_written_vault() {
        let (store, first_vault, writer) = test_store().await;
        let second_vault = Uuid::now_v7().into_bytes();
        store
            .create_sync_vault(second_vault, storage::VaultKind::Personal)
            .await
            .expect("create second vault");
        let removed_reader = Uuid::now_v7().into_bytes();
        let revoked_reader = Uuid::now_v7().into_bytes();
        let hub = NotificationHub::default();
        let mut writer_events = hub.subscribe(writer);
        let mut removed_events = hub.subscribe(removed_reader);
        let mut revoked_events = hub.subscribe(revoked_reader);
        let mut authenticator = TestAuthenticator::new(writer, true);
        authenticator.denied_read = Some((removed_reader, first_vault));
        authenticator.denied_notifications = Some(revoked_reader);
        let app = router_with_notifications(store, authenticator, hub.clone());

        let first_batch = SyncWriteBatch {
            writes: (0..2)
                .map(|_| api::SyncWrite {
                    object_id: Uuid::now_v7(),
                    base_seq: None,
                    payload: vec![1],
                    tombstone: false,
                })
                .collect(),
        };
        let response = app
            .clone()
            .oneshot(write_request(first_vault, &first_batch))
            .await
            .expect("first write response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("first body");
        let assignments = SyncWriteBatchResponse::from_cbor(&body).expect("first assignments");
        assert_eq!(assignments.assignments.len(), 2);
        assert_eq!(assignments.assignments[1].seq, 2);
        assert_eq!(
            api::SyncNotification::from_cbor(&writer_events.try_recv().expect("writer event")),
            Ok(api::SyncNotification::VaultAdvanced {
                vault: Uuid::from_bytes(first_vault),
                seq: 2
            })
        );
        assert!(matches!(removed_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
        assert!(matches!(revoked_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));

        let second_batch = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![2],
                tombstone: false,
            }],
        };
        let response = app
            .oneshot(write_request(second_vault, &second_batch))
            .await
            .expect("second write response");
        assert_eq!(response.status(), StatusCode::OK);
        let second_event =
            api::SyncNotification::VaultAdvanced { vault: Uuid::from_bytes(second_vault), seq: 1 };
        assert_eq!(
            api::SyncNotification::from_cbor(&writer_events.try_recv().expect("writer event")),
            Ok(second_event.clone())
        );
        assert_eq!(
            api::SyncNotification::from_cbor(&removed_events.try_recv().expect("reader event")),
            Ok(second_event)
        );
        assert!(matches!(revoked_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn rejected_writes_never_notify_and_disconnected_receivers_do_not_fail_writes() {
        let (store, vault, writer) = test_store().await;
        let hub = NotificationHub::default();
        let mut events = hub.subscribe(writer);
        let app = router_with_notifications(
            store.clone(),
            TestAuthenticator::new(writer, true),
            hub.clone(),
        );
        let first_batch = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![1],
                tombstone: false,
            }],
        };
        let response = app
            .clone()
            .oneshot(write_request(vault, &first_batch))
            .await
            .expect("initial write response");
        assert_eq!(response.status(), StatusCode::OK);
        let _ = events.try_recv().expect("initial notification");

        let response = app
            .clone()
            .oneshot(write_request(vault, &first_batch))
            .await
            .expect("conflicting write response");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let rejected_batch = SyncWriteBatch {
            writes: vec![api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![2],
                tombstone: false,
            }],
        };
        let mut rejecting_authenticator = TestAuthenticator::new(writer, true);
        rejecting_authenticator.reject_writes = true;
        let rejecting_app =
            router_with_notifications(store.clone(), rejecting_authenticator, hub.clone());
        let response = rejecting_app
            .oneshot(write_request(vault, &rejected_batch))
            .await
            .expect("rejected write response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let denied_app = router_with_notifications(
            store.clone(),
            TestAuthenticator::new(writer, false),
            hub.clone(),
        );
        let response = denied_app
            .oneshot(write_request(vault, &rejected_batch))
            .await
            .expect("denied write response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let unauthenticated = Request::builder()
            .method("POST")
            .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(Body::from(rejected_batch.to_cbor().expect("encode write batch")))
            .expect("unauthenticated request");
        let response =
            app.clone().oneshot(unauthenticated).await.expect("unauthenticated write response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(matches!(events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));

        drop(events);
        let response = app
            .oneshot(write_request(vault, &rejected_batch))
            .await
            .expect("write without receiver response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("write body");
        let assignments = SyncWriteBatchResponse::from_cbor(&body).expect("write assignments");
        assert_eq!(assignments.assignments[0].seq, 2);
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
    async fn acknowledgement_bounds_body_after_authentication_without_advancing_cursor() {
        let (store, vault, device) = test_store().await;
        let app = router(store.clone(), TestAuthenticator::new(device, true));
        let uri = format!("/sync/v1/vaults/{}/ack", path(vault));
        let request = |body| {
            request_headers(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(header::CONTENT_TYPE, "application/cbor"),
            )
            .body(Body::from(body))
            .expect("ack request")
        };

        assert_eq!(store.ack_sync_cursor(vault, device, 0).await.expect("initial ack"), 0);
        let largest_valid = SyncAckRequest { cursor: u64::MAX }.to_cbor().expect("largest ack");
        assert_eq!(largest_valid.len(), MAX_ACK_REQUEST_BYTES);
        let response = app.clone().oneshot(request(largest_valid)).await.expect("ahead response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("ahead body");
        assert_eq!(
            ProblemDetails::from_cbor(&bytes).expect("ahead problem").code.as_str(),
            "sync.cursor_ahead"
        );

        for size in [MAX_ACK_REQUEST_BYTES + 1, MAX_REQUEST_BYTES + 1] {
            let response = app
                .clone()
                .oneshot(request(vec![0xff; size]))
                .await
                .expect("oversized ack response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body size {size}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/problem+cbor"
            );
            let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem");
            let problem = ProblemDetails::from_cbor(&bytes).expect("CBOR problem");
            assert_eq!(problem.code.as_str(), "sync.invalid_request");
            assert!(!problem.changed);
            assert!(!problem.retryable);
            assert_eq!(store.ack_sync_cursor(vault, device, 0).await.expect("stored ack"), 0);
        }

        let unauthenticated = Request::builder()
            .method("POST")
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(Body::from(vec![0xff; MAX_REQUEST_BYTES + 1]))
            .expect("unauthenticated ack request");
        let response = app.oneshot(unauthenticated).await.expect("auth response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth body");
        assert_eq!(
            ProblemDetails::from_cbor(&bytes).expect("auth problem").code.as_str(),
            "auth.authentication_required"
        );
        assert_eq!(store.ack_sync_cursor(vault, device, 0).await.expect("stored ack"), 0);
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
    async fn page_queries_are_bounded_after_authentication_on_both_read_routes() {
        let (store, vault, device) = test_store().await;
        let before_changes = store.sync_changes(vault, 0, 1).await.expect("initial changes");
        let before_snapshot = store.sync_snapshot(vault, 0, 1).await.expect("initial snapshot");
        let app = router(store.clone(), TestAuthenticator::new(device, true));

        let max_queries =
            [format!("after={}&limit=1000", u64::MAX), format!("limit=1000&after={}", u64::MAX)];
        for query in &max_queries {
            assert_eq!(query.len(), MAX_SYNC_PAGE_QUERY_BYTES);
            assert_eq!(
                parse_query(Some(query), "test").expect("maximum canonical query"),
                api::SyncChangesQuery { after: u64::MAX, limit: 1000 }
            );
        }
        let too_long = format!("{}&", max_queries[0]);
        assert_eq!(too_long.len(), MAX_SYNC_PAGE_QUERY_BYTES + 1);
        let very_long = format!("after=0&limit=1&{}", "x".repeat(4096));

        for endpoint in ["changes", "snapshot"] {
            let request = |query: &str, authenticated: bool| {
                let builder = Request::builder()
                    .uri(format!("/sync/v1/vaults/{}/{endpoint}?{query}", path(vault)));
                let builder = if authenticated { request_headers(builder) } else { builder };
                builder.body(Body::empty()).expect("page request")
            };

            for query in &max_queries {
                let response =
                    app.clone().oneshot(request(query, true)).await.expect("max query response");
                assert_eq!(response.status(), StatusCode::GONE);
                let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("body");
                assert_eq!(
                    ProblemDetails::from_cbor(&bytes).expect("cursor problem").code.as_str(),
                    "sync.cursor_expired"
                );
            }

            for query in [too_long.as_str(), very_long.as_str(), "after=00&limit=1"] {
                let response = app
                    .clone()
                    .oneshot(request(query, true))
                    .await
                    .expect("invalid query response");
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    response.headers().get(header::CONTENT_TYPE).unwrap(),
                    "application/problem+cbor"
                );
                let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("body");
                let problem = ProblemDetails::from_cbor(&bytes).expect("invalid query problem");
                assert_eq!(problem.code.as_str(), "sync.invalid_request");
                assert!(!problem.changed);
                assert!(!problem.retryable);
                assert_eq!(
                    problem.detail.contains("too long"),
                    query.len() > MAX_SYNC_PAGE_QUERY_BYTES
                );
            }

            let response = app
                .clone()
                .oneshot(request(&very_long, false))
                .await
                .expect("unauthenticated response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("auth body");
            assert_eq!(
                ProblemDetails::from_cbor(&bytes).expect("auth problem").code.as_str(),
                "auth.authentication_required"
            );

            assert_eq!(store.sync_changes(vault, 0, 1).await.expect("changes"), before_changes);
            assert_eq!(store.sync_snapshot(vault, 0, 1).await.expect("snapshot"), before_snapshot);
        }
    }

    #[tokio::test]
    async fn read_cursor_errors_require_reconciliation_while_ack_keeps_ahead_error() {
        let (store, vault, device) = test_store().await;
        let object = Uuid::now_v7().into_bytes();
        let initial = storage::ObjectWrite {
            object_id: object,
            base_sequence: None,
            envelope: vec![1],
            key_epoch: 1,
            tombstone: false,
            signer_device_id: Some(device),
        };
        store.write_sync_batch(vault, std::slice::from_ref(&initial)).await.expect("initial write");
        store
            .write_sync_batch(
                vault,
                &[storage::ObjectWrite {
                    base_sequence: Some(1),
                    tombstone: true,
                    envelope: vec![2],
                    ..initial
                }],
            )
            .await
            .expect("tombstone");
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_millis(),
        )
        .expect("timestamp fits SQLite integer");
        let retention =
            store.purge_sync_history(vault, Some(2), now_ms).await.expect("purge tombstone");
        assert_eq!(retention.purge_horizon, 2);
        assert_eq!(store.ack_sync_cursor(vault, device, 0).await.expect("initial ack"), 0);
        let before = store.sync_snapshot(vault, 0, 1).await.expect("snapshot state");
        let app = router(store.clone(), TestAuthenticator::new(device, true));

        for (endpoint, after) in [("changes", 0), ("changes", 3), ("snapshot", 3)] {
            let request =
                request_headers(Request::builder().uri(format!(
                    "/sync/v1/vaults/{}/{endpoint}?after={after}&limit=1",
                    path(vault)
                )))
                .body(Body::empty())
                .expect("read request");
            let response = app.clone().oneshot(request).await.expect("read response");
            assert_eq!(response.status(), StatusCode::GONE, "{endpoint} after={after}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/problem+cbor"
            );
            let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem");
            let problem = ProblemDetails::from_cbor(&body).expect("CBOR problem");
            assert_eq!(problem.code.as_str(), "sync.cursor_expired");
            assert!(!problem.changed);
            assert!(!problem.retryable);
        }

        let snapshot = request_headers(
            Request::builder()
                .uri(format!("/sync/v1/vaults/{}/snapshot?after=0&limit=1", path(vault))),
        )
        .body(Body::empty())
        .expect("snapshot request");
        assert_eq!(
            app.clone().oneshot(snapshot).await.expect("snapshot response").status(),
            StatusCode::OK
        );

        let ack = request_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/sync/v1/vaults/{}/ack", path(vault)))
                .header(header::CONTENT_TYPE, "application/cbor"),
        )
        .body(Body::from(SyncAckRequest { cursor: 3 }.to_cbor().expect("ack")))
        .expect("ack request");
        let response = app.oneshot(ack).await.expect("ack response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("ack problem");
        assert_eq!(
            ProblemDetails::from_cbor(&body).expect("ack CBOR problem").code.as_str(),
            "sync.cursor_ahead"
        );
        assert_eq!(store.sync_snapshot(vault, 0, 1).await.expect("snapshot state"), before);
        assert_eq!(store.ack_sync_cursor(vault, device, 0).await.expect("stored ack"), 0);
    }

    #[tokio::test]
    async fn conflict_problem_contains_current_change_extension() {
        let (store, vault, device) = test_store().await;
        let app = router(store, TestAuthenticator::new(device, true));
        let first_object = Uuid::now_v7();
        let second_object = Uuid::now_v7();
        let absent_object = Uuid::now_v7();
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
            writes: vec![
                api::SyncWrite {
                    object_id: first_object,
                    base_seq: None,
                    payload: vec![1],
                    tombstone: false,
                },
                api::SyncWrite {
                    object_id: second_object,
                    base_seq: None,
                    payload: vec![2],
                    tombstone: false,
                },
            ],
        };
        assert_eq!(
            app.clone().oneshot(make_request(first)).await.expect("first").status(),
            StatusCode::OK
        );
        let stale = SyncWriteBatch {
            writes: vec![
                api::SyncWrite {
                    object_id: second_object,
                    base_seq: None,
                    payload: vec![3],
                    tombstone: false,
                },
                api::SyncWrite {
                    object_id: absent_object,
                    base_seq: Some(1),
                    payload: vec![4],
                    tombstone: false,
                },
                api::SyncWrite {
                    object_id: first_object,
                    base_seq: None,
                    payload: vec![5],
                    tombstone: false,
                },
            ],
        };
        let response = app.oneshot(make_request(stale.clone())).await.expect("conflict");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("conflict body");
        let conflict = api::SyncConflictProblem::from_cbor(&body).expect("conflict problem");
        conflict.validate_for_batch(&stale).expect("complete ordered conflict extension");
        assert_eq!(conflict.problem.code.as_str(), "sync.conflict");
        assert_eq!(
            conflict.conflicts,
            vec![
                api::SyncConflictEntry {
                    object_id: second_object,
                    current: Some(api::SyncChange {
                        object_id: second_object,
                        seq: 2,
                        payload: vec![2],
                        tombstone: false,
                        signer_device_id: Some(Uuid::from_bytes(device)),
                    }),
                },
                api::SyncConflictEntry { object_id: absent_object, current: None },
                api::SyncConflictEntry {
                    object_id: first_object,
                    current: Some(api::SyncChange {
                        object_id: first_object,
                        seq: 1,
                        payload: vec![1],
                        tombstone: false,
                        signer_device_id: Some(Uuid::from_bytes(device)),
                    }),
                },
            ]
        );
    }

    #[tokio::test]
    async fn invalid_stored_conflict_does_not_emit_partial_conflict_problem() {
        let object_id = Uuid::now_v7().into_bytes();
        let error = storage::SyncStoreError::Conflict {
            conflicts: vec![storage::ConflictEntry {
                object_id,
                current: Some(storage::SyncChange {
                    object_id,
                    sequence: 0,
                    envelope: vec![1],
                    key_epoch: 1,
                    tombstone: false,
                    signer_device_id: None,
                }),
            }],
        };
        let response = SyncHttpError::from_store(error, "test-conflict").into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("problem body");
        let problem = ProblemDetails::from_cbor(&body).expect("storage problem");
        assert_eq!(problem.code.as_str(), "sync.storage_unavailable");
        assert!(api::SyncConflictProblem::from_cbor(&body).is_err());
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
