// SPDX-License-Identifier: AGPL-3.0-only
//! Public enrolled-device authentication and key discovery.

use std::{
    error::Error as _,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthJwk, AuthJwks,
        AuthRateLimitHeaders, AuthRefreshRequest, AuthTokenResponse, BrowserAuthRefreshRequest,
        BrowserAuthTokenResponse, MAX_CHALLENGE_REQUEST_BYTES, MAX_DEVICE_REQUEST_BYTES,
        MAX_REFRESH_REQUEST_BYTES,
    },
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use scoplen_store::{
    PostgresStore, SqliteStore,
    device_authentication::{
        CurrentPrincipal, DeviceAuthAdmission, DeviceAuthEndpoint, DeviceAuthFailureReason,
        DeviceAuthenticationError, DeviceChallenge,
    },
    device_token_keys::{DeviceTokenKeyError, DeviceTokenKeyring},
    kms::LocalKeyFile,
    operator_token_keys::{OperatorTokenKeyError, OperatorTokenKeyring},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const REFRESH_COOKIE: &str = "__Secure-spl-refresh";
const MAX_DPOP_HEADER_BYTES: usize = 8_192;

#[derive(Clone)]
pub(crate) enum AuthBackend {
    Sqlite(Arc<SqliteStore>),
    Postgres(Arc<PostgresStore>),
}

impl AuthBackend {
    async fn admit_source(
        &self,
        endpoint: DeviceAuthEndpoint,
        source: IpAddr,
    ) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => store.admit_device_auth_source(endpoint, source).await,
            Self::Postgres(store) => store.admit_device_auth_source(endpoint, source).await,
        }
    }

    async fn admit_device(
        &self,
        endpoint: DeviceAuthEndpoint,
        device_id: [u8; 16],
    ) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => store.admit_device_auth_device(endpoint, device_id).await,
            Self::Postgres(store) => store.admit_device_auth_device(endpoint, device_id).await,
        }
    }

    async fn challenge(
        &self,
        device_id: [u8; 16],
    ) -> Result<DeviceChallenge, DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => store.issue_device_challenge(device_id).await,
            Self::Postgres(store) => store.issue_device_challenge(device_id).await,
        }
    }

    async fn authenticate(
        &self,
        source: IpAddr,
        origin: &str,
        device_id: [u8; 16],
        nonce: &[u8; 32],
        signature: &[u8; 64],
        keyring: &DeviceTokenKeyring,
    ) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .authenticate_device(source, origin, device_id, nonce, signature, keyring)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .authenticate_device(source, origin, device_id, nonce, signature, keyring)
                    .await
            }
        }
    }

    async fn refresh(
        &self,
        source: IpAddr,
        origin: &str,
        token: &str,
        proof: &str,
        keyring: &DeviceTokenKeyring,
    ) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => {
                store.refresh_device(source, origin, token, proof, keyring).await
            }
            Self::Postgres(store) => {
                store.refresh_device(source, origin, token, proof, keyring).await
            }
        }
    }

    pub(crate) async fn keyring(
        &self,
        kms: &LocalKeyFile,
    ) -> Result<DeviceTokenKeyring, DeviceTokenKeyError> {
        match self {
            Self::Sqlite(store) => store.ensure_device_token_keyring(kms).await,
            Self::Postgres(store) => store.ensure_device_token_keyring(kms).await,
        }
    }

    pub(crate) async fn operator_keyring(
        &self,
        kms: &LocalKeyFile,
    ) -> Result<OperatorTokenKeyring, OperatorTokenKeyError> {
        match self {
            Self::Sqlite(store) => store.ensure_operator_token_keyring(kms).await,
            Self::Postgres(store) => store.ensure_operator_token_keyring(kms).await,
        }
    }

    pub(crate) async fn current_principal(
        &self,
        device_id: [u8; 16],
    ) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => store.current_device_principal(device_id).await,
            Self::Postgres(store) => store.current_device_principal(device_id).await,
        }
    }

    pub(crate) async fn claim_dpop(
        &self,
        proof: &DpopProof,
        target: &DpopTarget,
        token: DpopToken<'_>,
        jkt: &str,
    ) -> Result<(), DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => store.claim_dpop_proof(proof, target, token, jkt, None).await,
            Self::Postgres(store) => store.claim_dpop_proof(proof, target, token, jkt, None).await,
        }
    }

    pub(crate) async fn personal_vault(
        &self,
        account_id: [u8; 16],
    ) -> Result<[u8; 16], scoplen_store::sync::SyncStoreError> {
        match self {
            Self::Sqlite(store) => store.get_personal_sync_vault_key(account_id).await.map(|v| v.0),
            Self::Postgres(store) => {
                store.get_personal_sync_vault_key(account_id).await.map(|v| v.0)
            }
        }
    }

    async fn audit_failure(
        &self,
        endpoint: DeviceAuthEndpoint,
        reason: DeviceAuthFailureReason,
        source: IpAddr,
    ) -> Result<(), DeviceAuthenticationError> {
        match self {
            Self::Sqlite(store) => {
                store.audit_device_auth_failure(endpoint, reason, source, None, None).await
            }
            Self::Postgres(store) => {
                store.audit_device_auth_failure(endpoint, reason, source, None, None).await
            }
        }
    }
}

struct AuthState {
    trusted_origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
}

pub(crate) fn router(
    trusted_origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
) -> Router {
    let operator_router =
        crate::operator_auth::router(trusted_origin.clone(), backend.clone(), kms.clone());
    let logout_router =
        crate::operator_logout::router(trusted_origin.clone(), backend.clone(), kms.clone());
    let state = Arc::new(AuthState { trusted_origin, backend, kms });
    Router::new()
        .route("/api/v1/auth/challenge", post(challenge))
        .route("/api/v1/auth/device", post(device))
        .route("/api/v1/auth/refresh", post(refresh).options(refresh_options))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/operator-jwks.json", get(operator_jwks))
        .with_state(state)
        .merge(operator_router)
        .merge(logout_router)
}

#[allow(clippy::too_many_lines, clippy::manual_let_else)]
async fn challenge(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AuthState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let request_id = Uuid::new_v4().to_string();
    let endpoint = DeviceAuthEndpoint::Challenge;
    if let Err(response) = source_admission(&state, endpoint, source, &request_id).await {
        return response;
    }
    let (parts, body) = request.into_parts();
    if let Err((status, code, reason)) = device_headers(&parts.headers, &state.trusted_origin) {
        return audited_problem(
            &state,
            endpoint,
            source,
            reason,
            status,
            code,
            false,
            false,
            &request_id,
            None,
        )
        .await;
    }
    let body = match json_body(&parts.headers, body, MAX_CHALLENGE_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(status) => {
            return audited_problem(
                &state,
                endpoint,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                status,
                "auth.invalid_request",
                false,
                false,
                &request_id,
                None,
            )
            .await;
        }
    };
    let decoded = match AuthChallengeRequest::from_json(&body) {
        Ok(value) => value,
        Err(_) => {
            return audited_problem(
                &state,
                endpoint,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                false,
                false,
                &request_id,
                None,
            )
            .await;
        }
    };
    if let Err(response) =
        device_admission(&state, endpoint, source, decoded.device_id.into_bytes(), &request_id)
            .await
    {
        return response;
    }
    let issued = match state.backend.challenge(decoded.device_id.into_bytes()).await {
        Ok(value) => value,
        Err(_) => {
            return audited_problem(
                &state,
                endpoint,
                source,
                DeviceAuthFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                false,
                true,
                &request_id,
                None,
            )
            .await;
        }
    };
    let nonce = hex(issued.nonce());
    let server_time = OffsetDateTime::from_unix_timestamp(issued.issued_at_ms().div_euclid(1_000))
        .ok()
        .and_then(|timestamp| timestamp.format(&Rfc3339).ok());
    let Some(server_time) = server_time else {
        return audited_problem(
            &state,
            endpoint,
            source,
            DeviceAuthFailureReason::StorageUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            &request_id,
            None,
        )
        .await;
    };
    let Ok(body) = AuthChallengeResponse::new(nonce, server_time).and_then(|value| value.to_json())
    else {
        return audited_problem(
            &state,
            endpoint,
            source,
            DeviceAuthFailureReason::StorageUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            &request_id,
            None,
        )
        .await;
    };
    response(StatusCode::OK, "application/json", body.into_bytes())
}

#[allow(clippy::too_many_lines, clippy::manual_let_else)]
async fn device(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AuthState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let request_id = Uuid::new_v4().to_string();
    let endpoint = DeviceAuthEndpoint::Device;
    if let Err(response) = source_admission(&state, endpoint, source, &request_id).await {
        return response;
    }
    let (parts, body) = request.into_parts();
    if let Err((status, code, reason)) = device_headers(&parts.headers, &state.trusted_origin) {
        return audited_problem(
            &state,
            endpoint,
            source,
            reason,
            status,
            code,
            false,
            false,
            &request_id,
            None,
        )
        .await;
    }
    let body = match json_body(&parts.headers, body, MAX_DEVICE_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(status) => {
            return audited_problem(
                &state,
                endpoint,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                status,
                "auth.invalid_request",
                false,
                false,
                &request_id,
                None,
            )
            .await;
        }
    };
    let decoded = match AuthDeviceRequest::from_json(&body) {
        Ok(value) => value,
        Err(_) => {
            return audited_problem(
                &state,
                endpoint,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                false,
                false,
                &request_id,
                None,
            )
            .await;
        }
    };
    if let Err(response) =
        device_admission(&state, endpoint, source, decoded.device_id.into_bytes(), &request_id)
            .await
    {
        return response;
    }
    let (Ok(nonce), Ok(signature)) = (decode_hex(&decoded.nonce), decode_hex(&decoded.signature))
    else {
        return audited_problem(
            &state,
            endpoint,
            source,
            DeviceAuthFailureReason::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "auth.invalid_request",
            false,
            false,
            &request_id,
            None,
        )
        .await;
    };
    let keyring = match state.backend.keyring(&state.kms).await {
        Ok(value) => value,
        Err(_) => {
            return audited_problem(
                &state,
                endpoint,
                source,
                DeviceAuthFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                false,
                true,
                &request_id,
                None,
            )
            .await;
        }
    };
    match state
        .backend
        .authenticate(
            source,
            &state.trusted_origin,
            decoded.device_id.into_bytes(),
            &nonce,
            &signature,
            &keyring,
        )
        .await
    {
        Ok(value) => match value.to_json() {
            Ok(body) => response(StatusCode::OK, "application/json", body.into_bytes()),
            Err(_) => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                false,
                true,
                &request_id,
                None,
            ),
        },
        Err(error) => business_problem(&error, &request_id),
    }
}

#[allow(clippy::too_many_lines, clippy::manual_let_else)]
async fn refresh(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AuthState>>,
    request: Request<Body>,
) -> Response {
    if crate::operator_auth::operator_refresh_candidate(request.headers()) {
        return crate::operator_auth::refresh_operator(
            state.trusted_origin.clone(),
            state.backend.clone(),
            state.kms.clone(),
            peer.ip(),
            request,
        )
        .await;
    }
    let source = peer.ip();
    let request_id = Uuid::new_v4().to_string();
    let endpoint = DeviceAuthEndpoint::Refresh;
    if let Err(mut response) = source_admission(&state, endpoint, source, &request_id).await {
        if matching_origin(request.headers(), &state.trusted_origin) {
            add_cors(&mut response, &state.trusted_origin);
        }
        return response;
    }
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;
    let cors = matching_origin(headers, &state.trusted_origin);
    if headers.contains_key(header::AUTHORIZATION) || headers.contains_key("idempotency-key") {
        return refresh_problem(
            &state,
            source,
            DeviceAuthFailureReason::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "auth.invalid_request",
            &request_id,
            cors,
        )
        .await;
    }
    if header_count(headers, header::ORIGIN) > 1
        || (header_count(headers, header::ORIGIN) == 1 && !cors)
    {
        return refresh_problem(
            &state,
            source,
            DeviceAuthFailureReason::OriginDenied,
            StatusCode::FORBIDDEN,
            "policy.denied",
            &request_id,
            false,
        )
        .await;
    }
    let cookie = match refresh_cookie(headers) {
        Ok(value) => value,
        Err(()) => {
            return refresh_problem(
                &state,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                &request_id,
                cors,
            )
            .await;
        }
    };
    let proof = match headers.get_all("dpop").iter().collect::<Vec<_>>().as_slice() {
        [value]
            if !value.as_bytes().is_empty() && value.as_bytes().len() <= MAX_DPOP_HEADER_BYTES =>
        {
            match value.to_str() {
                Ok(value) => value.to_owned(),
                Err(_) => {
                    return refresh_problem(
                        &state,
                        source,
                        DeviceAuthFailureReason::InvalidRequest,
                        StatusCode::BAD_REQUEST,
                        "auth.invalid_dpop_proof",
                        &request_id,
                        cors,
                    )
                    .await;
                }
            }
        }
        _ => {
            return refresh_problem(
                &state,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_dpop_proof",
                &request_id,
                cors,
            )
            .await;
        }
    };
    let body = match json_body(headers, body, MAX_REFRESH_REQUEST_BYTES).await {
        Ok(value) => value,
        Err(status) => {
            return refresh_problem(
                &state,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                status,
                "auth.invalid_request",
                &request_id,
                cors,
            )
            .await;
        }
    };
    let browser = cookie.is_some();
    let refresh_token = if let Some(token) = cookie {
        if !cors {
            return refresh_problem(
                &state,
                source,
                DeviceAuthFailureReason::OriginDenied,
                StatusCode::FORBIDDEN,
                "policy.denied",
                &request_id,
                false,
            )
            .await;
        }
        if BrowserAuthRefreshRequest::from_json(&body).is_err() {
            return refresh_problem(
                &state,
                source,
                DeviceAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                &request_id,
                cors,
            )
            .await;
        }
        token
    } else {
        match AuthRefreshRequest::from_json(&body) {
            Ok(value) => value.refresh_token,
            Err(_) => {
                return refresh_problem(
                    &state,
                    source,
                    DeviceAuthFailureReason::InvalidRequest,
                    StatusCode::BAD_REQUEST,
                    "auth.invalid_request",
                    &request_id,
                    cors,
                )
                .await;
            }
        }
    };
    let keyring_started = Instant::now();
    let keyring = match state.backend.keyring(&state.kms).await {
        Ok(value) => value,
        Err(error) => {
            let error = match error {
                DeviceTokenKeyError::Storage(error) => DeviceAuthenticationError::from(error),
                DeviceTokenKeyError::Audit(_) => DeviceAuthenticationError::Audit,
                DeviceTokenKeyError::Clock => DeviceAuthenticationError::Clock,
                DeviceTokenKeyError::Entropy => DeviceAuthenticationError::Entropy,
                DeviceTokenKeyError::Integrity => DeviceAuthenticationError::Database,
                DeviceTokenKeyError::CommitOutcomeUnknown => {
                    DeviceAuthenticationError::CommitOutcomeUnknown
                }
            };
            log_auth_storage_failure(&error, endpoint, "keyring", &request_id, keyring_started);
            return refresh_problem(
                &state,
                source,
                DeviceAuthFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                &request_id,
                cors,
            )
            .await;
        }
    };
    let refresh_started = Instant::now();
    let mut result = match state
        .backend
        .refresh(source, &state.trusted_origin, &refresh_token, &proof, &keyring)
        .await
    {
        Ok(value) => {
            if browser {
                let browser_body = BrowserAuthTokenResponse {
                    access_token: value.access_token,
                    token_type: value.token_type,
                    expires_in: value.expires_in,
                    refresh_expires_in: value.refresh_expires_in,
                };
                let Ok(body) = browser_body.to_json() else {
                    return problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "auth.storage_unavailable",
                        false,
                        true,
                        &request_id,
                        None,
                    );
                };
                let mut response = response(StatusCode::OK, "application/json", body.into_bytes());
                let cookie = format!(
                    "{REFRESH_COOKIE}={}; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
                    value.refresh_token, value.refresh_expires_in
                );
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    cookie.parse().expect("generated hexadecimal cookie"),
                );
                response
            } else {
                match value.to_json() {
                    Ok(body) => response(StatusCode::OK, "application/json", body.into_bytes()),
                    Err(_) => problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "auth.storage_unavailable",
                        false,
                        true,
                        &request_id,
                        None,
                    ),
                }
            }
        }
        Err(error) => {
            log_auth_storage_failure(
                &error,
                endpoint,
                "refresh_transaction",
                &request_id,
                refresh_started,
            );
            business_problem(&error, &request_id)
        }
    };
    if cors {
        add_cors(&mut result, &state.trusted_origin);
    }
    result
}

async fn refresh_options(State(state): State<Arc<AuthState>>, request: Request<Body>) -> Response {
    let headers = request.headers();
    let request_id = Uuid::new_v4().to_string();
    if !matching_origin(headers, &state.trusted_origin)
        || header_count(headers, header::ORIGIN) != 1
        || header_count(headers, "access-control-request-method") != 1
        || headers.get("access-control-request-method")
            != Some(&axum::http::HeaderValue::from_static("POST"))
        || header_count(headers, "access-control-request-headers") != 1
    {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, false, &request_id, None);
    }
    let allowed = headers
        .get("access-control-request-headers")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').all(|name| {
                matches!(name.trim().to_ascii_lowercase().as_str(), "dpop" | "content-type")
            })
        });
    if !allowed {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, false, &request_id, None);
    }
    let mut result = response(StatusCode::NO_CONTENT, "application/json", Vec::new());
    add_cors(&mut result, &state.trusted_origin);
    result
        .headers_mut()
        .insert("access-control-allow-methods", "POST, OPTIONS".parse().expect("static methods"));
    result.headers_mut().insert(
        "access-control-allow-headers",
        "DPoP, Content-Type".parse().expect("static headers"),
    );
    result
}

#[allow(clippy::manual_let_else)]
async fn jwks(State(state): State<Arc<AuthState>>) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let keyring = match state.backend.keyring(&state.kms).await {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                false,
                true,
                &request_id,
                None,
            );
        }
    };
    let document = keyring
        .verification_keys()
        .iter()
        .map(|key| AuthJwk::new(&key.kid, key.public_key))
        .collect::<Result<Vec<_>, _>>()
        .and_then(AuthJwks::new)
        .and_then(|value| value.to_json());
    match document {
        Ok(body) => response(StatusCode::OK, "application/json", body),
        Err(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            &request_id,
            None,
        ),
    }
}

#[allow(clippy::manual_let_else)]
async fn operator_jwks(State(state): State<Arc<AuthState>>) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let keyring = match state.backend.operator_keyring(&state.kms).await {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                false,
                true,
                &request_id,
                None,
            );
        }
    };
    let document = keyring
        .verification_keys()
        .iter()
        .map(|key| AuthJwk::new(&key.kid, key.public_key))
        .collect::<Result<Vec<_>, _>>()
        .and_then(AuthJwks::new)
        .and_then(|value| value.to_json());
    match document {
        Ok(body) => response(StatusCode::OK, "application/json", body),
        Err(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            &request_id,
            None,
        ),
    }
}

#[allow(clippy::result_large_err)]
async fn source_admission(
    state: &AuthState,
    endpoint: DeviceAuthEndpoint,
    source: IpAddr,
    request_id: &str,
) -> Result<(), Response> {
    let started = Instant::now();
    tracing::debug!(request_id, endpoint = ?endpoint, phase = "source_admission", "authentication request received");
    match state.backend.admit_source(endpoint, source).await {
        Ok(DeviceAuthAdmission::Admitted) => Ok(()),
        Ok(DeviceAuthAdmission::RateLimited(delay)) => Err(audited_problem(
            state,
            endpoint,
            source,
            DeviceAuthFailureReason::RateLimited,
            StatusCode::TOO_MANY_REQUESTS,
            "auth.rate_limited",
            false,
            true,
            request_id,
            Some(delay),
        )
        .await),
        Err(error) => {
            log_auth_storage_failure(&error, endpoint, "source_admission", request_id, started);
            Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                false,
                true,
                request_id,
                None,
            ))
        }
    }
}

fn log_auth_storage_failure(
    error: &DeviceAuthenticationError,
    endpoint: DeviceAuthEndpoint,
    phase: &'static str,
    request_id: &str,
    started: Instant,
) {
    let kind = match error {
        DeviceAuthenticationError::Database => "database",
        DeviceAuthenticationError::DatabaseBusy => "database_busy",
        DeviceAuthenticationError::PoolTimedOut => "pool_timeout",
        DeviceAuthenticationError::PoolClosed => "pool_closed",
        DeviceAuthenticationError::Audit => "audit",
        DeviceAuthenticationError::Clock => "clock",
        DeviceAuthenticationError::Entropy => "entropy",
        DeviceAuthenticationError::CommitOutcomeUnknown => "commit_outcome_unknown",
        _ => return,
    };
    tracing::warn!(
        request_id,
        endpoint = ?endpoint,
        phase,
        error_kind = kind,
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "authentication storage operation failed"
    );
}

#[allow(clippy::result_large_err)]
async fn device_admission(
    state: &AuthState,
    endpoint: DeviceAuthEndpoint,
    source: IpAddr,
    device_id: [u8; 16],
    request_id: &str,
) -> Result<(), Response> {
    match state.backend.admit_device(endpoint, device_id).await {
        Ok(DeviceAuthAdmission::Admitted) => Ok(()),
        Ok(DeviceAuthAdmission::RateLimited(delay)) => Err(audited_problem(
            state,
            endpoint,
            source,
            DeviceAuthFailureReason::RateLimited,
            StatusCode::TOO_MANY_REQUESTS,
            "auth.rate_limited",
            false,
            true,
            request_id,
            Some(delay),
        )
        .await),
        Err(_) => Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            request_id,
            None,
        )),
    }
}

fn device_headers(
    headers: &HeaderMap,
    trusted_origin: &str,
) -> Result<(), (StatusCode, &'static str, DeviceAuthFailureReason)> {
    if headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key("dpop")
        || headers.contains_key("idempotency-key")
        || matches!(refresh_cookie(headers), Err(()) | Ok(Some(_)))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "auth.invalid_request",
            DeviceAuthFailureReason::InvalidRequest,
        ));
    }
    if header_count(headers, header::ORIGIN) > 1
        || (header_count(headers, header::ORIGIN) == 1 && !matching_origin(headers, trusted_origin))
    {
        return Err((
            StatusCode::FORBIDDEN,
            "policy.denied",
            DeviceAuthFailureReason::OriginDenied,
        ));
    }
    Ok(())
}

pub(crate) async fn json_body(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
) -> Result<String, StatusCode> {
    if !is_json(headers) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let bytes = match to_bytes(body, limit + 1).await {
        Ok(value) if value.len() <= limit => value,
        Ok(_) => return Err(StatusCode::PAYLOAD_TOO_LARGE),
        Err(error)
            if error
                .source()
                .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>) =>
        {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    String::from_utf8(bytes.to_vec()).map_err(|_| StatusCode::BAD_REQUEST)
}

fn is_json(headers: &HeaderMap) -> bool {
    if header_count(headers, header::CONTENT_TYPE) != 1 {
        return false;
    }
    headers.get(header::CONTENT_TYPE).is_some_and(|value| {
        value.to_str().is_ok_and(|value| {
            let mut parts = value.split(';');
            parts.next().is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
                && parts.all(|part| part.trim().eq_ignore_ascii_case("charset=utf-8"))
        })
    })
}

pub(crate) fn refresh_cookie(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut result = None;
    for value in &headers.get_all(header::COOKIE) {
        let value = value.to_str().map_err(|_| ())?;
        for segment in value.split(';') {
            let Some((name, token)) = segment.trim_start().split_once('=') else {
                continue;
            };
            if name.trim_end() != REFRESH_COOKIE {
                continue;
            }
            if result.is_some()
                || token.is_empty()
                || token.len() > 2_048
                || !token
                    .bytes()
                    .all(|byte| (0x21..=0x7e).contains(&byte) && !b",;\"\\".contains(&byte))
            {
                return Err(());
            }
            result = Some(token.to_owned());
        }
    }
    Ok(result)
}

pub(crate) fn header_count(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
) -> usize {
    headers.get_all(name).iter().count()
}

pub(crate) fn matching_origin(headers: &HeaderMap, trusted_origin: &str) -> bool {
    header_count(headers, header::ORIGIN) == 1
        && headers
            .get(header::ORIGIN)
            .is_some_and(|value| value.as_bytes() == trusted_origin.as_bytes())
}

#[allow(clippy::too_many_arguments)]
async fn audited_problem(
    state: &AuthState,
    endpoint: DeviceAuthEndpoint,
    source: IpAddr,
    reason: DeviceAuthFailureReason,
    status: StatusCode,
    code: &'static str,
    changed: bool,
    retryable: bool,
    request_id: &str,
    retry_after: Option<u64>,
) -> Response {
    if state.backend.audit_failure(endpoint, reason, source).await.is_err() {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            request_id,
            None,
        );
    }
    problem(status, code, changed, retryable, request_id, retry_after)
}

async fn refresh_problem(
    state: &AuthState,
    source: IpAddr,
    reason: DeviceAuthFailureReason,
    status: StatusCode,
    code: &'static str,
    request_id: &str,
    cors: bool,
) -> Response {
    let mut result = audited_problem(
        state,
        DeviceAuthEndpoint::Refresh,
        source,
        reason,
        status,
        code,
        false,
        status == StatusCode::SERVICE_UNAVAILABLE,
        request_id,
        None,
    )
    .await;
    if cors {
        add_cors(&mut result, &state.trusted_origin);
    }
    result
}

fn business_problem(error: &DeviceAuthenticationError, request_id: &str) -> Response {
    match error {
        DeviceAuthenticationError::Denied { changed } => problem(
            StatusCode::UNAUTHORIZED,
            "auth.authentication_required",
            *changed,
            false,
            request_id,
            None,
        ),
        DeviceAuthenticationError::RateLimited(delay) => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "auth.rate_limited",
            false,
            true,
            request_id,
            Some(*delay),
        ),
        DeviceAuthenticationError::InvalidDpopProof => problem(
            StatusCode::BAD_REQUEST,
            "auth.invalid_dpop_proof",
            false,
            false,
            request_id,
            None,
        ),
        DeviceAuthenticationError::InvalidInput => {
            problem(StatusCode::BAD_REQUEST, "auth.invalid_request", false, false, request_id, None)
        }
        DeviceAuthenticationError::CommitOutcomeUnknown => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.commit_outcome_unknown",
            true,
            false,
            request_id,
            None,
        ),
        _ => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            request_id,
            None,
        ),
    }
}

pub(crate) fn problem(
    status: StatusCode,
    code: &'static str,
    changed: bool,
    retryable: bool,
    request_id: &str,
    retry_after: Option<u64>,
) -> Response {
    let (title, detail) = match code {
        "auth.authentication_required" => (
            "Authentication required",
            "Authentication was denied. Obtain a new challenge before retrying.",
        ),
        "auth.rate_limited" => (
            "Authentication rate limited",
            "Authentication is temporarily limited. Wait for Retry-After before trying again.",
        ),
        "auth.invalid_dpop_proof" => (
            "Invalid DPoP proof",
            "The DPoP proof is invalid. Create a new proof for this request.",
        ),
        "auth.use_dpop_nonce" => {
            ("DPoP nonce required", "Create a new proof with the server nonce.")
        }
        "auth.commit_outcome_unknown" => (
            "Authentication outcome unknown",
            "The server could not confirm whether this credential exchange committed. Reauthenticate with a new challenge; do not replay this request.",
        ),
        "auth.storage_unavailable" => (
            "Authentication unavailable",
            "Authentication storage is unavailable. No credential result can be confirmed.",
        ),
        "policy.denied" => ("Origin denied", "This origin is not permitted for authentication."),
        _ => (
            "Invalid authentication request",
            "The request is invalid. Check its fields and headers.",
        ),
    };
    let details = ProblemDetails::new(
        ErrorCode::new(code).expect("registered authentication code"),
        status.as_u16(),
        title,
        detail,
        request_id,
        changed,
        retryable,
    )
    .expect("valid authentication problem");
    let mut result = response(
        status,
        "application/problem+json",
        serde_json::to_vec(&details).expect("serializable problem"),
    );
    if let Some(delay) = retry_after {
        let headers = AuthRateLimitHeaders::new(u16::try_from(delay).expect("bounded delay"))
            .expect("bounded authentication delay");
        result.headers_mut().insert(
            header::RETRY_AFTER,
            headers.retry_after_seconds().to_string().parse().expect("bounded delay"),
        );
        result.headers_mut().insert(
            "ratelimit-policy",
            headers.rate_limit_policy().parse().expect("static policy"),
        );
        result
            .headers_mut()
            .insert("ratelimit", headers.rate_limit().parse().expect("bounded rate"));
    }
    result
}

pub(crate) fn response(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::from(body))
        .expect("static authentication response headers")
}

pub(crate) fn add_cors(response: &mut Response, origin: &str) {
    let headers = response.headers_mut();
    headers.insert(
        "access-control-allow-origin",
        origin.parse().expect("validated deployment origin"),
    );
    headers.insert("access-control-allow-credentials", "true".parse().expect("static credentials"));
    headers.insert(
        "access-control-expose-headers",
        "DPoP-Nonce".parse().expect("static exposed header"),
    );
    headers.insert(header::VARY, "Origin".parse().expect("static vary"));
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], ()> {
    let bytes = input.as_bytes();
    if bytes.len() != N * 2 {
        return Err(());
    }
    let mut output = [0; N];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        output[index] = (digit(pair[0]).ok_or(())? << 4) | digit(pair[1]).ok_or(())?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    mod diagnostics;

    use super::*;
    use scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE;
    use scoplen_crypto::{
        DeviceAccessToken, DeviceAuthContext, DeviceCertificate, DeviceKemKeyPair, DpopProof,
        DpopTarget, DpopToken, Ed25519SigningKey, P256SigningKey, TrustedDeviceAccessTokenKeys,
    };
    use scoplen_store::RelationalStore;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const ORIGIN: &str = "https://example.com";

    fn account_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[7; 32]).expect("account key")
    }

    fn device_key() -> P256SigningKey {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        P256SigningKey::from_bytes(&scalar).expect("device key")
    }

    fn now_seconds() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("scoplen-auth-http-{}", Uuid::now_v7()));
        std::fs::create_dir(&path).expect("test directory");
        path
    }

    fn key_management(directory: &std::path::Path) -> Arc<LocalKeyFile> {
        let path = directory.join("deployment.key");
        std::fs::write(&path, "09".repeat(32)).expect("test key file");
        Arc::new(LocalKeyFile::load(&path).expect("test KMS"))
    }

    #[cfg(feature = "postgres-integration")]
    async fn postgres_fixture() -> (PostgresStore, sqlx::PgPool, String) {
        let database = std::env::var("SCOPLEN_TEST_DATABASE_URL")
            .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
        let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
        let schema = format!("device_auth_http_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
        let mut url = url::Url::parse(&database).expect("fixture URL");
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let store = PostgresStore::connect(url.as_str()).await.expect("PostgreSQL store");
        (store, pool, schema)
    }

    #[cfg(feature = "postgres-integration")]
    async fn cleanup_postgres(
        store: PostgresStore,
        pool: sqlx::PgPool,
        schema: String,
        server: tokio::task::JoinHandle<()>,
        directory: PathBuf,
    ) {
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        drop(store);
        assert!(
            schema.starts_with("device_auth_http_")
                && schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .expect("remove owned schema");
        pool.close().await;
        crate::test_support::remove_test_directory(directory).await;
    }

    fn certificate(account_id: Uuid, device_id: Uuid) -> Vec<u8> {
        let kem = DeviceKemKeyPair::from_private_bytes(&[3; 32]).expect("KEM");
        DeviceCertificate::issue(
            &account_key(),
            device_id,
            account_id,
            device_key().public_key_sec1(),
            kem.public_key().to_vec(),
            "test device".into(),
            "windows".into(),
            1,
        )
        .expect("certificate")
        .encode()
        .expect("canonical certificate")
    }

    async fn seed_sqlite_identity(store: &SqliteStore) -> (Uuid, Uuid) {
        let account_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let cert = certificate(account_id, device_id);
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES (?, ?, ?, ?)")
            .bind(account_id.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
            .bind([4_u8; 32].as_slice()).bind(1_i64)
            .execute(store.pool()).await.expect("account");
        sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES (?, ?, ?, 1, ?)")
            .bind(device_id.as_bytes().as_slice()).bind(account_id.as_bytes().as_slice())
            .bind(&cert).bind(1_i64).execute(store.pool()).await.expect("device");
        sqlx::query(
            "INSERT INTO sync_account_key_certificates (account_id, certificate) VALUES (?, ?)",
        )
        .bind(account_id.as_bytes().as_slice())
        .bind(&cert)
        .execute(store.pool())
        .await
        .expect("published certificate");
        (account_id, device_id)
    }

    #[cfg(feature = "postgres-integration")]
    async fn seed_postgres_identity(store: &PostgresStore) -> (Uuid, Uuid) {
        let account_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let cert = certificate(account_id, device_id);
        sqlx::query("INSERT INTO identity_accounts (account_id, account_signing_public_key, account_kem_public_key, created_at_ms) VALUES ($1, $2, $3, $4)")
            .bind(account_id.as_bytes().as_slice()).bind(account_key().public_key().as_slice())
            .bind([4_u8; 32].as_slice()).bind(1_i64)
            .execute(store.pool()).await.expect("account");
        sqlx::query("INSERT INTO identity_devices (device_id, account_id, certificate, active, created_at_ms) VALUES ($1, $2, $3, true, $4)")
            .bind(device_id.as_bytes().as_slice()).bind(account_id.as_bytes().as_slice())
            .bind(&cert).bind(1_i64).execute(store.pool()).await.expect("device");
        sqlx::query(
            "INSERT INTO sync_account_key_certificates (account_id, certificate) VALUES ($1, $2)",
        )
        .bind(account_id.as_bytes().as_slice())
        .bind(&cert)
        .execute(store.pool())
        .await
        .expect("published certificate");
        (account_id, device_id)
    }

    struct HttpReply {
        status: u16,
        headers: String,
        body: Vec<u8>,
    }

    impl HttpReply {
        fn body_text(&self) -> &str {
            std::str::from_utf8(&self.body).expect("UTF-8 response")
        }
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim())
        }
        fn problem(&self, status: u16, code: &str, changed: bool) {
            assert_eq!(self.status, status, "{}", self.body_text());
            assert_eq!(self.header("content-type"), Some("application/problem+json"));
            let value: ProblemDetails = serde_json::from_slice(&self.body).expect("typed problem");
            assert_eq!(value.code.as_str(), code);
            assert_eq!(value.changed, changed);
            assert_ne!(value.instance, "");
            assert_eq!(self.header("cache-control"), Some("no-store"));
            assert_eq!(self.header("pragma"), Some("no-cache"));
        }
    }

    async fn http(
        address: SocketAddr,
        method: &str,
        path: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> HttpReply {
        let mut stream = tokio::net::TcpStream::connect(address).await.expect("connect listener");
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
        stream.write_all(request.as_bytes()).await.expect("request headers");
        stream.write_all(body.as_bytes()).await.expect("request body");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.expect("response");
        let boundary =
            bytes.windows(4).position(|window| window == b"\r\n\r\n").expect("HTTP boundary");
        let head = std::str::from_utf8(&bytes[..boundary]).expect("response headers");
        let status = head
            .lines()
            .next()
            .expect("status")
            .split_whitespace()
            .nth(1)
            .expect("status code")
            .parse()
            .expect("numeric status");
        HttpReply { status, headers: head.to_owned(), body: bytes[boundary + 4..].to_vec() }
    }

    fn json_headers() -> [(&'static str, &'static str); 1] {
        [("Content-Type", "application/json")]
    }

    fn signature(device_id: Uuid, nonce: &str) -> String {
        let context = DeviceAuthContext::new(ORIGIN, nonce, device_id).expect("signature context");
        hex(&device_key().sign(&context.signature_input()))
    }

    fn proof() -> String {
        let key = device_key();
        let target = DpopTarget::new("POST", ORIGIN, "/api/v1/auth/refresh").expect("target");
        DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &target,
            DpopToken::Refresh,
            now_seconds(),
            None,
        )
        .expect("DPoP proof")
        .as_str()
        .to_owned()
    }

    async fn cleanup(store: SqliteStore, server: tokio::task::JoinHandle<()>, directory: PathBuf) {
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        drop(store);
        for _ in 0..20 {
            if std::fs::remove_dir_all(&directory).is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("could not remove owned test directory");
    }

    async fn clear_sqlite_cooldowns(store: &SqliteStore) {
        sqlx::query("UPDATE device_auth_admission SET cooldown_until_ms = NULL")
            .execute(store.pool())
            .await
            .expect("advance test cooldowns");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn sqlite_real_http_device_refresh_browser_and_jwks() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = key_management(&directory);
        let (account_id, device_id) = seed_sqlite_identity(&store).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve auth HTTP");
        });

        let jwks = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(jwks.status, 200);
        assert_eq!(jwks.header("cache-control"), Some("no-store"));
        let keys = AuthJwks::from_json(&jwks.body).expect("public JWKS");
        assert_eq!(keys.keys().len(), 1);
        assert!(!jwks.body_text().contains("\"d\""));

        let unknown = Uuid::now_v7();
        let unknown_body =
            AuthChallengeRequest::new(unknown).expect("request").to_json().expect("json");
        let unknown_challenge =
            http(address, "POST", "/api/v1/auth/challenge", &unknown_body, &json_headers()).await;
        assert_eq!(unknown_challenge.status, 200);
        AuthChallengeResponse::from_json(unknown_challenge.body_text()).expect("unknown shape");

        let challenge_body =
            AuthChallengeRequest::new(device_id).expect("request").to_json().expect("json");
        let challenge =
            http(address, "POST", "/api/v1/auth/challenge", &challenge_body, &json_headers()).await;
        assert_eq!(challenge.status, 200);
        let challenge = AuthChallengeResponse::from_json(challenge.body_text()).expect("challenge");
        let signed = AuthDeviceRequest::new(
            device_id,
            &challenge.nonce,
            signature(device_id, &challenge.nonce),
        )
        .expect("device request")
        .to_json()
        .expect("json");
        let issued = http(address, "POST", "/api/v1/auth/device", &signed, &json_headers()).await;
        assert_eq!(issued.status, 200, "{}", issued.body_text());
        let issued = AuthTokenResponse::from_json(issued.body_text()).expect("token response");
        assert_eq!(issued.expires_in, 600);
        assert_eq!(issued.refresh_expires_in, 2_592_000);
        let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
        for key in keys.keys() {
            trusted.insert(key.kid(), key.public_key()).expect("trusted public key");
        }
        let token = DeviceAccessToken::parse(&issued.access_token).expect("JWT");
        let claims = token.verify(&trusted, now_seconds()).expect("signed JWT");
        assert_eq!(claims.claims().sub, account_id);
        assert_eq!(claims.claims().did, device_id);
        assert_eq!(claims.claims().scope, INITIAL_DEVICE_ACCESS_SCOPE);

        let native_body = AuthRefreshRequest::new(&issued.refresh_token)
            .expect("refresh request")
            .to_json()
            .expect("json");
        let native_proof = proof();
        let rotated = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &native_body,
            &[("Content-Type", "application/json"), ("DPoP", &native_proof)],
        )
        .await;
        assert_eq!(rotated.status, 200, "{}", rotated.body_text());
        let rotated = AuthTokenResponse::from_json(rotated.body_text()).expect("rotated token");
        assert_ne!(rotated.refresh_token, issued.refresh_token);
        assert!(rotated.refresh_expires_in <= issued.refresh_expires_in);

        let browser_proof = proof();
        let cookie = format!("{REFRESH_COOKIE}={}", rotated.refresh_token);
        let browser = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            "{}",
            &[
                ("Content-Type", "application/json"),
                ("DPoP", &browser_proof),
                ("Cookie", &cookie),
                ("Origin", ORIGIN),
            ],
        )
        .await;
        assert_eq!(browser.status, 200, "{}", browser.body_text());
        BrowserAuthTokenResponse::from_json(browser.body_text()).expect("browser-safe response");
        assert!(!browser.body_text().contains("refresh_token"));
        assert!(
            browser
                .header("set-cookie")
                .expect("rotated cookie")
                .contains("HttpOnly; Secure; SameSite=Strict; Max-Age=")
        );
        assert_eq!(browser.header("access-control-allow-origin"), Some(ORIGIN));

        let stale_proof = proof();
        let stale = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &native_body,
            &[("Content-Type", "application/json"), ("DPoP", &stale_proof)],
        )
        .await;
        stale.problem(401, "auth.authentication_required", true);
        let revoked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_refresh_families WHERE revoked_at_ms IS NOT NULL",
        )
        .fetch_one(store.pool())
        .await
        .expect("family revocation");
        assert_eq!(revoked, 1);

        let bad = http(address, "POST", "/api/v1/auth/challenge", "{}", &json_headers()).await;
        bad.problem(400, "auth.invalid_request", false);
        cleanup(store, server, directory).await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn sqlite_real_http_rejects_invalid_identity_origin_cookie_and_proof() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = key_management(&directory);
        let (_, device_id) = seed_sqlite_identity(&store).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve auth HTTP");
        });

        let challenge_body =
            AuthChallengeRequest::new(device_id).expect("request").to_json().expect("json");
        let unsupported =
            http(address, "POST", "/api/v1/auth/challenge", &challenge_body, &[]).await;
        unsupported.problem(415, "auth.invalid_request", false);
        let oversized = " ".repeat(MAX_CHALLENGE_REQUEST_BYTES + 1);
        let oversized =
            http(address, "POST", "/api/v1/auth/challenge", &oversized, &json_headers()).await;
        oversized.problem(413, "auth.invalid_request", false);
        let denied_origin = http(
            address,
            "POST",
            "/api/v1/auth/challenge",
            &challenge_body,
            &[("Content-Type", "application/json"), ("Origin", "https://other.example")],
        )
        .await;
        denied_origin.problem(403, "policy.denied", false);
        let challenge =
            http(address, "POST", "/api/v1/auth/challenge", &challenge_body, &json_headers()).await;
        let challenge = AuthChallengeResponse::from_json(challenge.body_text()).expect("challenge");
        let correct = AuthDeviceRequest::new(
            device_id,
            &challenge.nonce,
            signature(device_id, &challenge.nonce),
        )
        .expect("device request")
        .to_json()
        .expect("json");
        let origin_denial = http(
            address,
            "POST",
            "/api/v1/auth/device",
            &correct,
            &[("Content-Type", "application/json"), ("Origin", "https://other.example")],
        )
        .await;
        origin_denial.problem(403, "policy.denied", false);
        let forbidden_proof = http(
            address,
            "POST",
            "/api/v1/auth/device",
            &correct,
            &[("Content-Type", "application/json"), ("DPoP", "unexpected")],
        )
        .await;
        forbidden_proof.problem(400, "auth.invalid_request", false);
        let malformed = http(address, "POST", "/api/v1/auth/device", "{}", &json_headers()).await;
        malformed.problem(400, "auth.invalid_request", false);
        let mut forged = AuthDeviceRequest::from_json(&correct).expect("request");
        let replacement = if forged.signature.starts_with("00") { "01" } else { "00" };
        forged.signature.replace_range(0..2, replacement);
        let forged = forged.to_json().expect("forged JSON");
        let invalid = http(address, "POST", "/api/v1/auth/device", &forged, &json_headers()).await;
        invalid.problem(401, "auth.authentication_required", true);
        clear_sqlite_cooldowns(&store).await;
        let replay = http(address, "POST", "/api/v1/auth/device", &correct, &json_headers()).await;
        replay.problem(401, "auth.authentication_required", false);
        let invalid_problem: ProblemDetails =
            serde_json::from_slice(&invalid.body).expect("invalid problem");
        let replay_problem: ProblemDetails =
            serde_json::from_slice(&replay.body).expect("replay problem");
        assert_eq!(invalid_problem.detail, replay_problem.detail);
        clear_sqlite_cooldowns(&store).await;

        let challenge =
            http(address, "POST", "/api/v1/auth/challenge", &challenge_body, &json_headers()).await;
        let challenge = AuthChallengeResponse::from_json(challenge.body_text()).expect("challenge");
        let request = AuthDeviceRequest::new(
            device_id,
            &challenge.nonce,
            signature(device_id, &challenge.nonce),
        )
        .expect("request")
        .to_json()
        .expect("json");
        let issued = http(address, "POST", "/api/v1/auth/device", &request, &json_headers()).await;
        assert_eq!(issued.status, 200, "{}", issued.body_text());
        let issued = AuthTokenResponse::from_json(issued.body_text()).expect("token response");
        let refresh_body = AuthRefreshRequest::new(&issued.refresh_token)
            .expect("refresh request")
            .to_json()
            .expect("json");
        let cookie = format!("{REFRESH_COOKIE}={}", issued.refresh_token);
        let missing_origin = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            "{}",
            &[("Content-Type", "application/json"), ("DPoP", &proof()), ("Cookie", &cookie)],
        )
        .await;
        missing_origin.problem(403, "policy.denied", false);
        let duplicate_cookie = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            "{}",
            &[
                ("Content-Type", "application/json"),
                ("DPoP", &proof()),
                ("Cookie", &format!("{cookie}; {cookie}")),
                ("Origin", ORIGIN),
            ],
        )
        .await;
        duplicate_cookie.problem(400, "auth.invalid_request", false);
        let both = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &refresh_body,
            &[
                ("Content-Type", "application/json"),
                ("DPoP", &proof()),
                ("Cookie", &cookie),
                ("Origin", ORIGIN),
            ],
        )
        .await;
        both.problem(400, "auth.invalid_request", false);
        let bad_proof = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &refresh_body,
            &[("Content-Type", "application/json"), ("DPoP", "invalid")],
        )
        .await;
        bad_proof.problem(400, "auth.invalid_dpop_proof", false);
        clear_sqlite_cooldowns(&store).await;
        let preflight = http(
            address,
            "OPTIONS",
            "/api/v1/auth/refresh",
            "",
            &[
                ("Origin", ORIGIN),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "content-type, dpop"),
            ],
        )
        .await;
        assert_eq!(preflight.status, 204);
        assert_eq!(preflight.header("access-control-allow-origin"), Some(ORIGIN));
        let valid = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &refresh_body,
            &[("Content-Type", "application/json"), ("DPoP", &proof())],
        )
        .await;
        assert_eq!(valid.status, 200, "{}", valid.body_text());
        store.verify_deployment_audit_chain().await.expect("audit chain").expect("audit head");
        cleanup(store, server, directory).await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn sqlite_real_http_audit_failure_rolls_back_device_and_refresh() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = key_management(&directory);
        let (_, device_id) = seed_sqlite_identity(&store).await;
        sqlx::query("CREATE TABLE auth_http_audit_control (fail_audit INTEGER NOT NULL)")
            .execute(store.pool())
            .await
            .expect("control table");
        sqlx::query("INSERT INTO auth_http_audit_control (fail_audit) VALUES (0)")
            .execute(store.pool())
            .await
            .expect("control row");
        sqlx::query("CREATE TRIGGER auth_http_fail_audit BEFORE INSERT ON deployment_audit_events WHEN (SELECT fail_audit FROM auth_http_audit_control) = 1 BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
            .execute(store.pool()).await.expect("fixed audit trigger");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve auth HTTP");
        });
        let jwks = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(jwks.status, 200, "{}", jwks.body_text());
        let challenge_body =
            AuthChallengeRequest::new(device_id).expect("request").to_json().expect("JSON");
        let challenge =
            http(address, "POST", "/api/v1/auth/challenge", &challenge_body, &json_headers()).await;
        let challenge = AuthChallengeResponse::from_json(challenge.body_text()).expect("challenge");
        let request = AuthDeviceRequest::new(
            device_id,
            &challenge.nonce,
            signature(device_id, &challenge.nonce),
        )
        .expect("device request")
        .to_json()
        .expect("JSON");
        sqlx::query("UPDATE auth_http_audit_control SET fail_audit = 1")
            .execute(store.pool())
            .await
            .expect("enable failure");
        let denied = http(address, "POST", "/api/v1/auth/device", &request, &json_headers()).await;
        denied.problem(503, "auth.storage_unavailable", false);
        assert!(!denied.body_text().contains("access_token"));
        let unconsumed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_auth_challenges WHERE consumed_at_ms IS NULL",
        )
        .fetch_one(store.pool())
        .await
        .expect("challenge rollback");
        assert_eq!(unconsumed, 1);
        let families: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_refresh_families")
            .fetch_one(store.pool())
            .await
            .expect("family rollback");
        assert_eq!(families, 0);
        sqlx::query("UPDATE auth_http_audit_control SET fail_audit = 0")
            .execute(store.pool())
            .await
            .expect("disable failure");
        let issued = http(address, "POST", "/api/v1/auth/device", &request, &json_headers()).await;
        assert_eq!(issued.status, 200, "{}", issued.body_text());
        let issued = AuthTokenResponse::from_json(issued.body_text()).expect("token response");
        let refresh_body = AuthRefreshRequest::new(&issued.refresh_token)
            .expect("refresh request")
            .to_json()
            .expect("JSON");
        sqlx::query("UPDATE auth_http_audit_control SET fail_audit = 1")
            .execute(store.pool())
            .await
            .expect("enable refresh failure");
        let failed_refresh = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &refresh_body,
            &[("Content-Type", "application/json"), ("DPoP", &proof())],
        )
        .await;
        failed_refresh.problem(503, "auth.storage_unavailable", false);
        assert!(!failed_refresh.body_text().contains("access_token"));
        let spent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_refresh_tokens WHERE spent_at_ms IS NOT NULL",
        )
        .fetch_one(store.pool())
        .await
        .expect("rotation rollback");
        assert_eq!(spent, 0);
        let replays: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_dpop_replays")
            .fetch_one(store.pool())
            .await
            .expect("proof rollback");
        assert_eq!(replays, 0);
        sqlx::query("UPDATE auth_http_audit_control SET fail_audit = 0")
            .execute(store.pool())
            .await
            .expect("disable refresh failure");
        let rotated = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &refresh_body,
            &[("Content-Type", "application/json"), ("DPoP", &proof())],
        )
        .await;
        assert_eq!(rotated.status, 200, "{}", rotated.body_text());
        store.verify_deployment_audit_chain().await.expect("audit chain").expect("audit head");
        cleanup(store, server, directory).await;
    }

    #[tokio::test]
    async fn uncertain_commit_problem_preserves_device_recovery_flags() {
        let reply =
            business_problem(&DeviceAuthenticationError::CommitOutcomeUnknown, "request-id");
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(reply.into_body(), 4_096).await.expect("problem body");
        let details: ProblemDetails = serde_json::from_slice(&body).expect("typed problem");
        assert_eq!(details.code.as_str(), "auth.commit_outcome_unknown");
        assert!(details.changed);
        assert!(!details.retryable);
        assert_eq!(details.instance, "request-id");
    }

    #[tokio::test]
    async fn sqlite_real_http_refresh_quota_keeps_cors_and_hides_bucket() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = key_management(&directory);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve auth HTTP");
        });
        let mut limited = None;
        for _ in 0..62 {
            let reply = http(
                address,
                "POST",
                "/api/v1/auth/refresh",
                "{}",
                &[("Content-Type", "application/json"), ("Origin", ORIGIN)],
            )
            .await;
            if reply.status == 429 {
                limited = Some(reply);
                break;
            }
            reply.problem(400, "auth.invalid_dpop_proof", false);
        }
        let limited = limited.expect("source bucket must deny after 30 requests");
        limited.problem(429, "auth.rate_limited", false);
        assert_eq!(limited.header("access-control-allow-origin"), Some(ORIGIN));
        assert_eq!(limited.header("access-control-allow-credentials"), Some("true"));
        assert_eq!(limited.header("ratelimit-policy"), Some("\"authentication\";q=30;w=60"));
        let retry_after = limited.header("retry-after").expect("retry delay");
        let seconds: u64 = retry_after.parse().expect("numeric delay");
        assert!((1..=300).contains(&seconds));
        assert_eq!(
            limited.header("ratelimit"),
            Some(format!("\"authentication\";r=0;t={retry_after}").as_str())
        );
        assert!(!limited.body_text().contains("127.0.0.1"));
        cleanup(store, server, directory).await;
    }

    fn checked_operator_jwks(reply: &HttpReply) -> AuthJwks {
        assert_eq!(reply.status, 200, "{}", reply.body_text());
        assert_eq!(reply.header("content-type"), Some("application/json"));
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        assert!(reply.body.len() <= 4_096);
        let document: serde_json::Value = serde_json::from_slice(&reply.body).expect("JWKS JSON");
        for key in document["keys"].as_array().expect("keys") {
            let mut fields =
                key.as_object().expect("public JWK").keys().map(String::as_str).collect::<Vec<_>>();
            fields.sort_unstable();
            assert_eq!(fields, ["alg", "crv", "kid", "kty", "use", "x"]);
        }
        let keys = AuthJwks::from_json(&reply.body).expect("bounded public JWKS");
        assert!(keys.keys().iter().all(|key| key.kid().starts_with("operator-")));
        assert!(keys.keys().windows(2).all(|pair| pair[0].kid() < pair[1].kid()));
        keys
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn sqlite_real_http_operator_jwks_isolated_rotation_and_failure() {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = key_management(&directory);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve Operator JWKS");
        });
        sqlx::query("CREATE TRIGGER fail_operator_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
            .execute(store.pool()).await.expect("fail audit");
        http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await.problem(
            503,
            "auth.storage_unavailable",
            false,
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_access_token_keys")
            .fetch_one(store.pool())
            .await
            .expect("rolled back key count");
        assert_eq!(count, 0);
        sqlx::query("DROP TRIGGER fail_operator_audit")
            .execute(store.pool())
            .await
            .expect("restore audit");
        let initial = http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await;
        let original = checked_operator_jwks(&initial);
        assert_eq!(original.keys().len(), 1);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_access_token_keys")
            .fetch_one(store.pool())
            .await
            .expect("device key count");
        assert_eq!(count, 0);
        let same = http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await;
        assert_eq!(same.body, initial.body);
        let device = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(device.status, 200);
        let device_keys = AuthJwks::from_json(&device.body).expect("device JWKS");
        assert_eq!(device_keys.keys().len(), 1);
        assert_ne!(device_keys.keys()[0].public_key(), original.keys()[0].public_key());
        assert_eq!(device_keys.keys()[0].kid().len(), 32);
        let old_at = i64::try_from(now_seconds()).expect("clock") * 1_000
            - 30 * 24 * 60 * 60 * 1_000
            - 1_000;
        sqlx::query("UPDATE operator_access_token_keys SET activated_at_ms = ?")
            .bind(old_at)
            .execute(store.pool())
            .await
            .expect("age Operator key");
        sqlx::query("CREATE TRIGGER fail_operator_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
            .execute(store.pool()).await.expect("fail rotation audit");
        http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await.problem(
            503,
            "auth.storage_unavailable",
            false,
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_access_token_keys")
            .fetch_one(store.pool())
            .await
            .expect("rotation rolled back");
        assert_eq!(count, 1);
        sqlx::query("DROP TRIGGER fail_operator_audit")
            .execute(store.pool())
            .await
            .expect("restore rotation audit");
        let rotated = http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await;
        let rotated = checked_operator_jwks(&rotated);
        assert_eq!(rotated.keys().len(), 2);
        assert!(rotated.keys().iter().any(|key| key.kid() == original.keys()[0].kid()));
        sqlx::query("UPDATE operator_access_token_keys SET encrypted_seed = zeroblob(73) WHERE active_slot = 1")
            .execute(store.pool()).await.expect("corrupt Operator envelope");
        http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await.problem(
            503,
            "auth.storage_unavailable",
            false,
        );
        let healthy_device = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(healthy_device.status, 200);
        assert_eq!(healthy_device.body, device.body);
        cleanup(store, server, directory).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_real_http_operator_jwks_isolated_and_fail_closed() {
        let directory = directory();
        let (store, pool, schema) = postgres_fixture().await;
        let kms = key_management(&directory);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Postgres(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve PostgreSQL Operator JWKS");
        });
        let initial = http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await;
        let keys = checked_operator_jwks(&initial);
        assert_eq!(keys.keys().len(), 1);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_access_token_keys")
            .fetch_one(store.pool())
            .await
            .expect("device key count");
        assert_eq!(count, 0, "Operator JWKS must not initialize the device keyring");
        let device = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(device.status, 200);
        let device_keys = AuthJwks::from_json(&device.body).expect("device JWKS");
        assert_eq!(device_keys.keys().len(), 1);
        assert_ne!(keys.keys()[0].public_key(), device_keys.keys()[0].public_key());
        sqlx::query("UPDATE operator_access_token_keys SET encrypted_seed = decode(repeat('00', 73), 'hex') WHERE active_slot = 1")
            .execute(store.pool()).await.expect("corrupt Operator envelope");
        http(address, "GET", "/.well-known/operator-jwks.json", "", &[]).await.problem(
            503,
            "auth.storage_unavailable",
            false,
        );
        let healthy_device = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(healthy_device.status, 200);
        assert_eq!(healthy_device.body, device.body);
        cleanup_postgres(store, pool, schema, server, directory).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_real_http_device_refresh_and_jwks() {
        let directory = directory();
        let kms = key_management(&directory);
        let (store, pool, schema) = postgres_fixture().await;
        let (account_id, device_id) = seed_postgres_identity(&store).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Postgres(Arc::new(store.clone()));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router(ORIGIN.into(), backend, kms)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve PostgreSQL auth HTTP");
        });
        let jwks = http(address, "GET", "/.well-known/jwks.json", "", &[]).await;
        assert_eq!(jwks.status, 200, "{}", jwks.body_text());
        let keys = AuthJwks::from_json(&jwks.body).expect("public JWKS");
        assert_eq!(keys.keys().len(), 1);
        let challenge_body =
            AuthChallengeRequest::new(device_id).expect("request").to_json().expect("JSON");
        let challenge =
            http(address, "POST", "/api/v1/auth/challenge", &challenge_body, &json_headers()).await;
        assert_eq!(challenge.status, 200, "{}", challenge.body_text());
        let challenge = AuthChallengeResponse::from_json(challenge.body_text()).expect("challenge");
        let request = AuthDeviceRequest::new(
            device_id,
            &challenge.nonce,
            signature(device_id, &challenge.nonce),
        )
        .expect("device request")
        .to_json()
        .expect("JSON");
        let issued = http(address, "POST", "/api/v1/auth/device", &request, &json_headers()).await;
        assert_eq!(issued.status, 200, "{}", issued.body_text());
        let issued = AuthTokenResponse::from_json(issued.body_text()).expect("token response");
        let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
        for key in keys.keys() {
            trusted.insert(key.kid(), key.public_key()).expect("trusted key");
        }
        let token = DeviceAccessToken::parse(&issued.access_token).expect("JWT");
        let claims = token.verify(&trusted, now_seconds()).expect("signed JWT");
        assert_eq!(claims.claims().sub, account_id);
        assert_eq!(claims.claims().did, device_id);
        let refresh_body = AuthRefreshRequest::new(&issued.refresh_token)
            .expect("refresh request")
            .to_json()
            .expect("JSON");
        let rotated = http(
            address,
            "POST",
            "/api/v1/auth/refresh",
            &refresh_body,
            &[("Content-Type", "application/json"), ("DPoP", &proof())],
        )
        .await;
        assert_eq!(rotated.status, 200, "{}", rotated.body_text());
        let rotated = AuthTokenResponse::from_json(rotated.body_text()).expect("rotated token");
        assert_ne!(rotated.refresh_token, issued.refresh_token);
        let replay = http(address, "POST", "/api/v1/auth/device", &request, &json_headers()).await;
        replay.problem(401, "auth.authentication_required", false);
        store.verify_deployment_audit_chain().await.expect("audit chain").expect("audit head");
        cleanup_postgres(store, pool, schema, server, directory).await;
    }
}
