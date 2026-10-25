// SPDX-License-Identifier: AGPL-3.0-only
//! Origin-bound Operator passkeys and cookie-only browser refresh.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::post,
};
use scoplen_api::{
    auth::{BrowserAuthRefreshRequest, MAX_REFRESH_REQUEST_BYTES},
    operator_auth::{
        MAX_OPERATOR_LOGIN_FINISH_BYTES, MAX_OPERATOR_OPTIONS_REQUEST_BYTES,
        MAX_OPERATOR_SETUP_FINISH_BYTES, OperatorLoginFinishRequest, OperatorLoginOptionsRequest,
        OperatorLoginOptionsResponse, OperatorSetupFinishRequest, OperatorSetupFinishResponse,
        OperatorSetupOptionsRequest, OperatorSetupOptionsResponse,
    },
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use scoplen_identity::operator_passkeys::{AssertionArtifacts, OperatorPasskeyVerifier};
use scoplen_store::{
    kms::LocalKeyFile,
    operator_admission::{
        OperatorAdmissionDecision, OperatorAdmissionError, OperatorAuthEndpoint,
        OperatorAuthFailureReason, OperatorPrivateBucket,
    },
    operator_sessions::{
        OperatorAuthentication, OperatorLoginOptions, OperatorSessionError, OperatorSessionResponse,
    },
    operator_setup::{OperatorRegistration, OperatorSetupError, OperatorSetupOptions},
    operator_token_keys::OperatorTokenKeyring,
};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::device_auth::{
    AuthBackend, header_count, json_body, matching_origin, problem, refresh_cookie, response,
};

const OPTIONS_PATH: &str = "/api/v1/auth/operator/setup/options";
const FINISH_PATH: &str = "/api/v1/auth/operator/setup/finish";
const LOGIN_OPTIONS_PATH: &str = "/api/v1/auth/operator/login/options";
const LOGIN_FINISH_PATH: &str = "/api/v1/auth/operator/login/finish";
const REFRESH_PATH: &str = "/api/v1/auth/refresh";

struct OperatorAuthState {
    origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
}

pub(crate) fn router(origin: String, backend: AuthBackend, kms: Arc<LocalKeyFile>) -> Router {
    Router::new()
        .route("/api/v1/auth/operator/setup/options", post(setup_options))
        .route("/api/v1/auth/operator/setup/finish", post(setup_finish))
        .route("/api/v1/auth/operator/login/options", post(login_options))
        .route("/api/v1/auth/operator/login/finish", post(login_finish))
        .with_state(Arc::new(OperatorAuthState { origin, backend, kms }))
}

struct Attempt<'a> {
    state: &'a OperatorAuthState,
    source: IpAddr,
    endpoint: OperatorAuthEndpoint,
    request_id: String,
    digest: Option<[u8; 32]>,
    ceremony_id: Option<Uuid>,
}

impl Attempt<'_> {
    #[allow(clippy::result_large_err)]
    async fn keyring(&self) -> Result<OperatorTokenKeyring, Response> {
        match self.state.backend.operator_keyring(&self.state.kms).await {
            Ok(keyring) => Ok(keyring),
            Err(_) => Err(self
                .denied(
                    OperatorAuthFailureReason::StorageUnavailable,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth.storage_unavailable",
                    None,
                )
                .await),
        }
    }

    async fn session_error(&self, error: OperatorSessionError) -> Response {
        let (reason, status, code) = match error {
            OperatorSessionError::Denied { changed } => {
                return problem(
                    StatusCode::UNAUTHORIZED,
                    "auth.authentication_required",
                    changed,
                    false,
                    &self.request_id,
                    None,
                );
            }
            OperatorSessionError::RateLimited(delay) => {
                return problem(
                    StatusCode::TOO_MANY_REQUESTS,
                    "auth.rate_limited",
                    false,
                    true,
                    &self.request_id,
                    Some(delay),
                );
            }
            OperatorSessionError::CommitOutcomeUnknown => return unknown_session(&self.request_id),
            OperatorSessionError::InvalidDpopProof => (
                OperatorAuthFailureReason::InvalidDpopProof,
                StatusCode::BAD_REQUEST,
                "auth.invalid_dpop_proof",
            ),
            OperatorSessionError::InvalidInput => (
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
            ),
            _ => (
                OperatorAuthFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
            ),
        };
        self.denied(reason, status, code, None).await
    }

    fn private(&self) -> Option<OperatorPrivateBucket<'_>> {
        self.digest
            .as_ref()
            .map(OperatorPrivateBucket::SetupDigest)
            .or_else(|| self.ceremony_id.map(OperatorPrivateBucket::Ceremony))
    }

    async fn denied(
        &self,
        reason: OperatorAuthFailureReason,
        status: StatusCode,
        code: &'static str,
        delay: Option<u64>,
    ) -> Response {
        let result = match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                store
                    .audit_operator_auth_failure(self.endpoint, reason, self.source, self.private())
                    .await
            }
            AuthBackend::Postgres(store) => {
                store
                    .audit_operator_auth_failure(self.endpoint, reason, self.source, self.private())
                    .await
            }
        };
        if result.is_err() {
            return self.unavailable();
        }
        problem(
            status,
            code,
            false,
            matches!(status, StatusCode::SERVICE_UNAVAILABLE | StatusCode::TOO_MANY_REQUESTS),
            &self.request_id,
            delay,
        )
    }

    fn unavailable(&self) -> Response {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            false,
            true,
            &self.request_id,
            None,
        )
    }

    #[allow(clippy::result_large_err)]
    async fn admission(
        &self,
        decision: Result<OperatorAdmissionDecision, OperatorAdmissionError>,
    ) -> Result<(), Response> {
        match decision {
            Ok(OperatorAdmissionDecision::Admitted) => Ok(()),
            Ok(OperatorAdmissionDecision::RateLimited(delay)) => Err(self
                .denied(
                    OperatorAuthFailureReason::RateLimited,
                    StatusCode::TOO_MANY_REQUESTS,
                    "auth.rate_limited",
                    Some(delay),
                )
                .await),
            Err(_) => Err(self.unavailable()),
        }
    }

    async fn setup_error(&self, error: OperatorSetupError) -> Response {
        let (reason, status, code) = match error {
            OperatorSetupError::Denied { consumed: true } => {
                return problem(
                    StatusCode::UNAUTHORIZED,
                    "auth.authentication_required",
                    true,
                    false,
                    &self.request_id,
                    None,
                );
            }
            OperatorSetupError::CommitOutcomeUnknown => {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth.commit_outcome_unknown",
                    true,
                    false,
                    &self.request_id,
                    None,
                );
            }
            OperatorSetupError::Denied { consumed: false } => (
                OperatorAuthFailureReason::AuthenticationDenied,
                StatusCode::UNAUTHORIZED,
                "auth.authentication_required",
            ),
            OperatorSetupError::WrongKey => (
                OperatorAuthFailureReason::InvalidDpopProof,
                StatusCode::BAD_REQUEST,
                "auth.invalid_dpop_proof",
            ),
            OperatorSetupError::InvalidRequest => (
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
            ),
            _ => (
                OperatorAuthFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
            ),
        };
        self.denied(reason, status, code, None).await
    }

    #[allow(clippy::result_large_err)]
    async fn presented_proof(
        &self,
        headers: &axum::http::HeaderMap,
        path: &str,
    ) -> Result<(DpopProof, DpopTarget, String), Response> {
        let target =
            DpopTarget::new("POST", &self.state.origin, path).map_err(|_| self.unavailable())?;
        let now =
            SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| self.unavailable())?.as_secs();
        let verified = (|| {
            if header_count(headers, "dpop") != 1 {
                return None;
            }
            let raw = headers.get("dpop")?.to_str().ok()?;
            if raw.len() > 8_192 || !raw.is_ascii() {
                return None;
            }
            let proof = DpopProof::parse(raw).ok()?;
            let verified =
                proof.verify_presented_key(&target, DpopToken::Refresh, now, None).ok()?;
            Some((proof, target, verified.jkt))
        })();
        let Some(verified) = verified else {
            return Err(self
                .denied(
                    OperatorAuthFailureReason::InvalidDpopProof,
                    StatusCode::BAD_REQUEST,
                    "auth.invalid_dpop_proof",
                    None,
                )
                .await);
        };
        Ok(verified)
    }

    #[allow(clippy::result_large_err)]
    async fn proof(&self, headers: &axum::http::HeaderMap, path: &str) -> Result<String, Response> {
        let (proof, target, jkt) = self.presented_proof(headers, path).await?;
        let claim = match &self.state.backend {
            AuthBackend::Sqlite(store) => {
                store.claim_operator_dpop_proof(&proof, &target, DpopToken::Refresh, &jkt).await
            }
            AuthBackend::Postgres(store) => {
                store.claim_operator_dpop_proof(&proof, &target, DpopToken::Refresh, &jkt).await
            }
        };
        match claim {
            Ok(()) => Ok(jkt),
            Err(OperatorAdmissionError::InvalidDpopProof) => Err(self
                .denied(
                    OperatorAuthFailureReason::InvalidDpopProof,
                    StatusCode::BAD_REQUEST,
                    "auth.invalid_dpop_proof",
                    None,
                )
                .await),
            Err(_) => Err(self.unavailable()),
        }
    }
}

async fn setup_options(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<OperatorAuthState>>,
    request: Request<Body>,
) -> Response {
    ceremony(&state, peer.ip(), OperatorAuthEndpoint::SetupOptions, request).await
}

async fn setup_finish(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<OperatorAuthState>>,
    request: Request<Body>,
) -> Response {
    ceremony(&state, peer.ip(), OperatorAuthEndpoint::SetupFinish, request).await
}

async fn login_options(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<OperatorAuthState>>,
    request: Request<Body>,
) -> Response {
    ceremony(&state, peer.ip(), OperatorAuthEndpoint::LoginOptions, request).await
}

async fn login_finish(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<OperatorAuthState>>,
    request: Request<Body>,
) -> Response {
    ceremony(&state, peer.ip(), OperatorAuthEndpoint::LoginFinish, request).await
}

enum CeremonyRequest {
    Options(OperatorSetupOptionsRequest),
    Finish(OperatorSetupFinishRequest),
    LoginOptions(OperatorLoginOptionsRequest),
    LoginFinish(OperatorLoginFinishRequest),
}

impl CeremonyRequest {
    fn token(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Options(value) => Some(&value.setup_token),
            Self::Finish(value) => Some(&value.setup_token),
            Self::LoginOptions(_) | Self::LoginFinish(_) => None,
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn ceremony(
    state: &OperatorAuthState,
    source: IpAddr,
    endpoint: OperatorAuthEndpoint,
    request: Request<Body>,
) -> Response {
    let mut attempt = Attempt {
        state,
        source,
        endpoint,
        request_id: Uuid::new_v4().to_string(),
        digest: None,
        ceremony_id: None,
    };
    let admitted = match &state.backend {
        AuthBackend::Sqlite(store) => store.admit_operator_auth_source(endpoint, source).await,
        AuthBackend::Postgres(store) => store.admit_operator_auth_source(endpoint, source).await,
    };
    if let Err(response) = attempt.admission(admitted).await {
        return response;
    }
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some()
        || parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key("idempotency-key")
        || matches!(refresh_cookie(&parts.headers), Err(()) | Ok(Some(_)))
    {
        return attempt
            .denied(
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                None,
            )
            .await;
    }
    if !matching_origin(&parts.headers, &state.origin) {
        return attempt
            .denied(
                OperatorAuthFailureReason::OriginDenied,
                StatusCode::FORBIDDEN,
                "policy.denied",
                None,
            )
            .await;
    }
    let (path, limit) = match endpoint {
        OperatorAuthEndpoint::SetupOptions => (OPTIONS_PATH, MAX_OPERATOR_OPTIONS_REQUEST_BYTES),
        OperatorAuthEndpoint::SetupFinish => (FINISH_PATH, MAX_OPERATOR_SETUP_FINISH_BYTES),
        OperatorAuthEndpoint::LoginOptions => {
            (LOGIN_OPTIONS_PATH, MAX_OPERATOR_OPTIONS_REQUEST_BYTES)
        }
        OperatorAuthEndpoint::LoginFinish => (LOGIN_FINISH_PATH, MAX_OPERATOR_LOGIN_FINISH_BYTES),
        OperatorAuthEndpoint::Refresh | OperatorAuthEndpoint::Logout => {
            unreachable!("session operations are not passkey ceremonies")
        }
    };
    let body = match json_body(&parts.headers, body, limit).await {
        Ok(body) => body,
        Err(status) => {
            return attempt
                .denied(
                    OperatorAuthFailureReason::InvalidRequest,
                    status,
                    "auth.invalid_request",
                    None,
                )
                .await;
        }
    };
    let decoded = match endpoint {
        OperatorAuthEndpoint::SetupOptions => {
            OperatorSetupOptionsRequest::from_json(body.as_bytes()).map(CeremonyRequest::Options)
        }
        OperatorAuthEndpoint::SetupFinish => {
            OperatorSetupFinishRequest::from_json(body.as_bytes()).map(CeremonyRequest::Finish)
        }
        OperatorAuthEndpoint::LoginOptions => {
            OperatorLoginOptionsRequest::from_json(body.as_bytes())
                .map(CeremonyRequest::LoginOptions)
        }
        OperatorAuthEndpoint::LoginFinish => {
            OperatorLoginFinishRequest::from_json(body.as_bytes()).map(CeremonyRequest::LoginFinish)
        }
        OperatorAuthEndpoint::Refresh | OperatorAuthEndpoint::Logout => {
            unreachable!("session operations are not passkey ceremonies")
        }
    };
    let Ok(decoded) = decoded else {
        return attempt
            .denied(
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                None,
            )
            .await;
    };
    let jkt = match attempt.proof(&parts.headers, path).await {
        Ok(jkt) => jkt,
        Err(response) => return response,
    };
    attempt.digest = decoded.token().map(|token| Sha256::digest(token).into());
    if let CeremonyRequest::LoginFinish(input) = &decoded {
        attempt.ceremony_id = Some(input.ceremony_id);
    }
    if let Some(private) = attempt.private() {
        let admitted = match &state.backend {
            AuthBackend::Sqlite(store) => {
                store.admit_operator_auth_private(endpoint, private).await
            }
            AuthBackend::Postgres(store) => {
                store.admit_operator_auth_private(endpoint, private).await
            }
        };
        if let Err(response) = attempt.admission(admitted).await {
            return response;
        }
    }
    let Ok(verifier) = OperatorPasskeyVerifier::new(&state.origin) else {
        return attempt.unavailable();
    };
    match decoded {
        CeremonyRequest::Options(decoded) => {
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => {
                    store.operator_setup_options(&decoded.setup_token, &jkt, &verifier).await
                }
                AuthBackend::Postgres(store) => {
                    store.operator_setup_options(&decoded.setup_token, &jkt, &verifier).await
                }
            };
            match result {
                Ok(options) => match encode_options(&options) {
                    Some(body) => response(StatusCode::OK, "application/json", body),
                    None => attempt.unavailable(),
                },
                Err(error) => attempt.setup_error(error).await,
            }
        }
        CeremonyRequest::Finish(decoded) => {
            let input = OperatorRegistration {
                source,
                setup_token: &decoded.setup_token,
                ceremony_id: decoded.ceremony_id,
                browser_jkt: &jkt,
                credential_id: &decoded.credential_id,
                client_data_json: &decoded.client_data_json,
                attestation_object: &decoded.attestation_object,
            };
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => store.finish_operator_setup(&input, &verifier).await,
                AuthBackend::Postgres(store) => {
                    store.finish_operator_setup(&input, &verifier).await
                }
            };
            match result {
                Ok(operator_id) => match (OperatorSetupFinishResponse { operator_id }).to_json() {
                    Ok(body) => response(StatusCode::CREATED, "application/json", body),
                    Err(_) => problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "auth.commit_outcome_unknown",
                        true,
                        false,
                        &attempt.request_id,
                        None,
                    ),
                },
                Err(error) => attempt.setup_error(error).await,
            }
        }
        CeremonyRequest::LoginOptions(_) => {
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => store.operator_login_options(&jkt, &verifier).await,
                AuthBackend::Postgres(store) => store.operator_login_options(&jkt, &verifier).await,
            };
            match result {
                Ok(options) => match encode_login_options(&options) {
                    Some(body) => response(StatusCode::OK, "application/json", body),
                    None => attempt.unavailable(),
                },
                Err(error) => attempt.session_error(error).await,
            }
        }
        CeremonyRequest::LoginFinish(decoded) => {
            let keyring = match attempt.keyring().await {
                Ok(value) => value,
                Err(response) => return response,
            };
            let input = OperatorAuthentication {
                source,
                ceremony_id: decoded.ceremony_id,
                browser_jkt: &jkt,
                artifacts: AssertionArtifacts {
                    credential_id: &decoded.credential_id,
                    client_data: &decoded.client_data_json,
                    authenticator_data: &decoded.authenticator_data,
                    signature: &decoded.signature,
                    user_handle: &decoded.user_handle,
                },
            };
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => {
                    store.finish_operator_login(&input, &verifier, &keyring).await
                }
                AuthBackend::Postgres(store) => {
                    store.finish_operator_login(&input, &verifier, &keyring).await
                }
            };
            match result {
                Ok(session) => session_response(&session, &attempt.request_id),
                Err(error) => attempt.session_error(error).await,
            }
        }
    }
}

fn encode_options(options: &OperatorSetupOptions) -> Option<Vec<u8>> {
    let expires_at =
        OffsetDateTime::from_unix_timestamp(options.expires_at_s).ok()?.format(&Rfc3339).ok()?;
    let candidate = serde_json::to_vec(&serde_json::json!({ "ceremony_id": options.ceremony_id, "expires_at": expires_at, "public_key": options.public_key })).ok()?;
    OperatorSetupOptionsResponse::from_json(&candidate).ok()?.to_json().ok()
}

fn encode_login_options(options: &OperatorLoginOptions) -> Option<Vec<u8>> {
    let expires_at =
        OffsetDateTime::from_unix_timestamp(options.expires_at_s).ok()?.format(&Rfc3339).ok()?;
    let candidate = serde_json::to_vec(&serde_json::json!({ "ceremony_id": options.ceremony_id, "expires_at": expires_at, "public_key": options.public_key })).ok()?;
    OperatorLoginOptionsResponse::from_json(&candidate).ok()?.to_json().ok()
}

fn unknown_session(request_id: &str) -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "auth.commit_outcome_unknown",
        true,
        false,
        request_id,
        None,
    )
}

fn session_response(session: &OperatorSessionResponse, request_id: &str) -> Response {
    let (Ok(body), Ok(cookie)) =
        (session.browser().to_json(), session.set_cookie().parse::<axum::http::HeaderValue>())
    else {
        return unknown_session(request_id);
    };
    let mut result = response(StatusCode::OK, "application/json", body.into_bytes());
    result.headers_mut().insert(header::SET_COOKIE, cookie);
    result
}

/// This selects an internal verifier profile, never an authenticated identity. Operator
/// credentials contain 32 random bytes in unpadded base64url; device credentials use hex.
pub(crate) fn operator_refresh_candidate(headers: &axum::http::HeaderMap) -> bool {
    refresh_cookie(headers).ok().flatten().is_some_and(|token| token.len() == 43)
}

pub(crate) async fn refresh_operator(
    origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
    source: IpAddr,
    request: Request<Body>,
) -> Response {
    let cors = matching_origin(request.headers(), &origin);
    let state = OperatorAuthState { origin, backend, kms };
    let mut result = refresh_browser(&state, source, request).await;
    if cors {
        crate::device_auth::add_cors(&mut result, &state.origin);
    }
    result
}

#[allow(clippy::too_many_lines)]
async fn refresh_browser(
    state: &OperatorAuthState,
    source: IpAddr,
    request: Request<Body>,
) -> Response {
    let attempt = Attempt {
        state,
        source,
        endpoint: OperatorAuthEndpoint::Refresh,
        request_id: Uuid::new_v4().to_string(),
        digest: None,
        ceremony_id: None,
    };
    let admitted = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store.admit_operator_auth_source(attempt.endpoint, source).await
        }
        AuthBackend::Postgres(store) => {
            store.admit_operator_auth_source(attempt.endpoint, source).await
        }
    };
    if let Err(response) = attempt.admission(admitted).await {
        return response;
    }
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some()
        || parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key("idempotency-key")
    {
        return attempt
            .denied(
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                None,
            )
            .await;
    }
    if !matching_origin(&parts.headers, &state.origin) {
        return attempt
            .denied(
                OperatorAuthFailureReason::OriginDenied,
                StatusCode::FORBIDDEN,
                "policy.denied",
                None,
            )
            .await;
    }
    let Ok(Some(token)) = refresh_cookie(&parts.headers) else {
        return attempt
            .denied(
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                None,
            )
            .await;
    };
    let body = match json_body(&parts.headers, body, MAX_REFRESH_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(status) => {
            return attempt
                .denied(
                    OperatorAuthFailureReason::InvalidRequest,
                    status,
                    "auth.invalid_request",
                    None,
                )
                .await;
        }
    };
    if BrowserAuthRefreshRequest::from_json(&body).is_err() {
        return attempt
            .denied(
                OperatorAuthFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                None,
            )
            .await;
    }
    let proof = match attempt.presented_proof(&parts.headers, REFRESH_PATH).await {
        Ok((proof, _, _)) => proof,
        Err(response) => return response,
    };
    let keyring = match attempt.keyring().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store.refresh_operator(source, &state.origin, &token, proof.as_str(), &keyring).await
        }
        AuthBackend::Postgres(store) => {
            store.refresh_operator(source, &state.origin, &token, proof.as_str(), &keyring).await
        }
    };
    match result {
        Ok(session) => session_response(&session, &attempt.request_id),
        Err(error) => attempt.session_error(error).await,
    }
}

#[cfg(test)]
#[path = "operator_auth_tests.rs"]
mod tests;
