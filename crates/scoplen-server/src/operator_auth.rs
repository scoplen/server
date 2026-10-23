// SPDX-License-Identifier: AGPL-3.0-only
//! Origin-bound first-Operator registration through the production authentication router.

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
use scoplen_api::operator_auth::{
    MAX_OPERATOR_OPTIONS_REQUEST_BYTES, MAX_OPERATOR_SETUP_FINISH_BYTES,
    OperatorSetupFinishRequest, OperatorSetupFinishResponse, OperatorSetupOptionsRequest,
    OperatorSetupOptionsResponse,
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use scoplen_identity::operator_passkeys::OperatorPasskeyVerifier;
use scoplen_store::{
    operator_admission::{
        OperatorAdmissionDecision, OperatorAdmissionError, OperatorAuthEndpoint,
        OperatorAuthFailureReason, OperatorPrivateBucket,
    },
    operator_setup::{OperatorRegistration, OperatorSetupError, OperatorSetupOptions},
};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::device_auth::{
    AuthBackend, header_count, json_body, matching_origin, problem, refresh_cookie, response,
};

const OPTIONS_PATH: &str = "/api/v1/auth/operator/setup/options";
const FINISH_PATH: &str = "/api/v1/auth/operator/setup/finish";

struct OperatorAuthState {
    origin: String,
    backend: AuthBackend,
}

pub(crate) fn router(origin: String, backend: AuthBackend) -> Router {
    Router::new()
        .route("/api/v1/auth/operator/setup/options", post(setup_options))
        .route("/api/v1/auth/operator/setup/finish", post(setup_finish))
        .with_state(Arc::new(OperatorAuthState { origin, backend }))
}

struct Attempt<'a> {
    state: &'a OperatorAuthState,
    source: IpAddr,
    endpoint: OperatorAuthEndpoint,
    request_id: String,
    digest: Option<[u8; 32]>,
}

impl Attempt<'_> {
    fn private(&self) -> Option<OperatorPrivateBucket<'_>> {
        self.digest.as_ref().map(OperatorPrivateBucket::SetupDigest)
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
    async fn proof(&self, headers: &axum::http::HeaderMap, path: &str) -> Result<String, Response> {
        let verified = (|| {
            if header_count(headers, "dpop") != 1 {
                return None;
            }
            let raw = headers.get("dpop")?.to_str().ok()?;
            if raw.len() > 8_192 || !raw.is_ascii() {
                return None;
            }
            let proof = DpopProof::parse(raw).ok()?;
            let target = DpopTarget::new("POST", &self.state.origin, path).ok()?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            let verified =
                proof.verify_presented_key(&target, DpopToken::Refresh, now, None).ok()?;
            Some((proof, target, verified.jkt))
        })();
        let Some((proof, target, jkt)) = verified else {
            return Err(self
                .denied(
                    OperatorAuthFailureReason::InvalidDpopProof,
                    StatusCode::BAD_REQUEST,
                    "auth.invalid_dpop_proof",
                    None,
                )
                .await);
        };
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
    setup(&state, peer.ip(), OperatorAuthEndpoint::SetupOptions, request).await
}

async fn setup_finish(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<OperatorAuthState>>,
    request: Request<Body>,
) -> Response {
    setup(&state, peer.ip(), OperatorAuthEndpoint::SetupFinish, request).await
}

enum SetupRequest {
    Options(OperatorSetupOptionsRequest),
    Finish(OperatorSetupFinishRequest),
}

impl SetupRequest {
    fn token(&self) -> &[u8; 32] {
        match self {
            Self::Options(value) => &value.setup_token,
            Self::Finish(value) => &value.setup_token,
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn setup(
    state: &OperatorAuthState,
    source: IpAddr,
    endpoint: OperatorAuthEndpoint,
    request: Request<Body>,
) -> Response {
    let mut attempt =
        Attempt { state, source, endpoint, request_id: Uuid::new_v4().to_string(), digest: None };
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
    let (path, limit) = if endpoint == OperatorAuthEndpoint::SetupOptions {
        (OPTIONS_PATH, MAX_OPERATOR_OPTIONS_REQUEST_BYTES)
    } else {
        (FINISH_PATH, MAX_OPERATOR_SETUP_FINISH_BYTES)
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
    let decoded = if endpoint == OperatorAuthEndpoint::SetupOptions {
        OperatorSetupOptionsRequest::from_json(body.as_bytes()).map(SetupRequest::Options)
    } else {
        OperatorSetupFinishRequest::from_json(body.as_bytes()).map(SetupRequest::Finish)
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
    attempt.digest = Some(Sha256::digest(decoded.token()).into());
    let private = attempt.private().expect("decoded setup digest");
    let admitted = match &state.backend {
        AuthBackend::Sqlite(store) => store.admit_operator_auth_private(endpoint, private).await,
        AuthBackend::Postgres(store) => store.admit_operator_auth_private(endpoint, private).await,
    };
    if let Err(response) = attempt.admission(admitted).await {
        return response;
    }
    let Ok(verifier) = OperatorPasskeyVerifier::new(&state.origin) else {
        return attempt.unavailable();
    };
    match decoded {
        SetupRequest::Options(decoded) => {
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
        SetupRequest::Finish(decoded) => {
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
    }
}

fn encode_options(options: &OperatorSetupOptions) -> Option<Vec<u8>> {
    let expires_at =
        OffsetDateTime::from_unix_timestamp(options.expires_at_s).ok()?.format(&Rfc3339).ok()?;
    let candidate = serde_json::to_vec(&serde_json::json!({ "ceremony_id": options.ceremony_id, "expires_at": expires_at, "public_key": options.public_key })).ok()?;
    OperatorSetupOptionsResponse::from_json(&candidate).ok()?.to_json().ok()
}

#[cfg(test)]
#[path = "operator_auth_tests.rs"]
mod tests;
