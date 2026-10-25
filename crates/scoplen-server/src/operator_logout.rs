// SPDX-License-Identifier: AGPL-3.0-only
//! Current Operator-family termination without refresh-cookie authentication or mutation.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::post,
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::AuthRateLimitHeaders,
    operator_auth::{
        MAX_OPERATOR_LOGOUT_REQUEST_BYTES, OperatorLogoutRequest, OperatorLogoutResponse,
    },
};
use scoplen_crypto::{
    DeviceAccessToken, DpopProof, DpopTarget, DpopToken, OperatorAccessToken,
    TrustedDeviceAccessTokenKeys, TrustedOperatorAccessTokenKeys, VerifiedOperatorAccessToken,
};
use scoplen_store::{
    kms::LocalKeyFile,
    operator_admission::{
        OperatorAdmissionDecision, OperatorAdmissionError, OperatorAuthEndpoint,
        OperatorAuthFailureReason,
    },
    operator_sessions::OperatorSessionError,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::device_auth::{AuthBackend, header_count, json_body, matching_origin, response};

const ROUTE: &str = "/api/v1/auth/operator/logout";

struct LogoutState {
    origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
}

pub(crate) fn router(origin: String, backend: AuthBackend, kms: Arc<LocalKeyFile>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/operator/logout",
            post(logout).options(preflight).fallback(method_denied),
        )
        .with_state(Arc::new(LogoutState { origin, backend, kms }))
}

#[derive(Clone, Copy)]
enum Kind {
    Method,
    Invalid,
    Media,
    TooLarge,
    Authentication,
    Proof,
    Policy,
    Rate(u64),
    Storage,
    Unknown,
}

#[derive(Clone, Copy)]
struct Failure {
    kind: Kind,
    // Store denials/rate failures already include their audit; an uncertain commit stays uncertain.
    audited: bool,
}

impl From<Kind> for Failure {
    fn from(kind: Kind) -> Self {
        Self { kind, audited: false }
    }
}

impl Kind {
    fn reason(self) -> OperatorAuthFailureReason {
        match self {
            Self::Method | Self::Invalid | Self::Media | Self::TooLarge => {
                OperatorAuthFailureReason::InvalidRequest
            }
            Self::Authentication => OperatorAuthFailureReason::AuthenticationDenied,
            Self::Proof => OperatorAuthFailureReason::InvalidDpopProof,
            Self::Policy => OperatorAuthFailureReason::OriginDenied,
            Self::Rate(_) => OperatorAuthFailureReason::RateLimited,
            Self::Storage | Self::Unknown => OperatorAuthFailureReason::StorageUnavailable,
        }
    }
}

async fn logout(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<LogoutState>>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4().to_string();
    let cors = matching_origin(request.headers(), &state.origin);
    let mut result = match terminate(&state, peer.ip(), request).await {
        Ok(body) => response(StatusCode::OK, "application/json", body),
        Err(mut failure) => {
            if !failure.audited {
                let audited = match &state.backend {
                    AuthBackend::Sqlite(store) => {
                        store
                            .audit_operator_auth_failure(
                                OperatorAuthEndpoint::Logout,
                                failure.kind.reason(),
                                peer.ip(),
                                None,
                            )
                            .await
                    }
                    AuthBackend::Postgres(store) => {
                        store
                            .audit_operator_auth_failure(
                                OperatorAuthEndpoint::Logout,
                                failure.kind.reason(),
                                peer.ip(),
                                None,
                            )
                            .await
                    }
                };
                if audited.is_err() {
                    failure.kind = Kind::Storage;
                }
            }
            problem(failure.kind, &id)
        }
    };
    if cors {
        add_cors(&mut result, &state.origin);
    }
    result
}

async fn terminate(
    state: &LogoutState,
    source: IpAddr,
    request: Request<Body>,
) -> Result<Vec<u8>, Failure> {
    let admission = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store.admit_operator_auth_source(OperatorAuthEndpoint::Logout, source).await
        }
        AuthBackend::Postgres(store) => {
            store.admit_operator_auth_source(OperatorAuthEndpoint::Logout, source).await
        }
    };
    match admission {
        Ok(OperatorAdmissionDecision::Admitted) => {}
        Ok(OperatorAdmissionDecision::RateLimited(delay)) => return Err(Kind::Rate(delay).into()),
        Err(_) => return Err(Failure { kind: Kind::Storage, audited: true }),
    }
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some() || parts.headers.contains_key("idempotency-key") {
        return Err(Kind::Invalid.into());
    }
    if !matching_origin(&parts.headers, &state.origin) {
        return Err(Kind::Policy.into());
    }
    let media = single(&parts.headers, header::CONTENT_TYPE.as_str(), 128).ok_or(Kind::Media)?;
    let mut media = media.split(';');
    if !media.next().is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json"))
        || media.next().is_some_and(|part| !part.trim().eq_ignore_ascii_case("charset=utf-8"))
        || media.next().is_some()
    {
        return Err(Kind::Media.into());
    }
    let body = json_body(&parts.headers, body, MAX_OPERATOR_LOGOUT_REQUEST_BYTES).await.map_err(
        |status| match status {
            StatusCode::PAYLOAD_TOO_LARGE => Kind::TooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Kind::Media,
            _ => Kind::Invalid,
        },
    )?;
    OperatorLogoutRequest::from_json(body.as_bytes()).map_err(|_| Kind::Invalid)?;
    let confirmation = OperatorLogoutResponse.to_json().map_err(|_| Kind::Storage)?;
    let verified = authenticate(state, &parts.headers).await?;
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => store.logout_operator(source, &verified, &state.origin).await,
        AuthBackend::Postgres(store) => {
            store.logout_operator(source, &verified, &state.origin).await
        }
    };
    match result {
        Ok(_) => Ok(confirmation),
        Err(OperatorSessionError::Denied { .. }) => {
            Err(Failure { kind: Kind::Authentication, audited: true })
        }
        Err(OperatorSessionError::RateLimited(delay)) => {
            Err(Failure { kind: Kind::Rate(delay), audited: true })
        }
        Err(OperatorSessionError::CommitOutcomeUnknown) => {
            Err(Failure { kind: Kind::Unknown, audited: true })
        }
        Err(OperatorSessionError::InvalidDpopProof) => Err(Kind::Proof.into()),
        Err(OperatorSessionError::InvalidInput) => Err(Kind::Invalid.into()),
        Err(_) => Err(Kind::Storage.into()),
    }
}

async fn authenticate(
    state: &LogoutState,
    headers: &HeaderMap,
) -> Result<VerifiedOperatorAccessToken, Failure> {
    let raw = single(headers, header::AUTHORIZATION.as_str(), 4_101)
        .and_then(|value| value.strip_prefix("DPoP "))
        .ok_or(Kind::Authentication)?;
    let proof = DpopProof::parse(single(headers, "dpop", 8_192).ok_or(Kind::Proof)?)
        .map_err(|_| Kind::Proof)?;
    let target = DpopTarget::new("POST", &state.origin, ROUTE).map_err(|_| Kind::Storage)?;
    let now =
        u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| Kind::Storage)?;
    let keys = state.backend.operator_keyring(&state.kms).await.map_err(|_| Kind::Storage)?;
    let mut trusted =
        TrustedOperatorAccessTokenKeys::new(&state.origin).map_err(|_| Kind::Storage)?;
    for key in keys.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).map_err(|_| Kind::Storage)?;
    }
    let verified = OperatorAccessToken::parse(raw).and_then(|token| token.verify(&trusted, now));
    let Ok(verified) = verified else {
        if authenticated_device(state, raw, &proof, &target, now).await? {
            return Err(Kind::Policy.into());
        }
        return Err(Kind::Authentication.into());
    };
    let claimed = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store
                .claim_operator_dpop_proof(
                    &proof,
                    &target,
                    DpopToken::Protected(raw),
                    &verified.claims().cnf_jkt,
                )
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .claim_operator_dpop_proof(
                    &proof,
                    &target,
                    DpopToken::Protected(raw),
                    &verified.claims().cnf_jkt,
                )
                .await
        }
    };
    claimed.map_err(|error| {
        if matches!(error, OperatorAdmissionError::InvalidDpopProof) {
            Kind::Proof
        } else {
            Kind::Storage
        }
    })?;
    Ok(verified)
}

async fn authenticated_device(
    state: &LogoutState,
    raw: &str,
    proof: &DpopProof,
    target: &DpopTarget,
    now: u64,
) -> Result<bool, Failure> {
    let Ok(token) = DeviceAccessToken::parse(raw) else { return Ok(false) };
    let keys = state.backend.keyring(&state.kms).await.map_err(|_| Kind::Storage)?;
    let mut trusted =
        TrustedDeviceAccessTokenKeys::new(&state.origin).map_err(|_| Kind::Storage)?;
    for key in keys.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).map_err(|_| Kind::Storage)?;
    }
    let Ok(token) = token.verify(&trusted, now) else { return Ok(false) };
    let claims = token.claims();
    let Some(current) = state
        .backend
        .current_principal(claims.did.into_bytes())
        .await
        .map_err(|_| Kind::Storage)?
    else {
        return Ok(false);
    };
    if current.account_id != claims.sub.into_bytes() || current.jkt != claims.cnf_jkt {
        return Ok(false);
    }
    state
        .backend
        .claim_dpop(proof, target, DpopToken::Protected(raw), &claims.cnf_jkt)
        .await
        .map_err(|error| {
            if matches!(
                error,
                scoplen_store::device_authentication::DeviceAuthenticationError::InvalidDpopProof
            ) {
                Kind::Proof
            } else {
                Kind::Storage
            }
        })?;
    Ok(true)
}

fn single<'a>(headers: &'a HeaderMap, name: &str, maximum: usize) -> Option<&'a str> {
    if header_count(headers, name) != 1 {
        return None;
    }
    headers
        .get(name)?
        .to_str()
        .ok()
        .filter(|value| !value.is_empty() && value.len() <= maximum && value.is_ascii())
}

fn add_cors(result: &mut Response, origin: &str) {
    result
        .headers_mut()
        .insert("access-control-allow-origin", origin.parse().expect("trusted origin"));
    result.headers_mut().insert(header::VARY, "Origin".parse().expect("static header"));
    result.headers_mut().insert(
        "access-control-expose-headers",
        "Retry-After, RateLimit, RateLimit-Policy".parse().expect("static header"),
    );
}

async fn preflight(State(state): State<Arc<LogoutState>>, request: Request<Body>) -> Response {
    let headers = request.headers();
    let allowed = single(headers, "access-control-request-headers", 256).is_some_and(|value| {
        value.split(',').all(|name| {
            matches!(
                name.trim().to_ascii_lowercase().as_str(),
                "authorization" | "dpop" | "content-type"
            )
        })
    });
    if request.uri().query().is_some()
        || !matching_origin(headers, &state.origin)
        || single(headers, "access-control-request-method", 16) != Some("POST")
        || !allowed
    {
        return problem(Kind::Policy, &Uuid::new_v4().to_string());
    }
    let mut result = response(StatusCode::NO_CONTENT, "application/json", Vec::new());
    add_cors(&mut result, &state.origin);
    result
        .headers_mut()
        .insert("access-control-allow-methods", "POST".parse().expect("static method"));
    result.headers_mut().insert(
        "access-control-allow-headers",
        "Authorization, DPoP, Content-Type".parse().expect("static headers"),
    );
    result
}

async fn method_denied() -> Response {
    let mut result = problem(Kind::Method, &Uuid::new_v4().to_string());
    result.headers_mut().insert(header::ALLOW, "POST, OPTIONS".parse().expect("static methods"));
    result
}

#[allow(clippy::too_many_lines)]
fn problem(kind: Kind, id: &str) -> Response {
    let (status, code, detail, changed, retryable) = match kind {
        Kind::Method => (
            405,
            "auth.invalid_request",
            "Sign out requires POST. This request revoked no session. Use the documented method.",
            false,
            false,
        ),
        Kind::Invalid => (
            400,
            "auth.invalid_request",
            "The sign-out request is invalid. No session was revoked by this request. Send only an empty JSON object without query parameters or an Idempotency-Key.",
            false,
            false,
        ),
        Kind::Media => (
            415,
            "auth.invalid_request",
            "The sign-out request must use application/json. No session was revoked by this request. Correct the content type.",
            false,
            false,
        ),
        Kind::TooLarge => (
            413,
            "auth.invalid_request",
            "The sign-out request exceeds 256 bytes. No session was revoked by this request. Send an empty JSON object.",
            false,
            false,
        ),
        Kind::Authentication => (
            401,
            "auth.authentication_required",
            "The current Operator session could not be verified. This request revoked no session and does not confirm any earlier attempt. Keep the unresolved outcome; an expired token cannot retry and another sign-in cannot confirm the old session.",
            false,
            false,
        ),
        Kind::Proof => (
            400,
            "auth.invalid_dpop_proof",
            "The sign-out proof could not be verified. This request revoked no session. Check the browser clock and explicitly send a fresh proof while the retained access token is valid.",
            false,
            false,
        ),
        Kind::Policy => (
            403,
            "policy.denied",
            "This sign-out request is not permitted. No session was revoked by this request. Use the configured deployment origin and a current Operator session.",
            false,
            false,
        ),
        Kind::Rate(_) => (
            429,
            "auth.rate_limited",
            "Sign-out admission is temporarily limited. This request revoked no session. Keep the credentials and wait at least Retry-After before an explicit fresh-proof attempt.",
            false,
            true,
        ),
        Kind::Storage => (
            503,
            "auth.storage_unavailable",
            "The server could not complete sign out. This request revoked no session. Keep the credentials and explicitly retry with a fresh proof while the access token is valid.",
            false,
            true,
        ),
        Kind::Unknown => (
            503,
            "auth.commit_outcome_unknown",
            "The server could not confirm whether this session was revoked. Keep the credentials; explicitly retry sign out with the retained unexpired access token and a fresh proof. Do not refresh or replay automatically. Another sign-in cannot confirm this session's outcome.",
            true,
            true,
        ),
    };
    let details = ProblemDetails::new(
        ErrorCode::new(code).expect("registered code"),
        status,
        "Operator sign out was not confirmed",
        detail,
        id,
        changed,
        retryable,
    )
    .expect("bounded logout problem");
    let mut result = response(
        StatusCode::from_u16(status).expect("static status"),
        "application/problem+json",
        serde_json::to_vec(&details).expect("problem JSON"),
    );
    if let Kind::Rate(delay) = kind {
        let rate =
            AuthRateLimitHeaders::new(u16::try_from(delay.clamp(1, 300)).expect("bounded delay"))
                .expect("bounded rate");
        result.headers_mut().insert(
            header::RETRY_AFTER,
            rate.retry_after_seconds().to_string().parse().expect("decimal delay"),
        );
        result.headers_mut().insert("ratelimit", rate.rate_limit().parse().expect("rate"));
        result
            .headers_mut()
            .insert("ratelimit-policy", rate.rate_limit_policy().parse().expect("policy"));
    }
    result
}
