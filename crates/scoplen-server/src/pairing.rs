// SPDX-License-Identifier: AGPL-3.0-only
//! Native second-device pairing relay with durable admission and current-device authorization.

use std::{error::Error as _, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, MatchedPath, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::Response,
    routing::{delete, get, post},
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::DeviceAccessOperation,
    pairing::{
        MAX_PAIRING_LARGE_REQUEST_BYTES, MAX_PAIRING_SMALL_BYTES, PairingClaimRequest,
        PairingCodecError, PairingCompleteRequest, PairingCreateRequest, PairingMessageRequest,
        PairingRateLimitHeaders, decode_pairing_authorization, validate_pairing_request_metadata,
    },
};
use scoplen_crypto::SecretBytes;
use scoplen_store::{
    device_authentication::CurrentPrincipal,
    kms::LocalKeyFile,
    pairing::{PairingActor, PairingStoreError},
    pairing_admission::{
        PairingAdmissionDecision, PairingAdmissionError, PairingEndpoint, PairingFailureReason,
        PairingPrivateBucket,
    },
};
use scoplen_sync::http::AuthFailure;
use sha2::{Digest as _, Sha256};
use uuid::{Uuid, Variant};

use crate::{
    device_auth::{AuthBackend, matching_origin, response},
    personal_sync::PersonalSyncAuthenticator,
};

const LANDING: &str = concat!(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>Pair device - Scoplen</title></head><body><main>",
    "<h1>Open this link in Scoplen</h1>",
    "<p>On your existing device, open Scoplen and paste this full link into the pairing dialog.</p>",
    "<p>Keep the part after the # character when copying the link. ",
    "Enter the pairing password only in Scoplen.</p></main></body></html>",
);

macro_rules! store_call {
    ($backend:expr, $method:ident($($arg:expr),* $(,)?)) => {
        match $backend {
            AuthBackend::Sqlite(store) => store.$method($($arg),*).await,
            AuthBackend::Postgres(store) => store.$method($($arg),*).await,
        }
    };
}

struct PairingState {
    backend: AuthBackend,
    auth: PersonalSyncAuthenticator,
    origin: String,
}

pub(crate) fn router(origin: String, backend: AuthBackend, kms: Arc<LocalKeyFile>) -> Router {
    let auth = PersonalSyncAuthenticator::new(backend.clone(), kms, origin.clone());
    Router::new()
        .route("/pair", get(landing).fallback(landing))
        .route("/api/v1/auth/pairings", post(handle))
        .route("/api/v1/auth/pairings/{pairing}", get(handle))
        .route("/api/v1/auth/pairings/{pairing}", delete(handle))
        .route("/api/v1/auth/pairings/{pairing}/claim", post(handle))
        .route("/api/v1/auth/pairings/{pairing}/messages", post(handle))
        .route("/api/v1/auth/pairings/{pairing}/complete", post(handle))
        .method_not_allowed_fallback(handle)
        .with_state(Arc::new(PairingState { backend, auth, origin }))
}

async fn landing(State(state): State<Arc<PairingState>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let failure = if parts.method != Method::GET && parts.method != Method::HEAD {
        Some(Failure::invalid(StatusCode::METHOD_NOT_ALLOWED))
    } else if parts.headers.contains_key(header::ORIGIN)
        && !matching_origin(&parts.headers, &state.origin)
    {
        Some(Failure::origin())
    } else if ["authorization", "dpop", "cookie"]
        .iter()
        .any(|name| parts.headers.contains_key(*name))
        || validate_pairing_request_metadata(
            parts.uri.query(),
            &[],
            false,
            parts.headers.contains_key("idempotency-key"),
            prohibited_cache_header(&parts.headers),
        )
        .is_err()
        || to_bytes(body, 0).await.is_err()
    {
        Some(Failure::invalid(StatusCode::BAD_REQUEST))
    } else {
        None
    };
    let mut result = failure.map_or_else(
        || response(StatusCode::OK, "text/html; charset=utf-8", LANDING.as_bytes().to_vec()),
        |failure| failure.response(PairingEndpoint::Read),
    );
    result.headers_mut().insert(header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'".parse().expect("static pairing landing policy"));
    result.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("static content type policy"),
    );
    result
}

struct Attempt<'a> {
    state: &'a PairingState,
    endpoint: PairingEndpoint,
    source: std::net::IpAddr,
    private: Option<PairingPrivateBucket>,
}

impl Attempt<'_> {
    async fn fail(&self, failure: Failure) -> Response {
        // An attempted business commit must retain its uncertainty even if later audit fails.
        if failure.changed {
            return failure.response(self.endpoint);
        }
        if store_call!(
            &self.state.backend,
            audit_pairing_failure(self.endpoint, failure.reason, self.source, self.private)
        )
        .is_err()
        {
            return Failure::storage().response(self.endpoint);
        }
        failure.response(self.endpoint)
    }

    async fn admission(
        &self,
        decision: Result<PairingAdmissionDecision, PairingAdmissionError>,
    ) -> Option<Response> {
        match decision {
            Ok(PairingAdmissionDecision::Admitted) => None,
            Ok(PairingAdmissionDecision::RateLimited(delay)) => {
                Some(self.fail(Failure::limited(delay)).await)
            }
            Err(_) => Some(self.fail(Failure::storage()).await),
        }
    }

    async fn store_failure(&self, error: PairingStoreError) -> Response {
        let failure = match error {
            PairingStoreError::InvalidRequest => Failure::invalid(StatusCode::BAD_REQUEST),
            PairingStoreError::Denied => Failure::denied(),
            PairingStoreError::AuthenticationDenied => Failure::authentication(),
            PairingStoreError::Conflict => Failure::conflict(),
            PairingStoreError::QuotaExceeded => Failure::quota(),
            PairingStoreError::ResourceLimited => {
                match store_call!(
                    &self.state.backend,
                    pairing_retry_after(self.endpoint, self.source, self.private, 60)
                ) {
                    Ok(delay) => Failure::limited(delay),
                    Err(_) => Failure::storage(),
                }
            }
            PairingStoreError::CommitOutcomeUnknown => Failure::unknown(),
            _ => Failure::storage(),
        };
        self.fail(failure).await
    }
}

enum Decoded {
    Create(PairingCreateRequest),
    Claim,
    Read,
    Message(PairingMessageRequest),
    Complete(PairingCompleteRequest),
    Cancel,
}

impl Decoded {
    fn parse(endpoint: PairingEndpoint, body: &[u8]) -> Result<Self, PairingCodecError> {
        Ok(match endpoint {
            PairingEndpoint::Create => Self::Create(PairingCreateRequest::from_json(body)?),
            PairingEndpoint::Claim => {
                PairingClaimRequest::from_json(body)?;
                Self::Claim
            }
            PairingEndpoint::Read => Self::Read,
            PairingEndpoint::Message => Self::Message(PairingMessageRequest::from_json(body)?),
            PairingEndpoint::Complete => Self::Complete(PairingCompleteRequest::from_json(body)?),
            PairingEndpoint::Cancel => Self::Cancel,
        })
    }
}

enum Role {
    Initiator(CurrentPrincipal),
    Responder(SecretBytes<32>),
}

impl Role {
    fn actor(&self) -> PairingActor<'_> {
        match self {
            Self::Initiator(principal) => PairingActor::Initiator(principal),
            Self::Responder(token) => PairingActor::Responder(token.as_bytes()),
        }
    }

    fn private(&self) -> PairingPrivateBucket {
        match self {
            Self::Initiator(principal) => PairingPrivateBucket::Account(principal.account_id),
            Self::Responder(token) => {
                PairingPrivateBucket::Capability(Sha256::digest(token.as_bytes()).into())
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<PairingState>>,
    matched: MatchedPath,
    request: Request<Body>,
) -> Response {
    let (endpoint, valid_method) = endpoint(matched.as_str(), request.method());
    let mut attempt = Attempt { state: &state, endpoint, source: peer.ip(), private: None };
    let decision = store_call!(&state.backend, admit_pairing_source(endpoint, attempt.source));
    if let Some(response) = attempt.admission(decision).await {
        return response;
    }
    if !valid_method {
        return attempt.fail(Failure::invalid(StatusCode::METHOD_NOT_ALLOWED)).await;
    }
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;
    if headers.contains_key(header::ORIGIN) && !matching_origin(headers, &state.origin) {
        return attempt.fail(Failure::origin()).await;
    }
    if let Err(error) = validate_pairing_request_metadata(
        parts.uri.query(),
        &[],
        true,
        headers.contains_key("idempotency-key"),
        prohibited_cache_header(headers),
    ) {
        return attempt.fail(Failure::codec(&error)).await;
    }
    let pairing = if endpoint == PairingEndpoint::Create {
        if [header::AUTHORIZATION.as_str(), "dpop", header::COOKIE.as_str()]
            .iter()
            .any(|name| headers.contains_key(*name))
        {
            return attempt.fail(Failure::invalid(StatusCode::BAD_REQUEST)).await;
        }
        None
    } else {
        let Some(id) = pairing_id(parts.uri.path()) else {
            return attempt.fail(Failure::invalid(StatusCode::BAD_REQUEST)).await;
        };
        Some(id)
    };
    let permits_body = !matches!(endpoint, PairingEndpoint::Read | PairingEndpoint::Cancel);
    if permits_body && !is_json(headers) {
        return attempt.fail(Failure::invalid(StatusCode::BAD_REQUEST)).await;
    }
    let limit = match endpoint {
        PairingEndpoint::Read | PairingEndpoint::Cancel => 0,
        PairingEndpoint::Create | PairingEndpoint::Claim => MAX_PAIRING_SMALL_BYTES,
        PairingEndpoint::Message | PairingEndpoint::Complete => MAX_PAIRING_LARGE_REQUEST_BYTES,
    };
    let body = match to_bytes(body, limit).await {
        Ok(body) => body,
        Err(error) => {
            let oversized = error
                .source()
                .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>);
            let status = if permits_body && oversized {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return attempt.fail(Failure::invalid(status)).await;
        }
    };
    let decoded = match Decoded::parse(endpoint, &body) {
        Ok(value) => value,
        Err(error) => return attempt.fail(Failure::codec(&error)).await,
    };
    if let Decoded::Create(decoded) = decoded {
        return match store_call!(
            &state.backend,
            create_pairing(&state.origin, &decoded, attempt.source)
        ) {
            Ok(value) => encoded(value.to_json(), StatusCode::CREATED, &attempt),
            Err(error) => attempt.store_failure(error).await,
        };
    }
    let pairing = pairing.expect("session endpoint has canonical id");
    let role = match authenticate(&attempt, pairing, &parts).await {
        Ok(role) => role,
        Err(error) => return attempt.fail(error).await,
    };
    attempt.private = Some(role.private());
    let decision = store_call!(
        &state.backend,
        admit_pairing_private(endpoint, attempt.source, role.private())
    );
    if let Some(response) = attempt.admission(decision).await {
        return response;
    }
    execute(&attempt, pairing, &role, decoded).await
}

async fn authenticate(
    attempt: &Attempt<'_>,
    pairing: Uuid,
    parts: &axum::http::request::Parts,
) -> Result<Role, Failure> {
    let headers = &parts.headers;
    if headers.contains_key(header::COOKIE) {
        return Err(Failure::invalid(StatusCode::BAD_REQUEST));
    }
    let authorization = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok());
    if authorization.is_some_and(|value| value.starts_with("Pairing ")) {
        if headers.contains_key("dpop")
            || headers.get_all(header::AUTHORIZATION).iter().count() != 1
        {
            return Err(Failure::invalid(StatusCode::BAD_REQUEST));
        }
        if matches!(attempt.endpoint, PairingEndpoint::Claim | PairingEndpoint::Complete) {
            return Err(Failure::denied());
        }
        let token = decode_pairing_authorization(authorization.expect("Pairing scheme"))
            .map_err(|_| Failure::denied())?;
        store_call!(
            &attempt.state.backend,
            verify_pairing_responder(&attempt.state.origin, pairing, token.as_bytes())
        )
        .map_err(|error| match error {
            PairingStoreError::Denied => Failure::denied(),
            _ => Failure::storage(),
        })?;
        return Ok(Role::Responder(token));
    }
    let operation = match attempt.endpoint {
        PairingEndpoint::Claim => DeviceAccessOperation::PairingClaim,
        PairingEndpoint::Read => DeviceAccessOperation::PairingRead,
        PairingEndpoint::Message => DeviceAccessOperation::PairingMessage,
        PairingEndpoint::Complete => DeviceAccessOperation::PairingComplete,
        PairingEndpoint::Cancel => DeviceAccessOperation::PairingCancel,
        PairingEndpoint::Create => unreachable!("creation is anonymous"),
    };
    attempt
        .state
        .auth
        .authenticate_operation(operation, &parts.method, &parts.uri, headers)
        .await
        .map(Role::Initiator)
        .map_err(Failure::auth)
}

async fn execute(attempt: &Attempt<'_>, pairing: Uuid, role: &Role, decoded: Decoded) -> Response {
    let origin = &attempt.state.origin;
    let source = attempt.source;
    let result = match decoded {
        Decoded::Claim => {
            let Role::Initiator(principal) = role else { unreachable!("old role checked") };
            store_call!(&attempt.state.backend, claim_pairing(origin, pairing, principal, source))
                .map(|value| value.to_json())
        }
        Decoded::Read => {
            store_call!(&attempt.state.backend, read_pairing(origin, pairing, role.actor(), source))
                .map(|value| value.to_json())
        }
        Decoded::Message(request) => store_call!(
            &attempt.state.backend,
            post_pairing_message(origin, pairing, role.actor(), &request, source)
        )
        .map(|value| value.to_json()),
        Decoded::Complete(request) => {
            let Role::Initiator(principal) = role else { unreachable!("old role checked") };
            store_call!(
                &attempt.state.backend,
                complete_pairing(origin, pairing, principal, &request, source)
            )
            .map(|value| value.to_json())
        }
        Decoded::Cancel => {
            return match store_call!(
                &attempt.state.backend,
                cancel_pairing(origin, pairing, role.actor(), source)
            ) {
                Ok(()) => {
                    let mut result =
                        response(StatusCode::NO_CONTENT, "application/json", Vec::new());
                    result.headers_mut().remove(header::CONTENT_TYPE);
                    result
                }
                Err(error) => attempt.store_failure(error).await,
            };
        }
        Decoded::Create(_) => unreachable!("creation executed separately"),
    };
    match result {
        Ok(body) => encoded(body, StatusCode::OK, attempt),
        Err(error) => attempt.store_failure(error).await,
    }
}

fn encoded(
    body: Result<Vec<u8>, PairingCodecError>,
    status: StatusCode,
    attempt: &Attempt<'_>,
) -> Response {
    match body {
        Ok(body) => response(status, "application/json", body),
        // Store operations validate the exact DTO before committing. Retain a conservative
        // uncertainty response if an internal invariant ever fails after a mutation committed.
        Err(_) if attempt.endpoint == PairingEndpoint::Read => {
            Failure::storage().response(attempt.endpoint)
        }
        Err(_) => Failure::unknown().response(attempt.endpoint),
    }
}

fn endpoint(path: &str, method: &Method) -> (PairingEndpoint, bool) {
    let (endpoint, expected) = match path {
        "/api/v1/auth/pairings" => (PairingEndpoint::Create, Method::POST),
        "/api/v1/auth/pairings/{pairing}/claim" => (PairingEndpoint::Claim, Method::POST),
        "/api/v1/auth/pairings/{pairing}/messages" => (PairingEndpoint::Message, Method::POST),
        "/api/v1/auth/pairings/{pairing}/complete" => (PairingEndpoint::Complete, Method::POST),
        _ if method == Method::DELETE => (PairingEndpoint::Cancel, Method::DELETE),
        _ => (PairingEndpoint::Read, Method::GET),
    };
    (endpoint, method == expected)
}

fn pairing_id(path: &str) -> Option<Uuid> {
    let text = path.strip_prefix("/api/v1/auth/pairings/")?.split('/').next()?;
    let id = Uuid::parse_str(text).ok()?;
    (id.get_version_num() == 7 && id.get_variant() == Variant::RFC4122 && id.to_string() == text)
        .then_some(id)
}

fn prohibited_cache_header(headers: &HeaderMap) -> bool {
    [
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
        "cache-control",
        "pragma",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

fn is_json(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONTENT_TYPE).iter().count() == 1
        && headers.get(header::CONTENT_TYPE).is_some_and(|value| {
            value.to_str().is_ok_and(|value| {
                let mut parts = value.split(';');
                parts
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
                    && parts.all(|part| part.trim().eq_ignore_ascii_case("charset=utf-8"))
            })
        })
}

struct Failure {
    status: StatusCode,
    code: ErrorCode,
    title: String,
    detail: String,
    changed: bool,
    retryable: bool,
    reason: PairingFailureReason,
    delay: Option<u64>,
}

impl Failure {
    fn new(
        status: StatusCode,
        code: &str,
        title: &str,
        detail: &str,
        reason: PairingFailureReason,
    ) -> Self {
        Self {
            status,
            code: ErrorCode::new(code).expect("static pairing error"),
            title: title.into(),
            detail: detail.into(),
            changed: false,
            retryable: false,
            reason,
            delay: None,
        }
    }

    fn invalid(status: StatusCode) -> Self {
        Self::new(
            status,
            "auth.invalid_request",
            "Invalid pairing request",
            "Check the pairing request's fields, size, method and headers. No pairing state changed.",
            PairingFailureReason::InvalidRequest,
        )
    }

    fn codec(error: &PairingCodecError) -> Self {
        Self::invalid(if matches!(error, PairingCodecError::TooLarge(_)) {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        })
    }

    fn origin() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "policy.denied",
            "Pairing origin denied",
            "Use this deployment's configured origin for pairing. No pairing state changed.",
            PairingFailureReason::OriginDenied,
        )
    }

    fn denied() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "auth.pairing_denied",
            "Pairing denied",
            "This credential cannot access the pairing session. No pairing state changed.",
            PairingFailureReason::PairingDenied,
        )
    }

    fn authentication() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "auth.authentication_required",
            "Authentication required",
            "Authenticate this enrolled device and create a fresh DPoP proof for the request.",
            PairingFailureReason::AuthenticationDenied,
        )
    }

    fn conflict() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "auth.pairing_conflict",
            "Pairing conflict",
            "The operation conflicts with the pairing state. Retain the pending identity and check the session before starting a new ceremony.",
            PairingFailureReason::Conflict,
        )
    }

    fn quota() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "sync.quota_exceeded",
            "Account capacity exceeded",
            "The account cannot publish another complete device and key snapshot. No device was admitted.",
            PairingFailureReason::InvalidRequest,
        )
    }

    fn limited(delay: u64) -> Self {
        let mut result = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "auth.rate_limited",
            "Pairing rate limited",
            "Wait for Retry-After before trying again. No pairing state changed.",
            PairingFailureReason::RateLimited,
        );
        result.retryable = true;
        result.delay = Some(delay);
        result
    }

    fn storage() -> Self {
        let mut result = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            "Pairing unavailable",
            "This request changed no pairing state. Retry later with a fresh proof if required.",
            PairingFailureReason::StorageUnavailable,
        );
        result.retryable = true;
        result
    }

    fn unknown() -> Self {
        let mut result = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.commit_outcome_unknown",
            "Pairing outcome unknown",
            "Retain your pending identity and exact request. Check the authenticated session or device admission before deciding what to do next; do not automatically resend or replace the ceremony.",
            PairingFailureReason::StorageUnavailable,
        );
        result.changed = true;
        result
    }

    fn auth(error: AuthFailure) -> Self {
        if error.status.is_server_error() {
            return Self::storage();
        }
        Self {
            status: error.status,
            code: error.code,
            title: error.title,
            detail: error.detail,
            retryable: error.retryable,
            changed: false,
            reason: PairingFailureReason::AuthenticationDenied,
            delay: None,
        }
    }

    fn response(self, endpoint: PairingEndpoint) -> Response {
        let details = ProblemDetails::new(
            self.code,
            self.status.as_u16(),
            self.title,
            self.detail,
            Uuid::new_v4().to_string(),
            self.changed,
            self.retryable,
        )
        .expect("static pairing problem");
        let mut result = response(
            self.status,
            "application/problem+json",
            serde_json::to_vec(&details).expect("serializable pairing problem"),
        );
        if let Some(delay) = self.delay {
            let values = PairingRateLimitHeaders::new(
                u16::try_from(delay).expect("bounded pairing delay"),
                endpoint == PairingEndpoint::Read,
            )
            .expect("bounded pairing admission");
            let headers = result.headers_mut();
            headers.insert(
                header::RETRY_AFTER,
                values.retry_after_seconds().to_string().parse().expect("bounded delay"),
            );
            headers.insert(
                "ratelimit-policy",
                values.rate_limit_policy().parse().expect("static pairing policy"),
            );
            headers.insert("ratelimit", values.rate_limit().parse().expect("bounded pairing rate"));
        }
        result
    }
}
