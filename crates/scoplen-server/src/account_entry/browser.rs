// SPDX-License-Identifier: AGPL-3.0-only
//! Same-origin Account browser entry with independent, proof-bound opaque credentials.

use std::{net::SocketAddr, sync::Arc, time::Duration};

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
    account_browser::{
        ACCOUNT_BROWSER_REFRESH_COOKIE, AccountBrowserAccessToken, AccountBrowserCodecError,
        AccountBrowserHttpMetadata, AccountBrowserLogoutRequest, AccountBrowserLogoutResponse,
        AccountBrowserOperation, AccountBrowserPasswordLoginRequest,
        AccountBrowserPasswordLoginResponse, AccountBrowserPasswordOptionsRequest,
        AccountBrowserRefreshRequest, AccountBrowserRefreshResponse, AccountBrowserRefreshToken,
    },
    auth::AuthRateLimitHeaders,
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use scoplen_store::{
    account_browser_sessions::{AccountBrowserSessionError, AccountBrowserSessionResponse},
    account_entry_admission::{AccountEntryEndpoint, AccountEntryFailureReason},
    device_authentication::DeviceAuthenticationError,
};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use super::EntryState;
use crate::device_auth::{AuthBackend, header_count, response};

pub(super) fn routes() -> Router<Arc<EntryState>> {
    Router::new()
        .route("/api/v1/auth/accounts/browser/password/options", post(handle).fallback(handle))
        .route("/api/v1/auth/accounts/browser/password/login", post(handle).fallback(handle))
        .route("/api/v1/auth/accounts/browser/refresh", post(handle).fallback(handle))
        .route("/api/v1/auth/accounts/browser/logout", post(handle).fallback(handle))
}

fn endpoint(operation: AccountBrowserOperation) -> AccountEntryEndpoint {
    match operation {
        AccountBrowserOperation::PasswordOptions => AccountEntryEndpoint::PasswordOptions,
        AccountBrowserOperation::PasswordLogin => AccountEntryEndpoint::PasswordLogin,
        AccountBrowserOperation::Refresh => AccountEntryEndpoint::AccountBrowserRefresh,
        AccountBrowserOperation::Logout => AccountEntryEndpoint::AccountBrowserLogout,
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Invalid,
    Media,
    Large,
    Origin,
    Method,
    Proof,
    Authentication(bool),
    Rate(u64),
    Storage,
    Unknown,
    LogoutUnknown,
}

impl From<AccountBrowserCodecError> for Failure {
    fn from(error: AccountBrowserCodecError) -> Self {
        match error {
            AccountBrowserCodecError::TooLarge => Self::Large,
            AccountBrowserCodecError::MediaType => Self::Media,
            AccountBrowserCodecError::OriginDenied => Self::Origin,
            _ => Self::Invalid,
        }
    }
}
impl From<AccountBrowserSessionError> for Failure {
    fn from(error: AccountBrowserSessionError) -> Self {
        match error {
            AccountBrowserSessionError::InvalidRequest => Self::Invalid,
            AccountBrowserSessionError::RequestTooLarge => Self::Large,
            AccountBrowserSessionError::Denied { changed } => Self::Authentication(changed),
            AccountBrowserSessionError::InvalidDpopProof => Self::Proof,
            AccountBrowserSessionError::RateLimited(wait) => Self::Rate(wait),
            AccountBrowserSessionError::StorageUnavailable => Self::Storage,
            AccountBrowserSessionError::CommitOutcomeUnknown => Self::Unknown,
        }
    }
}
impl Failure {
    fn reason(self) -> AccountEntryFailureReason {
        match self {
            Self::Invalid | Self::Media | Self::Large | Self::Method => {
                AccountEntryFailureReason::InvalidRequest
            }
            Self::Origin => AccountEntryFailureReason::OriginDenied,
            Self::Authentication(_) | Self::Proof => {
                AccountEntryFailureReason::AuthenticationDenied
            }
            Self::Rate(_) => AccountEntryFailureReason::RateLimited,
            Self::Storage | Self::Unknown | Self::LogoutUnknown => {
                AccountEntryFailureReason::StorageUnavailable
            }
        }
    }
    #[allow(clippy::too_many_lines)]
    fn problem(self, id: &str) -> Response {
        let (status, code, title, detail) = match self {
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                "Invalid browser request",
                "Check the request fields and headers.",
            ),
            Self::Media => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "auth.invalid_request",
                "Unsupported request media",
                "Send application/json with identity content encoding.",
            ),
            Self::Large => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "auth.invalid_request",
                "Request too large",
                "Reduce the request to its supported limit.",
            ),
            Self::Origin => (
                StatusCode::FORBIDDEN,
                "policy.denied",
                "Origin denied",
                "Use the configured deployment origin.",
            ),
            Self::Method => (
                StatusCode::METHOD_NOT_ALLOWED,
                "auth.invalid_request",
                "Method not allowed",
                "Use POST for browser authentication.",
            ),
            Self::Proof => (
                StatusCode::BAD_REQUEST,
                "auth.invalid_dpop_proof",
                "Invalid browser proof",
                "Create a fresh proof with this browser's original key.",
            ),
            Self::Authentication(_) => (
                StatusCode::UNAUTHORIZED,
                "auth.authentication_required",
                "Sign-in required",
                "Start a fresh password sign-in.",
            ),
            Self::Rate(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "auth.rate_limited",
                "Sign-in rate limited",
                "Wait for Retry-After before trying again.",
            ),
            Self::Storage => (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                "Browser authentication unavailable",
                "The server could not confirm this operation.",
            ),
            Self::Unknown => (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.commit_outcome_unknown",
                "Authentication result unconfirmed",
                "No credentials were returned. Start a fresh password sign-in without replaying this request.",
            ),
            Self::LogoutUnknown => (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.commit_outcome_unknown",
                "Sign out unconfirmed",
                "Keep the original credentials for an explicit fresh-proof confirmation before they expire.",
            ),
        };
        let details = ProblemDetails::new(
            ErrorCode::new(code).expect("registered browser code"),
            status.as_u16(),
            title,
            detail,
            id,
            matches!(self, Self::Unknown | Self::LogoutUnknown | Self::Authentication(true)),
            matches!(self, Self::Rate(_) | Self::Storage | Self::LogoutUnknown),
        )
        .expect("bounded browser problem");
        let mut result = response(
            status,
            "application/problem+json",
            serde_json::to_vec(&details).expect("bounded problem JSON"),
        );
        if let Self::Rate(wait) = self {
            let wait = u16::try_from(wait.clamp(1, 300)).expect("bounded retry delay");
            let rate = AuthRateLimitHeaders::new(wait).expect("bounded retry delay");
            result.headers_mut().insert(
                header::RETRY_AFTER,
                rate.retry_after_seconds().to_string().parse().expect("bounded retry delay"),
            );
            result
                .headers_mut()
                .insert("ratelimit", rate.rate_limit().parse().expect("bounded rate"));
            result.headers_mut().insert(
                "ratelimit-policy",
                rate.rate_limit_policy().parse().expect("static rate policy"),
            );
        }
        if matches!(self, Self::Method) {
            result.headers_mut().insert(header::ALLOW, "POST".parse().expect("static method"));
        }
        result
    }
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Failure> {
    if header_count(headers, name) > 1 {
        return Err(Failure::Invalid);
    }
    headers.get(name).map(|value| value.to_str().map_err(|_| Failure::Invalid)).transpose()
}

fn refresh_cookie(headers: &HeaderMap) -> Result<(Option<&str>, usize, bool), Failure> {
    let mut selected = None;
    let mut count = 0;
    let mut other = false;
    let mut bytes = 0;
    for value in headers.get_all(header::COOKIE) {
        bytes += value.as_bytes().len();
        if bytes > 8192 {
            return Err(Failure::Invalid);
        }
        for cookie in value.to_str().map_err(|_| Failure::Invalid)?.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                return Err(Failure::Invalid);
            };
            if name == ACCOUNT_BROWSER_REFRESH_COOKIE {
                count += 1;
                selected = Some(value);
            }
            if matches!(name, "__Secure-spl-refresh" | "refresh_token") {
                other = true;
            }
        }
    }
    Ok((selected, count, other))
}

fn metadata(
    parts: &axum::http::request::Parts,
    operation: AccountBrowserOperation,
    origin: &str,
) -> Result<(), Failure> {
    let (_, count, other) = if operation == AccountBrowserOperation::Refresh {
        refresh_cookie(&parts.headers)?
    } else {
        (None, 0, false)
    };
    for name in ["content-length", "if-match", "idempotency-key"] {
        let _ = one(&parts.headers, name)?;
    }
    AccountBrowserHttpMetadata {
        content_type: one(&parts.headers, "content-type")?.unwrap_or(""),
        content_encoding: one(&parts.headers, "content-encoding")?,
        origin: one(&parts.headers, "origin")?,
        dpop: one(&parts.headers, "dpop")?,
        authorization: one(&parts.headers, "authorization")?,
        refresh_cookie_count: count,
        has_other_refresh_credentials: other,
        has_query: parts.uri.query().is_some(),
        has_if_match: parts.headers.contains_key(header::IF_MATCH),
        has_idempotency_key: parts.headers.contains_key("idempotency-key"),
    }
    .validate(operation, origin)
    .map_err(Failure::from)
}

async fn audit_failure(
    state: &EntryState,
    source: std::net::IpAddr,
    operation: AccountBrowserOperation,
    kind: Failure,
) -> Failure {
    if state
        .backend
        .audit_account_entry_failure(endpoint(operation), source, kind.reason())
        .await
        .is_ok()
    {
        kind
    } else {
        Failure::Storage
    }
}

#[allow(clippy::too_many_lines)]
async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4().to_string();
    let operation = AccountBrowserOperation::ALL
        .into_iter()
        .find(|value| value.route() == request.uri().path())
        .expect("router-owned browser path");
    let mut result =
        if let Err(kind) = super::source_admission(&state, peer.ip(), endpoint(operation)).await {
            kind.problem(&id)
        } else {
            match execute(&state, peer.ip(), operation, request).await {
                Ok(result) => result,
                Err((kind, audited)) => {
                    let kind = if audited {
                        kind
                    } else {
                        audit_failure(&state, peer.ip(), operation, kind).await
                    };
                    kind.problem(&id)
                }
            }
        };
    result.headers_mut().insert("x-request-id", id.parse().expect("UUID request id"));
    result
}

fn proof_failure(error: &DeviceAuthenticationError) -> Failure {
    match error {
        DeviceAuthenticationError::Denied { .. } => Failure::Proof,
        _ => Failure::Storage,
    }
}

#[allow(clippy::too_many_lines)]
async fn execute(
    state: &EntryState,
    source: std::net::IpAddr,
    operation: AccountBrowserOperation,
    request: Request<Body>,
) -> Result<Response, (Failure, bool)> {
    if request.method() != axum::http::Method::POST {
        return Err((Failure::Method, false));
    }
    let (parts, body) = request.into_parts();
    metadata(&parts, operation, &state.origin).map_err(|kind| (kind, false))?;
    let _permit = state.proof_jobs.try_acquire().map_err(|_| (Failure::Rate(1), false))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let body = timeout_at(deadline, super::secret_body(body, operation.body_limits().0))
        .await
        .map_err(|_| (Failure::Storage, false))?
        .map_err(|kind| {
            (
                match kind {
                    super::Failure::TooLarge => Failure::Large,
                    _ => Failure::Invalid,
                },
                false,
            )
        })?;
    let raw = one(&parts.headers, "dpop")
        .map_err(|kind| (kind, false))?
        .ok_or((Failure::Proof, false))?;
    if matches!(
        operation,
        AccountBrowserOperation::PasswordOptions | AccountBrowserOperation::PasswordLogin
    ) {
        match operation {
            AccountBrowserOperation::PasswordOptions => {
                AccountBrowserPasswordOptionsRequest::from_json(body.as_bytes())
                    .map_err(|error| (error.into(), false))?;
            }
            _ => {
                AccountBrowserPasswordLoginRequest::from_json(body.as_bytes())
                    .map_err(|error| (error.into(), false))?;
            }
        }
        let proof = DpopProof::parse(raw).map_err(|_| (Failure::Proof, false))?;
        let target = DpopTarget::new("POST", &state.origin, operation.route())
            .map_err(|_| (Failure::Storage, false))?;
        let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| (Failure::Storage, false))?;
        let jkt = proof
            .verify_presented_key(&target, DpopToken::Refresh, now, None)
            .map_err(|_| (Failure::Proof, false))?
            .jkt;
        state
            .backend
            .claim_dpop(&proof, &target, DpopToken::Refresh, &jkt)
            .await
            .map_err(|error| (proof_failure(&error), false))?;
        macro_rules! password {
            ($store:expr) => {{
                match operation {
                    AccountBrowserOperation::PasswordOptions => {
                        let options = $store
                            .issue_account_browser_password_options(
                                source,
                                &state.origin,
                                body.as_bytes(),
                                &jkt,
                                state.kms.as_ref(),
                                deadline,
                            )
                            .await
                            .map_err(store_failure)?;
                        Ok(response(
                            StatusCode::OK,
                            "application/json",
                            options.to_json().map_err(|_| (Failure::Storage, false))?,
                        ))
                    }
                    _ => {
                        let session = $store
                            .execute_account_browser_password_login(
                                source,
                                &state.origin,
                                body,
                                &jkt,
                                state.kms.as_ref(),
                                deadline,
                            )
                            .await
                            .map_err(store_failure)?;
                        session_response(session, true)
                    }
                }
            }};
        }
        return match &state.backend {
            AuthBackend::Sqlite(store) => password!(store),
            AuthBackend::Postgres(store) => password!(store),
        };
    }
    if operation == AccountBrowserOperation::Refresh {
        AccountBrowserRefreshRequest::from_json(body.as_bytes())
            .map_err(|error| (error.into(), false))?;
        let (cookie, _, _) = refresh_cookie(&parts.headers).map_err(|kind| (kind, false))?;
        let token = AccountBrowserRefreshToken::parse(
            cookie.ok_or((Failure::Authentication(false), false))?,
        )
        .map_err(|_| (Failure::Authentication(false), false))?;
        let session = match &state.backend {
            AuthBackend::Sqlite(store) => {
                store
                    .refresh_account_browser_session(source, &state.origin, &token, raw, deadline)
                    .await
            }
            AuthBackend::Postgres(store) => {
                store
                    .refresh_account_browser_session(source, &state.origin, &token, raw, deadline)
                    .await
            }
        }
        .map_err(store_failure)?;
        return session_response(session, false);
    }
    AccountBrowserLogoutRequest::from_json(body.as_bytes())
        .map_err(|error| (error.into(), false))?;
    let token = AccountBrowserAccessToken::parse(
        one(&parts.headers, "authorization")
            .map_err(|kind| (kind, false))?
            .and_then(|value| value.strip_prefix("DPoP "))
            .ok_or((Failure::Authentication(false), false))?,
    )
    .map_err(|_| (Failure::Authentication(false), false))?;
    let current = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store.account_browser_logout_eligibility(&token, &state.origin).await
        }
        AuthBackend::Postgres(store) => {
            store.account_browser_logout_eligibility(&token, &state.origin).await
        }
    }
    .map_err(store_failure)?
    .ok_or((Failure::Authentication(false), false))?;
    let proof = DpopProof::parse(raw).map_err(|_| (Failure::Proof, false))?;
    let target = DpopTarget::new("POST", &state.origin, operation.route())
        .map_err(|_| (Failure::Storage, false))?;
    state
        .backend
        .claim_dpop(&proof, &target, DpopToken::Protected(token.as_str()), &current.jkt)
        .await
        .map_err(|error| (proof_failure(&error), false))?;
    match &state.backend {
        AuthBackend::Sqlite(store) => {
            store.logout_account_browser_session(source, &current, deadline).await
        }
        AuthBackend::Postgres(store) => {
            store.logout_account_browser_session(source, &current, deadline).await
        }
    }
    .map_err(|error| match error {
        AccountBrowserSessionError::CommitOutcomeUnknown => (Failure::LogoutUnknown, true),
        other => store_failure(other),
    })?;
    Ok(response(
        StatusCode::OK,
        "application/json",
        AccountBrowserLogoutResponse.to_json().to_vec(),
    ))
}

fn store_failure(error: AccountBrowserSessionError) -> (Failure, bool) {
    let audited = matches!(
        error,
        AccountBrowserSessionError::Denied { .. }
            | AccountBrowserSessionError::InvalidDpopProof
            | AccountBrowserSessionError::RateLimited(_)
            | AccountBrowserSessionError::CommitOutcomeUnknown
    );
    (error.into(), audited)
}

fn session_response(
    session: AccountBrowserSessionResponse,
    initial: bool,
) -> Result<Response, (Failure, bool)> {
    let body = if initial {
        AccountBrowserPasswordLoginResponse(session.browser).to_json()
    } else {
        AccountBrowserRefreshResponse(session.browser).to_json()
    }
    .map_err(|_| (Failure::Storage, false))?;
    let cookie = axum::http::HeaderValue::from_bytes(session.set_cookie.as_bytes())
        .map_err(|_| (Failure::Storage, false))?;
    let mut result = response(StatusCode::OK, "application/json", body);
    result.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(result)
}
