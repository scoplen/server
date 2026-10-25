// SPDX-License-Identifier: AGPL-3.0-only
//! Native Account entry, with independent durable admission and no browser credentials.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode, header, request::Parts},
    response::Response,
    routing::post,
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    account_admission::{
        AccountAdmissionCodecError, AccountEntryHttpMetadata, AccountEntryOperation,
        AccountRequestChallengeRequest, AccountRequestChallengeResponse,
    },
    auth::AuthRateLimitHeaders,
};
use scoplen_store::account_entry_admission::{
    AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
    AccountEntryStateError,
};
use uuid::Uuid;

use crate::device_auth::{AuthBackend, header_count, json_body, response};

struct EntryState {
    origin: String,
    backend: AuthBackend,
}

pub(crate) fn router(origin: String, backend: AuthBackend) -> Router {
    Router::new()
        .route("/api/v1/auth/accounts/requests/challenge", post(challenge).fallback(method_denied))
        .with_state(Arc::new(EntryState { origin, backend }))
}

impl AuthBackend {
    async fn admit_account_entry_source(
        &self,
        endpoint: AccountEntryEndpoint,
        source: IpAddr,
    ) -> Result<AccountEntryAdmissionDecision, AccountEntryStateError> {
        match self {
            Self::Sqlite(store) => store.admit_account_entry_source(endpoint, source).await,
            Self::Postgres(store) => store.admit_account_entry_source(endpoint, source).await,
        }
    }

    async fn issue_account_request_challenge(
        &self,
        source: IpAddr,
        origin: &str,
        request: &AccountRequestChallengeRequest,
    ) -> Result<AccountRequestChallengeResponse, AccountEntryStateError> {
        match self {
            Self::Sqlite(store) => {
                store.issue_account_request_challenge(source, origin, request).await
            }
            Self::Postgres(store) => {
                store.issue_account_request_challenge(source, origin, request).await
            }
        }
    }

    async fn audit_account_entry_failure(
        &self,
        endpoint: AccountEntryEndpoint,
        source: IpAddr,
        reason: AccountEntryFailureReason,
    ) -> Result<(), AccountEntryStateError> {
        match self {
            Self::Sqlite(store) => {
                store.audit_account_entry_failure(endpoint, source, reason, &[]).await
            }
            Self::Postgres(store) => {
                store.audit_account_entry_failure(endpoint, source, reason, &[]).await
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Invalid,
    Media,
    TooLarge,
    Origin,
    Method,
    Rate(u64),
    Storage,
}

impl Failure {
    fn reason(self) -> AccountEntryFailureReason {
        match self {
            Self::Invalid | Self::Media | Self::TooLarge | Self::Method => {
                AccountEntryFailureReason::InvalidRequest
            }
            Self::Origin => AccountEntryFailureReason::OriginDenied,
            Self::Rate(_) => AccountEntryFailureReason::RateLimited,
            Self::Storage => AccountEntryFailureReason::StorageUnavailable,
        }
    }

    fn problem(self, id: &str) -> Response {
        let (status, code, title, detail, retryable) = match self {
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                "Invalid Account request",
                "Check the request fields and headers.",
                false,
            ),
            Self::Media => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "auth.invalid_request",
                "Unsupported Account request media",
                "Send application/json with identity content encoding.",
                false,
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "auth.invalid_request",
                "Account request too large",
                "Reduce the request to the supported limit.",
                false,
            ),
            Self::Origin => (
                StatusCode::FORBIDDEN,
                "policy.denied",
                "Account origin denied",
                "Use the configured deployment origin.",
                false,
            ),
            Self::Method => (
                StatusCode::METHOD_NOT_ALLOWED,
                "auth.invalid_request",
                "Account method not allowed",
                "Use POST for this native Account endpoint.",
                false,
            ),
            Self::Rate(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "auth.rate_limited",
                "Account entry rate limited",
                "Wait for Retry-After before trying again.",
                true,
            ),
            Self::Storage => (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                "Account entry unavailable",
                "No Account result can be confirmed. Retain any pending operation before explicitly trying again.",
                true,
            ),
        };
        let problem = ProblemDetails::new(
            ErrorCode::new(code).expect("registered Account error"),
            status.as_u16(),
            title,
            detail,
            id,
            false,
            retryable,
        )
        .expect("bounded Account problem");
        let mut result = response(
            status,
            "application/problem+json",
            serde_json::to_vec(&problem).expect("bounded Account problem JSON"),
        );
        if let Self::Rate(wait) = self {
            let wait = u16::try_from(wait.clamp(1, 300)).expect("bounded retry delay");
            let rate = AuthRateLimitHeaders::new(wait).expect("bounded rate headers");
            let headers = result.headers_mut();
            headers.insert(
                header::RETRY_AFTER,
                rate.retry_after_seconds().to_string().parse().expect("bounded retry delay"),
            );
            headers.insert(
                "ratelimit-policy",
                rate.rate_limit_policy().parse().expect("static rate policy"),
            );
            headers.insert("ratelimit", rate.rate_limit().parse().expect("bounded rate state"));
        }
        if matches!(self, Self::Method) {
            result
                .headers_mut()
                .insert(header::ALLOW, "POST".parse().expect("static allowed method"));
        }
        result
    }
}

impl From<AccountAdmissionCodecError> for Failure {
    fn from(error: AccountAdmissionCodecError) -> Self {
        match error {
            AccountAdmissionCodecError::TooLarge => Self::TooLarge,
            AccountAdmissionCodecError::MediaType => Self::Media,
            AccountAdmissionCodecError::OriginDenied => Self::Origin,
            _ => Self::Invalid,
        }
    }
}

fn metadata(parts: &Parts, origin: &str) -> Result<(), Failure> {
    let headers = &parts.headers;
    if [header::CONTENT_TYPE, header::CONTENT_ENCODING, header::ORIGIN, header::CONTENT_LENGTH]
        .iter()
        .any(|name| header_count(headers, name) > 1)
    {
        return Err(Failure::Invalid);
    }
    let text = |name| {
        headers.get(name).map(|value| value.to_str().map_err(|_| Failure::Invalid)).transpose()
    };
    AccountEntryHttpMetadata {
        content_type: text(header::CONTENT_TYPE)?.unwrap_or(""),
        content_encoding: text(header::CONTENT_ENCODING)?,
        origin: text(header::ORIGIN)?,
        has_query: parts.uri.query().is_some(),
        has_authorization: headers.contains_key(header::AUTHORIZATION),
        has_dpop: headers.contains_key("dpop"),
        has_cookie: headers.contains_key(header::COOKIE),
        has_idempotency_key: headers.contains_key("idempotency-key"),
        has_if_match: headers.contains_key(header::IF_MATCH),
    }
    .validate(origin)
    .map_err(Failure::from)
}

async fn failure(state: &EntryState, source: IpAddr, kind: Failure, id: &str) -> Response {
    if state
        .backend
        .audit_account_entry_failure(AccountEntryEndpoint::RequestChallenge, source, kind.reason())
        .await
        .is_err()
    {
        return Failure::Storage.problem(id);
    }
    kind.problem(id)
}

async fn source_admission(state: &EntryState, source: IpAddr) -> Result<(), Failure> {
    match state
        .backend
        .admit_account_entry_source(AccountEntryEndpoint::RequestChallenge, source)
        .await
    {
        Ok(AccountEntryAdmissionDecision::Admitted) => Ok(()),
        // Durable source rejection already includes its mandatory audit.
        Ok(AccountEntryAdmissionDecision::RateLimited(wait)) => Err(Failure::Rate(wait)),
        Err(_) => Err(Failure::Storage),
    }
}

async fn challenge(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(&state, source).await {
        return kind.problem(&id);
    }
    let (parts, body) = request.into_parts();
    if let Err(kind) = metadata(&parts, &state.origin) {
        return failure(&state, source, kind, &id).await;
    }
    let (limit, _) = AccountEntryOperation::RequestChallenge.body_limits();
    let body = match json_body(&parts.headers, body, limit).await {
        Ok(value) => value,
        Err(status) => {
            let kind = match status {
                StatusCode::PAYLOAD_TOO_LARGE => Failure::TooLarge,
                StatusCode::UNSUPPORTED_MEDIA_TYPE => Failure::Media,
                _ => Failure::Invalid,
            };
            return failure(&state, source, kind, &id).await;
        }
    };
    let request = match AccountRequestChallengeRequest::from_json(body.as_bytes()) {
        Ok(value) => value,
        Err(error) => return failure(&state, source, error.into(), &id).await,
    };
    match state.backend.issue_account_request_challenge(source, &state.origin, &request).await {
        Ok(issued) => match issued.to_json() {
            Ok(body) => response(StatusCode::OK, "application/json", body),
            Err(_) => failure(&state, source, Failure::Storage, &id).await,
        },
        Err(AccountEntryStateError::RateLimited(wait)) => Failure::Rate(wait).problem(&id),
        Err(_) => failure(&state, source, Failure::Storage, &id).await,
    }
}

async fn method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(&state, peer.ip()).await {
        return kind.problem(&id);
    }
    failure(&state, peer.ip(), Failure::Method, &id).await
}

#[cfg(test)]
mod tests;
