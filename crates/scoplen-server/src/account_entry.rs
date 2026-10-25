// SPDX-License-Identifier: AGPL-3.0-only
//! Native Account entry, with independent durable admission and no browser credentials.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode, header, request::Parts},
    response::Response,
    routing::post,
};
use http_body_util::BodyExt as _;
use scoplen_api::{
    ErrorCode, ProblemDetails,
    account_admission::{
        AccountAdmissionCodecError, AccountEntryHttpMetadata, AccountEntryOperation,
        AccountRequestChallengeRequest, AccountRequestChallengeResponse,
    },
    auth::AuthRateLimitHeaders,
};
use scoplen_crypto::SecretVec;
use scoplen_store::account_entry_admission::{
    AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
    AccountEntryStateError,
};
use scoplen_store::account_registration::{AccountRegistrationError, AccountRegistrationResult};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use uuid::Uuid;
use zeroize::Zeroizing;

mod admission;
mod password;

use crate::{
    AccountSettings, ServerError,
    device_auth::{AuthBackend, header_count, json_body, response},
};

pub(crate) async fn prepare(
    backend: &AuthBackend,
    kms: &dyn scoplen_store::kms::KeyManagementService,
    settings: AccountSettings,
) -> Result<(), ServerError> {
    macro_rules! initialize {
        ($store:expr) => {{
            $store.ensure_account_probe_key(kms).await.map_err(|_| {
                ServerError::Task("Account password probe initialization failed".into())
            })?;
            $store.initialize_account_id_retention(settings.used_account_id_limit).await
                .map_err(|_| ServerError::Task("Account identity retention initialization failed; verify the admitted deployment limit and retained state".into()))?
        }};
    }
    let summary = match backend {
        AuthBackend::Sqlite(store) => initialize!(store),
        AuthBackend::Postgres(store) => initialize!(store),
    };
    warn_retention_pressure(summary);
    Ok(())
}

fn warn_retention_pressure(summary: scoplen_store::account_used_ids::AccountIdRetentionSummary) {
    use scoplen_store::account_used_ids::AccountIdPressure;
    let pressure = match summary.pressure {
        AccountIdPressure::Normal => return,
        AccountIdPressure::Warning => "warning",
        AccountIdPressure::Exhausted => "exhausted",
    };
    tracing::warn!(
        event = "account_id_retention_pressure",
        pressure,
        used = summary.used,
        ceiling = summary.ceiling,
        "Account registration identity capacity"
    );
}

struct EntryState {
    origin: String,
    backend: AuthBackend,
    settings: AccountSettings,
    proof_jobs: Semaphore,
    kms: Arc<scoplen_store::kms::LocalKeyFile>,
}

pub(crate) fn router(
    origin: String,
    backend: AuthBackend,
    settings: AccountSettings,
    kms: Arc<scoplen_store::kms::LocalKeyFile>,
) -> Router {
    routes().with_state(Arc::new(EntryState {
        origin,
        backend,
        settings,
        proof_jobs: Semaphore::new(16),
        kms,
    }))
}

fn routes() -> Router<Arc<EntryState>> {
    Router::new()
        .route("/api/v1/auth/accounts/requests/challenge", post(challenge).fallback(method_denied))
        .route(
            "/api/v1/auth/accounts/register",
            post(register).fallback(registration_method_denied),
        )
        .merge(admission::routes())
        .merge(password::routes())
}

impl AuthBackend {
    async fn execute_account_registration(
        &self,
        source: IpAddr,
        origin: &str,
        settings: AccountSettings,
        body: &[u8],
        deadline: Instant,
    ) -> Result<AccountRegistrationResult, AccountRegistrationError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .execute_account_registration(
                        source,
                        origin,
                        settings.registration_enabled,
                        settings.used_account_id_limit,
                        body,
                        deadline,
                    )
                    .await
            }
            Self::Postgres(store) => {
                store
                    .execute_account_registration(
                        source,
                        origin,
                        settings.registration_enabled,
                        settings.used_account_id_limit,
                        body,
                        deadline,
                    )
                    .await
            }
        }
    }

    async fn warn_account_id_pressure(&self) {
        let result = timeout_at(Instant::now() + Duration::from_secs(5), async {
            match self {
                Self::Sqlite(store) => store.account_id_retention_summary().await,
                Self::Postgres(store) => store.account_id_retention_summary().await,
            }
        })
        .await;
        if let Ok(Ok(summary)) = result {
            warn_retention_pressure(summary);
        } else {
            tracing::warn!(
                event = "account_id_retention_pressure_unavailable",
                "Account registration capacity warning unavailable"
            );
        }
    }

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
    Authentication,
    RegistrationDenied,
    AdmissionConflict,
    Quota,
    Policy,
    CommitUnknown,
}

impl Failure {
    fn reason(self) -> AccountEntryFailureReason {
        match self {
            Self::Invalid | Self::Media | Self::TooLarge | Self::Method => {
                AccountEntryFailureReason::InvalidRequest
            }
            Self::Origin | Self::Policy => AccountEntryFailureReason::OriginDenied,
            Self::Rate(_) => AccountEntryFailureReason::RateLimited,
            Self::Storage | Self::CommitUnknown => AccountEntryFailureReason::StorageUnavailable,
            Self::Authentication
            | Self::RegistrationDenied
            | Self::AdmissionConflict
            | Self::Quota => AccountEntryFailureReason::AuthenticationDenied,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep fixed public problem metadata in one exhaustive match"
    )]
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
            Self::Authentication => (
                StatusCode::UNAUTHORIZED,
                "auth.authentication_required",
                "Account authentication required",
                "Obtain a fresh challenge and verify the retained operation before continuing.",
                false,
            ),
            Self::RegistrationDenied => (
                StatusCode::CONFLICT,
                "auth.registration_denied",
                "Account registration denied",
                "The registration cannot create a new Account. Retain any unresolved original operation.",
                false,
            ),
            Self::AdmissionConflict => (
                StatusCode::CONFLICT,
                "auth.admission_conflict",
                "Account admission state changed",
                "Reconcile the Account state and obtain a fresh login snapshot before preparing another Device.",
                false,
            ),
            Self::Quota => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "auth.quota_exceeded",
                "Account entry capacity exceeded",
                "The deployment cannot retain the requested Account entry operation.",
                false,
            ),
            Self::Policy => (
                StatusCode::FORBIDDEN,
                "policy.denied",
                "Account registration disabled",
                "The deployment is closed to new registrations. Exact historical confirmation remains available.",
                false,
            ),
            Self::CommitUnknown => (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.commit_outcome_unknown",
                "Account result unconfirmed",
                "Retain the original operation and keys. Explicitly confirm that operation with a fresh challenge before continuing.",
                false,
            ),
        };
        let problem = ProblemDetails::new(
            ErrorCode::new(code).expect("registered Account error"),
            status.as_u16(),
            title,
            detail,
            id,
            matches!(self, Self::CommitUnknown),
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

impl From<AccountRegistrationError> for Failure {
    fn from(error: AccountRegistrationError) -> Self {
        match error {
            AccountRegistrationError::InvalidRequest => Self::Invalid,
            AccountRegistrationError::RequestTooLarge => Self::TooLarge,
            AccountRegistrationError::PolicyDenied => Self::Policy,
            AccountRegistrationError::AuthenticationRequired => Self::Authentication,
            AccountRegistrationError::RegistrationDenied => Self::RegistrationDenied,
            AccountRegistrationError::QuotaExceeded => Self::Quota,
            AccountRegistrationError::RateLimited(wait) => Self::Rate(wait),
            AccountRegistrationError::StorageUnavailable => Self::Storage,
            AccountRegistrationError::CommitOutcomeUnknown => Self::CommitUnknown,
        }
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

async fn failure(
    state: &EntryState,
    source: IpAddr,
    endpoint: AccountEntryEndpoint,
    kind: Failure,
    id: &str,
) -> Response {
    if !matches!(
        timeout_at(
            Instant::now() + Duration::from_secs(5),
            state.backend.audit_account_entry_failure(endpoint, source, kind.reason()),
        )
        .await,
        Ok(Ok(()))
    ) {
        return Failure::Storage.problem(id);
    }
    kind.problem(id)
}

async fn source_admission(
    state: &EntryState,
    source: IpAddr,
    endpoint: AccountEntryEndpoint,
) -> Result<(), Failure> {
    match state.backend.admit_account_entry_source(endpoint, source).await {
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
    let endpoint = AccountEntryEndpoint::RequestChallenge;
    if let Err(kind) = source_admission(&state, source, endpoint).await {
        return kind.problem(&id);
    }
    let (parts, body) = request.into_parts();
    if let Err(kind) = metadata(&parts, &state.origin) {
        return failure(&state, source, endpoint, kind, &id).await;
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
            return failure(&state, source, endpoint, kind, &id).await;
        }
    };
    let request = match AccountRequestChallengeRequest::from_json(body.as_bytes()) {
        Ok(value) => value,
        Err(error) => return failure(&state, source, endpoint, error.into(), &id).await,
    };
    match state.backend.issue_account_request_challenge(source, &state.origin, &request).await {
        Ok(issued) => match issued.to_json() {
            Ok(body) => response(StatusCode::OK, "application/json", body),
            Err(_) => failure(&state, source, endpoint, Failure::Storage, &id).await,
        },
        Err(AccountEntryStateError::RateLimited(wait)) => Failure::Rate(wait).problem(&id),
        Err(_) => failure(&state, source, endpoint, Failure::Storage, &id).await,
    }
}

async fn method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    deny_method(&state, peer.ip(), AccountEntryEndpoint::RequestChallenge).await
}

async fn registration_method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    deny_method(&state, peer.ip(), AccountEntryEndpoint::Register).await
}

async fn deny_method(
    state: &EntryState,
    source: IpAddr,
    endpoint: AccountEntryEndpoint,
) -> Response {
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(state, source, endpoint).await {
        return kind.problem(&id);
    }
    failure(state, source, endpoint, Failure::Method, &id).await
}

async fn secret_body(mut body: Body, limit: usize) -> Result<SecretVec, Failure> {
    // A fixed capacity avoids reallocating a buffer that may contain the verifier.
    let mut encoded = Zeroizing::new(Vec::with_capacity(limit));
    while let Some(frame) = body.frame().await {
        let data =
            frame.map_err(|_| Failure::Invalid)?.into_data().map_err(|_| Failure::Invalid)?;
        if encoded.len().checked_add(data.len()).is_none_or(|length| length > limit) {
            return Err(Failure::TooLarge);
        }
        encoded.extend_from_slice(&data);
    }
    Ok(SecretVec::new(std::mem::take(&mut *encoded)))
}

async fn register(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let endpoint = AccountEntryEndpoint::Register;
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(&state, source, endpoint).await {
        return kind.problem(&id);
    }
    let (parts, body) = request.into_parts();
    if let Err(kind) = metadata(&parts, &state.origin) {
        return failure(&state, source, endpoint, kind, &id).await;
    }
    let _permit = match state.proof_jobs.try_acquire() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return failure(&state, source, endpoint, Failure::Rate(1), &id).await;
        }
        Err(tokio::sync::TryAcquireError::Closed) => {
            return failure(&state, source, endpoint, Failure::Storage, &id).await;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let (limit, _) = AccountEntryOperation::Register.body_limits();
    if parts.headers.get(header::CONTENT_LENGTH).is_some_and(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limit as u64)
    }) {
        return failure(&state, source, endpoint, Failure::TooLarge, &id).await;
    }
    let body = match timeout_at(deadline, secret_body(body, limit)).await {
        Ok(Ok(body)) => body,
        Ok(Err(kind)) => return failure(&state, source, endpoint, kind, &id).await,
        Err(_) => return failure(&state, source, endpoint, Failure::Storage, &id).await,
    };
    match state
        .backend
        .execute_account_registration(
            source,
            &state.origin,
            state.settings,
            body.as_bytes(),
            deadline,
        )
        .await
    {
        Ok(AccountRegistrationResult::Created(body)) => {
            state.backend.warn_account_id_pressure().await;
            response(StatusCode::CREATED, "application/json", body)
        }
        Ok(AccountRegistrationResult::Confirmed(body)) => {
            response(StatusCode::OK, "application/json", body)
        }
        Err(error) => {
            if error == AccountRegistrationError::QuotaExceeded {
                state.backend.warn_account_id_pressure().await;
            }
            Failure::from(error).problem(&id)
        }
    }
}

#[cfg(test)]
mod tests;
