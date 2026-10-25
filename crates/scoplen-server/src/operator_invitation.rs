// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated deployment-Operator issuance of one-use Personal invitations.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::post,
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::{OperatorAccessOperation, OperatorAccessRequirement},
    personal_enrollment::{
        MAX_PERSONAL_INVITATION_REQUEST_BYTES, PersonalInvitationRequest, PersonalRateLimitHeaders,
    },
};
use scoplen_control::operator_invitation::OperatorInvitationPolicy;
use scoplen_crypto::{
    DeviceAccessToken, DpopProof, DpopTarget, DpopToken, OperatorAccessToken,
    TrustedDeviceAccessTokenKeys, TrustedOperatorAccessTokenKeys, VerifiedOperatorAccessToken,
};
use scoplen_store::{
    IssuedPersonalInvitation, PersonalInvitationStoreError,
    kms::LocalKeyFile,
    operator_admission::OperatorAdmissionError,
    operator_invitations::InvitationFailureReason,
    operator_sessions::CurrentOperatorSession,
    personal_admission::{PersonalAdmissionDecision, PersonalAdmissionError},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::device_auth::AuthBackend;

const ROUTE: &str = "/api/v1/admin/personal-invitations";

impl AuthBackend {
    async fn invitation_source(
        &self,
        source: IpAddr,
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        match self {
            Self::Sqlite(s) => s.admit_personal_invitation_source(source).await,
            Self::Postgres(s) => s.admit_personal_invitation_source(source).await,
        }
    }
    async fn invitation_operator(
        &self,
        id: Uuid,
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        match self {
            Self::Sqlite(s) => s.admit_personal_invitation_operator(id).await,
            Self::Postgres(s) => s.admit_personal_invitation_operator(id).await,
        }
    }
    async fn invitation_failure(
        &self,
        reason: InvitationFailureReason,
    ) -> Result<(), PersonalAdmissionError> {
        match self {
            Self::Sqlite(s) => s.audit_personal_invitation_failure(reason).await,
            Self::Postgres(s) => s.audit_personal_invitation_failure(reason).await,
        }
    }
    async fn invitation_current(
        &self,
        token: &VerifiedOperatorAccessToken,
    ) -> Result<Option<CurrentOperatorSession>, Failure> {
        match self {
            Self::Sqlite(s) => s.current_operator_session(token).await,
            Self::Postgres(s) => s.current_operator_session(token).await,
        }
        .map_err(|_| Failure::Storage)
    }
    async fn invitation_proof(
        &self,
        proof: &DpopProof,
        target: &DpopTarget,
        token: &str,
        jkt: &str,
    ) -> Result<(), Failure> {
        let result = match self {
            Self::Sqlite(s) => {
                s.claim_operator_dpop_proof(proof, target, DpopToken::Protected(token), jkt).await
            }
            Self::Postgres(s) => {
                s.claim_operator_dpop_proof(proof, target, DpopToken::Protected(token), jkt).await
            }
        };
        result.map_err(|e| {
            if matches!(e, OperatorAdmissionError::InvalidDpopProof) {
                Failure::Authentication
            } else {
                Failure::Storage
            }
        })
    }
    async fn issue_invitation(
        &self,
        verified: &VerifiedOperatorAccessToken,
        origin: &str,
    ) -> Result<IssuedPersonalInvitation, PersonalInvitationStoreError> {
        match self {
            Self::Sqlite(s) => s.issue_personal_invitation_for_operator(verified, origin).await,
            Self::Postgres(s) => s.issue_personal_invitation_for_operator(verified, origin).await,
        }
    }
}

struct InvitationState {
    origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
    policy:
        Result<OperatorInvitationPolicy, scoplen_control::operator_invitation::OperatorPolicyError>,
}

pub(crate) fn router(origin: String, backend: AuthBackend, kms: Arc<LocalKeyFile>) -> Router {
    let policy = OperatorInvitationPolicy::new();
    Router::new()
        .route("/api/v1/admin/personal-invitations", post(issue))
        .with_state(Arc::new(InvitationState { origin, backend, kms, policy }))
}

#[derive(Clone, Copy)]
enum Failure {
    Invalid,
    MediaType,
    TooLarge,
    Authentication,
    Policy,
    Origin,
    Rate(u64),
    Storage,
    UnknownCommit,
}

impl Failure {
    fn reason(self) -> InvitationFailureReason {
        match self {
            Self::Invalid | Self::MediaType | Self::TooLarge => {
                InvitationFailureReason::InvalidRequest
            }
            Self::Authentication => InvitationFailureReason::AuthenticationRequired,
            Self::Policy => InvitationFailureReason::PolicyDenied,
            Self::Origin => InvitationFailureReason::OriginDenied,
            Self::Rate(_) => InvitationFailureReason::RateLimited,
            Self::Storage | Self::UnknownCommit => InvitationFailureReason::StorageUnavailable,
        }
    }
}

async fn issue(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<InvitationState>>,
    request: Request<Body>,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    match issue_request(&state, peer.ip(), request).await {
        Ok(body) => response(StatusCode::CREATED, "application/json", body),
        Err(mut failure) => {
            if state.backend.invitation_failure(failure.reason()).await.is_err()
                && !matches!(failure, Failure::UnknownCommit)
            {
                failure = Failure::Storage;
            }
            problem(failure, &request_id)
        }
    }
}

fn admitted(
    result: &Result<PersonalAdmissionDecision, PersonalAdmissionError>,
) -> Result<(), Failure> {
    match result {
        Ok(PersonalAdmissionDecision::Admitted) => Ok(()),
        Ok(PersonalAdmissionDecision::RateLimited(delay)) => Err(Failure::Rate(*delay)),
        Err(_) => Err(Failure::Storage),
    }
}

async fn issue_request(
    state: &InvitationState,
    source: IpAddr,
    request: Request<Body>,
) -> Result<Vec<u8>, Failure> {
    admitted(&state.backend.invitation_source(source).await)?;
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;
    if parts.uri.query().is_some() || headers.contains_key("idempotency-key") {
        return Err(Failure::Invalid);
    }
    if headers.get_all(header::ORIGIN).iter().count() > 1
        || headers
            .get(header::ORIGIN)
            .is_some_and(|value| value.to_str().ok() != Some(state.origin.as_str()))
    {
        return Err(Failure::Origin);
    }
    let media =
        single(headers, header::CONTENT_TYPE.as_str(), 128).map_err(|_| Failure::MediaType)?;
    if !media.eq_ignore_ascii_case("application/json")
        && !media.eq_ignore_ascii_case("application/json; charset=utf-8")
    {
        return Err(Failure::MediaType);
    }
    let verified = authenticate(state, headers).await?;
    let operation = OperatorAccessOperation::PersonalInvitationIssue;
    let OperatorAccessRequirement::Scope(scope) = operation.requirement() else {
        return Err(Failure::Policy);
    };
    if !scope.is_present_in(&verified.claims().scope) {
        return Err(Failure::Policy);
    }
    let current =
        state.backend.invitation_current(&verified).await?.ok_or(Failure::Authentication)?;
    let policy = state.policy.as_ref().map_err(|_| Failure::Storage)?;
    if !policy
        .allows_personal_invitation(current.operator_id, true)
        .map_err(|_| Failure::Storage)?
    {
        return Err(Failure::Policy);
    }
    admitted(&state.backend.invitation_operator(current.operator_id).await)?;
    let encoded =
        to_bytes(body, MAX_PERSONAL_INVITATION_REQUEST_BYTES + 1).await.map_err(|error| {
            let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            while let Some(error) = cause {
                if error.is::<http_body_util::LengthLimitError>() {
                    return Failure::TooLarge;
                }
                cause = error.source();
            }
            Failure::Invalid
        })?;
    if encoded.len() > MAX_PERSONAL_INVITATION_REQUEST_BYTES {
        return Err(Failure::TooLarge);
    }
    PersonalInvitationRequest::from_json(&encoded).map_err(|_| Failure::Invalid)?;
    let issued = state.backend.issue_invitation(&verified, &state.origin).await.map_err(
        |error| match error {
            PersonalInvitationStoreError::Denied => Failure::Authentication,
            PersonalInvitationStoreError::CommitOutcomeUnknown => Failure::UnknownCommit,
            _ => Failure::Storage,
        },
    )?;
    Ok(issued.response_json().to_vec())
}

async fn authenticate(
    state: &InvitationState,
    headers: &HeaderMap,
) -> Result<VerifiedOperatorAccessToken, Failure> {
    let raw = single(headers, header::AUTHORIZATION.as_str(), 4_101)?
        .strip_prefix("DPoP ")
        .ok_or(Failure::Authentication)?;
    let proof =
        DpopProof::parse(single(headers, "dpop", 8_192)?).map_err(|_| Failure::Authentication)?;
    let target = DpopTarget::new("POST", &state.origin, ROUTE).map_err(|_| Failure::Storage)?;
    let now =
        u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| Failure::Storage)?;
    let keys = state.backend.operator_keyring(&state.kms).await.map_err(|_| Failure::Storage)?;
    let mut trusted =
        TrustedOperatorAccessTokenKeys::new(&state.origin).map_err(|_| Failure::Storage)?;
    for key in keys.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).map_err(|_| Failure::Storage)?;
    }
    let verified = OperatorAccessToken::parse(raw).and_then(|token| token.verify(&trusted, now));
    let Ok(verified) = verified else {
        if authenticated_device(state, raw, &proof, &target, now).await? {
            return Err(Failure::Policy);
        }
        return Err(Failure::Authentication);
    };
    state.backend.invitation_proof(&proof, &target, raw, &verified.claims().cnf_jkt).await?;
    Ok(verified)
}

async fn authenticated_device(
    state: &InvitationState,
    raw: &str,
    proof: &DpopProof,
    target: &DpopTarget,
    now: u64,
) -> Result<bool, Failure> {
    let Ok(token) = DeviceAccessToken::parse(raw) else {
        return Ok(false);
    };
    let keys = state.backend.keyring(&state.kms).await.map_err(|_| Failure::Storage)?;
    let mut trusted =
        TrustedDeviceAccessTokenKeys::new(&state.origin).map_err(|_| Failure::Storage)?;
    for key in keys.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).map_err(|_| Failure::Storage)?;
    }
    let Ok(token) = token.verify(&trusted, now) else {
        return Ok(false);
    };
    let claims = token.claims();
    let Some(current) = state
        .backend
        .current_principal(claims.did.into_bytes())
        .await
        .map_err(|_| Failure::Storage)?
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
                Failure::Authentication
            } else {
                Failure::Storage
            }
        })?;
    Ok(true)
}

fn single<'a>(headers: &'a HeaderMap, name: &str, max: usize) -> Result<&'a str, Failure> {
    if headers.get_all(name).iter().count() != 1 {
        return Err(Failure::Authentication);
    }
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= max && value.is_ascii())
        .ok_or(Failure::Authentication)
}

fn response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type.parse().expect("static content type"));
    headers.insert(header::CACHE_CONTROL, "no-store".parse().expect("static header"));
    headers.insert(header::PRAGMA, "no-cache".parse().expect("static header"));
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().expect("static header"));
    response
}

fn problem(failure: Failure, id: &str) -> Response {
    let (status, code, detail, changed, retryable) = match failure {
        Failure::Invalid => (
            StatusCode::BAD_REQUEST,
            "auth.invalid_request",
            "The invitation request is invalid. No invitation was issued. Send exactly an empty JSON object without query or idempotency headers.",
            false,
            false,
        ),
        Failure::MediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "auth.invalid_request",
            "The invitation request must use application/json. No invitation was issued. Correct the content type before trying again.",
            false,
            false,
        ),
        Failure::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "auth.invalid_request",
            "The invitation request exceeds 256 bytes. No invitation was issued. Send an empty JSON object.",
            false,
            false,
        ),
        Failure::Authentication => (
            StatusCode::UNAUTHORIZED,
            "auth.authentication_required",
            "Operator authentication could not be verified. No invitation was issued. Sign in again and send a fresh proof.",
            false,
            false,
        ),
        Failure::Policy | Failure::Origin => (
            StatusCode::FORBIDDEN,
            "policy.denied",
            "This request is not permitted to issue a Personal invitation. No invitation was issued. Use a current Operator session from this deployment.",
            false,
            false,
        ),
        Failure::Rate(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            "auth.rate_limited",
            "Invitation admission is temporarily limited. No invitation was issued. Wait at least Retry-After before explicitly trying again.",
            false,
            true,
        ),
        Failure::Storage => (
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            "The server could not complete the invitation request. No invitation was issued. Try again after storage is available.",
            false,
            true,
        ),
        Failure::UnknownCommit => (
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.commit_outcome_unknown",
            "The server could not confirm whether an invitation was issued. Its one-time URL cannot be recovered. Do not replay this request automatically; explicitly decide whether to issue another invitation.",
            true,
            false,
        ),
    };
    let body = ProblemDetails {
        problem_type: "about:blank".into(),
        title: status.canonical_reason().unwrap_or("Request failed").into(),
        status: status.as_u16(),
        detail: detail.into(),
        instance: id.into(),
        code: ErrorCode::new(code).expect("registered code"),
        changed,
        retryable,
    };
    let mut result = response(
        status,
        "application/problem+json",
        serde_json::to_vec(&body).expect("problem JSON"),
    );
    if let Failure::Rate(delay) = failure {
        let rate = PersonalRateLimitHeaders::new(
            u16::try_from(delay.clamp(1, 300)).expect("bounded delay"),
        )
        .expect("bounded rate");
        result.headers_mut().insert(
            header::RETRY_AFTER,
            rate.retry_after_seconds().to_string().parse().expect("decimal"),
        );
        result.headers_mut().insert("ratelimit", rate.rate_limit().parse().expect("rate"));
        result
            .headers_mut()
            .insert("ratelimit-policy", rate.rate_limit_policy().parse().expect("policy"));
    }
    result
}

#[cfg(test)]
#[path = "operator_invitation_tests.rs"]
mod tests;
