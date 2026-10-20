// SPDX-License-Identifier: AGPL-3.0-only
//! Public first-device Personal enrollment, with no authenticated-session side effect.

use std::{
    error::Error as _,
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
    personal_enrollment::{
        MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES, PersonalEnrollmentCodecError,
        PersonalEnrollmentRequest, PersonalEnrollmentResponse, PersonalRateLimitHeaders,
    },
};
use scoplen_identity::{PersonalEnrollmentVerificationError, verify_personal_enrollment};
use scoplen_store::personal_admission::{
    PersonalAdmissionDecision, PersonalAdmissionError, PersonalEnrollmentFailureReason,
};
use scoplen_store::{PersonalInvitationStoreError, PostgresStore, SqliteStore};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) enum EnrollmentBackend {
    Sqlite(Arc<SqliteStore>),
    Postgres(Arc<PostgresStore>),
}

impl EnrollmentBackend {
    async fn redeem(
        &self,
        verified: &scoplen_identity::VerifiedPersonalEnrollment,
        source: IpAddr,
    ) -> Result<(), PersonalInvitationStoreError> {
        match self {
            Self::Sqlite(store) => {
                store.redeem_verified_personal_invitation_from_source(verified, source).await?
            }
            Self::Postgres(store) => {
                store.redeem_verified_personal_invitation_from_source(verified, source).await?
            }
        };
        Ok(())
    }

    async fn admit_source(
        &self,
        source: IpAddr,
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        match self {
            Self::Sqlite(store) => store.admit_personal_enrollment_source(source).await,
            Self::Postgres(store) => store.admit_personal_enrollment_source(source).await,
        }
    }

    async fn admit_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        match self {
            Self::Sqlite(store) => store.admit_personal_enrollment_digest(digest).await,
            Self::Postgres(store) => store.admit_personal_enrollment_digest(digest).await,
        }
    }

    async fn audit_failure(
        &self,
        reason: PersonalEnrollmentFailureReason,
        source: IpAddr,
        denied_digest: Option<&[u8; 32]>,
    ) -> Result<(), PersonalAdmissionError> {
        match self {
            Self::Sqlite(store) => {
                store.audit_personal_enrollment_failure(reason, source, denied_digest).await
            }
            Self::Postgres(store) => {
                store.audit_personal_enrollment_failure(reason, source, denied_digest).await
            }
        }
    }
}

struct EnrollmentState {
    trusted_origin: String,
    backend: EnrollmentBackend,
}

pub(crate) fn router(trusted_origin: String, backend: EnrollmentBackend) -> Router {
    let state = Arc::new(EnrollmentState { trusted_origin, backend });
    Router::new().route("/api/v1/auth/personal-enroll", post(enroll)).with_state(state)
}

#[allow(clippy::too_many_lines)]
async fn enroll(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EnrollmentState>>,
    request: Request<Body>,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let source = peer.ip();
    match state.backend.admit_source(source).await {
        Ok(PersonalAdmissionDecision::Admitted) => {}
        Ok(PersonalAdmissionDecision::RateLimited(delay)) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::RateLimited,
                StatusCode::TOO_MANY_REQUESTS,
                "auth.rate_limited",
                &request_id,
                None,
                Some(delay),
            )
            .await;
        }
        Err(_) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                &request_id,
                None,
                None,
            )
            .await;
        }
    }
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;
    if headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key("dpop")
        || headers.contains_key("idempotency-key")
    {
        return audited_problem(
            &state,
            source,
            PersonalEnrollmentFailureReason::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "auth.invalid_request",
            &request_id,
            None,
            None,
        )
        .await;
    }
    if headers.get_all(header::ORIGIN).iter().count() > 1 {
        return audited_problem(
            &state,
            source,
            PersonalEnrollmentFailureReason::OriginDenied,
            StatusCode::FORBIDDEN,
            "policy.denied",
            &request_id,
            None,
            None,
        )
        .await;
    }
    let origin = headers.get(header::ORIGIN).map(|value| value.to_str().unwrap_or(""));
    if origin.is_some_and(|value| value != state.trusted_origin) {
        return audited_problem(
            &state,
            source,
            PersonalEnrollmentFailureReason::OriginDenied,
            StatusCode::FORBIDDEN,
            "policy.denied",
            &request_id,
            None,
            None,
        )
        .await;
    }
    if !is_json(headers) {
        return audited_problem(
            &state,
            source,
            PersonalEnrollmentFailureReason::InvalidRequest,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "auth.invalid_request",
            &request_id,
            None,
            None,
        )
        .await;
    }
    let body = match to_bytes(body, MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES + 1).await {
        Ok(body) if body.len() <= MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES => body,
        Ok(_) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::InvalidRequest,
                StatusCode::PAYLOAD_TOO_LARGE,
                "auth.invalid_request",
                &request_id,
                None,
                None,
            )
            .await;
        }
        Err(error) => {
            let status = body_read_error_status(&error);
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::InvalidRequest,
                status,
                "auth.invalid_request",
                &request_id,
                None,
                None,
            )
            .await;
        }
    };
    let decoded = PersonalEnrollmentRequest::from_http_json_structural(
        &body,
        headers.contains_key(header::AUTHORIZATION),
        headers.contains_key("dpop"),
        headers.contains_key("idempotency-key"),
        origin,
        &state.trusted_origin,
    );
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            let (status, code, reason) = codec_problem(&error);
            return audited_problem(&state, source, reason, status, code, &request_id, None, None)
                .await;
        }
    };
    let digest: [u8; 32] = Sha256::digest(decoded.invitation_token).into();
    match state.backend.admit_digest(&digest).await {
        Ok(PersonalAdmissionDecision::Admitted) => {}
        Ok(PersonalAdmissionDecision::RateLimited(delay)) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::RateLimited,
                StatusCode::TOO_MANY_REQUESTS,
                "auth.rate_limited",
                &request_id,
                None,
                Some(delay),
            )
            .await;
        }
        Err(_) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                &request_id,
                None,
                None,
            )
            .await;
        }
    }
    if let Err(error) = decoded.validate() {
        let denied_digest =
            matches!(error, PersonalEnrollmentCodecError::IdentityMismatch).then_some(&digest);
        let (status, code, reason) = codec_problem(&error);
        return audited_problem(
            &state,
            source,
            reason,
            status,
            code,
            &request_id,
            denied_digest,
            None,
        )
        .await;
    }
    let verified = match verify_personal_enrollment(&state.trusted_origin, &decoded) {
        Ok(verified) => verified,
        Err(PersonalEnrollmentVerificationError::Denied) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::EnrollmentDenied,
                StatusCode::UNAUTHORIZED,
                "auth.enrollment_denied",
                &request_id,
                Some(&digest),
                None,
            )
            .await;
        }
        Err(PersonalEnrollmentVerificationError::InvalidRequest) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "auth.invalid_request",
                &request_id,
                None,
                None,
            )
            .await;
        }
        Err(PersonalEnrollmentVerificationError::InvalidTrustedOrigin) => {
            return audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::StorageUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.storage_unavailable",
                &request_id,
                None,
                None,
            )
            .await;
        }
    };
    let result = PersonalEnrollmentResponse {
        account_id: verified.account_id(),
        device_id: verified.device_id(),
        personal_vault_id: verified.personal_vault_id(),
    };
    let Ok(body) = result.to_json() else {
        return audited_problem(
            &state,
            source,
            PersonalEnrollmentFailureReason::StorageUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.storage_unavailable",
            &request_id,
            None,
            None,
        )
        .await;
    };
    match state.backend.redeem(&verified, source).await {
        Ok(()) => response(StatusCode::CREATED, "application/json", body),
        Err(PersonalInvitationStoreError::Denied) => {
            audited_problem(
                &state,
                source,
                PersonalEnrollmentFailureReason::EnrollmentDenied,
                StatusCode::UNAUTHORIZED,
                "auth.enrollment_denied",
                &request_id,
                Some(&digest),
                None,
            )
            .await
        }
        Err(PersonalInvitationStoreError::CommitOutcomeUnknown) => {
            problem(StatusCode::SERVICE_UNAVAILABLE, "auth.commit_outcome_unknown", &request_id)
        }
        Err(_) => {
            let _ = state
                .backend
                .audit_failure(PersonalEnrollmentFailureReason::StorageUnavailable, source, None)
                .await;
            problem(StatusCode::SERVICE_UNAVAILABLE, "auth.storage_unavailable", &request_id)
        }
    }
}

fn body_read_error_status(error: &axum::Error) -> StatusCode {
    if error.source().is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1 {
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

fn codec_problem(
    error: &PersonalEnrollmentCodecError,
) -> (StatusCode, &'static str, PersonalEnrollmentFailureReason) {
    match error {
        PersonalEnrollmentCodecError::EnrollmentRequestTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "auth.invalid_request",
            PersonalEnrollmentFailureReason::InvalidRequest,
        ),
        PersonalEnrollmentCodecError::OriginMismatch => {
            (StatusCode::FORBIDDEN, "policy.denied", PersonalEnrollmentFailureReason::OriginDenied)
        }
        PersonalEnrollmentCodecError::IdentityMismatch => (
            StatusCode::UNAUTHORIZED,
            "auth.enrollment_denied",
            PersonalEnrollmentFailureReason::EnrollmentDenied,
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "auth.invalid_request",
            PersonalEnrollmentFailureReason::InvalidRequest,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn audited_problem(
    state: &EnrollmentState,
    source: IpAddr,
    reason: PersonalEnrollmentFailureReason,
    status: StatusCode,
    code: &str,
    request_id: &str,
    denied_digest: Option<&[u8; 32]>,
    retry_after: Option<u64>,
) -> Response {
    if state.backend.audit_failure(reason, source, denied_digest).await.is_err() {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "auth.storage_unavailable", request_id);
    }
    let mut result = problem(status, code, request_id);
    if let Some(delay) = retry_after {
        let values =
            PersonalRateLimitHeaders::new(u16::try_from(delay).expect("bounded retry delay"))
                .expect("bounded Personal rate limit");
        let headers = result.headers_mut();
        headers.insert(
            header::RETRY_AFTER,
            values.retry_after_seconds().to_string().parse().expect("bounded retry delay"),
        );
        headers
            .insert("ratelimit-policy", values.rate_limit_policy().parse().expect("static policy"));
        headers.insert("ratelimit", values.rate_limit().parse().expect("bounded rate header"));
    }
    result
}

fn problem(status: StatusCode, code: &str, request_id: &str) -> Response {
    let (title, detail, retryable, changed) = if code == "auth.commit_outcome_unknown" {
        (
            "Enrollment outcome unknown",
            "The server could not confirm whether enrollment committed. Try device authentication with this device before taking another action; do not automatically resend enrollment.",
            false,
            true,
        )
    } else {
        match status {
            StatusCode::SERVICE_UNAVAILABLE => (
                "Enrollment unavailable",
                "Enrollment could not be committed. No account was changed; retry the same request later.",
                true,
                false,
            ),
            StatusCode::TOO_MANY_REQUESTS => (
                "Enrollment rate limited",
                "Enrollment is temporarily limited. No account was changed; wait for Retry-After before trying again.",
                true,
                false,
            ),
            StatusCode::UNAUTHORIZED => (
                "Enrollment denied",
                "Enrollment was denied. No account was changed; request a new invitation if needed.",
                false,
                false,
            ),
            StatusCode::FORBIDDEN => (
                "Origin denied",
                "This origin cannot enroll a device. No account was changed; use the invitation's deployment origin.",
                false,
                false,
            ),
            StatusCode::PAYLOAD_TOO_LARGE => (
                "Enrollment request too large",
                "The request exceeds the enrollment limit. No account was changed; reduce its size.",
                false,
                false,
            ),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => (
                "JSON required",
                "Enrollment requires application/json. No account was changed; send a UTF-8 JSON body.",
                false,
                false,
            ),
            _ => (
                "Invalid enrollment request",
                "The enrollment request is invalid. No account was changed; check its fields and headers.",
                false,
                false,
            ),
        }
    };
    let details = ProblemDetails::new(
        ErrorCode::new(code).expect("registered enrollment problem code"),
        status.as_u16(),
        title,
        detail,
        request_id,
        changed,
        retryable,
    )
    .expect("valid enrollment problem");
    let body = serde_json::to_vec(&details).expect("serializable enrollment problem");
    response(status, "application/problem+json", body)
}

fn response(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::from(body))
        .expect("static enrollment response headers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoplen_api::sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate};
    use scoplen_crypto::{
        DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
        PersonalEnrollmentArtifacts, PersonalEnrollmentContext,
    };
    use scoplen_store::RelationalStore;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const ORIGIN: &str = "https://example.com";

    fn id() -> Uuid {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).expect("random UUID");
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }

    fn account_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[1; 32]).expect("account key")
    }

    fn device_key() -> P256SigningKey {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        P256SigningKey::from_bytes(&scalar).expect("device key")
    }

    fn sign_proof(request: &mut PersonalEnrollmentRequest) {
        let bundle = request.key_bundle_update.to_cbor().expect("bundle CBOR");
        let certificate = request.device_certificate.encode().expect("certificate CBOR");
        let context = PersonalEnrollmentContext::new(
            ORIGIN,
            &request.invitation_token,
            request.account_id,
            request.personal_vault_id,
            PersonalEnrollmentArtifacts {
                account_signing_public_key: &request.account_signing_public_key,
                account_kem_public_key: &request.account_kem_public_key,
                key_bundle_update: &bundle,
                device_certificate: &certificate,
                wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
            },
        )
        .expect("proof context");
        request.device_signature = context.sign(&device_key()).expect("device signature");
    }

    fn enrollment(token: [u8; 32]) -> PersonalEnrollmentRequest {
        let account_id = id();
        let device_id = id();
        let kem = DeviceKemKeyPair::from_private_bytes(&[2; 32]).expect("device KEM");
        let mut request = PersonalEnrollmentRequest {
            invitation_token: token,
            account_id,
            personal_vault_id: id(),
            account_signing_public_key: account_key().public_key(),
            account_kem_public_key: [4; 32],
            key_bundle_update: SyncAccountKeyBundleUpdate {
                revision: 1,
                device_wraps: vec![SyncAccountDeviceWrap { device_id, wrapped_ark: vec![5] }],
                account_signing_key: vec![6],
                account_kem_key: vec![7],
                recovery_blob: vec![8],
                signature: vec![0; 64],
            },
            device_certificate: DeviceCertificate::issue(
                &account_key(),
                device_id,
                account_id,
                device_key().public_key_sec1(),
                kem.public_key().to_vec(),
                "first device".into(),
                "windows".into(),
                1,
            )
            .expect("certificate"),
            wrapped_personal_vault_key: vec![9],
            device_signature: [0; 64],
        };
        request.key_bundle_update.signature = account_key()
            .sign(&request.key_bundle_update.signature_input().expect("signature input"))
            .to_vec();
        sign_proof(&mut request);
        request
    }

    async fn post(address: SocketAddr, body: &[u8], extra_headers: &[(&str, &str)]) -> String {
        let mut stream =
            tokio::net::TcpStream::connect(address).await.expect("connect HTTP listener");
        let mut request = format!(
            "POST /api/v1/auth/personal-enroll HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in extra_headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.expect("write request headers");
        stream.write_all(body).await.expect("write body");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read response");
        String::from_utf8(response).expect("UTF-8 response")
    }

    fn status(response: &str, expected: u16, code: Option<&str>) {
        assert!(response.starts_with(&format!("HTTP/1.1 {expected} ")), "{response}");
        assert!(response.to_ascii_lowercase().contains("cache-control: no-store"));
        assert!(response.to_ascii_lowercase().contains("pragma: no-cache"));
        assert!(response.to_ascii_lowercase().contains("referrer-policy: no-referrer"));
        if let Some(code) = code {
            assert!(response.contains("content-type: application/problem+json"));
            let body = response.split_once("\r\n\r\n").expect("HTTP body").1;
            let problem: ProblemDetails = serde_json::from_str(body).expect("typed problem");
            assert_eq!(problem.status, expected);
            assert_eq!(problem.code.as_str(), code);
            assert!(!problem.changed);
            assert_ne!(problem.instance, "");
        }
    }

    #[tokio::test]
    async fn body_read_errors_distinguish_limit_from_transport() {
        let too_large = to_bytes(Body::from(vec![0; 2]), 1).await.expect_err("length limit");
        assert_eq!(body_read_error_status(&too_large), StatusCode::PAYLOAD_TOO_LARGE);
        let interrupted = Body::from_stream(tokio_stream::once(Err::<axum::body::Bytes, _>(
            std::io::Error::other("interrupted test stream"),
        )));
        let interrupted = to_bytes(interrupted, 1).await.expect_err("transport error");
        assert_eq!(body_read_error_status(&interrupted), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn uncertain_commit_problem_preserves_recovery_semantics() {
        let response = problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.commit_outcome_unknown",
            "test-request-id",
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        let body = to_bytes(response.into_body(), 4_096).await.expect("problem body");
        let details: ProblemDetails = serde_json::from_slice(&body).expect("typed problem");
        assert_eq!(details.code.as_str(), "auth.commit_outcome_unknown");
        assert!(details.changed);
        assert!(!details.retryable);
        assert!(details.detail.contains("device authentication"));
        assert!(!details.detail.contains("No account was changed"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn real_listener_enrollment_checks_wire_identity_replay_and_rate() {
        let directory = std::env::temp_dir().join(format!("scoplen-enroll-http-{}", id()));
        std::fs::create_dir_all(&directory).expect("test directory");
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let invitation =
            store.issue_personal_invitation(*id().as_bytes(), ORIGIN).await.expect("invitation");
        let request = enrollment(*invitation.token_bytes());
        let good = request.to_json().expect("request JSON");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("local address");
        let app = router(ORIGIN.into(), EnrollmentBackend::Sqlite(Arc::new(store.clone())));
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve enrollment");
        });

        status(&post(address, b"{}", &[]).await, 415, Some("auth.invalid_request"));
        status(
            &post(address, b"{}", &[("Content-Type", "application/json")]).await,
            400,
            Some("auth.invalid_request"),
        );
        status(
            &post(
                address,
                &good,
                &[("Content-Type", "application/json"), ("Origin", "https://other.example")],
            )
            .await,
            403,
            Some("policy.denied"),
        );
        status(
            &post(
                address,
                &good,
                &[("Content-Type", "application/json"), ("Authorization", "Bearer ignored")],
            )
            .await,
            400,
            Some("auth.invalid_request"),
        );
        status(
            &post(
                address,
                &vec![b' '; MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES + 1],
                &[("Content-Type", "application/json")],
            )
            .await,
            413,
            Some("auth.invalid_request"),
        );

        let mut bad = request.clone();
        bad.device_signature[0] ^= 1;
        status(
            &post(
                address,
                &bad.to_json().expect("bad JSON"),
                &[("Content-Type", "application/json")],
            )
            .await,
            401,
            Some("auth.enrollment_denied"),
        );
        let limited = post(address, &good, &[("Content-Type", "application/json")]).await;
        status(&limited, 429, Some("auth.rate_limited"));
        assert!(limited.to_ascii_lowercase().contains("retry-after: 1"));
        assert!(limited.to_ascii_lowercase().contains("ratelimit-policy: \"personal\";q=30;w=60"));
        assert!(limited.to_ascii_lowercase().contains("ratelimit: \"personal\";r=0;t=1"));
        sqlx::query("UPDATE personal_admission SET cooldown_until_ms = 0")
            .execute(store.pool())
            .await
            .expect("advance cooldown for test");
        let created = post(address, &good, &[("Content-Type", "application/json")]).await;
        status(&created, 201, None);
        let body = created.split_once("\r\n\r\n").expect("success body").1;
        let response =
            PersonalEnrollmentResponse::from_json(body.as_bytes()).expect("typed response");
        assert_eq!(response.account_id, request.account_id);
        assert_eq!(response.device_id, request.device_certificate.device_id);
        assert_eq!(response.personal_vault_id, request.personal_vault_id);
        status(
            &post(address, &good, &[("Content-Type", "application/json")]).await,
            401,
            Some("auth.enrollment_denied"),
        );
        let consumed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM personal_invitations WHERE consumed_at_ms IS NOT NULL",
        )
        .fetch_one(store.pool())
        .await
        .expect("consumption count");
        assert_eq!(consumed, 1);
        let events: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events ORDER BY sequence")
                .fetch_all(store.pool())
                .await
                .expect("audit events");
        assert_eq!(events.len(), 10);
        for event in events {
            assert!(
                !event
                    .windows(request.invitation_token.len())
                    .any(|bytes| bytes == request.invitation_token)
            );
        }
        sqlx::query("UPDATE personal_admission SET cooldown_until_ms = 0")
            .execute(store.pool())
            .await
            .expect("advance replay cooldown for test");
        let digest: [u8; 32] = Sha256::digest(request.invitation_token).into();
        let attempts_before: i64 = sqlx::query_scalar(
            "SELECT attempts FROM personal_admission WHERE kind = 2 AND bucket_key = ?",
        )
        .bind(digest.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("digest attempts");
        let mut mismatched: serde_json::Value =
            serde_json::from_slice(&good).expect("request JSON value");
        mismatched["account_id"] = serde_json::Value::String(id().to_string());
        let mismatched = serde_json::to_vec(&mismatched).expect("mismatched JSON");
        status(
            &post(address, &mismatched, &[("Content-Type", "application/json")]).await,
            401,
            Some("auth.enrollment_denied"),
        );
        let attempts_after: i64 = sqlx::query_scalar(
            "SELECT attempts FROM personal_admission WHERE kind = 2 AND bucket_key = ?",
        )
        .bind(digest.as_slice())
        .fetch_one(store.pool())
        .await
        .expect("digest attempts after mismatch");
        assert_eq!(
            attempts_after,
            attempts_before + 1,
            "identity mismatch consumes digest admission"
        );
        status(
            &post(address, &good, &[("Content-Type", "application/json")]).await,
            429,
            Some("auth.rate_limited"),
        );
        sqlx::query("CREATE TRIGGER fail_personal_admission BEFORE INSERT ON personal_admission BEGIN SELECT RAISE(ABORT, 'admission unavailable'); END")
            .execute(store.pool()).await.expect("install admission failure");
        status(&post(address, b"{}", &[]).await, 503, Some("auth.storage_unavailable"));
        sqlx::query("DROP TRIGGER fail_personal_admission")
            .execute(store.pool())
            .await
            .expect("restore admission");
        let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
            .fetch_one(store.pool())
            .await
            .expect("audited admission failure");
        assert_eq!(audited, 13, "admission failure is audited without identity mutation");
        sqlx::query("UPDATE personal_admission SET cooldown_until_ms = 0")
            .execute(store.pool())
            .await
            .expect("advance cooldown for audit-failure test");
        sqlx::query("CREATE TRIGGER fail_personal_failure_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'failure audit unavailable'); END")
            .execute(store.pool()).await.expect("install audit failure");
        status(&post(address, b"{}", &[]).await, 503, Some("auth.storage_unavailable"));
        sqlx::query("DROP TRIGGER fail_personal_failure_audit")
            .execute(store.pool())
            .await
            .expect("restore audit");
        let after_failed_audit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
                .fetch_one(store.pool())
                .await
                .expect("audit rollback count");
        assert_eq!(after_failed_audit, audited);
        server.abort();
        let _ = server.await;
        store.pool().close().await;
        drop(store);
        for attempt in 0..20 {
            match std::fs::remove_dir_all(&directory) {
                Ok(()) => break,
                Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => panic!("remove test directory: {error}"),
            }
        }
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_real_listener_redeems_once_and_audits() {
        let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
            .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
        let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
        let invitation =
            store.issue_personal_invitation(*id().as_bytes(), ORIGIN).await.expect("invitation");
        let request = enrollment(*invitation.token_bytes());
        let body = request.to_json().expect("request JSON");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let app = router(ORIGIN.into(), EnrollmentBackend::Postgres(Arc::new(store.clone())));
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve PostgreSQL enrollment");
        });
        let created = post(address, &body, &[("Content-Type", "application/json")]).await;
        status(&created, 201, None);
        let receipt = PersonalEnrollmentResponse::from_json(
            created.split_once("\r\n\r\n").expect("success body").1.as_bytes(),
        )
        .expect("typed response");
        assert_eq!(receipt.account_id, request.account_id);
        assert_eq!(receipt.device_id, request.device_certificate.device_id);
        assert_eq!(receipt.personal_vault_id, request.personal_vault_id);
        status(
            &post(address, &body, &[("Content-Type", "application/json")]).await,
            401,
            Some("auth.enrollment_denied"),
        );
        let consumed: Option<i64> = sqlx::query_scalar(
            "SELECT consumed_at_ms FROM personal_invitations WHERE invitation_id = $1",
        )
        .bind(invitation.invitation_id().as_slice())
        .fetch_one(store.pool())
        .await
        .expect("invitation consumption");
        assert!(consumed.is_some());
        let enrolled = store
            .find_active_personal_device(*receipt.device_id.as_bytes())
            .await
            .expect("device readback");
        assert!(enrolled.is_some());
        store.verify_deployment_audit_chain().await.expect("audit chain").expect("audit head");
        server.abort();
        let _ = server.await;
        store.pool().close().await;
    }
}
