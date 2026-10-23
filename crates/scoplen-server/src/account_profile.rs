// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded current-account profile on the native enrolled-device boundary.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    response::Response,
    routing::get,
};
use scoplen_api::{ErrorCode, ProblemDetails, auth::DeviceAccessOperation};
use scoplen_store::{device_authentication::DeviceAuthenticationError, kms::LocalKeyFile};
use uuid::Uuid;

use crate::{
    device_auth::{AuthBackend, matching_origin, response},
    personal_sync::PersonalSyncAuthenticator,
};

#[derive(Clone)]
struct ProfileState {
    backend: AuthBackend,
    auth: PersonalSyncAuthenticator,
    trusted_origin: String,
}

pub(crate) fn router(
    trusted_origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
) -> Router {
    let auth = PersonalSyncAuthenticator::new(backend.clone(), kms, trusted_origin.clone());
    Router::new().route("/api/v1/accounts/me", get(read)).with_state(ProfileState {
        backend,
        auth,
        trusted_origin,
    })
}

async fn read(State(state): State<ProfileState>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN)
        && !matching_origin(&parts.headers, &state.trusted_origin)
    {
        return problem(StatusCode::FORBIDDEN);
    }
    let principal = match state
        .auth
        .authenticate_operation(
            DeviceAccessOperation::AccountProfileRead,
            &parts.method,
            &parts.uri,
            &parts.headers,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return problem(error.status),
    };
    if to_bytes(body, 0).await.is_err() {
        return problem(StatusCode::BAD_REQUEST);
    }
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => store.read_account_profile(&principal).await,
        AuthBackend::Postgres(store) => store.read_account_profile(&principal).await,
    };
    let profile = match result {
        Ok(value) => value,
        Err(DeviceAuthenticationError::Denied { .. }) => return problem(StatusCode::UNAUTHORIZED),
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE),
    };
    let (Ok(body), Ok(etag)) = (profile.to_json(), profile.etag.parse()) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut result = response(StatusCode::OK, "application/json", body);
    result.headers_mut().insert(header::ETAG, etag);
    result
}

fn problem(status: StatusCode) -> Response {
    let (code, title, detail) = match status {
        StatusCode::UNAUTHORIZED => (
            "auth.authentication_required",
            "Authentication required",
            "Authenticate this enrolled device and create a fresh DPoP proof for the request.",
        ),
        StatusCode::FORBIDDEN => (
            "policy.denied",
            "Access denied",
            "This caller or origin cannot read the current account profile.",
        ),
        StatusCode::BAD_REQUEST => (
            "auth.invalid_request",
            "Invalid profile request",
            "The current account profile request must have no body.",
        ),
        _ => (
            "auth.storage_unavailable",
            "Account profile unavailable",
            "The server could not verify current account state. Retry with a fresh proof.",
        ),
    };
    let details = ProblemDetails::new(
        ErrorCode::new(code).expect("static profile code"),
        status.as_u16(),
        title,
        detail,
        Uuid::new_v4().to_string(),
        false,
        status.is_server_error(),
    )
    .expect("static profile problem");
    response(
        status,
        "application/problem+json",
        serde_json::to_vec(&details).expect("serializable profile problem"),
    )
}
