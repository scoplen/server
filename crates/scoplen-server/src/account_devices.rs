// SPDX-License-Identifier: AGPL-3.0-only
//! Current-account signed device statements on the enrolled-device boundary.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    response::Response,
    routing::get,
};
use scoplen_api::{
    ErrorCode, ProblemDetails, account_devices::validate_account_devices_request,
    auth::DeviceAccessOperation,
};
use scoplen_store::{device_authentication::DeviceAuthenticationError, kms::LocalKeyFile};
use uuid::Uuid;

use crate::{
    device_auth::{AuthBackend, matching_origin, response},
    personal_sync::PersonalSyncAuthenticator,
};

#[derive(Clone)]
struct DeviceState {
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
    Router::new().route("/api/v1/accounts/me/devices", get(read)).with_state(DeviceState {
        backend,
        auth,
        trusted_origin,
    })
}

async fn read(State(state): State<DeviceState>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN)
        && !matching_origin(&parts.headers, &state.trusted_origin)
    {
        return problem(StatusCode::FORBIDDEN);
    }
    let principal = match state
        .auth
        .authenticate_operation(
            DeviceAccessOperation::AccountDevicesRead,
            &parts.method,
            &parts.uri,
            &parts.headers,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return problem(error.status),
    };
    let Ok(body) = to_bytes(body, 0).await else {
        return problem(StatusCode::BAD_REQUEST);
    };
    if validate_account_devices_request(
        parts.uri.query(),
        &body,
        parts.headers.contains_key("idempotency-key"),
        parts.headers.contains_key(header::IF_MATCH),
    )
    .is_err()
    {
        return problem(StatusCode::BAD_REQUEST);
    }
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => store.read_account_device_statements(&principal).await,
        AuthBackend::Postgres(store) => store.read_account_device_statements(&principal).await,
    };
    let snapshot = match result {
        Ok(value) => value,
        Err(DeviceAuthenticationError::Denied { .. }) => return problem(StatusCode::UNAUTHORIZED),
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE),
    };
    match snapshot.to_json() {
        Ok(body) => response(StatusCode::OK, "application/json", body),
        Err(_) => problem(StatusCode::SERVICE_UNAVAILABLE),
    }
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
            "This caller or origin cannot read the current account's device statements.",
        ),
        StatusCode::BAD_REQUEST => (
            "auth.invalid_request",
            "Invalid device statements request",
            "Omit the request body, query, Idempotency-Key and If-Match headers.",
        ),
        _ => (
            "auth.storage_unavailable",
            "Device statements unavailable",
            "The server could not verify the complete current account state. Retry with a fresh proof.",
        ),
    };
    let details = ProblemDetails::new(
        ErrorCode::new(code).expect("static device statements code"),
        status.as_u16(),
        title,
        detail,
        Uuid::new_v4().to_string(),
        false,
        status.is_server_error(),
    )
    .expect("static device statements problem");
    response(
        status,
        "application/problem+json",
        serde_json::to_vec(&details).expect("serializable device statements problem"),
    )
}
