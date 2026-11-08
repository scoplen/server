// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded current-account profile for genuine Device and Account-browser actors.

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
    account_actor::AccountActorAuthenticator,
    device_auth::{AuthBackend, matching_origin, response},
};

#[derive(Clone)]
struct ProfileState {
    backend: AuthBackend,
    auth: AccountActorAuthenticator,
    trusted_origin: String,
}

pub(crate) fn router(
    trusted_origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
) -> Router {
    let auth = AccountActorAuthenticator::new(backend.clone(), kms, trusted_origin.clone());
    Router::new().route("/api/v1/accounts/me", get(read)).with_state(ProfileState {
        backend,
        auth,
        trusted_origin,
    })
}

async fn read(State(state): State<ProfileState>, request: Request<Body>) -> Response {
    let id = Uuid::new_v4();
    let mut result = read_inner(state, request, &id).await;
    result.headers_mut().insert("x-request-id", id.to_string().parse().expect("UUID header"));
    result
}

async fn read_inner(state: ProfileState, request: Request<Body>, id: &Uuid) -> Response {
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN)
        && !matching_origin(&parts.headers, &state.trusted_origin)
    {
        return problem(StatusCode::FORBIDDEN, id);
    }
    let (principal, _) = match state
        .auth
        .authenticate_request(
            DeviceAccessOperation::AccountProfileRead,
            &parts.method,
            &parts.uri,
            &parts.headers,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return problem(error.status, id),
    };
    if to_bytes(body, 0).await.is_err() {
        return problem(StatusCode::BAD_REQUEST, id);
    }
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => store.read_account_profile(&principal).await,
        AuthBackend::Postgres(store) => store.read_account_profile(&principal).await,
    };
    let profile = match result {
        Ok(value) => value,
        Err(DeviceAuthenticationError::Denied { .. }) => {
            return problem(StatusCode::UNAUTHORIZED, id);
        }
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, id),
    };
    let (Ok(body), Ok(etag)) = (profile.to_json(), profile.etag.parse()) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, id);
    };
    let mut result = response(StatusCode::OK, "application/json", body);
    result.headers_mut().insert(header::ETAG, etag);
    result
}

fn problem(status: StatusCode, id: &Uuid) -> Response {
    let (code, title, detail) = match status {
        StatusCode::UNAUTHORIZED => (
            "auth.authentication_required",
            "Authentication required",
            "Sign in and create a fresh DPoP proof for the request.",
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
        id.to_string(),
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
