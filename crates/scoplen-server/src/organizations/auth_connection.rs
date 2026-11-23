// SPDX-License-Identifier: AGPL-3.0-only
//! Current Organization login connection and explicit, original-family suspension.

use std::net::SocketAddr;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, MatchedPath, State},
    http::{Request, StatusCode},
    response::Response,
    routing::{get, post},
};
use scoplen_api::{
    account_browser::AccountBrowserAccessOperation, auth_connection::ConnectionRequest,
    auth_connection_draft::DraftRequestError, organization::parse_organization_idempotency_key,
};
use scoplen_store::{
    account_entry_admission::AccountEntryEndpoint, organizations::OrganizationStoreError,
};
use uuid::Uuid;

use super::{
    OrganizationState, browser_authority, invalid, problem, specific_problem, store_problem, team,
    valid_encoding,
};
use crate::device_auth::AuthBackend;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/auth-connection", get(handle))
        .route("/api/v1/orgs/{org}/auth-connection/suspend", post(handle))
}

async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<OrganizationState>,
    route: MatchedPath,
    request: Request<Body>,
) -> Response {
    use AccountBrowserAccessOperation::{AuthConnectionRead, AuthConnectionSuspend};
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let Some(operation @ (AuthConnectionRead | AuthConnectionSuspend)) =
        AccountBrowserAccessOperation::from_route(parts.method.as_str(), route.as_str())
    else {
        return invalid(&id);
    };
    let suspend = operation == AuthConnectionSuspend;
    let endpoint = AccountEntryEndpoint::OrganizationAuthConnectionSuspend;
    if suspend && let Err(response) = team::admission(&state, endpoint, peer.ip(), None, &id).await
    {
        return response;
    }
    let session = match browser_authority(&state, operation, &parts, &id).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if suspend
        && let Err(response) = team::admission(
            &state,
            endpoint,
            peer.ip(),
            Some(Uuid::from_bytes(session.account_id)),
            &id,
        )
        .await
    {
        return response;
    }
    let Some(organization) = parts
        .uri
        .path()
        .strip_prefix("/api/v1/orgs/")
        .and_then(|path| path.split_once('/'))
        .and_then(|(id, _)| parse_organization_idempotency_key(id).ok())
    else {
        return invalid(&id);
    };
    if !valid_encoding(&parts.headers) || to_bytes(body, 0).await.is_err() {
        return invalid(&id);
    }
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default()));
    let request = match ConnectionRequest::from_http(operation, parts.uri.query(), headers, &[]) {
        Ok(request) => request,
        Err(error) => return request_problem(error, &id),
    };
    macro_rules! apply {
        ($store:expr) => {
            match request {
                ConnectionRequest::Read => {
                    $store.read_organization_auth_connection(&session, organization).await
                }
                ConnectionRequest::Suspend { revision, key } => {
                    $store
                        .suspend_organization_auth_connection(
                            &session,
                            &state.origin,
                            organization,
                            revision,
                            key,
                        )
                        .await
                }
                _ => return invalid(&id),
            }
        };
    }
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => apply!(store),
        AuthBackend::Postgres(store) => apply!(store),
    };
    match result {
        Ok(resource) => {
            let json = resource.to_json();
            if suspend && json.is_err() {
                return unconfirmed(&id);
            }
            team::encoded(json, Some(&resource.etag()), StatusCode::OK, &id)
        }
        Err(OrganizationStoreError::CommitOutcomeUnknown) if suspend => unconfirmed(&id),
        Err(error) => store_problem(error, &id),
    }
}

fn request_problem(error: DraftRequestError, id: &Uuid) -> Response {
    match error {
        DraftRequestError::PreconditionRequired => specific_problem(
            StatusCode::PRECONDITION_REQUIRED,
            "organization.precondition_required",
            "Connection revision required",
            "Read the connection and submit its strong ETag in If-Match.",
            false,
            false,
            id,
        ),
        DraftRequestError::Invalid => invalid(id),
        DraftRequestError::TooLarge => {
            problem(StatusCode::PAYLOAD_TOO_LARGE, "organization.invalid_request", false, id)
        }
        DraftRequestError::MediaType => {
            problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "organization.invalid_request", false, id)
        }
    }
}

fn unconfirmed(id: &Uuid) -> Response {
    specific_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "organization.commit_outcome_unknown",
        "Connection suspension unconfirmed",
        "Only the original browser session can confirm suspension. Explicitly retry with the original key and If-Match and a fresh proof within 24 hours. Read the connection for its current state.",
        true,
        true,
        id,
    )
}
