// SPDX-License-Identifier: AGPL-3.0-only
//! Organization-local, untested issuer drafts for current Device and Account-browser writers.

use std::{error::Error as _, net::SocketAddr};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{Method, Request, StatusCode, header},
    response::Response,
    routing::{delete, get, post},
};
use scoplen_api::{
    auth::DeviceAccessOperation,
    auth_connection_draft::{DraftRequest, DraftRequestError, MAX_CREATE_BYTES},
    organization::parse_organization_idempotency_key,
};
use scoplen_store::organizations::OrganizationStoreError;
use uuid::Uuid;

use super::{OrganizationState, invalid, problem, reply, specific_problem, store_problem, team};
use crate::device_auth::AuthBackend;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/auth-connection-draft", post(handle))
        .route("/api/v1/orgs/{org}/auth-connection-draft", get(handle))
        .route("/api/v1/orgs/{org}/auth-connection-draft", delete(handle))
}

async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<OrganizationState>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let Some(operation) = DeviceAccessOperation::from_route(
        parts.method.as_str(),
        "/api/v1/orgs/{org}/auth-connection-draft",
    ) else {
        return invalid(&id);
    };
    let (principal, expires_at, _) =
        match team::admitted_actor(&state, peer.ip(), operation, &parts, &id).await {
            Ok(actor) => actor,
            Err(response) => return *response,
        };
    let organization = parts
        .uri
        .path()
        .strip_prefix("/api/v1/orgs/")
        .and_then(|path| path.strip_suffix("/auth-connection-draft"))
        .and_then(|value| parse_organization_idempotency_key(value).ok());
    let Some(organization) = organization else { return invalid(&id) };
    // Preserve multiplicity and presence. An opaque value cannot match a valid key,
    // precondition or JSON media type; unrelated transport headers are ignored by the codec.
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default()));
    if parts.headers.contains_key(header::CONTENT_ENCODING)
        && (parts.headers.get_all(header::CONTENT_ENCODING).iter().count() != 1
            || parts.headers[header::CONTENT_ENCODING] != "identity")
    {
        return invalid(&id);
    }
    let creating = parts.method == Method::POST;
    let max = if creating { MAX_CREATE_BYTES } else { 0 };
    let bytes = match to_bytes(body, max).await {
        Ok(bytes) => bytes,
        Err(error)
            if creating
                && error.source().is_some_and(
                    <dyn std::error::Error>::is::<http_body_util::LengthLimitError>,
                ) =>
        {
            return draft_problem(DraftRequestError::TooLarge, &id);
        }
        Err(_) => return invalid(&id),
    };
    let request =
        match DraftRequest::from_http(parts.method.as_str(), parts.uri.query(), headers, &bytes) {
            Ok(request) => request,
            Err(error) => return draft_problem(error, &id),
        };
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store
                .organization_auth_draft(
                    &principal,
                    expires_at,
                    &state.origin,
                    organization,
                    &request,
                )
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .organization_auth_draft(
                    &principal,
                    expires_at,
                    &state.origin,
                    organization,
                    &request,
                )
                .await
        }
    };
    match (request, result) {
        (_, Err(error)) => store_problem(error, &id),
        (DraftRequest::Cancel(_, _), Ok(None)) => {
            let mut response = reply(StatusCode::NO_CONTENT, "application/json", Vec::new(), &id);
            response.headers_mut().remove(header::CONTENT_TYPE);
            response
        }
        (DraftRequest::Read | DraftRequest::Create(_, _), Ok(Some(value))) => {
            let status = if creating { StatusCode::CREATED } else { StatusCode::OK };
            team::encoded(value.to_json(), Some(&value.etag()), status, &id)
        }
        _ => store_problem(OrganizationStoreError::StorageUnavailable, &id),
    }
}

fn draft_problem(error: DraftRequestError, id: &Uuid) -> Response {
    let status = match error {
        DraftRequestError::Invalid => return invalid(id),
        DraftRequestError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        DraftRequestError::MediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        DraftRequestError::PreconditionRequired => {
            return specific_problem(
                StatusCode::PRECONDITION_REQUIRED,
                "organization.precondition_required",
                "Draft precondition required",
                "Use If-None-Match: * to create a draft or its original strong If-Match to cancel it.",
                false,
                false,
                id,
            );
        }
    };
    problem(status, "organization.invalid_request", false, id)
}
