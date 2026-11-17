// SPDX-License-Identifier: AGPL-3.0-only
//! The six independently mapped Device and Account-browser access-request operations.

use super::{OrganizationState, invalid, problem, store_problem, team};
use crate::device_auth::{AuthBackend, matching_origin};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use scoplen_api::{
    access_request::{
        AccessRequestCheckRequest, AccessRequestCreateRequest, AccessRequestDecisionRequest,
        AccessRequestListQuery, AccessRequestResource, MAX_ACCESS_REQUEST_BYTES,
    },
    auth::DeviceAccessOperation,
    organization::parse_organization_idempotency_key,
};
use scoplen_store::organizations::{
    OrganizationPrincipal as _, OrganizationStoreError,
    access_requests::{AccessRequestTarget, AccessRequestWrite, AccessRequestWriteResult},
};
use uuid::Uuid;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/access-requests/check", post(handle))
        .route("/api/v1/orgs/{org}/access-requests", post(handle))
        .route("/api/v1/orgs/{org}/access-requests", get(handle))
        .route("/api/v1/orgs/{org}/access-requests/{id}", get(handle))
        .route("/api/v1/orgs/{org}/access-requests/{id}/decisions", post(handle))
        .route("/api/v1/orgs/{org}/access-requests/{id}/cancel", post(handle))
}

#[allow(clippy::too_many_lines)]
async fn handle(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    State(state): State<OrganizationState>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let segments: Vec<_> = parts.uri.path().split('/').collect();
    let (organization, target, template) = match segments.as_slice() {
        ["", "api", "v1", "orgs", org, "access-requests"] => {
            (*org, None, "/api/v1/orgs/{org}/access-requests")
        }
        ["", "api", "v1", "orgs", org, "access-requests", "check"] => {
            (*org, None, "/api/v1/orgs/{org}/access-requests/check")
        }
        ["", "api", "v1", "orgs", org, "access-requests", target] => {
            (*org, Some(*target), "/api/v1/orgs/{org}/access-requests/{id}")
        }
        ["", "api", "v1", "orgs", org, "access-requests", target, "decisions"] => {
            (*org, Some(*target), "/api/v1/orgs/{org}/access-requests/{id}/decisions")
        }
        ["", "api", "v1", "orgs", org, "access-requests", target, "cancel"] => {
            (*org, Some(*target), "/api/v1/orgs/{org}/access-requests/{id}/cancel")
        }
        _ => return invalid(&id),
    };
    let Some(operation) = DeviceAccessOperation::from_route(parts.method.as_str(), template) else {
        return invalid(&id);
    };
    let admission = team::endpoint(operation);
    if let Some(endpoint) = admission
        && let Err(response) = team::admission(&state, endpoint, peer.ip(), None, &id).await
    {
        return response;
    }
    if parts.headers.contains_key(header::ORIGIN) && !matching_origin(&parts.headers, &state.origin)
    {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, &id);
    }
    let (principal, expires_at) = match state
        .account_auth
        .authenticate_request(operation, &parts.method, &parts.uri, &parts.headers)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return problem(
                error.status,
                match error.status {
                    StatusCode::FORBIDDEN => "policy.denied",
                    StatusCode::SERVICE_UNAVAILABLE => "organization.storage_unavailable",
                    _ => "auth.authentication_required",
                },
                false,
                &id,
            );
        }
    };
    if let Some(endpoint) = admission
        && let Err(response) = team::admission(
            &state,
            endpoint,
            peer.ip(),
            Some(Uuid::from_bytes(principal.account_id())),
            &id,
        )
        .await
    {
        return response;
    }
    let Ok(organization) = parse_organization_idempotency_key(organization) else {
        return invalid(&id);
    };
    let Ok(target) = target.map(parse_organization_idempotency_key).transpose() else {
        return invalid(&id);
    };
    macro_rules! store {($method:ident($($args:expr),* $(,)?)) => {match &state.backend {
        AuthBackend::Sqlite(store) => store.$method($($args),*).await,
        AuthBackend::Postgres(store) => store.$method($($args),*).await,
    }};}
    if parts.method == "GET" {
        if parts.headers.contains_key(header::IF_MATCH)
            || parts.headers.contains_key("idempotency-key")
            || !to_bytes(body, 1).await.is_ok_and(|body| body.is_empty())
        {
            return invalid(&id);
        }
        if let Some(target) = target {
            if parts.uri.query().is_some() {
                return invalid(&id);
            }
            return match store!(read_organization_access_request(
                &principal,
                expires_at,
                AccessRequestTarget { organization, id: target }
            )) {
                Ok(resource) => {
                    team::encoded(resource.to_json(), Some(&resource.etag), StatusCode::OK, &id)
                }
                Err(error) => store_problem(error, &id),
            };
        }
        let Ok(Query(pairs)) = Query::<Vec<(String, String)>>::try_from_uri(&parts.uri) else {
            return invalid(&id);
        };
        let Ok(query) = AccessRequestListQuery::from_parameters(
            pairs.iter().map(|(key, value)| (key.as_str(), value.as_str())),
        ) else {
            return invalid(&id);
        };
        return match store!(list_organization_access_requests(
            &principal,
            expires_at,
            organization,
            &query
        )) {
            Ok(page) => team::encoded(page.to_json(), None, StatusCode::OK, &id),
            Err(error) => store_problem(error, &id),
        };
    }
    if parts.uri.query().is_some() {
        return invalid(&id);
    }
    if operation == DeviceAccessOperation::AccessRequestCheck {
        if parts.headers.contains_key(header::IF_MATCH)
            || parts.headers.contains_key("idempotency-key")
        {
            return invalid(&id);
        }
        let bytes = match team::body(&parts, body, MAX_ACCESS_REQUEST_BYTES, &id).await {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Ok(request) = AccessRequestCheckRequest::from_json(bytes.as_bytes()) else {
            return invalid(&id);
        };
        return match store!(check_organization_access_request(
            &principal,
            expires_at,
            organization,
            &request.fields
        )) {
            Ok(response) => team::encoded(response.to_json(), None, StatusCode::OK, &id),
            Err(error) => store_problem(error, &id),
        };
    }
    if operation == DeviceAccessOperation::AccessRequestCreate {
        if parts.headers.contains_key(header::IF_MATCH) {
            return invalid(&id);
        }
        let key = match team::operation_key(&parts, &id) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let bytes = match team::body(&parts, body, MAX_ACCESS_REQUEST_BYTES, &id).await {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Ok(request) = AccessRequestCreateRequest::from_json(bytes.as_bytes()) else {
            return invalid(&id);
        };
        return write_response(
            &state,
            organization,
            store!(write_organization_access_request(
                &principal,
                expires_at,
                &state.origin,
                AccessRequestTarget { organization, id: request.id },
                AccessRequestWrite::Create { key, request: &request }
            )),
            StatusCode::CREATED,
            &id,
        )
        .await;
    }
    let Some(target) = target else { return invalid(&id) };
    let target = AccessRequestTarget { organization, id: target };
    let key = match team::operation_key(&parts, &id) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let if_match = protected_precondition(&parts.headers);
    if operation == DeviceAccessOperation::AccessRequestDecide {
        let bytes = match team::body(&parts, body, MAX_ACCESS_REQUEST_BYTES, &id).await {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Ok(request) = AccessRequestDecisionRequest::from_json(bytes.as_bytes()) else {
            return invalid(&id);
        };
        return write_response(
            &state,
            organization,
            store!(write_organization_access_request(
                &principal,
                expires_at,
                &state.origin,
                target,
                AccessRequestWrite::Decide { key, if_match, request }
            )),
            StatusCode::OK,
            &id,
        )
        .await;
    }
    if operation == DeviceAccessOperation::AccessRequestCancel {
        if !to_bytes(body, 1).await.is_ok_and(|body| body.is_empty()) {
            return invalid(&id);
        }
        return write_response(
            &state,
            organization,
            store!(write_organization_access_request(
                &principal,
                expires_at,
                &state.origin,
                target,
                AccessRequestWrite::Cancel { key, if_match }
            )),
            StatusCode::OK,
            &id,
        )
        .await;
    }
    invalid(&id)
}

fn protected_precondition(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let first = values.next()?;
    Some(if values.next().is_some() { "" } else { first.to_str().unwrap_or("") })
}

async fn write_response(
    state: &OrganizationState,
    organization: Uuid,
    result: Result<AccessRequestWriteResult, OrganizationStoreError>,
    status: StatusCode,
    id: &Uuid,
) -> Response {
    let value = match result {
        Ok(value) => value,
        Err(error) => return store_problem(error, id),
    };
    if value.view_changed {
        super::notify_organization(state, organization).await;
    }
    let Ok(resource) = AccessRequestResource::from_json(&value.response_json) else {
        return store_problem(OrganizationStoreError::StorageUnavailable, id);
    };
    team::encoded(Ok(value.response_json), Some(&resource.etag), status, id)
}
