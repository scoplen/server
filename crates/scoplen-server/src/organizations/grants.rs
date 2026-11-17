// SPDX-License-Identifier: AGPL-3.0-only
//! Current-authorized Host Grant management for genuine Device and browser actors.

use super::{OrganizationState, invalid, problem, reply, store_problem, team};
use crate::device_auth::{AuthBackend, matching_origin};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::{delete, get, post, put},
};
use scoplen_api::{
    auth::DeviceAccessOperation,
    grant::{GrantCreateRequest, GrantReplaceRequest, GrantResource, MAX_GRANT_BYTES},
    organization::{OrganizationListQuery, parse_organization_idempotency_key},
};
use scoplen_store::organizations::{
    OrganizationPrincipal as _, OrganizationStoreError,
    grants::{GrantTarget, GrantWrite, GrantWriteResult},
};
use uuid::Uuid;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/grants", get(handle))
        .route("/api/v1/orgs/{org}/grants", post(handle))
        .route("/api/v1/orgs/{org}/grants/{id}", get(handle))
        .route("/api/v1/orgs/{org}/grants/{id}", put(handle))
        .route("/api/v1/orgs/{org}/grants/{id}", delete(handle))
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
    let (organization, target) = match segments.as_slice() {
        ["", "api", "v1", "orgs", org, "grants"] => (*org, None),
        ["", "api", "v1", "orgs", org, "grants", target] => (*org, Some(*target)),
        _ => return invalid(&id),
    };
    let template = if target.is_some() {
        "/api/v1/orgs/{org}/grants/{id}"
    } else {
        "/api/v1/orgs/{org}/grants"
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
    macro_rules! store {($method:ident($($args:expr),* $(,)?))=>{match &state.backend{
        AuthBackend::Sqlite(store)=>store.$method($($args),*).await,
        AuthBackend::Postgres(store)=>store.$method($($args),*).await,
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
            return match store!(read_organization_grant(
                &principal,
                expires_at,
                GrantTarget { organization, id: target }
            )) {
                Ok(value) => match value.to_json() {
                    Ok(bytes) => encoded(bytes, Some(&value.etag), StatusCode::OK, &id),
                    Err(_) => store_problem(OrganizationStoreError::StorageUnavailable, &id),
                },
                Err(error) => store_problem(error, &id),
            };
        }
        let Ok(Query(pairs)) = Query::<Vec<(String, String)>>::try_from_uri(&parts.uri) else {
            return invalid(&id);
        };
        let Ok(query) = OrganizationListQuery::from_parameters(
            pairs.iter().map(|(key, value)| (key.as_str(), value.as_str())),
        ) else {
            return invalid(&id);
        };
        return match store!(list_organization_grants(&principal, expires_at, organization, query)) {
            Ok(page) => match page.to_json() {
                Ok(bytes) => encoded(bytes, None, StatusCode::OK, &id),
                Err(_) => store_problem(OrganizationStoreError::StorageUnavailable, &id),
            },
            Err(error) => store_problem(error, &id),
        };
    }
    if parts.uri.query().is_some() {
        return invalid(&id);
    }
    if parts.method == "POST" {
        if target.is_some() || parts.headers.contains_key(header::IF_MATCH) {
            return invalid(&id);
        }
        let key = match team::operation_key(&parts, &id) {
            Ok(key) => key,
            Err(response) => return response,
        };
        let bytes = match team::body(&parts, body, MAX_GRANT_BYTES, &id).await {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let Ok(request) = GrantCreateRequest::from_json(bytes.as_bytes()) else {
            return invalid(&id);
        };
        return write_response(
            &state,
            organization,
            store!(write_organization_grant(
                &principal,
                expires_at,
                &state.origin,
                GrantTarget { organization, id: request.id },
                GrantWrite::Create { key, fields: &request.fields }
            )),
            StatusCode::CREATED,
            &id,
        )
        .await;
    }
    if parts.headers.contains_key("idempotency-key") {
        return invalid(&id);
    }
    let Some(target) = target else { return invalid(&id) };
    let target = GrantTarget { organization, id: target };
    let if_match = protected_precondition(&parts.headers);
    if parts.method == "PUT" {
        let bytes = match team::body(&parts, body, MAX_GRANT_BYTES, &id).await {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let Ok(request) = GrantReplaceRequest::from_json(bytes.as_bytes()) else {
            return invalid(&id);
        };
        return write_response(
            &state,
            organization,
            store!(write_organization_grant(
                &principal,
                expires_at,
                &state.origin,
                target,
                GrantWrite::Replace { if_match, fields: &request.fields }
            )),
            StatusCode::OK,
            &id,
        )
        .await;
    }
    if parts.method == "DELETE" {
        if !to_bytes(body, 1).await.is_ok_and(|body| body.is_empty()) {
            return invalid(&id);
        }
        return write_response(
            &state,
            organization,
            store!(write_organization_grant(
                &principal,
                expires_at,
                &state.origin,
                target,
                GrantWrite::Delete { if_match }
            )),
            StatusCode::NO_CONTENT,
            &id,
        )
        .await;
    }
    invalid(&id)
}

fn protected_precondition(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let first = values.next()?;
    // Preserve malformed/multiple headers as invalid until the store checks current authority.
    Some(if values.next().is_some() { "" } else { first.to_str().unwrap_or("") })
}

async fn write_response(
    state: &OrganizationState,
    org: Uuid,
    result: Result<GrantWriteResult, OrganizationStoreError>,
    status: StatusCode,
    id: &Uuid,
) -> Response {
    let value = match result {
        Ok(value) => value,
        Err(error) => return store_problem(error, id),
    };
    if value.changed {
        super::notify_organization(state, org).await;
    }
    match value.response_json {
        Some(bytes) => {
            let Ok(resource) = GrantResource::from_json(&bytes) else {
                return store_problem(OrganizationStoreError::StorageUnavailable, id);
            };
            encoded(bytes, Some(&resource.etag), status, id)
        }
        None => reply(status, "application/json", Vec::new(), id),
    }
}

fn encoded(bytes: Vec<u8>, etag: Option<&str>, status: StatusCode, id: &Uuid) -> Response {
    let mut response = reply(status, "application/json", bytes, id);
    if let Some(etag) = etag {
        let Ok(etag) = etag.parse() else {
            return store_problem(OrganizationStoreError::StorageUnavailable, id);
        };
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}
