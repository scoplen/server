// SPDX-License-Identifier: AGPL-3.0-only
//! Current-Device Organization inventory and revision-fenced sync reads.

use super::{OrganizationState, invalid, problem, reply, store_problem, team};
use crate::device_auth::{AuthBackend, matching_origin};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::{delete, get, post, put},
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::DeviceAccessOperation,
    inventory::{
        InventoryCreateRequest, InventoryReplaceRequest, InventoryType,
        MAX_INVENTORY_RESOURCE_BYTES,
    },
    organization::{OrganizationListQuery, parse_organization_idempotency_key},
    sync::SyncOrganizationViewQuery,
};
use scoplen_store::organizations::{
    OrganizationPrincipal as _, OrganizationStoreError,
    inventory::{InventoryTarget, InventoryWrite},
};
use uuid::Uuid;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/sync/v1/vaults/{vault}/view", get(view))
        .route("/api/v1/orgs/{org}/hosts", get(handle))
        .route("/api/v1/orgs/{org}/hosts", post(handle))
        .route("/api/v1/orgs/{org}/hosts/{id}", get(handle))
        .route("/api/v1/orgs/{org}/hosts/{id}", put(handle))
        .route("/api/v1/orgs/{org}/hosts/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/access-profiles", get(handle))
        .route("/api/v1/orgs/{org}/access-profiles", post(handle))
        .route("/api/v1/orgs/{org}/access-profiles/{id}", get(handle))
        .route("/api/v1/orgs/{org}/access-profiles/{id}", put(handle))
        .route("/api/v1/orgs/{org}/access-profiles/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/routes", get(handle))
        .route("/api/v1/orgs/{org}/routes", post(handle))
        .route("/api/v1/orgs/{org}/routes/{id}", get(handle))
        .route("/api/v1/orgs/{org}/routes/{id}", put(handle))
        .route("/api/v1/orgs/{org}/routes/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/host-groups", get(handle))
        .route("/api/v1/orgs/{org}/host-groups", post(handle))
        .route("/api/v1/orgs/{org}/host-groups/{id}", get(handle))
        .route("/api/v1/orgs/{org}/host-groups/{id}", put(handle))
        .route("/api/v1/orgs/{org}/host-groups/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/trust-records", get(handle))
        .route("/api/v1/orgs/{org}/trust-records", post(handle))
        .route("/api/v1/orgs/{org}/trust-records/{id}", get(handle))
        .route("/api/v1/orgs/{org}/trust-records/{id}", put(handle))
        .route("/api/v1/orgs/{org}/trust-records/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/snippets", get(handle))
        .route("/api/v1/orgs/{org}/snippets", post(handle))
        .route("/api/v1/orgs/{org}/snippets/{id}", get(handle))
        .route("/api/v1/orgs/{org}/snippets/{id}", put(handle))
        .route("/api/v1/orgs/{org}/snippets/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/gateway-networks", get(handle))
        .route("/api/v1/orgs/{org}/gateway-networks", post(handle))
        .route("/api/v1/orgs/{org}/gateway-networks/{id}", get(handle))
        .route("/api/v1/orgs/{org}/gateway-networks/{id}", put(handle))
        .route("/api/v1/orgs/{org}/gateway-networks/{id}", delete(handle))
}

#[allow(clippy::too_many_lines)]
async fn handle(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<OrganizationState>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN) && !matching_origin(&parts.headers, &state.origin)
    {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, &id);
    }
    let segments: Vec<_> = parts.uri.path().split('/').collect();
    let (org, segment, target) = match segments.as_slice() {
        ["", "api", "v1", "orgs", org, segment] => (*org, *segment, None),
        ["", "api", "v1", "orgs", org, segment, target] => (*org, *segment, Some(*target)),
        _ => return invalid(&id),
    };
    let Ok(kind) = InventoryType::from_segment(segment) else { return invalid(&id) };
    let template = format!(
        "/api/v1/orgs/{{org}}/{}{}",
        kind.segment(),
        if target.is_some() { "/{id}" } else { "" }
    );
    let Some(operation) = DeviceAccessOperation::from_route(parts.method.as_str(), &template)
    else {
        return invalid(&id);
    };
    let admission = team::endpoint(operation);
    if let Some(endpoint) = admission
        && let Err(response) = team::admission(&state, endpoint, peer.ip(), None, &id).await
    {
        return response;
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
    let Ok(org) = parse_organization_idempotency_key(org) else { return invalid(&id) };
    let Ok(target) = target.map(parse_organization_idempotency_key).transpose() else {
        return invalid(&id);
    };
    macro_rules! store {($method:ident($($args:expr),* $(,)?))=>{match &state.backend{AuthBackend::Sqlite(store)=>store.$method($($args),*).await,AuthBackend::Postgres(store)=>store.$method($($args),*).await}};}
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
            return match store!(read_organization_inventory(
                &principal, expires_at, org, kind, target
            )) {
                Ok(value) => team::encoded(value.to_json(), Some(&value.etag), StatusCode::OK, &id),
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
        return match store!(list_organization_inventory(&principal, expires_at, org, kind, &query))
        {
            Ok(value) => team::encoded(value.to_json(), None, StatusCode::OK, &id),
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
            Ok(value) => value,
            Err(error) => return error,
        };
        let body = match team::body(&parts, body, MAX_INVENTORY_RESOURCE_BYTES, &id).await {
            Ok(value) => value,
            Err(error) => return error,
        };
        let Ok(request) = InventoryCreateRequest::from_json(kind, body.as_bytes()) else {
            return invalid(&id);
        };
        let value = store!(write_organization_inventory(
            &principal,
            expires_at,
            &state.origin,
            InventoryTarget { org, kind, id: request.id },
            InventoryWrite::Create { key, request: &request }
        ));
        return write_response(&state, org, value, StatusCode::CREATED, &id).await;
    }
    if parts.headers.contains_key("idempotency-key") {
        return invalid(&id);
    }
    let Some(target) = target else { return invalid(&id) };
    let if_match = match team::precondition(&parts, &id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if parts.method == "PUT" {
        let body = match team::body(&parts, body, MAX_INVENTORY_RESOURCE_BYTES, &id).await {
            Ok(value) => value,
            Err(error) => return error,
        };
        let Ok(request) = InventoryReplaceRequest::from_json(kind, body.as_bytes()) else {
            return invalid(&id);
        };
        let value = store!(write_organization_inventory(
            &principal,
            expires_at,
            &state.origin,
            InventoryTarget { org, kind, id: target },
            InventoryWrite::Replace { if_match: &if_match, request: &request }
        ));
        return write_response(&state, org, value, StatusCode::OK, &id).await;
    }
    if parts.method == "DELETE" {
        if !to_bytes(body, 1).await.is_ok_and(|body| body.is_empty()) {
            return invalid(&id);
        }
        let value = store!(write_organization_inventory(
            &principal,
            expires_at,
            &state.origin,
            InventoryTarget { org, kind, id: target },
            InventoryWrite::Delete { if_match: &if_match }
        ));
        return write_response(&state, org, value, StatusCode::NO_CONTENT, &id).await;
    }
    invalid(&id)
}

async fn write_response(
    state: &OrganizationState,
    org: Uuid,
    value: Result<
        scoplen_store::organizations::inventory::InventoryWriteResult,
        OrganizationStoreError,
    >,
    status: StatusCode,
    id: &Uuid,
) -> Response {
    match value {
        Ok(value) => {
            if value.changed {
                super::notify_organization(state, org).await;
            }
            match value.resource {
                Some(resource) => {
                    team::encoded(resource.to_json(), Some(&resource.etag), status, id)
                }
                None => reply(status, "application/json", Vec::new(), id),
            }
        }
        Err(error) => store_problem(error, id),
    }
}

async fn view(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN) && !matching_origin(&parts.headers, &state.origin)
    {
        return sync_problem(OrganizationStoreError::PermissionDenied, &id);
    }
    let (principal, expires_at) = match state
        .auth
        .authenticate_request(
            DeviceAccessOperation::OrganizationViewRead,
            &parts.method,
            &parts.uri,
            &parts.headers,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return sync_status(
                error.status,
                match error.status {
                    StatusCode::FORBIDDEN => "policy.denied",
                    StatusCode::SERVICE_UNAVAILABLE => "sync.storage_unavailable",
                    _ => "auth.authentication_required",
                },
                false,
                &id,
            );
        }
    };
    if parts.headers.contains_key(header::IF_MATCH)
        || parts.headers.contains_key("idempotency-key")
        || !to_bytes(body, 1).await.is_ok_and(|body| body.is_empty())
    {
        return sync_problem(OrganizationStoreError::InvalidRequest, &id);
    }
    let vault = parts
        .uri
        .path()
        .strip_prefix("/sync/v1/vaults/")
        .and_then(|value| value.strip_suffix("/view"))
        .and_then(|value| parse_organization_idempotency_key(value).ok());
    let Some(vault) = vault else {
        return sync_problem(OrganizationStoreError::InvalidRequest, &id);
    };
    let Ok(query) = SyncOrganizationViewQuery::from_query(parts.uri.query().unwrap_or("")) else {
        return sync_problem(OrganizationStoreError::InvalidRequest, &id);
    };
    let limits = state.read_limits;
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store.organization_inventory_view(&principal, expires_at, vault, &query, limits).await
        }
        AuthBackend::Postgres(store) => {
            store.organization_inventory_view(&principal, expires_at, vault, &query, limits).await
        }
    };
    match result {
        Ok(value) => match value.to_cbor_with_limits(limits) {
            Ok(body) => reply(StatusCode::OK, "application/cbor", body, &id),
            Err(_) => sync_problem(OrganizationStoreError::StorageUnavailable, &id),
        },
        Err(error) => sync_problem(error, &id),
    }
}

fn sync_problem(error: OrganizationStoreError, id: &Uuid) -> Response {
    let (status, code, retryable) = match error {
        OrganizationStoreError::InvalidRequest => {
            (StatusCode::BAD_REQUEST, "sync.invalid_request", false)
        }
        OrganizationStoreError::Conflict => (StatusCode::CONFLICT, "sync.invalid_request", false),
        OrganizationStoreError::AuthenticationRequired => {
            (StatusCode::UNAUTHORIZED, "auth.authentication_required", false)
        }
        OrganizationStoreError::PermissionDenied => (StatusCode::FORBIDDEN, "policy.denied", false),
        OrganizationStoreError::NotFound => (StatusCode::NOT_FOUND, "sync.object_not_found", false),
        OrganizationStoreError::ViewChanged => (StatusCode::CONFLICT, "sync.view_changed", true),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "sync.storage_unavailable", true),
    };
    sync_status(status, code, retryable, id)
}

fn sync_status(status: StatusCode, code: &str, retryable: bool, id: &Uuid) -> Response {
    let value = ProblemDetails::new(
        ErrorCode::new(code).expect("static code"),
        status.as_u16(),
        "Team inventory unavailable",
        "Refresh the team session and retry the complete view with a fresh proof.",
        id.to_string(),
        false,
        retryable,
    )
    .expect("static problem");
    reply(status, "application/problem+cbor", value.to_cbor().expect("static CBOR problem"), id)
}
