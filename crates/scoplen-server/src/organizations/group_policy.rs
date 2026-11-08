// SPDX-License-Identifier: AGPL-3.0-only
//! Account-authenticated local groups and persisted-policy administration.

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
    auth::DeviceAccessOperation,
    group_policy::{
        GroupCreateRequest, GroupReplaceRequest, MAX_GROUP_POLICY_BYTES, PolicyCreateRequest,
        PolicyReplaceRequest,
    },
    organization::{OrganizationListQuery, parse_organization_idempotency_key},
};
use scoplen_store::organizations::{
    OrganizationPrincipal as _, OrganizationStoreError,
    group_policy::{ControlFields, ControlKind, ControlResource, ControlTarget, ControlWrite},
};
use uuid::Uuid;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/groups", get(handle))
        .route("/api/v1/orgs/{org}/groups", post(handle))
        .route("/api/v1/orgs/{org}/groups/{id}", get(handle))
        .route("/api/v1/orgs/{org}/groups/{id}", put(handle))
        .route("/api/v1/orgs/{org}/groups/{id}", delete(handle))
        .route("/api/v1/orgs/{org}/policies", get(handle))
        .route("/api/v1/orgs/{org}/policies", post(handle))
        .route("/api/v1/orgs/{org}/policies/{id}", get(handle))
        .route("/api/v1/orgs/{org}/policies/{id}", put(handle))
        .route("/api/v1/orgs/{org}/policies/{id}", delete(handle))
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
    let (organization, segment, target) = match segments.as_slice() {
        ["", "api", "v1", "orgs", organization, segment] => (*organization, *segment, None),
        ["", "api", "v1", "orgs", organization, segment, target] => {
            (*organization, *segment, Some(*target))
        }
        _ => return invalid(&id),
    };
    let kind = match segment {
        "groups" => ControlKind::Group,
        "policies" => ControlKind::Policy,
        _ => return invalid(&id),
    };
    let template =
        format!("/api/v1/orgs/{{org}}/{segment}{}", if target.is_some() { "/{id}" } else { "" });
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
    let Ok(organization) = parse_organization_idempotency_key(organization) else {
        return invalid(&id);
    };
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
            return resource_response(
                store!(read_organization_control(
                    &principal,
                    expires_at,
                    ControlTarget { organization, kind, id: target }
                ))
                .map(Some),
                StatusCode::OK,
                &id,
            );
        }
        let Ok(Query(pairs)) = Query::<Vec<(String, String)>>::try_from_uri(&parts.uri) else {
            return invalid(&id);
        };
        let Ok(query) = OrganizationListQuery::from_parameters(
            pairs.iter().map(|(key, value)| (key.as_str(), value.as_str())),
        ) else {
            return invalid(&id);
        };
        return match store!(list_organization_control(
            &principal,
            expires_at,
            organization,
            kind,
            query
        )) {
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
        let body = match team::body(&parts, body, MAX_GROUP_POLICY_BYTES, &id).await {
            Ok(value) => value,
            Err(error) => return error,
        };
        let (target, fields) = match kind {
            ControlKind::Group => match GroupCreateRequest::from_json(body.as_bytes()) {
                Ok(value) => (value.id, ControlFields::Group(value.fields)),
                Err(_) => return invalid(&id),
            },
            ControlKind::Policy => match PolicyCreateRequest::from_json(body.as_bytes()) {
                Ok(value) => (value.id, ControlFields::Policy(value.fields)),
                Err(_) => return invalid(&id),
            },
        };
        return write_response(
            &state,
            organization,
            store!(write_organization_control(
                &principal,
                expires_at,
                &state.origin,
                ControlTarget { organization, kind, id: target },
                ControlWrite::Create { key, fields: &fields }
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
    let target = ControlTarget { organization, kind, id: target };
    let if_match = match team::precondition(&parts, &id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if parts.method == "PUT" {
        let body = match team::body(&parts, body, MAX_GROUP_POLICY_BYTES, &id).await {
            Ok(value) => value,
            Err(error) => return error,
        };
        let fields = match kind {
            ControlKind::Group => match GroupReplaceRequest::from_json(body.as_bytes()) {
                Ok(value) => ControlFields::Group(value.fields),
                Err(_) => return invalid(&id),
            },
            ControlKind::Policy => match PolicyReplaceRequest::from_json(body.as_bytes()) {
                Ok(value) => ControlFields::Policy(value.fields),
                Err(_) => return invalid(&id),
            },
        };
        return write_response(
            &state,
            organization,
            store!(write_organization_control(
                &principal,
                expires_at,
                &state.origin,
                target,
                ControlWrite::Replace { if_match: &if_match, fields: &fields }
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
            store!(write_organization_control(
                &principal,
                expires_at,
                &state.origin,
                target,
                ControlWrite::Delete { if_match: &if_match }
            )),
            StatusCode::NO_CONTENT,
            &id,
        )
        .await;
    }
    invalid(&id)
}

async fn write_response(
    state: &OrganizationState,
    org: Uuid,
    result: Result<
        scoplen_store::organizations::group_policy::ControlWriteResult,
        OrganizationStoreError,
    >,
    status: StatusCode,
    id: &Uuid,
) -> Response {
    if result.as_ref().is_ok_and(|value| value.changed) {
        super::notify_organization(state, org).await;
    }
    resource_response(result.map(|value| value.resource), status, id)
}

fn resource_response(
    result: Result<Option<ControlResource>, OrganizationStoreError>,
    status: StatusCode,
    id: &Uuid,
) -> Response {
    match result {
        Ok(Some(value)) => team::encoded(value.to_json(), Some(value.etag()), status, id),
        Ok(None) => reply(status, "application/json", Vec::new(), id),
        Err(error) => store_problem(error, id),
    }
}
