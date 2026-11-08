// SPDX-License-Identifier: AGPL-3.0-only
//! Native current-Device public CA provisioning, trust reads and scoped certificate issuance.

use super::{OrganizationState, invalid, problem, reply, store_problem, team};
use crate::device_auth::{AuthBackend, matching_origin};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use scoplen_api::{
    auth::DeviceAccessOperation,
    certificate::{CertificateIssuanceRequest, MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES},
    organization::{OrganizationListQuery, parse_organization_idempotency_key},
    user_ca::{MAX_USER_CA_CREATE_BYTES, UserCaCreateRequest},
};
use scoplen_store::organizations::OrganizationStoreError;
use uuid::Uuid;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/certificate-authorities", get(handle))
        .route("/api/v1/orgs/{org}/certificate-authorities", post(handle))
        .route("/api/v1/orgs/{org}/certificate-authorities/{id}", get(handle))
        .route("/api/v1/orgs/{org}/certificates", post(handle))
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
    let (org, target, template) = match segments.as_slice() {
        ["", "api", "v1", "orgs", org, "certificate-authorities"] => {
            (*org, None, "/api/v1/orgs/{org}/certificate-authorities")
        }
        ["", "api", "v1", "orgs", org, "certificate-authorities", target] => {
            (*org, Some(*target), "/api/v1/orgs/{org}/certificate-authorities/{id}")
        }
        ["", "api", "v1", "orgs", org, "certificates"] => {
            (*org, None, "/api/v1/orgs/{org}/certificates")
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
    let (principal, expires_at) = match state
        .auth
        .authenticate_request(operation, &parts.method, &parts.uri, &parts.headers)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            let code = match error.status {
                StatusCode::FORBIDDEN => "policy.denied",
                StatusCode::SERVICE_UNAVAILABLE => "organization.storage_unavailable",
                _ => "auth.authentication_required",
            };
            return problem(error.status, code, false, &id);
        }
    };
    if let Some(endpoint) = admission
        && let Err(response) = team::admission(
            &state,
            endpoint,
            peer.ip(),
            Some(Uuid::from_bytes(principal.account_id)),
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
    if parts.headers.contains_key(header::IF_MATCH) {
        return invalid(&id);
    }
    macro_rules! store {($method:ident($($args:expr),* $(,)?))=>{match &state.backend{AuthBackend::Sqlite(store)=>store.$method($($args),*).await,AuthBackend::Postgres(store)=>store.$method($($args),*).await}};}
    if parts.method == "GET" {
        if parts.headers.contains_key("idempotency-key")
            || !to_bytes(body, 1).await.is_ok_and(|value| value.is_empty())
        {
            return invalid(&id);
        }
        if let Some(target) = target {
            if parts.uri.query().is_some() {
                return invalid(&id);
            }
            return match store!(read_organization_user_ca(&principal, expires_at, org, target)) {
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
        return match store!(list_organization_user_cas(&principal, expires_at, org, &query)) {
            Ok(value) => team::encoded(value.to_json(), None, StatusCode::OK, &id),
            Err(error) => store_problem(error, &id),
        };
    }
    if parts.uri.query().is_some() {
        return invalid(&id);
    }
    let key = match team::operation_key(&parts, &id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let issuance = operation == DeviceAccessOperation::UserCertificateIssue;
    let max =
        if issuance { MAX_CERTIFICATE_ISSUANCE_REQUEST_BYTES } else { MAX_USER_CA_CREATE_BYTES };
    let body = match team::body(&parts, body, max, &id).await {
        Ok(value) => value,
        Err(error) if issuance => {
            return problem(error.status(), "certificate.invalid_request", false, &id);
        }
        Err(error) => return error,
    };
    if !issuance {
        let Ok(request) = UserCaCreateRequest::from_json(body.as_bytes()) else {
            return invalid(&id);
        };
        return match store!(create_organization_user_ca(
            &principal,
            expires_at,
            &state.origin,
            org,
            key,
            &request,
            state.kms.as_ref()
        )) {
            Ok(value) => {
                team::encoded(value.to_json(), Some(&value.etag), StatusCode::CREATED, &id)
            }
            Err(error) => store_problem(error, &id),
        };
    }
    let Ok(request) = CertificateIssuanceRequest::from_json(body.as_bytes()) else {
        return problem(StatusCode::BAD_REQUEST, "certificate.invalid_request", false, &id);
    };
    match store!(issue_organization_user_certificate(
        &principal,
        expires_at,
        &state.origin,
        org,
        key,
        &request,
        peer.ip(),
        state.kms.as_ref()
    )) {
        Ok(value) => {
            let (Ok(body), Ok(etag)) = (value.to_json(), value.etag.parse()) else {
                return store_problem(OrganizationStoreError::StorageUnavailable, &id);
            };
            let mut result = reply(StatusCode::CREATED, "application/json", body, &id);
            result.headers_mut().insert(header::ETAG, etag);
            result
        }
        Err(error) => store_problem(error, &id),
    }
}
