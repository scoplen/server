// SPDX-License-Identifier: AGPL-3.0-only
//! D-144 read-only timeline and contiguous original-byte verification.

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::get,
};
use scoplen_api::{
    audit::{
        AuditCodecError, AuditListQuery, AuditRange, MAX_AUDIT_QUERY_BYTES,
        MAX_AUDIT_RANGE_QUERY_BYTES,
    },
    auth::DeviceAccessOperation,
    organization::parse_organization_idempotency_key,
};
use scoplen_store::organizations::OrganizationStoreError;
use uuid::Uuid;

use super::{OrganizationState, invalid, problem, reply, store_problem};
use crate::device_auth::{AuthBackend, matching_origin};

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/audit-events", get(handle))
        .route("/api/v1/orgs/{org}/audit-events/verify", get(handle))
}

async fn handle(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN) && !matching_origin(&parts.headers, &state.origin)
    {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, &id);
    }
    let segments: Vec<_> = parts.uri.path().split('/').collect();
    let (organization, verify, template) = match segments.as_slice() {
        ["", "api", "v1", "orgs", org, "audit-events"] => {
            (*org, false, "/api/v1/orgs/{org}/audit-events")
        }
        ["", "api", "v1", "orgs", org, "audit-events", "verify"] => {
            (*org, true, "/api/v1/orgs/{org}/audit-events/verify")
        }
        _ => return invalid(&id),
    };
    let Some(operation) = DeviceAccessOperation::from_route(parts.method.as_str(), template) else {
        return invalid(&id);
    };
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
    let Ok(organization) = parse_organization_idempotency_key(organization) else {
        return invalid(&id);
    };
    if parts.headers.contains_key(header::IF_MATCH)
        || parts.headers.contains_key("idempotency-key")
        || !to_bytes(body, 1).await.is_ok_and(|body| body.is_empty())
    {
        return invalid(&id);
    }
    let max_query = if verify { MAX_AUDIT_RANGE_QUERY_BYTES } else { MAX_AUDIT_QUERY_BYTES };
    if parts.uri.query().is_some_and(|query| query.len() > 3 * max_query) {
        return codec_problem(AuditCodecError::TooLarge, &id);
    }
    let Ok(Query(pairs)) = Query::<Vec<(String, String)>>::try_from_uri(&parts.uri) else {
        return invalid(&id);
    };
    let parameters = pairs.iter().map(|(name, value)| (name.as_str(), value.as_str()));
    macro_rules! store {
        ($method:ident($($argument:expr),* $(,)?)) => {
            match &state.backend {
                AuthBackend::Sqlite(store) => store.$method($($argument),*).await,
                AuthBackend::Postgres(store) => store.$method($($argument),*).await,
            }
        };
    }
    let result = if verify {
        let range = match AuditRange::from_parameters(parameters) {
            Ok(range) => range,
            Err(error) => return codec_problem(error, &id),
        };
        store!(verify_organization_audit(
            &principal,
            expires_at,
            organization,
            range,
            &state.audit_verification_key,
        ))
        .and_then(|value| value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable))
    } else {
        let query = match AuditListQuery::from_parameters(parameters) {
            Ok(query) => query,
            Err(error) => return codec_problem(error, &id),
        };
        store!(list_organization_audit(&principal, expires_at, organization, &query)).and_then(
            |value| value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable),
        )
    };
    match result {
        Ok(bytes) => reply(StatusCode::OK, "application/json", bytes, &id),
        Err(error) => store_problem(error, &id),
    }
}

fn codec_problem(error: AuditCodecError, id: &Uuid) -> Response {
    if error == AuditCodecError::TooLarge {
        problem(StatusCode::PAYLOAD_TOO_LARGE, "organization.invalid_request", false, id)
    } else {
        invalid(id)
    }
}
