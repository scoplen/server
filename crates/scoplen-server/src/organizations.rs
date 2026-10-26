// SPDX-License-Identifier: AGPL-3.0-only
//! Native Account team creation and caller-only membership discovery.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::DeviceAccessOperation,
    organization::{
        MAX_ORGANIZATION_CREATE_BYTES, OrganizationCreateRequest, OrganizationListQuery,
        parse_organization_idempotency_key,
    },
};
use scoplen_store::{kms::LocalKeyFile, organizations::OrganizationStoreError};
use uuid::Uuid;

use crate::{
    OrganizationSettings,
    device_auth::{AuthBackend, json_body, matching_origin, response},
    personal_sync::PersonalSyncAuthenticator,
};

#[derive(Clone)]
struct OrganizationState {
    backend: AuthBackend,
    auth: PersonalSyncAuthenticator,
    origin: String,
    policy: OrganizationSettings,
}

pub(crate) fn router(
    origin: String,
    backend: AuthBackend,
    kms: Arc<LocalKeyFile>,
    policy: OrganizationSettings,
) -> Router {
    let auth = PersonalSyncAuthenticator::new(backend.clone(), kms, origin.clone());
    Router::new()
        .route("/api/v1/orgs", post(create))
        .route("/api/v1/orgs", get(list))
        .route("/api/v1/orgs/{org}", get(read))
        .with_state(OrganizationState { backend, auth, origin, policy })
}

async fn create(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    handle(state, request, DeviceAccessOperation::OrganizationCreate).await
}

async fn list(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    handle(state, request, DeviceAccessOperation::OrganizationList).await
}

async fn read(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    handle(state, request, DeviceAccessOperation::OrganizationRead).await
}

#[allow(clippy::too_many_lines)]
async fn handle(
    state: OrganizationState,
    request: Request<Body>,
    operation: DeviceAccessOperation,
) -> Response {
    let request_id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    if parts.headers.contains_key(header::ORIGIN) && !matching_origin(&parts.headers, &state.origin)
    {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, &request_id);
    }
    let (principal, expires_at) = match state
        .auth
        .authenticate_request(operation, &parts.method, &parts.uri, &parts.headers)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            let (status, code) = match error.status {
                StatusCode::FORBIDDEN => (StatusCode::FORBIDDEN, "policy.denied"),
                StatusCode::SERVICE_UNAVAILABLE => {
                    (StatusCode::SERVICE_UNAVAILABLE, "organization.storage_unavailable")
                }
                _ => (StatusCode::UNAUTHORIZED, "auth.authentication_required"),
            };
            return problem(status, code, false, &request_id);
        }
    };
    if parts.headers.contains_key(header::IF_MATCH) {
        return invalid(&request_id);
    }
    match operation {
        DeviceAccessOperation::OrganizationCreate => {
            if parts.uri.query().is_some()
                || parts.headers.get_all("idempotency-key").iter().count() != 1
            {
                return invalid(&request_id);
            }
            let key = parts
                .headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| parse_organization_idempotency_key(value).ok());
            let Some(key) = key else { return invalid(&request_id) };
            let body = match json_body(&parts.headers, body, MAX_ORGANIZATION_CREATE_BYTES).await {
                Ok(value) => value,
                Err(StatusCode::UNSUPPORTED_MEDIA_TYPE) => {
                    return problem(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "organization.invalid_request",
                        false,
                        &request_id,
                    );
                }
                Err(_) => return invalid(&request_id),
            };
            let Ok(decoded) = OrganizationCreateRequest::from_json(body.as_bytes()) else {
                return invalid(&request_id);
            };
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => {
                    store
                        .create_organization(
                            &principal,
                            expires_at,
                            state.policy.allow_creation,
                            key,
                            &decoded,
                        )
                        .await
                }
                AuthBackend::Postgres(store) => {
                    store
                        .create_organization(
                            &principal,
                            expires_at,
                            state.policy.allow_creation,
                            key,
                            &decoded,
                        )
                        .await
                }
            };
            resource_response(result, StatusCode::CREATED, &request_id)
        }
        DeviceAccessOperation::OrganizationList | DeviceAccessOperation::OrganizationRead => {
            if parts.headers.contains_key("idempotency-key") || to_bytes(body, 0).await.is_err() {
                return invalid(&request_id);
            }
            if operation == DeviceAccessOperation::OrganizationRead {
                if parts.uri.query().is_some() {
                    return invalid(&request_id);
                }
                let id = parts
                    .uri
                    .path()
                    .strip_prefix("/api/v1/orgs/")
                    .and_then(|value| parse_organization_idempotency_key(value).ok());
                let Some(id) = id else { return invalid(&request_id) };
                let result = match &state.backend {
                    AuthBackend::Sqlite(store) => {
                        store.read_organization(&principal, expires_at, id).await
                    }
                    AuthBackend::Postgres(store) => {
                        store.read_organization(&principal, expires_at, id).await
                    }
                };
                return resource_response(result, StatusCode::OK, &request_id);
            }
            let parameters = Query::<Vec<(String, String)>>::try_from_uri(&parts.uri);
            let Ok(Query(parameters)) = parameters else { return invalid(&request_id) };
            let query = OrganizationListQuery::from_parameters(
                parameters.iter().map(|(name, value)| (name.as_str(), value.as_str())),
            );
            let Ok(query) = query else { return invalid(&request_id) };
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => {
                    store.list_organizations(&principal, expires_at, query).await
                }
                AuthBackend::Postgres(store) => {
                    store.list_organizations(&principal, expires_at, query).await
                }
            };
            match result {
                Ok(page) => match page.to_json() {
                    Ok(body) => reply(StatusCode::OK, "application/json", body, &request_id),
                    Err(_) => {
                        store_problem(OrganizationStoreError::StorageUnavailable, &request_id)
                    }
                },
                Err(error) => store_problem(error, &request_id),
            }
        }
        _ => invalid(&request_id),
    }
}

fn resource_response(
    result: Result<scoplen_api::organization::OrganizationResource, OrganizationStoreError>,
    status: StatusCode,
    request_id: &Uuid,
) -> Response {
    let value = match result {
        Ok(value) => value,
        Err(error) => return store_problem(error, request_id),
    };
    let (Ok(body), Ok(etag)) = (value.to_json(), value.etag.parse()) else {
        return store_problem(OrganizationStoreError::StorageUnavailable, request_id);
    };
    let mut result = reply(status, "application/json", body, request_id);
    result.headers_mut().insert(header::ETAG, etag);
    result
}

fn store_problem(error: OrganizationStoreError, request_id: &Uuid) -> Response {
    let (status, code, changed) = match error {
        OrganizationStoreError::InvalidRequest => return invalid(request_id),
        OrganizationStoreError::AuthenticationRequired => {
            (StatusCode::UNAUTHORIZED, "auth.authentication_required", false)
        }
        OrganizationStoreError::CreationDisabled => (StatusCode::FORBIDDEN, "policy.denied", false),
        OrganizationStoreError::NotFound => {
            (StatusCode::NOT_FOUND, "organization.not_found", false)
        }
        OrganizationStoreError::Conflict => (StatusCode::CONFLICT, "organization.conflict", false),
        OrganizationStoreError::StorageUnavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "organization.storage_unavailable", false)
        }
        OrganizationStoreError::CommitOutcomeUnknown => {
            (StatusCode::SERVICE_UNAVAILABLE, "organization.commit_outcome_unknown", true)
        }
    };
    problem(status, code, changed, request_id)
}

fn invalid(request_id: &Uuid) -> Response {
    problem(StatusCode::BAD_REQUEST, "organization.invalid_request", false, request_id)
}

fn problem(status: StatusCode, code: &str, changed: bool, request_id: &Uuid) -> Response {
    let (title, detail) = match code {
        "organization.not_found" => ("Team not found", "The requested team is unavailable."),
        "organization.conflict" => (
            "Team creation conflict",
            "Retain the original creation key and name; this key already belongs to another payload.",
        ),
        "organization.commit_outcome_unknown" => (
            "Team creation unconfirmed",
            "Retry the original key and name with a fresh proof within the original 24-hour window.",
        ),
        "organization.storage_unavailable" => (
            "Teams unavailable",
            "Retry with a fresh proof, preserving the original creation key and name when applicable.",
        ),
        "policy.denied" => (
            "Access denied",
            "Obtain a permitted Device session or contact the deployment administrator.",
        ),
        "auth.authentication_required" => (
            "Authentication required",
            "Authenticate the enrolled Device and create a fresh request proof.",
        ),
        _ => ("Invalid team request", "Correct the team name, route, query or request headers."),
    };
    let details = ProblemDetails::new(
        ErrorCode::new(code).expect("static organization code"),
        status.as_u16(),
        title,
        detail,
        request_id.to_string(),
        changed,
        status.is_server_error(),
    )
    .expect("static organization problem");
    reply(
        status,
        "application/problem+json",
        serde_json::to_vec(&details).expect("serializable problem"),
        request_id,
    )
}

fn reply(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    request_id: &Uuid,
) -> Response {
    let mut result = response(status, content_type, body);
    result
        .headers_mut()
        .insert("x-request-id", request_id.to_string().parse().expect("UUID header"));
    result
}
