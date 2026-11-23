// SPDX-License-Identifier: AGPL-3.0-only
//! Owner operations on an Organization's login connection and activation candidates.

use std::{error::Error as _, net::SocketAddr};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, MatchedPath, State},
    http::{Request, StatusCode, Uri, request::Parts},
    response::Response,
    routing::{delete, get, post},
};
use scoplen_api::{
    account_browser::AccountBrowserAccessOperation, auth_connection::ConnectionRequest,
    auth_connection_draft::DraftRequestError, organization::parse_organization_idempotency_key,
};
use scoplen_crypto::SecretVec;
use scoplen_store::{
    account_browser_sessions::CurrentAccountBrowserSession,
    account_entry_admission::AccountEntryEndpoint,
    organizations::{OrganizationStoreError, auth_connection::ActivationConfirmation},
};
use uuid::Uuid;

use super::{
    OrganizationState, auth_draft_login::fingerprint, browser_authority, invalid, problem, reply,
    specific_problem, store_problem, team, valid_encoding,
};
use crate::device_auth::AuthBackend;

const MAX_ACTIVATION_BODY: usize = 4_096;

macro_rules! store_call {
    ($state:expr, $method:ident($($argument:expr),* $(,)?)) => {
        match &$state.backend {
            AuthBackend::Sqlite(store) => store.$method($($argument),*).await,
            AuthBackend::Postgres(store) => store.$method($($argument),*).await,
        }
    };
}

mod activation;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/auth-connection", get(handle))
        .route("/api/v1/orgs/{org}/auth-connection/suspend", post(handle))
        .route("/api/v1/orgs/{org}/auth-connection/activations", post(handle))
        .route("/api/v1/orgs/{org}/auth-connection/activations/{attempt}", get(handle))
        .route("/api/v1/orgs/{org}/auth-connection/activations/{attempt}", delete(handle))
        .route("/api/v1/orgs/{org}/auth-connection/activations/{attempt}/confirm", post(handle))
}

async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<OrganizationState>,
    route: MatchedPath,
    request: Request<Body>,
) -> Response {
    use AccountBrowserAccessOperation::{
        AuthActivationAbandon, AuthActivationConfirm, AuthActivationRead, AuthActivationStart,
        AuthConnectionRead, AuthConnectionSuspend,
    };
    use AccountEntryEndpoint::{
        OrganizationAuthActivationAbandon, OrganizationAuthActivationConfirm,
        OrganizationAuthActivationStart, OrganizationAuthConnectionSuspend,
    };
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let Some(operation) =
        AccountBrowserAccessOperation::from_route(parts.method.as_str(), route.as_str())
    else {
        return invalid(&id);
    };
    let endpoint = match operation {
        AuthConnectionRead | AuthActivationRead => None,
        AuthActivationStart => Some(OrganizationAuthActivationStart),
        AuthActivationConfirm => Some(OrganizationAuthActivationConfirm),
        AuthActivationAbandon => Some(OrganizationAuthActivationAbandon),
        AuthConnectionSuspend => Some(OrganizationAuthConnectionSuspend),
        _ => return invalid(&id),
    };
    if let Some(endpoint) = endpoint
        && let Err(response) = team::admission(&state, endpoint, peer.ip(), None, &id).await
    {
        return response;
    }
    let session = match browser_authority(&state, operation, &parts, &id).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Some(endpoint) = endpoint
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
    let Some((organization, attempt)) = path_ids(&parts.uri) else {
        return invalid(&id);
    };
    let start = operation == AuthActivationStart;
    match decode_request(operation, &parts, body, start).await {
        Ok(request) => dispatch(&state, &session, organization, attempt, request, &id).await,
        Err(error) => request_problem(error, start || operation == AuthActivationConfirm, &id),
    }
}

fn path_ids(uri: &Uri) -> Option<(Uuid, Option<Uuid>)> {
    let (organization, resource) = uri.path().strip_prefix("/api/v1/orgs/")?.split_once('/')?;
    let organization = parse_organization_idempotency_key(organization).ok()?;
    let attempt = resource
        .strip_prefix("auth-connection/activations/")
        .map(|path| {
            parse_organization_idempotency_key(path.strip_suffix("/confirm").unwrap_or(path))
        })
        .transpose()
        .ok()?;
    Some((organization, attempt))
}

async fn decode_request(
    operation: AccountBrowserAccessOperation,
    parts: &Parts,
    body: Body,
    start: bool,
) -> Result<ConnectionRequest, DraftRequestError> {
    if !valid_encoding(&parts.headers) {
        return Err(DraftRequestError::Invalid);
    }
    let limit = if start { MAX_ACTIVATION_BODY } else { 0 };
    let raw = to_bytes(body, limit).await.map_err(|error| {
        if start
            && error
                .source()
                .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>)
        {
            DraftRequestError::TooLarge
        } else {
            DraftRequestError::Invalid
        }
    })?;
    let body = SecretVec::new(raw.into());
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default()));
    ConnectionRequest::from_http(operation, parts.uri.query(), headers, body.as_bytes())
}

async fn dispatch(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    organization: Uuid,
    attempt: Option<Uuid>,
    request: ConnectionRequest,
    id: &Uuid,
) -> Response {
    let suspend = matches!(&request, ConnectionRequest::Suspend { .. });
    let result = match (request, attempt) {
        (ConnectionRequest::Read, None) => {
            store_call!(state, read_organization_auth_connection(session, organization))
        }
        (ConnectionRequest::Suspend { revision, key }, None) => store_call!(
            state,
            suspend_organization_auth_connection(
                session,
                &state.origin,
                organization,
                revision,
                key
            )
        ),
        (ConnectionRequest::Start { expected, candidate }, None) => {
            return activation::start(state, session, organization, expected, &candidate, id).await;
        }
        (ConnectionRequest::Confirm { expected, key }, Some(attempt)) => {
            let confirmation = ActivationConfirmation { organization, attempt, expected, key };
            return activation::confirm(state, session, &confirmation, id).await;
        }
        (ConnectionRequest::ReadActivation, Some(attempt)) => {
            return match store_call!(
                state,
                organization_auth_activation_status(session, organization, attempt, |issuer| {
                    fingerprint(state, issuer)
                })
            ) {
                Ok(status) => team::encoded(status.to_json(), None, StatusCode::OK, id),
                Err(error) => store_problem(error, id),
            };
        }
        (ConnectionRequest::Abandon, Some(attempt)) => {
            return match store_call!(
                state,
                abandon_organization_auth_activation(session, organization, attempt)
            ) {
                Ok(()) => reply(StatusCode::NO_CONTENT, "application/json", Vec::new(), id),
                Err(OrganizationStoreError::CommitOutcomeUnknown) => specific_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "organization.commit_outcome_unknown",
                    "Activation abandonment unconfirmed",
                    "Check the original activation before deciding whether to abandon it again.",
                    true,
                    false,
                    id,
                ),
                Err(error) => store_problem(error, id),
            };
        }
        _ => return invalid(id),
    };
    match result {
        Ok(resource) => {
            let json = resource.to_json();
            if suspend && json.is_err() {
                return unconfirmed(id);
            }
            team::encoded(json, Some(&resource.etag()), StatusCode::OK, id)
        }
        Err(OrganizationStoreError::CommitOutcomeUnknown) if suspend => unconfirmed(id),
        Err(error) => store_problem(error, id),
    }
}

fn request_problem(error: DraftRequestError, supports_empty: bool, id: &Uuid) -> Response {
    match error {
        DraftRequestError::PreconditionRequired if supports_empty => specific_problem(
            StatusCode::PRECONDITION_REQUIRED,
            "organization.precondition_required",
            "Connection condition required",
            "Use If-None-Match: * for an empty slot or the current connection ETag in If-Match.",
            false,
            false,
            id,
        ),
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
