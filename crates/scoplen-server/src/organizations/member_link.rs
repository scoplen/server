// SPDX-License-Identifier: AGPL-3.0-only
//! Native member linking through the active Organization connection.

use std::net::SocketAddr;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, MatchedPath, State},
    http::{Request, StatusCode, Uri, header},
    response::Response,
    routing::{delete, get, post},
};
use scoplen_api::{
    account_browser::AccountBrowserAccessOperation,
    auth_connection::ConnectionTarget,
    auth_connection_draft::{
        DraftRequestError,
        callback::{Callback, member_link_cookie_name},
    },
    member_link::{LinkAction, MemberLinkRequest},
};
use scoplen_crypto::random_key;
use scoplen_store::{
    account_browser_sessions::CurrentAccountBrowserSession,
    account_entry_admission::AccountEntryEndpoint,
    organizations::{
        OrganizationStoreError as StoreError,
        auth_draft_login::DraftLoginProvider,
        member_link::{LinkClaim, LinkOutcome, LinkStart},
    },
};
use uuid::Uuid;

use super::{
    OrganizationState,
    auth_draft_login::{authorization_url, callback_cookie, fingerprint},
    browser_authority, invalid, problem, reply, specific_problem, store_problem, team,
    valid_encoding,
};
use crate::{
    device_auth::AuthBackend,
    oidc::{DraftExchangeError, verify_claimed_member_link},
};

macro_rules! store_call {
    ($state:expr, $method:ident($($argument:expr),* $(,)?)) => {
        match &$state.backend {
            AuthBackend::Sqlite(store) => store.$method($($argument),*).await,
            AuthBackend::Postgres(store) => store.$method($($argument),*).await,
        }
    };
}

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/auth-link", get(handle))
        .route("/api/v1/orgs/{org}/auth-link", delete(handle))
        .route("/api/v1/orgs/{org}/auth-link/attempts", post(handle))
        .route("/api/v1/orgs/{org}/auth-link/attempts/{attempt}", get(handle))
        .route("/api/v1/orgs/{org}/auth-link/attempts/{attempt}", delete(handle))
        .route("/api/v1/orgs/{org}/auth-link/attempts/{attempt}/confirm", post(handle))
        .route("/api/v1/orgs/{org}/members/{membership}/auth-link", get(handle))
        .route("/api/v1/orgs/{org}/members/{membership}/auth-link", delete(handle))
}

async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<OrganizationState>,
    route: MatchedPath,
    request: Request<Body>,
) -> Response {
    use AccountBrowserAccessOperation::{
        AuthLinkAbandon, AuthLinkAttemptRead, AuthLinkConfirm, AuthLinkNamedRead,
        AuthLinkNamedWithdraw, AuthLinkSelfRead, AuthLinkSelfUnlink, AuthLinkStart,
    };
    use AccountEntryEndpoint::{
        OrganizationAuthLinkAbandon, OrganizationAuthLinkConfirm, OrganizationAuthLinkStart,
        OrganizationAuthLinkUnlink, OrganizationAuthLinkWithdraw,
    };

    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let Some(operation) =
        AccountBrowserAccessOperation::from_route(parts.method.as_str(), route.as_str())
    else {
        return invalid(&id);
    };
    let endpoint = match operation {
        AuthLinkSelfRead | AuthLinkNamedRead | AuthLinkAttemptRead => None,
        AuthLinkStart => Some(OrganizationAuthLinkStart),
        AuthLinkAbandon => Some(OrganizationAuthLinkAbandon),
        AuthLinkConfirm => Some(OrganizationAuthLinkConfirm),
        AuthLinkSelfUnlink => Some(OrganizationAuthLinkUnlink),
        AuthLinkNamedWithdraw => Some(OrganizationAuthLinkWithdraw),
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
    let Some((organization, target)) = path_captures(&parts.uri) else {
        return invalid(&id);
    };
    if !valid_encoding(&parts.headers) || to_bytes(body, 0).await.is_err() {
        return invalid(&id);
    }
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default()));
    match MemberLinkRequest::from_http(
        operation,
        organization,
        target,
        parts.uri.query(),
        headers,
        &[],
    ) {
        Ok(request) => dispatch(&state, &session, request, &id).await,
        Err(DraftRequestError::PreconditionRequired) => problem(
            StatusCode::PRECONDITION_REQUIRED,
            "organization.precondition_required",
            false,
            &id,
        ),
        Err(_) => invalid(&id),
    }
}

fn path_captures(uri: &Uri) -> Option<(&str, Option<&str>)> {
    let path = uri.path().strip_prefix("/api/v1/orgs/")?;
    let (organization, resource) = path.split_once('/')?;
    let target = resource
        .strip_prefix("auth-link/attempts/")
        .map(|value| value.strip_suffix("/confirm").unwrap_or(value))
        .or_else(|| resource.strip_prefix("members/")?.strip_suffix("/auth-link"));
    Some((organization, target))
}

async fn dispatch(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    request: MemberLinkRequest,
    id: &Uuid,
) -> Response {
    let organization = request.organization_id;
    let trust = |issuer: &str| fingerprint(state, issuer);
    let read = |json| team::encoded(json, None, StatusCode::OK, id);
    match request.action {
        LinkAction::ReadSelf => {
            match store_call!(state, self_member_link_status(session, organization)) {
                Ok(status) => read(status.to_json()),
                Err(error) => store_problem(error, id),
            }
        }
        LinkAction::ReadNamed { membership } => {
            match store_call!(state, named_member_link_status(session, organization, membership)) {
                Ok(status) => read(status.to_json()),
                Err(error) => store_problem(error, id),
            }
        }
        LinkAction::Start { revision } => start(state, session, organization, revision, id).await,
        LinkAction::ReadAttempt { attempt } => {
            match store_call!(
                state,
                member_link_attempt_status(session, organization, attempt, trust)
            ) {
                Ok(status) => read(status.to_json()),
                Err(error) => store_problem(error, id),
            }
        }
        LinkAction::Confirm { attempt, revision, key } => {
            match store_call!(
                state,
                confirm_member_link(session, organization, attempt, revision, key, trust)
            ) {
                Ok(link) => {
                    team::encoded(link.to_json(), Some(&link.etag()), StatusCode::CREATED, id)
                }
                Err(StoreError::CommitOutcomeUnknown) => specific_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "organization.commit_outcome_unknown",
                    "Identity link confirmation unconfirmed",
                    "Within the original sign-in window, explicitly retry with the original key and If-Match and a fresh proof.",
                    true,
                    true,
                    id,
                ),
                Err(error) => store_problem(error, id),
            }
        }
        LinkAction::Abandon { attempt } => {
            empty(store_call!(state, abandon_member_link(session, organization, attempt)), id)
        }
        LinkAction::UnlinkSelf { link } => {
            empty(store_call!(state, withdraw_member_link(session, organization, None, link)), id)
        }
        LinkAction::WithdrawNamed { membership, link } => empty(
            store_call!(state, withdraw_member_link(session, organization, Some(membership), link)),
            id,
        ),
    }
}

fn empty(result: Result<(), StoreError>, id: &Uuid) -> Response {
    match result {
        Ok(()) => reply(StatusCode::NO_CONTENT, "application/json", Vec::new(), id),
        Err(error) => store_problem(error, id),
    }
}

async fn start(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    organization: Uuid,
    revision: Uuid,
    id: &Uuid,
) -> Response {
    let [Ok(state_proof), Ok(browser_binding), Ok(nonce), Ok(verifier)] =
        std::array::from_fn(|_| random_key())
    else {
        return store_problem(StoreError::StorageUnavailable, id);
    };
    let start = LinkStart {
        organization,
        revision,
        state: &state_proof,
        browser_binding: &browser_binding,
        nonce: &nonce,
        verifier: &verifier,
    };
    let mut issuer = None;
    let navigate = |target: &ConnectionTarget, provider: &DraftLoginProvider| {
        issuer = Some(target.issuer.clone());
        authorization_url(
            &state.origin,
            &target.issuer,
            &provider.authorization_endpoint,
            target.client_id.as_bytes(),
            &verifier,
            &state_proof,
            &nonce,
        )
        .ok_or(StoreError::StorageUnavailable)
    };
    let attempt = store_call!(
        state,
        start_member_link(
            session,
            &start,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref(),
            navigate
        )
    );
    let started = match attempt {
        Ok(started) => started,
        Err(StoreError::CommitOutcomeUnknown | StoreError::UpdateCommitOutcomeUnknown) => {
            return start_unconfirmed(id);
        }
        Err(error) => return store_problem(error, id),
    };
    let name = member_link_cookie_name(&state_proof);
    let Some(cookie) = callback_cookie(&name, &browser_binding, &started.attempt.expires_at) else {
        return start_unconfirmed(id);
    };
    let Some(body) = issuer.as_deref().and_then(|value| started.to_json(value).ok()) else {
        return start_unconfirmed(id);
    };
    let mut response = reply(StatusCode::CREATED, "application/json", body.as_bytes().to_vec(), id);
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

fn start_unconfirmed(id: &Uuid) -> Response {
    specific_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "organization.commit_outcome_unknown",
        "Identity link attempt unconfirmed",
        "Wait for the pending attempt to expire before starting again.",
        true,
        false,
        id,
    )
}

pub(super) async fn finish_callback(state: &OrganizationState, callback: Callback<'_>) -> bool {
    let claimed = store_call!(
        state,
        claim_member_link(
            &state.origin,
            callback,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref()
        )
    );
    match claimed {
        Ok(LinkClaim::Denied) => true,
        Ok(LinkClaim::Exchange(mut attempt)) => {
            let outcome =
                match verify_claimed_member_link(&state.enterprise_identity, &mut attempt).await {
                    Ok(subject) => LinkOutcome::Verified(subject),
                    Err(DraftExchangeError::InvalidIdentity) => LinkOutcome::InvalidIdentity,
                    Err(_) => LinkOutcome::ExchangeFailed,
                };
            let _ = store_call!(
                state,
                finish_member_link(
                    &state.origin,
                    &attempt,
                    |issuer| fingerprint(state, issuer),
                    outcome,
                    state.kms.as_ref()
                )
            );
            true
        }
        Err(_) => false,
    }
}
