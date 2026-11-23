// SPDX-License-Identifier: AGPL-3.0-only
//! Trusted discovery and one-time navigation for a reviewed connection candidate.

use axum::{
    body::{Body, Bytes},
    http::{StatusCode, header},
    response::Response,
};
use scoplen_api::{
    auth_connection::{
        Activation, ActivationCandidate, ActivationContext, ActivationStarted, ConnectionTarget,
        ExpectedRevision,
    },
    auth_connection_draft::{callback::activation_cookie_name, test_login::DraftLoginStatus},
};
use scoplen_crypto::random_key;
use scoplen_store::{
    account_browser_sessions::CurrentAccountBrowserSession,
    organizations::{
        OrganizationStoreError as StoreError,
        auth_connection::{
            ACTIVATION_PREFLIGHT_LIFETIME, ActivationConfirmation, ActivationPreflight,
            ConnectionActivationStart,
        },
    },
};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use super::{
    AuthBackend, OrganizationState, fingerprint, invalid, reply, specific_problem, store_problem,
    team,
};
use crate::{
    oidc::{DiscoveryError, TrustedIssuer},
    organizations::auth_draft_login::{
        authorization_url, callback_cookie, discovery_problem, login_provider,
    },
};

pub(super) async fn start(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    organization: Uuid,
    expected: ExpectedRevision,
    candidate: &ActivationCandidate,
    id: &Uuid,
) -> Response {
    // Start the local deadline before acquisition, so it cannot outlive the database lease.
    let deadline = Instant::now() + ACTIVATION_PREFLIGHT_LIFETIME;
    let preflight = match store_call!(
        state,
        reserve_organization_auth_activation(
            session,
            organization,
            expected,
            candidate.draft_generation
        )
    ) {
        Ok(preflight) => preflight,
        Err(error) => return store_problem(error, id),
    };
    let response = start_admitted(
        state,
        session,
        (organization, expected),
        candidate,
        &preflight,
        deadline,
        id,
    )
    .await;
    if response.status() != StatusCode::CREATED
        && let Err(error) = store_call!(state, release_organization_auth_activation(&preflight))
    {
        tracing::warn!(%error, "connection activation preflight could not be released");
    }
    response
}

async fn start_admitted(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    (organization, expected): (Uuid, ExpectedRevision),
    candidate: &ActivationCandidate,
    preflight: &ActivationPreflight,
    deadline: Instant,
    id: &Uuid,
) -> Response {
    let issuer = preflight.issuer();
    let trusted = match TrustedIssuer::from_settings(&state.enterprise_identity, issuer) {
        Ok(trusted) => trusted,
        Err(error) => return discovery_problem(error, id),
    };
    if Instant::now() >= deadline {
        return discovery_problem(DiscoveryError::Unavailable, id);
    }
    let provider = match timeout_at(deadline, trusted.discover()).await {
        Ok(Ok(metadata)) => login_provider(metadata),
        Ok(Err(error)) => return discovery_problem(error, id),
        Err(_) => return discovery_problem(DiscoveryError::Unavailable, id),
    };
    let [Ok(state_proof), Ok(nonce), Ok(verifier), Ok(browser_binding)] =
        std::array::from_fn(|_| random_key())
    else {
        return store_problem(StoreError::StorageUnavailable, id);
    };
    let client_id = &candidate.credentials.client_id;
    let Some(authorization_url) = authorization_url(
        &state.origin,
        issuer,
        &provider.authorization_endpoint,
        client_id,
        &verifier,
        &state_proof,
        &nonce,
    ) else {
        return discovery_problem(DiscoveryError::Incompatible, id);
    };
    let Ok(client_id) = std::str::from_utf8(client_id.as_bytes()) else { return invalid(id) };
    // Check the complete response before writing. A UUID and the widest millisecond
    // UTC timestamp reserve the wire space for fields allocated in the transaction.
    let mut response = ActivationStarted {
        attempt: Activation {
            id: Uuid::now_v7(),
            context: ActivationContext {
                organization_id: organization,
                draft_generation: candidate.draft_generation,
                expected_revision: expected,
                target: ConnectionTarget {
                    issuer: issuer.to_owned(),
                    client_id: client_id.to_owned(),
                    space_id: candidate.space_id.clone(),
                },
            },
            status: DraftLoginStatus::Pending,
            expires_at: "9999-12-31T23:59:59.999Z".into(),
        },
        authorization_url,
    };
    if response.to_json().is_err() {
        return discovery_problem(DiscoveryError::Incompatible, id);
    }
    let start = ConnectionActivationStart {
        preflight,
        candidate,
        provider: &provider,
        trust_fingerprint: trusted.fingerprint(),
        state: &state_proof,
        browser_binding: &browser_binding,
        nonce: &nonce,
        verifier: &verifier,
    };
    response.attempt = match store_call!(
        state,
        start_organization_auth_activation(
            session,
            &start,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref()
        )
    ) {
        Ok(attempt) => attempt,
        Err(StoreError::CommitOutcomeUnknown) => return unconfirmed(id),
        Err(error) => return store_problem(error, id),
    };
    let name = activation_cookie_name(&state_proof);
    let Some(cookie) = callback_cookie(&name, &browser_binding, &response.attempt.expires_at)
    else {
        return unconfirmed(id);
    };
    let Ok(body) = response.to_json() else { return unconfirmed(id) };
    let mut response = reply(StatusCode::CREATED, "application/json", Vec::new(), id);
    *response.body_mut() = Body::from(Bytes::from_owner(body));
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

pub(super) async fn confirm(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    confirmation: &ActivationConfirmation,
    id: &Uuid,
) -> Response {
    let unconfirmed = || {
        specific_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "organization.commit_outcome_unknown",
            "Connection activation unconfirmed",
            "Only the original browser session can confirm this activation. If its password proof is still fresh, retry explicitly with the original key and condition and a fresh DPoP proof. Read the connection for its current state.",
            true,
            true,
            id,
        )
    };
    match store_call!(
        state,
        confirm_organization_auth_activation(
            session,
            confirmation,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref()
        )
    ) {
        Ok(resource) => {
            let body = resource.to_json();
            if body.is_err() {
                return unconfirmed();
            }
            team::encoded(body, Some(&resource.etag()), StatusCode::OK, id)
        }
        Err(StoreError::CommitOutcomeUnknown) => unconfirmed(),
        Err(error) => store_problem(error, id),
    }
}

fn unconfirmed(id: &Uuid) -> Response {
    specific_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "organization.commit_outcome_unknown",
        "Activation start unconfirmed",
        "Wait for the pending activation to expire before starting another.",
        true,
        false,
        id,
    )
}
