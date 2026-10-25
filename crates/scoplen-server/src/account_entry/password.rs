// SPDX-License-Identifier: AGPL-3.0-only
//! Native password entry discloses attempts and bootstrap only after confirmed storage.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode, header},
    response::Response,
    routing::post,
};
use scoplen_api::account_admission::AccountEntryOperation;
use scoplen_store::{
    account_entry_admission::AccountEntryEndpoint,
    account_password_login::AccountPasswordLoginError,
};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use super::{EntryState, Failure, failure, metadata, secret_body, source_admission};
use crate::device_auth::{AuthBackend, response};

pub(super) fn routes() -> Router<Arc<EntryState>> {
    Router::new()
        .route(
            "/api/v1/auth/accounts/password/options",
            post(options).fallback(options_method_denied),
        )
        .route("/api/v1/auth/accounts/password/login", post(login).fallback(login_method_denied))
}

fn password_failure(error: &AccountPasswordLoginError) -> Failure {
    match error {
        AccountPasswordLoginError::InvalidRequest => Failure::Invalid,
        AccountPasswordLoginError::RequestTooLarge => Failure::TooLarge,
        AccountPasswordLoginError::AuthenticationRequired => Failure::Authentication,
        AccountPasswordLoginError::AdmissionConflict => Failure::AdmissionConflict,
        AccountPasswordLoginError::RateLimited(wait) => Failure::Rate(*wait),
        AccountPasswordLoginError::StorageUnavailable => Failure::Storage,
    }
}

fn excessive_length(request: &Request<Body>, limit: usize) -> bool {
    request.headers().get(header::CONTENT_LENGTH).is_some_and(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limit as u64)
    })
}

pub(super) async fn options(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let endpoint = AccountEntryEndpoint::PasswordOptions;
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(&state, source, endpoint).await {
        return kind.problem(&id);
    }
    let (limit, _) = AccountEntryOperation::PasswordOptions.body_limits();
    let oversized = excessive_length(&request, limit);
    let (parts, body) = request.into_parts();
    if let Err(kind) = metadata(&parts, &state.origin) {
        return failure(&state, source, endpoint, kind, &id).await;
    }
    if oversized {
        return failure(&state, source, endpoint, Failure::TooLarge, &id).await;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let body = match timeout_at(deadline, secret_body(body, limit)).await {
        Ok(Ok(body)) => body,
        Ok(Err(kind)) => return failure(&state, source, endpoint, kind, &id).await,
        Err(_) => return failure(&state, source, endpoint, Failure::Storage, &id).await,
    };
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store
                .issue_account_password_options(
                    source,
                    &state.origin,
                    body.as_bytes(),
                    state.kms.as_ref(),
                    deadline,
                )
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .issue_account_password_options(
                    source,
                    &state.origin,
                    body.as_bytes(),
                    state.kms.as_ref(),
                    deadline,
                )
                .await
        }
    };
    match result {
        Ok(issued) => match issued.to_json() {
            Ok(body) => response(StatusCode::OK, "application/json", body),
            Err(_) => failure(&state, source, endpoint, Failure::Storage, &id).await,
        },
        Err(error) => password_failure(&error).problem(&id),
    }
}

pub(super) async fn login(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let endpoint = AccountEntryEndpoint::PasswordLogin;
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(&state, source, endpoint).await {
        return kind.problem(&id);
    }
    let (limit, _) = AccountEntryOperation::PasswordLogin.body_limits();
    let oversized = excessive_length(&request, limit);
    let (parts, body) = request.into_parts();
    if let Err(kind) = metadata(&parts, &state.origin) {
        return failure(&state, source, endpoint, kind, &id).await;
    }
    let _permit = match state.proof_jobs.try_acquire() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return failure(&state, source, endpoint, Failure::Rate(1), &id).await;
        }
        Err(tokio::sync::TryAcquireError::Closed) => {
            return failure(&state, source, endpoint, Failure::Storage, &id).await;
        }
    };
    if oversized {
        return failure(&state, source, endpoint, Failure::TooLarge, &id).await;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let body = match timeout_at(deadline, secret_body(body, limit)).await {
        Ok(Ok(body)) => body,
        Ok(Err(kind)) => return failure(&state, source, endpoint, kind, &id).await,
        Err(_) => return failure(&state, source, endpoint, Failure::Storage, &id).await,
    };
    // The store owns the only AuthSecret-bearing request buffer and its commit boundary.
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store
                .execute_account_password_login(
                    source,
                    &state.origin,
                    body,
                    state.kms.as_ref(),
                    deadline,
                )
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .execute_account_password_login(
                    source,
                    &state.origin,
                    body,
                    state.kms.as_ref(),
                    deadline,
                )
                .await
        }
    };
    match result {
        Ok(authenticated) => match authenticated.to_json() {
            Ok(body) => response(StatusCode::OK, "application/json", body),
            Err(_) => failure(&state, source, endpoint, Failure::Storage, &id).await,
        },
        Err(error) => password_failure(&error).problem(&id),
    }
}

pub(super) async fn options_method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    deny_method(&state, peer, AccountEntryEndpoint::PasswordOptions).await
}

pub(super) async fn login_method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    deny_method(&state, peer, AccountEntryEndpoint::PasswordLogin).await
}

async fn deny_method(
    state: &EntryState,
    peer: SocketAddr,
    endpoint: AccountEntryEndpoint,
) -> Response {
    let source = peer.ip();
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(state, source, endpoint).await {
        return kind.problem(&id);
    }
    failure(state, source, endpoint, Failure::Method, &id).await
}

#[cfg(test)]
mod tests;
