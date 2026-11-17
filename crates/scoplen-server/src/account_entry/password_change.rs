// SPDX-License-Identifier: AGPL-3.0-only
//! Native password change preserves the store-owned commit and confirmation boundary.

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
    account_password_change::{AccountPasswordChangeError, AccountPasswordChangeResult},
};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use super::{EntryState, Failure, deny_method, failure, metadata, secret_body, source_admission};
use crate::device_auth::{AuthBackend, response};

pub(super) fn routes() -> Router<Arc<EntryState>> {
    Router::new()
        .route("/api/v1/auth/accounts/password-changes", post(admit).fallback(method_denied))
}

impl From<AccountPasswordChangeError> for Failure {
    fn from(error: AccountPasswordChangeError) -> Self {
        match error {
            AccountPasswordChangeError::InvalidRequest => Self::Invalid,
            AccountPasswordChangeError::RequestTooLarge => Self::TooLarge,
            AccountPasswordChangeError::AuthenticationRequired => Self::Authentication,
            AccountPasswordChangeError::AdmissionConflict => Self::AdmissionConflict,
            AccountPasswordChangeError::QuotaExceeded => Self::Quota,
            AccountPasswordChangeError::RateLimited(wait) => Self::Rate(wait),
            AccountPasswordChangeError::StorageUnavailable => Self::Storage,
            AccountPasswordChangeError::CommitOutcomeUnknown => Self::CommitUnknown,
        }
    }
}

async fn admit(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let endpoint = AccountEntryEndpoint::PasswordChange;
    let id = Uuid::new_v4().to_string();
    if let Err(kind) = source_admission(&state, source, endpoint).await {
        return kind.problem(&id);
    }
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
    let deadline = Instant::now() + Duration::from_secs(15);
    let (limit, _) = AccountEntryOperation::PasswordChange.body_limits();
    if parts.headers.get(header::CONTENT_LENGTH).is_some_and(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limit as u64)
    }) {
        return failure(&state, source, endpoint, Failure::TooLarge, &id).await;
    }
    let body = match timeout_at(deadline, secret_body(body, limit)).await {
        Ok(Ok(body)) => body,
        Ok(Err(kind)) => return failure(&state, source, endpoint, kind, &id).await,
        Err(_) => return failure(&state, source, endpoint, Failure::Storage, &id).await,
    };
    let result = match &state.backend {
        AuthBackend::Sqlite(store) => {
            store
                .execute_account_password_change(source, &state.origin, body.as_bytes(), deadline)
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .execute_account_password_change(source, &state.origin, body.as_bytes(), deadline)
                .await
        }
    };
    match result {
        Ok(AccountPasswordChangeResult::Changed(body)) => {
            response(StatusCode::CREATED, "application/json", body)
        }
        Ok(AccountPasswordChangeResult::Confirmed(body)) => {
            response(StatusCode::OK, "application/json", body)
        }
        Err(error) => Failure::from(error).problem(&id),
    }
}

async fn method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    deny_method(&state, peer.ip(), AccountEntryEndpoint::PasswordChange).await
}
