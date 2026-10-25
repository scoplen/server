// SPDX-License-Identifier: AGPL-3.0-only
//! Native Device admission preserves the store-owned commit and confirmation boundary.

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
    account_device_admission::{AccountDeviceAdmissionError, AccountDeviceAdmissionResult},
    account_entry_admission::AccountEntryEndpoint,
};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use super::{EntryState, Failure, deny_method, failure, metadata, secret_body, source_admission};
use crate::device_auth::{AuthBackend, response};

pub(super) fn routes() -> Router<Arc<EntryState>> {
    Router::new()
        .route("/api/v1/auth/accounts/device-admissions", post(admit).fallback(method_denied))
}

impl From<AccountDeviceAdmissionError> for Failure {
    fn from(error: AccountDeviceAdmissionError) -> Self {
        match error {
            AccountDeviceAdmissionError::InvalidRequest => Self::Invalid,
            AccountDeviceAdmissionError::RequestTooLarge => Self::TooLarge,
            AccountDeviceAdmissionError::AuthenticationRequired => Self::Authentication,
            AccountDeviceAdmissionError::AdmissionConflict => Self::AdmissionConflict,
            AccountDeviceAdmissionError::QuotaExceeded => Self::Quota,
            AccountDeviceAdmissionError::RateLimited(wait) => Self::Rate(wait),
            AccountDeviceAdmissionError::StorageUnavailable => Self::Storage,
            AccountDeviceAdmissionError::CommitOutcomeUnknown => Self::CommitUnknown,
        }
    }
}

async fn admit(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
    request: Request<Body>,
) -> Response {
    let source = peer.ip();
    let endpoint = AccountEntryEndpoint::DeviceAdmission;
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
    let (limit, _) = AccountEntryOperation::DeviceAdmission.body_limits();
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
                .execute_account_device_admission(source, &state.origin, body.as_bytes(), deadline)
                .await
        }
        AuthBackend::Postgres(store) => {
            store
                .execute_account_device_admission(source, &state.origin, body.as_bytes(), deadline)
                .await
        }
    };
    match result {
        Ok(AccountDeviceAdmissionResult::Admitted(body)) => {
            response(StatusCode::CREATED, "application/json", body)
        }
        Ok(AccountDeviceAdmissionResult::Confirmed(body)) => {
            response(StatusCode::OK, "application/json", body)
        }
        Err(error) => Failure::from(error).problem(&id),
    }
}

async fn method_denied(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<EntryState>>,
) -> Response {
    deny_method(&state, peer.ip(), AccountEntryEndpoint::DeviceAdmission).await
}
