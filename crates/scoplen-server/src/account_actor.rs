// SPDX-License-Identifier: AGPL-3.0-only
//! Select native Device or finite Account-browser business authority without profile fallback.

use std::sync::Arc;

use axum::http::{HeaderMap, Method, StatusCode, Uri};
use scoplen_api::{
    account_browser::{
        AccountBrowserAccessOperation, AccountBrowserAccessRequirement, AccountBrowserCodecError,
        AccountBrowserProtectedHttpMetadata,
    },
    auth::DeviceAccessOperation,
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use scoplen_store::{
    account_browser_sessions::AccountBrowserSessionError,
    device_authentication::DeviceAuthenticationError, kms::LocalKeyFile,
    organizations::OrganizationActor,
};
use scoplen_sync::http::AuthFailure;

use crate::{device_auth::AuthBackend, personal_sync::PersonalSyncAuthenticator};

#[derive(Clone)]
pub(crate) struct AccountActorAuthenticator {
    backend: AuthBackend,
    native: PersonalSyncAuthenticator,
    origin: String,
}

impl AccountActorAuthenticator {
    pub(crate) fn new(backend: AuthBackend, kms: Arc<LocalKeyFile>, origin: String) -> Self {
        let native = PersonalSyncAuthenticator::new(backend.clone(), kms, origin.clone());
        Self { backend, native, origin }
    }

    pub(crate) async fn authenticate_request(
        &self,
        operation: DeviceAccessOperation,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<(OrganizationActor, u64), AuthFailure> {
        self.authenticate_request_with_scopes(operation, method, uri, headers)
            .await
            .map(|(actor, expires, _)| (actor, expires))
    }

    pub(crate) async fn authenticate_request_with_scopes(
        &self,
        operation: DeviceAccessOperation,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<(OrganizationActor, u64, String), AuthFailure> {
        let authorization =
            one(headers, "authorization")?.ok_or_else(|| failure(StatusCode::UNAUTHORIZED))?;
        if !authorization.starts_with("DPoP ab1_") {
            return self
                .native
                .authenticate_request_with_scopes(operation, method, uri, headers)
                .await
                .map(|(principal, expires, scope)| {
                    (OrganizationActor::Device(principal), expires, scope)
                });
        }
        let browser_operation = AccountBrowserAccessOperation::from_route(
            operation.http_method(),
            operation.route_template(),
        )
        .filter(|value| value.http_method() == method.as_str())
        .ok_or_else(|| failure(StatusCode::FORBIDDEN))?;
        let token = AccountBrowserProtectedHttpMetadata {
            authorization,
            dpop: one(headers, "dpop")?.ok_or_else(|| failure(StatusCode::UNAUTHORIZED))?,
            origin: one(headers, "origin")?,
        }
        .validate(browser_operation, &self.origin)
        .map_err(|error| {
            failure(if error == AccountBrowserCodecError::OriginDenied {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            })
        })?;
        let current = match &self.backend {
            AuthBackend::Sqlite(store) => {
                store.current_account_browser_session(&token, &self.origin).await
            }
            AuthBackend::Postgres(store) => {
                store.current_account_browser_session(&token, &self.origin).await
            }
        }
        .map_err(|error| match error {
            AccountBrowserSessionError::Denied { .. } => failure(StatusCode::UNAUTHORIZED),
            _ => failure(StatusCode::SERVICE_UNAVAILABLE),
        })?
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED))?;
        let proof = DpopProof::parse(
            one(headers, "dpop")?.ok_or_else(|| failure(StatusCode::UNAUTHORIZED))?,
        )
        .map_err(|_| failure(StatusCode::UNAUTHORIZED))?;
        let target = DpopTarget::new(method.as_str(), &self.origin, uri.path())
            .map_err(|_| failure(StatusCode::UNAUTHORIZED))?;
        self.backend
            .claim_dpop(&proof, &target, DpopToken::Protected(token.as_str()), &current.jkt)
            .await
            .map_err(|error| match error {
                DeviceAuthenticationError::Denied { .. }
                | DeviceAuthenticationError::InvalidDpopProof
                | DeviceAuthenticationError::InvalidInput => failure(StatusCode::UNAUTHORIZED),
                _ => failure(StatusCode::SERVICE_UNAVAILABLE),
            })?;
        if !matches!(browser_operation.requirement(), AccountBrowserAccessRequirement::AnyScope(scopes)
            if scopes.iter().any(|scope|scope.is_present_in(&current.scope)))
        {
            return Err(failure(StatusCode::FORBIDDEN));
        }
        let expires = u64::try_from(current.expires_at_ms.div_euclid(1000))
            .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE))?;
        let scope = current.scope.clone();
        Ok((OrganizationActor::AccountBrowser(current), expires, scope))
    }
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, AuthFailure> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(failure(StatusCode::UNAUTHORIZED));
    }
    value.map(|value| value.to_str().map_err(|_| failure(StatusCode::UNAUTHORIZED))).transpose()
}

fn failure(status: StatusCode) -> AuthFailure {
    let (code, title, detail) = match status {
        StatusCode::FORBIDDEN => (
            "policy.denied",
            "Access denied",
            "Use the configured origin and a session permitted for this operation.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "auth.storage_unavailable",
            "Account unavailable",
            "The server could not verify the current account session.",
        ),
        _ => (
            "auth.authentication_required",
            "Sign-in required",
            "Sign in and create a fresh proof for this request.",
        ),
    };
    AuthFailure::new(status, code, title, detail, status.is_server_error())
        .expect("static Account actor problem")
}
