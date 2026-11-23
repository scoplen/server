// SPDX-License-Identifier: AGPL-3.0-only
//! One provider exchange for an already claimed draft login.

use axum::body::Bytes;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::header;
use scoplen_api::auth_connection_draft::callback::callback_path;
use scoplen_crypto::{SecretVec, validate_server_origin};
use scoplen_store::organizations::auth_draft_login::{ClaimedDraftLogin, DraftLoginExchange};
use serde::Deserialize;
use thiserror::Error;
use url::form_urlencoded;
use zeroize::{Zeroize as _, Zeroizing};

use crate::EnterpriseIdentitySettings;

use super::{
    TrustedIssuer,
    id_token::{ExpectedClaims, IdToken},
    trust::read_json,
};

const TOKEN_LIMIT: usize = 65_536;
const JWKS_LIMIT: usize = 131_072;

/// Fixed callback outcomes without provider diagnostics or identity contents.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum DraftExchangeError {
    /// The attempt is expired, already used, or its issuer trust has changed.
    #[error("draft login is no longer available")]
    Stale,
    /// The issuer did not return an admitted token response or keys.
    #[error("draft login exchange failed")]
    ExchangeFailed,
    /// The issuer's result failed the human ID Token profile.
    #[error("draft login identity could not be verified")]
    InvalidIdentity,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    access_token: String,
    token_type: String,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.id_token.zeroize();
        self.access_token.zeroize();
    }
}

fn current_trust(
    settings: &EnterpriseIdentitySettings,
    attempt: &ClaimedDraftLogin,
) -> Result<TrustedIssuer, DraftExchangeError> {
    let _ = current_time(attempt.expires_at_ms())?;
    let trust = TrustedIssuer::from_settings(settings, attempt.provider().0)
        .map_err(|_| DraftExchangeError::Stale)?;
    if trust.fingerprint() != attempt.trust_fingerprint() {
        return Err(DraftExchangeError::Stale);
    }
    Ok(trust)
}

fn current_time(expires_at_ms: i64) -> Result<i64, DraftExchangeError> {
    let now = time::OffsetDateTime::now_utc();
    if now.unix_timestamp_nanos() / 1_000_000 >= i128::from(expires_at_ms) {
        return Err(DraftExchangeError::Stale);
    }
    Ok(now.unix_timestamp())
}

/// Exchange one durably claimed code and verify the issuer's signed human login.
/// The caller still commits the terminal outcome under current storage authority.
///
/// # Errors
/// Returns only bounded error classes. The code is consumed in memory even if
/// the exchange has an uncertain result, so retries must start a new attempt.
pub async fn verify_claimed_draft_login(
    settings: &EnterpriseIdentitySettings,
    attempt: &mut ClaimedDraftLogin,
) -> Result<(), DraftExchangeError> {
    let exchange = attempt.take_exchange().ok_or(DraftExchangeError::Stale)?;
    let origin = attempt.origin();
    let (issuer, provider) = attempt.provider();
    if !origin.starts_with("https://") || validate_server_origin(origin).is_err() {
        return Err(DraftExchangeError::Stale);
    }
    let path = callback_path(issuer).map_err(|_| DraftExchangeError::Stale)?;
    let redirect_uri = format!("{origin}{path}");
    let trust = current_trust(settings, attempt)?;
    let _ = current_time(attempt.expires_at_ms())?;
    let reply = exchange_code(&trust, &provider.token_endpoint, &redirect_uri, &exchange).await?;
    let id = IdToken::parse(&reply.id_token)?;
    let trust = current_trust(settings, attempt)?;
    let _ = current_time(attempt.expires_at_ms())?;
    let keys = signing_keys(&trust, &provider.jwks_uri).await?;
    let now = current_time(attempt.expires_at_ms())?;
    let client = std::str::from_utf8(exchange.material.credentials.client_id.as_bytes())
        .map_err(|_| DraftExchangeError::ExchangeFailed)?;
    id.verify(
        &keys,
        &ExpectedClaims {
            issuer,
            client,
            access_token: &reply.access_token,
            code: exchange.code.as_bytes(),
            now,
        },
        |nonce| attempt.matches_nonce(nonce),
    )
}

async fn exchange_code(
    trust: &TrustedIssuer,
    endpoint: &str,
    redirect_uri: &str,
    exchange: &DraftLoginExchange,
) -> Result<TokenResponse, DraftExchangeError> {
    let failed = DraftExchangeError::ExchangeFailed;
    let endpoint = trust.pinned_endpoint(endpoint).ok_or(failed)?;
    let credentials = &exchange.material.credentials;
    let client = Zeroizing::new(
        form_urlencoded::byte_serialize(credentials.client_id.as_bytes()).collect::<String>(),
    );
    let secret = Zeroizing::new(
        form_urlencoded::byte_serialize(credentials.client_secret.as_bytes()).collect::<String>(),
    );
    let code = std::str::from_utf8(exchange.code.as_bytes()).map_err(|_| failed)?;
    let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(exchange.material.verifier.as_bytes()));
    let form = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", &verifier)
        .finish();
    let request = trust
        .client
        .post(endpoint)
        .basic_auth(client.as_str(), Some(secret.as_str()))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::from_owner(SecretVec::new(form.into_bytes())));
    let body = read_json(request, TOKEN_LIMIT, false).await.map_err(|_| failed)?;
    let reply: TokenResponse = serde_json::from_slice(&body).map_err(|_| failed)?;
    if !reply.token_type.eq_ignore_ascii_case("Bearer") || reply.access_token.is_empty() {
        return Err(failed);
    }
    Ok(reply)
}

async fn signing_keys(
    trust: &TrustedIssuer,
    endpoint: &str,
) -> Result<Zeroizing<Vec<u8>>, DraftExchangeError> {
    let failed = DraftExchangeError::ExchangeFailed;
    let endpoint = trust.pinned_endpoint(endpoint).ok_or(failed)?;
    read_json(trust.client.get(endpoint), JWKS_LIMIT, true).await.map_err(|_| failed)
}
