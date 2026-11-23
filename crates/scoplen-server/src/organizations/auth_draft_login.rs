// SPDX-License-Identifier: AGPL-3.0-only
//! Account-browser draft login and its isolated provider callback.

use std::{error::Error as _, net::SocketAddr};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, Uri, header, request::Parts},
    response::Response,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::{
    account_browser::AccountBrowserAccessOperation,
    auth_connection_draft::{
        DraftRequestError,
        callback::{
            Callback, IssuerIdentification, activation_cookie_name_from_query, callback_path,
        },
        test_login::{DraftLoginCredentials, DraftLoginRequest, DraftLoginStarted},
    },
    organization::parse_organization_idempotency_key,
};
use scoplen_crypto::{SecretBytes, SecretVec, random_key};
use scoplen_store::{
    account_browser_sessions::CurrentAccountBrowserSession,
    account_entry_admission::AccountEntryEndpoint,
    organizations::{
        OrganizationStoreError as StoreError,
        auth_connection::ActivationClaim,
        auth_draft_login::{
            DraftLoginClaim, DraftLoginMaterial, DraftLoginOutcome, DraftLoginProvider,
            DraftLoginStart,
        },
    },
};
use sha2::{Digest as _, Sha256};
use time::{
    OffsetDateTime,
    format_description::well_known::{Rfc2822, Rfc3339},
};
use url::Url;
use uuid::Uuid;

use super::{
    OrganizationState, browser_authority, invalid, problem, reply, specific_problem, store_problem,
    team, valid_encoding,
};
use crate::{
    device_auth::AuthBackend,
    oidc::{
        DiscoveryError, DraftExchangeError, ProviderMetadata, TrustedIssuer,
        verify_claimed_activation, verify_claimed_draft_login,
    },
};

const COOKIE: &str = "__Host-spl-auth-test";
const COOKIE_ATTRIBUTES: &str = "Path=/; HttpOnly; Secure; SameSite=Lax";
const MAX_START_BODY: usize = 4096;
const MAX_AUTHORIZATION_URL: usize = 7680;

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/auth-connection-draft/test-login", post(start))
        .route("/api/v1/orgs/{org}/auth-connection-draft/test-login/{attempt}", get(status))
        .route("/api/v1/auth/enterprise/oidc/{issuer_hash}/callback", get(callback))
}

macro_rules! store_call {
    ($state:expr, $method:ident($($argument:expr),* $(,)?)) => {
        match &$state.backend {
            AuthBackend::Sqlite(store) => store.$method($($argument),*).await,
            AuthBackend::Postgres(store) => store.$method($($argument),*).await,
        }
    };
}

fn path_ids(uri: &Uri) -> Option<(Uuid, Option<Uuid>)> {
    let mut segments = uri.path().strip_prefix("/api/v1/orgs/")?.split('/');
    let organization = parse_organization_idempotency_key(segments.next()?).ok()?;
    if segments.next()? != "auth-connection-draft" || segments.next()? != "test-login" {
        return None;
    }
    let attempt = match segments.next() {
        Some(value) => Some(parse_organization_idempotency_key(value).ok()?),
        None => None,
    };
    segments.next().is_none().then_some((organization, attempt))
}

fn decode_request<'a>(
    parts: &'a Parts,
    body: &[u8],
) -> Result<DraftLoginRequest<'a>, DraftRequestError> {
    DraftLoginRequest::from_http(
        parts.method.as_str(),
        parts.uri.query(),
        parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or_default())),
        body,
    )
}

async fn start(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<OrganizationState>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let endpoint = AccountEntryEndpoint::OrganizationAuthDraftTestStart;
    if let Err(response) = team::admission(&state, endpoint, peer.ip(), None, &id).await {
        return response;
    }
    let session = match browser_authority(
        &state,
        AccountBrowserAccessOperation::AuthDraftTestStart,
        &parts,
        &id,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = team::admission(
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
    let Some((organization, None)) = path_ids(&parts.uri) else { return invalid(&id) };
    if !valid_encoding(&parts.headers) {
        return invalid(&id);
    }
    let body = match to_bytes(body, MAX_START_BODY).await {
        Ok(body) => body,
        Err(error)
            if error
                .source()
                .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>) =>
        {
            return request_error(DraftRequestError::TooLarge, &id);
        }
        Err(_) => return invalid(&id),
    };
    match decode_request(&parts, &body) {
        Ok(DraftLoginRequest::Start { if_match, credentials }) => {
            start_attempt(&state, &session, organization, if_match, credentials, &id).await
        }
        Ok(DraftLoginRequest::Read) => invalid(&id),
        Err(error) => request_error(error, &id),
    }
}

async fn start_attempt(
    state: &OrganizationState,
    session: &CurrentAccountBrowserSession,
    organization: Uuid,
    if_match: &str,
    credentials: DraftLoginCredentials,
    id: &Uuid,
) -> Response {
    let issuer = match store_call!(
        state,
        organization_auth_draft_login_issuer(session, organization, if_match)
    ) {
        Ok(issuer) => issuer,
        Err(error) => return store_problem(error, id),
    };
    let trusted = match TrustedIssuer::from_settings(&state.enterprise_identity, &issuer) {
        Ok(trusted) => trusted,
        Err(error) => return discovery_problem(error, id),
    };
    let metadata = match trusted.discover().await {
        Ok(metadata) => metadata,
        Err(error) => return discovery_problem(error, id),
    };
    let [Ok(state_proof), Ok(nonce), Ok(verifier), Ok(browser_binding)] =
        std::array::from_fn(|_| random_key())
    else {
        return store_problem(StoreError::StorageUnavailable, id);
    };
    let material = DraftLoginMaterial { credentials, verifier };
    let provider = login_provider(metadata);
    let Some(authorization_url) = authorization_url(
        &state.origin,
        &issuer,
        &provider.authorization_endpoint,
        &material.credentials.client_id,
        &material.verifier,
        &state_proof,
        &nonce,
    ) else {
        return discovery_problem(DiscoveryError::Incompatible, id);
    };
    let start = DraftLoginStart {
        organization,
        if_match,
        issuer: &issuer,
        provider: &provider,
        trust_fingerprint: trusted.fingerprint(),
        state: &state_proof,
        browser_binding: &browser_binding,
        nonce: &nonce,
        material: &material,
    };
    let attempt = match store_call!(
        state,
        start_organization_auth_draft_login(
            session,
            &start,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref()
        )
    ) {
        Ok(attempt) => attempt,
        Err(StoreError::CommitOutcomeUnknown) => {
            return specific_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "organization.commit_outcome_unknown",
                "Draft login start unconfirmed",
                "Wait for the pending attempt to expire before starting another test.",
                true,
                false,
                id,
            );
        }
        Err(error) => return store_problem(error, id),
    };
    let Some(cookie) = callback_cookie(COOKIE, &browser_binding, &attempt.expires_at) else {
        return store_problem(StoreError::StorageUnavailable, id);
    };
    let Ok(body) = (DraftLoginStarted { attempt, authorization_url }).to_json(&issuer) else {
        return store_problem(StoreError::StorageUnavailable, id);
    };
    let mut response = reply(StatusCode::CREATED, "application/json", body.as_bytes().to_vec(), id);
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}

pub(super) fn login_provider(metadata: ProviderMetadata) -> DraftLoginProvider {
    DraftLoginProvider {
        authorization_endpoint: metadata.authorization_endpoint,
        token_endpoint: metadata.token_endpoint,
        userinfo_endpoint: metadata.userinfo_endpoint,
        jwks_uri: metadata.jwks_uri,
        response_issuer_required: metadata.issuer_identification
            == IssuerIdentification::ResponseParameter,
    }
}

pub(super) fn authorization_url(
    origin: &str,
    issuer: &str,
    endpoint: &str,
    client_id: &SecretVec,
    verifier: &SecretBytes<32>,
    state: &SecretBytes<32>,
    nonce: &SecretBytes<32>,
) -> Option<SecretVec> {
    let mut url = Url::parse(endpoint).ok()?;
    let callback = format!("{origin}{}", callback_path(issuer).ok()?);
    let client = std::str::from_utf8(client_id.as_bytes()).ok()?;
    let verifier = URL_SAFE_NO_PAD.encode(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("client_id", client)
        .append_pair("redirect_uri", &callback)
        .append_pair("state", &URL_SAFE_NO_PAD.encode(state.as_bytes()))
        .append_pair("nonce", &URL_SAFE_NO_PAD.encode(nonce.as_bytes()))
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    (url.as_str().len() <= MAX_AUTHORIZATION_URL)
        .then(|| SecretVec::new(String::from(url).into_bytes()))
}

pub(super) fn callback_cookie(
    name: &str,
    binding: &SecretBytes<32>,
    expires_at: &str,
) -> Option<HeaderValue> {
    let expires = OffsetDateTime::parse(expires_at, &Rfc3339)
        .ok()?
        .replace_nanosecond(0)
        .ok()?
        .format(&Rfc2822)
        .ok()?;
    HeaderValue::from_str(&format!(
        "{name}={}; {COOKIE_ATTRIBUTES}; Expires={} GMT",
        URL_SAFE_NO_PAD.encode(binding.as_bytes()),
        expires.strip_suffix(" +0000")?
    ))
    .ok()
}

async fn status(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let session = match browser_authority(
        &state,
        AccountBrowserAccessOperation::AuthDraftTestRead,
        &parts,
        &id,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let Some((organization, Some(attempt))) = path_ids(&parts.uri) else { return invalid(&id) };
    if !valid_encoding(&parts.headers) || to_bytes(body, 0).await.is_err() {
        return invalid(&id);
    }
    match decode_request(&parts, &[]) {
        Ok(DraftLoginRequest::Read) => (),
        Ok(DraftLoginRequest::Start { .. }) => return invalid(&id),
        Err(error) => return request_error(error, &id),
    }
    match store_call!(state, organization_auth_draft_login_status(&session, organization, attempt))
    {
        Ok(attempt) => team::encoded(attempt.to_json(), None, StatusCode::OK, &id),
        Err(error) => store_problem(error, &id),
    }
}

pub(super) fn fingerprint(state: &OrganizationState, issuer: &str) -> Option<[u8; 32]> {
    TrustedIssuer::from_settings(&state.enterprise_identity, issuer)
        .ok()
        .map(|entry| entry.fingerprint())
}

pub(super) fn discovery_problem(error: DiscoveryError, id: &Uuid) -> Response {
    if error == DiscoveryError::Untrusted {
        return store_problem(StoreError::PermissionDenied, id);
    }
    specific_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "organization.auth_provider_unavailable",
        "Identity provider unavailable",
        "Check the configured identity provider and try again.",
        false,
        error == DiscoveryError::Unavailable,
        id,
    )
}

fn request_error(error: DraftRequestError, id: &Uuid) -> Response {
    match error {
        DraftRequestError::Invalid => invalid(id),
        DraftRequestError::MediaType => {
            problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "organization.invalid_request", false, id)
        }
        DraftRequestError::TooLarge => {
            problem(StatusCode::PAYLOAD_TOO_LARGE, "organization.invalid_request", false, id)
        }
        DraftRequestError::PreconditionRequired => specific_problem(
            StatusCode::PRECONDITION_REQUIRED,
            "organization.precondition_required",
            "Current draft required",
            "Read the current draft and supply its exact ETag in one If-Match header.",
            false,
            false,
            id,
        ),
    }
}

fn callback_target(origin: &str, uri: &Uri, headers: &HeaderMap) -> bool {
    let Some(expected) = origin.strip_prefix("https://") else { return false };
    if uri.scheme_str().is_some_and(|scheme| scheme != "https") {
        return false;
    }
    let mut host = headers.get_all(header::HOST).iter();
    let host_matches = host
        .next()
        .map(|value| value.to_str().is_ok_and(|value| value.eq_ignore_ascii_case(expected)));
    let uri_matches = uri.authority().map(|value| value.as_str().eq_ignore_ascii_case(expected));
    host.next().is_none()
        && host_matches.or(uri_matches) == Some(true)
        && uri_matches != Some(false)
        && headers.get_all("sec-fetch-mode").iter().all(|value| value == "navigate")
        && headers.get_all("sec-fetch-dest").iter().all(|value| value == "document")
}

fn callback_binding<'a>(
    headers: &'a HeaderMap,
    cookie_name: &str,
    query_len: usize,
) -> Result<Option<&'a str>, ()> {
    let mut total = query_len;
    let mut binding = None;
    for value in headers.get_all(header::COOKIE) {
        total += value.as_bytes().len();
        if total > 8192 {
            return Err(());
        }
        for cookie in value.to_str().map_err(|_| ())?.split(';') {
            let (name, value) = cookie.trim().split_once('=').ok_or(())?;
            if name == cookie_name && binding.replace(value).is_some() {
                return Err(());
            }
        }
    }
    Ok(binding)
}

async fn callback(State(state): State<OrganizationState>, request: Request<Body>) -> Response {
    let id = Uuid::new_v4();
    let (parts, body) = request.into_parts();
    let query = parts.uri.query().unwrap_or_default();
    if !callback_target(&state.origin, &parts.uri, &parts.headers)
        || to_bytes(body, 0).await.is_err()
    {
        return callback_page(None, &id);
    }
    let Ok(activation_cookie) = activation_cookie_name_from_query(query) else {
        return callback_page(None, &id);
    };
    let cookie = match callback_binding(&parts.headers, &activation_cookie, query.len()) {
        Ok(Some(value)) => Some((activation_cookie.as_str(), value)),
        Ok(None) => match callback_binding(&parts.headers, COOKIE, query.len()) {
            Ok(Some(value)) => Some((COOKIE, value)),
            _ => None,
        },
        Err(()) => None,
    };
    let Some((name, binding)) = cookie else { return callback_page(None, &id) };
    let Ok(callback) =
        Callback::parse(parts.method.as_str(), parts.uri.path(), query, [binding].into_iter())
    else {
        return callback_page(None, &id);
    };
    if name != COOKIE {
        return activation_callback(&state, callback, name, &id).await;
    }
    draft_callback(&state, callback, &id).await
}

async fn draft_callback(state: &OrganizationState, callback: Callback<'_>, id: &Uuid) -> Response {
    match store_call!(
        state,
        claim_organization_auth_draft_login(
            &state.origin,
            callback,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref()
        )
    ) {
        Ok(DraftLoginClaim::Denied) => callback_page(Some(COOKIE), id),
        Ok(DraftLoginClaim::Exchange(mut attempt)) => {
            let outcome =
                match verify_claimed_draft_login(&state.enterprise_identity, &mut attempt).await {
                    Ok(()) => DraftLoginOutcome::Verified,
                    Err(DraftExchangeError::InvalidIdentity) => DraftLoginOutcome::InvalidIdentity,
                    Err(_) => DraftLoginOutcome::ExchangeFailed,
                };
            let _ = store_call!(
                state,
                finish_organization_auth_draft_login(
                    &state.origin,
                    &attempt,
                    |issuer| fingerprint(state, issuer),
                    outcome
                )
            );
            callback_page(Some(COOKIE), id)
        }
        Err(_) => callback_page(None, id),
    }
}

async fn activation_callback(
    state: &OrganizationState,
    callback: Callback<'_>,
    cookie_name: &str,
    id: &Uuid,
) -> Response {
    match store_call!(
        state,
        claim_organization_auth_activation(
            &state.origin,
            callback,
            |issuer| fingerprint(state, issuer),
            state.kms.as_ref()
        )
    ) {
        Ok(ActivationClaim::Denied) => callback_page(Some(cookie_name), id),
        Ok(ActivationClaim::Exchange(mut attempt)) => {
            let outcome =
                match verify_claimed_activation(&state.enterprise_identity, &mut attempt).await {
                    Ok(()) => DraftLoginOutcome::Verified,
                    Err(DraftExchangeError::InvalidIdentity) => DraftLoginOutcome::InvalidIdentity,
                    Err(_) => DraftLoginOutcome::ExchangeFailed,
                };
            let _ = store_call!(
                state,
                finish_organization_auth_activation(
                    &attempt,
                    |issuer| fingerprint(state, issuer),
                    outcome
                )
            );
            callback_page(Some(cookie_name), id)
        }
        Err(_) => callback_page(None, id),
    }
}

fn callback_page(cookie_name: Option<&str>, id: &Uuid) -> Response {
    let (status, title) = match cookie_name {
        Some(COOKIE) => (StatusCode::OK, "Draft login test"),
        Some(_) => (StatusCode::OK, "Connection activation"),
        None => (StatusCode::BAD_REQUEST, "Draft login test"),
    };
    let mut response = reply(status, "text/html; charset=utf-8", format!("<!doctype html><html lang=en><meta charset=utf-8><title>{title}</title><p>Return to the original team tab to check the result.</p></html>").into_bytes(), id);
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if let Some(name) = cookie_name
        && let Ok(value) =
            HeaderValue::from_str(&format!("{name}=; {COOKIE_ATTRIBUTES}; Max-Age=0"))
    {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}
