// SPDX-License-Identifier: AGPL-3.0-only
//! Public HTTPS audit acceptance. Identity and business state are never seeded through SQL.

use std::{net::Ipv4Addr, time::Duration};

use axum::{
    body::Bytes,
    http::{HeaderMap, Request},
};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use scoplen_api::{
    ProblemDetails,
    account_admission::{AccountPasswordLoginRequest, AccountPasswordOptionsRequest},
    account_browser::{
        AccountBrowserAccessToken, AccountBrowserPasswordLoginRequest,
        AccountBrowserPasswordLoginResponse, AccountBrowserPasswordOptionsRequest,
        AccountBrowserPasswordOptionsResponse, AccountBrowserRefreshResponse,
    },
    audit::{
        AuditCategory, AuditEvent, AuditFilter, AuditListQuery, AuditOutcome, AuditPage,
        AuditRange, AuditResource, AuditResourceKind, AuditVerification, MAX_AUDIT_PAGE_BYTES,
        MAX_AUDIT_PROBLEM_BYTES, MAX_AUDIT_VERIFICATION_BYTES, format_audit_timestamp,
        parse_audit_timestamp, validate_audit_cache_headers,
    },
    auth::AuthTokenResponse,
    group_policy::{PolicyCreateRequest, PolicyFields, PolicyReplaceRequest, PolicyResource},
    inventory::{InventoryResource, InventoryType},
    organization::{OrganizationCreateRequest, OrganizationResource, OrganizationUpdateRequest},
    team::{
        TeamAcceptanceReceipt, TeamInvitationAcceptRequest, TeamInvitationCreateRequest,
        TeamInvitationResource, TeamMemberResource, TeamMemberStatus, TeamMemberUpdateRequest,
        TeamRole,
    },
};
use scoplen_crypto::{
    DpopProof, DpopTarget, DpopToken, P256SigningKey, PASSWORD_BOOTSTRAP_PROFILE,
    PasswordKdfContext, TeamInvitationPassword, generate_p256_signing_key,
};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::Registration;
use crate::{Driver, Https, Result};

const OPTIONS: &str = "/api/v1/auth/accounts/browser/password/options";
const LOGIN: &str = "/api/v1/auth/accounts/browser/password/login";
const REFRESH: &str = "/api/v1/auth/accounts/browser/refresh";

#[derive(Clone, Copy)]
pub(super) struct Actor<'a> {
    key: &'a P256SigningKey,
    access: Option<&'a str>,
}

pub(super) fn native<'a>(account: &'a Registration, token: &'a AuthTokenResponse) -> Actor<'a> {
    Actor { key: &account.device.keys.signing, access: Some(&token.access_token) }
}

pub(super) struct Browser {
    key: P256SigningKey,
    access: Zeroizing<String>,
    cookie: Zeroizing<String>,
}

impl Browser {
    pub(super) fn actor(&self) -> Actor<'_> {
        Actor { key: &self.key, access: Some(&self.access) }
    }

    pub(super) async fn login(https: &Https, account: &Registration) -> Result<Self> {
        let key = generate_p256_signing_key().map_err(|_| "browser proof key generation failed")?;
        let actor = Actor { key: &key, access: None };
        let body = AccountBrowserPasswordOptionsRequest(AccountPasswordOptionsRequest {
            username: account.payload.username.clone(),
        })
        .to_json()
        .map_err(|_| "browser password options request invalid")?;
        let reply = exchange(https, actor, "POST", OPTIONS, &body, &[], 200).await?;
        let options = AccountBrowserPasswordOptionsResponse::from_json(&reply.body)
            .map_err(|_| "browser password options response invalid")?
            .0;
        if options.salt != account.payload.password_salt {
            return Err("browser options selected a different registered password context");
        }
        let secrets = PasswordKdfContext::new(
            &https.origin,
            &account.payload.username,
            PASSWORD_BOOTSTRAP_PROFILE,
            &options.salt,
        )
        .and_then(|context| context.derive(account.password.clone()))
        .map_err(|_| "browser password derivation failed")?;
        let body = AccountBrowserPasswordLoginRequest(AccountPasswordLoginRequest {
            attempt_id: options.attempt_id,
            auth_secret: secrets.auth_secret().clone(),
        })
        .to_json()
        .map_err(|_| "browser password login request invalid")?;
        let reply = exchange(https, actor, "POST", LOGIN, body.as_bytes(), &[], 200).await?;
        let (access, cookie) = browser_session(&reply, true)?;
        Ok(Self { key, access, cookie })
    }

    pub(super) async fn refresh(&mut self, https: &Https) -> Result<()> {
        let reply = exchange(
            https,
            Actor { key: &self.key, access: None },
            "POST",
            REFRESH,
            b"{}",
            &[("Cookie", self.cookie.as_str())],
            200,
        )
        .await?;
        let (access, cookie) = browser_session(&reply, false)?;
        if access == self.access || cookie == self.cookie {
            return Err("browser refresh did not rotate its credentials");
        }
        self.access = access;
        self.cookie = cookie;
        Ok(())
    }
}

pub(super) struct Reply {
    headers: HeaderMap,
    pub(super) body: Zeroizing<Vec<u8>>,
}

impl Reply {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

fn browser_session(reply: &Reply, initial: bool) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let value = if initial {
        AccountBrowserPasswordLoginResponse::from_json(&reply.body)
            .map_err(|_| "browser login response invalid")?
            .0
    } else {
        AccountBrowserRefreshResponse::from_json(&reply.body)
            .map_err(|_| "browser refresh response invalid")?
            .0
    };
    AccountBrowserAccessToken::parse(&value.access_token)
        .map_err(|_| "browser access credential profile invalid")?;
    let shape: serde_json::Value =
        serde_json::from_slice(&reply.body).map_err(|_| "browser session JSON invalid")?;
    if shape.as_object().is_none_or(|object| object.len() != 4)
        || value.token_type != "DPoP"
        || value.expires_in != 600
        || !(1..=2_592_000).contains(&value.refresh_expires_in)
        || (initial && value.refresh_expires_in != 2_592_000)
    {
        return Err("browser session shape or lifetime invalid");
    }
    let cookie = reply.header("set-cookie").ok_or("browser refresh cookie missing")?;
    if reply.headers.get_all("set-cookie").iter().count() != 1
        || !cookie.starts_with("__Secure-spl-account-refresh=ar1_")
        || !cookie.contains("; Path=/api/v1/auth/accounts/browser/refresh;")
        || cookie.contains("Domain=")
        || !cookie.ends_with(&format!("Max-Age={}", value.refresh_expires_in))
        || ["HttpOnly", "Secure", "SameSite=Strict"]
            .iter()
            .any(|required| !cookie.split("; ").any(|attribute| attribute == *required))
    {
        return Err("browser refresh cookie boundary invalid");
    }
    Ok((
        Zeroizing::new(value.access_token),
        Zeroizing::new(cookie.split(';').next().ok_or("browser cookie pair missing")?.into()),
    ))
}

fn response_limit(path: &str, method: &str, status: u16) -> usize {
    if status >= 400 {
        MAX_AUDIT_PROBLEM_BYTES
    } else if path.split('?').next().is_some_and(|path| path.ends_with("/audit-events/verify")) {
        MAX_AUDIT_VERIFICATION_BYTES
    } else if path.split('?').next().is_some_and(|path| path.ends_with("/audit-events")) {
        MAX_AUDIT_PAGE_BYTES
    } else if path.split('?').next().is_some_and(|path| path.ends_with("/grants"))
        && method == "GET"
    {
        scoplen_api::grant::MAX_GRANT_PAGE_BYTES
    } else if path.contains("/grants") {
        scoplen_api::grant::MAX_GRANT_BYTES
    } else if path.split('?').next().is_some_and(|path| path.ends_with("/access-requests"))
        && method == "GET"
    {
        scoplen_api::access_request::MAX_ACCESS_REQUEST_PAGE_BYTES
    } else if path.ends_with("/certificates") {
        scoplen_api::certificate::MAX_CERTIFICATE_ISSUANCE_RESPONSE_BYTES
    } else if path.ends_with("/inventory/imports") {
        scoplen_api::inventory_import::MAX_INVENTORY_IMPORT_RESULT_BYTES
    } else if let Some(resource) = snippet_route(path) {
        if method == "GET" && !resource {
            scoplen_api::inventory::MAX_INVENTORY_PAGE_BYTES
        } else {
            scoplen_api::inventory::MAX_INVENTORY_RESOURCE_BYTES
        }
    } else {
        8_192
    }
}

fn snippet_route(path: &str) -> Option<bool> {
    let path = path.split('?').next()?;
    let parts: Vec<_> = path.split('/').collect();
    if !matches!(parts.len(), 6 | 7)
        || parts[..4] != ["", "api", "v1", "orgs"]
        || Uuid::parse_str(parts[4]).ok()?.to_string() != parts[4]
        || parts[5] != "snippets"
    {
        return None;
    }
    if parts.len() == 7 && Uuid::parse_str(parts[6]).ok()?.to_string() != parts[6] {
        return None;
    }
    Some(parts.len() == 7)
}

fn validate_headers(headers: &HeaderMap, path: &str, status: u16) -> Result<()> {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    validate_audit_cache_headers(header("cache-control"), header("pragma"))
        .map_err(|_| "audit consumer response cache metadata invalid")?;
    let cookie_allowed = status == 200 && matches!(path, LOGIN | REFRESH);
    if header("x-request-id").is_none_or(str::is_empty)
        || (!cookie_allowed && headers.contains_key("set-cookie"))
        || headers.contains_key("access-control-allow-origin")
        || headers.contains_key("access-control-allow-credentials")
        || (path.contains("/audit-events") && headers.contains_key("etag"))
    {
        return Err("audit consumer response privacy metadata invalid");
    }
    if status != 204
        && header("content-type")
            != Some(if status >= 400 { "application/problem+json" } else { "application/json" })
    {
        return Err("audit consumer response content type invalid");
    }
    Ok(())
}

pub(super) async fn exchange(
    https: &Https,
    actor: Actor<'_>,
    method: &str,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
    expected: u16,
) -> Result<Reply> {
    exchange_inner(https, actor, method, path, body, extra, Some(expected))
        .await?
        .ok_or("audit consumer expected a complete response")
}

/// Deliberately lose a mutation reply before inspecting its status, headers or body.
pub(super) async fn lose_response(
    https: &Https,
    actor: Actor<'_>,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> Result<()> {
    exchange_inner(https, actor, "POST", path, body, extra, None).await?;
    Ok(())
}

async fn exchange_inner(
    https: &Https,
    actor: Actor<'_>,
    method: &str,
    path: &str,
    body: &[u8],
    extra: &[(&str, &str)],
    expected: Option<u16>,
) -> Result<Option<Reply>> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock invalid")?
            .as_secs();
        let proof = DpopProof::sign(
            actor.key,
            &actor.key.public_key_sec1(),
            &DpopTarget::new(method, &https.origin, path.split('?').next().ok_or("path missing")?)
                .map_err(|_| "audit consumer DPoP target invalid")?,
            actor.access.map_or(DpopToken::Refresh, DpopToken::Protected),
            now,
            None,
        )
        .map_err(|_| "audit consumer DPoP signing failed")?;
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", https.origin))
            .header("Origin", &https.origin)
            .header("DPoP", proof.as_str());
        if method != "GET" && method != "DELETE" {
            request = request.header("Content-Type", "application/json");
        }
        if let Some(access) = actor.access {
            request = request.header("Authorization", format!("DPoP {access}"));
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let tcp = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, https.port))
            .await
            .map_err(|_| "audit consumer loopback connection failed")?;
        let tls = https
            .connector
            .connect(ServerName::try_from("localhost").map_err(|_| "TLS name invalid")?, tcp)
            .await
            .map_err(|_| "audit consumer TLS verification failed")?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("audit consumer requires verified HTTP/2");
        }
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .max_header_list_size(16_384)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(|_| "audit consumer HTTP/2 handshake failed")?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender
            .send_request(
                request
                    .body(Full::new(Bytes::copy_from_slice(body)))
                    .map_err(|_| "audit consumer request encoding failed")?,
            )
            .await
            .map_err(|_| "audit consumer request failed; abandon this fixture")?;
        let Some(expected) = expected else {
            drop(response);
            return Ok(None);
        };
        let status = response.status().as_u16();
        if status != expected {
            eprintln!("audit consumer HTTP status: expected {expected}, received {status}");
            return Err("audit consumer public API returned an unexpected status");
        }
        validate_headers(response.headers(), path, status)?;
        let (parts, body) = response.into_parts();
        let bytes = Limited::new(body, response_limit(path, method, status))
            .collect()
            .await
            .map_err(|_| "audit consumer response exceeds its bound or is incomplete")?
            .to_bytes();
        if status == 204 && !bytes.is_empty() {
            return Err("audit consumer empty response has a body");
        }
        Ok(Some(Reply { headers: parts.headers, body: Zeroizing::new(bytes.to_vec()) }))
    })
    .await
    .map_err(|_| "audit consumer request timed out; abandon this fixture")?
}

fn organization(reply: &Reply) -> Result<OrganizationResource> {
    OrganizationResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "audit fixture Organization Resource invalid")
}

pub(super) async fn create_team(https: &Https, actor: Actor<'_>) -> Result<OrganizationResource> {
    let body = OrganizationCreateRequest::new("Disposable audit HTTPS team")
        .and_then(|value| value.to_json())
        .map_err(|_| "audit fixture team request invalid")?;
    let key = Uuid::now_v7().to_string();
    organization(
        &exchange(https, actor, "POST", "/api/v1/orgs", &body, &[("Idempotency-Key", &key)], 201)
            .await?,
    )
}

async fn rename_team(https: &Https, actor: Actor<'_>, org: Uuid, name: &str) -> Result<()> {
    let path = format!("/api/v1/orgs/{org}");
    let current = organization(&exchange(https, actor, "GET", &path, &[], &[], 200).await?)?;
    let body = OrganizationUpdateRequest::new(name)
        .and_then(|value| value.to_json())
        .map_err(|_| "audit fixture rename request invalid")?;
    let updated = organization(
        &exchange(https, actor, "PATCH", &path, &body, &[("If-Match", &current.etag)], 200).await?,
    )?;
    if updated.id != org || updated.name != name {
        return Err("audit fixture rename response changed its context");
    }
    Ok(())
}

pub(super) async fn invite(
    https: &Https,
    owner: Actor<'_>,
    recipient: Actor<'_>,
    account: &Registration,
    org: Uuid,
) -> Result<Uuid> {
    let id = Uuid::now_v7();
    let password = TeamInvitationPassword::generate().map_err(|_| "invitation password failed")?;
    let body = TeamInvitationCreateRequest {
        invitation_id: id,
        recipient_username: account.payload.username.clone(),
        roles: vec![TeamRole::Member],
        password_verifier: password
            .verifier(&https.origin, &org, &id)
            .map_err(|_| "invitation verifier failed")?,
    }
    .to_json()
    .map_err(|_| "audit fixture invitation request invalid")?;
    let root = format!("/api/v1/orgs/{org}");
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        owner,
        "POST",
        &format!("{root}/invitations"),
        body.as_bytes(),
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    let invitation = TeamInvitationResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "audit fixture invitation response invalid")?;
    if invitation.id != id || invitation.recipient_account_id != account.payload.account_id {
        return Err("audit fixture invitation recipient differs");
    }
    let body = TeamInvitationAcceptRequest { password }
        .to_json()
        .map_err(|_| "audit fixture invitation acceptance invalid")?;
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        recipient,
        "POST",
        &format!("{root}/invitations/{id}/accept"),
        body.as_bytes(),
        &[("Idempotency-Key", &key)],
        200,
    )
    .await?;
    let receipt = TeamAcceptanceReceipt::from_json(&reply.body)
        .map_err(|_| "audit fixture acceptance receipt invalid")?;
    receipt
        .validate_for_request(account.payload.account_id, org, id)
        .map_err(|_| "audit fixture acceptance context differs")?;
    Ok(receipt.membership_id)
}

pub(super) async fn member(
    https: &Https,
    owner: Actor<'_>,
    org: Uuid,
    id: Uuid,
) -> Result<TeamMemberResource> {
    let reply =
        exchange(https, owner, "GET", &format!("/api/v1/orgs/{org}/members/{id}"), &[], &[], 200)
            .await?;
    let value = TeamMemberResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "audit fixture member response invalid")?;
    value.validate_for_organization(org).map_err(|_| "audit fixture member tenant differs")?;
    if value.id != id {
        return Err("audit fixture member id differs");
    }
    Ok(value)
}

pub(super) async fn update_member(
    https: &Https,
    owner: Actor<'_>,
    org: Uuid,
    id: Uuid,
    role: TeamRole,
    status: TeamMemberStatus,
) -> Result<()> {
    let current = member(https, owner, org, id).await?;
    let body = TeamMemberUpdateRequest { roles: vec![role], status }
        .to_json()
        .map_err(|_| "audit fixture member update invalid")?;
    let reply = exchange(
        https,
        owner,
        "PATCH",
        &format!("/api/v1/orgs/{org}/members/{id}"),
        &body,
        &[("If-Match", &current.etag)],
        200,
    )
    .await?;
    let updated = TeamMemberResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "audit fixture updated member invalid")?;
    if updated.id != id
        || updated.organization_id != org
        || updated.roles != [role]
        || updated.status != status
        || updated.account_id != current.account_id
    {
        return Err("audit fixture updated member context differs");
    }
    Ok(())
}

fn policy(reply: &Reply, org: Uuid, id: Uuid) -> Result<PolicyResource> {
    let value = PolicyResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "audit fixture policy Resource invalid")?;
    value.validate_for_request(org, id).map_err(|_| "audit fixture policy context differs")?;
    Ok(value)
}

async fn create_policy(
    https: &Https,
    owner: Actor<'_>,
    org: Uuid,
    recipient: Uuid,
) -> Result<PolicyResource> {
    let id = Uuid::now_v7();
    let request = PolicyCreateRequest {
        id,
        fields: PolicyFields {
            name: "Audit acceptance Account permit".into(),
            source: format!(
                "permit(principal == Account::\"{recipient}\", action == Action::\"view_audit\", resource == Organization::\"{org}\");"
            ),
            enabled: true,
        },
    };
    let body = request.to_json().map_err(|_| "audit fixture policy request invalid")?;
    let key = Uuid::now_v7().to_string();
    policy(
        &exchange(
            https,
            owner,
            "POST",
            &format!("/api/v1/orgs/{org}/policies"),
            &body,
            &[("Idempotency-Key", &key)],
            201,
        )
        .await?,
        org,
        id,
    )
}

pub(super) async fn replace_policy(
    https: &Https,
    owner: Actor<'_>,
    org: Uuid,
    current: PolicyResource,
    enabled: bool,
) -> Result<PolicyResource> {
    let request = PolicyReplaceRequest { fields: PolicyFields { enabled, ..current.fields } };
    let body = request.to_json().map_err(|_| "audit fixture policy replacement invalid")?;
    policy(
        &exchange(
            https,
            owner,
            "PUT",
            &format!("/api/v1/orgs/{org}/policies/{}", current.id),
            &body,
            &[("If-Match", &current.etag)],
            200,
        )
        .await?,
        org,
        current.id,
    )
}

async fn create_host(https: &Https, owner: Actor<'_>, org: Uuid) -> Result<Uuid> {
    let id = Uuid::now_v7();
    let body = serde_json::to_vec(&json!({"id":id,"data":{"fields":{
        "name":"Audit acceptance Host", "address":"audit.example.test", "port":22
    }}}))
    .map_err(|_| "audit fixture Host encoding failed")?;
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        owner,
        "POST",
        &format!("/api/v1/orgs/{org}/hosts"),
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    let value = InventoryResource::from_http_json(
        InventoryType::Host,
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "audit fixture Host Resource invalid")?;
    if value.id != id {
        return Err("audit fixture Host context differs");
    }
    Ok(id)
}

fn list_path(org: Uuid, limit: u16, cursor: Option<u64>, filter: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", &limit.to_string()).append_pair("sort", "-sequence");
    if let Some(cursor) = cursor {
        query.append_pair("cursor", &cursor.to_string());
    }
    if let Some(filter) = filter {
        query.append_pair("filter", filter);
    }
    format!("/api/v1/orgs/{org}/audit-events?{}", query.finish())
}

pub(super) async fn timeline(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    limit: u16,
    filter: Option<&str>,
) -> Result<Vec<AuditEvent>> {
    let mut query = AuditListQuery {
        limit,
        cursor: None,
        filter: filter
            .map(AuditFilter::parse)
            .transpose()
            .map_err(|_| "audit acceptance filter invalid")?
            .unwrap_or_default(),
    };
    let mut events = Vec::new();
    for _ in 0..64 {
        let reply = exchange(
            https,
            actor,
            "GET",
            &list_path(org, limit, query.cursor, filter),
            &[],
            &[],
            200,
        )
        .await?;
        let page = AuditPage::from_json_for(&reply.body, org, &query)
            .map_err(|_| "audit Page failed captured request validation")?;
        if events
            .last()
            .zip(page.items.first())
            .is_some_and(|(last, first): (&AuditEvent, _)| last.sequence <= first.sequence)
        {
            return Err("audit pagination repeated or reversed a sequence");
        }
        query.cursor = page.next_cursor;
        events.extend(page.items);
        if query.cursor.is_none() {
            return Ok(events);
        }
    }
    Err("audit fixture pagination exceeded its finite event budget")
}

async fn permission(https: &Https, actor: Actor<'_>, org: Uuid, status: u16) -> Result<()> {
    for suffix in ["audit-events?limit=1", "audit-events/verify?from_sequence=1&to_sequence=1"] {
        let reply = exchange(
            https,
            actor,
            "GET",
            &format!("/api/v1/orgs/{org}/{suffix}"),
            &[],
            &[],
            status,
        )
        .await?;
        if status >= 400 {
            let problem = ProblemDetails::from_json(&reply.body, MAX_AUDIT_PROBLEM_BYTES)
                .map_err(|_| "audit refusal problem invalid")?;
            if problem.status != status
                || problem.changed
                || problem.retryable
                || problem.code.as_str()
                    != if status == 404 { "organization.not_found" } else { "policy.denied" }
            {
                return Err("audit refusal semantics differ");
            }
        } else if suffix.starts_with("audit-events?") {
            AuditPage::from_json_for(
                &reply.body,
                org,
                &AuditListQuery { limit: 1, ..AuditListQuery::default() },
            )
            .map_err(|_| "allowed audit Page invalid")?;
        } else {
            let result = AuditVerification::from_json_for(
                &reply.body,
                org,
                AuditRange::new(1, 1).map_err(|_| "fixed range invalid")?,
            )
            .map_err(|_| "allowed audit Verification invalid")?;
            if !result.valid {
                return Err("genuine audit genesis did not verify");
            }
        }
    }
    Ok(())
}

async fn both(
    https: &Https,
    native: Actor<'_>,
    browser: &Browser,
    org: Uuid,
    status: u16,
) -> Result<()> {
    permission(https, native, org, status).await?;
    permission(https, browser.actor(), org, status).await
}

async fn filters(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    baseline: &[AuditEvent],
    owner: Uuid,
) -> Result<()> {
    let first = baseline.last().ok_or("genuine audit history is empty")?;
    let latest = baseline.first().ok_or("genuine audit history is empty")?;
    let after_latest = format_audit_timestamp(
        parse_audit_timestamp(&latest.occurred_at)
            .map_err(|_| "genuine audit timestamp invalid")?
            .checked_add(1)
            .ok_or("audit timestamp overflow")?,
    )
    .map_err(|_| "audit time upper bound invalid")?;
    let cases = [
        format!("occurred_at ge \"{}\"", first.occurred_at),
        format!("occurred_at lt \"{}\"", first.occurred_at),
        format!("occurred_at ge \"{}\"", latest.occurred_at),
        format!("occurred_at lt \"{}\"", latest.occurred_at),
        format!("actor_account_id eq \"{owner}\""),
        format!("resource eq \"organization:{org}\""),
        "event_class eq \"organization.name_updated\"".into(),
        "event_class eq \"unregistered.audit_fixture\"".into(),
        "outcome eq \"success\"".into(),
        "outcome eq \"failure\"".into(),
        "outcome eq \"unknown\"".into(),
        format!(
            "occurred_at ge \"{}\" and occurred_at lt \"{after_latest}\" and actor_account_id eq \"{owner}\" and resource eq \"organization:{org}\" and event_class eq \"organization.name_updated\" and outcome eq \"success\"",
            first.occurred_at
        ),
    ];
    for text in cases {
        let filter = AuditFilter::parse(&text).map_err(|_| "acceptance filter grammar invalid")?;
        let expected = baseline
            .iter()
            .filter_map(|event| match filter.matches(event) {
                Ok(true) => Some(Ok(event.clone())),
                Ok(false) => None,
                Err(_) => Some(Err("acceptance event/filter context invalid")),
            })
            .collect::<Result<Vec<_>>>()?;
        if timeline(https, actor, org, 2, Some(&text)).await? != expected {
            return Err("audit filter result differs from captured immutable history");
        }
    }
    Ok(())
}

async fn range(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    from: u64,
    to: u64,
    baseline: &[AuditEvent],
) -> Result<AuditVerification> {
    let selected = AuditRange::new(from, to).map_err(|_| "acceptance range invalid")?;
    let reply = exchange(
        https,
        actor,
        "GET",
        &format!("/api/v1/orgs/{org}/audit-events/verify?from_sequence={from}&to_sequence={to}"),
        &[],
        &[],
        200,
    )
    .await?;
    let result = AuditVerification::from_json_for(&reply.body, org, selected)
        .map_err(|_| "audit Verification failed captured range validation")?;
    let first = baseline
        .iter()
        .find(|event| event.sequence == from)
        .ok_or("acceptance range first event absent")?;
    let last = baseline
        .iter()
        .find(|event| event.sequence == to)
        .ok_or("acceptance range last event absent")?;
    if !result.valid
        || result.previous_hash != Some(first.previous_hash)
        || result.head_hash != Some(last.event_hash)
        || result.checkpoint.is_some()
        || result.uncheckpointed_from_sequence != Some(from)
    {
        return Err("audit range did not preserve genuine unsigned chain evidence");
    }
    Ok(result)
}

fn attribution(
    events: &[AuditEvent],
    org: Uuid,
    owner: &Registration,
    recipient: &Registration,
    host: Uuid,
) -> Result<()> {
    let created = events
        .iter()
        .find(|event| event.event_class.as_deref() == Some("organization.created"))
        .ok_or("public team creation audit absent")?;
    if created.actor_account_id != Some(owner.payload.account_id)
        || created.actor_device_id != Some(owner.device.id)
        || created.actor_browser_family_id.is_some()
        || created.resource
            != Some(AuditResource { kind: AuditResourceKind::Organization, id: org })
        || created.category != AuditCategory::AccountChange
        || created.outcome != AuditOutcome::Success
    {
        return Err("Device team creation audit attribution differs");
    }
    let renamed: Vec<_> = events
        .iter()
        .filter(|event| event.event_class.as_deref() == Some("organization.name_updated"))
        .collect();
    if renamed.len() != 2
        || renamed.iter().any(|event| {
            event.actor_account_id != Some(owner.payload.account_id)
                || event.actor_device_id.is_some()
                || event.actor_browser_family_id.is_none()
        })
        || renamed[0].actor_browser_family_id != renamed[1].actor_browser_family_id
    {
        return Err("browser refresh changed or fabricated the recorded audit actor");
    }
    let accepted = events
        .iter()
        .find(|event| event.event_class.as_deref() == Some("organization.invitation_accepted"))
        .ok_or("public invitation acceptance audit absent")?;
    if accepted.actor_account_id != Some(recipient.payload.account_id)
        || accepted.actor_device_id.is_some()
        || accepted.actor_browser_family_id.is_none()
        || accepted.actor_browser_family_id == renamed[0].actor_browser_family_id
    {
        return Err("independent browser acceptance actor differs");
    }
    let inventory = events
        .iter()
        .find(|event| event.event_class.as_deref() == Some("organization.inventory_created"))
        .ok_or("public inventory audit absent")?;
    if inventory.actor_device_id != Some(owner.device.id)
        || inventory.resource != Some(AuditResource { kind: AuditResourceKind::Host, id: host })
        || inventory.category != AuditCategory::Scoplen
    {
        return Err("public Host audit metadata differs");
    }
    if !events.iter().any(|event| {
        event.event_class.as_deref() == Some("organization.policies_created")
            && event.category == AuditCategory::Authorization
            && event.actor_browser_family_id == renamed[0].actor_browser_family_id
    }) {
        return Err("public policy audit attribution absent");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn verify(https: &Https) -> Result<()> {
    println!("audit acceptance: genuine Account and browser authentication");
    let owner = Registration::new(&https.origin)?;
    owner.register(https).await?;
    let recipient = Registration::new(&https.origin)?;
    recipient.register(https).await?;
    let owner_token = owner.device.authenticate(https).await?;
    let owner_token = owner.device.refresh(https, owner_token).await?;
    let recipient_token = recipient.device.authenticate(https).await?;
    let recipient_token = recipient.device.refresh(https, recipient_token).await?;
    let mut owner_browser = Browser::login(https, &owner).await?;
    let recipient_browser = Browser::login(https, &recipient).await?;
    let owner_actor = native(&owner, &owner_token);
    let recipient_actor = native(&recipient, &recipient_token);
    let org = create_team(https, owner_actor).await?.id;
    let foreign = create_team(https, recipient_browser.actor()).await?.id;
    both(https, owner_actor, &owner_browser, org, 200).await?;
    both(https, recipient_actor, &recipient_browser, foreign, 200).await?;
    both(https, owner_actor, &owner_browser, foreign, 404).await?;
    both(https, recipient_actor, &recipient_browser, org, 404).await?;
    both(https, owner_actor, &owner_browser, Uuid::now_v7(), 404).await?;
    rename_team(https, owner_browser.actor(), org, "Audit before browser refresh").await?;
    owner_browser.refresh(https).await?;
    rename_team(https, owner_browser.actor(), org, "Audit after browser refresh").await?;
    let host = create_host(https, owner_actor, org).await?;
    let membership = invite(https, owner_actor, recipient_browser.actor(), &recipient, org).await?;

    println!("audit acceptance: current roles and custom policy");
    both(https, recipient_actor, &recipient_browser, org, 403).await?;
    for role in [TeamRole::Administrator, TeamRole::Approver, TeamRole::SecurityAuditor] {
        update_member(https, owner_actor, org, membership, role, TeamMemberStatus::Active).await?;
        both(
            https,
            recipient_actor,
            &recipient_browser,
            org,
            if role == TeamRole::SecurityAuditor { 200 } else { 403 },
        )
        .await?;
    }
    update_member(https, owner_actor, org, membership, TeamRole::Member, TeamMemberStatus::Active)
        .await?;
    both(https, recipient_actor, &recipient_browser, org, 403).await?;
    let permit =
        create_policy(https, owner_browser.actor(), org, recipient.payload.account_id).await?;
    both(https, recipient_actor, &recipient_browser, org, 200).await?;
    let disabled = replace_policy(https, owner_browser.actor(), org, permit, false).await?;
    both(https, recipient_actor, &recipient_browser, org, 403).await?;
    let _enabled = replace_policy(https, owner_browser.actor(), org, disabled, true).await?;
    both(https, recipient_actor, &recipient_browser, org, 200).await?;
    update_member(
        https,
        owner_actor,
        org,
        membership,
        TeamRole::Member,
        TeamMemberStatus::Suspended,
    )
    .await?;
    both(https, recipient_actor, &recipient_browser, org, 404).await?;
    update_member(https, owner_actor, org, membership, TeamRole::Member, TeamMemberStatus::Active)
        .await?;
    both(https, recipient_actor, &recipient_browser, org, 200).await?;
    let current = member(https, owner_actor, org, membership).await?;
    exchange(
        https,
        owner_actor,
        "DELETE",
        &format!("/api/v1/orgs/{org}/members/{membership}"),
        &[],
        &[("If-Match", &current.etag)],
        204,
    )
    .await?;
    both(https, recipient_actor, &recipient_browser, org, 404).await?;
    both(https, recipient_actor, &recipient_browser, foreign, 200).await?;

    println!("audit acceptance: immutable attribution, filters and pagination");
    let baseline = timeline(https, owner_actor, org, 2, None).await?;
    let count = u64::try_from(baseline.len()).map_err(|_| "audit history count overflow")?;
    if count < 3
        || baseline.first().is_none_or(|event| event.sequence != count)
        || baseline.last().is_none_or(|event| event.sequence != 1)
        || baseline.windows(2).any(|pair| {
            pair[0].sequence != pair[1].sequence + 1 || pair[0].previous_hash != pair[1].event_hash
        })
    {
        return Err("public business audit history is not a contiguous immutable chain");
    }
    attribution(&baseline, org, &owner, &recipient, host)?;
    if timeline(https, owner_browser.actor(), org, 3, None).await? != baseline {
        return Err("Device and browser audit projections differ");
    }
    filters(https, owner_browser.actor(), org, &baseline, owner.payload.account_id).await?;
    let original_foreign = timeline(https, recipient_browser.actor(), foreign, 2, None).await?;
    if original_foreign.len() != 1
        || original_foreign[0].actor_device_id.is_some()
        || original_foreign[0].actor_account_id != Some(recipient.payload.account_id)
        || original_foreign[0].actor_browser_family_id.is_none()
    {
        return Err("independent browser team history differs");
    }

    println!("audit acceptance: genesis, predecessor and unsigned range evidence");
    range(https, owner_actor, org, 1, count, &baseline).await?;
    let first = range(https, owner_browser.actor(), org, 1, 1, &baseline).await?;
    let second = range(https, owner_actor, org, 2, count, &baseline).await?;
    if !first.can_join(&second) {
        return Err("genuine adjacent audit ranges did not join");
    }
    if timeline(https, owner_actor, org, 2, None).await? != baseline
        || timeline(https, recipient_browser.actor(), foreign, 2, None).await? != original_foreign
    {
        return Err("audit reads or authorization failures changed immutable projections");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
            ("x-request-id", "fixture-request"),
            ("content-type", "application/json"),
        ] {
            headers.insert(name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn audit_transport_keeps_page_range_and_problem_bounds_separate() {
        assert_eq!(response_limit("/api/v1/orgs/x/audit-events?limit=500", "GET", 200), 1_048_576);
        assert_eq!(
            response_limit("/api/v1/orgs/x/audit-events/verify?from_sequence=1", "GET", 200),
            4_096
        );
        assert_eq!(response_limit("/api/v1/orgs/x/audit-events", "GET", 503), 4_096);
        assert_eq!(response_limit(LOGIN, "POST", 200), 8_192);
    }

    #[test]
    fn grant_transport_separates_pages_resources_certificates_and_problems() {
        assert_eq!(response_limit("/api/v1/orgs/x/grants?limit=500", "GET", 200), 2_097_152);
        assert_eq!(response_limit("/api/v1/orgs/x/grants", "POST", 201), 4_096);
        assert_eq!(response_limit("/api/v1/orgs/x/grants/id", "GET", 200), 4_096);
        assert_eq!(response_limit("/api/v1/orgs/x/grants/id", "PUT", 200), 4_096);
        assert_eq!(response_limit("/api/v1/orgs/x/certificates", "POST", 201), 131_072);
        assert_eq!(response_limit("/api/v1/orgs/x/grants?limit=500", "GET", 503), 4_096);
        assert_eq!(response_limit("/api/v1/orgs/x/certificates", "POST", 403), 4_096);
    }

    #[test]
    fn snippet_transport_uses_exact_collection_resource_and_problem_bounds() {
        let org = Uuid::now_v7();
        let id = Uuid::now_v7();
        let collection = format!("/api/v1/orgs/{org}/snippets");
        let resource = format!("{collection}/{id}");
        assert_eq!(response_limit(&format!("{collection}?limit=500"), "GET", 200), 8_388_608);
        for (path, method) in [(&collection, "POST"), (&resource, "GET"), (&resource, "PUT")] {
            assert_eq!(response_limit(path, method, 200), 2_097_152);
            assert_eq!(response_limit(path, method, 404), 4_096);
        }
        for path in [
            format!("{collection}/extra/path"),
            format!("{collection}-other"),
            format!("{resource}/versions"),
            format!("/other{collection}"),
            "/api/v1/orgs/invalid/snippets".into(),
        ] {
            assert_eq!(response_limit(&path, "GET", 200), 8_192);
        }
    }

    #[test]
    fn audit_transport_rejects_cookie_resource_and_missing_privacy_metadata() {
        let path = "/api/v1/orgs/x/audit-events?limit=1";
        assert!(validate_headers(&headers(), path, 200).is_ok());
        for (name, value) in [
            ("set-cookie", "fixture-cookie"),
            ("etag", "fixture-tag"),
            ("access-control-allow-origin", "https://localhost"),
        ] {
            let mut invalid = headers();
            invalid.insert(name, value.parse().unwrap());
            assert!(validate_headers(&invalid, path, 200).is_err());
        }
        for name in ["cache-control", "pragma", "x-request-id", "content-type"] {
            let mut invalid = headers();
            invalid.remove(name);
            assert!(validate_headers(&invalid, path, 200).is_err());
        }
        let mut login = headers();
        login.insert("set-cookie", "fixture-cookie".parse().unwrap());
        assert!(validate_headers(&login, LOGIN, 200).is_ok());
        assert!(validate_headers(&login, OPTIONS, 200).is_err());
    }
}
