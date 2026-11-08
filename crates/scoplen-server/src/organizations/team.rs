// SPDX-License-Identifier: AGPL-3.0-only
//! Native, scope-separated D-136 team lifecycle routes.

use std::net::{IpAddr, SocketAddr};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Query, State},
    http::{Request, StatusCode, header, request::Parts},
    response::Response,
    routing::{delete, get, patch, post},
};
use scoplen_api::organization::{
    OrganizationListQuery, OrganizationPreconditionError, parse_organization_idempotency_key,
    parse_organization_if_match,
};
use scoplen_api::{
    auth::{AuthRateLimitHeaders, DeviceAccessOperation, DeviceAccessScope},
    team::{
        MAX_DISSOLUTION_REQUEST_BYTES, MAX_INVITATION_ACCEPT_BYTES, MAX_INVITATION_CREATE_BYTES,
        MAX_MEMBER_UPDATE_BYTES, TeamDissolveRequest, TeamInvitationAcceptRequest,
        TeamInvitationCreateRequest, TeamMemberUpdateRequest,
    },
};
use scoplen_crypto::SecretVec;
use scoplen_store::account_entry_admission::{
    AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryPrivateBucket,
    VerifiedAccountBucket,
};
use scoplen_store::organizations::OrganizationStoreError;
use uuid::Uuid;

use super::{OrganizationState, invalid, problem, reply, specific_problem, store_problem};
use crate::device_auth::{AuthBackend, json_body, matching_origin};

pub(super) fn routes() -> Router<OrganizationState> {
    Router::new()
        .route("/api/v1/orgs/{org}/invitations", get(handle))
        .route("/api/v1/orgs/{org}/invitations", post(handle))
        .route("/api/v1/orgs/{org}/invitations/{invitation}", get(handle))
        .route("/api/v1/orgs/{org}/invitations/{invitation}", delete(handle))
        .route("/api/v1/orgs/{org}/invitations/{invitation}/accept", post(handle))
        .route("/api/v1/orgs/{org}/members", get(handle))
        .route("/api/v1/orgs/{org}/members/{membership}", get(handle))
        .route("/api/v1/orgs/{org}/members/{membership}", patch(handle))
        .route("/api/v1/orgs/{org}/members/{membership}", delete(handle))
        .route("/api/v1/orgs/{org}/dissolve", post(handle))
        .route("/join-team", get(landing))
}

async fn landing() -> Response {
    reply(StatusCode::OK,"text/html; charset=utf-8",b"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Join a Scoplen team</title><main><h1>Join a Scoplen team</h1><p>Open Join team in Scoplen. Paste this invitation link and enter the separate invitation password supplied by your team administrator.</p><p>Sign in with the account named in the invitation. This page does not accept invitations.</p></main></html>".to_vec(),&Uuid::new_v4())
}

fn route(parts: &Parts) -> Option<(DeviceAccessOperation, &str, Option<&str>)> {
    let segments: Vec<_> = parts.uri.path().split('/').collect();
    let (template, org, target) = match segments.as_slice() {
        ["", "api", "v1", "orgs", org, "invitations"] => {
            ("/api/v1/orgs/{org}/invitations", *org, None)
        }
        ["", "api", "v1", "orgs", org, "invitations", id] => {
            ("/api/v1/orgs/{org}/invitations/{invitation}", *org, Some(*id))
        }
        ["", "api", "v1", "orgs", org, "invitations", id, "accept"] => {
            ("/api/v1/orgs/{org}/invitations/{invitation}/accept", *org, Some(*id))
        }
        ["", "api", "v1", "orgs", org, "members"] => ("/api/v1/orgs/{org}/members", *org, None),
        ["", "api", "v1", "orgs", org, "members", id] => {
            ("/api/v1/orgs/{org}/members/{membership}", *org, Some(*id))
        }
        ["", "api", "v1", "orgs", org, "dissolve"] => ("/api/v1/orgs/{org}/dissolve", *org, None),
        _ => return None,
    };
    Some((DeviceAccessOperation::from_route(parts.method.as_str(), template)?, org, target))
}

pub(super) fn endpoint(operation: DeviceAccessOperation) -> Option<AccountEntryEndpoint> {
    Some(match operation {
        DeviceAccessOperation::TeamInvitationCreate => AccountEntryEndpoint::TeamInvitationCreate,
        DeviceAccessOperation::TeamInvitationAccept => AccountEntryEndpoint::TeamInvitationAccept,
        DeviceAccessOperation::TeamInvitationRevoke => AccountEntryEndpoint::TeamInvitationRevoke,
        DeviceAccessOperation::TeamMemberUpdate => AccountEntryEndpoint::TeamMemberUpdate,
        DeviceAccessOperation::TeamMemberRemove => AccountEntryEndpoint::TeamMemberRemove,
        DeviceAccessOperation::TeamDissolve => AccountEntryEndpoint::TeamDissolve,
        DeviceAccessOperation::InventoryHostCreate => AccountEntryEndpoint::InventoryHostCreate,
        DeviceAccessOperation::InventoryHostReplace => AccountEntryEndpoint::InventoryHostReplace,
        DeviceAccessOperation::InventoryHostDelete => AccountEntryEndpoint::InventoryHostDelete,
        DeviceAccessOperation::InventoryAccessProfileCreate => {
            AccountEntryEndpoint::InventoryAccessProfileCreate
        }
        DeviceAccessOperation::InventoryAccessProfileReplace => {
            AccountEntryEndpoint::InventoryAccessProfileReplace
        }
        DeviceAccessOperation::InventoryAccessProfileDelete => {
            AccountEntryEndpoint::InventoryAccessProfileDelete
        }
        DeviceAccessOperation::InventoryRouteCreate => AccountEntryEndpoint::InventoryRouteCreate,
        DeviceAccessOperation::InventoryRouteReplace => AccountEntryEndpoint::InventoryRouteReplace,
        DeviceAccessOperation::InventoryRouteDelete => AccountEntryEndpoint::InventoryRouteDelete,
        DeviceAccessOperation::InventoryHostGroupCreate => {
            AccountEntryEndpoint::InventoryHostGroupCreate
        }
        DeviceAccessOperation::InventoryHostGroupReplace => {
            AccountEntryEndpoint::InventoryHostGroupReplace
        }
        DeviceAccessOperation::InventoryHostGroupDelete => {
            AccountEntryEndpoint::InventoryHostGroupDelete
        }
        DeviceAccessOperation::InventoryTrustRecordCreate => {
            AccountEntryEndpoint::InventoryTrustRecordCreate
        }
        DeviceAccessOperation::InventoryTrustRecordReplace => {
            AccountEntryEndpoint::InventoryTrustRecordReplace
        }
        DeviceAccessOperation::InventoryTrustRecordDelete => {
            AccountEntryEndpoint::InventoryTrustRecordDelete
        }
        DeviceAccessOperation::InventorySnippetCreate => {
            AccountEntryEndpoint::InventorySnippetCreate
        }
        DeviceAccessOperation::InventorySnippetReplace => {
            AccountEntryEndpoint::InventorySnippetReplace
        }
        DeviceAccessOperation::InventorySnippetDelete => {
            AccountEntryEndpoint::InventorySnippetDelete
        }
        DeviceAccessOperation::InventoryGatewayNetworkCreate => {
            AccountEntryEndpoint::InventoryGatewayNetworkCreate
        }
        DeviceAccessOperation::InventoryGatewayNetworkReplace => {
            AccountEntryEndpoint::InventoryGatewayNetworkReplace
        }
        DeviceAccessOperation::InventoryGatewayNetworkDelete => {
            AccountEntryEndpoint::InventoryGatewayNetworkDelete
        }
        DeviceAccessOperation::OrganizationGroupCreate => {
            AccountEntryEndpoint::OrganizationGroupCreate
        }
        DeviceAccessOperation::OrganizationGroupReplace => {
            AccountEntryEndpoint::OrganizationGroupReplace
        }
        DeviceAccessOperation::OrganizationGroupDelete => {
            AccountEntryEndpoint::OrganizationGroupDelete
        }
        DeviceAccessOperation::OrganizationPolicyCreate => {
            AccountEntryEndpoint::OrganizationPolicyCreate
        }
        DeviceAccessOperation::OrganizationPolicyReplace => {
            AccountEntryEndpoint::OrganizationPolicyReplace
        }
        DeviceAccessOperation::OrganizationPolicyDelete => {
            AccountEntryEndpoint::OrganizationPolicyDelete
        }
        DeviceAccessOperation::UserCaCreate => AccountEntryEndpoint::OrganizationUserCaCreate,
        DeviceAccessOperation::UserCertificateIssue => {
            AccountEntryEndpoint::OrganizationUserCertificateIssue
        }
        _ => return None,
    })
}

#[allow(clippy::result_large_err)]
pub(super) async fn admission(
    state: &OrganizationState,
    endpoint: AccountEntryEndpoint,
    source: IpAddr,
    account: Option<Uuid>,
    id: &Uuid,
) -> Result<(), Response> {
    let result = if let Some(account) = account {
        let account = VerifiedAccountBucket::after_authentication(account)
            .map_err(|_| store_problem(OrganizationStoreError::StorageUnavailable, id))?;
        let bucket = AccountEntryPrivateBucket::EstablishedAccount(account);
        match &state.backend {
            AuthBackend::Sqlite(store) => {
                store.admit_account_entry_private(endpoint, source, bucket).await
            }
            AuthBackend::Postgres(store) => {
                store.admit_account_entry_private(endpoint, source, bucket).await
            }
        }
    } else {
        match &state.backend {
            AuthBackend::Sqlite(store) => store.admit_account_entry_source(endpoint, source).await,
            AuthBackend::Postgres(store) => {
                store.admit_account_entry_source(endpoint, source).await
            }
        }
    };
    match result {
        Ok(AccountEntryAdmissionDecision::Admitted) => Ok(()),
        Ok(AccountEntryAdmissionDecision::RateLimited(wait)) => {
            let mut result = specific_problem(
                StatusCode::TOO_MANY_REQUESTS,
                "auth.rate_limited",
                "Team operation rate limited",
                "Wait for Retry-After before trying again.",
                false,
                true,
                id,
            );
            let rate = AuthRateLimitHeaders::new(
                u16::try_from(wait.clamp(1, 300)).expect("bounded delay"),
            )
            .expect("bounded rate");
            result.headers_mut().insert(
                header::RETRY_AFTER,
                rate.retry_after_seconds().to_string().parse().expect("bounded delay"),
            );
            result.headers_mut().insert(
                "ratelimit-policy",
                rate.rate_limit_policy().parse().expect("static rate policy"),
            );
            result
                .headers_mut()
                .insert("ratelimit", rate.rate_limit().parse().expect("bounded rate state"));
            Err(result)
        }
        Err(_) => Err(store_problem(OrganizationStoreError::StorageUnavailable, id)),
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn precondition(parts: &Parts, id: &Uuid) -> Result<String, Response> {
    if parts.headers.get_all(header::IF_MATCH).iter().count() > 1 {
        return Err(invalid(id));
    }
    let raw = parts
        .headers
        .get(header::IF_MATCH)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| invalid(id))?;
    match parse_organization_if_match(raw) {
        Ok(value) => Ok(value.to_owned()),
        Err(OrganizationPreconditionError::Required) => Err(problem(
            StatusCode::PRECONDITION_REQUIRED,
            "organization.precondition_required",
            false,
            id,
        )),
        Err(OrganizationPreconditionError::Invalid) => Err(invalid(id)),
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn operation_key(parts: &Parts, id: &Uuid) -> Result<Uuid, Response> {
    if parts.headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(invalid(id));
    }
    parts
        .headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_organization_idempotency_key(v).ok())
        .ok_or_else(|| invalid(id))
}

#[allow(clippy::result_large_err)]
pub(super) async fn body(
    parts: &Parts,
    body: Body,
    max: usize,
    id: &Uuid,
) -> Result<SecretVec, Response> {
    if parts.headers.contains_key(header::CONTENT_ENCODING)
        && (parts.headers.get_all(header::CONTENT_ENCODING).iter().count() != 1
            || parts.headers.get(header::CONTENT_ENCODING).is_none_or(|value| value != "identity"))
    {
        return Err(invalid(id));
    }
    json_body(&parts.headers, body, max)
        .await
        .map(|text| SecretVec::new(text.into_bytes()))
        .map_err(|status| problem(status, "organization.invalid_request", false, id))
}

pub(super) fn encoded(
    value: Result<Vec<u8>, scoplen_api::organization::OrganizationCodecError>,
    etag: Option<&str>,
    status: StatusCode,
    id: &Uuid,
) -> Response {
    let Ok(value) = value else {
        return store_problem(OrganizationStoreError::StorageUnavailable, id);
    };
    let mut result = reply(status, "application/json", value, id);
    if let Some(etag) = etag {
        let Ok(etag) = etag.parse() else {
            return store_problem(OrganizationStoreError::StorageUnavailable, id);
        };
        result.headers_mut().insert(header::ETAG, etag);
    }
    result
}

#[allow(clippy::too_many_lines)]
async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<OrganizationState>,
    request: Request<Body>,
) -> Response {
    let id = Uuid::new_v4();
    let (parts, request_body) = request.into_parts();
    let Some((operation, organization, target)) = route(&parts) else { return invalid(&id) };
    let admission_endpoint = endpoint(operation);
    if let Some(endpoint) = admission_endpoint
        && let Err(response) = admission(&state, endpoint, peer.ip(), None, &id).await
    {
        return response;
    }
    if parts.headers.contains_key(header::ORIGIN) && !matching_origin(&parts.headers, &state.origin)
    {
        return problem(StatusCode::FORBIDDEN, "policy.denied", false, &id);
    }
    let (principal, expires_at, scopes) = match state
        .auth
        .authenticate_request_with_scopes(operation, &parts.method, &parts.uri, &parts.headers)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return problem(
                error.status,
                match error.status {
                    StatusCode::FORBIDDEN => "policy.denied",
                    StatusCode::SERVICE_UNAVAILABLE => "organization.storage_unavailable",
                    _ => "auth.authentication_required",
                },
                false,
                &id,
            );
        }
    };
    if let Some(endpoint) = admission_endpoint
        && let Err(response) = admission(
            &state,
            endpoint,
            peer.ip(),
            Some(Uuid::from_bytes(principal.account_id)),
            &id,
        )
        .await
    {
        return response;
    }
    let Ok(organization) = parse_organization_idempotency_key(organization) else {
        return invalid(&id);
    };
    let Ok(target) = target.map(parse_organization_idempotency_key).transpose() else {
        return invalid(&id);
    };
    let manage = DeviceAccessScope::TeamsManage.is_present_in(&scopes);
    let join = DeviceAccessScope::TeamsJoin.is_present_in(&scopes);
    let paged = matches!(
        operation,
        DeviceAccessOperation::TeamInvitationList | DeviceAccessOperation::TeamMemberList
    );
    if !paged && parts.uri.query().is_some() {
        return invalid(&id);
    }
    let needs_key = matches!(
        operation,
        DeviceAccessOperation::TeamInvitationCreate
            | DeviceAccessOperation::TeamInvitationAccept
            | DeviceAccessOperation::TeamDissolve
    );
    let key = if needs_key {
        match operation_key(&parts, &id) {
            Ok(key) => Some(key),
            Err(response) => return response,
        }
    } else {
        if parts.headers.contains_key("idempotency-key") {
            return invalid(&id);
        }
        None
    };
    let needs_match = matches!(
        operation,
        DeviceAccessOperation::TeamInvitationRevoke
            | DeviceAccessOperation::TeamMemberUpdate
            | DeviceAccessOperation::TeamMemberRemove
            | DeviceAccessOperation::TeamDissolve
    );
    let if_match = if needs_match {
        match precondition(&parts, &id) {
            Ok(value) => Some(value),
            Err(response) => return response,
        }
    } else {
        if parts.headers.contains_key(header::IF_MATCH) {
            return invalid(&id);
        }
        None
    };
    let max = match operation {
        DeviceAccessOperation::TeamInvitationCreate => MAX_INVITATION_CREATE_BYTES,
        DeviceAccessOperation::TeamInvitationAccept => MAX_INVITATION_ACCEPT_BYTES,
        DeviceAccessOperation::TeamMemberUpdate => MAX_MEMBER_UPDATE_BYTES,
        DeviceAccessOperation::TeamDissolve => MAX_DISSOLUTION_REQUEST_BYTES,
        _ => 0,
    };
    let payload = if max == 0 {
        if to_bytes(request_body, 0).await.is_err() {
            return invalid(&id);
        }
        SecretVec::new(Vec::new())
    } else {
        match body(&parts, request_body, max, &id).await {
            Ok(value) => value,
            Err(response) => return response,
        }
    };
    macro_rules! call {($method:ident $(,$arg:expr)* $(,)?)=>{match &state.backend {
        AuthBackend::Sqlite(store)=>store.$method(&principal,expires_at,organization $(,$arg)*).await,
        AuthBackend::Postgres(store)=>store.$method(&principal,expires_at,organization $(,$arg)*).await,
    }}}
    macro_rules! resource {
        ($result:expr,$status:expr) => {
            match $result {
                Ok(value) => encoded(value.to_json(), Some(&value.etag), $status, &id),
                Err(error) => store_problem(error, &id),
            }
        };
    }
    macro_rules! receipt {
        ($result:expr) => {
            match $result {
                Ok(value) => encoded(value.to_json(), None, StatusCode::OK, &id),
                Err(error) => store_problem(error, &id),
            }
        };
    }
    match operation {
        DeviceAccessOperation::TeamInvitationCreate => {
            let Ok(decoded) = TeamInvitationCreateRequest::from_json(payload.as_bytes()) else {
                return invalid(&id);
            };
            resource!(
                call!(create_team_invitation, key.expect("validated key"), &decoded),
                StatusCode::CREATED
            )
        }
        DeviceAccessOperation::TeamInvitationAccept => {
            let Ok(decoded) = TeamInvitationAcceptRequest::from_json(payload.as_bytes()) else {
                return invalid(&id);
            };
            let result = match &state.backend {
                AuthBackend::Sqlite(store) => {
                    store
                        .accept_team_invitation(
                            &principal,
                            expires_at,
                            &state.origin,
                            organization,
                            target.expect("target route"),
                            key.expect("validated key"),
                            &decoded,
                        )
                        .await
                }
                AuthBackend::Postgres(store) => {
                    store
                        .accept_team_invitation(
                            &principal,
                            expires_at,
                            &state.origin,
                            organization,
                            target.expect("target route"),
                            key.expect("validated key"),
                            &decoded,
                        )
                        .await
                }
            };
            if result.is_ok() {
                super::notify_membership_account(&state, principal.account_id).await;
                super::notify_organization(&state, organization).await;
            }
            receipt!(result)
        }
        DeviceAccessOperation::TeamInvitationRead => resource!(
            call!(read_team_invitation, target.expect("target route"), manage, join),
            StatusCode::OK
        ),
        DeviceAccessOperation::TeamInvitationRevoke => match call!(
            revoke_team_invitation,
            target.expect("target route"),
            if_match.as_deref().expect("validated precondition")
        ) {
            Ok(()) => reply(StatusCode::NO_CONTENT, "application/json", Vec::new(), &id),
            Err(error) => store_problem(error, &id),
        },
        DeviceAccessOperation::TeamInvitationList | DeviceAccessOperation::TeamMemberList => {
            let Ok(Query(parameters)) = Query::<Vec<(String, String)>>::try_from_uri(&parts.uri)
            else {
                return invalid(&id);
            };
            let Ok(query) = OrganizationListQuery::from_parameters(
                parameters.iter().map(|(key, value)| (key.as_str(), value.as_str())),
            ) else {
                return invalid(&id);
            };
            if operation == DeviceAccessOperation::TeamInvitationList {
                receipt!(call!(list_team_invitations, query))
            } else {
                receipt!(call!(list_team_members, query))
            }
        }
        DeviceAccessOperation::TeamMemberRead => {
            resource!(call!(read_team_member, target.expect("target route")), StatusCode::OK)
        }
        DeviceAccessOperation::TeamMemberUpdate | DeviceAccessOperation::TeamMemberRemove => {
            let decoded = if operation == DeviceAccessOperation::TeamMemberUpdate {
                match TeamMemberUpdateRequest::from_json(payload.as_bytes()) {
                    Ok(value) => Some(value),
                    Err(_) => return invalid(&id),
                }
            } else {
                None
            };
            match call!(
                change_team_member,
                target.expect("target route"),
                if_match.as_deref().expect("validated precondition"),
                manage,
                join,
                decoded.as_ref()
            ) {
                Ok(value) => {
                    super::notify_memberships(&state, organization, target).await;
                    super::notify_organization(&state, organization).await;
                    match value {
                        Some(value) => {
                            encoded(value.to_json(), Some(&value.etag), StatusCode::OK, &id)
                        }
                        None => reply(StatusCode::NO_CONTENT, "application/json", Vec::new(), &id),
                    }
                }
                Err(error) => store_problem(error, &id),
            }
        }
        DeviceAccessOperation::TeamDissolve => {
            let Ok(decoded) = TeamDissolveRequest::from_json(payload.as_bytes()) else {
                return invalid(&id);
            };
            let result = call!(
                dissolve_team,
                key.expect("validated key"),
                if_match.as_deref().expect("validated precondition"),
                &decoded
            );
            if result.is_ok() {
                super::notify_memberships(&state, organization, None).await;
            }
            receipt!(result)
        }
        _ => invalid(&id),
    }
}
