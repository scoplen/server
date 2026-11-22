// SPDX-License-Identifier: AGPL-3.0-only
//! Independent request failure acceptance against the production HTTPS listener.

use scoplen_api::{
    access_request::{
        AccessRequestCheckRequest, AccessRequestCheckResponse, AccessRequestCreateRequest,
        AccessRequestDecisionRequest, AccessRequestFields, AccessRequestListQuery,
        AccessRequestOutcome, AccessRequestPage, AccessRequestResource, AccessRequestStatus,
        AccessRequestView,
    },
    audit::{AuditCategory, AuditEvent, AuditOutcome, AuditResource, AuditResourceKind},
    auth::AuthTokenResponse,
    grant::GrantResource,
    group_policy::{PolicyResource, SimpleRule, SimpleRuleSelector},
    inventory::{InventoryResource, InventoryType},
    organization::OrganizationListQuery,
    sync::{SyncSessionRequest, SyncSessionResponse},
    team::{TeamMemberStatus, TeamRole},
};
use scoplen_model::ObjectType;
use serde_json::json;
use std::fmt::Write as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::super::{
    Registration,
    audit::{
        Actor, Browser, Reply, create_team, exchange, invite, lose_response, native,
        replace_policy, timeline, update_member,
    },
};
use super::{asset, list, policy, problem, rule, withdraw};
use crate::{Https, Result};

const REASON: &str = "  independently reviewed\nmaintenance\t ";

struct Context<'a> {
    https: &'a Https,
    owner: &'a Registration,
    owner_token: &'a AuthTokenResponse,
    member: &'a Registration,
    org: Uuid,
    membership: Uuid,
    host: InventoryResource,
    view: PolicyResource,
    request: PolicyResource,
}

struct Written {
    path: String,
    body: Zeroizing<Vec<u8>>,
    key: String,
    if_match: Option<String>,
    status: u16,
    original: Zeroizing<Vec<u8>>,
    resource: AccessRequestResource,
}

impl Written {
    fn headers(&self) -> Vec<(&str, &str)> {
        let mut headers = vec![("Idempotency-Key", self.key.as_str())];
        if let Some(etag) = &self.if_match {
            headers.push(("If-Match", etag.as_str()));
        }
        headers
    }
}

#[derive(Eq, PartialEq)]
struct Snapshot {
    revision: u64,
    events: Vec<AuditEvent>,
    grants: Vec<GrantResource>,
}

#[derive(Clone, Copy)]
struct ExpectedActor {
    account: Uuid,
    device: Option<Uuid>,
}

impl ExpectedActor {
    fn matches(self, event: &AuditEvent) -> bool {
        event.actor_account_id == Some(self.account)
            && event.actor_device_id == self.device
            && event.actor_browser_family_id.is_some() == self.device.is_none()
            && event.category == AuditCategory::Authorization
            && event.outcome == AuditOutcome::Success
    }
}

fn resource(reply: &Reply) -> Result<AccessRequestResource> {
    AccessRequestResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Request HTTPS Resource is invalid")
}

impl Context<'_> {
    fn base(&self) -> String {
        format!("/api/v1/orgs/{}/access-requests", self.org)
    }

    fn fields(&self) -> AccessRequestFields {
        AccessRequestFields {
            host: self.host.id,
            remote_user: "deploy".into(),
            duration_seconds: 120,
            reason: REASON.into(),
        }
    }

    async fn snapshot(&self) -> Result<Snapshot> {
        let body = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: self.owner.device.id,
        }
        .to_cbor()
        .map_err(|_| "Request HTTPS sync session input is invalid")?;
        let bytes = self
            .https
            .exchange(
                "POST",
                "/sync/v1/session",
                &body,
                Some((&self.owner.device.keys.signing, Some(&self.owner_token.access_token))),
                200,
            )
            .await?;
        let session = SyncSessionResponse::from_cbor(&bytes)
            .map_err(|_| "Request HTTPS sync session is invalid")?;
        let revision = session
            .vaults
            .iter()
            .filter_map(|vault| vault.organization)
            .find(|context| context.organization == self.org)
            .ok_or("Request HTTPS team view is missing")?
            .view_revision;
        let owner = native(self.owner, self.owner_token);
        Ok(Snapshot {
            revision,
            events: timeline(self.https, owner, self.org, 100, None).await?,
            grants: list(self.https, owner, self.org).await?,
        })
    }

    async fn write(
        &self,
        actor: Actor<'_>,
        path: String,
        body: Vec<u8>,
        if_match: Option<String>,
        status: u16,
    ) -> Result<Written> {
        let key = Uuid::now_v7().to_string();
        let mut headers = vec![("Idempotency-Key", key.as_str())];
        if let Some(etag) = &if_match {
            headers.push(("If-Match", etag.as_str()));
        }
        let reply = exchange(self.https, actor, "POST", &path, &body, &headers, status).await?;
        let resource = resource(&reply)?;
        Ok(Written {
            path,
            body: Zeroizing::new(body),
            key,
            if_match,
            status,
            original: reply.body,
            resource,
        })
    }

    async fn create(&self, actor: Actor<'_>, account: Uuid) -> Result<Written> {
        self.create_fields(actor, account, self.fields()).await
    }

    async fn write_losing_response(
        &self,
        actor: Actor<'_>,
        path: String,
        body: Vec<u8>,
        if_match: Option<String>,
        status: u16,
        id: Uuid,
    ) -> Result<Written> {
        let key = Uuid::now_v7().to_string();
        let mut headers = vec![("Idempotency-Key", key.as_str())];
        if let Some(etag) = &if_match {
            headers.push(("If-Match", etag.as_str()));
        }
        lose_response(self.https, actor, &path, &body, &headers).await?;
        let reply =
            exchange(self.https, actor, "GET", &format!("{}/{id}", self.base()), &[], &[], 200)
                .await?;
        let resource = resource(&reply)?;
        resource.validate_for_id(id).map_err(|_| "Request HTTPS observed state changed its id")?;
        // This read observes current state; only original-writer/key confirmation proves the operation.
        Ok(Written {
            path,
            body: Zeroizing::new(body),
            key,
            if_match,
            status,
            original: reply.body,
            resource,
        })
    }

    async fn create_fields(
        &self,
        actor: Actor<'_>,
        account: Uuid,
        fields: AccessRequestFields,
    ) -> Result<Written> {
        let request = AccessRequestCreateRequest { id: Uuid::now_v7(), fields };
        let body = request.to_json().map_err(|_| "Request HTTPS create input is invalid")?;
        let written = self.write(actor, self.base(), body, None, 201).await?;
        written
            .resource
            .validate_for_create(&request, account)
            .map_err(|_| "Request HTTPS create changed its identity or exact input")?;
        if written.resource.status != AccessRequestStatus::Pending {
            return Err("Request HTTPS creation was not pending");
        }
        Ok(written)
    }

    async fn get(&self, actor: Actor<'_>, id: Uuid) -> Result<AccessRequestResource> {
        let value = resource(
            &exchange(self.https, actor, "GET", &format!("{}/{id}", self.base()), &[], &[], 200)
                .await?,
        )?;
        value.validate_for_id(id).map_err(|_| "Request HTTPS read changed its id")?;
        Ok(value)
    }

    async fn page(
        &self,
        actor: Actor<'_>,
        account: Uuid,
        view: AccessRequestView,
    ) -> Result<Vec<AccessRequestResource>> {
        let mut query =
            AccessRequestListQuery { view, page: OrganizationListQuery { limit: 2, cursor: None } };
        let mut items = Vec::new();
        for _ in 0..16 {
            let view = if view == AccessRequestView::Mine { "mine" } else { "approvals" };
            let mut path = format!("{}?view={view}&limit=2", self.base());
            if let Some(cursor) = query.page.cursor {
                write!(path, "&cursor={cursor}")
                    .map_err(|_| "Request HTTPS Page query encoding failed")?;
            }
            let reply = exchange(self.https, actor, "GET", &path, &[], &[], 200).await?;
            if reply.header("etag").is_some() {
                return Err("Request HTTPS Page disclosed an ETag");
            }
            let page = AccessRequestPage::from_http_json(
                &reply.body,
                reply.header("cache-control"),
                reply.header("pragma"),
            )
            .map_err(|_| "Request HTTPS Page is invalid")?;
            page.validate_for_query(account, query)
                .map_err(|_| "Request HTTPS Page changed its owner or cursor")?;
            query.page.cursor = page.next_cursor;
            items.extend(page.items);
            if query.page.cursor.is_none() {
                return Ok(items);
            }
        }
        Err("Request HTTPS pagination exceeded the finite fixture")
    }

    async fn confirm(&self, actor: Actor<'_>, written: &Written) -> Result<()> {
        let before = self.snapshot().await?;
        let reply = exchange(
            self.https,
            actor,
            "POST",
            &written.path,
            &written.body,
            &written.headers(),
            written.status,
        )
        .await?;
        if resource(&reply)? != written.resource
            || reply.body != written.original
            || self.snapshot().await? != before
        {
            return Err("Request HTTPS original confirmation changed bytes or durable state");
        }
        Ok(())
    }

    async fn failure(
        &self,
        actor: Actor<'_>,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
        status: u16,
        code: &str,
    ) -> Result<()> {
        let before = self.snapshot().await?;
        problem(
            &exchange(self.https, actor, "POST", path, body, headers, status).await?,
            status,
            code,
        )?;
        if self.snapshot().await? != before {
            return Err("Request HTTPS failure changed durable request effects");
        }
        Ok(())
    }
}

async fn terminal(
    c: &Context<'_>,
    actor: Actor<'_>,
    original: &AccessRequestResource,
    decision: Option<AccessRequestOutcome>,
) -> Result<Written> {
    terminal_reply(c, actor, original, decision, false).await
}

async fn terminal_reply(
    c: &Context<'_>,
    actor: Actor<'_>,
    original: &AccessRequestResource,
    decision: Option<AccessRequestOutcome>,
    lose_reply: bool,
) -> Result<Written> {
    let (suffix, body) = if let Some(decision) = decision {
        (
            "decisions",
            AccessRequestDecisionRequest { decision }
                .to_json()
                .map_err(|_| "Request HTTPS decision input is invalid")?,
        )
    } else {
        ("cancel", Vec::new())
    };
    let path = format!("{}/{}/{suffix}", c.base(), original.id);
    let written = if lose_reply {
        c.write_losing_response(actor, path, body, Some(original.etag.clone()), 200, original.id)
            .await?
    } else {
        c.write(actor, path, body, Some(original.etag.clone()), 200).await?
    };
    if let Some(decision) = decision {
        written
            .resource
            .validate_for_decision(
                original,
                AccessRequestDecisionRequest { decision },
                c.owner.payload.account_id,
            )
            .map_err(|_| "Request HTTPS decision changed the reviewed request or actor")?;
    } else {
        written
            .resource
            .validate_for_cancel(original, original.requester_account_id)
            .map_err(|_| "Request HTTPS cancellation changed the original request")?;
    }
    Ok(written)
}

async fn check(c: &Context<'_>, actor: Actor<'_>, allowed: bool) -> Result<()> {
    let before = c.snapshot().await?;
    let body = AccessRequestCheckRequest { fields: c.fields() }
        .to_json()
        .map_err(|_| "Request HTTPS check input is invalid")?;
    let reply =
        exchange(c.https, actor, "POST", &format!("{}/check", c.base()), &body, &[], 200).await?;
    if reply.header("etag").is_some()
        || AccessRequestCheckResponse::from_json(&reply.body)
            .map_err(|_| "Request HTTPS check response is invalid")?
            .allowed
            != allowed
        || c.snapshot().await? != before
    {
        return Err("Request HTTPS check changed state or returned the wrong eligibility");
    }
    Ok(())
}

async fn self_and_host_guard(
    c: &Context<'_>,
    actor: Actor<'_>,
    expected: ExpectedActor,
) -> Result<()> {
    let host = asset(
        c.https,
        actor,
        c.org,
        InventoryType::Host,
        json!({"name":"Pending-only deletion guard","address":"guard.example.test"}),
    )
    .await?;
    let mut fields = c.fields();
    fields.host = host.id;
    let before = c.snapshot().await?;
    let pending = c.create_fields(actor, expected.account, fields).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &pending.resource,
        expected,
        "organization.access_request_created",
    )?;
    c.failure(
        actor,
        &format!("{}/{}/decisions", c.base(), pending.resource.id),
        br#"{"decision":"approve"}"#,
        &[("Idempotency-Key", pending.key.as_str())],
        404,
        "organization.not_found",
    )
    .await?;
    let path = format!("/api/v1/orgs/{}/hosts/{}", c.org, host.id);
    let before = c.snapshot().await?;
    problem(
        &exchange(c.https, actor, "DELETE", &path, &[], &[("If-Match", &host.etag)], 409).await?,
        409,
        "organization.conflict",
    )?;
    if c.snapshot().await? != before {
        return Err("Request HTTPS pending Host deletion changed state");
    }
    let cancelled = terminal(c, actor, &pending.resource, None).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &cancelled.resource,
        expected,
        "organization.access_request_cancelled",
    )?;
    exchange(c.https, actor, "DELETE", &path, &[], &[("If-Match", &host.etag)], 204).await?;
    if c.get(actor, pending.resource.id).await? != cancelled.resource {
        return Err("Request HTTPS terminal Host history did not retain its original opaque id");
    }
    c.confirm(actor, &cancelled).await?;
    Ok(())
}

async fn current_routing(
    c: &mut Context<'_>,
    requester: Actor<'_>,
    approver: Actor<'_>,
    pending: &Written,
    cancellable: &Written,
    member_actor: ExpectedActor,
) -> Result<PolicyResource> {
    let path = format!("{}/{}/decisions", c.base(), pending.resource.id);
    let routing = policy(c.https, approver, c.org, format!(
        "forbid(principal == Account::\"{}\", action == Action::\"approve_access\", resource == AccessRequest::\"{}\");",
        c.owner.payload.account_id, pending.resource.id)).await?;
    c.failure(
        approver,
        &path,
        br#"{"decision":"approve"}"#,
        &[("Idempotency-Key", pending.key.as_str())],
        404,
        "organization.not_found",
    )
    .await?;
    let inaccessible = exchange(
        c.https,
        approver,
        "GET",
        &format!("{}/{}", c.base(), pending.resource.id),
        &[],
        &[],
        404,
    )
    .await?;
    problem(&inaccessible, 404, "organization.not_found")?;
    if c.get(requester, pending.resource.id).await? != pending.resource
        || c.page(approver, c.owner.payload.account_id, AccessRequestView::Approvals)
            .await?
            .iter()
            .any(|item| item.id == pending.resource.id)
    {
        return Err("Request HTTPS routing failed to separate own history and current approvals");
    }
    let routing = replace_policy(c.https, approver, c.org, routing, false).await?;
    let hidden = policy(c.https, approver, c.org, format!(
        "forbid(principal == Account::\"{}\", action == Action::\"view_inventory\", resource == Host::\"{}\");",
        c.owner.payload.account_id, c.host.id)).await?;
    c.failure(
        approver,
        &path,
        br#"{"decision":"approve"}"#,
        &[("Idempotency-Key", pending.key.as_str())],
        404,
        "organization.not_found",
    )
    .await?;
    if c.page(approver, c.owner.payload.account_id, AccessRequestView::Approvals)
        .await?
        .iter()
        .any(|item| item.id == pending.resource.id)
    {
        return Err("Request HTTPS approval ignored current approver visibility");
    }
    replace_policy(c.https, approver, c.org, hidden, false).await?;
    println!(
        "Request acceptance: waiting one real admission window after eight Owner decision attempts"
    );
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    requester_eligibility(c, requester, approver, pending, cancellable, member_actor).await?;
    Ok(routing)
}

async fn requester_eligibility(
    c: &mut Context<'_>,
    requester: Actor<'_>,
    approver: Actor<'_>,
    pending: &Written,
    cancellable: &Written,
    member_actor: ExpectedActor,
) -> Result<()> {
    let path = format!("{}/{}/decisions", c.base(), pending.resource.id);
    let headers =
        [("If-Match", pending.resource.etag.as_str()), ("Idempotency-Key", pending.key.as_str())];
    c.request = replace_policy(c.https, approver, c.org, c.request.clone(), false).await?;
    check(c, requester, false).await?;
    c.failure(
        approver,
        &path,
        br#"{"decision":"approve"}"#,
        &headers,
        409,
        "organization.conflict",
    )
    .await?;
    c.request = replace_policy(c.https, approver, c.org, c.request.clone(), true).await?;
    c.view = replace_policy(c.https, approver, c.org, c.view.clone(), false).await?;
    let body = AccessRequestCheckRequest { fields: c.fields() }
        .to_json()
        .map_err(|_| "Request HTTPS hidden check input is invalid")?;
    c.failure(requester, &format!("{}/check", c.base()), &body, &[], 404, "organization.not_found")
        .await?;
    c.confirm(requester, pending).await?;
    let before = c.snapshot().await?;
    let cancelled = terminal(c, requester, &cancellable.resource, None).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &cancelled.resource,
        member_actor,
        "organization.access_request_cancelled",
    )?;
    c.confirm(requester, &cancelled).await?;
    c.confirm(requester, cancellable).await?;
    c.failure(
        approver,
        &path,
        br#"{"decision":"approve"}"#,
        &headers,
        409,
        "organization.conflict",
    )
    .await?;
    c.view = replace_policy(c.https, approver, c.org, c.view.clone(), true).await?;
    update_member(
        c.https,
        approver,
        c.org,
        c.membership,
        TeamRole::Member,
        TeamMemberStatus::Suspended,
    )
    .await?;
    c.failure(
        approver,
        &path,
        br#"{"decision":"approve"}"#,
        &headers,
        409,
        "organization.conflict",
    )
    .await?;
    update_member(
        c.https,
        approver,
        c.org,
        c.membership,
        TeamRole::Member,
        TeamMemberStatus::Active,
    )
    .await?;
    if c.get(requester, pending.resource.id).await? != pending.resource {
        return Err("Request HTTPS membership restoration changed original history");
    }
    check(c, requester, true).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn profile(
    c: &mut Context<'_>,
    requester: Actor<'_>,
    approver: Actor<'_>,
    other_requester: Actor<'_>,
    other_approver: Actor<'_>,
    browser: bool,
) -> Result<()> {
    let member_actor = ExpectedActor {
        account: c.member.payload.account_id,
        device: (!browser).then_some(c.member.device.id),
    };
    let owner_actor = ExpectedActor {
        account: c.owner.payload.account_id,
        device: (!browser).then_some(c.owner.device.id),
    };
    check(c, requester, true).await?;
    self_and_host_guard(c, approver, owner_actor).await?;
    let mut requests = Vec::new();
    for _ in 0..3 {
        let before = c.snapshot().await?;
        let pending = c.create(requester, member_actor.account).await?;
        if pending.resource.requester_membership_id != c.membership {
            return Err("Request HTTPS creation selected another Membership");
        }
        effect(
            &before,
            &c.snapshot().await?,
            &pending.resource,
            member_actor,
            "organization.access_request_created",
        )?;
        requests.push(pending);
    }
    let [deniable, cancellable, pending] = requests.as_slice() else {
        return Err("Request HTTPS fixture request set differs");
    };
    for actor in [requester, approver] {
        if c.get(actor, pending.resource.id).await? != pending.resource {
            return Err("Request HTTPS refresh changed pending input");
        }
    }
    let mine = c.page(requester, member_actor.account, AccessRequestView::Mine).await?;
    let inbox = c.page(approver, owner_actor.account, AccessRequestView::Approvals).await?;
    if requests
        .iter()
        .any(|request| !mine.contains(&request.resource) || !inbox.contains(&request.resource))
        || !c.page(requester, member_actor.account, AccessRequestView::Approvals).await?.is_empty()
    {
        return Err("Request HTTPS own/routed pagination differs");
    }
    c.failure(
        other_requester,
        &pending.path,
        &pending.body,
        &pending.headers(),
        409,
        "organization.conflict",
    )
    .await?;
    let mut altered = AccessRequestCreateRequest {
        id: pending.resource.id,
        fields: pending.resource.fields.clone(),
    };
    altered.fields.reason.push(' ');
    c.failure(
        requester,
        &pending.path,
        &altered.to_json().map_err(|_| "Request HTTPS changed-input probe is invalid")?,
        &pending.headers(),
        409,
        "organization.conflict",
    )
    .await?;
    let path = format!("{}/{}/decisions", c.base(), pending.resource.id);
    let key = Uuid::now_v7().to_string();
    for (headers, status, code) in [
        (vec![("Idempotency-Key", key.as_str())], 428, "organization.precondition_required"),
        (
            vec![("Idempotency-Key", key.as_str()), ("If-Match", "W/\"weak\"")],
            400,
            "organization.invalid_request",
        ),
        (
            vec![("Idempotency-Key", key.as_str()), ("If-Match", "\"stale\"")],
            412,
            "organization.precondition_failed",
        ),
    ] {
        c.failure(approver, &path, br#"{"decision":"approve"}"#, &headers, status, code).await?;
    }
    c.failure(
        requester,
        &path,
        br#"{"decision":"approve"}"#,
        &[("Idempotency-Key", key.as_str())],
        404,
        "organization.not_found",
    )
    .await?;
    let before = c.snapshot().await?;
    let denied =
        terminal(c, approver, &deniable.resource, Some(AccessRequestOutcome::Deny)).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &denied.resource,
        owner_actor,
        "organization.access_request_denied",
    )?;
    c.confirm(approver, &denied).await?;
    let routing =
        current_routing(c, requester, approver, pending, cancellable, member_actor).await?;
    let before = c.snapshot().await?;
    let accepted =
        terminal(c, approver, &pending.resource, Some(AccessRequestOutcome::Approve)).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &accepted.resource,
        owner_actor,
        "organization.access_request_approved",
    )?;
    c.confirm(approver, &accepted).await?;
    c.failure(
        other_approver,
        &accepted.path,
        &accepted.body,
        &accepted.headers(),
        409,
        "organization.conflict",
    )
    .await?;
    c.failure(
        approver,
        &accepted.path,
        br#"{"decision":"deny"}"#,
        &accepted.headers(),
        409,
        "organization.conflict",
    )
    .await?;
    c.failure(
        approver,
        &accepted.path,
        &accepted.body,
        &[
            ("Idempotency-Key", accepted.key.as_str()),
            ("If-Match", accepted.resource.etag.as_str()),
        ],
        409,
        "organization.conflict",
    )
    .await?;
    println!(
        "Request acceptance: waiting one real admission window after eight more Owner decision attempts"
    );
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    let current = c
        .snapshot()
        .await?
        .grants
        .into_iter()
        .find(|grant| {
            accepted.resource.grant.as_ref().is_some_and(|history| history.id == grant.id)
        })
        .ok_or("Request HTTPS approved Grant was not available for withdrawal")?;
    withdraw(c.https, approver, c.org, &current).await?;
    c.confirm(approver, &accepted).await?;
    c.confirm(requester, pending).await?;
    if c.get(requester, pending.resource.id).await? != accepted.resource
        || !c.snapshot().await?.grants.is_empty()
    {
        return Err("Request HTTPS historical confirmation restored a withdrawn Grant");
    }
    let routing = replace_policy(c.https, approver, c.org, routing, true).await?;
    c.failure(
        approver,
        &accepted.path,
        &accepted.body,
        &accepted.headers(),
        404,
        "organization.not_found",
    )
    .await?;
    replace_policy(c.https, approver, c.org, routing, false).await?;
    c.confirm(approver, &accepted).await?;
    Ok(())
}

async fn confirm_lost_reply(
    c: &Context<'_>,
    writer: Actor<'_>,
    other_writer: Actor<'_>,
    written: &Written,
) -> Result<()> {
    let key = Uuid::now_v7().to_string();
    let mut headers = written.headers();
    headers[0] = ("Idempotency-Key", key.as_str());
    let (status, code) = if written.if_match.is_some() {
        (412, "organization.precondition_failed")
    } else {
        (409, "organization.conflict")
    };
    c.failure(writer, &written.path, &written.body, &headers, status, code).await?;
    c.failure(
        other_writer,
        &written.path,
        &written.body,
        &written.headers(),
        409,
        "organization.conflict",
    )
    .await?;
    c.confirm(writer, written).await
}

#[allow(clippy::too_many_lines)]
async fn response_loss_profile(
    c: &Context<'_>,
    requester: Actor<'_>,
    approver: Actor<'_>,
    other_requester: Actor<'_>,
    other_approver: Actor<'_>,
    browser: bool,
) -> Result<()> {
    let requester_actor = ExpectedActor {
        account: c.member.payload.account_id,
        device: (!browser).then_some(c.member.device.id),
    };
    let approver_actor = ExpectedActor {
        account: c.owner.payload.account_id,
        device: (!browser).then_some(c.owner.device.id),
    };
    let request = AccessRequestCreateRequest { id: Uuid::now_v7(), fields: c.fields() };
    let body = request.to_json().map_err(|_| "Request HTTPS lost-create input is invalid")?;
    let before = c.snapshot().await?;
    let pending = c.write_losing_response(requester, c.base(), body, None, 201, request.id).await?;
    pending
        .resource
        .validate_for_create(&request, requester_actor.account)
        .map_err(|_| "Request HTTPS lost-create observation changed the original input")?;
    if pending.resource.status != AccessRequestStatus::Pending
        || pending.resource.requester_membership_id != c.membership
    {
        return Err("Request HTTPS lost-create observation selected another state or Membership");
    }
    effect(
        &before,
        &c.snapshot().await?,
        &pending.resource,
        requester_actor,
        "organization.access_request_created",
    )?;
    confirm_lost_reply(c, requester, other_requester, &pending).await?;

    let before = c.snapshot().await?;
    let approved =
        terminal_reply(c, approver, &pending.resource, Some(AccessRequestOutcome::Approve), true)
            .await?;
    effect(
        &before,
        &c.snapshot().await?,
        &approved.resource,
        approver_actor,
        "organization.access_request_approved",
    )?;
    confirm_lost_reply(c, approver, other_approver, &approved).await?;
    c.confirm(requester, &pending).await?;
    if c.get(requester, request.id).await? != approved.resource {
        return Err("Request HTTPS create confirmation rewrote approved current state");
    }
    let grant = c
        .snapshot()
        .await?
        .grants
        .into_iter()
        .find(|grant| {
            approved.resource.grant.as_ref().is_some_and(|history| history.id == grant.id)
        })
        .ok_or("Request HTTPS lost approval did not retain its original Grant")?;
    withdraw(c.https, approver, c.org, &grant).await?;

    let before = c.snapshot().await?;
    let cancellable = c.create(requester, requester_actor.account).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &cancellable.resource,
        requester_actor,
        "organization.access_request_created",
    )?;
    let before = c.snapshot().await?;
    let cancelled = terminal_reply(c, requester, &cancellable.resource, None, true).await?;
    effect(
        &before,
        &c.snapshot().await?,
        &cancelled.resource,
        requester_actor,
        "organization.access_request_cancelled",
    )?;
    confirm_lost_reply(c, requester, other_requester, &cancelled).await?;
    c.confirm(requester, &cancellable).await?;
    if c.get(requester, cancellable.resource.id).await? != cancelled.resource
        || !c.snapshot().await?.grants.is_empty()
    {
        return Err("Request HTTPS lost cancellation changed current state or created a Grant");
    }
    Ok(())
}

pub(super) async fn verify(https: &Https) -> Result<()> {
    verify_flow(https, false).await
}

pub(super) async fn verify_response_loss(https: &Https) -> Result<()> {
    verify_flow(https, true).await
}

#[allow(clippy::too_many_lines)]
async fn verify_flow(https: &Https, response_loss: bool) -> Result<()> {
    println!("Request acceptance: genuine independent Account, Device and browser families");
    let owner = Registration::new(&https.origin)?;
    owner.register(https).await?;
    let member = Registration::new(&https.origin)?;
    member.register(https).await?;
    let owner_token = owner.device.authenticate(https).await?;
    let owner_token = owner.device.refresh(https, owner_token).await?;
    let member_token = member.device.authenticate(https).await?;
    let member_token = member.device.refresh(https, member_token).await?;
    let owner_browser = Browser::login(https, &owner).await?;
    let mut member_browser = Browser::login(https, &member).await?;
    let other_family = Browser::login(https, &member).await?;
    let owner_actor = native(&owner, &owner_token);
    let member_actor = native(&member, &member_token);
    let owner_personal = super::super::host(owner.device.id)?;
    let member_personal = super::super::host(member.device.id)?;
    for (account, token, object) in
        [(&owner, &owner_token, &owner_personal), (&member, &member_token, &member_personal)]
    {
        super::super::upload(
            https,
            &account.device,
            token,
            account.payload.personal_vault_id,
            &account.vault_key,
            object,
            None,
        )
        .await?;
    }
    let org = create_team(https, owner_actor).await?.id;
    let foreign = create_team(https, member_actor).await?;
    let foreign_host = asset(
        https,
        member_browser.actor(),
        foreign.id,
        InventoryType::Host,
        json!({"name":"Independent request team","address":"foreign.example.test"}),
    )
    .await?;
    let membership = invite(https, owner_actor, member_browser.actor(), &member, org).await?;
    let host = asset(
        https,
        owner_browser.actor(),
        org,
        InventoryType::Host,
        json!({"name":"Exact request target","address":"request.example.test"}),
    )
    .await?;
    let view = rule(
        https,
        owner_actor,
        org,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id }],
        },
    )
    .await?;
    let request = rule(
        https,
        owner_actor,
        org,
        membership,
        SimpleRule::RequestAccess { hosts: vec![host.id] },
    )
    .await?;
    let mut c = Context {
        https,
        owner: &owner,
        owner_token: &owner_token,
        member: &member,
        org,
        membership,
        host,
        view,
        request,
    };
    if response_loss {
        println!("Request acceptance: losing native create, approval and cancellation responses");
        response_loss_profile(
            &c,
            member_actor,
            owner_actor,
            member_browser.actor(),
            owner_browser.actor(),
            false,
        )
        .await?;
        println!(
            "Request acceptance: waiting one real admission window before browser response loss"
        );
        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        println!("Request acceptance: losing browser create, approval and cancellation responses");
        response_loss_profile(
            &c,
            member_browser.actor(),
            owner_browser.actor(),
            other_family.actor(),
            owner_actor,
            true,
        )
        .await?;
    } else {
        let before = c.snapshot().await?;
        let original = c.create(member_browser.actor(), member.payload.account_id).await?;
        effect(
            &before,
            &c.snapshot().await?,
            &original.resource,
            ExpectedActor { account: member.payload.account_id, device: None },
            "organization.access_request_created",
        )?;
        member_browser.refresh(https).await?;
        c.confirm(member_browser.actor(), &original).await?;
        c.failure(
            other_family.actor(),
            &original.path,
            &original.body,
            &original.headers(),
            409,
            "organization.conflict",
        )
        .await?;
        terminal(&c, member_browser.actor(), &original.resource, None).await?;
        println!(
            "Request acceptance: native deny/cancel, current routing and exact original confirmation"
        );
        profile(
            &mut c,
            member_actor,
            owner_actor,
            member_browser.actor(),
            owner_browser.actor(),
            false,
        )
        .await?;
        println!(
            "Request acceptance: waiting one real admission window before the browser profile"
        );
        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        println!(
            "Request acceptance: browser deny/cancel, current routing and exact original confirmation"
        );
        profile(
            &mut c,
            member_browser.actor(),
            owner_browser.actor(),
            other_family.actor(),
            owner_actor,
            true,
        )
        .await?;
        let absent = Uuid::now_v7();
        let original_id = original.resource.id;
        for actor in [member_actor, member_browser.actor()] {
            let missing = problem(
                &exchange(https, actor, "GET", &format!("{}/{absent}", c.base()), &[], &[], 404)
                    .await?,
                404,
                "organization.not_found",
            )?;
            let cross = problem(
                &exchange(
                    https,
                    actor,
                    "GET",
                    &format!("/api/v1/orgs/{}/access-requests/{original_id}", foreign.id),
                    &[],
                    &[],
                    404,
                )
                .await?,
                404,
                "organization.not_found",
            )?;
            if missing != cross {
                return Err("Request HTTPS foreign and absent request problems differ");
            }
            for host in [foreign_host.id, absent] {
                let body = AccessRequestCheckRequest {
                    fields: AccessRequestFields { host, ..c.fields() },
                }
                .to_json()
                .map_err(|_| "Request HTTPS foreign check is invalid")?;
                c.failure(
                    actor,
                    &format!("{}/check", c.base()),
                    &body,
                    &[],
                    404,
                    "organization.not_found",
                )
                .await?;
            }
        }
        for actor in [owner_actor, owner_browser.actor()] {
            problem(
                &exchange(
                    https,
                    actor,
                    "GET",
                    &format!("/api/v1/orgs/{}/access-requests?view=mine", foreign.id),
                    &[],
                    &[],
                    404,
                )
                .await?,
                404,
                "organization.not_found",
            )?;
        }
    }
    let current_foreign = super::inventory(
        &exchange(
            https,
            member_actor,
            "GET",
            &format!("/api/v1/orgs/{}/hosts/{}", foreign.id, foreign_host.id),
            &[],
            &[],
            200,
        )
        .await?,
        InventoryType::Host,
        foreign_host.id,
    )?;
    if current_foreign != foreign_host {
        return Err("Request HTTPS checks changed another team's Host");
    }
    for (account, token, object) in
        [(&owner, &owner_token, &owner_personal), (&member, &member_token, &member_personal)]
    {
        super::super::download(
            https,
            &account.device,
            token,
            (account.payload.personal_vault_id, &account.vault_key),
            &account.device,
            object,
            1,
        )
        .await?;
    }
    println!(
        "Request acceptance: Personal and independent team data remain usable; 24-hour pending deadline was not accelerated"
    );
    Ok(())
}

fn effect(
    before: &Snapshot,
    after: &Snapshot,
    current: &AccessRequestResource,
    actor: ExpectedActor,
    action: &str,
) -> Result<()> {
    let approved = current.status == AccessRequestStatus::Approved;
    let count = if approved { 2 } else { 1 };
    if after.revision != before.revision + u64::from(approved)
        || after.events.len() != before.events.len() + count
        || after.events[count..] != before.events
    {
        return Err("Request HTTPS transition changed the wrong revision or audit count");
    }
    let request_event = after.events[..count]
        .iter()
        .find(|event| event.event_class.as_deref() == Some(action))
        .ok_or("Request HTTPS attributable request audit is missing")?;
    if !actor.matches(request_event)
        || request_event.resource
            != Some(AuditResource { kind: AuditResourceKind::AccessRequest, id: current.id })
    {
        return Err("Request HTTPS request audit attribution differs");
    }
    let mut expected_grants = before.grants.clone();
    if approved {
        let history =
            current.grant.as_ref().ok_or("Request HTTPS approval has no Grant interval")?;
        let persisted = after
            .grants
            .iter()
            .find(|grant| grant.id == history.id)
            .ok_or("Request HTTPS approval Grant is missing")?;
        if persisted.fields.membership != current.requester_membership_id
            || persisted.fields.host != current.fields.host
            || persisted.fields.remote_user != current.fields.remote_user
            || persisted.fields.valid_from != history.valid_from
            || persisted.fields.valid_until != Some(history.valid_until)
        {
            return Err("Request HTTPS approval Grant differs from original input or interval");
        }
        let event = after.events[..count]
            .iter()
            .find(|event| event.event_class.as_deref() == Some("organization.grants_created"))
            .ok_or("Request HTTPS approval Grant audit is missing")?;
        if !actor.matches(event)
            || event.resource
                != Some(AuditResource { kind: AuditResourceKind::Grant, id: history.id })
        {
            return Err("Request HTTPS Grant audit attribution differs");
        }
        expected_grants.push(persisted.clone());
        expected_grants.sort_by_key(|grant| grant.id);
    }
    if after.grants != expected_grants {
        return Err("Request HTTPS transition changed the wrong Grants");
    }
    Ok(())
}
