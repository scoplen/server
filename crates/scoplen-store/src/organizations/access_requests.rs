// SPDX-License-Identifier: AGPL-3.0-only
//! Current-authority access requests, immutable confirmation and atomic finite Grants.

use super::{
    OrganizationPrincipal, OrganizationStoreError as Error, PostgresStore, SqliteStore, Uuid,
    actor_audit, append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    inventory::{Graph, row_uuid},
    now_ms, postgres_actor, sqlite_actor, timestamp,
};
use scoplen_api::{
    access_request::{
        AccessRequestCheckResponse, AccessRequestCreateRequest, AccessRequestDecision,
        AccessRequestDecisionRequest, AccessRequestFields, AccessRequestGrant,
        AccessRequestListQuery, AccessRequestOutcome, AccessRequestPage, AccessRequestResource,
        AccessRequestStatus, AccessRequestView,
    },
    audit::parse_audit_timestamp,
    grant::{GrantFields, GrantResource},
    inventory::InventoryType,
    organization::{OrganizationPreconditionError, parse_organization_if_match},
};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use std::fmt::Write as _;

const PENDING_MS: i64 = 86_400_000;

/// Immutable tenant and request identity selected by the authenticated route.
#[derive(Clone, Copy)]
pub struct AccessRequestTarget {
    pub organization: Uuid,
    pub id: Uuid,
}

/// Complete original operation, including its protected historical precondition.
pub enum AccessRequestWrite<'a> {
    Create { key: Uuid, request: &'a AccessRequestCreateRequest },
    Decide { key: Uuid, if_match: Option<&'a str>, request: AccessRequestDecisionRequest },
    Cancel { key: Uuid, if_match: Option<&'a str> },
}

/// Only a confirmed new approval changes the Organization view.
pub struct AccessRequestWriteResult {
    pub response_json: Vec<u8>,
    pub changed: bool,
    pub view_changed: bool,
}

struct StoredRequest {
    resource: AccessRequestResource,
    expires_at_ms: i64,
    updated_at_ms: i64,
}

fn write_error(error: &sqlx::Error) -> Error {
    if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
        Error::Conflict
    } else {
        Error::StorageUnavailable
    }
}

fn retag(resource: &mut AccessRequestResource) -> Result<Vec<u8>, Error> {
    resource.etag = "\"pending\"".into();
    let digest = Sha256::digest(resource.to_json().map_err(|_| Error::StorageUnavailable)?);
    let mut etag = String::from("\"sha256-");
    for byte in digest {
        write!(etag, "{byte:02x}").expect("String write");
    }
    etag.push('"');
    resource.etag = etag;
    resource.to_json().map_err(|_| Error::StorageUnavailable)
}

fn digest(
    expected: &impl OrganizationPrincipal,
    origin: &str,
    path: &str,
    if_match: Option<&str>,
    canonical: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-access-request-v1".as_slice(),
        origin.as_bytes(),
        expected.account_id().as_slice(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    if let Some(kind) = expected.receipt_writer_kind() {
        hash.update(kind);
        hash.update([0]);
    }
    for part in [
        expected.writer_id().as_slice(),
        b"POST",
        path.as_bytes(),
        if_match.unwrap_or_default().as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    hash.finalize().into()
}

macro_rules! access_requests {
    ($store:ty, $db:ty, $begin:literal, $actor:ident, $audit:ident, $postgres:literal) => {
        impl $store {
            pub(super) async fn ensure_access_request_host_deletion_allowed(
                tx: &mut Transaction<'_, $db>, organization: Uuid, host: Uuid,
            ) -> Result<(), Error> {
                let pending: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT id FROM organization_access_requests WHERE organization_id=$1 AND host_id=$2 AND status='pending' LIMIT 1",
                ).bind(organization.as_bytes().as_slice()).bind(host.as_bytes().as_slice())
                    .fetch_optional(&mut **tx).await?;
                if pending.is_some() {return Err(Error::Conflict);}
                Ok(())
            }

            async fn access_request_row(
                tx: &mut Transaction<'_, $db>, target: AccessRequestTarget,
            ) -> Result<StoredRequest, Error> {
                let row = sqlx::query("SELECT * FROM organization_access_requests WHERE organization_id=$1 AND id=$2")
                    .bind(target.organization.as_bytes().as_slice()).bind(target.id.as_bytes().as_slice())
                    .fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let resource = AccessRequestResource::from_json(&row.try_get::<Vec<u8>,_>("response_json")?)
                    .map_err(|_| Error::StorageUnavailable)?;
                let created_at_ms: i64 = row.try_get("created_at_ms")?;
                let updated_at_ms: i64 = row.try_get("updated_at_ms")?;
                let expires_at_ms: i64 = row.try_get("expires_at_ms")?;
                if resource.id != target.id || row_uuid(&row,"organization_id")? != target.organization
                    || resource.requester_account_id != row_uuid(&row,"requester_account_id")?
                    || resource.requester_membership_id != row_uuid(&row,"requester_membership_id")?
                    || resource.fields.host != row_uuid(&row,"host_id")?
                    || resource.status.as_str() != row.try_get::<String,_>("status")?
                    || parse_audit_timestamp(&resource.created_at).ok() != Some(created_at_ms)
                    || parse_audit_timestamp(&resource.updated_at).ok() != Some(updated_at_ms)
                    || parse_audit_timestamp(&resource.expires_at).ok() != Some(expires_at_ms)
                {return Err(Error::StorageUnavailable);}
                Ok(StoredRequest {resource,expires_at_ms,updated_at_ms})
            }

            async fn access_request_eligible(
                tx: &mut Transaction<'_, $db>, graph: &mut Graph, organization: Uuid, fields: &AccessRequestFields,
            ) -> Result<bool, Error> {
                let (host,_) = Self::inventory_object(tx,organization,fields.host).await?;
                if host.object_type != InventoryType::Host.object_type()
                    || !Self::inventory_readable(tx,graph,&host).await?
                {return Err(Error::NotFound);}
                graph.authorize_request_access(fields)
            }

            async fn access_request_routed(
                tx: &mut Transaction<'_, $db>, graph: &mut Graph, organization: Uuid,
                account: Uuid, resource: &AccessRequestResource,
            ) -> Result<bool, Error> {
                if account == resource.requester_account_id {return Ok(false);}
                let host = match Self::inventory_object(tx,organization,resource.fields.host).await {
                    Ok((host,_)) => host,
                    Err(Error::NotFound) => return Ok(false),
                    Err(error) => return Err(error),
                };
                if host.object_type != InventoryType::Host.object_type()
                    || !Self::inventory_readable(tx,graph,&host).await?
                {return Ok(false);}
                let requester = sqlx::query("SELECT email FROM identity_accounts WHERE account_id=$1")
                    .bind(resource.requester_account_id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
                let email = requester.as_ref().map(|row|row.try_get::<Option<String>,_>("email")).transpose()?.flatten();
                graph.authorize_access_request(resource,requester.is_some(),email)
            }

            /// Evaluate exact input without creating a request, receipt, Grant or audit event.
            /// # Errors
            /// Current authentication, visibility and storage/evaluation failures remain errors.
            pub async fn check_organization_access_request(
                &self, expected: &impl OrganizationPrincipal, expires_at: u64,
                organization: Uuid, fields: &AccessRequestFields,
            ) -> Result<AccessRequestCheckResponse, Error> {
                fields.to_json().map_err(|_| Error::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let (current,_,_,_) = Self::inventory_owner(&mut tx,expected,expires_at,organization,false).await?;
                let mut graph = Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                let allowed = Self::access_request_eligible(&mut tx,&mut graph,organization,fields).await?;
                $actor(&mut tx,expected,expires_at).await?;
                tx.commit().await?;
                Ok(AccessRequestCheckResponse {allowed})
            }

            /// Read own opaque history or a request satisfying current independent routing.
            /// # Errors
            /// Foreign, missing and inaccessible ids share the static not-found boundary.
            pub async fn read_organization_access_request(
                &self, expected: &impl OrganizationPrincipal, expires_at: u64, target: AccessRequestTarget,
            ) -> Result<AccessRequestResource, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let (current,_,_,_) = Self::inventory_owner(&mut tx,expected,expires_at,target.organization,false).await?;
                let row = Self::access_request_row(&mut tx,target).await?;
                let account = Uuid::from_bytes(expected.account_id());
                if row.resource.requester_account_id != account {
                    let mut graph = Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                    if !Self::access_request_routed(&mut tx,&mut graph,target.organization,account,&row.resource).await?
                    {return Err(Error::NotFound);}
                }
                $actor(&mut tx,expected,expires_at).await?;
                tx.commit().await?;
                Ok(row.resource)
            }

            /// List only currently readable ascending requests; cursors are locators.
            /// # Errors
            /// Returns fixed authentication, membership, query or storage errors.
            pub async fn list_organization_access_requests(
                &self, expected: &impl OrganizationPrincipal, expires_at: u64,
                organization: Uuid, query: &AccessRequestListQuery,
            ) -> Result<AccessRequestPage, Error> {
                query.page.validate().map_err(|_| Error::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let (current,_,_,_) = Self::inventory_owner(&mut tx,expected,expires_at,organization,false).await?;
                let now = now_ms()?;
                let mut graph = if query.view == AccessRequestView::Approvals {
                    Some(Self::inventory_graph(&mut tx,current,now).await?)
                } else {None};
                let account = Uuid::from_bytes(expected.account_id());
                let mut after = query.page.cursor.map(|id|id.as_bytes().to_vec()).unwrap_or_default();
                let mut page = AccessRequestPage {items:Vec::new(),next_cursor:None};
                'scan: loop {
                    let rows = if query.view == AccessRequestView::Mine {
                        sqlx::query("SELECT id FROM organization_access_requests WHERE organization_id=$1 AND id>$2 AND requester_account_id=$3 ORDER BY id LIMIT 100")
                            .bind(organization.as_bytes().as_slice()).bind(&after).bind(account.as_bytes().as_slice()).fetch_all(&mut *tx).await?
                    } else {
                        sqlx::query("SELECT id FROM organization_access_requests WHERE organization_id=$1 AND id>$2 AND status='pending' AND expires_at_ms>$3 ORDER BY id LIMIT 100")
                            .bind(organization.as_bytes().as_slice()).bind(&after).bind(now).fetch_all(&mut *tx).await?
                    };
                    if rows.is_empty() {break;}
                    for row in rows {
                        let id = row_uuid(&row,"id")?;
                        after = id.as_bytes().to_vec();
                        let row = Self::access_request_row(&mut tx,AccessRequestTarget {organization,id}).await?;
                        if let Some(graph) = &mut graph {
                            if !Self::access_request_routed(&mut tx,graph,organization,account,&row.resource).await? {continue;}
                        }
                        if page.items.len() == usize::from(query.page.limit) {
                            page.next_cursor = page.items.last().map(|item|item.id);
                            break 'scan;
                        }
                        page.items.push(row.resource);
                        if page.to_json().is_err() {
                            page.items.pop();
                            if page.items.is_empty() {return Err(Error::StorageUnavailable);}
                            page.next_cursor = page.items.last().map(|item|item.id);
                            break 'scan;
                        }
                    }
                }
                page.validate_for_query(account,*query).map_err(|_| Error::StorageUnavailable)?;
                page.to_json().map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx,expected,expires_at).await?;
                tx.commit().await?;
                Ok(page)
            }

            async fn access_request_receipt(
                tx: &mut Transaction<'_, $db>, expected: &impl OrganizationPrincipal,
                organization: Uuid, key: Uuid, digest: &[u8;32], now: i64,
            ) -> Result<Option<Vec<u8>>, Error> {
                let row = sqlx::query("SELECT organization_id,request_digest,response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3")
                    .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice()).bind(now).fetch_optional(&mut **tx).await?;
                row.map(|row| {
                    if row_uuid(&row,"organization_id")? != organization
                        || row.try_get::<Vec<u8>,_>("request_digest")?.as_slice() != digest.as_slice()
                    {return Err(Error::Conflict);}
                    Ok(row.try_get("response_json")?)
                }).transpose()
            }

            async fn save_access_request_receipt(
                tx: &mut Transaction<'_, $db>, expected: &impl OrganizationPrincipal,
                organization: Uuid, key: Uuid, digest: &[u8;32], response: &[u8], now: i64,
            ) -> Result<(), Error> {
                sqlx::query("DELETE FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3")
                    .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice()).bind(now).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO organization_inventory_receipts (account_id,idempotency_key,organization_id,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                    .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice()).bind(organization.as_bytes().as_slice())
                    .bind(digest.as_slice()).bind(response).bind(now).bind(now.checked_add(PENDING_MS).ok_or(Error::StorageUnavailable)?)
                    .execute(&mut **tx).await.map_err(|error|write_error(&error))?;
                Ok(())
            }

            /// Create, decide or cancel under current authority and one tenant transaction.
            /// # Errors
            /// Unconfirmed COMMIT requires only explicit original-operation confirmation.
            #[allow(clippy::too_many_lines)]
            pub async fn write_organization_access_request(
                &self, expected: &impl OrganizationPrincipal, expires_at: u64, origin: &str,
                target: AccessRequestTarget, write: AccessRequestWrite<'_>,
            ) -> Result<AccessRequestWriteResult, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let (current,_,_,_) = Self::inventory_owner(&mut tx,expected,expires_at,target.organization,true).await?;
                let now = now_ms()?;
                let account = Uuid::from_bytes(expected.account_id());
                let base = format!("/api/v1/orgs/{}/access-requests",target.organization);
                let (key,request_digest,response,view_changed) = match write {
                    AccessRequestWrite::Create {key,request} => {
                        if request.id != target.id {return Err(Error::InvalidRequest);}
                        scoplen_model::validate_uuid_v7(key).map_err(|_| Error::InvalidRequest)?;
                        let canonical = request.to_json().map_err(|_| Error::InvalidRequest)?;
                        let request_digest = digest(expected,origin,&base,None,&canonical);
                        if let Some(bytes) = Self::access_request_receipt(&mut tx,expected,target.organization,key,&request_digest,now).await? {
                            let retained = AccessRequestResource::from_json(&bytes).map_err(|_| Error::StorageUnavailable)?;
                            retained.validate_for_create(request,account).map_err(|_| Error::StorageUnavailable)?;
                            let current = Self::access_request_row(&mut tx,target).await?;
                            if current.resource.requester_account_id != account {return Err(Error::NotFound);}
                            if retained.status != AccessRequestStatus::Pending || !same_request(&retained,&current.resource) {return Err(Error::StorageUnavailable);}
                            $actor(&mut tx,expected,expires_at).await?;
                            tx.commit().await?;
                            return Ok(AccessRequestWriteResult {response_json:bytes,changed:false,view_changed:false});
                        }
                        let used: Option<Vec<u8>> = sqlx::query_scalar("SELECT id FROM organization_access_requests WHERE id=$1")
                            .bind(target.id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                        if used.is_some() {return Err(Error::Conflict);}
                        let membership = current.membership.id;
                        let mut graph = Self::inventory_graph(&mut tx,current,now).await?;
                        if !Self::access_request_eligible(&mut tx,&mut graph,target.organization,&request.fields).await? {return Err(Error::PermissionDenied);}
                        let deadline = now.checked_add(PENDING_MS).ok_or(Error::StorageUnavailable)?;
                        let mut resource = AccessRequestResource {id:request.id,etag:"\"pending\"".into(),
                            created_at:timestamp(now)?,updated_at:timestamp(now)?,requester_account_id:account,
                            requester_membership_id:membership,fields:request.fields.clone(),expires_at:timestamp(deadline)?,
                            status:AccessRequestStatus::Pending,decision:None,grant:None};
                        let response = retag(&mut resource)?;
                        sqlx::query("INSERT INTO organization_access_requests (organization_id,id,requester_account_id,requester_membership_id,host_id,status,response_json,created_at_ms,updated_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$7,$8)")
                            .bind(target.organization.as_bytes().as_slice()).bind(target.id.as_bytes().as_slice())
                            .bind(account.as_bytes().as_slice()).bind(membership.as_bytes().as_slice()).bind(request.fields.host.as_bytes().as_slice())
                            .bind(&response).bind(now).bind(deadline).execute(&mut *tx).await.map_err(|error|write_error(&error))?;
                        Self::access_request_audit(&mut tx,expected,target,"organization.access_request_created",now).await?;
                        (key,request_digest,response,false)
                    }
                    transition => {
                        let row = Self::access_request_row(&mut tx,target).await?;
                        let (key,if_match,decision) = match transition {
                            AccessRequestWrite::Decide {key,if_match,request} => (key,if_match,Some(request)),
                            AccessRequestWrite::Cancel {key,if_match} => (key,if_match,None),
                            AccessRequestWrite::Create {..} => unreachable!(),
                        };
                        if decision.is_some() {
                            let mut graph = Self::inventory_graph(&mut tx,current,now).await?;
                            if !Self::access_request_routed(&mut tx,&mut graph,target.organization,account,&row.resource).await? {return Err(Error::NotFound);}
                        } else if row.resource.requester_account_id != account {return Err(Error::NotFound);}
                        scoplen_model::validate_uuid_v7(key).map_err(|_| Error::InvalidRequest)?;
                        let if_match = parse_organization_if_match(if_match).map_err(|error|match error {
                            OrganizationPreconditionError::Required => Error::PreconditionRequired,
                            OrganizationPreconditionError::Invalid => Error::InvalidRequest,
                        })?;
                        let path = format!("{base}/{}/{}",target.id,if decision.is_some() {"decisions"} else {"cancel"});
                        let canonical = decision.map(AccessRequestDecisionRequest::to_json).transpose().map_err(|_| Error::InvalidRequest)?.unwrap_or_default();
                        let request_digest = digest(expected,origin,&path,Some(if_match),&canonical);
                        if let Some(bytes) = Self::access_request_receipt(&mut tx,expected,target.organization,key,&request_digest,now).await? {
                            let retained = AccessRequestResource::from_json(&bytes).map_err(|_| Error::StorageUnavailable)?;
                            if let Some(decision) = decision {
                                retained.validate_for_decision(&row.resource,decision,account).map_err(|_| Error::StorageUnavailable)?;
                            } else {retained.validate_for_cancel(&row.resource,account).map_err(|_| Error::StorageUnavailable)?;}
                            $actor(&mut tx,expected,expires_at).await?;
                            tx.commit().await?;
                            return Ok(AccessRequestWriteResult {response_json:bytes,changed:false,view_changed:false});
                        }
                        if row.resource.etag != if_match {return Err(Error::PreconditionFailed);}
                        if row.resource.status != AccessRequestStatus::Pending || now >= row.expires_at_ms {return Err(Error::Conflict);}
                        if decision.is_some() {
                            let requester = Self::read_organization_in_transaction(&mut tx,row.resource.requester_account_id.as_bytes(),target.organization.as_bytes()).await
                                .map_err(|error|if error == Error::NotFound {Error::Conflict} else {error})?;
                            if requester.membership.id != row.resource.requester_membership_id {return Err(Error::Conflict);}
                            let suffix = if $postgres {" FOR SHARE"} else {""};
                            let active: Option<Vec<u8>> = sqlx::query_scalar(&format!("SELECT account_id FROM identity_accounts WHERE account_id=$1{suffix}"))
                                .bind(row.resource.requester_account_id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                            if active.is_none() {return Err(Error::Conflict);}
                            let mut requester_graph = Self::inventory_graph(&mut tx,requester,now).await?;
                            match Self::access_request_eligible(&mut tx,&mut requester_graph,target.organization,&row.resource.fields).await {
                                Ok(true) => {},
                                Ok(false) | Err(Error::NotFound) => return Err(Error::Conflict),
                                Err(error) => return Err(error),
                            }
                        }
                        let mut resource = row.resource;
                        let updated = now.max(row.updated_at_ms.checked_add(1).ok_or(Error::StorageUnavailable)?);
                        resource.updated_at = timestamp(updated)?;
                        let mut view_changed = false;
                        let action = if let Some(decision) = decision {
                            resource.decision = Some(AccessRequestDecision {outcome:decision.decision,actor_account_id:account,decided_at:timestamp(now)?});
                            if decision.decision == AccessRequestOutcome::Approve {
                                let start = u64::try_from(now.div_euclid(1000)).map_err(|_| Error::StorageUnavailable)?;
                                let end = start.checked_add(u64::from(resource.fields.duration_seconds)).ok_or(Error::StorageUnavailable)?;
                                let fields = GrantFields {membership:resource.requester_membership_id,host:resource.fields.host,
                                    remote_user:resource.fields.remote_user.clone(),valid_from:start,valid_until:Some(end)};
                                fields.validate().map_err(|_| Error::StorageUnavailable)?;
                                let id = Uuid::now_v7();
                                let mut grant = GrantResource {id,etag:"\"pending\"".into(),created_at:timestamp(now)?,updated_at:timestamp(now)?,fields};
                                Self::persist_organization_grant(&mut tx,target.organization,&mut grant,now,now,false).await?;
                                resource.grant = Some(AccessRequestGrant {id,valid_from:start,valid_until:end});
                                resource.status = AccessRequestStatus::Approved;
                                Self::team_revision(&mut tx,target.organization,now).await?;
                                let event = actor_audit(expected,serde_json::json!({"action":"organization.grants_created","account_id":account,
                                    "organization_id":target.organization,"object_id":id}))?;
                                $audit(&mut tx,target.organization.into_bytes(),&event,now).await.map_err(|_| Error::StorageUnavailable)?;
                                view_changed = true;
                                "organization.access_request_approved"
                            } else {resource.status = AccessRequestStatus::Denied; "organization.access_request_denied"}
                        } else {resource.status = AccessRequestStatus::Cancelled; "organization.access_request_cancelled"};
                        let response = retag(&mut resource)?;
                        Self::update_access_request(&mut tx,target,&resource,&response,updated).await?;
                        Self::access_request_audit(&mut tx,expected,target,action,now).await?;
                        (key,request_digest,response,view_changed)
                    }
                };
                Self::save_access_request_receipt(&mut tx,expected,target.organization,key,&request_digest,&response,now).await?;
                $actor(&mut tx,expected,expires_at).await?;
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(AccessRequestWriteResult {response_json:response,changed:true,view_changed})
            }

            async fn update_access_request(
                tx: &mut Transaction<'_, $db>, target: AccessRequestTarget,
                resource: &AccessRequestResource, response: &[u8], updated: i64,
            ) -> Result<(), Error> {
                let changed = sqlx::query("UPDATE organization_access_requests SET status=$1,response_json=$2,updated_at_ms=$3 WHERE organization_id=$4 AND id=$5 AND status='pending'")
                    .bind(resource.status.as_str()).bind(response).bind(updated).bind(target.organization.as_bytes().as_slice())
                    .bind(target.id.as_bytes().as_slice()).execute(&mut **tx).await?.rows_affected();
                if changed != 1 {return Err(Error::Conflict);}
                Ok(())
            }

            async fn access_request_audit(
                tx: &mut Transaction<'_, $db>, expected: &impl OrganizationPrincipal,
                target: AccessRequestTarget, action: &str, now: i64,
            ) -> Result<(), Error> {
                let event = actor_audit(expected,serde_json::json!({"action":action,"account_id":Uuid::from_bytes(expected.account_id()),
                    "organization_id":target.organization,"request_id":target.id}))?;
                $audit(tx,target.organization.into_bytes(),&event,now).await.map(|_|()).map_err(|_| Error::StorageUnavailable)
            }

            /// Expire at most 100 indexed candidates, each with one atomic system audit.
            /// # Errors
            /// A failed or unconfirmed transaction reports no confirmed batch count.
            pub async fn expire_organization_access_requests(&self) -> Result<u64, Error> {
                let candidates = sqlx::query("SELECT organization_id,id FROM organization_access_requests WHERE status='pending' AND expires_at_ms<=$1 ORDER BY expires_at_ms,organization_id,id LIMIT 100")
                    .bind(now_ms()?).fetch_all(&self.pool).await?;
                let mut expired = 0;
                for candidate in candidates {
                    let target = AccessRequestTarget {organization:row_uuid(&candidate,"organization_id")?,id:row_uuid(&candidate,"id")?};
                    let mut tx = self.pool.begin_with($begin).await?;
                    let suffix = if $postgres {" FOR UPDATE"} else {""};
                    let owner: Option<Vec<u8>> = sqlx::query_scalar(&format!("SELECT id FROM organizations WHERE id=$1{suffix}"))
                        .bind(target.organization.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                    if owner.is_none() {tx.rollback().await?; continue;}
                    let row = match Self::access_request_row(&mut tx,target).await {
                        Ok(row) => row,
                        Err(Error::NotFound) => {tx.rollback().await?; continue;},
                        Err(error) => return Err(error),
                    };
                    let now = now_ms()?;
                    if row.resource.status != AccessRequestStatus::Pending || now < row.expires_at_ms {tx.rollback().await?; continue;}
                    let updated = now.max(row.updated_at_ms.checked_add(1).ok_or(Error::StorageUnavailable)?);
                    let mut resource = row.resource;
                    resource.status = AccessRequestStatus::Expired;
                    resource.updated_at = timestamp(updated)?;
                    let bytes = retag(&mut resource)?;
                    Self::update_access_request(&mut tx,target,&resource,&bytes,updated).await?;
                    let event = serde_json::to_vec(&serde_json::json!({"action":"organization.access_request_expired",
                        "organization_id":target.organization,"request_id":target.id})).map_err(|_| Error::StorageUnavailable)?;
                    $audit(&mut tx,target.organization.into_bytes(),&event,now).await.map_err(|_| Error::StorageUnavailable)?;
                    tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                    expired += 1;
                }
                Ok(expired)
            }
        }
    };
}

fn same_request(left: &AccessRequestResource, right: &AccessRequestResource) -> bool {
    left.id == right.id
        && left.requester_account_id == right.requester_account_id
        && left.requester_membership_id == right.requester_membership_id
        && left.fields == right.fields
        && left.created_at == right.created_at
        && left.expires_at == right.expires_at
}

access_requests!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    sqlite_actor,
    append_audit_event_in_transaction,
    false
);
access_requests!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_actor,
    append_audit_event_in_postgres_transaction,
    true
);
