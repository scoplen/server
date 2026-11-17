// SPDX-License-Identifier: AGPL-3.0-only
//! Durable named-Membership Host Grants and irreversible private withdrawal.

use super::{
    OrganizationPrincipal, OrganizationStoreError as Error, PostgresStore, SqliteStore, Uuid,
    actor_audit, append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    now_ms, postgres_actor, sqlite_actor, timestamp,
};
use scoplen_api::{
    control_plane::OrganizationHostGrant,
    grant::{GrantCreateRequest, GrantFields, GrantPage, GrantReplaceRequest, GrantResource},
    inventory::InventoryType,
    organization::{
        OrganizationListQuery, OrganizationPreconditionError, parse_organization_if_match,
    },
};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use std::fmt::Write as _;

/// One Grant in its immutable Organization namespace.
#[derive(Clone, Copy, Debug)]
pub struct GrantTarget {
    pub organization: Uuid,
    pub id: Uuid,
}

/// Complete desired mutation; protected preconditions are checked after current authority.
pub enum GrantWrite<'a> {
    Create { key: Uuid, fields: &'a GrantFields },
    Replace { if_match: Option<&'a str>, fields: &'a GrantFields },
    Delete { if_match: Option<&'a str> },
}

/// Exact retained response bytes, with notification required only for a committed change.
pub struct GrantWriteResult {
    /// Original create bytes on confirmation; absent only for DELETE.
    pub response_json: Option<Vec<u8>>,
    pub changed: bool,
}

struct StoredGrant {
    resource: GrantResource,
    response_json: Vec<u8>,
    updated_at_ms: i64,
}

fn precondition(value: Option<&str>) -> Result<&str, Error> {
    parse_organization_if_match(value).map_err(|error| match error {
        OrganizationPreconditionError::Required => Error::PreconditionRequired,
        OrganizationPreconditionError::Invalid => Error::InvalidRequest,
    })
}

fn write_error(error: &sqlx::Error) -> Error {
    if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
        Error::Conflict
    } else {
        Error::StorageUnavailable
    }
}

fn retag(resource: &mut GrantResource) -> Result<Vec<u8>, Error> {
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

fn create_digest(
    expected: &impl OrganizationPrincipal,
    origin: &str,
    target: GrantTarget,
    canonical: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-grant-create-v1".as_slice(),
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
        format!("/api/v1/orgs/{}/grants", target.organization).as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    hash.finalize().into()
}

macro_rules! grants {
    ($store:ty, $db:ty, $begin:literal, $principal:ident, $audit:ident) => {
        impl $store {
            /// The caller owns current authority, references, revision, audit and commit.
            pub(super) async fn persist_organization_grant(
                tx: &mut Transaction<'_, $db>, organization: Uuid,
                resource: &mut GrantResource, created_at_ms: i64, updated_at_ms: i64, replace: bool,
            ) -> Result<Vec<u8>, Error> {
                let bytes = retag(resource)?;
                let sql = if replace {
                    "INSERT INTO organization_grants (organization_id,id,membership_id,host_id,response_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (organization_id,id) DO UPDATE SET membership_id=excluded.membership_id,host_id=excluded.host_id,response_json=excluded.response_json,updated_at_ms=excluded.updated_at_ms WHERE organization_grants.withdrawn_at_ms IS NULL"
                } else {
                    "INSERT INTO organization_grants (organization_id,id,membership_id,host_id,response_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)"
                };
                let changed = sqlx::query(sql)
                    .bind(organization.as_bytes().as_slice()).bind(resource.id.as_bytes().as_slice())
                    .bind(resource.fields.membership.as_bytes().as_slice()).bind(resource.fields.host.as_bytes().as_slice())
                    .bind(&bytes).bind(created_at_ms).bind(updated_at_ms)
                    .execute(&mut **tx).await.map_err(|error|write_error(&error))?.rows_affected();
                if changed != 1 {return Err(Error::StorageUnavailable);}
                Ok(bytes)
            }

            /// Lifecycle callers already own the tenant lock, revision, audit and notification.
            pub(super) async fn withdraw_organization_grants(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
                membership: Option<Uuid>,
                now: i64,
            ) -> Result<(), Error> {
                let sql = if membership.is_some() {
                    "UPDATE organization_grants SET withdrawn_at_ms=$1 WHERE organization_id=$2 AND withdrawn_at_ms IS NULL AND membership_id=$3"
                } else {
                    "UPDATE organization_grants SET withdrawn_at_ms=$1 WHERE organization_id=$2 AND withdrawn_at_ms IS NULL"
                };
                let mut query = sqlx::query(sql).bind(now).bind(organization.as_bytes().as_slice());
                if let Some(membership) = membership {
                    query = query.bind(membership.as_bytes().to_vec());
                }
                query.execute(&mut **tx).await?;
                Ok(())
            }

            pub(super) async fn ensure_grant_host_deletion_allowed(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
                host: Uuid,
            ) -> Result<(), Error> {
                let grant: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT id FROM organization_grants WHERE organization_id=$1 AND host_id=$2 AND withdrawn_at_ms IS NULL LIMIT 1",
                )
                .bind(organization.as_bytes().as_slice())
                .bind(host.as_bytes().as_slice())
                .fetch_optional(&mut **tx)
                .await?;
                if grant.is_some() {
                    return Err(Error::Conflict);
                }
                Ok(())
            }

            /// Time validity is evaluated by the shared Cedar helper, never by this loader.
            pub(super) async fn load_organization_host_grants(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
                membership: Uuid,
                host: Uuid,
            ) -> Result<Vec<OrganizationHostGrant>, Error> {
                let active: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT m.id FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.organization_id=$1 AND m.id=$2 AND m.status='active' AND o.dissolved_at_ms IS NULL",
                )
                .bind(organization.as_bytes().as_slice())
                .bind(membership.as_bytes().as_slice())
                .fetch_optional(&mut **tx)
                .await?;
                if active.is_none() {
                    return Ok(Vec::new());
                }
                match Self::inventory_object(tx, organization, host).await {
                    Ok((object, _)) if object.object_type == InventoryType::Host.object_type() => {}
                    Ok(_) | Err(Error::NotFound) => return Ok(Vec::new()),
                    Err(error) => return Err(error),
                }
                let rows = sqlx::query(
                    "SELECT id FROM organization_grants WHERE organization_id=$1 AND membership_id=$2 AND host_id=$3 AND withdrawn_at_ms IS NULL ORDER BY id",
                )
                .bind(organization.as_bytes().as_slice())
                .bind(membership.as_bytes().as_slice())
                .bind(host.as_bytes().as_slice())
                .fetch_all(&mut **tx)
                .await?;
                let mut result = Vec::with_capacity(rows.len());
                for row in rows {
                    let id = super::inventory::row_uuid(&row, "id")?;
                    let stored = Self::grant_resource(tx, GrantTarget { organization, id }).await?;
                    result.push(OrganizationHostGrant {
                        id,
                        organization,
                        fields: stored.resource.fields,
                    });
                }
                Ok(result)
            }

            async fn grant_resource(
                tx: &mut Transaction<'_, $db>,
                target: GrantTarget,
            ) -> Result<StoredGrant, Error> {
                let row = sqlx::query(
                    "SELECT membership_id,host_id,response_json,created_at_ms,updated_at_ms FROM organization_grants WHERE organization_id=$1 AND id=$2 AND withdrawn_at_ms IS NULL",
                )
                .bind(target.organization.as_bytes().as_slice())
                .bind(target.id.as_bytes().as_slice())
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(Error::NotFound)?;
                let response_json: Vec<u8> = row.try_get("response_json")?;
                let resource = GrantResource::from_json(&response_json)
                    .map_err(|_| Error::StorageUnavailable)?;
                let updated_at_ms = row.try_get("updated_at_ms")?;
                if resource.id != target.id
                    || resource.fields.membership != super::inventory::row_uuid(&row, "membership_id")?
                    || resource.fields.host != super::inventory::row_uuid(&row, "host_id")?
                    || resource.created_at != timestamp(row.try_get("created_at_ms")?)?
                    || resource.updated_at != timestamp(updated_at_ms)?
                {
                    return Err(Error::StorageUnavailable);
                }
                Ok(StoredGrant { resource, response_json, updated_at_ms })
            }

            async fn grant_references(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
                fields: &GrantFields,
            ) -> Result<(), Error> {
                fields.validate().map_err(|_| Error::InvalidRequest)?;
                let membership: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT id FROM organization_memberships WHERE organization_id=$1 AND id=$2 AND status='active'",
                )
                .bind(organization.as_bytes().as_slice())
                .bind(fields.membership.as_bytes().as_slice())
                .fetch_optional(&mut **tx)
                .await?;
                if membership.is_none() {
                    return Err(Error::InvalidRequest);
                }
                match Self::inventory_object(tx, organization, fields.host).await {
                    Ok((object, _)) if object.object_type == InventoryType::Host.object_type() => Ok(()),
                    Ok(_) | Err(Error::NotFound) => Err(Error::InvalidRequest),
                    Err(error) => Err(error),
                }
            }

            /// Read a current Grant using transaction-current policy authority.
            /// # Errors
            /// Identity, tenant, policy and stored projection errors fail closed.
            pub async fn read_organization_grant(
                &self,
                expected: &impl OrganizationPrincipal,
                expires_at: u64,
                target: GrantTarget,
            ) -> Result<GrantResource, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let (current, _, _, _) = Self::inventory_owner(
                    &mut tx, expected, expires_at, target.organization, false,
                ).await?;
                Self::authorize_organization_action(
                    &mut tx, &current, now_ms()?, "view_policy",
                ).await?;
                let stored = Self::grant_resource(&mut tx, target).await?;
                $principal(&mut tx, expected, expires_at).await?;
                tx.commit().await?;
                Ok(stored.resource)
            }

            /// List current, unwithdrawn Grants in ascending identifier order.
            /// # Errors
            /// Invalid queries, current authority or corrupt bounded Resources fail closed.
            pub async fn list_organization_grants(
                &self,
                expected: &impl OrganizationPrincipal,
                expires_at: u64,
                organization: Uuid,
                query: OrganizationListQuery,
            ) -> Result<GrantPage, Error> {
                query.validate().map_err(|_| Error::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let (current, _, _, _) = Self::inventory_owner(
                    &mut tx, expected, expires_at, organization, false,
                ).await?;
                Self::authorize_organization_action(
                    &mut tx, &current, now_ms()?, "view_policy",
                ).await?;
                let rows = sqlx::query(
                    "SELECT id FROM organization_grants WHERE organization_id=$1 AND withdrawn_at_ms IS NULL AND id>$2 ORDER BY id LIMIT $3",
                )
                .bind(organization.as_bytes().as_slice())
                .bind(query.cursor.map(|id| id.as_bytes().to_vec()).unwrap_or_default())
                .bind(i64::from(query.limit) + 1)
                .fetch_all(&mut *tx)
                .await?;
                let mut page = GrantPage { items: Vec::new(), next_cursor: None };
                for row in rows {
                    if page.items.len() == usize::from(query.limit) {
                        page.next_cursor = page.items.last().map(|item| item.id);
                        break;
                    }
                    let id = super::inventory::row_uuid(&row, "id")?;
                    page.items.push(Self::grant_resource(
                        &mut tx, GrantTarget { organization, id },
                    ).await?.resource);
                }
                page.validate_for_query(query).map_err(|_| Error::StorageUnavailable)?;
                page.to_json().map_err(|_| Error::StorageUnavailable)?;
                $principal(&mut tx, expected, expires_at).await?;
                tx.commit().await?;
                Ok(page)
            }

            /// Commit a Grant, revision, attributable audit and original receipt atomically.
            /// # Errors
            /// Fixed current authority, precondition, reference and unknown-COMMIT errors.
            #[allow(clippy::too_many_lines)]
            pub async fn write_organization_grant(
                &self,
                expected: &impl OrganizationPrincipal,
                expires_at: u64,
                origin: &str,
                target: GrantTarget,
                write: GrantWrite<'_>,
            ) -> Result<GrantWriteResult, Error> {
                scoplen_model::validate_uuid_v7(target.id).map_err(|_| Error::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let (current, _, _, _) = Self::inventory_owner(
                    &mut tx, expected, expires_at, target.organization, true,
                ).await?;
                let now = now_ms()?;
                Self::authorize_organization_action(
                    &mut tx, &current, now, "manage_policy",
                ).await?;
                let org = target.organization.as_bytes().as_slice();
                let id = target.id.as_bytes().as_slice();
                let mut receipt = None;
                let (previous, fields) = match write {
                    GrantWrite::Create { key, fields } => {
                        scoplen_model::validate_uuid_v7(key).map_err(|_| Error::InvalidRequest)?;
                        let request = GrantCreateRequest { id: target.id, fields: fields.clone() };
                        let canonical = request.to_json().map_err(|_| Error::InvalidRequest)?;
                        let digest = create_digest(expected, origin, target, &canonical);
                        let stored = sqlx::query(
                            "SELECT organization_id,request_digest,response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3",
                        )
                        .bind(expected.account_id().as_slice())
                        .bind(key.as_bytes().as_slice())
                        .bind(now)
                        .fetch_optional(&mut *tx)
                        .await?;
                        if let Some(row) = stored {
                            if row.try_get::<Vec<u8>, _>("request_digest")?.as_slice() != digest {
                                return Err(Error::Conflict);
                            }
                            let bytes: Vec<u8> = row.try_get("response_json")?;
                            let retained = GrantResource::from_json(&bytes)
                                .map_err(|_| Error::StorageUnavailable)?;
                            retained.validate_for_create(&request)
                                .map_err(|_| Error::StorageUnavailable)?;
                            if super::inventory::row_uuid(&row, "organization_id")? != target.organization {
                                return Err(Error::StorageUnavailable);
                            }
                            $principal(&mut tx, expected, expires_at).await?;
                            tx.commit().await?;
                            return Ok(GrantWriteResult { response_json: Some(bytes), changed: false });
                        }
                        let used: Option<Vec<u8>> = sqlx::query_scalar(
                            "SELECT id FROM organization_grants WHERE id=$1",
                        )
                        .bind(id).fetch_optional(&mut *tx).await?;
                        if used.is_some() {
                            return Err(Error::Conflict);
                        }
                        Self::grant_references(&mut tx, target.organization, fields).await?;
                        receipt = Some((key, digest));
                        (None, Some(fields.clone()))
                    }
                    GrantWrite::Replace { if_match, fields } => {
                        let if_match = precondition(if_match)?;
                        GrantReplaceRequest { fields: fields.clone() }.to_json()
                            .map_err(|_| Error::InvalidRequest)?;
                        let current = Self::grant_resource(&mut tx, target).await?;
                        if current.resource.etag != if_match {
                            return Err(Error::PreconditionFailed);
                        }
                        Self::grant_references(&mut tx, target.organization, fields).await?;
                        if current.resource.fields == *fields {
                            $principal(&mut tx, expected, expires_at).await?;
                            tx.commit().await?;
                            return Ok(GrantWriteResult {
                                response_json: Some(current.response_json), changed: false,
                            });
                        }
                        (Some(current), Some(fields.clone()))
                    }
                    GrantWrite::Delete { if_match } => {
                        let if_match = precondition(if_match)?;
                        let current = Self::grant_resource(&mut tx, target).await?;
                        if current.resource.etag != if_match {
                            return Err(Error::PreconditionFailed);
                        }
                        (Some(current), None)
                    }
                };
                let updated_at_ms = previous.as_ref().map_or(Ok(now), |previous| {
                    previous.updated_at_ms.checked_add(1)
                        .map(|next| next.max(now)).ok_or(Error::StorageUnavailable)
                })?;
                let response_json = if let Some(fields) = fields {
                    let mut resource = GrantResource {
                        id: target.id,
                        etag: "\"pending\"".into(),
                        created_at: previous.as_ref().map_or_else(
                            || timestamp(now), |previous| Ok(previous.resource.created_at.clone()),
                        )?,
                        updated_at: timestamp(updated_at_ms)?,
                        fields,
                    };
                    let created_at_ms = previous.as_ref().map_or(Ok(now), |previous| {
                        scoplen_api::audit::parse_audit_timestamp(&previous.resource.created_at)
                            .map_err(|_| Error::StorageUnavailable)
                    })?;
                    let bytes = Self::persist_organization_grant(&mut tx,target.organization,
                        &mut resource,created_at_ms,updated_at_ms,previous.is_some()).await?;
                    Some(bytes)
                } else {
                    sqlx::query(
                        "UPDATE organization_grants SET withdrawn_at_ms=$1 WHERE organization_id=$2 AND id=$3 AND withdrawn_at_ms IS NULL",
                    )
                    .bind(now).bind(org).bind(id).execute(&mut *tx).await?;
                    None
                };
                Self::team_revision(&mut tx, target.organization, now).await?;
                let suffix = if response_json.is_none() { "deleted" }
                    else if receipt.is_some() { "created" } else { "updated" };
                let event = actor_audit(expected, serde_json::json!({
                    "action": format!("organization.grants_{suffix}"),
                    "account_id": Uuid::from_bytes(expected.account_id()),
                    "organization_id": target.organization,
                    "object_id": target.id,
                }))?;
                $audit(&mut tx, target.organization.into_bytes(), &event, now)
                    .await.map_err(|_| Error::StorageUnavailable)?;
                if let Some((key, digest)) = receipt {
                    sqlx::query(
                        "DELETE FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3",
                    )
                    .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice())
                    .bind(now).execute(&mut *tx).await?;
                    sqlx::query(
                        "INSERT INTO organization_inventory_receipts (account_id,idempotency_key,organization_id,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                    )
                    .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice())
                    .bind(org).bind(digest.as_slice())
                    .bind(response_json.as_ref().ok_or(Error::StorageUnavailable)?)
                    .bind(now).bind(now.checked_add(86_400_000).ok_or(Error::StorageUnavailable)?)
                    .execute(&mut *tx).await.map_err(|error|write_error(&error))?;
                }
                $principal(&mut tx, expected, expires_at).await?;
                tx.commit().await.map_err(|_| if receipt.is_some() {
                    Error::CommitOutcomeUnknown
                } else {
                    Error::UpdateCommitOutcomeUnknown
                })?;
                Ok(GrantWriteResult { response_json, changed: true })
            }
        }
    };
}

grants!(SqliteStore, Sqlite, "BEGIN IMMEDIATE", sqlite_actor, append_audit_event_in_transaction);
grants!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_actor,
    append_audit_event_in_postgres_transaction
);
