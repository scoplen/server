// SPDX-License-Identifier: AGPL-3.0-only
//! Organization issuer drafts and their original-writer receipts.

use scoplen_api::{
    auth_connection_draft::{DraftRequest, DraftResource},
    organization::{ORGANIZATION_CREATION_RECEIPT_SECONDS, parse_organization_if_match},
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Sqlite, Transaction};
use uuid::Uuid;

use super::{
    OrganizationPrincipal, OrganizationStoreError as Error, PostgresStore, SqliteStore,
    actor_audit, append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    inventory::row_uuid, lock_postgres, lock_sqlite, now_ms, postgres_actor, sqlite_actor,
    timestamp,
};

struct Mutation {
    key: Uuid,
    digest: [u8; 32],
    origin_digest: [u8; 32],
}

impl Mutation {
    fn from_request(
        origin: &str,
        expected: &impl OrganizationPrincipal,
        organization: Uuid,
        request: &DraftRequest<'_>,
    ) -> Result<Option<Self>, Error> {
        scoplen_crypto::validate_server_origin(origin).map_err(|_| Error::InvalidRequest)?;
        let (key, method, condition, payload) = match request {
            DraftRequest::Read => return Ok(None),
            DraftRequest::Create(key, body) => {
                (*key, "POST", "*", body.to_json().map_err(|_| Error::InvalidRequest)?)
            }
            DraftRequest::Cancel(key, tag) => {
                let condition =
                    parse_organization_if_match(Some(tag)).map_err(|_| Error::InvalidRequest)?;
                (*key, "DELETE", condition, Vec::new())
            }
        };
        scoplen_model::validate_uuid_v7(key).map_err(|_| Error::InvalidRequest)?;
        let path = format!("/api/v1/orgs/{organization}/auth-connection-draft");
        let mut hash = Sha256::new();
        for field in [
            origin.as_bytes(),
            &expected.account_id(),
            expected.receipt_writer_kind().unwrap_or(b"device"),
            &expected.writer_id(),
            key.as_bytes(),
            method.as_bytes(),
            path.as_bytes(),
            condition.as_bytes(),
            payload.as_slice(),
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        Ok(Some(Self {
            key,
            digest: hash.finalize().into(),
            origin_digest: Sha256::digest(origin.as_bytes()).into(),
        }))
    }
}

fn resource(
    organization_id: Uuid,
    id: Uuid,
    created_at: i64,
    issuer: String,
) -> Result<DraftResource, Error> {
    let value = DraftResource { organization_id, id, created_at: timestamp(created_at)?, issuer };
    value.to_json().map_err(|_| Error::StorageUnavailable)?;
    Ok(value)
}

macro_rules! issuer_drafts {
    ($store:ty, $db:ty, $begin:literal, $lock:ident, $actor:ident, $audit:ident, $org_lock:literal) => {
        impl $store {
            pub(super) async fn authorize_auth_draft(
                tx: &mut Transaction<'_, $db>,
                account: &[u8; 16],
                organization: Uuid,
            ) -> Result<i64, Error> {
                sqlx::query(concat!(
                    "SELECT o.id FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id ",
                    "WHERE o.id=$1 AND m.account_id=$2 AND o.dissolved_at_ms IS NULL AND m.status='active'", $org_lock
                ))
                    .bind(organization.as_bytes().as_slice()).bind(account.as_slice())
                    .fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let current = Self::read_organization_in_transaction(tx, account, organization.as_bytes()).await?;
                if !current.membership.roles.iter().any(|role| matches!(role.as_str(), "owner" | "administrator")) {
                    return Err(Error::PermissionDenied);
                }
                let now = now_ms()?;
                Self::authorize_organization_action(tx, &current, now, "manage_organization").await?;
                Ok(now)
            }

            /// Read, create or cancel an untested issuer after checking the current actor,
            /// active membership, role floor and Organization Cedar policies. The HTTP
            /// caller must first verify scope, token-bound proof, Origin and mutation admission.
            ///
            /// # Errors
            /// Returns fixed authorization, request, condition, conflict or storage classes.
            /// A failed mutation COMMIT can be confirmed only with the original writer and request.
            pub async fn organization_auth_draft(
                &self,
                expected: &impl OrganizationPrincipal,
                expires_at: u64,
                origin: &str,
                organization: Uuid,
                request: &DraftRequest<'_>,
            ) -> Result<Option<DraftResource>, Error> {
                scoplen_model::validate_uuid_v7(organization).map_err(|_| Error::InvalidRequest)?;
                let mutation = Mutation::from_request(origin, expected, organization, request)?;
                let account = expected.account_id();
                let mut tx = self.pool.begin_with($begin).await?;
                // The Account lock also serializes reuse of one key across different tenants.
                $lock(&mut tx, &account, mutation.is_some()).await?;
                $actor(&mut tx, expected, expires_at).await?;
                let now = Self::authorize_auth_draft(&mut tx, &account, organization).await?;
                let Some(mutation) = mutation else {
                    let row = sqlx::query("SELECT generation,issuer,created_at_ms FROM organization_auth_drafts WHERE organization_id=$1")
                        .bind(organization.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                    let result = resource(
                        organization,
                        row_uuid(&row, "generation")?,
                        row.try_get("created_at_ms")?,
                        row.try_get("issuer")?,
                    )?;
                    $actor(&mut tx, expected, expires_at).await?;
                    tx.commit().await?;
                    return Ok(Some(result));
                };
                let receipt = sqlx::query("SELECT request_digest,generation,created_at_ms,expires_at_ms FROM organization_auth_draft_receipts WHERE account_id=$1 AND origin_digest=$2 AND idempotency_key=$3")
                    .bind(account.as_slice()).bind(mutation.origin_digest.as_slice()).bind(mutation.key.as_bytes().as_slice())
                    .fetch_optional(&mut *tx).await?;
                if let Some(row) = receipt {
                    let Some(created_at) = row.try_get::<Option<i64>, _>("created_at_ms")? else {
                        return Err(Error::Conflict);
                    };
                    let receipt_expires_at: i64 = row.try_get("expires_at_ms")?;
                    let stored: Vec<u8> = row.try_get("request_digest")?;
                    if !(created_at..receipt_expires_at).contains(&now)
                        || stored.as_slice() != mutation.digest.as_slice()
                    {
                        return Err(Error::Conflict);
                    }
                    let result = match request {
                        DraftRequest::Create(_, body) => Some(resource(
                            organization,
                            row_uuid(&row, "generation")?,
                            created_at,
                            body.issuer.clone(),
                        )?),
                        DraftRequest::Cancel(_, _) => None,
                        DraftRequest::Read => return Err(Error::StorageUnavailable),
                    };
                    $actor(&mut tx, expected, expires_at).await?;
                    tx.commit().await?;
                    return Ok(result);
                }
                let (generation, result, action) =
                    Self::change_draft_slot(&mut tx, organization, now, request).await?;
                let ttl_ms = i64::try_from(ORGANIZATION_CREATION_RECEIPT_SECONDS * 1000)
                    .map_err(|_| Error::StorageUnavailable)?;
                let deadline = now.checked_add(ttl_ms).ok_or(Error::StorageUnavailable)?;
                sqlx::query("INSERT INTO organization_auth_draft_receipts (account_id,origin_digest,idempotency_key,request_digest,generation,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                    .bind(account.as_slice()).bind(mutation.origin_digest.as_slice()).bind(mutation.key.as_bytes().as_slice())
                    .bind(mutation.digest.as_slice()).bind(generation.as_bytes().as_slice()).bind(now).bind(deadline).execute(&mut *tx).await?;
                let event = actor_audit(
                    expected,
                    serde_json::json!({
                        "action": action, "account_id": Uuid::from_bytes(account), "organization_id": organization, "generation": generation,
                    }),
                )?;
                $audit(&mut tx, organization.into_bytes(), &event, now)
                    .await
                    .map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, expected, expires_at).await?;
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(result)
            }

            async fn change_draft_slot(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
                now: i64,
                request: &DraftRequest<'_>,
            ) -> Result<(Uuid, Option<DraftResource>, &'static str), Error> {
                match request {
                    DraftRequest::Create(_, body) => {
                        let generation = Uuid::now_v7();
                        let inserted = sqlx::query("INSERT INTO organization_auth_drafts (organization_id,generation,issuer,created_at_ms) VALUES ($1,$2,$3,$4) ON CONFLICT (organization_id) DO NOTHING")
                            .bind(organization.as_bytes().as_slice()).bind(generation.as_bytes().as_slice()).bind(&body.issuer).bind(now).execute(&mut **tx).await?;
                        if inserted.rows_affected() != 1 {
                            return Err(Error::PreconditionFailed);
                        }
                        let result = resource(organization, generation, now, body.issuer.clone())?;
                        Ok((generation, Some(result), "organization.auth_draft_created"))
                    }
                    DraftRequest::Cancel(_, tag) => {
                        let row = sqlx::query(
                            "SELECT generation FROM organization_auth_drafts WHERE organization_id=$1",
                        )
                        .bind(organization.as_bytes().as_slice())
                        .fetch_optional(&mut **tx)
                        .await?
                        .ok_or(Error::PreconditionFailed)?;
                        let generation = row_uuid(&row, "generation")?;
                        if format!("\"{generation}\"") != *tag {
                            return Err(Error::PreconditionFailed);
                        }
                        sqlx::query("DELETE FROM organization_auth_drafts WHERE organization_id=$1 AND generation=$2")
                            .bind(organization.as_bytes().as_slice()).bind(generation.as_bytes().as_slice()).execute(&mut **tx).await?;
                        Ok((generation, None, "organization.auth_draft_cancelled"))
                    }
                    DraftRequest::Read => Err(Error::StorageUnavailable),
                }
            }
        }
    };
}

issuer_drafts!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_actor,
    append_audit_event_in_transaction,
    ""
);
issuer_drafts!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_actor,
    append_audit_event_in_postgres_transaction,
    " FOR UPDATE OF o,m"
);
