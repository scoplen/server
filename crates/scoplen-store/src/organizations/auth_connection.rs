// SPDX-License-Identifier: AGPL-3.0-only
//! Organization connection candidates, installed revisions and original-writer receipts.

mod activation;
pub use activation::{
    ACTIVATION_PREFLIGHT_LIFETIME, ActivationPreflight, ConnectionActivationStart,
};
mod activation_callback;
pub use activation_callback::{ActivationClaim, ClaimedActivation};
mod activation_confirm;
pub use activation_confirm::ActivationConfirmation;

use scoplen_api::{
    account_browser::AccountBrowserAccessScope,
    auth_connection::{ConnectionResource, ConnectionStatus, ConnectionTarget},
    organization::ORGANIZATION_CREATION_RECEIPT_SECONDS,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::account_browser_sessions::CurrentAccountBrowserSession;

use super::{
    OrganizationStoreError as Error, PostgresStore, SqliteStore, actor_audit,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    inventory::row_uuid, lock_postgres, lock_sqlite, now_ms, postgres_actor, sqlite_actor,
    timestamp,
};

struct TransitionReceipt {
    account: [u8; 16],
    key: Uuid,
    origin_digest: [u8; 32],
    request_digest: [u8; 32],
}

impl TransitionReceipt {
    fn new(
        session: &CurrentAccountBrowserSession,
        key: Uuid,
        path: &str,
        condition: &str,
        purpose: &[u8],
    ) -> Self {
        let origin = session.trusted_origin().as_bytes();
        let mut digest = Sha256::new();
        digest.update(purpose);
        for field in [
            origin,
            &session.account_id,
            &session.family_id,
            key.as_bytes(),
            b"POST",
            path.as_bytes(),
            condition.as_bytes(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        Self {
            account: session.account_id,
            key,
            origin_digest: Sha256::digest(origin).into(),
            request_digest: digest.finalize().into(),
        }
    }
}

fn original_transition(
    bytes: &[u8],
    organization: Uuid,
    status: ConnectionStatus,
) -> Result<ConnectionResource, Error> {
    #[derive(Deserialize)]
    struct ReceiptTag {
        etag: String,
    }
    let tag: ReceiptTag = serde_json::from_slice(bytes).map_err(|_| Error::StorageUnavailable)?;
    ConnectionResource::from_http_json(
        bytes,
        organization,
        Some(status),
        Some(&tag.etag),
        Some("no-store"),
        Some("no-cache"),
    )
    .map_err(|_| Error::StorageUnavailable)
}

macro_rules! auth_connections {
    ($store:ty, $db:ty, $begin:literal, $lock:ident, $actor:ident, $audit:ident) => {
        impl $store {
            async fn check_auth_connection_management(
                tx: &mut Transaction<'_, $db>,
                session: &CurrentAccountBrowserSession,
                organization: Uuid,
                writing: bool,
            ) -> Result<i64, Error> {
                scoplen_model::validate_uuid_v7(organization).map_err(|_| Error::InvalidRequest)?;
                $lock(tx, &session.account_id, writing).await?;
                $actor(tx, session, 0).await?;
                if !AccountBrowserAccessScope::AuthConnectionManage.is_present_in(&session.scope) {
                    return Err(Error::PermissionDenied);
                }
                Self::authorize_auth_settings(tx, &session.account_id, organization, &["owner"]).await
            }

            async fn auth_connection_head(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
            ) -> Result<Option<ConnectionResource>, Error> {
                let row = sqlx::query("SELECT revision,status,issuer,client_id,space_id,created_at_ms FROM organization_auth_connections WHERE organization_id=$1")
                    .bind(organization.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
                row.map(|row| {
                    let status: String = row.try_get("status")?;
                    let status = match status.as_str() {
                        "active" => ConnectionStatus::Active,
                        "suspended" => ConnectionStatus::Suspended,
                        _ => return Err(Error::StorageUnavailable),
                    };
                    let value = ConnectionResource {
                        id: row_uuid(&row, "revision")?,
                        organization_id: organization,
                        created_at: timestamp(row.try_get("created_at_ms")?)?,
                        status,
                        target: ConnectionTarget {
                            issuer: row.try_get("issuer")?,
                            client_id: row.try_get("client_id")?,
                            space_id: row.try_get("space_id")?,
                        },
                    };
                    value.to_json().map_err(|_| Error::StorageUnavailable)?;
                    Ok(value)
                }).transpose()
            }

            async fn read_transition_receipt(
                tx: &mut Transaction<'_, $db>,
                receipt: &TransitionReceipt,
                organization: Uuid,
                status: ConnectionStatus,
            ) -> Result<Option<ConnectionResource>, Error> {
                let row = sqlx::query("SELECT request_digest,response_json,created_at_ms,expires_at_ms FROM organization_auth_connection_receipts WHERE account_id=$1 AND origin_digest=$2 AND idempotency_key=$3")
                    .bind(receipt.account.as_slice()).bind(receipt.origin_digest.as_slice())
                    .bind(receipt.key.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
                let Some(row) = row else { return Ok(None); };
                let Some(created_at) = row.try_get::<Option<i64>, _>("created_at_ms")? else {
                    return Err(Error::Conflict);
                };
                let expires_at: i64 = row.try_get("expires_at_ms")?;
                let digest: Vec<u8> = row.try_get("request_digest")?;
                if !(created_at..expires_at).contains(&now_ms()?) || digest != receipt.request_digest {
                    return Err(Error::Conflict);
                }
                let bytes: Vec<u8> = row.try_get("response_json")?;
                original_transition(&bytes, organization, status).map(Some)
            }

            async fn record_transition_receipt(
                tx: &mut Transaction<'_, $db>, receipt: &TransitionReceipt, body: &[u8], now: i64,
            ) -> Result<(), Error> {
                let ttl_ms = i64::try_from(ORGANIZATION_CREATION_RECEIPT_SECONDS * 1000)
                    .map_err(|_| Error::StorageUnavailable)?;
                let expires_at = now.checked_add(ttl_ms).ok_or(Error::StorageUnavailable)?;
                sqlx::query("INSERT INTO organization_auth_connection_receipts (account_id,origin_digest,idempotency_key,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                    .bind(receipt.account.as_slice()).bind(receipt.origin_digest.as_slice())
                    .bind(receipt.key.as_bytes().as_slice()).bind(receipt.request_digest.as_slice())
                    .bind(body).bind(now).bind(expires_at).execute(&mut **tx).await?;
                Ok(())
            }

            /// Read the current public connection revision with live browser and Owner authority.
            ///
            /// # Errors
            /// Returns fixed authentication, authorization, absence or storage classes.
            pub async fn read_organization_auth_connection(
                &self,
                session: &CurrentAccountBrowserSession,
                organization: Uuid,
            ) -> Result<ConnectionResource, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_auth_connection_management(&mut tx, session, organization, false).await?;
                let value = Self::auth_connection_head(&mut tx, organization).await?.ok_or(Error::NotFound)?;
                $actor(&mut tx, session, 0).await?;
                tx.commit().await?;
                Ok(value)
            }

            // Call under the same Organization lock as the change that invalidates the proof.
            pub(super) async fn fence_organization_auth_links(
                tx: &mut Transaction<'_, $db>,
                organization: Uuid,
                membership: Option<Uuid>,
                retire_links: bool,
            ) -> Result<(), Error> {
                let organization = organization.as_bytes().as_slice();
                let membership = membership.as_ref().map(|id| id.as_bytes().as_slice());
                sqlx::query("DELETE FROM organization_auth_link_attempts WHERE organization_id=$1 AND membership_id=COALESCE($2,membership_id)")
                    .bind(organization).bind(membership).execute(&mut **tx).await?;
                if retire_links {
                    sqlx::query(
                        "UPDATE organization_memberships SET auth_link_generation=auth_link_generation+1
                         WHERE organization_id=$1 AND id IN
                           (SELECT membership_id FROM organization_auth_links
                            WHERE organization_id=$1 AND membership_id=COALESCE($2,membership_id))"
                    ).bind(organization).bind(membership).execute(&mut **tx).await?;
                    sqlx::query("DELETE FROM organization_auth_links WHERE organization_id=$1 AND membership_id=COALESCE($2,membership_id)")
                        .bind(organization).bind(membership).execute(&mut **tx).await?;
                }
                Ok(())
            }

            /// Suspend the expected active revision and retire all candidates, or recover the
            /// original public result for the same eligible browser request.
            ///
            /// # Errors
            /// Returns fixed authority, condition, conflict, storage or commit-uncertainty classes.
            pub async fn suspend_organization_auth_connection(
                &self,
                session: &CurrentAccountBrowserSession,
                origin: &str,
                organization: Uuid,
                expected_revision: Uuid,
                key: Uuid,
            ) -> Result<ConnectionResource, Error> {
                if origin != session.trusted_origin() {
                    return Err(Error::AuthenticationRequired);
                }
                scoplen_model::validate_uuid_v7(expected_revision).map_err(|_| Error::InvalidRequest)?;
                scoplen_model::validate_uuid_v7(key).map_err(|_| Error::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_auth_connection_management(&mut tx, session, organization, true).await?;
                let path = format!("/api/v1/orgs/{organization}/auth-connection/suspend");
                let condition = format!("\"{expected_revision}\"");
                let receipt = TransitionReceipt::new(session, key, &path, &condition, b"spl-organization-auth-connection-suspend-v1\0");
                if let Some(result) = Self::read_transition_receipt(&mut tx, &receipt, organization, ConnectionStatus::Suspended).await? {
                    $actor(&mut tx, session, 0).await?;
                    tx.commit().await?;
                    return Ok(result);
                }

                let mut value = Self::auth_connection_head(&mut tx, organization)
                    .await?.filter(|value| value.id == expected_revision).ok_or(Error::PreconditionFailed)?;
                if value.status == ConnectionStatus::Suspended {
                    return Err(Error::Conflict);
                }
                value.id = Uuid::now_v7();
                value.status = ConnectionStatus::Suspended;
                let now = now_ms()?;
                value.created_at = timestamp(now)?;
                let body = value.to_json().map_err(|_| Error::StorageUnavailable)?;
                let changed = sqlx::query("UPDATE organization_auth_connections SET revision=$1,status='suspended',provider=NULL,trust_fingerprint=NULL,credential=NULL,created_at_ms=$2 WHERE organization_id=$3 AND revision=$4 AND status='active'")
                    .bind(value.id.as_bytes().as_slice()).bind(now).bind(organization.as_bytes().as_slice())
                    .bind(expected_revision.as_bytes().as_slice()).execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(Error::PreconditionFailed);
                }
                sqlx::query("DELETE FROM organization_auth_connection_activations WHERE organization_id=$1")
                    .bind(organization.as_bytes().as_slice()).execute(&mut *tx).await?;
                Self::fence_organization_auth_links(&mut tx, organization, None, false).await?;
                Self::record_transition_receipt(&mut tx, &receipt, &body, now).await?;
                let event = actor_audit(session, serde_json::json!({
                    "action": "organization.auth_connection_suspended",
                    "account_id": Uuid::from_bytes(session.account_id),
                    "organization_id": organization,
                    "previous_revision": expected_revision,
                    "revision": value.id,
                }))?;
                $audit(&mut tx, organization.into_bytes(), &event, now)
                    .await.map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(value)
            }
        }
    };
}

auth_connections!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_actor,
    append_audit_event_in_transaction
);
auth_connections!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_actor,
    append_audit_event_in_postgres_transaction
);
