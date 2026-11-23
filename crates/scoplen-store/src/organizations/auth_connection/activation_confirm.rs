// SPDX-License-Identifier: AGPL-3.0-only
//! Install exactly the original family's verified activation and retain its public result.

use scoplen_api::{
    auth_connection::{ConnectionResource, ConnectionStatus, ExpectedRevision},
    auth_connection_draft::test_login::DraftLoginStatus,
};
use sqlx::Row;
use uuid::Uuid;

use super::{
    super::{
        OrganizationStoreError as Error, PostgresStore, SqliteStore, actor_audit,
        append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
        auth_envelope, now_ms, postgres_actor, sqlite_actor, timestamp,
    },
    TransitionReceipt,
    activation::{CandidateBinding, CandidateField, require_fresh, revision_id},
};
use crate::{account_browser_sessions::CurrentAccountBrowserSession, kms::KeyManagementService};

pub(in crate::organizations) fn installed_aad(
    organization: Uuid,
    revision: Uuid,
    usage: u8,
) -> Vec<u8> {
    let mut aad = b"spl-organization-auth-connection-credential\0v1\0".to_vec();
    aad.push(usage);
    aad.extend_from_slice(organization.as_bytes());
    aad.extend_from_slice(revision.as_bytes());
    aad
}

/// Exact original activation and HTTP preconditions for confirmation.
pub struct ActivationConfirmation {
    pub organization: Uuid,
    pub attempt: Uuid,
    pub expected: ExpectedRevision,
    pub key: Uuid,
}

macro_rules! confirmations {
    ($store:ty, $begin:literal, $actor:ident, $audit:ident) => {
        impl $store {
            /// Install a verified activation or recover the original public result.
            ///
            /// # Errors
            /// Rejects stale authority, trust, freshness, revisions and proofs. A failed
            /// confirmation commit can be recovered only with the exact original request.
            pub async fn confirm_organization_auth_activation(
                &self, session: &CurrentAccountBrowserSession, confirmation: &ActivationConfirmation,
                trust: impl Fn(&str) -> Option<[u8;32]> + Send, kms: &dyn KeyManagementService,
            ) -> Result<ConnectionResource, Error> {
                let ActivationConfirmation { organization, attempt, expected, key } = *confirmation;
                scoplen_model::validate_uuid_v7(attempt).map_err(|_| Error::InvalidRequest)?;
                scoplen_model::validate_uuid_v7(key).map_err(|_| Error::InvalidRequest)?;
                let expected_id = revision_id(expected);
                if let Some(revision) = expected_id {
                    scoplen_model::validate_uuid_v7(revision).map_err(|_| Error::InvalidRequest)?;
                }
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_auth_connection_management(&mut tx, session, organization, true).await?;
                let created_at: i64 = sqlx::query_scalar("SELECT created_at_ms FROM account_browser_families WHERE family_id=$1 AND account_id=$2")
                    .bind(session.family_id.as_slice()).bind(session.account_id.as_slice())
                    .fetch_one(&mut *tx).await?;
                require_fresh(created_at, now_ms()?)?;
                let path = format!("/api/v1/orgs/{organization}/auth-connection/activations/{attempt}/confirm");
                let condition = expected_id.map_or_else(|| "*".into(), |id| format!("\"{id}\""));
                let receipt = TransitionReceipt::new(session, key, &path, &condition, b"spl-organization-auth-connection-confirm-v1\0");
                if let Some(result) = Self::read_transition_receipt(&mut tx, &receipt, organization, ConnectionStatus::Active).await? {
                    $actor(&mut tx, session, 0).await?;
                    require_fresh(created_at, now_ms()?)?;
                    tx.commit().await?;
                    return Ok(result);
                }
                let (candidate, expires_at, fingerprint) =
                    Self::family_activation(&mut tx, session, organization, attempt).await?;
                if candidate.context.expected_revision != expected {
                    return Err(Error::PreconditionFailed);
                }
                if candidate.status != DraftLoginStatus::Verified {
                    return Err(Error::Conflict);
                }
                if trust(&candidate.context.target.issuer) != Some(fingerprint) {
                    return Err(Error::NotFound);
                }
                let row = sqlx::query("SELECT credential,provider FROM organization_auth_connection_activations WHERE id=$1 AND phase='verified' AND expires_at_ms>$2")
                    .bind(attempt.as_bytes().as_slice()).bind(now_ms()?).fetch_optional(&mut *tx).await?
                    .ok_or(Error::NotFound)?;
                let binding = CandidateBinding { attempt, organization, draft: candidate.context.draft_generation };
                let secret = auth_envelope::open(
                    &row.try_get::<Vec<u8>,_>("credential")?, 1..=512,
                    |usage| binding.aad(CandidateField::Credential, usage), kms,
                )?;
                let revision = Uuid::now_v7();
                let credential = auth_envelope::seal(secret.as_bytes(), |usage| installed_aad(organization, revision, usage), kms)?;
                let provider: String = row.try_get("provider")?;
                let now = now_ms()?;
                if now >= expires_at { return Err(Error::NotFound); }
                let context_changed = Self::auth_connection_head(&mut tx, organization).await?
                    .is_some_and(|previous| previous.target != candidate.context.target);
                let value = ConnectionResource {
                    id: revision, organization_id: organization, created_at: timestamp(now)?,
                    status: ConnectionStatus::Active, target: candidate.context.target,
                };
                let body = value.to_json().map_err(|_| Error::StorageUnavailable)?;
                let updated = sqlx::query(
                    "INSERT INTO organization_auth_connections (organization_id,revision,status,issuer,client_id,space_id,provider,trust_fingerprint,credential,created_at_ms)
                     VALUES ($1,$2,'active',$3,$4,$5,$6,$7,$8,$9)
                     ON CONFLICT (organization_id) DO UPDATE SET
                        revision=excluded.revision,status=excluded.status,issuer=excluded.issuer,client_id=excluded.client_id,
                        space_id=excluded.space_id,provider=excluded.provider,trust_fingerprint=excluded.trust_fingerprint,
                        credential=excluded.credential,created_at_ms=excluded.created_at_ms
                     WHERE organization_auth_connections.revision=$10"
                ).bind(organization.as_bytes().as_slice()).bind(revision.as_bytes().as_slice())
                    .bind(&value.target.issuer).bind(&value.target.client_id).bind(&value.target.space_id)
                    .bind(provider).bind(fingerprint.as_slice()).bind(credential).bind(now)
                    .bind(expected_id.as_ref().map(|revision| revision.as_bytes().as_slice()))
                    .execute(&mut *tx).await?;
                if updated.rows_affected() != 1 { return Err(Error::PreconditionFailed); }
                sqlx::query("DELETE FROM organization_auth_connection_activations WHERE organization_id=$1")
                    .bind(organization.as_bytes().as_slice()).execute(&mut *tx).await?;
                Self::fence_organization_auth_links(&mut tx, organization, None, context_changed).await?;
                Self::record_transition_receipt(&mut tx, &receipt, &body, now).await?;
                let event = actor_audit(session, serde_json::json!({
                    "action": "organization.auth_connection_activated",
                    "organization_id": organization,
                    "account_id": Uuid::from_bytes(session.account_id),
                    "attempt_id": attempt,
                    "draft_generation": binding.draft,
                    "previous_revision": expected_id,
                    "revision": revision,
                }))?;
                $audit(&mut tx, organization.into_bytes(), &event, now)
                    .await.map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                let now = now_ms()?;
                require_fresh(created_at, now)?;
                if now >= expires_at || trust(&value.target.issuer) != Some(fingerprint) {
                    return Err(Error::NotFound);
                }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(value)
            }
        }
    };
}

confirmations!(SqliteStore, "BEGIN IMMEDIATE", sqlite_actor, append_audit_event_in_transaction);
confirmations!(PostgresStore, "BEGIN", postgres_actor, append_audit_event_in_postgres_transaction);
