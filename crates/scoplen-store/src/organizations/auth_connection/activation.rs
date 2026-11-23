// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-reviewed, original-family-bound Organization connection activation candidates.

use std::time::Duration;

use scoplen_api::{
    auth_connection::{
        Activation, ActivationCandidate, ActivationContext, ConnectionTarget, ExpectedRevision,
    },
    auth_connection_draft::test_login::DraftLoginStatus,
};
use scoplen_crypto::SecretBytes;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Sqlite, Transaction};
use uuid::Uuid;

use super::super::{
    OrganizationStoreError as Error, PostgresStore, SqliteStore, actor_audit,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    auth_draft_login::DraftLoginProvider, auth_envelope, inventory::row_uuid, now_ms,
    postgres_actor, sqlite_actor, timestamp,
};
use crate::{account_browser_sessions::CurrentAccountBrowserSession, kms::KeyManagementService};

const PASSWORD_FRESH_MS: i64 = 300_000;

/// Upper bound on an admitted start before it becomes a durable activation.
pub const ACTIVATION_PREFLIGHT_LIFETIME: Duration = Duration::from_secs(20);

/// Database-backed admission for one family's discovery, on the reviewed draft and head.
pub struct ActivationPreflight {
    family: [u8; 16],
    reservation: Uuid,
    organization: Uuid,
    expected: ExpectedRevision,
    draft: Uuid,
    issuer: String,
}

impl ActivationPreflight {
    /// The authorized issuer from the exact currently saved draft.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// Admitted discovery and one-time proofs for a candidate in the current native browser family.
pub struct ConnectionActivationStart<'a> {
    pub preflight: &'a ActivationPreflight,
    pub candidate: &'a ActivationCandidate,
    pub provider: &'a DraftLoginProvider,
    pub trust_fingerprint: [u8; 32],
    pub state: &'a SecretBytes<32>,
    pub browser_binding: &'a SecretBytes<32>,
    pub nonce: &'a SecretBytes<32>,
    pub verifier: &'a SecretBytes<32>,
}

#[derive(Clone, Copy)]
pub(super) struct CandidateBinding {
    pub(super) attempt: Uuid,
    pub(super) organization: Uuid,
    pub(super) draft: Uuid,
}

#[derive(Clone, Copy)]
pub(super) enum CandidateField {
    Credential,
    Verifier,
}

impl CandidateBinding {
    pub(super) fn aad(self, field: CandidateField, usage: u8) -> Vec<u8> {
        let mut aad = b"spl-organization-auth-activation\0v1\0".to_vec();
        aad.push(match field {
            CandidateField::Credential => 1,
            CandidateField::Verifier => 2,
        });
        aad.push(usage);
        aad.extend_from_slice(self.attempt.as_bytes());
        aad.extend_from_slice(self.organization.as_bytes());
        aad.extend_from_slice(self.draft.as_bytes());
        aad
    }
}

pub(super) fn revision_id(expected: ExpectedRevision) -> Option<Uuid> {
    match expected {
        ExpectedRevision::Empty => None,
        ExpectedRevision::Current(id) => Some(id),
    }
}

fn candidate_audit(
    session: &CurrentAccountBrowserSession,
    activation: &Activation,
    action: &str,
) -> Result<Vec<u8>, Error> {
    actor_audit(
        session,
        serde_json::json!({
            "action": action,
            "organization_id": activation.context.organization_id,
            "account_id": Uuid::from_bytes(session.account_id),
            "attempt_id": activation.id,
            "draft_generation": activation.context.draft_generation,
            "expected_revision": revision_id(activation.context.expected_revision),
        }),
    )
}

pub(super) fn require_fresh(created_at: i64, now: i64) -> Result<i64, Error> {
    let deadline = created_at.checked_add(PASSWORD_FRESH_MS).ok_or(Error::StorageUnavailable)?;
    if !(created_at..deadline).contains(&now) {
        return Err(Error::PermissionDenied);
    }
    Ok(deadline)
}

macro_rules! activations {
    ($store:ty, $db:ty, $begin:literal, $actor:ident, $audit:ident,
     $cleanup_lock:literal, $db_clock:literal) => {
        impl $store {
            async fn activation_start_context(
                tx: &mut Transaction<'_, $db>, session: &CurrentAccountBrowserSession,
                organization: Uuid, expected: ExpectedRevision, draft: Uuid,
            ) -> Result<(String, i64), Error> {
                scoplen_model::validate_uuid_v7(draft).map_err(|_| Error::InvalidRequest)?;
                if let Some(id) = revision_id(expected) {
                    scoplen_model::validate_uuid_v7(id).map_err(|_| Error::InvalidRequest)?;
                }
                let created_at: i64 = sqlx::query_scalar("SELECT created_at_ms FROM account_browser_families WHERE family_id=$1 AND account_id=$2")
                    .bind(session.family_id.as_slice()).bind(session.account_id.as_slice())
                    .fetch_one(&mut **tx).await?;
                let now = now_ms()?;
                require_fresh(created_at, now)?;
                let head = Self::auth_connection_head(tx, organization).await?;
                if head.map(|head| head.id) != revision_id(expected) {
                    return Err(Error::PreconditionFailed);
                }
                let issuer = sqlx::query_scalar("SELECT issuer FROM organization_auth_drafts WHERE organization_id=$1 AND generation=$2")
                    .bind(organization.as_bytes().as_slice()).bind(draft.as_bytes().as_slice())
                    .fetch_optional(&mut **tx).await?.ok_or(Error::PreconditionFailed)?;
                let outstanding: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_auth_connection_activations WHERE family_id=$1 AND expires_at_ms>$2)")
                    .bind(session.family_id.as_slice()).bind(now).fetch_one(&mut **tx).await?;
                if outstanding {
                    return Err(Error::Conflict);
                }
                Ok((issuer, created_at))
            }

            /// Check the exact draft and claim this family's discovery slot before any network work.
            ///
            /// # Errors
            /// Rejects insufficient live authority, stale native sign-in or head/draft, and family conflicts.
            pub async fn reserve_organization_auth_activation(
                &self, session: &CurrentAccountBrowserSession, organization: Uuid,
                expected: ExpectedRevision, draft: Uuid,
            ) -> Result<ActivationPreflight, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                // Lock the Account before checking the family's candidate and preflight, even across Organizations.
                Self::check_auth_connection_management(&mut tx, session, organization, true).await?;
                let (issuer, created_at) = Self::activation_start_context(&mut tx, session, organization, expected, draft).await?;
                let family = session.family_id;
                let reservation = Uuid::now_v7();
                let now: i64 = sqlx::query_scalar($db_clock).fetch_one(&mut *tx).await?;
                let duration = i64::try_from(ACTIVATION_PREFLIGHT_LIFETIME.as_millis())
                    .map_err(|_| Error::StorageUnavailable)?;
                let expires = now.checked_add(duration).ok_or(Error::StorageUnavailable)?;
                let reserved = sqlx::query("INSERT INTO organization_auth_activation_preflights
                    (family_id,reservation_id,expires_at_ms) VALUES ($1,$2,$3)
                    ON CONFLICT (family_id) DO UPDATE SET reservation_id=excluded.reservation_id,expires_at_ms=excluded.expires_at_ms
                    WHERE organization_auth_activation_preflights.expires_at_ms<=$4")
                    .bind(family.as_slice()).bind(reservation.as_bytes().as_slice())
                    .bind(expires).bind(now).execute(&mut *tx).await?;
                if reserved.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                $actor(&mut tx, session, 0).await?;
                require_fresh(created_at, now_ms()?)?;
                tx.commit().await?;
                Ok(ActivationPreflight { family, reservation, organization, expected, draft, issuer })
            }

            /// End an uncompleted discovery without disturbing a successor's reservation.
            ///
            /// # Errors
            /// Returns a fixed storage error if the guarded deletion cannot be confirmed.
            pub async fn release_organization_auth_activation(
                &self, preflight: &ActivationPreflight,
            ) -> Result<(), Error> {
                sqlx::query("DELETE FROM organization_auth_activation_preflights WHERE family_id=$1 AND reservation_id=$2")
                    .bind(preflight.family.as_slice()).bind(preflight.reservation.as_bytes().as_slice())
                    .execute(&self.pool).await?;
                Ok(())
            }

            /// Persist one candidate and initiation audit after discovery, without changing the active revision.
            ///
            /// # Errors
            /// Rejects changed authority, trust, draft, head, expired native proof, storage failure or an uncertain commit.
            pub async fn start_organization_auth_activation(
                &self, session: &CurrentAccountBrowserSession, start: &ConnectionActivationStart<'_>,
                trust: impl FnOnce(&str) -> Option<[u8; 32]> + Send, kms: &dyn KeyManagementService,
            ) -> Result<Activation, Error> {
                let preflight = start.preflight;
                let organization = preflight.organization;
                let expected_revision = preflight.expected;
                let draft = preflight.draft;
                if session.family_id != preflight.family || start.candidate.draft_generation != draft {
                    return Err(Error::NotFound);
                }
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_auth_connection_management(&mut tx, session, organization, true).await?;
                let (issuer, created_at) = Self::activation_start_context(&mut tx, session, organization, expected_revision, draft).await?;
                if issuer != preflight.issuer {
                    return Err(Error::PreconditionFailed);
                }
                let consumed = sqlx::query(concat!("DELETE FROM organization_auth_activation_preflights
                    WHERE family_id=$1 AND reservation_id=$2 AND expires_at_ms>(", $db_clock, ")"))
                    .bind(preflight.family.as_slice()).bind(preflight.reservation.as_bytes().as_slice())
                    .execute(&mut *tx).await?;
                if consumed.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                start.candidate.to_json().map_err(|_| Error::InvalidRequest)?;
                let client_id = std::str::from_utf8(start.candidate.credentials.client_id.as_bytes())
                    .map_err(|_| Error::InvalidRequest)?.to_owned();
                let binding = CandidateBinding {attempt: Uuid::now_v7(), organization, draft};
                let credential = auth_envelope::seal(start.candidate.credentials.client_secret.as_bytes(),
                    |usage| binding.aad(CandidateField::Credential, usage), kms)?;
                let verifier = auth_envelope::seal(start.verifier.as_bytes(),
                    |usage| binding.aad(CandidateField::Verifier, usage), kms)?;
                let provider = serde_json::to_string(start.provider).map_err(|_| Error::InvalidRequest)?;
                let now = now_ms()?;
                let expires = require_fresh(created_at, now)?;
                let expected = revision_id(expected_revision);
                let target = ConnectionTarget { issuer, client_id, space_id: start.candidate.space_id.clone() };
                sqlx::query("DELETE FROM organization_auth_connection_activations WHERE family_id=$1 AND expires_at_ms<=$2")
                    .bind(session.family_id.as_slice()).bind(now).execute(&mut *tx).await?;
                let inserted = sqlx::query("INSERT INTO organization_auth_connection_activations
                    (id,organization_id,draft_generation,expected_revision,family_id,state_digest,browser_digest,nonce_digest,
                     trust_fingerprint,issuer,client_id,space_id,provider,phase,credential,verifier,created_at_ms,expires_at_ms)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',$14,$15,$16,$17) ON CONFLICT (family_id) DO NOTHING")
                    .bind(binding.attempt.as_bytes().as_slice()).bind(organization.as_bytes().as_slice())
                    .bind(draft.as_bytes().as_slice()).bind(expected.as_ref().map(|id|id.as_bytes().as_slice()))
                    .bind(session.family_id.as_slice()).bind(Sha256::digest(start.state.as_bytes()).as_slice())
                    .bind(Sha256::digest(start.browser_binding.as_bytes()).as_slice()).bind(Sha256::digest(start.nonce.as_bytes()).as_slice())
                    .bind(start.trust_fingerprint.as_slice()).bind(&target.issuer).bind(&target.client_id).bind(&target.space_id)
                    .bind(provider).bind(credential).bind(verifier).bind(now).bind(expires).execute(&mut *tx).await?;
                if inserted.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                let result = Activation { id: binding.attempt, status: DraftLoginStatus::Pending, expires_at: timestamp(expires)?,
                    context: ActivationContext {organization_id: organization, draft_generation: draft, expected_revision, target} };
                result.to_json().map_err(|_| Error::InvalidRequest)?;
                let event = candidate_audit(session, &result, "organization.auth_activation_started")?;
                $audit(&mut tx, organization.into_bytes(), &event, now).await.map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                if trust(&preflight.issuer) != Some(start.trust_fingerprint) {
                    return Err(Error::PermissionDenied);
                }
                require_fresh(created_at, now_ms()?)?;
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(result)
            }

            pub(super) async fn family_activation(
                tx: &mut Transaction<'_, $db>, session: &CurrentAccountBrowserSession, organization: Uuid, id: Uuid,
            ) -> Result<(Activation, i64, [u8; 32]), Error> {
                scoplen_model::validate_uuid_v7(id).map_err(|_| Error::InvalidRequest)?;
                let row = sqlx::query("SELECT a.draft_generation,a.expected_revision,a.phase,a.expires_at_ms,a.issuer,a.client_id,a.space_id,a.trust_fingerprint
                    FROM organization_auth_connection_activations a JOIN organization_auth_drafts d
                    ON d.organization_id=a.organization_id AND d.generation=a.draft_generation AND d.issuer=a.issuer
                    LEFT JOIN organization_auth_connections c ON c.organization_id=a.organization_id
                    WHERE a.id=$1 AND a.organization_id=$2 AND a.family_id=$3 AND a.created_at_ms<=$4 AND a.expires_at_ms>$4
                    AND (a.expected_revision=c.revision OR (a.expected_revision IS NULL AND c.revision IS NULL))")
                    .bind(id.as_bytes().as_slice()).bind(organization.as_bytes().as_slice())
                    .bind(session.family_id.as_slice()).bind(now_ms()?).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let expected: Option<Vec<u8>> = row.try_get("expected_revision")?;
                let expected_revision = match expected {
                    Some(bytes) => ExpectedRevision::Current(Uuid::from_slice(&bytes).map_err(|_| Error::StorageUnavailable)?),
                    None => ExpectedRevision::Empty,
                };
                let status = match row.try_get::<&str, _>("phase")? {
                    "pending"|"claimed" => DraftLoginStatus::Pending,
                    "verified" => DraftLoginStatus::Verified,
                    "failed" => DraftLoginStatus::Failed,
                    _ => return Err(Error::StorageUnavailable),
                };
                let expires: i64 = row.try_get("expires_at_ms")?;
                let result = Activation { id, status, expires_at: timestamp(expires)?,
                    context: ActivationContext {organization_id: organization, draft_generation: row_uuid(&row,"draft_generation")?, expected_revision,
                        target: ConnectionTarget { issuer: row.try_get("issuer")?, client_id: row.try_get("client_id")?, space_id: row.try_get("space_id")? }}};
                result.to_json().map_err(|_| Error::StorageUnavailable)?;
                let fingerprint: Vec<u8> = row.try_get("trust_fingerprint")?;
                Ok((result, expires, fingerprint.try_into().map_err(|_| Error::StorageUnavailable)?))
            }

            /// Read only a current, unexpired candidate in the initiating browser family.
            ///
            /// # Errors
            /// Rejects missing authority, changed trust, foreign, obsolete or expired attempts.
            pub async fn organization_auth_activation_status(
                &self, session: &CurrentAccountBrowserSession, organization: Uuid, id: Uuid,
                trust: impl FnOnce(&str) -> Option<[u8; 32]> + Send,
            ) -> Result<Activation, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_auth_connection_management(&mut tx, session, organization, false).await?;
                let (result, expires, fingerprint) = Self::family_activation(&mut tx, session, organization, id).await?;
                $actor(&mut tx, session, 0).await?;
                if trust(&result.context.target.issuer) != Some(fingerprint) || now_ms()? >= expires {
                    return Err(Error::NotFound);
                }
                tx.commit().await?;
                Ok(result)
            }

            /// Erase a current candidate and record its abandonment together, even during an exchange.
            ///
            /// # Errors
            /// Rejects unauthorized, foreign or expired attempts, audit failure and uncertain commit.
            pub async fn abandon_organization_auth_activation(
                &self, session: &CurrentAccountBrowserSession, organization: Uuid, id: Uuid,
            ) -> Result<(), Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_auth_connection_management(&mut tx, session, organization, true).await?;
                let (candidate, expires, _) = Self::family_activation(&mut tx, session, organization, id).await?;
                let now = now_ms()?;
                let deleted = sqlx::query("DELETE FROM organization_auth_connection_activations WHERE id=$1 AND organization_id=$2 AND family_id=$3 AND expires_at_ms>$4")
                    .bind(id.as_bytes().as_slice()).bind(organization.as_bytes().as_slice()).bind(session.family_id.as_slice())
                    .bind(now).execute(&mut *tx).await?;
                if deleted.rows_affected() != 1 {
                    return Err(Error::NotFound);
                }
                let event = candidate_audit(session, &candidate, "organization.auth_activation_abandoned")?;
                $audit(&mut tx, organization.into_bytes(), &event, now).await.map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                if now_ms()? >= expires {
                    return Err(Error::NotFound);
                }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)
            }

            /// Erase up to 100 expired candidates and 100 expired preflights per worker pass.
            /// Returns the number of expired candidates removed.
            ///
            /// # Errors
            /// Returns a fixed storage error when expiry cleanup cannot be confirmed.
            pub async fn cleanup_organization_auth_activations(&self) -> Result<u64, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let deleted = sqlx::query(concat!("DELETE FROM organization_auth_connection_activations WHERE id IN (SELECT id FROM organization_auth_connection_activations WHERE expires_at_ms<=$1 ORDER BY expires_at_ms,id LIMIT 100", $cleanup_lock,") AND expires_at_ms<=$1"))
                    .bind(now_ms()?).execute(&mut *tx).await?.rows_affected();
                let now: i64 = sqlx::query_scalar($db_clock).fetch_one(&mut *tx).await?;
                sqlx::query(concat!("DELETE FROM organization_auth_activation_preflights WHERE family_id IN (SELECT family_id FROM organization_auth_activation_preflights WHERE expires_at_ms<=$1 ORDER BY expires_at_ms,family_id LIMIT 100", $cleanup_lock,") AND expires_at_ms<=$1"))
                    .bind(now).execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(deleted)
            }
        }
    }
}

activations!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    sqlite_actor,
    append_audit_event_in_transaction,
    "",
    "SELECT CAST(strftime('%s','now') AS INTEGER)*1000 + CAST(substr(strftime('%f','now'),4,3) AS INTEGER)"
);
activations!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_actor,
    append_audit_event_in_postgres_transaction,
    " FOR UPDATE SKIP LOCKED",
    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
);

#[cfg(test)]
mod tests {
    use super::*;

    struct TestKms([u8; 32]);

    impl KeyManagementService for TestKms {
        fn key_encryption_key(&self) -> &[u8; 32] {
            &self.0
        }
        fn backend_name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn candidate_envelopes_bind_purpose_attempt_organization_and_draft() {
        let kms = TestKms([11; 32]);
        let binding = CandidateBinding {
            attempt: Uuid::now_v7(),
            organization: Uuid::now_v7(),
            draft: Uuid::now_v7(),
        };
        let material = SecretBytes::new([12; 32]);
        for (purpose, other) in [
            (CandidateField::Credential, CandidateField::Verifier),
            (CandidateField::Verifier, CandidateField::Credential),
        ] {
            let sealed =
                auth_envelope::seal(material.as_bytes(), |usage| binding.aad(purpose, usage), &kms)
                    .unwrap();
            let open = |context: CandidateBinding, field| {
                auth_envelope::open(&sealed, 32..=32, |usage| context.aad(field, usage), &kms)
            };
            assert_eq!(open(binding, purpose).unwrap().as_bytes(), material.as_bytes());
            assert_eq!(open(binding, other), Err(Error::StorageUnavailable));
            for wrong in [
                CandidateBinding { attempt: Uuid::now_v7(), ..binding },
                CandidateBinding { organization: Uuid::now_v7(), ..binding },
                CandidateBinding { draft: Uuid::now_v7(), ..binding },
            ] {
                assert_eq!(open(wrong, purpose), Err(Error::StorageUnavailable));
            }
        }
    }

    #[test]
    fn native_password_freshness_is_bounded_and_rejects_future_evidence() {
        assert_eq!(require_fresh(100, 99), Err(Error::PermissionDenied));
        assert_eq!(require_fresh(100, 100), Ok(300_100));
        assert_eq!(require_fresh(100, 300_099), Ok(300_100));
        assert_eq!(require_fresh(100, 300_100), Err(Error::PermissionDenied));
    }
}
