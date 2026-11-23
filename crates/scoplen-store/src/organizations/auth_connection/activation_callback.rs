// SPDX-License-Identifier: AGPL-3.0-only
//! One-use callback claims, with completion fenced by current Organization authority.

use scoplen_api::{
    account_browser::AccountBrowserAccessScope,
    auth_connection_draft::{
        callback::{Callback, CallbackResult, IssuerIdentification},
        test_login::DraftLoginCredentials,
    },
};
use scoplen_crypto::{SecretBytes, SecretVec};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

use super::{
    super::{
        OrganizationStoreError as Error, PostgresStore, SqliteStore,
        append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
        auth_draft_login::{
            DraftLoginExchange, DraftLoginMaterial, DraftLoginOutcome, DraftLoginProvider,
        },
        auth_envelope,
        inventory::row_uuid,
        lock_postgres, lock_sqlite, now_ms,
    },
    activation::{CandidateBinding, CandidateField, require_fresh},
};
use crate::kms::KeyManagementService;

#[derive(Clone, Copy)]
struct ActivationCaller {
    binding: CandidateBinding,
    account: Uuid,
    family: Uuid,
}

impl ActivationCaller {
    fn audit(self, revision: Option<Uuid>, phase: &str, reason: &str) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&serde_json::json!({
            "action": "organization.auth_activation_finished",
            "organization_id": self.binding.organization,
            "attempt_id": self.binding.attempt,
            "draft_generation": self.binding.draft,
            "expected_revision": revision,
            "account_id": self.account,
            "browser_family_id": self.family,
            "status": phase,
            "reason": reason,
            "outcome": if phase == "verified" { "success" } else { "failure" },
        }))
        .map_err(|_| Error::StorageUnavailable)
    }
}

fn digest(value: &SecretBytes<32>) -> SecretBytes<32> {
    SecretBytes::new(Sha256::digest(value.as_bytes()).into())
}

fn stored_revision(bytes: Option<Vec<u8>>) -> Result<Option<Uuid>, Error> {
    bytes
        .map(|bytes| {
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::StorageUnavailable)?;
            scoplen_model::validate_uuid_v7(id).map_err(|_| Error::StorageUnavailable)?;
            Ok(id)
        })
        .transpose()
}

/// Activation callback whose original browser proved correlation and current authority.
pub enum ActivationClaim {
    /// Provider denial with a recorded, credential-free terminal result.
    Denied,
    /// The only permitted exchange for the claimed attempt.
    Exchange(Box<ClaimedActivation>),
}

/// A durably claimed activation. Its verifier has already been removed from storage.
pub struct ClaimedActivation {
    caller: ActivationCaller,
    revision: Option<Uuid>,
    nonce_digest: SecretBytes<32>,
    trust_fingerprint: [u8; 32],
    expires_at_ms: i64,
    issuer: String,
    provider: DraftLoginProvider,
    origin: String,
    exchange: Option<DraftLoginExchange>,
}

impl ClaimedActivation {
    /// The exact originally admitted issuer and endpoints.
    #[must_use]
    pub fn provider(&self) -> (&str, &DraftLoginProvider) {
        (&self.issuer, &self.provider)
    }

    /// Trusted origin used to register the exact callback URI.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Last instant for the claimed attempt and its original password proof.
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    /// Original deployment trust fingerprint.
    #[must_use]
    pub const fn trust_fingerprint(&self) -> [u8; 32] {
        self.trust_fingerprint
    }

    /// Match the raw nonce from the provider against the stored digest.
    #[must_use]
    pub fn matches_nonce(&self, nonce: &SecretBytes<32>) -> bool {
        self.nonce_digest == digest(nonce)
    }

    /// Consume the only in-memory copy of exchange authority.
    pub fn take_exchange(&mut self) -> Option<DraftLoginExchange> {
        self.exchange.take()
    }
}

macro_rules! activation_callbacks {
    ($store:ty, $db:ty, $begin:literal, $lock:ident, $audit:ident, $family_lock:literal) => {
        impl $store {
            async fn activation_callback_deadline(
                tx: &mut Transaction<'_, $db>, caller: ActivationCaller, origin: &str,
            ) -> Result<i64, Error> {
                $lock(tx, caller.account.as_bytes(), false).await?;
                let row = sqlx::query(concat!(
                    "SELECT f.created_at_ms,f.expires_at_ms,f.scope FROM account_browser_families f ",
                    "JOIN account_password_bootstrap b ON b.account_id=f.account_id ",
                    "JOIN identity_accounts a ON a.account_id=f.account_id WHERE f.family_id=$1 ",
                    "AND f.account_id=$2 AND f.trusted_origin=$3 AND b.origin=$3 ",
                    "AND f.revoked_at_ms IS NULL AND b.credential_generation=f.credential_generation ",
                    "AND b.password_profile=1 AND a.password_owned", $family_lock
                ))
                    .bind(caller.family.as_bytes().as_slice()).bind(caller.account.as_bytes().as_slice())
                    .bind(origin).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let expires_at: i64 = row.try_get("expires_at_ms")?;
                let scope: &str = row.try_get("scope")?;
                if !AccountBrowserAccessScope::AuthConnectionManage.is_present_in(scope) {
                    return Err(Error::NotFound);
                }
                Self::authorize_auth_settings(tx, caller.account.as_bytes(), caller.binding.organization, &["owner"]).await?;
                let now = now_ms()?;
                let password_deadline = require_fresh(row.try_get("created_at_ms")?, now)?;
                let deadline = expires_at.min(password_deadline);
                if now >= deadline {
                    return Err(Error::NotFound);
                }
                Ok(deadline)
            }

            async fn require_activation_callback_head(
                tx: &mut Transaction<'_, $db>, organization: Uuid, revision: Option<Uuid>,
            ) -> Result<(), Error> {
                if Self::auth_connection_head(tx, organization).await?.map(|head| head.id) != revision {
                    return Err(Error::NotFound);
                }
                Ok(())
            }

            /// Claim a state-bound activation callback. A confirmed claim erases the durable
            /// verifier before any outbound exchange. Provider denial also erases the credential.
            ///
            /// # Errors
            /// Rejects unmatched callbacks, invalid authority, stale trust or versions and
            /// storage failures. An uncertain commit discloses no outbound exchange authority.
            pub async fn claim_organization_auth_activation(
                &self, origin: &str, callback: Callback<'_>,
                trust: impl FnOnce(&str) -> Option<[u8;32]> + Send, kms: &dyn KeyManagementService,
            ) -> Result<ActivationClaim, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let state = digest(&callback.state);
                let row = sqlx::query(
                    "SELECT a.id,a.organization_id,a.draft_generation,a.family_id,a.browser_digest,f.account_id
                     FROM organization_auth_connection_activations a
                     JOIN account_browser_families f ON f.family_id=a.family_id
                     WHERE a.state_digest=$1 AND a.phase='pending' AND a.created_at_ms<=$2 AND a.expires_at_ms>$2"
                ).bind(state.as_bytes().as_slice()).bind(now_ms()?).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let browser: Vec<u8> = row.try_get("browser_digest")?;
                if SecretBytes::from_slice(&browser).as_ref() != Some(&digest(&callback.browser_binding)) {
                    return Err(Error::NotFound);
                }
                let binding = CandidateBinding {
                    attempt: row_uuid(&row,"id")?,
                    organization: row_uuid(&row,"organization_id")?,
                    draft: row_uuid(&row,"draft_generation")?,
                };
                let caller = ActivationCaller { binding, account: row_uuid(&row,"account_id")?, family: row_uuid(&row,"family_id")? };
                let deadline = Self::activation_callback_deadline(&mut tx, caller, origin).await?;
                let now = now_ms()?;
                let row = sqlx::query(
                    "SELECT a.expected_revision,a.issuer,a.client_id,a.provider,a.trust_fingerprint,
                            a.nonce_digest,a.credential,a.verifier,a.expires_at_ms
                     FROM organization_auth_connection_activations a
                     JOIN organization_auth_drafts d ON d.organization_id=a.organization_id
                         AND d.generation=a.draft_generation AND d.issuer=a.issuer
                     WHERE a.id=$1 AND a.phase='pending' AND a.created_at_ms<=$2 AND a.expires_at_ms>$2"
                ).bind(binding.attempt.as_bytes().as_slice()).bind(now).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let revision = stored_revision(row.try_get("expected_revision")?)?;
                Self::require_activation_callback_head(&mut tx, binding.organization, revision).await?;
                let issuer: String = row.try_get("issuer")?;
                let trust_fingerprint: [u8;32] = row.try_get::<Vec<u8>,_>("trust_fingerprint")?
                    .try_into().map_err(|_| Error::StorageUnavailable)?;
                if trust(&issuer) != Some(trust_fingerprint) {
                    return Err(Error::NotFound);
                }
                let provider: DraftLoginProvider = serde_json::from_str(row.try_get("provider")?)
                    .map_err(|_| Error::StorageUnavailable)?;
                let mode = if provider.response_issuer_required {
                    IssuerIdentification::ResponseParameter
                } else {
                    IssuerIdentification::ExclusiveCallback
                };
                let result = callback.bind_issuer(&issuer, mode).map_err(|_| Error::NotFound)?;
                let expires_at_ms = deadline.min(row.try_get("expires_at_ms")?);
                let claim = match result {
                    CallbackResult::Denied => ActivationClaim::Denied,
                    CallbackResult::Code(code) => {
                        let nonce_digest = SecretBytes::from_slice(&row.try_get::<Vec<u8>,_>("nonce_digest")?)
                            .ok_or(Error::StorageUnavailable)?;
                        let client_id = SecretVec::new(row.try_get::<String,_>("client_id")?.into_bytes());
                        let client_secret = auth_envelope::open(
                            &row.try_get::<Vec<u8>,_>("credential")?,
                            1..=512, |usage| binding.aad(CandidateField::Credential, usage), kms,
                        )?;
                        let verifier = auth_envelope::open(
                            &row.try_get::<Vec<u8>,_>("verifier")?,
                            32..=32, |usage| binding.aad(CandidateField::Verifier, usage), kms,
                        )?;
                        let verifier = SecretBytes::from_slice(verifier.as_bytes()).ok_or(Error::StorageUnavailable)?;
                        let material = DraftLoginMaterial {
                            credentials: DraftLoginCredentials { client_id, client_secret },
                            verifier,
                        };
                        ActivationClaim::Exchange(Box::new(ClaimedActivation {
                            caller, revision, nonce_digest, trust_fingerprint, expires_at_ms,
                            issuer, provider, origin: origin.to_owned(),
                            exchange: Some(DraftLoginExchange { code, material }),
                        }))
                    }
                };
                let denied = matches!(claim, ActivationClaim::Denied);
                let phase = if denied { "failed" } else { "claimed" };
                let now = now_ms()?;
                let updated = sqlx::query(
                    "UPDATE organization_auth_connection_activations
                     SET phase=$1,verifier=NULL,credential=CASE WHEN $1='failed' THEN NULL ELSE credential END
                     WHERE id=$2 AND phase='pending' AND created_at_ms<=$3 AND expires_at_ms>$3"
                ).bind(phase).bind(binding.attempt.as_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                if updated.rows_affected() != 1 { return Err(Error::NotFound); }
                if denied {
                    let audit = caller.audit(revision, "failed", "provider_denied")?;
                    $audit(&mut tx, binding.organization.into_bytes(), &audit, now)
                        .await.map_err(|_| Error::StorageUnavailable)?;
                }
                if now_ms()? >= expires_at_ms { return Err(Error::NotFound); }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(claim)
            }

            /// Record the terminal exchange result, rechecking the original family, live
            /// Owner authority, draft, trust and connection head in the result transaction.
            ///
            /// # Errors
            /// Rejects obsolete candidates, unavailable authority and storage failure.
            pub async fn finish_organization_auth_activation(
                &self, attempt: &ClaimedActivation,
                trust: impl Fn(&str) -> Option<[u8;32]> + Send, outcome: DraftLoginOutcome,
            ) -> Result<(), Error> {
                if attempt.exchange.is_some() {
                    return Err(Error::NotFound);
                }
                let mut tx = self.pool.begin_with($begin).await?;
                let caller = attempt.caller;
                let binding = caller.binding;
                let deadline = Self::activation_callback_deadline(&mut tx, caller, &attempt.origin).await?
                    .min(attempt.expires_at_ms);
                Self::require_activation_callback_head(&mut tx, binding.organization, attempt.revision).await?;
                if trust(&attempt.issuer) != Some(attempt.trust_fingerprint) {
                    return Err(Error::NotFound);
                }
                let (phase, reason) = match outcome {
                    DraftLoginOutcome::Verified => ("verified", "verified"),
                    DraftLoginOutcome::InvalidIdentity => ("failed", "invalid_identity"),
                    DraftLoginOutcome::ExchangeFailed => ("failed", "exchange_failed"),
                };
                let now = now_ms()?;
                if now >= deadline { return Err(Error::NotFound); }
                let updated = sqlx::query(
                    "UPDATE organization_auth_connection_activations
                     SET phase=$1,credential=CASE WHEN $1='failed' THEN NULL ELSE credential END
                     WHERE id=$2 AND phase='claimed' AND created_at_ms<=$3 AND expires_at_ms>$3
                       AND trust_fingerprint=$4 AND EXISTS (
                            SELECT 1 FROM organization_auth_drafts d
                            WHERE d.organization_id=$5 AND d.generation=$6 AND d.issuer=$7
                       )"
                ).bind(phase).bind(binding.attempt.as_bytes().as_slice()).bind(now)
                    .bind(attempt.trust_fingerprint.as_slice()).bind(binding.organization.as_bytes().as_slice())
                    .bind(binding.draft.as_bytes().as_slice()).bind(&attempt.issuer).execute(&mut *tx).await?;
                if updated.rows_affected() != 1 { return Err(Error::NotFound); }
                let audit = caller.audit(attempt.revision, phase, reason)?;
                $audit(&mut tx, binding.organization.into_bytes(), &audit, now)
                    .await.map_err(|_| Error::StorageUnavailable)?;
                if now_ms()? >= deadline || trust(&attempt.issuer) != Some(attempt.trust_fingerprint) {
                    return Err(Error::NotFound);
                }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(())
            }
        }
    };
}

activation_callbacks!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    append_audit_event_in_transaction,
    ""
);
activation_callbacks!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    append_audit_event_in_postgres_transaction,
    " FOR SHARE OF f,b,a"
);
