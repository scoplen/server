// SPDX-License-Identifier: AGPL-3.0-only
//! Durable, single-use Organization draft login attempts.

use scoplen_api::{
    account_browser::AccountBrowserAccessScope,
    auth_connection_draft::{
        callback::{Callback, CallbackResult, IssuerIdentification},
        test_login::{DraftLoginAttempt, DraftLoginCredentials, DraftLoginStatus},
    },
    organization::parse_organization_if_match,
};
use scoplen_crypto::{SecretBytes, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Sqlite, Transaction};
use uuid::Uuid;

use crate::{account_browser_sessions::CurrentAccountBrowserSession, kms::KeyManagementService};

use super::{
    OrganizationStoreError as Error, PostgresStore, SqliteStore,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    inventory::row_uuid, lock_postgres, lock_sqlite, now_ms, postgres_actor, sqlite_actor,
    timestamp,
};

mod envelope;

const TTL_MS: i64 = 300_000;

/// The exact endpoints and response-issuer mode admitted during trusted discovery.
#[derive(Serialize, Deserialize)]
pub struct DraftLoginProvider {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_issuer_required: bool,
}

/// One confidential exchange's redacting, zeroizing credentials.
#[derive(Debug, Eq, PartialEq)]
pub struct DraftLoginMaterial {
    pub credentials: DraftLoginCredentials,
    pub verifier: SecretBytes<32>,
}

/// Facts generated after start admission and trusted discovery. Random proofs are the
/// original bytes before base64url encoding. Only their digests are persisted.
pub struct DraftLoginStart<'a> {
    pub organization: Uuid,
    pub if_match: &'a str,
    pub issuer: &'a str,
    pub provider: &'a DraftLoginProvider,
    pub trust_fingerprint: [u8; 32],
    pub state: &'a SecretBytes<32>,
    pub browser_binding: &'a SecretBytes<32>,
    pub nonce: &'a SecretBytes<32>,
    pub material: &'a DraftLoginMaterial,
}

/// Only returned after the callback claim has committed and erased the retained envelope.
pub struct ClaimedDraftLogin {
    binding: AttemptBinding,
    nonce_digest: SecretBytes<32>,
    trust_fingerprint: [u8; 32],
    expires_at_ms: i64,
    issuer: String,
    provider: DraftLoginProvider,
    origin: String,
    exchange: Option<DraftLoginExchange>,
}

/// In-memory material for the single outbound exchange.
pub struct DraftLoginExchange {
    pub code: SecretVec,
    pub material: DraftLoginMaterial,
}

impl ClaimedDraftLogin {
    /// The exact issuer and discovered endpoints bound to the original draft.
    #[must_use]
    pub fn provider(&self) -> (&str, &DraftLoginProvider) {
        (&self.issuer, &self.provider)
    }

    /// The HTTPS origin of the original browser family.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Exchange deadline, bounded by the attempt and original browser family's lifetime.
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    /// Compare the original unencoded nonce with the provider's decoded nonce.
    #[must_use]
    pub fn matches_nonce(&self, nonce: &SecretBytes<32>) -> bool {
        self.nonce_digest == digest(nonce)
    }

    /// Trust admitted at initiation and confirmed by the claim transaction.
    #[must_use]
    pub const fn trust_fingerprint(&self) -> [u8; 32] {
        self.trust_fingerprint
    }

    /// Remove the request credentials before sending the one permitted exchange.
    pub fn take_exchange(&mut self) -> Option<DraftLoginExchange> {
        self.exchange.take()
    }
}

/// Provider denial finishes in the claim transaction without returning exchange material.
pub enum DraftLoginClaim {
    Denied,
    Exchange(Box<ClaimedDraftLogin>),
}

/// Fixed terminal classification. Provider errors and identity claims never enter the audit.
#[derive(Clone, Copy)]
pub enum DraftLoginOutcome {
    Verified,
    ExchangeFailed,
    InvalidIdentity,
}

#[derive(Clone, Copy)]
struct AttemptBinding {
    id: Uuid,
    organization: Uuid,
    generation: Uuid,
    account: Uuid,
    family: Uuid,
}

impl AttemptBinding {
    fn audit(self, result: Option<(&str, &str)>) -> Result<Vec<u8>, Error> {
        let mut event = serde_json::json!({
            "action": "organization.auth_draft_test_started",
            "organization_id": self.organization,
            "generation": self.generation,
            "attempt_id": self.id,
            "account_id": self.account,
            "browser_family_id": self.family,
        });
        if let Some((status, reason)) = result {
            event["action"] = "organization.auth_draft_test_finished".into();
            event["status"] = status.into();
            event["reason"] = reason.into();
            event["outcome"] = if status == "verified" { "success" } else { "failure" }.into();
        }
        serde_json::to_vec(&event).map_err(|_| Error::StorageUnavailable)
    }
}

fn digest(proof: &SecretBytes<32>) -> SecretBytes<32> {
    SecretBytes::new(Sha256::digest(proof.as_bytes()).into())
}

fn attempt(
    id: Uuid,
    organization_id: Uuid,
    draft_generation: Uuid,
    phase: &str,
    expires_at: i64,
) -> Result<DraftLoginAttempt, Error> {
    let status = match phase {
        "pending" | "claimed" => DraftLoginStatus::Pending,
        "verified" => DraftLoginStatus::Verified,
        "failed" => DraftLoginStatus::Failed,
        _ => return Err(Error::StorageUnavailable),
    };
    Ok(DraftLoginAttempt {
        id,
        organization_id,
        draft_generation,
        status,
        expires_at: timestamp(expires_at)?,
    })
}

macro_rules! draft_login {
    ($store:ty, $db:ty, $begin:literal, $lock:ident, $actor:ident, $audit:ident,
        $family_lock:literal, $cleanup_lock:literal) => {
        impl $store {
            async fn current_draft_login_target(
                tx: &mut Transaction<'_, $db>, organization: Uuid, if_match: &str,
            ) -> Result<(Uuid, String), Error> {
                let tag = parse_organization_if_match(Some(if_match)).map_err(|_| Error::InvalidRequest)?;
                let row = sqlx::query("SELECT generation,issuer FROM organization_auth_drafts WHERE organization_id=$1")
                    .bind(organization.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.ok_or(Error::PreconditionFailed)?;
                let generation = row_uuid(&row, "generation")?;
                if format!("\"{generation}\"") != tag { return Err(Error::PreconditionFailed); }
                Ok((generation, row.try_get("issuer")?))
            }

            async fn check_draft_login_session(
                tx: &mut Transaction<'_, $db>, session: &CurrentAccountBrowserSession, organization: Uuid,
            ) -> Result<(), Error> {
                $lock(tx, &session.account_id, false).await?;
                $actor(tx, session, 0).await?;
                if !AccountBrowserAccessScope::AuthTestRun.is_present_in(&session.scope) {
                    return Err(Error::PermissionDenied);
                }
                Self::authorize_auth_draft(tx, &session.account_id, organization).await?;
                Ok(())
            }

            /// Resolve the current draft before contacting any issuer.
            ///
            /// # Errors
            /// Rejects stale authority, stale draft and an outstanding family attempt.
            pub async fn organization_auth_draft_login_issuer(
                &self, session: &CurrentAccountBrowserSession, organization: Uuid, if_match: &str,
            ) -> Result<String, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_draft_login_session(&mut tx, session, organization).await?;
                let (_, issuer) = Self::current_draft_login_target(&mut tx, organization, if_match).await?;
                let active: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organization_auth_draft_tests WHERE family_id=$1 AND phase IN ('pending','claimed') AND expires_at_ms>$2)")
                    .bind(session.family_id.as_slice()).bind(now_ms()?).fetch_one(&mut *tx).await?;
                if active { return Err(Error::Conflict); }
                $actor(&mut tx, session, 0).await?;
                tx.commit().await?;
                Ok(issuer)
            }

            /// Store the immutable five-minute attempt and its initiation audit. The HTTP
            /// caller first checks proof, exact Origin, provider admission and discovery.
            ///
            /// # Errors
            /// Rejects stale authority, draft or a family with an outstanding attempt.
            pub async fn start_organization_auth_draft_login(
                &self, session: &CurrentAccountBrowserSession, start: &DraftLoginStart<'_>,
                trust: impl FnOnce(&str) -> Option<[u8;32]> + Send, kms: &dyn KeyManagementService,
            ) -> Result<DraftLoginAttempt, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_draft_login_session(&mut tx, session, start.organization).await?;
                let (generation, issuer) = Self::current_draft_login_target(&mut tx, start.organization, start.if_match).await?;
                if issuer != start.issuer {
                    return Err(Error::PreconditionFailed);
                }
                if trust(start.issuer) != Some(start.trust_fingerprint) { return Err(Error::PermissionDenied); }
                let binding = AttemptBinding { id: Uuid::now_v7(), organization: start.organization, generation,
                    account: Uuid::from_bytes(session.account_id), family: Uuid::from_bytes(session.family_id) };
                let credentials = envelope::seal(binding.id, generation, start.material, kms)?;
                let provider = serde_json::to_string(start.provider).map_err(|_| Error::InvalidRequest)?;
                let now = now_ms()?;
                let expires_at = now.checked_add(TTL_MS).ok_or(Error::StorageUnavailable)?;
                sqlx::query("DELETE FROM organization_auth_draft_tests WHERE family_id=$1 AND phase IN ('pending','claimed') AND expires_at_ms<=$2")
                    .bind(session.family_id.as_slice()).bind(now).execute(&mut *tx).await?;
                // Different teams share one outstanding attempt slot per browser family.
                let inserted = sqlx::query("INSERT INTO organization_auth_draft_tests (id,generation,family_id,state_digest,browser_digest,nonce_digest,trust_fingerprint,provider,phase,credentials,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11) ON CONFLICT (family_id) WHERE phase IN ('pending','claimed') DO NOTHING")
                    .bind(binding.id.as_bytes().as_slice()).bind(generation.as_bytes().as_slice()).bind(session.family_id.as_slice())
                    .bind(digest(start.state).as_bytes().as_slice()).bind(digest(start.browser_binding).as_bytes().as_slice())
                    .bind(digest(start.nonce).as_bytes().as_slice()).bind(start.trust_fingerprint.as_slice())
                    .bind(provider).bind(credentials).bind(now).bind(expires_at).execute(&mut *tx).await?;
                if inserted.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                $audit(&mut tx, start.organization.into_bytes(), &binding.audit(None)?, now)
                    .await.map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                if now_ms()? >= expires_at { return Err(Error::StorageUnavailable); }
                let result = attempt(binding.id, start.organization, generation, "pending", expires_at)?;
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(result)
            }

            /// Read a current attempt from the original, still-authorized browser family.
            ///
            /// # Errors
            /// Rejects invalid authority and missing, foreign, expired or superseded attempts.
            pub async fn organization_auth_draft_login_status(
                &self, session: &CurrentAccountBrowserSession, organization: Uuid, id: Uuid,
            ) -> Result<DraftLoginAttempt, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                Self::check_draft_login_session(&mut tx, session, organization).await?;
                let row = sqlx::query("SELECT t.generation,t.phase,t.expires_at_ms FROM organization_auth_draft_tests t JOIN organization_auth_drafts d ON d.generation=t.generation WHERE d.organization_id=$1 AND t.id=$2 AND t.family_id=$3 AND t.created_at_ms<=$4 AND t.expires_at_ms>$4")
                    .bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(session.family_id.as_slice()).bind(now_ms()?)
                    .fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let expires_at = row.try_get("expires_at_ms")?;
                let result = attempt(id, organization, row_uuid(&row,"generation")?, row.try_get("phase")?, expires_at)?;
                $actor(&mut tx, session, 0).await?;
                if now_ms()? >= expires_at { return Err(Error::NotFound); }
                tx.commit().await?;
                Ok(result)
            }

            async fn check_draft_login_callback_authority(
                tx: &mut Transaction<'_, $db>, binding: AttemptBinding, origin: &str,
            ) -> Result<i64, Error> {
                $lock(tx, binding.account.as_bytes(), false).await?;
                let row = sqlx::query(concat!("SELECT f.created_at_ms,f.expires_at_ms,f.scope FROM account_browser_families f JOIN account_password_bootstrap b ON b.account_id=f.account_id JOIN identity_accounts a ON a.account_id=f.account_id WHERE f.family_id=$1 AND f.account_id=$2 AND f.trusted_origin=$3 AND b.origin=$3 AND f.revoked_at_ms IS NULL AND b.credential_generation=f.credential_generation AND b.password_profile=1 AND a.password_owned", $family_lock))
                    .bind(binding.family.as_bytes().as_slice()).bind(binding.account.as_bytes().as_slice()).bind(origin)
                    .fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let expires_at = row.try_get("expires_at_ms")?;
                if !(row.try_get::<i64,_>("created_at_ms")?..expires_at).contains(&now_ms()?)
                    || !AccountBrowserAccessScope::AuthTestRun.is_present_in(row.try_get("scope")?) {
                    return Err(Error::NotFound);
                }
                Self::authorize_auth_draft(tx, binding.account.as_bytes(), binding.organization).await?;
                Ok(expires_at)
            }

            /// Claim the exact callback once, clearing its ciphertext in the same transaction.
            /// `trust` reads the current deployment entry without side effects or network I/O.
            ///
            /// # Errors
            /// Rejects unmatched callbacks, expired or revoked authority, changed trust, and
            /// unavailable storage. A failed commit discloses no code or credentials.
            pub async fn claim_organization_auth_draft_login(
                &self, origin: &str, callback: Callback<'_>, trust: impl FnOnce(&str) -> Option<[u8;32]> + Send,
                kms: &dyn KeyManagementService,
            ) -> Result<DraftLoginClaim, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let state = digest(&callback.state);
                let row = sqlx::query("SELECT t.id,t.generation,t.family_id,t.state_digest,t.browser_digest,d.organization_id,f.account_id FROM organization_auth_draft_tests t JOIN organization_auth_drafts d ON d.generation=t.generation JOIN account_browser_families f ON f.family_id=t.family_id WHERE t.state_digest=$1 AND t.phase='pending' AND t.created_at_ms<=$2 AND t.expires_at_ms>$2")
                    .bind(state.as_bytes().as_slice()).bind(now_ms()?).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let stored_state: Vec<u8> = row.try_get("state_digest")?;
                let stored_binding: Vec<u8> = row.try_get("browser_digest")?;
                if SecretBytes::from_slice(&stored_state).as_ref() != Some(&state)
                    || SecretBytes::from_slice(&stored_binding).as_ref() != Some(&digest(&callback.browser_binding)) {
                    return Err(Error::NotFound);
                }
                let binding = AttemptBinding { id: row_uuid(&row,"id")?, generation: row_uuid(&row,"generation")?,
                    family: row_uuid(&row,"family_id")?, organization: row_uuid(&row,"organization_id")?, account: row_uuid(&row,"account_id")? };
                let family_expires_at = Self::check_draft_login_callback_authority(&mut tx, binding, origin).await?;
                let now = now_ms()?;
                let row = sqlx::query("SELECT t.nonce_digest,t.trust_fingerprint,t.provider,t.credentials,d.issuer FROM organization_auth_draft_tests t JOIN organization_auth_drafts d ON d.generation=t.generation WHERE t.id=$1 AND t.phase='pending' AND t.created_at_ms<=$2 AND t.expires_at_ms>$2")
                    .bind(binding.id.as_bytes().as_slice()).bind(now).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let issuer: String = row.try_get("issuer")?;
                let fingerprint: Vec<u8> = row.try_get("trust_fingerprint")?;
                let trust_fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| Error::StorageUnavailable)?;
                if trust(&issuer) != Some(trust_fingerprint) {
                    return Err(Error::NotFound);
                }
                let provider: DraftLoginProvider = serde_json::from_str(row.try_get("provider")?).map_err(|_| Error::StorageUnavailable)?;
                let mode = if provider.response_issuer_required { IssuerIdentification::ResponseParameter } else { IssuerIdentification::ExclusiveCallback };
                let result = callback.bind_issuer(&issuer, mode).map_err(|_| Error::NotFound)?;
                let phase = if matches!(result, CallbackResult::Denied) { "failed" } else { "claimed" };
                let expires_at: i64 = sqlx::query_scalar("UPDATE organization_auth_draft_tests SET phase=$1,credentials=NULL WHERE id=$2 AND phase='pending' AND created_at_ms<=$3 AND expires_at_ms>$3 RETURNING expires_at_ms")
                    .bind(phase).bind(binding.id.as_bytes().as_slice()).bind(now_ms()?).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let expires_at_ms = expires_at.min(family_expires_at);
                let claim = match result {
                    CallbackResult::Denied => {
                        $audit(&mut tx, binding.organization.into_bytes(), &binding.audit(Some(("failed", "provider_denied")))?, now)
                            .await.map_err(|_| Error::StorageUnavailable)?;
                        DraftLoginClaim::Denied
                    }
                    CallbackResult::Code(code) => {
                        let encrypted: Vec<u8> = row.try_get("credentials")?;
                        let material = envelope::open(binding.id, binding.generation, &encrypted, kms)?;
                        let nonce: Vec<u8> = row.try_get("nonce_digest")?;
                        let nonce_digest = SecretBytes::from_slice(&nonce).ok_or(Error::StorageUnavailable)?;
                        DraftLoginClaim::Exchange(Box::new(ClaimedDraftLogin { binding, nonce_digest, trust_fingerprint,
                            expires_at_ms, issuer, provider, origin: origin.to_owned(), exchange: Some(DraftLoginExchange { code, material }) }))
                    }
                };
                if now_ms()? >= expires_at_ms { return Err(Error::NotFound); }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(claim)
            }

            /// Commit a verified or failed exchange result with its original browser audit.
            /// The caller verifies the provider result before selecting the terminal outcome.
            ///
            /// # Errors
            /// Rejects expired or superseded attempts, changed authority or trust, storage
            /// failure and repeated completion. No successful status survives audit failure.
            pub async fn finish_organization_auth_draft_login(
                &self, origin: &str, claimed: &ClaimedDraftLogin,
                trust: impl FnOnce(&str) -> Option<[u8;32]> + Send, outcome: DraftLoginOutcome,
            ) -> Result<(), Error> {
                let binding = claimed.binding;
                let mut tx = self.pool.begin_with($begin).await?;
                let family_expires_at = Self::check_draft_login_callback_authority(&mut tx, binding, origin).await?;
                let (phase, reason) = match outcome {
                    DraftLoginOutcome::Verified => ("verified", "verified"),
                    DraftLoginOutcome::ExchangeFailed => ("failed", "exchange_failed"),
                    DraftLoginOutcome::InvalidIdentity => ("failed", "invalid_identity"),
                };
                let trust_fingerprint = trust(&claimed.issuer).ok_or(Error::NotFound)?;
                let now = now_ms()?;
                let expires_at: i64 = sqlx::query_scalar("UPDATE organization_auth_draft_tests SET phase=$1 WHERE id=$2 AND phase='claimed' AND trust_fingerprint=$3 AND created_at_ms<=$4 AND expires_at_ms>$4 RETURNING expires_at_ms")
                    .bind(phase).bind(binding.id.as_bytes().as_slice()).bind(trust_fingerprint.as_slice()).bind(now).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                $audit(&mut tx, binding.organization.into_bytes(), &binding.audit(Some((phase, reason)))?, now)
                    .await.map_err(|_| Error::StorageUnavailable)?;
                if now_ms()? >= expires_at.min(family_expires_at) { return Err(Error::NotFound); }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(())
            }

            /// Erase up to 100 expired attempts per worker pass, including unclaimed keys.
            ///
            /// # Errors
            /// Returns a storage error when deletion fails or cannot be confirmed.
            pub async fn cleanup_organization_auth_draft_logins(&self) -> Result<u64, Error> {
                Ok(sqlx::query(concat!("DELETE FROM organization_auth_draft_tests WHERE id IN (SELECT id FROM organization_auth_draft_tests WHERE expires_at_ms<=$1 ORDER BY expires_at_ms,id LIMIT 100",$cleanup_lock,") AND expires_at_ms<=$1"))
                    .bind(now_ms()?).execute(&self.pool).await?.rows_affected())
            }
        }
    };
}

draft_login!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_actor,
    append_audit_event_in_transaction,
    "",
    ""
);
draft_login!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_actor,
    append_audit_event_in_postgres_transaction,
    " FOR SHARE OF f,b,a",
    " FOR UPDATE SKIP LOCKED"
);
