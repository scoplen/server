// SPDX-License-Identifier: AGPL-3.0-only
//! Single-use claims against the exact active Organization connection.

use scoplen_api::auth_connection_draft::{
    callback::{Callback, CallbackResult, IssuerIdentification},
    test_login::DraftLoginCredentials,
};
use scoplen_crypto::{SecretBytes, SecretVec};

use super::{
    DraftLoginProvider, Error, Postgres, PostgresStore, Row, Scope, Sqlite, SqliteStore,
    Transaction, Uuid, Writer, append_audit_event_in_postgres_transaction,
    append_audit_event_in_transaction,
    attempt::{digest, verifier_aad},
    lock_postgres, lock_sqlite, now_ms, require_fresh, row_uuid,
};
use crate::{
    kms::KeyManagementService,
    organizations::{
        auth_connection::installed_aad,
        auth_draft_login::{DraftLoginExchange, DraftLoginMaterial},
        auth_envelope,
    },
};

/// Completed provider denial, or material for the single authorized exchange.
pub enum LinkClaim {
    Denied,
    Exchange(Box<ClaimedLink>),
}

/// External verification outcome; only a protected comparison is retained in the database.
pub enum LinkOutcome {
    Verified(SecretVec),
    ExchangeFailed,
    InvalidIdentity,
}

/// Material released only after the durable claim erased the original verifier.
pub struct ClaimedLink {
    writer: Writer,
    id: Uuid,
    revision: Uuid,
    expires: i64,
    nonce: SecretBytes<32>,
    issuer: String,
    provider: DraftLoginProvider,
    origin: String,
    fingerprint: [u8; 32],
    exchange: Option<DraftLoginExchange>,
}

impl ClaimedLink {
    #[must_use]
    pub fn provider(&self) -> (&str, &DraftLoginProvider) {
        (&self.issuer, &self.provider)
    }
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires
    }
    #[must_use]
    pub const fn trust_fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    #[must_use]
    pub fn matches_nonce(&self, nonce: &SecretBytes<32>) -> bool {
        self.nonce == digest(nonce)
    }
    pub fn take_exchange(&mut self) -> Option<DraftLoginExchange> {
        self.exchange.take()
    }
}

macro_rules! link_callbacks {
    ($store:ty,$db:ty,$begin:literal,$lock:ident,$family_lock:literal,$audit:ident) => {
        impl $store {
            async fn link_callback_writer(
                tx: &mut Transaction<'_, $db>,
                org: Uuid,
                account: Uuid,
                family: Uuid,
                origin: &str,
            ) -> Result<(Writer, i64), Error> {
                $lock(tx, account.as_bytes(), false).await?;
                let row=sqlx::query(concat!("SELECT f.created_at_ms,f.expires_at_ms,f.scope FROM account_browser_families f
                            JOIN account_password_bootstrap b ON b.account_id=f.account_id JOIN identity_accounts a ON a.account_id=f.account_id
                            WHERE f.family_id=$1 AND f.account_id=$2 AND f.trusted_origin=$3 AND b.origin=$3 AND f.revoked_at_ms IS NULL
                            AND b.credential_generation=f.credential_generation AND b.password_profile=1 AND a.password_owned",$family_lock))
                            .bind(family.as_bytes().as_slice()).bind(account.as_bytes().as_slice()).bind(origin)
                            .fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                if !Scope::AuthLinksSelf.is_present_in(row.try_get("scope")?) {
                    return Err(Error::NotFound);
                }
                let now = now_ms()?;
                let deadline = require_fresh(row.try_get("created_at_ms")?, now)
                    .map_err(|_| Error::NotFound)?
                    .min(row.try_get("expires_at_ms")?);
                if now >= deadline {
                    return Err(Error::NotFound);
                }
                Ok((Self::active_link_membership(tx, account, org, family).await?, deadline))
            }

            async fn pending_link_callback(tx:&mut Transaction<'_,$db>, origin:&str, callback:&Callback<'_>) -> Result<(Writer,Uuid,i64),Error> {
                let row=sqlx::query("SELECT id,organization_id,account_id,family_id,browser_digest FROM organization_auth_link_attempts
                            WHERE state_digest=$1 AND phase='pending' AND created_at_ms<=$2 AND expires_at_ms>$2")
                            .bind(digest(&callback.state).as_bytes().as_slice()).bind(now_ms()?).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                if SecretBytes::from_slice(&row.try_get::<Vec<u8>, _>("browser_digest")?).as_ref()
                    != Some(&digest(&callback.browser_binding))
                {
                    return Err(Error::NotFound);
                }
                let id = row_uuid(&row, "id")?;
                let org = row_uuid(&row, "organization_id")?;
                let (writer, deadline) = Self::link_callback_writer(
                    tx,
                    org,
                    row_uuid(&row, "account_id")?,
                    row_uuid(&row, "family_id")?,
                    origin,
                )
                .await?;
                Ok((writer,id,deadline))
            }

            /// Claim only a matching callback in the original family and erase its verifier.
            ///
            /// # Errors
            /// Rejects uncorrelated, stale or repeated callbacks and unavailable or uncertain storage.
            pub async fn claim_member_link(
                &self,
                origin: &str,
                callback: Callback<'_>,
                trust: impl FnOnce(&str) -> Option<[u8; 32]> + Send,
                kms: &dyn KeyManagementService,
            ) -> Result<LinkClaim, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let (writer,id,deadline)=Self::pending_link_callback(&mut tx,origin,&callback).await?;
                let org=writer.member.organization_id;
                let (attempt, expires) = Self::live_link_attempt(&mut tx, writer, id).await?;
                let revision = attempt.connection_revision;
                let active = Self::link_active_revision(&mut tx, org, revision).await?;
                if trust(&active.target.issuer) != Some(active.fingerprint) {
                    return Err(Error::NotFound);
                }
                let mode = if active.provider.response_issuer_required {
                    IssuerIdentification::ResponseParameter
                } else {
                    IssuerIdentification::ExclusiveCallback
                };
                let result =
                    callback.bind_issuer(&active.target.issuer, mode).map_err(|_| Error::NotFound)?;
                let expires = expires.min(deadline);
                let claim = match result {
                    CallbackResult::Denied => LinkClaim::Denied,
                    CallbackResult::Code(code) => {
                        let row=sqlx::query("SELECT a.nonce_digest,a.verifier,c.credential FROM organization_auth_link_attempts a
                                    JOIN organization_auth_connections c ON c.organization_id=a.organization_id AND c.revision=a.connection_revision
                                    WHERE a.id=$1 AND a.phase='pending' AND c.status='active'")
                                    .bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                        let verifier = auth_envelope::open(
                            &row.try_get::<Vec<u8>, _>("verifier")?,
                            32..=32,
                            |u| verifier_aad(writer, id, revision, u),
                            kms,
                        )?;
                        let secret = auth_envelope::open(
                            &row.try_get::<Vec<u8>, _>("credential")?,
                            1..=512,
                            |u| installed_aad(org, revision, u),
                            kms,
                        )?;
                        let material = DraftLoginMaterial {
                            verifier: SecretBytes::from_slice(verifier.as_bytes())
                                .ok_or(Error::StorageUnavailable)?,
                            credentials: DraftLoginCredentials {
                                client_id: SecretVec::new(active.target.client_id.into_bytes()),
                                client_secret: secret,
                            },
                        };
                        LinkClaim::Exchange(Box::new(ClaimedLink {
                            writer,
                            id,
                            revision,
                            expires,
                            nonce: SecretBytes::from_slice(&row.try_get::<Vec<u8>, _>("nonce_digest")?)
                                .ok_or(Error::StorageUnavailable)?,
                            issuer: active.target.issuer,
                            provider: active.provider,
                            origin: origin.to_owned(),
                            fingerprint: active.fingerprint,
                            exchange: Some(DraftLoginExchange { code, material }),
                        }))
                    }
                };
                let denied = matches!(claim, LinkClaim::Denied);
                let now = now_ms()?;
                let changed = sqlx::query(
                    "UPDATE organization_auth_link_attempts SET phase=$1,verifier=NULL
                            WHERE id=$2 AND phase='pending' AND expires_at_ms>$3",
                )
                .bind(if denied { "failed" } else { "claimed" })
                .bind(id.as_bytes().as_slice())
                .bind(now)
                .execute(&mut *tx)
                .await?;
                if changed.rows_affected() != 1 {
                    return Err(Error::NotFound);
                }
                if denied {
                    let event = writer.event(
                        "organization.auth_link_finished",
                        Some(revision),
                        Some(id),
                        None,
                        Some(("failure", "provider_denied")),
                    )?;
                    $audit(&mut tx, org.into_bytes(), &event, now)
                        .await
                        .map_err(|_| Error::StorageUnavailable)?;
                }
                if now_ms()? >= expires {
                    return Err(Error::NotFound);
                }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(claim)
            }

            /// Record a verified or failed exchange only while the original authority and revision still hold.
            ///
            /// # Errors
            /// Rejects unconsumed or superseded claims, stale authority, invalid outcomes or storage failures.
            pub async fn finish_member_link(
                &self,
                origin: &str,
                claim: &ClaimedLink,
                trust: impl FnOnce(&str) -> Option<[u8; 32]> + Send,
                outcome: LinkOutcome,
                kms: &dyn KeyManagementService,
            ) -> Result<(), Error> {
                if claim.exchange.is_some() || origin != claim.origin {
                    return Err(Error::NotFound);
                }
                let mut tx = self.pool.begin_with($begin).await?;
                let org = claim.writer.member.organization_id;
                let (writer, deadline) = Self::link_callback_writer(
                    &mut tx,
                    org,
                    claim.writer.account,
                    claim.writer.family,
                    origin,
                )
                .await?;
                if writer.generation != claim.writer.generation || writer.member != claim.writer.member {
                    return Err(Error::NotFound);
                }
                let (attempt, expires) = Self::live_link_attempt(&mut tx, writer, claim.id).await?;
                if attempt.connection_revision != claim.revision {
                    return Err(Error::NotFound);
                }
                let active = Self::link_active_revision(&mut tx, org, claim.revision).await?;
                let (phase, result, reason, comparison) = match outcome {
                    LinkOutcome::Verified(subject)
                        if !subject.is_empty() && subject.len() <= 255 && subject.as_bytes().is_ascii() =>
                    {
                        (
                            "verified",
                            "success",
                            "verified",
                            Some(
                                Self::compare_link_subject(&mut tx, org, &active.target, &subject, kms)
                                    .await?,
                            ),
                        )
                    }
                    LinkOutcome::Verified(_) | LinkOutcome::InvalidIdentity => {
                        ("failed", "failure", "invalid_identity", None)
                    }
                    LinkOutcome::ExchangeFailed => ("failed", "failure", "exchange_failed", None),
                };
                let now = now_ms()?;
                let updated = sqlx::query(
                    "UPDATE organization_auth_link_attempts SET phase=$1,subject_comparison=$2
                            WHERE id=$3 AND phase='claimed' AND created_at_ms<=$4 AND expires_at_ms>$4",
                )
                .bind(phase)
                .bind(comparison.as_ref().map(SecretVec::as_bytes))
                .bind(claim.id.as_bytes().as_slice())
                .bind(now)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() != 1 {
                    return Err(Error::NotFound);
                }
                let event = writer.event(
                    "organization.auth_link_finished",
                    Some(claim.revision),
                    Some(claim.id),
                    None,
                    Some((result, reason)),
                )?;
                $audit(&mut tx, org.into_bytes(), &event, now)
                    .await
                    .map_err(|_| Error::StorageUnavailable)?;
                if now_ms()? >= expires.min(deadline).min(claim.expires)
                    || active.fingerprint != claim.fingerprint
                    || trust(&active.target.issuer) != Some(active.fingerprint)
                {
                    return Err(Error::NotFound);
                }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)
            }
        }
    };
}
link_callbacks!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    "",
    append_audit_event_in_transaction
);
link_callbacks!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    " FOR SHARE OF f,b,a",
    append_audit_event_in_postgres_transaction
);
