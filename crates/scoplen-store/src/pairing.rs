// SPDX-License-Identifier: AGPL-3.0-only
//! Durable, bounded second-device relay and atomic account membership publication.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};
use scoplen_api::{
    account_devices::AccountDeviceStatements,
    pairing::{
        PairingClaimResponse, PairingCompleteRequest, PairingContext, PairingCreateRequest,
        PairingCreateResponse, PairingMessageAck, PairingMessageRequest, PairingReceipt,
        PairingRole, PairingSnapshot, PairingState, PairingStep,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    DeviceCertificate, PairingApplicationContext, PairingCompletionContext,
    PairingContext as CryptoContext, RevocationStatement, SecretBytes,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    PostgresStore, SqliteStore,
    device_authentication::{
        CurrentPrincipal, DeviceAuthenticationError, load_postgres_principal, load_sqlite_principal,
    },
    pairing_admission::{PairingEndpoint, PairingPrivateBucket},
};

const RETENTION_MS: i64 = 86_400_000;
const LIFETIME_MS: i64 = 300_000;
const MAX_PAYLOAD_BYTES: i64 = 268_435_456;

/// A current old-device identity or the separately delivered new-device capability.
#[derive(Clone, Copy)]
pub enum PairingActor<'a> {
    Initiator(&'a CurrentPrincipal),
    Responder(&'a [u8; 32]),
}

/// Redacted persistence failures; no relay, key, credential, or signing bytes are exposed.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PairingStoreError {
    #[error("pairing request is invalid")]
    InvalidRequest,
    #[error("pairing denied")]
    Denied,
    #[error("current device authentication denied")]
    AuthenticationDenied,
    #[error("pairing transcript conflicts")]
    Conflict,
    #[error("pairing response capacity exceeded")]
    QuotaExceeded,
    #[error("pairing deployment resource limit reached")]
    ResourceLimited,
    #[error("pairing storage unavailable")]
    Database,
    #[error("pairing audit unavailable")]
    Audit,
    #[error("pairing trusted clock unavailable")]
    Clock,
    #[error("pairing entropy unavailable")]
    Entropy,
    #[error("pairing commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for PairingStoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

fn now_ms() -> Result<i64, PairingStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or(PairingStoreError::Clock)
}

fn timestamp(ms: i64) -> Result<String, PairingStoreError> {
    OffsetDateTime::from_unix_timestamp(ms / 1000)
        .map_err(|_| PairingStoreError::Clock)?
        .format(&Rfc3339)
        .map_err(|_| PairingStoreError::Clock)
}

fn audit(kind: u8, id: Uuid, now: i64) -> Vec<u8> {
    let mut bytes = b"spl-pairing-audit-v1".to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(&now.to_be_bytes());
    bytes.extend_from_slice(id.as_bytes());
    bytes
}

impl From<DeviceAuthenticationError> for PairingStoreError {
    fn from(error: DeviceAuthenticationError) -> Self {
        match error {
            DeviceAuthenticationError::Denied { .. } => Self::AuthenticationDenied,
            _ => Self::Database,
        }
    }
}

async fn sqlite_current(
    tx: &mut Transaction<'_, Sqlite>,
    expected: &CurrentPrincipal,
) -> Result<(), PairingStoreError> {
    current(
        load_sqlite_principal(tx, expected.device_id).await.map_err(PairingStoreError::from)?,
        expected,
    )
}

async fn postgres_current(
    tx: &mut Transaction<'_, Postgres>,
    expected: &CurrentPrincipal,
) -> Result<(), PairingStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(expected.account_id.as_slice())
        .execute(&mut **tx)
        .await?;
    current(
        load_postgres_principal(tx, expected.device_id, true)
            .await
            .map_err(PairingStoreError::from)?,
        expected,
    )
}

fn current(
    actual: Option<CurrentPrincipal>,
    expected: &CurrentPrincipal,
) -> Result<(), PairingStoreError> {
    if actual.is_some_and(|actual| {
        actual.account_id == expected.account_id
            && actual.device_id == expected.device_id
            && actual.jkt == expected.jkt
            && actual.signing_public_key == expected.signing_public_key
    }) {
        Ok(())
    } else {
        Err(PairingStoreError::AuthenticationDenied)
    }
}

struct Session {
    context: PairingContext,
    account: Option<[u8; 16]>,
    capability: SecretBytes<32>,
    expires: i64,
    retain_until: i64,
    state: PairingState,
    count: usize,
    fingerprint: Option<Vec<u8>>,
    revision: Option<i64>,
}

impl Session {
    fn authorize(&self, actor: PairingActor<'_>) -> Result<PairingRole, PairingStoreError> {
        match actor {
            PairingActor::Initiator(principal)
                if self.account == Some(principal.account_id)
                    && self.context.initiator_device_id
                        == Some(Uuid::from_bytes(principal.device_id)) =>
            {
                Ok(PairingRole::Initiator)
            }
            PairingActor::Responder(token)
                if self.capability == SecretBytes::new(Sha256::digest(token).into()) =>
            {
                Ok(PairingRole::Responder)
            }
            _ => Err(PairingStoreError::Denied),
        }
    }

    fn live(&self, now: i64) -> Result<(), PairingStoreError> {
        if now >= self.expires {
            Err(PairingStoreError::Denied)
        } else if self.state.is_terminal() {
            Err(PairingStoreError::Conflict)
        } else {
            Ok(())
        }
    }

    fn receipt(&self) -> Result<Option<PairingReceipt>, PairingStoreError> {
        if self.state != PairingState::Completed {
            return Ok(None);
        }
        Ok(Some(PairingReceipt {
            account_id: Uuid::from_bytes(self.account.ok_or(PairingStoreError::Database)?),
            device_id: self.context.responder_device_id,
            revision: self
                .revision
                .and_then(|v| u64::try_from(v).ok())
                .ok_or(PairingStoreError::Database)?,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_update(
    session: &Session,
    request: &PairingCompleteRequest,
    key: &[u8],
    revision: i64,
    encrypted: [&[u8]; 3],
    certificates: &[Vec<u8>],
    revocations: &[Vec<u8>],
    handoff: &[u8],
) -> Result<SyncAccountKeyBundleUpdate, PairingStoreError> {
    let key: [u8; 32] = key.try_into().map_err(|_| PairingStoreError::Database)?;
    let account = Uuid::from_bytes(session.account.ok_or(PairingStoreError::Database)?);
    let certificate = DeviceCertificate::decode(&request.device_certificate)
        .map_err(|_| PairingStoreError::InvalidRequest)?;
    certificate.verify(&key).map_err(|_| PairingStoreError::InvalidRequest)?;
    if certificate.account_id != account
        || certificate.device_id != session.context.responder_device_id
    {
        return Err(PairingStoreError::InvalidRequest);
    }
    let update = SyncAccountKeyBundleUpdate::from_cbor(&request.key_bundle_update)
        .map_err(|_| PairingStoreError::InvalidRequest)?;
    update
        .validate_next_revision(u64::try_from(revision).map_err(|_| PairingStoreError::Database)?)
        .map_err(|_| PairingStoreError::Conflict)?;
    i64::try_from(update.revision).map_err(|_| PairingStoreError::Conflict)?;
    if [
        update.account_signing_key.as_slice(),
        update.account_kem_key.as_slice(),
        update.recovery_blob.as_slice(),
    ] != encrypted
    {
        return Err(PairingStoreError::InvalidRequest);
    }
    VerifyingKey::from_bytes(&key)
        .map_err(|_| PairingStoreError::Database)?
        .verify_strict(
            &update.signature_input().map_err(|_| PairingStoreError::InvalidRequest)?,
            &Signature::from_slice(&update.signature)
                .map_err(|_| PairingStoreError::InvalidRequest)?,
        )
        .map_err(|_| PairingStoreError::InvalidRequest)?;
    let mut recipients = BTreeSet::new();
    for bytes in certificates {
        let prior = DeviceCertificate::decode(bytes).map_err(|_| PairingStoreError::Database)?;
        prior.verify(&key).map_err(|_| PairingStoreError::Database)?;
        if prior.account_id != account || !recipients.insert(prior.device_id) {
            return Err(PairingStoreError::Database);
        }
        if prior.device_id == certificate.device_id {
            return Err(PairingStoreError::Conflict);
        }
        if prior.signing_public_key == certificate.signing_public_key
            || prior.kem_public_key == certificate.kem_public_key
        {
            return Err(PairingStoreError::InvalidRequest);
        }
    }
    let mut revoked = BTreeSet::new();
    for bytes in revocations {
        let statement =
            RevocationStatement::decode(bytes).map_err(|_| PairingStoreError::Database)?;
        statement.verify(&key).map_err(|_| PairingStoreError::Database)?;
        if !revoked.insert(statement.device_id) {
            return Err(PairingStoreError::Database);
        }
        if statement.device_id == certificate.device_id {
            return Err(PairingStoreError::Conflict);
        }
        recipients.remove(&statement.device_id);
    }
    recipients.insert(certificate.device_id);
    if recipients != update.device_wraps.iter().map(|wrap| wrap.device_id).collect() {
        return Err(PairingStoreError::InvalidRequest);
    }
    let crypto = CryptoContext::new(
        session.context.pairing_id,
        session.context.initiator_device_id.ok_or(PairingStoreError::Database)?,
        certificate.device_id,
    )
    .map_err(|_| PairingStoreError::Database)?;
    let context = PairingApplicationContext::new(&session.context.origin, crypto)
        .map_err(|_| PairingStoreError::Database)?;
    PairingCompletionContext::new(
        &context,
        account,
        handoff,
        &request.device_certificate,
        &request.key_bundle_update,
    )
    .map_err(|_| PairingStoreError::InvalidRequest)?
    .verify(&certificate.signing_public_key, &request.new_device_signature)
    .map_err(|_| PairingStoreError::InvalidRequest)?;
    let mut projected = certificates.to_vec();
    projected.push(request.device_certificate.clone());
    projected.sort_unstable();
    AccountDeviceStatements::new(account, projected, revocations.to_vec())
        .and_then(|statements| statements.to_json())
        .map_err(|_| PairingStoreError::QuotaExceeded)?;
    Ok(update)
}

// Concrete backend expansion keeps sqlx transactions typed while both implementations execute
// exactly the same relay state machine and atomic membership checks.
macro_rules! pairing_store {
    ($module:ident, $store:ty, $db:ty, $row:ty, $postgres:expr, $begin:ident,
     $current:ident, $statements:ident, $capacity:ident, $append:ident, $clear:ident) => {
        mod $module {
            use super::*;
            use crate::{account_devices::{StatementKind, $statements},
                account_keys::$capacity, deployment_audit::$append, pairing_admission::$clear};

            fn sql(source: &str) -> String {
                if !$postgres { return source.to_owned(); }
                let mut n = 0;
                source.chars().map(|c| if c == '?' { n += 1; format!("${n}") } else { c.to_string() }).collect()
            }

            async fn finish<T>(tx: Transaction<'_, $db>, result: Result<T, PairingStoreError>, changed: bool)
                -> Result<T, PairingStoreError> {
                match result {
                    Ok(value) => { tx.commit().await.map_err(|_| if changed { PairingStoreError::CommitOutcomeUnknown } else { PairingStoreError::Database })?; Ok(value) }
                    Err(error) => { tx.rollback().await.map_err(|_| PairingStoreError::Database)?; Err(error) }
                }
            }

            async fn start<'a>(store: &'a $store, actor: Option<PairingActor<'_>>) -> Result<Transaction<'a, $db>, PairingStoreError> {
                let mut tx = $begin(store).await?;
                if $postgres {
                    sqlx::query("SELECT pg_advisory_xact_lock(1935897196, 114)")
                        .execute(&mut *tx).await?;
                }
                if let Some(PairingActor::Initiator(principal)) = actor { $current(&mut tx, principal).await?; }
                Ok(tx)
            }

            async fn event(tx: &mut Transaction<'_, $db>, kind: u8, id: Uuid, now: i64) -> Result<(), PairingStoreError> {
                $append(tx, &audit(kind, id, now), now).await.map_err(|_| PairingStoreError::Audit)?;
                Ok(())
            }

            async fn success(tx: &mut Transaction<'_, $db>, source: IpAddr, endpoint: PairingEndpoint, actor: PairingActor<'_>) -> Result<(), PairingStoreError> {
                let private = match actor {
                    PairingActor::Initiator(principal) => PairingPrivateBucket::Account(principal.account_id),
                    PairingActor::Responder(token) => PairingPrivateBucket::Capability(Sha256::digest(token).into()),
                };
                $clear(tx, source, endpoint, private).await.map_err(|_| PairingStoreError::Database)
            }

            async fn session(tx: &mut Transaction<'_, $db>, origin: &str, id: Uuid, now: i64) -> Result<Session, PairingStoreError> {
                let mut query = sql("SELECT * FROM pairing_sessions WHERE pairing_id=? AND trusted_origin=? AND retain_until_ms>?");
                if $postgres { query.push_str(" FOR UPDATE"); }
                let row: $row = sqlx::query(&query).bind(id.as_bytes().as_slice()).bind(origin).bind(now)
                    .fetch_optional(&mut **tx).await?.ok_or(PairingStoreError::Denied)?;
                let state: String = row.try_get("state")?;
                let state = match state.as_str() { "waiting" => PairingState::Waiting,
                    "exchanging" => PairingState::Exchanging, "ready" => PairingState::Ready,
                    "completed" => PairingState::Completed, "cancelled" => PairingState::Cancelled,
                    "expired" => PairingState::Expired, _ => return Err(PairingStoreError::Database) };
                let expires: i64 = row.try_get("expires_at_ms")?;
                let initiator: Option<Vec<u8>> = row.try_get("initiator_device_id")?;
                let account: Option<Vec<u8>> = row.try_get("account_id")?;
                Ok(Session {
                    context: PairingContext { origin: origin.to_owned(), pairing_id: id,
                        initiator_device_id: initiator.map(|v| Uuid::from_slice(&v).map_err(|_| PairingStoreError::Database)).transpose()?,
                        responder_device_id: Uuid::from_slice(&row.try_get::<Vec<u8>, _>("responder_device_id")?).map_err(|_| PairingStoreError::Database)?,
                        expires_at: timestamp(expires)? },
                    account: account.map(|v| v.try_into().map_err(|_| PairingStoreError::Database)).transpose()?,
                    capability: SecretBytes::from_slice(&row.try_get::<Vec<u8>, _>("capability_digest")?).ok_or(PairingStoreError::Database)?,
                    expires, retain_until: row.try_get("retain_until_ms")?, state, count: usize::try_from(row.try_get::<i64, _>("slot_count")?).map_err(|_| PairingStoreError::Database)?,
                    fingerprint: row.try_get("approval_fingerprint")?, revision: row.try_get("completed_revision")?,
                })
            }

            async fn cleanup(store: &$store) -> Result<(), PairingStoreError> {
                let mut tx = start(store, None).await?;
                let result = async {
                    let now = now_ms()?;
                    let ids: Vec<Vec<u8>> = sqlx::query_scalar(&sql("SELECT pairing_id FROM pairing_sessions WHERE state IN ('waiting','exchanging','ready') AND expires_at_ms<=? ORDER BY expires_at_ms LIMIT 256"))
                        .bind(now).fetch_all(&mut *tx).await?;
                    let mut changed = !ids.is_empty();
                    for id in ids {
                        sqlx::query(&sql("UPDATE pairing_sessions SET state='expired', payload_bytes=0 WHERE pairing_id=?"))
                            .bind(&id).execute(&mut *tx).await?;
                        sqlx::query(&sql("UPDATE pairing_slots SET payload=NULL WHERE pairing_id=?"))
                            .bind(&id).execute(&mut *tx).await?;
                        event(&mut tx, 6, Uuid::from_slice(&id).map_err(|_| PairingStoreError::Database)?, now).await?;
                    }
                    let ids: Vec<Vec<u8>> = sqlx::query_scalar(&sql("SELECT pairing_id FROM pairing_sessions WHERE retain_until_ms<=? ORDER BY retain_until_ms LIMIT 256"))
                        .bind(now).fetch_all(&mut *tx).await?;
                    changed |= !ids.is_empty();
                    for id in ids {
                        sqlx::query(&sql("DELETE FROM pairing_sessions WHERE pairing_id=?"))
                            .bind(&id).execute(&mut *tx).await?;
                        event(&mut tx, 7, Uuid::from_slice(&id).map_err(|_| PairingStoreError::Database)?, now).await?;
                    }
                    Ok(changed)
                }.await;
                match result {
                    Ok(false) => tx.rollback().await.map_err(|_| PairingStoreError::Database),
                    other => finish(tx, other.map(|_| ()), true).await,
                }
            }

            impl $store {
                /// Create a five-minute session and return its one-time responder capability.
                ///
                /// # Errors
                /// Rejects invalid context, exhausted deployment budgets, or storage failure.
                pub async fn create_pairing(&self, origin: &str, request: &PairingCreateRequest, _source: IpAddr) -> Result<PairingCreateResponse, PairingStoreError> {
                    request.to_json().map_err(|_| PairingStoreError::InvalidRequest)?;
                    cleanup(self).await?;
                    let mut tx = start(self, None).await?;
                    let result = async {
                        let now = now_ms()? / 1000 * 1000;
                        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions").fetch_one(&mut *tx).await?;
                        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions WHERE state IN ('waiting','exchanging','ready')").fetch_one(&mut *tx).await?;
                        if count >= 10_000 || active >= 1000 { return Err(PairingStoreError::ResourceLimited); }
                        let context = PairingContext { origin: origin.to_owned(), pairing_id: Uuid::now_v7(),
                            initiator_device_id: None, responder_device_id: request.device_id, expires_at: timestamp(now + LIFETIME_MS)? };
                        context.validate().map_err(|_| PairingStoreError::InvalidRequest)?;
                        let mut raw = Zeroizing::new([0;32]);
                        getrandom::fill(raw.as_mut()).map_err(|_| PairingStoreError::Entropy)?;
                        let token = SecretBytes::new(*raw);
                        let digest = Sha256::digest(token.as_bytes());
                        sqlx::query(&sql("INSERT INTO pairing_sessions (pairing_id,trusted_origin,responder_device_id,capability_digest,created_at_ms,expires_at_ms,retain_until_ms,state,slot_count,payload_bytes) VALUES (?,?,?,?,?,?,?,'waiting',0,0)"))
                            .bind(context.pairing_id.as_bytes().as_slice()).bind(origin).bind(request.device_id.as_bytes().as_slice())
                            .bind(digest.as_slice()).bind(now).bind(now+LIFETIME_MS).bind(now+LIFETIME_MS+RETENTION_MS)
                            .execute(&mut *tx).await?;
                        event(&mut tx, 1, context.pairing_id, now).await?;
                        let response = PairingCreateResponse { context, new_device_token: token };
                        response.to_json().map_err(|_| PairingStoreError::Database)?;
                        Ok(response)
                    }.await;
                    finish(tx, result, true).await
                }

                /// Verify a capability before selecting its private admission bucket.
                ///
                /// # Errors
                /// Returns a generic denial without loading any relay payload.
                pub async fn verify_pairing_responder(&self, origin: &str, id: Uuid, token: &[u8;32]) -> Result<(), PairingStoreError> {
                    let mut tx = start(self, None).await?;
                    let result = async { session(&mut tx, origin, id, now_ms()?).await?.authorize(PairingActor::Responder(token))?; Ok(()) }.await;
                    finish(tx, result, false).await
                }

                /// Bind the current old device once, with exact claim replay.
                ///
                /// # Errors
                /// Rejects expired sessions, competing claimants, stale identities, or storage failure.
                pub async fn claim_pairing(&self, origin: &str, id: Uuid, principal: &CurrentPrincipal, source: IpAddr) -> Result<PairingClaimResponse, PairingStoreError> {
                    cleanup(self).await?;
                    let mut tx = start(self, Some(PairingActor::Initiator(principal))).await?;
                    let mut changed = false;
                    let result = async {
                        let now = now_ms()?;
                        let mut stored = session(&mut tx, origin, id, now).await?;
                        if stored.account.is_some() { stored.authorize(PairingActor::Initiator(principal))?; }
                        let now = now_ms()?;
                        stored.live(now)?;
                        if stored.context.responder_device_id == Uuid::from_bytes(principal.device_id) { return Err(PairingStoreError::Denied); }
                        success(&mut tx, source, PairingEndpoint::Claim, PairingActor::Initiator(principal)).await?;
                        let now = now_ms()?;
                        stored.live(now)?;
                        if stored.account.is_none() {
                            sqlx::query(&sql("UPDATE pairing_sessions SET account_id=?, initiator_device_id=?, state='exchanging' WHERE pairing_id=?"))
                                .bind(principal.account_id.as_slice()).bind(principal.device_id.as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                            stored.context.initiator_device_id = Some(Uuid::from_bytes(principal.device_id));
                            event(&mut tx, 2, id, now).await?;
                            changed = true;
                        }
                        let response = PairingClaimResponse { context: stored.context };
                        response.to_json().map_err(|_| PairingStoreError::Database)?;
                        Ok(response)
                    }.await;
                    finish(tx, result, changed).await
                }

                /// Read the ordered relay transcript or a retained terminal receipt.
                ///
                /// # Errors
                /// Rejects wrong roles, stale identities, expired retention, or storage failure.
                pub async fn read_pairing(&self, origin: &str, id: Uuid, actor: PairingActor<'_>, source: IpAddr) -> Result<PairingSnapshot, PairingStoreError> {
                    cleanup(self).await?;
                    let mut tx = start(self, Some(actor)).await?;
                    let result = async {
                        let mut stored = session(&mut tx, origin, id, now_ms()?).await?;
                        stored.authorize(actor)?;
                        success(&mut tx, source, PairingEndpoint::Read, actor).await?;
                        let now = now_ms()?;
                        if now >= stored.retain_until { return Err(PairingStoreError::Denied); }
                        if now >= stored.expires && !stored.state.is_terminal() { stored.state = PairingState::Expired; }
                        let rows: Vec<$row> = if stored.state.is_terminal() { Vec::new() } else {
                            sqlx::query(&sql("SELECT slot_index,payload FROM pairing_slots WHERE pairing_id=? AND payload IS NOT NULL ORDER BY slot_index"))
                                .bind(id.as_bytes().as_slice()).fetch_all(&mut *tx).await?
                        };
                        let mut messages = Vec::new();
                        for row in rows { let index = usize::try_from(row.try_get::<i64,_>("slot_index")?).map_err(|_| PairingStoreError::Database)?;
                            messages.push(PairingMessageRequest { step: *PairingStep::ALL.get(index).ok_or(PairingStoreError::Database)?, payload: row.try_get("payload")? }); }
                        let receipt = stored.receipt()?;
                        let result = PairingSnapshot { context: stored.context, state: stored.state, messages, receipt };
                        result.to_json().map_err(|_| PairingStoreError::Database)?;
                        Ok(result)
                    }.await;
                    finish(tx, result, false).await
                }

                /// Append exactly the next role-specific slot, permitting exact retransmission.
                ///
                /// # Errors
                /// Rejects out-of-order/substituted slots, wrong roles, exhausted budgets, or storage failure.
                pub async fn post_pairing_message(&self, origin: &str, id: Uuid, actor: PairingActor<'_>, request: &PairingMessageRequest, source: IpAddr) -> Result<PairingMessageAck, PairingStoreError> {
                    request.validate().map_err(|_| PairingStoreError::InvalidRequest)?;
                    cleanup(self).await?;
                    let mut tx = start(self, Some(actor)).await?;
                    let mut changed = false;
                    let result = async {
                        let now = now_ms()?;
                        let stored = session(&mut tx, origin, id, now).await?;
                        if stored.authorize(actor)? != request.step.role() { return Err(PairingStoreError::Denied); }
                        let now = now_ms()?;
                        stored.live(now)?;
                        if stored.account.is_none() { return Err(PairingStoreError::Conflict); }
                        success(&mut tx, source, PairingEndpoint::Message, actor).await?;
                        let now = now_ms()?;
                        stored.live(now)?;
                        let index = i64::try_from(request.step.index()).map_err(|_| PairingStoreError::InvalidRequest)?;
                        let digest = Sha256::digest(&request.payload);
                        if request.step.index() < stored.count {
                            let payload: Vec<u8> = sqlx::query_scalar(&sql("SELECT payload FROM pairing_slots WHERE pairing_id=? AND slot_index=?"))
                                .bind(id.as_bytes().as_slice()).bind(index).fetch_one(&mut *tx).await?;
                            if payload != request.payload { return Err(PairingStoreError::Conflict); }
                        } else {
                            if request.step.index() != stored.count { return Err(PairingStoreError::Conflict); }
                            let total: i64 = sqlx::query_scalar(if $postgres { "SELECT COALESCE(SUM(payload_bytes),0)::bigint FROM pairing_sessions" } else { "SELECT COALESCE(SUM(payload_bytes),0) FROM pairing_sessions" }).fetch_one(&mut *tx).await?;
                            let size = i64::try_from(request.payload.len()).map_err(|_| PairingStoreError::InvalidRequest)?;
                            if total.checked_add(size).is_none_or(|n| n > MAX_PAYLOAD_BYTES) { return Err(PairingStoreError::ResourceLimited); }
                            sqlx::query(&sql("INSERT INTO pairing_slots (pairing_id,slot_index,payload,payload_digest) VALUES (?,?,?,?)"))
                                .bind(id.as_bytes().as_slice()).bind(index).bind(&request.payload).bind(digest.as_slice()).execute(&mut *tx).await?;
                            sqlx::query(&sql("UPDATE pairing_sessions SET slot_count=slot_count+1,payload_bytes=payload_bytes+?,state=? WHERE pairing_id=?"))
                                .bind(size).bind(if request.step == PairingStep::Acceptance { "ready" } else { "exchanging" })
                                .bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                            event(&mut tx, 3, id, now).await?;
                            changed = true;
                        }
                        let response = PairingMessageAck { step: request.step };
                        response.to_json().map_err(|_| PairingStoreError::Database)?;
                        Ok(response)
                    }.await;
                    finish(tx, result, changed).await
                }

                /// Cancel once and erase all relay payloads without extending original retention.
                ///
                /// # Errors
                /// Rejects wrong roles, already completed sessions, stale identities, or storage failure.
                pub async fn cancel_pairing(&self, origin: &str, id: Uuid, actor: PairingActor<'_>, source: IpAddr) -> Result<(), PairingStoreError> {
                    cleanup(self).await?;
                    let mut tx = start(self, Some(actor)).await?;
                    let mut changed = false;
                    let result = async {
                        let now = now_ms()?;
                        let stored = session(&mut tx, origin, id, now).await?;
                        stored.authorize(actor)?;
                        if stored.state == PairingState::Completed { return Err(PairingStoreError::Conflict); }
                        if stored.state == PairingState::Expired { return Err(PairingStoreError::Denied); }
                        success(&mut tx, source, PairingEndpoint::Cancel, actor).await?;
                        let now = now_ms()?;
                        if now >= stored.retain_until { return Err(PairingStoreError::Denied); }
                        if !stored.state.is_terminal() { stored.live(now)?; }
                        if !stored.state.is_terminal() {
                            sqlx::query(&sql("UPDATE pairing_sessions SET state='cancelled',payload_bytes=0 WHERE pairing_id=?"))
                                .bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                            sqlx::query(&sql("UPDATE pairing_slots SET payload=NULL WHERE pairing_id=?"))
                                .bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                            event(&mut tx, 5, id, now).await?;
                            changed = true;
                        }
                        Ok(())
                    }.await;
                    finish(tx, result, changed).await
                }

                /// Publish a second device, complete K-4 update, receipt, and audit atomically.
                ///
                /// # Errors
                /// Rejects stale authorization, invalid signed membership, changed encryption artifacts,
                /// response overflow, slot substitutions, or unconfirmed commit outcomes.
                #[allow(clippy::too_many_lines)]
                pub async fn complete_pairing(&self, origin: &str, id: Uuid, principal: &CurrentPrincipal, request: &PairingCompleteRequest, source: IpAddr) -> Result<PairingReceipt, PairingStoreError> {
                    request.validate().map_err(|_| PairingStoreError::InvalidRequest)?;
                    cleanup(self).await?;
                    let mut tx = start(self, Some(PairingActor::Initiator(principal))).await?;
                    let mut changed = false;
                    let result = async {
                        let now = now_ms()?;
                        let stored = session(&mut tx, origin, id, now).await?;
                        stored.authorize(PairingActor::Initiator(principal))?;
                        success(&mut tx, source, PairingEndpoint::Complete, PairingActor::Initiator(principal)).await?;
                        let now = now_ms()?;
                        if now >= stored.retain_until { return Err(PairingStoreError::Denied); }
                        let fingerprint = request.approval_fingerprint().map_err(|_| PairingStoreError::InvalidRequest)?;
                        if stored.state == PairingState::Completed {
                            if stored.fingerprint.as_deref() != Some(fingerprint.as_slice()) { return Err(PairingStoreError::Conflict); }
                            let receipt = stored.receipt()?.ok_or(PairingStoreError::Database)?;
                            receipt.to_json().map_err(|_| PairingStoreError::Database)?;
                            return Ok(receipt);
                        }
                        stored.live(now)?;
                        if stored.state != PairingState::Ready || stored.count != 7 { return Err(PairingStoreError::Conflict); }
                        let account = principal.account_id.as_slice();
                        let row: $row = sqlx::query(&sql("SELECT a.account_signing_public_key,b.revision,b.account_signing_key,b.account_kem_key,b.recovery_blob FROM identity_accounts a JOIN sync_account_key_bundles b ON a.account_id=b.account_id WHERE a.account_id=?"))
                            .bind(account).fetch_optional(&mut *tx).await?.ok_or(PairingStoreError::Database)?;
                        let key: Vec<u8> = row.try_get("account_signing_public_key")?;
                        let revision: i64 = row.try_get("revision")?;
                        let signing: Vec<u8> = row.try_get("account_signing_key")?;
                        let kem: Vec<u8> = row.try_get("account_kem_key")?;
                        let recovery: Vec<u8> = row.try_get("recovery_blob")?;
                        let mut total = 0;
                        let certs = $statements(&mut tx, account, StatementKind::Certificate, &mut total).await.map_err(PairingStoreError::from)?;
                        let revocations = $statements(&mut tx, account, StatementKind::Revocation, &mut total).await.map_err(PairingStoreError::from)?;
                        let handoff: Vec<u8> = sqlx::query_scalar(&sql("SELECT payload FROM pairing_slots WHERE pairing_id=? AND slot_index=5"))
                            .bind(id.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                        let acceptance: Vec<u8> = sqlx::query_scalar(&sql("SELECT payload FROM pairing_slots WHERE pairing_id=? AND slot_index=6"))
                            .bind(id.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                        if acceptance != request.new_device_signature { return Err(PairingStoreError::InvalidRequest); }
                        let update = verify_update(&stored, request, &key, revision, [&signing,&kem,&recovery], &certs,&revocations,&handoff)?;
                        let device = stored.context.responder_device_id.as_bytes().as_slice();
                        let exists: Option<Vec<u8>> = sqlx::query_scalar(&sql("SELECT device_id FROM identity_devices WHERE device_id=?"))
                            .bind(device).fetch_optional(&mut *tx).await?;
                        if exists.is_some() { return Err(PairingStoreError::Conflict); }
                        sqlx::query(&sql("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES (?,?,?,?,?)"))
                            .bind(device).bind(account).bind(&request.device_certificate).bind(true).bind(now).execute(&mut *tx).await?;
                        sqlx::query(&sql("INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES (?,?)"))
                            .bind(account).bind(&request.device_certificate).execute(&mut *tx).await?;
                        sqlx::query(&sql("UPDATE sync_account_key_bundles SET revision=?,signature=?,updated_at_ms=? WHERE account_id=?"))
                            .bind(i64::try_from(update.revision).map_err(|_| PairingStoreError::Conflict)?).bind(&update.signature).bind(now).bind(account).execute(&mut *tx).await?;
                        sqlx::query(&sql("DELETE FROM sync_account_key_device_wraps WHERE account_id=?")).bind(account).execute(&mut *tx).await?;
                        for wrap in &update.device_wraps {
                            sqlx::query(&sql("INSERT INTO sync_account_key_device_wraps (account_id,device_id,wrapped_ark) VALUES (?,?,?)"))
                                .bind(account).bind(wrap.device_id.as_bytes().as_slice()).bind(&wrap.wrapped_ark).execute(&mut *tx).await?;
                        }
                        $capacity(&mut tx, principal.account_id).await.map_err(|error| match error {
                            crate::account_keys::AccountKeyStoreError::KeyResponseLimit => PairingStoreError::QuotaExceeded,
                            _ => PairingStoreError::Database,
                        })?;
                        sqlx::query(&sql("UPDATE pairing_sessions SET state='completed',payload_bytes=0,approval_fingerprint=?,completed_revision=?,retain_until_ms=? WHERE pairing_id=?"))
                            .bind(fingerprint.as_slice()).bind(i64::try_from(update.revision).map_err(|_| PairingStoreError::Conflict)?)
                            .bind(now+RETENTION_MS).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                        sqlx::query(&sql("UPDATE pairing_slots SET payload=NULL WHERE pairing_id=?")).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                        event(&mut tx, 4, id, now).await?;
                        changed = true;
                        let receipt = PairingReceipt { account_id: Uuid::from_bytes(principal.account_id), device_id: stored.context.responder_device_id, revision: update.revision };
                        receipt.to_json().map_err(|_| PairingStoreError::Database)?;
                        Ok(receipt)
                    }.await;
                    finish(tx, result, changed).await
                }
            }
        }
    };
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool.begin_with("BEGIN IMMEDIATE").await
}
async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool.begin().await
}

pairing_store!(
    sqlite,
    SqliteStore,
    Sqlite,
    sqlx::sqlite::SqliteRow,
    false,
    sqlite_begin,
    sqlite_current,
    sqlite_statements,
    check_sqlite_key_response_capacity,
    append_deployment_audit_event_in_transaction,
    clear_sqlite_pairing_failure_streak
);
pairing_store!(
    postgres,
    PostgresStore,
    Postgres,
    sqlx::postgres::PgRow,
    true,
    postgres_begin,
    postgres_current,
    postgres_statements,
    check_postgres_key_response_capacity,
    append_deployment_audit_event_in_postgres_transaction,
    clear_postgres_pairing_failure_streak
);
