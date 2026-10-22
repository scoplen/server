// SPDX-License-Identifier: AGPL-3.0-only
//! Durable first-operator entitlement and atomic, audited `WebAuthn` registration.

use std::{
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_identity::operator_passkeys::{OperatorPasskeyVerifier, PasskeyError};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    audit::AuditStoreError,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
    operator_admission::{OperatorAdmissionError, OperatorAuthEndpoint, OperatorPrivateBucket},
};

#[derive(Debug, Error)]
pub enum OperatorSetupError {
    #[error("operator setup admission unavailable")]
    Admission(#[from] OperatorAdmissionError),
    #[error("operator setup authentication denied")]
    Denied { consumed: bool },
    #[error("operator setup proof key does not match")]
    WrongKey,
    #[error("operator setup input is invalid")]
    InvalidRequest,
    #[error("server.public_host must be a DNS name with valid HTTPS for operator setup")]
    Configuration,
    #[error("operator setup storage unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("operator setup audit unavailable")]
    Audit(#[from] AuditStoreError),
    #[error("operator setup stored state integrity failed")]
    Integrity,
    #[error("operator setup entropy unavailable")]
    Entropy,
    #[error("operator setup clock unavailable")]
    Clock,
    #[error("operator setup commit outcome unknown")]
    CommitOutcomeUnknown,
}

/// A secret disclosed only to the initializer after a confirmed durable commit.
pub struct SetupDisclosure {
    token: Zeroizing<[u8; 32]>,
    origin: String,
}

impl fmt::Debug for SetupDisclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SetupDisclosure([REDACTED])")
    }
}

impl SetupDisclosure {
    /// Explicit local installer output; never pass the result to tracing or write it to a file.
    #[must_use]
    pub fn expose_link(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{}/setup#token={}",
            self.origin,
            URL_SAFE_NO_PAD.encode(self.token.as_slice())
        ))
    }
}

/// Public options paired with durable server-only state. No bearer token is retained here.
pub struct OperatorSetupOptions {
    pub ceremony_id: Uuid,
    pub expires_at_s: i64,
    pub public_key: Value,
}

impl fmt::Debug for OperatorSetupOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorSetupOptions([REDACTED])")
    }
}

/// Structurally decoded transport artifacts. Embedded `WebAuthn` validation occurs after binding.
pub struct OperatorRegistration<'a> {
    pub source: IpAddr,
    pub setup_token: &'a [u8; 32],
    pub ceremony_id: Uuid,
    pub browser_jkt: &'a str,
    pub credential_id: &'a [u8],
    pub client_data_json: &'a [u8],
    pub attestation_object: &'a [u8],
}

fn now_s() -> Result<i64, OperatorSetupError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperatorSetupError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| OperatorSetupError::Clock)
}

fn jkt_valid(jkt: &str) -> bool {
    jkt.len() == 43
        && URL_SAFE_NO_PAD
            .decode(jkt)
            .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == jkt)
}

fn audit(action: u8, now: i64, operator: Option<Uuid>) -> Vec<u8> {
    // Bounded binary audit carries only event kind, trusted time and a server-created identity.
    let mut event = b"spl-operator-setup-v1".to_vec();
    event.push(action);
    event.extend_from_slice(&now.to_be_bytes());
    if let Some(id) = operator {
        event.extend_from_slice(id.as_bytes());
    }
    event
}

fn audit_time(now: i64) -> Result<i64, OperatorSetupError> {
    now.checked_mul(1_000).ok_or(OperatorSetupError::Clock)
}

macro_rules! setup_store {
    ($store:ty, $db:ty, $begin:expr, $lock:expr, $append:path, $admission_lock:path, $outcome:path) => {
        impl $store {
            /// Initialize once, or explicitly replace an uncompleted local entitlement.
            ///
            /// Call `reissue` only from the server-host CLI after loading its configured KMS.
            /// API startup uses false; worker/edge startup never calls this method.
            ///
            /// # Errors
            /// Completed setup can never be reissued. Unknown commit outcomes disclose no secret.
            pub async fn initialize_operator_setup(&self, origin: &str, reissue: bool) -> Result<Option<SetupDisclosure>, OperatorSetupError> {
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let row = sqlx::query::<$db>("SELECT completed_at_s, trusted_origin FROM operator_setup WHERE singleton = 1").fetch_optional(&mut *tx).await?;
                if let Some(row) = row {
                    let complete: Option<i64> = row.try_get("completed_at_s")?;
                    if complete.is_some() {
                        if reissue { return Err(OperatorSetupError::Denied { consumed: false }); }
                        tx.commit().await?;
                        return Ok(None);
                    }
                    OperatorPasskeyVerifier::new(origin).map_err(|_| OperatorSetupError::Configuration)?;
                    if !reissue {
                        if row.try_get::<String,_>("trusted_origin")? != origin { return Err(OperatorSetupError::Configuration); }
                        tx.commit().await?;
                        return Ok(None);
                    }
                }
                OperatorPasskeyVerifier::new(origin).map_err(|_| OperatorSetupError::Configuration)?;
                let now = now_s()?;
                let expiry = now.checked_add(3_600).ok_or(OperatorSetupError::Clock)?;
                let mut token = Zeroizing::new([0_u8;32]);
                getrandom::fill(token.as_mut()).map_err(|_| OperatorSetupError::Entropy)?;
                let digest: [u8;32] = Sha256::digest(token.as_slice()).into();
                sqlx::query::<$db>("INSERT INTO operator_setup (singleton, token_digest, trusted_origin, issued_at_s, expires_at_s) VALUES (1, $1, $2, $3, $4)
                    ON CONFLICT (singleton) DO UPDATE SET token_digest = excluded.token_digest, trusted_origin = excluded.trusted_origin, issued_at_s = excluded.issued_at_s, expires_at_s = excluded.expires_at_s")
                    .bind(digest.as_slice()).bind(origin).bind(now).bind(expiry).execute(&mut *tx).await?;
                sqlx::query::<$db>("DELETE FROM operator_ceremonies WHERE purpose = 1 AND consumed_at_s IS NULL").execute(&mut *tx).await?;
                $append(&mut tx, &audit(if reissue {2} else {1}, now, None), audit_time(now)?).await?;
                tx.commit().await.map_err(|_| OperatorSetupError::CommitOutcomeUnknown)?;
                Ok(Some(SetupDisclosure { token, origin: origin.to_owned() }))
            }

            /// Persist registration state without consuming its setup entitlement.
            /// The caller verifies and durably claims `DPoP` before supplying this JKT.
            ///
            /// # Errors
            /// Missing/expired/completed entitlement has one uniform denial. Options-only commit
            /// failures do not claim a business-state mutation and may request fresh options.
            pub async fn operator_setup_options(&self, token: &[u8;32], browser_jkt: &str, verifier: &OperatorPasskeyVerifier) -> Result<OperatorSetupOptions, OperatorSetupError> {
                if !jkt_valid(browser_jkt) { return Err(OperatorSetupError::InvalidRequest); }
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_s()?;
                let digest: [u8;32] = Sha256::digest(token).into();
                let entitlement = sqlx::query::<$db>("SELECT expires_at_s FROM operator_setup WHERE singleton = 1 AND token_digest = $1 AND trusted_origin = $2 AND completed_at_s IS NULL AND expires_at_s > $3")
                    .bind(digest.as_slice()).bind(verifier.origin()).bind(now).fetch_optional(&mut *tx).await?;
                let Some(entitlement) = entitlement else { return Err(OperatorSetupError::Denied { consumed: false }); };
                let expires_at_s = entitlement.try_get::<i64,_>("expires_at_s")?.min(now.checked_add(300).ok_or(OperatorSetupError::Clock)?);
                let operator_id = Uuid::now_v7();
                let options = verifier.registration_options(operator_id, u32::try_from(expires_at_s-now).map_err(|_| OperatorSetupError::Integrity)?).map_err(|_| OperatorSetupError::Integrity)?;
                let ceremony_id = Uuid::now_v7();
                sqlx::query::<$db>("DELETE FROM operator_ceremonies WHERE ceremony_id IN (SELECT ceremony_id FROM operator_ceremonies WHERE expires_at_s <= $1 ORDER BY expires_at_s LIMIT 128)").bind(now).execute(&mut *tx).await?;
                sqlx::query::<$db>("INSERT INTO operator_ceremonies (ceremony_id, purpose, operator_id, setup_digest, browser_jkt, trusted_origin, rp_id, issued_at_s, expires_at_s, state_version, library_state) VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, 1, $9)")
                    .bind(ceremony_id.as_bytes().as_slice()).bind(operator_id.as_bytes().as_slice()).bind(digest.as_slice()).bind(browser_jkt).bind(verifier.origin()).bind(verifier.rp_id()).bind(now).bind(expires_at_s).bind(&options.state).execute(&mut *tx).await?;
                $append(&mut tx, &audit(5, now, None), audit_time(now)?).await?;
                tx.commit().await?;
                Ok(OperatorSetupOptions { ceremony_id, expires_at_s, public_key: options.public_key })
            }

            /// Consume one live bound ceremony, verify the passkey and atomically create the first
            /// operator with its credential, permanent setup completion and deployment audit.
            ///
            /// # Errors
            /// A malformed embedded `WebAuthn` response consumes only the ceremony with denial
            /// audit; the entitlement survives. A wrong proof key cannot consume either.
            #[allow(clippy::too_many_lines)]
            pub async fn finish_operator_setup(&self, input: &OperatorRegistration<'_>, verifier: &OperatorPasskeyVerifier) -> Result<Uuid, OperatorSetupError> {
                if input.ceremony_id.get_version_num() != 7 || !jkt_valid(input.browser_jkt)
                    || !(1..=1_023).contains(&input.credential_id.len()) || !(1..=4_096).contains(&input.client_data_json.len())
                    || !(1..=16_384).contains(&input.attestation_object.len()) { return Err(OperatorSetupError::InvalidRequest); }
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                $admission_lock(&mut tx).await?;
                let now = now_s()?;
                let digest: [u8;32] = Sha256::digest(input.setup_token).into();
                let entitlement = sqlx::query::<$db>("SELECT singleton FROM operator_setup WHERE singleton = 1 AND token_digest = $1 AND trusted_origin = $2 AND completed_at_s IS NULL AND expires_at_s > $3")
                    .bind(digest.as_slice()).bind(verifier.origin()).bind(now).fetch_optional(&mut *tx).await?;
                if entitlement.is_none() { return Err(OperatorSetupError::Denied { consumed: false }); }
                let row = sqlx::query::<$db>("SELECT operator_id, browser_jkt, state_version, library_state FROM operator_ceremonies WHERE ceremony_id = $1 AND purpose = 1 AND setup_digest = $2 AND trusted_origin = $3 AND rp_id = $4 AND expires_at_s > $5 AND consumed_at_s IS NULL")
                    .bind(input.ceremony_id.as_bytes().as_slice()).bind(digest.as_slice()).bind(verifier.origin()).bind(verifier.rp_id()).bind(now).fetch_optional(&mut *tx).await?;
                let Some(row) = row else { return Err(OperatorSetupError::Denied { consumed: false }); };
                if row.try_get::<String,_>("browser_jkt")? != input.browser_jkt { return Err(OperatorSetupError::WrongKey); }
                if row.try_get::<i64,_>("state_version")? != 1 { return Err(OperatorSetupError::Integrity); }
                let operator_bytes: Vec<u8> = row.try_get("operator_id")?;
                let operator_id = Uuid::from_slice(&operator_bytes).map_err(|_| OperatorSetupError::Integrity)?;
                if operator_id.get_version_num() != 7 { return Err(OperatorSetupError::Integrity); }
                let state: Vec<u8> = row.try_get("library_state")?;
                let verified = verifier.verify_registration(&state, input.credential_id, input.client_data_json, input.attestation_object);
                let verified = match verified {
                    Ok(value) => Some(value),
                    Err(PasskeyError::Denied) => None,
                    Err(_) => return Err(OperatorSetupError::Integrity),
                };
                let duplicate = sqlx::query::<$db>("SELECT credential_id FROM operator_credentials WHERE credential_id = $1")
                    .bind(input.credential_id).fetch_optional(&mut *tx).await?.is_some();
                sqlx::query::<$db>("UPDATE operator_ceremonies SET consumed_at_s = $1 WHERE ceremony_id = $2")
                    .bind(now).bind(input.ceremony_id.as_bytes().as_slice()).execute(&mut *tx).await?;
                if let Some(verified) = verified.filter(|_| !duplicate) {
                    let credential = verified.to_storage(verifier).map_err(|_| OperatorSetupError::Integrity)?;
                    sqlx::query::<$db>("INSERT INTO deployment_operators (operator_id, active, created_at_s) VALUES ($1, 1, $2)")
                        .bind(operator_id.as_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                    sqlx::query::<$db>("INSERT INTO operator_credentials (credential_id, operator_id, user_handle, trusted_origin, rp_id, credential_version, credential_state, active, created_at_s) VALUES ($1, $2, $2, $3, $4, 1, $5, 1, $6)")
                        .bind(verified.credential_id()).bind(operator_id.as_bytes().as_slice()).bind(verifier.origin()).bind(verifier.rp_id()).bind(credential).bind(now).execute(&mut *tx).await?;
                    sqlx::query::<$db>("UPDATE operator_setup SET completed_at_s = $1 WHERE singleton = 1").bind(now).execute(&mut *tx).await?;
                    sqlx::query::<$db>("UPDATE operator_ceremonies SET consumed_at_s = $1 WHERE purpose = 1 AND consumed_at_s IS NULL").bind(now).execute(&mut *tx).await?;
                    $outcome(&mut tx, OperatorAuthEndpoint::SetupFinish, input.source, Some(OperatorPrivateBucket::SetupDigest(&digest)), true).await?;
                    $append(&mut tx, &audit(3, now, Some(operator_id)), audit_time(now)?).await?;
                    tx.commit().await.map_err(|_| OperatorSetupError::CommitOutcomeUnknown)?;
                    Ok(operator_id)
                } else {
                    $outcome(&mut tx, OperatorAuthEndpoint::SetupFinish, input.source, Some(OperatorPrivateBucket::SetupDigest(&digest)), false).await?;
                    $append(&mut tx, &audit(4, now, None), audit_time(now)?).await?;
                    tx.commit().await.map_err(|_| OperatorSetupError::CommitOutcomeUnknown)?;
                    Err(OperatorSetupError::Denied { consumed: true })
                }
            }
        }
    }
}

async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
fn sqlite_lock(
    _: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> std::future::Ready<Result<(), sqlx::Error>> {
    std::future::ready(Ok(()))
}
async fn postgres_begin(
    store: &PostgresStore,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    store.pool().begin().await
}
async fn postgres_lock(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<(), sqlx::Error> {
    // Dedicated setup serialization precedes deployment-audit locking on every path.
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1330660690)").execute(&mut **tx).await?;
    Ok(())
}

setup_store!(
    SqliteStore,
    sqlx::Sqlite,
    sqlite_begin,
    sqlite_lock,
    append_deployment_audit_event_in_transaction,
    crate::operator_admission::sqlite_lock,
    crate::operator_admission::sqlite_outcome
);
setup_store!(
    PostgresStore,
    sqlx::Postgres,
    postgres_begin,
    postgres_lock,
    append_deployment_audit_event_in_postgres_transaction,
    crate::operator_admission::postgres_lock,
    crate::operator_admission::postgres_outcome
);
