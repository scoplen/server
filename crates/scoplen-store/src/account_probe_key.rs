// SPDX-License-Identifier: AGPL-3.0-only
//! Independent deployment key for Account password probes, with no automatic replacement.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{
    SymmetricKey, XChaChaNonce, random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    audit::AuditStoreError,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
    kms::KeyManagementService,
};

const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_BYTES: usize = 73;
const AAD_DOMAIN: &[u8] = b"spl-account-password-probe-key\0v1\0";
const AUDIT_DOMAIN: &[u8] = b"spl-account-password-probe-key-v1";
const READ: &str =
    "SELECT encrypted_key, created_at_ms FROM account_password_probe_key WHERE singleton=1";

/// A zeroizing deployment secret, independent of Account credentials and token/audit keys.
pub struct AccountProbeKey(Zeroizing<[u8; 32]>);

impl AccountProbeKey {
    /// Borrow the secret for the shared synthetic-credential and username-bucket derivations.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AccountProbeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountProbeKey([REDACTED])")
    }
}

/// Probe-key failure, with no key material in diagnostics.
#[derive(Debug, Error)]
pub enum AccountProbeKeyError {
    #[error("Account password probe-key storage unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("Account password probe-key audit unavailable")]
    Audit(#[from] AuditStoreError),
    #[error("Account password probe-key integrity check failed")]
    Integrity,
    #[error("Account password probe-key entropy unavailable")]
    Entropy,
    #[error("Account password probe-key clock unavailable")]
    Clock,
    #[error("Account password probe-key commit outcome is unknown")]
    CommitOutcomeUnknown,
}

struct StoredProbeKey {
    encrypted_key: Vec<u8>,
    created_at_ms: i64,
}

fn stored_key(
    encrypted_key: Option<Vec<u8>>,
    created_at_ms: Option<i64>,
) -> Result<Option<StoredProbeKey>, AccountProbeKeyError> {
    match (encrypted_key, created_at_ms) {
        (None, None) => Ok(None),
        (Some(encrypted_key), Some(created_at_ms))
            if encrypted_key.len() == ENVELOPE_BYTES
                && encrypted_key[0] == ENVELOPE_VERSION
                && created_at_ms > 0 =>
        {
            Ok(Some(StoredProbeKey { encrypted_key, created_at_ms }))
        }
        _ => Err(AccountProbeKeyError::Integrity),
    }
}

fn aad(created_at_ms: i64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AAD_DOMAIN.len() + 8);
    bytes.extend_from_slice(AAD_DOMAIN);
    bytes.extend_from_slice(&created_at_ms.to_be_bytes());
    bytes
}

fn open(
    key: &StoredProbeKey,
    kms: &dyn KeyManagementService,
) -> Result<AccountProbeKey, AccountProbeKeyError> {
    if kms.key_encryption_key() == &[0; 32] {
        return Err(AccountProbeKeyError::Integrity);
    }
    let nonce = XChaChaNonce::from_slice(&key.encrypted_key[1..25])
        .ok_or(AccountProbeKeyError::Integrity)?;
    let kek = SymmetricKey::new(*kms.key_encryption_key());
    let plaintext = Zeroizing::new(
        xchacha20poly1305_open(&kek, &nonce, &key.encrypted_key[25..], &aad(key.created_at_ms))
            .map_err(|_| AccountProbeKeyError::Integrity)?,
    );
    if plaintext.len() != 32 {
        return Err(AccountProbeKeyError::Integrity);
    }
    let mut key = AccountProbeKey(Zeroizing::new([0; 32]));
    key.0.copy_from_slice(&plaintext);
    if key.as_bytes() == &[0; 32] {
        return Err(AccountProbeKeyError::Integrity);
    }
    Ok(key)
}

fn seal(
    key: &AccountProbeKey,
    created_at_ms: i64,
    kms: &dyn KeyManagementService,
) -> Result<StoredProbeKey, AccountProbeKeyError> {
    if kms.key_encryption_key() == &[0; 32] {
        return Err(AccountProbeKeyError::Integrity);
    }
    let kek = SymmetricKey::new(*kms.key_encryption_key());
    let nonce = random_nonce().map_err(|_| AccountProbeKeyError::Entropy)?;
    let ciphertext = xchacha20poly1305_seal(&kek, &nonce, key.as_bytes(), &aad(created_at_ms))
        .map_err(|_| AccountProbeKeyError::Integrity)?;
    let mut encrypted_key = Vec::with_capacity(ENVELOPE_BYTES);
    encrypted_key.push(ENVELOPE_VERSION);
    encrypted_key.extend_from_slice(nonce.as_ref());
    encrypted_key.extend_from_slice(&ciphertext);
    if encrypted_key.len() != ENVELOPE_BYTES {
        return Err(AccountProbeKeyError::Integrity);
    }
    Ok(StoredProbeKey { encrypted_key, created_at_ms })
}

fn now_ms() -> Result<i64, AccountProbeKeyError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AccountProbeKeyError::Clock)?
        .as_millis();
    i64::try_from(millis).ok().filter(|time| *time > 0).ok_or(AccountProbeKeyError::Clock)
}

fn audit_event(class: u8, now: i64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AUDIT_DOMAIN.len() + 9);
    bytes.extend_from_slice(AUDIT_DOMAIN);
    bytes.push(class);
    bytes.extend_from_slice(&now.to_be_bytes());
    bytes
}

async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<Transaction<'_, Sqlite>, AccountProbeKeyError> {
    Ok(store.pool().begin_with("BEGIN IMMEDIATE").await?)
}

async fn postgres_begin(
    store: &PostgresStore,
) -> Result<Transaction<'_, Postgres>, AccountProbeKeyError> {
    let mut transaction = store.pool().begin().await?;
    // Acquire the independent probe-key lock before the deployment-audit lock.
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1095782475)")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

macro_rules! probe_key_store {
    ($store:ty, $begin:ident, $write:literal, $append:ident) => {
        impl $store {
            /// Read the retained deployment probe key without creating or replacing it.
            ///
            /// # Errors
            /// Missing initialization, corrupt ciphertext or a wrong KMS key fails closed.
            pub async fn read_account_probe_key(
                &self,
                kms: &dyn KeyManagementService,
            ) -> Result<AccountProbeKey, AccountProbeKeyError> {
                let row = sqlx::query(READ)
                    .fetch_optional(self.pool())
                    .await?
                    .ok_or(AccountProbeKeyError::Integrity)?;
                let stored =
                    stored_key(row.try_get("encrypted_key")?, row.try_get("created_at_ms")?)?
                        .ok_or(AccountProbeKeyError::Integrity)?;
                open(&stored, kms)
            }

            /// Load or initialize the independently random Kprobe under a database lock.
            ///
            /// Initialization and its deployment audit commit together. No key is returned
            /// after an unconfirmed commit. Existing ciphertext is never silently replaced.
            ///
            /// # Errors
            /// Returns storage, integrity, entropy, clock, audit or uncertain-commit failure.
            pub async fn ensure_account_probe_key(
                &self,
                kms: &dyn KeyManagementService,
            ) -> Result<AccountProbeKey, AccountProbeKeyError> {
                let mut transaction = $begin(self).await?;
                let row = sqlx::query(READ)
                    .fetch_optional(&mut *transaction)
                    .await?
                    .ok_or(AccountProbeKeyError::Integrity)?;
                let stored =
                    stored_key(row.try_get("encrypted_key")?, row.try_get("created_at_ms")?)?;
                let initialized = stored.is_none();
                let key = if let Some(stored) = stored {
                    open(&stored, kms)?
                } else {
                    let now = now_ms()?;
                    let mut key = AccountProbeKey(Zeroizing::new([0; 32]));
                    getrandom::fill(&mut *key.0).map_err(|_| AccountProbeKeyError::Entropy)?;
                    if key.as_bytes() == &[0; 32] {
                        return Err(AccountProbeKeyError::Entropy);
                    }
                    let stored = seal(&key, now, kms)?;
                    let result = sqlx::query($write)
                        .bind(&stored.encrypted_key)
                        .bind(stored.created_at_ms)
                        .execute(&mut *transaction)
                        .await?;
                    if result.rows_affected() != 1 {
                        return Err(AccountProbeKeyError::Integrity);
                    }
                    $append(&mut transaction, &audit_event(1, now), now).await?;
                    key
                };
                transaction.commit().await.map_err(|error| {
                    if initialized {
                        AccountProbeKeyError::CommitOutcomeUnknown
                    } else {
                        AccountProbeKeyError::Storage(error)
                    }
                })?;
                Ok(key)
            }

            /// Rewrap the existing Kprobe without changing its value or resetting any debt.
            ///
            /// This only changes KMS protection. Replacing Kprobe itself needs the separately
            /// coordinated D-128 quiet maintenance transition and is not exposed here.
            ///
            /// # Errors
            /// Returns storage, integrity, entropy, clock, audit or uncertain-commit failure.
            pub async fn rewrap_account_probe_key(
                &self,
                current_kms: &dyn KeyManagementService,
                replacement_kms: &dyn KeyManagementService,
            ) -> Result<(), AccountProbeKeyError> {
                let mut transaction = $begin(self).await?;
                let row = sqlx::query(READ)
                    .fetch_optional(&mut *transaction)
                    .await?
                    .ok_or(AccountProbeKeyError::Integrity)?;
                let stored =
                    stored_key(row.try_get("encrypted_key")?, row.try_get("created_at_ms")?)?
                        .ok_or(AccountProbeKeyError::Integrity)?;
                let key = open(&stored, current_kms)?;
                let replacement = seal(&key, stored.created_at_ms, replacement_kms)?;
                let now = now_ms()?;
                let result = sqlx::query($write)
                    .bind(&replacement.encrypted_key)
                    .bind(replacement.created_at_ms)
                    .execute(&mut *transaction)
                    .await?;
                if result.rows_affected() != 1 {
                    return Err(AccountProbeKeyError::Integrity);
                }
                $append(&mut transaction, &audit_event(2, now), now).await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| AccountProbeKeyError::CommitOutcomeUnknown)?;
                Ok(())
            }
        }
    };
}

probe_key_store!(
    SqliteStore,
    sqlite_begin,
    "UPDATE account_password_probe_key SET encrypted_key=?, created_at_ms=? WHERE singleton=1",
    append_deployment_audit_event_in_transaction
);
probe_key_store!(
    PostgresStore,
    postgres_begin,
    "UPDATE account_password_probe_key SET encrypted_key=$1, created_at_ms=$2 WHERE singleton=1",
    append_deployment_audit_event_in_postgres_transaction
);
