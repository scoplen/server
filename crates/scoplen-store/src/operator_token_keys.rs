// SPDX-License-Identifier: AGPL-3.0-only
//! Database-serialized signing keys for independent Operator access tokens.

use std::{
    fmt::{self, Write as _},
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{
    Ed25519SigningKey, OperatorAccessTokenError, OperatorAccessTokenSigner, SymmetricKey,
    XChaChaNonce, random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
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

const ROTATE_AFTER_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
const VERIFY_OVERLAP_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_BYTES: usize = 1 + 24 + 32 + 16;
const AUDIT_DOMAIN: &[u8] = b"spl-operator-token-key-v1";
const AAD_DOMAIN: &[u8] = b"spl-operator-access-token-seed\0v1\0Ed25519\0";

/// The signing boundary has failed closed; no key material appears in these messages.
#[derive(Debug, Error)]
pub enum OperatorTokenKeyError {
    #[error("operator access-token key storage unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("operator access-token key audit unavailable")]
    Audit(#[from] AuditStoreError),
    #[error("operator access-token key entropy unavailable")]
    Entropy,
    #[error("operator access-token key clock unavailable")]
    Clock,
    #[error("operator access-token keyring integrity check failed")]
    Integrity,
    #[error("operator access-token key commit outcome unknown")]
    CommitOutcomeUnknown,
}

/// One public key accepted during the active or seven-day verification interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorTokenVerificationKey {
    pub kid: String,
    pub public_key: [u8; 32],
}

/// Secret signing key and the matching trusted public key, never printed in Debug output.
pub struct OperatorTokenSigningKey {
    kid: String,
    public_key: [u8; 32],
    signing_key: Ed25519SigningKey,
}

impl fmt::Debug for OperatorTokenSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorTokenSigningKey")
            .field("kid", &self.kid)
            .field("public_key", &self.public_key)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl OperatorAccessTokenSigner for OperatorTokenSigningKey {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], OperatorAccessTokenError> {
        Ok(self.signing_key.sign(message))
    }
}

impl OperatorTokenSigningKey {
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

/// A single consistent database snapshot for signing and trusted-key verification.
pub struct OperatorTokenKeyring {
    signing_key: OperatorTokenSigningKey,
    verification_keys: Vec<OperatorTokenVerificationKey>,
}

impl fmt::Debug for OperatorTokenKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorTokenKeyring")
            .field("signing_key", &self.signing_key)
            .field("verification_keys", &self.verification_keys)
            .finish()
    }
}

impl OperatorTokenKeyring {
    #[must_use]
    pub fn signing_key(&self) -> &OperatorTokenSigningKey {
        &self.signing_key
    }

    #[must_use]
    pub fn verification_keys(&self) -> &[OperatorTokenVerificationKey] {
        &self.verification_keys
    }
}

impl SqliteStore {
    /// Load or rotate the dedicated keyring under one SQLite write lock and deployment audit.
    ///
    /// # Errors
    ///
    /// A known precommit failure returns no signing key. An unconfirmed mutation commit returns
    /// `CommitOutcomeUnknown`; callers must not issue a token from that attempt.
    pub async fn ensure_operator_token_keyring(
        &self,
        kms: &dyn KeyManagementService,
    ) -> Result<OperatorTokenKeyring, OperatorTokenKeyError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let now = now_ms()?;
        let mut rows = load_sqlite_rows(&mut transaction).await?;
        let action = action_for(&rows, now)?;
        let mut mutated = false;
        match action {
            KeyAction::Create => {
                let key = create_key(kms, now)?;
                insert_sqlite_key(&mut transaction, &key).await?;
                append_sqlite_audit(&mut transaction, 1, now, &key.kid).await?;
                rows.push(key);
                mutated = true;
            }
            KeyAction::Rotate => {
                // Validate the old key and every retained row before changing state.
                let _ = keyring_from_rows(&rows, now, kms)?;
                let old = rows
                    .iter_mut()
                    .find(|row| row.active_slot == Some(1))
                    .ok_or(OperatorTokenKeyError::Integrity)?;
                let old_kid = old.kid.clone();
                let until =
                    now.checked_add(VERIFY_OVERLAP_MS).ok_or(OperatorTokenKeyError::Clock)?;
                retire_sqlite_key(&mut transaction, &old_kid, now, until).await?;
                old.active_slot = None;
                old.retired_at_ms = Some(now);
                old.verify_until_ms = Some(until);
                let key = create_key(kms, now)?;
                insert_sqlite_key(&mut transaction, &key).await?;
                append_sqlite_audit(&mut transaction, 2, now, &key.kid).await?;
                rows.push(key);
                mutated = true;
            }
            KeyAction::Load => {}
        }
        let keyring = keyring_from_rows(&rows, now, kms)?;
        if mutated {
            transaction.commit().await.map_err(|_| OperatorTokenKeyError::CommitOutcomeUnknown)?;
        } else {
            transaction.commit().await?;
        }
        Ok(keyring)
    }
}

impl PostgresStore {
    /// Load or rotate the dedicated keyring under a PostgreSQL transaction advisory lock.
    ///
    /// # Errors
    ///
    /// Returns storage, integrity, audit, clock, entropy, or uncertain-commit failure.
    pub async fn ensure_operator_token_keyring(
        &self,
        kms: &dyn KeyManagementService,
    ) -> Result<OperatorTokenKeyring, OperatorTokenKeyError> {
        let mut transaction = self.pool().begin().await?;
        // Distinct from the deployment-audit lock; always acquire keyring before audit.
        sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1263683912)")
            .fetch_one(&mut *transaction)
            .await?;
        let now = now_ms()?;
        let mut rows = load_postgres_rows(&mut transaction).await?;
        let action = action_for(&rows, now)?;
        let mut mutated = false;
        match action {
            KeyAction::Create => {
                let key = create_key(kms, now)?;
                insert_postgres_key(&mut transaction, &key).await?;
                append_postgres_audit(&mut transaction, 1, now, &key.kid).await?;
                rows.push(key);
                mutated = true;
            }
            KeyAction::Rotate => {
                let _ = keyring_from_rows(&rows, now, kms)?;
                let old = rows
                    .iter_mut()
                    .find(|row| row.active_slot == Some(1))
                    .ok_or(OperatorTokenKeyError::Integrity)?;
                let old_kid = old.kid.clone();
                let until =
                    now.checked_add(VERIFY_OVERLAP_MS).ok_or(OperatorTokenKeyError::Clock)?;
                retire_postgres_key(&mut transaction, &old_kid, now, until).await?;
                old.active_slot = None;
                old.retired_at_ms = Some(now);
                old.verify_until_ms = Some(until);
                let key = create_key(kms, now)?;
                insert_postgres_key(&mut transaction, &key).await?;
                append_postgres_audit(&mut transaction, 2, now, &key.kid).await?;
                rows.push(key);
                mutated = true;
            }
            KeyAction::Load => {}
        }
        let keyring = keyring_from_rows(&rows, now, kms)?;
        if mutated {
            transaction.commit().await.map_err(|_| OperatorTokenKeyError::CommitOutcomeUnknown)?;
        } else {
            transaction.commit().await?;
        }
        Ok(keyring)
    }
}

#[derive(Clone)]
struct StoredKey {
    kid: String,
    public_key: Vec<u8>,
    encrypted_seed: Vec<u8>,
    activated_at_ms: i64,
    retired_at_ms: Option<i64>,
    verify_until_ms: Option<i64>,
    active_slot: Option<i64>,
}

enum KeyAction {
    Create,
    Rotate,
    Load,
}

fn action_for(rows: &[StoredKey], now: i64) -> Result<KeyAction, OperatorTokenKeyError> {
    if rows.is_empty() {
        return Ok(KeyAction::Create);
    }
    let mut active = rows.iter().filter(|row| row.active_slot == Some(1));
    let key = active.next().ok_or(OperatorTokenKeyError::Integrity)?;
    if active.next().is_some() || now < key.activated_at_ms {
        return Err(OperatorTokenKeyError::Integrity);
    }
    if now
        >= key
            .activated_at_ms
            .checked_add(ROTATE_AFTER_MS)
            .ok_or(OperatorTokenKeyError::Integrity)?
    {
        Ok(KeyAction::Rotate)
    } else {
        Ok(KeyAction::Load)
    }
}

fn keyring_from_rows(
    rows: &[StoredKey],
    now: i64,
    kms: &dyn KeyManagementService,
) -> Result<OperatorTokenKeyring, OperatorTokenKeyError> {
    if rows.is_empty() {
        return Err(OperatorTokenKeyError::Integrity);
    }
    for pair in rows.windows(2) {
        if pair[0].retired_at_ms != Some(pair[1].activated_at_ms) {
            return Err(OperatorTokenKeyError::Integrity);
        }
    }
    let mut signing_key = None;
    let mut verification_keys = Vec::with_capacity(2);
    for row in rows {
        validate_row(row)?;
        let key = decrypt_key(row, kms)?;
        if key.public_key() != row.public_key.as_slice() {
            return Err(OperatorTokenKeyError::Integrity);
        }
        if row.active_slot == Some(1) {
            if now < row.activated_at_ms || signing_key.is_some() {
                return Err(OperatorTokenKeyError::Integrity);
            }
            signing_key = Some(OperatorTokenSigningKey {
                kid: row.kid.clone(),
                public_key: key.public_key(),
                signing_key: key,
            });
            verification_keys.push(OperatorTokenVerificationKey {
                kid: row.kid.clone(),
                public_key: row
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| OperatorTokenKeyError::Integrity)?,
            });
        } else if row.retired_at_ms.is_some_and(|retired| retired > now) {
            return Err(OperatorTokenKeyError::Integrity);
        } else if row.verify_until_ms.is_some_and(|until| until > now) {
            verification_keys.push(OperatorTokenVerificationKey {
                kid: row.kid.clone(),
                public_key: row
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| OperatorTokenKeyError::Integrity)?,
            });
        }
    }
    if verification_keys.len() > 2 {
        return Err(OperatorTokenKeyError::Integrity);
    }
    verification_keys.sort_by(|left, right| left.kid.cmp(&right.kid));
    Ok(OperatorTokenKeyring {
        signing_key: signing_key.ok_or(OperatorTokenKeyError::Integrity)?,
        verification_keys,
    })
}

fn validate_row(row: &StoredKey) -> Result<(), OperatorTokenKeyError> {
    if row.kid.strip_prefix("operator-").is_none_or(|suffix| {
        suffix.len() != 32
            || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) || row.public_key.len() != 32
        || row.encrypted_seed.len() != ENVELOPE_BYTES
        || row.encrypted_seed[0] != ENVELOPE_VERSION
        || row.activated_at_ms <= 0
        || ed25519_dalek::VerifyingKey::from_bytes(
            &row.public_key.as_slice().try_into().map_err(|_| OperatorTokenKeyError::Integrity)?,
        )
        .is_err()
    {
        return Err(OperatorTokenKeyError::Integrity);
    }
    match (row.active_slot, row.retired_at_ms, row.verify_until_ms) {
        (Some(1), None, None) => Ok(()),
        (None, Some(retired), Some(until))
            if retired > row.activated_at_ms
                && retired.checked_add(VERIFY_OVERLAP_MS) == Some(until) =>
        {
            Ok(())
        }
        _ => Err(OperatorTokenKeyError::Integrity),
    }
}

fn decrypt_key(
    row: &StoredKey,
    kms: &dyn KeyManagementService,
) -> Result<Ed25519SigningKey, OperatorTokenKeyError> {
    if kms.key_encryption_key() == &[0; 32] {
        return Err(OperatorTokenKeyError::Integrity);
    }
    let kek = SymmetricKey::new(*kms.key_encryption_key());
    let nonce = XChaChaNonce::from_slice(&row.encrypted_seed[1..25])
        .ok_or(OperatorTokenKeyError::Integrity)?;
    let plaintext = Zeroizing::new(
        xchacha20poly1305_open(&kek, &nonce, &row.encrypted_seed[25..], &aad(&row.kid))
            .map_err(|_| OperatorTokenKeyError::Integrity)?,
    );
    Ed25519SigningKey::from_bytes(&plaintext).map_err(|_| OperatorTokenKeyError::Integrity)
}

fn create_key(
    kms: &dyn KeyManagementService,
    now: i64,
) -> Result<StoredKey, OperatorTokenKeyError> {
    if kms.key_encryption_key() == &[0; 32] {
        return Err(OperatorTokenKeyError::Integrity);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| OperatorTokenKeyError::Entropy)?;
    let signing_key =
        Ed25519SigningKey::from_bytes(&seed[..]).map_err(|_| OperatorTokenKeyError::Entropy)?;
    let mut id = [0_u8; 16];
    getrandom::fill(&mut id).map_err(|_| OperatorTokenKeyError::Entropy)?;
    let mut kid = String::from("operator-");
    for byte in id {
        write!(&mut kid, "{byte:02x}").map_err(|_| OperatorTokenKeyError::Integrity)?;
    }
    let nonce = random_nonce().map_err(|_| OperatorTokenKeyError::Entropy)?;
    let kek = SymmetricKey::new(*kms.key_encryption_key());
    let ciphertext = xchacha20poly1305_seal(&kek, &nonce, &seed[..], &aad(&kid))
        .map_err(|_| OperatorTokenKeyError::Integrity)?;
    let mut encrypted_seed = Vec::with_capacity(ENVELOPE_BYTES);
    encrypted_seed.push(ENVELOPE_VERSION);
    encrypted_seed.extend_from_slice(nonce.as_ref());
    encrypted_seed.extend_from_slice(&ciphertext);
    if encrypted_seed.len() != ENVELOPE_BYTES {
        return Err(OperatorTokenKeyError::Integrity);
    }
    Ok(StoredKey {
        kid,
        public_key: signing_key.public_key().to_vec(),
        encrypted_seed,
        activated_at_ms: now,
        retired_at_ms: None,
        verify_until_ms: None,
        active_slot: Some(1),
    })
}

fn aad(kid: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AAD_DOMAIN.len() + kid.len());
    bytes.extend_from_slice(AAD_DOMAIN);
    bytes.extend_from_slice(kid.as_bytes());
    bytes
}

fn now_ms() -> Result<i64, OperatorTokenKeyError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperatorTokenKeyError::Clock)?
        .as_millis();
    i64::try_from(millis).map_err(|_| OperatorTokenKeyError::Clock)
}

fn decode_row<R: Row>(row: &R) -> Result<StoredKey, OperatorTokenKeyError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(StoredKey {
        kid: row.try_get("kid")?,
        public_key: row.try_get("public_key")?,
        encrypted_seed: row.try_get("encrypted_seed")?,
        activated_at_ms: row.try_get("activated_at_ms")?,
        retired_at_ms: row.try_get("retired_at_ms")?,
        verify_until_ms: row.try_get("verify_until_ms")?,
        active_slot: row.try_get("active_slot")?,
    })
}

async fn load_sqlite_rows(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<StoredKey>, OperatorTokenKeyError> {
    let rows = sqlx::query("SELECT kid, public_key, encrypted_seed, activated_at_ms, retired_at_ms, verify_until_ms, active_slot FROM operator_access_token_keys ORDER BY activated_at_ms, kid")
        .fetch_all(&mut **transaction).await?;
    rows.iter().map(decode_row).collect()
}

async fn load_postgres_rows(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<StoredKey>, OperatorTokenKeyError> {
    let rows = sqlx::query("SELECT kid, public_key, encrypted_seed, activated_at_ms, retired_at_ms, verify_until_ms, active_slot FROM operator_access_token_keys ORDER BY activated_at_ms, kid")
        .fetch_all(&mut **transaction).await?;
    rows.iter().map(decode_row).collect()
}

async fn insert_sqlite_key(
    transaction: &mut Transaction<'_, Sqlite>,
    key: &StoredKey,
) -> Result<(), OperatorTokenKeyError> {
    sqlx::query("INSERT INTO operator_access_token_keys (kid, public_key, encrypted_seed, activated_at_ms, active_slot) VALUES (?, ?, ?, ?, 1)")
        .bind(&key.kid).bind(&key.public_key).bind(&key.encrypted_seed)
        .bind(key.activated_at_ms).execute(&mut **transaction).await?;
    Ok(())
}

async fn insert_postgres_key(
    transaction: &mut Transaction<'_, Postgres>,
    key: &StoredKey,
) -> Result<(), OperatorTokenKeyError> {
    sqlx::query("INSERT INTO operator_access_token_keys (kid, public_key, encrypted_seed, activated_at_ms, active_slot) VALUES ($1, $2, $3, $4, 1)")
        .bind(&key.kid).bind(&key.public_key).bind(&key.encrypted_seed)
        .bind(key.activated_at_ms).execute(&mut **transaction).await?;
    Ok(())
}

async fn retire_sqlite_key(
    transaction: &mut Transaction<'_, Sqlite>,
    kid: &str,
    now: i64,
    until: i64,
) -> Result<(), OperatorTokenKeyError> {
    let result = sqlx::query("UPDATE operator_access_token_keys SET active_slot = NULL, retired_at_ms = ?, verify_until_ms = ? WHERE kid = ? AND active_slot = 1")
        .bind(now).bind(until).bind(kid).execute(&mut **transaction).await?;
    if result.rows_affected() != 1 {
        return Err(OperatorTokenKeyError::Integrity);
    }
    Ok(())
}

async fn retire_postgres_key(
    transaction: &mut Transaction<'_, Postgres>,
    kid: &str,
    now: i64,
    until: i64,
) -> Result<(), OperatorTokenKeyError> {
    let result = sqlx::query("UPDATE operator_access_token_keys SET active_slot = NULL, retired_at_ms = $1, verify_until_ms = $2 WHERE kid = $3 AND active_slot = 1")
        .bind(now).bind(until).bind(kid).execute(&mut **transaction).await?;
    if result.rows_affected() != 1 {
        return Err(OperatorTokenKeyError::Integrity);
    }
    Ok(())
}

fn audit_event(class: u8, now: i64, kid: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AUDIT_DOMAIN.len() + 1 + 8 + kid.len());
    bytes.extend_from_slice(AUDIT_DOMAIN);
    bytes.push(class);
    bytes.extend_from_slice(&now.to_be_bytes());
    bytes.extend_from_slice(kid.as_bytes());
    bytes
}

async fn append_sqlite_audit(
    transaction: &mut Transaction<'_, Sqlite>,
    class: u8,
    now: i64,
    kid: &str,
) -> Result<(), OperatorTokenKeyError> {
    append_deployment_audit_event_in_transaction(transaction, &audit_event(class, now, kid), now)
        .await?;
    Ok(())
}

async fn append_postgres_audit(
    transaction: &mut Transaction<'_, Postgres>,
    class: u8,
    now: i64,
    kid: &str,
) -> Result<(), OperatorTokenKeyError> {
    append_deployment_audit_event_in_postgres_transaction(
        transaction,
        &audit_event(class, now, kid),
        now,
    )
    .await?;
    Ok(())
}
