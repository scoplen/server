// SPDX-License-Identifier: AGPL-3.0-only
//! Durable storage for the K-4 account key bundle.
//!
//! The service owns authentication, signature verification, and membership checks.  This module
//! only validates persistence bounds and performs an atomic revision compare-and-swap.  Key
//! artifacts and signed device statements are intentionally kept opaque: the server must not
//! decrypt or reinterpret them in this layer.

#![forbid(unsafe_code)]

use sqlx::{Postgres, Row, Sqlite, Transaction, postgres::PgRow};
use thiserror::Error;

use crate::{PostgresStore, RelationalStore, SqliteStore};

/// Maximum size of one opaque key artifact, as specified by K-4.
pub const MAX_KEY_ARTIFACT_BYTES: usize = 64 * 1024;
/// Maximum number of device wraps in one account bundle update.
pub const MAX_DEVICE_WRAPS: usize = 1_000;
/// Maximum encoded HTTP request or response body for account key bundles.
///
/// The protocol codec is responsible for checking the exact deterministic CBOR length.  This
/// constant is exported so the HTTP layer can apply the same boundary before decoding.
pub const MAX_KEY_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

/// A 16-byte account identifier.
pub type AccountId = [u8; 16];
/// A 16-byte device identifier.
pub type DeviceId = [u8; 16];

/// One opaque ARK wrapping for an enrolled device.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeviceWrap {
    /// Enrolled device receiving this wrapping.
    pub device_id: DeviceId,
    /// HPKE or equivalent wrapping, interpreted by the client and crypto layer.
    pub wrapped_ark: Vec<u8>,
}

/// An authenticated account key bundle update after protocol decoding.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccountKeyBundleUpdate {
    /// Positive monotonic bundle revision.
    pub revision: u64,
    /// One wrapping for every enrolled, unrevoked device.
    pub device_wraps: Vec<DeviceWrap>,
    /// ARK-encrypted account signing key.
    pub account_signing_key: Vec<u8>,
    /// ARK-encrypted account KEM key.
    pub account_kem_key: Vec<u8>,
    /// Versioned recovery-wrapped ARK blob.
    pub recovery_blob: Vec<u8>,
    /// Ed25519 signature over the canonical update bytes.
    pub signature: [u8; 64],
}

/// The current bundle returned to one authenticated device.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccountKeyBundle {
    /// Current positive bundle revision.
    pub revision: u64,
    /// Only the requesting device's ARK wrapping is returned.
    pub wrapped_ark: Vec<u8>,
    /// ARK-encrypted account signing key.
    pub account_signing_key: Vec<u8>,
    /// ARK-encrypted account KEM key.
    pub account_kem_key: Vec<u8>,
    /// Versioned recovery-wrapped ARK blob.
    pub recovery_blob: Vec<u8>,
    /// Signed device certificates sorted by opaque byte value.
    pub certificates: Vec<Vec<u8>>,
    /// Signed device revocations sorted by opaque byte value.
    pub revocations: Vec<Vec<u8>>,
}

/// Result of a bundle update.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AccountKeyBundlePut {
    /// A new revision was committed.
    Applied { revision: u64 },
    /// The exact same revision and bytes were already committed.
    Replay { revision: u64 },
}

/// Persistence failures for account key bundles.
#[derive(Debug, Error)]
pub enum AccountKeyStoreError {
    /// No bundle exists for the account, or the requested device has no wrap.  The service maps
    /// both cases to the same not-found response so one device cannot enumerate another device.
    #[error("account key bundle does not exist")]
    BundleNotFound,
    /// The requested revision is zero.
    #[error("account key bundle revision must be positive")]
    InvalidRevision,
    /// The revision cannot be represented by SQLite's signed integer column.
    #[error("account key bundle revision is exhausted")]
    RevisionExhausted,
    /// A required opaque artifact is empty.
    #[error("account key artifact is empty: {0}")]
    EmptyArtifact(&'static str),
    /// An opaque artifact exceeds the K-4 per-field bound.
    #[error("account key artifact exceeds {MAX_KEY_ARTIFACT_BYTES} bytes: {0}")]
    ArtifactTooLarge(&'static str),
    /// Device wraps must be non-empty, sorted, and unique.
    #[error("account key device wraps must be non-empty, sorted, and unique")]
    InvalidDeviceWraps,
    /// Device wraps exceed the K-4 count bound.
    #[error("account key device wraps exceed {MAX_DEVICE_WRAPS} entries")]
    DeviceWrapLimit,
    /// A mutation would make an authenticated account-key response exceed its fixed wire bound.
    #[error("account key response exceeds {MAX_KEY_BUNDLE_BYTES} bytes")]
    KeyResponseLimit,
    /// The 64-byte Ed25519 signature was not representable by the public input type.
    #[error("account key signature must contain exactly 64 bytes")]
    InvalidSignature,
    /// A revision did not follow the current revision or was not an exact replay.
    #[error("account key bundle revision conflicts with current revision {current_revision}")]
    Conflict { current_revision: u64 },
    /// A stored row violated a schema or representation invariant.
    #[error("account key storage contains invalid row data: {0}")]
    CorruptRow(&'static str),
    /// A database constraint was violated while writing a bundle.
    #[error("account key storage constraint failed: {0}")]
    Constraint(#[source] sqlx::Error),
    /// The database operation failed.
    #[error("account key database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl SqliteStore {
    /// Read the account bundle visible to one authenticated device.
    ///
    /// The device wrap lookup is deliberately scoped by `device_id`; this method never returns a
    /// different device's wrapping.  Authentication and authorization are service concerns.
    ///
    /// # Errors
    ///
    /// Returns [`AccountKeyStoreError::BundleNotFound`] when the account or device wrap is absent,
    /// [`AccountKeyStoreError::CorruptRow`] when stored values violate their invariants, or
    /// [`AccountKeyStoreError::Database`] when SQLite cannot complete the read.
    pub async fn get_account_key_bundle(
        &self,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> Result<AccountKeyBundle, AccountKeyStoreError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT revision, account_signing_key, account_kem_key, recovery_blob
             FROM sync_account_key_bundles WHERE account_id = ?",
        )
        .bind(account_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AccountKeyStoreError::BundleNotFound)?;

        let revision = revision_from_sql(row.try_get("revision")?)?;
        let account_signing_key = artifact_from_row(&row, "account_signing_key")?;
        let account_kem_key = artifact_from_row(&row, "account_kem_key")?;
        let recovery_blob = artifact_from_row(&row, "recovery_blob")?;
        let wrapped_ark = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT wrapped_ark FROM sync_account_key_device_wraps
             WHERE account_id = ? AND device_id = ?",
        )
        .bind(account_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AccountKeyStoreError::BundleNotFound)?;
        let wrapped_ark = validate_artifact(wrapped_ark, "wrapped_ark")?;

        let mut certificates = read_statements(
            &mut transaction,
            "SELECT certificate FROM sync_account_key_certificates
             WHERE account_id = ? ORDER BY certificate ASC",
            account_id,
            "certificate",
        )
        .await?;
        let mut revocations = read_statements(
            &mut transaction,
            "SELECT revocation FROM sync_account_key_revocations
             WHERE account_id = ? ORDER BY revocation ASC",
            account_id,
            "revocation",
        )
        .await?;
        // SQLite orders BLOBs bytewise, but sort again in memory to make the wire-facing
        // ordering explicit if a future backend changes the query implementation.
        certificates.sort();
        revocations.sort();
        transaction.commit().await?;

        Ok(AccountKeyBundle {
            revision,
            wrapped_ark,
            account_signing_key,
            account_kem_key,
            recovery_blob,
            certificates,
            revocations,
        })
    }

    /// Atomically apply a signed account key rotation with revision compare-and-swap semantics.
    ///
    /// Revision one creates a bundle.  Thereafter only `current + 1` is a new update; an exact
    /// byte-for-byte replay of the current revision is idempotent.  A SQLite `BEGIN IMMEDIATE`
    /// transaction serializes competing rotations before the current revision is read, so no
    /// accepted update can be lost and no partial wrap set can become visible.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid artifact or device-wrap set,
    /// [`AccountKeyStoreError::Conflict`] for a stale, skipped, or non-identical replayed
    /// revision, or [`AccountKeyStoreError::Database`] when SQLite cannot commit the update.
    pub async fn put_account_key_bundle(
        &self,
        account_id: AccountId,
        update: &AccountKeyBundleUpdate,
    ) -> Result<AccountKeyBundlePut, AccountKeyStoreError> {
        validate_update(update)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let existing = sqlx::query(
            "SELECT revision, account_signing_key, account_kem_key, recovery_blob, signature
             FROM sync_account_key_bundles WHERE account_id = ?",
        )
        .bind(account_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;

        if let Some(row) = existing {
            let current_revision = revision_from_sql(row.try_get("revision")?)?;
            if update.revision == current_revision {
                if update_matches_current(&mut transaction, account_id, update, &row).await? {
                    transaction.commit().await?;
                    return Ok(AccountKeyBundlePut::Replay { revision: current_revision });
                }
                return Err(AccountKeyStoreError::Conflict { current_revision });
            }
            let expected =
                current_revision.checked_add(1).ok_or(AccountKeyStoreError::RevisionExhausted)?;
            if update.revision != expected {
                return Err(AccountKeyStoreError::Conflict { current_revision });
            }
        } else if update.revision != 1 {
            return Err(AccountKeyStoreError::Conflict { current_revision: 0 });
        }

        let updated_at_ms = now_ms()?;
        sqlx::query(
            "INSERT INTO sync_account_key_bundles
             (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (account_id) DO UPDATE SET
               revision = excluded.revision,
               account_signing_key = excluded.account_signing_key,
               account_kem_key = excluded.account_kem_key,
               recovery_blob = excluded.recovery_blob,
               signature = excluded.signature,
               updated_at_ms = excluded.updated_at_ms",
        )
        .bind(account_id.as_slice())
        .bind(revision_to_sql(update.revision)?)
        .bind(&update.account_signing_key)
        .bind(&update.account_kem_key)
        .bind(&update.recovery_blob)
        .bind(update.signature.as_slice())
        .bind(updated_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_write_error)?;

        sqlx::query("DELETE FROM sync_account_key_device_wraps WHERE account_id = ?")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        for wrap in &update.device_wraps {
            sqlx::query(
                "INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark)
                 VALUES (?, ?, ?)",
            )
            .bind(account_id.as_slice())
            .bind(wrap.device_id.as_slice())
            .bind(&wrap.wrapped_ark)
            .execute(&mut *transaction)
            .await
            .map_err(map_write_error)?;
        }
        check_sqlite_key_response_capacity(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(AccountKeyBundlePut::Applied { revision: update.revision })
    }

    /// Replace the signed device certificate and revocation statements for one account.
    ///
    /// Enrollment and revocation services call this method after authenticating their own
    /// operation.  Entries are treated as opaque, deduplicated by the database, and returned from
    /// [`get_account_key_bundle`] in lexicographic byte order.
    ///
    /// # Errors
    ///
    /// Returns a validation error when a statement is empty or exceeds the artifact limit, or a
    /// database error when the replacement transaction cannot commit.
    pub async fn replace_account_key_statements(
        &self,
        account_id: AccountId,
        certificates: &[Vec<u8>],
        revocations: &[Vec<u8>],
    ) -> Result<(), AccountKeyStoreError> {
        validate_statements(certificates, "certificate")?;
        validate_statements(revocations, "revocation")?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("DELETE FROM sync_account_key_certificates WHERE account_id = ?")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        for certificate in certificates {
            sqlx::query(
                "INSERT OR IGNORE INTO sync_account_key_certificates (account_id, certificate)
                 VALUES (?, ?)",
            )
            .bind(account_id.as_slice())
            .bind(certificate)
            .execute(&mut *transaction)
            .await
            .map_err(map_write_error)?;
        }
        sqlx::query("DELETE FROM sync_account_key_revocations WHERE account_id = ?")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        for revocation in revocations {
            sqlx::query(
                "INSERT OR IGNORE INTO sync_account_key_revocations (account_id, revocation)
                 VALUES (?, ?)",
            )
            .bind(account_id.as_slice())
            .bind(revocation)
            .execute(&mut *transaction)
            .await
            .map_err(map_write_error)?;
        }
        check_sqlite_key_response_capacity(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(())
    }
}

impl PostgresStore {
    /// Read the account bundle visible to one authenticated device from PostgreSQL.
    ///
    /// # Errors
    ///
    /// Returns [`AccountKeyStoreError::BundleNotFound`] when the account or device wrap is absent,
    /// [`AccountKeyStoreError::CorruptRow`] when stored values violate their invariants, or
    /// [`AccountKeyStoreError::Database`] when PostgreSQL cannot complete the read.
    pub async fn get_account_key_bundle(
        &self,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> Result<AccountKeyBundle, AccountKeyStoreError> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT revision, account_signing_key, account_kem_key, recovery_blob
             FROM sync_account_key_bundles WHERE account_id = $1",
        )
        .bind(account_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AccountKeyStoreError::BundleNotFound)?;

        let revision = revision_from_sql(row.try_get("revision")?)?;
        let account_signing_key = artifact_from_postgres_row(&row, "account_signing_key")?;
        let account_kem_key = artifact_from_postgres_row(&row, "account_kem_key")?;
        let recovery_blob = artifact_from_postgres_row(&row, "recovery_blob")?;
        let wrapped_ark = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT wrapped_ark FROM sync_account_key_device_wraps
             WHERE account_id = $1 AND device_id = $2",
        )
        .bind(account_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AccountKeyStoreError::BundleNotFound)?;
        let wrapped_ark = validate_artifact(wrapped_ark, "wrapped_ark")?;

        let mut certificates = read_postgres_statements(
            &mut transaction,
            "SELECT certificate FROM sync_account_key_certificates
             WHERE account_id = $1 ORDER BY certificate ASC",
            account_id,
            "certificate",
        )
        .await?;
        let mut revocations = read_postgres_statements(
            &mut transaction,
            "SELECT revocation FROM sync_account_key_revocations
             WHERE account_id = $1 ORDER BY revocation ASC",
            account_id,
            "revocation",
        )
        .await?;
        certificates.sort();
        revocations.sort();
        transaction.commit().await?;

        Ok(AccountKeyBundle {
            revision,
            wrapped_ark,
            account_signing_key,
            account_kem_key,
            recovery_blob,
            certificates,
            revocations,
        })
    }

    /// Atomically apply a signed account key rotation with PostgreSQL revision CAS semantics.
    ///
    /// A transaction-scoped advisory lock serializes competing first writes for one account;
    /// existing rows are additionally locked with `FOR UPDATE` before their revision is checked.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid artifact or device-wrap set,
    /// [`AccountKeyStoreError::Conflict`] for a stale, skipped, or non-identical replayed
    /// revision, or [`AccountKeyStoreError::Database`] when PostgreSQL cannot commit the update.
    pub async fn put_account_key_bundle(
        &self,
        account_id: AccountId,
        update: &AccountKeyBundleUpdate,
    ) -> Result<AccountKeyBundlePut, AccountKeyStoreError> {
        validate_update(update)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        let existing = sqlx::query(
            "SELECT revision, account_signing_key, account_kem_key, recovery_blob, signature
             FROM sync_account_key_bundles WHERE account_id = $1 FOR UPDATE",
        )
        .bind(account_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;

        if let Some(row) = existing {
            let current_revision = revision_from_sql(row.try_get("revision")?)?;
            if update.revision == current_revision {
                if update_matches_current_postgres(&mut transaction, account_id, update, &row)
                    .await?
                {
                    transaction.commit().await?;
                    return Ok(AccountKeyBundlePut::Replay { revision: current_revision });
                }
                return Err(AccountKeyStoreError::Conflict { current_revision });
            }
            let expected =
                current_revision.checked_add(1).ok_or(AccountKeyStoreError::RevisionExhausted)?;
            if update.revision != expected {
                return Err(AccountKeyStoreError::Conflict { current_revision });
            }
        } else if update.revision != 1 {
            return Err(AccountKeyStoreError::Conflict { current_revision: 0 });
        }

        let updated_at_ms = now_ms()?;
        sqlx::query(
            "INSERT INTO sync_account_key_bundles
             (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (account_id) DO UPDATE SET
               revision = EXCLUDED.revision,
               account_signing_key = EXCLUDED.account_signing_key,
               account_kem_key = EXCLUDED.account_kem_key,
               recovery_blob = EXCLUDED.recovery_blob,
               signature = EXCLUDED.signature,
               updated_at_ms = EXCLUDED.updated_at_ms",
        )
        .bind(account_id.as_slice())
        .bind(revision_to_sql(update.revision)?)
        .bind(&update.account_signing_key)
        .bind(&update.account_kem_key)
        .bind(&update.recovery_blob)
        .bind(update.signature.as_slice())
        .bind(updated_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_write_error)?;

        sqlx::query("DELETE FROM sync_account_key_device_wraps WHERE account_id = $1")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        for wrap in &update.device_wraps {
            sqlx::query(
                "INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark)
                 VALUES ($1, $2, $3)",
            )
            .bind(account_id.as_slice())
            .bind(wrap.device_id.as_slice())
            .bind(&wrap.wrapped_ark)
            .execute(&mut *transaction)
            .await
            .map_err(map_write_error)?;
        }
        check_postgres_key_response_capacity(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(AccountKeyBundlePut::Applied { revision: update.revision })
    }

    /// Replace the signed device certificate and revocation statements for one account in
    /// PostgreSQL.
    ///
    /// # Errors
    ///
    /// Returns a validation error when a statement is empty or exceeds the artifact limit, or a
    /// database error when the replacement transaction cannot commit.
    pub async fn replace_account_key_statements(
        &self,
        account_id: AccountId,
        certificates: &[Vec<u8>],
        revocations: &[Vec<u8>],
    ) -> Result<(), AccountKeyStoreError> {
        validate_statements(certificates, "certificate")?;
        validate_statements(revocations, "revocation")?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM sync_account_key_certificates WHERE account_id = $1")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        for certificate in certificates {
            sqlx::query(
                "INSERT INTO sync_account_key_certificates (account_id, certificate)
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(account_id.as_slice())
            .bind(certificate)
            .execute(&mut *transaction)
            .await
            .map_err(map_write_error)?;
        }
        sqlx::query("DELETE FROM sync_account_key_revocations WHERE account_id = $1")
            .bind(account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        for revocation in revocations {
            sqlx::query(
                "INSERT INTO sync_account_key_revocations (account_id, revocation)
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(account_id.as_slice())
            .bind(revocation)
            .execute(&mut *transaction)
            .await
            .map_err(map_write_error)?;
        }
        check_postgres_key_response_capacity(&mut transaction, account_id).await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn validate_update(update: &AccountKeyBundleUpdate) -> Result<(), AccountKeyStoreError> {
    if update.revision == 0 {
        return Err(AccountKeyStoreError::InvalidRevision);
    }
    validate_artifact(update.account_signing_key.clone(), "account_signing_key")?;
    validate_artifact(update.account_kem_key.clone(), "account_kem_key")?;
    validate_artifact(update.recovery_blob.clone(), "recovery_blob")?;
    if update.device_wraps.is_empty() {
        return Err(AccountKeyStoreError::InvalidDeviceWraps);
    }
    if update.device_wraps.len() > MAX_DEVICE_WRAPS {
        return Err(AccountKeyStoreError::DeviceWrapLimit);
    }
    let mut previous = None;
    for wrap in &update.device_wraps {
        if previous.is_some_and(|previous| previous >= wrap.device_id) {
            return Err(AccountKeyStoreError::InvalidDeviceWraps);
        }
        validate_artifact(wrap.wrapped_ark.clone(), "wrapped_ark")?;
        previous = Some(wrap.device_id);
    }
    // The field type is fixed-width, but retain an explicit check at this boundary so a future
    // deserializer cannot accidentally widen the signature without updating the contract.
    if update.signature.len() != 64 {
        return Err(AccountKeyStoreError::InvalidSignature);
    }
    revision_to_sql(update.revision)?;
    Ok(())
}

fn validate_statements(
    statements: &[Vec<u8>],
    field: &'static str,
) -> Result<(), AccountKeyStoreError> {
    for statement in statements {
        validate_artifact(statement.clone(), field)?;
    }
    Ok(())
}

fn validate_artifact(bytes: Vec<u8>, field: &'static str) -> Result<Vec<u8>, AccountKeyStoreError> {
    if bytes.is_empty() {
        return Err(AccountKeyStoreError::EmptyArtifact(field));
    }
    if bytes.len() > MAX_KEY_ARTIFACT_BYTES {
        return Err(AccountKeyStoreError::ArtifactTooLarge(field));
    }
    Ok(bytes)
}

async fn update_matches_current(
    transaction: &mut Transaction<'_, Sqlite>,
    account_id: AccountId,
    update: &AccountKeyBundleUpdate,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<bool, AccountKeyStoreError> {
    let signature: Vec<u8> = row.try_get("signature")?;
    if signature != update.signature.as_slice()
        || row.try_get::<Vec<u8>, _>("account_signing_key")? != update.account_signing_key
        || row.try_get::<Vec<u8>, _>("account_kem_key")? != update.account_kem_key
        || row.try_get::<Vec<u8>, _>("recovery_blob")? != update.recovery_blob
    {
        return Ok(false);
    }
    let rows = sqlx::query(
        "SELECT device_id, wrapped_ark FROM sync_account_key_device_wraps
         WHERE account_id = ? ORDER BY device_id ASC",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != update.device_wraps.len() {
        return Ok(false);
    }
    for (row, expected) in rows.iter().zip(&update.device_wraps) {
        let device_id: Vec<u8> = row.try_get("device_id")?;
        let wrapped_ark: Vec<u8> = row.try_get("wrapped_ark")?;
        if device_id.as_slice() != expected.device_id || wrapped_ark != expected.wrapped_ark {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn update_matches_current_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: AccountId,
    update: &AccountKeyBundleUpdate,
    row: &PgRow,
) -> Result<bool, AccountKeyStoreError> {
    let signature: Vec<u8> = row.try_get("signature")?;
    if signature != update.signature.as_slice()
        || row.try_get::<Vec<u8>, _>("account_signing_key")? != update.account_signing_key
        || row.try_get::<Vec<u8>, _>("account_kem_key")? != update.account_kem_key
        || row.try_get::<Vec<u8>, _>("recovery_blob")? != update.recovery_blob
    {
        return Ok(false);
    }
    let rows = sqlx::query(
        "SELECT device_id, wrapped_ark FROM sync_account_key_device_wraps
         WHERE account_id = $1 ORDER BY device_id ASC",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != update.device_wraps.len() {
        return Ok(false);
    }
    for (row, expected) in rows.iter().zip(&update.device_wraps) {
        let device_id: Vec<u8> = row.try_get("device_id")?;
        let wrapped_ark: Vec<u8> = row.try_get("wrapped_ark")?;
        if device_id.as_slice() != expected.device_id || wrapped_ark != expected.wrapped_ark {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn read_statements(
    transaction: &mut Transaction<'_, Sqlite>,
    query: &str,
    account_id: AccountId,
    field: &'static str,
) -> Result<Vec<Vec<u8>>, AccountKeyStoreError> {
    let rows = sqlx::query(query).bind(account_id.as_slice()).fetch_all(&mut **transaction).await?;
    rows.into_iter().map(|row| validate_artifact(row.try_get(field)?, field)).collect()
}

async fn read_postgres_statements(
    transaction: &mut Transaction<'_, Postgres>,
    query: &str,
    account_id: AccountId,
    field: &'static str,
) -> Result<Vec<Vec<u8>>, AccountKeyStoreError> {
    let rows = sqlx::query(query).bind(account_id.as_slice()).fetch_all(&mut **transaction).await?;
    rows.into_iter().map(|row| validate_artifact(row.try_get(field)?, field)).collect()
}

async fn check_sqlite_key_response_capacity(
    transaction: &mut Transaction<'_, Sqlite>,
    account_id: AccountId,
) -> Result<(), AccountKeyStoreError> {
    let row = sqlx::query(
        "SELECT revision, length(account_signing_key) AS signing_len,
                length(account_kem_key) AS kem_len, length(recovery_blob) AS recovery_len
         FROM sync_account_key_bundles WHERE account_id = ?",
    )
    .bind(account_id.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else { return Ok(()) };
    let wraps = sqlx::query_scalar::<_, i64>(
        "SELECT length(wrapped_ark) FROM sync_account_key_device_wraps WHERE account_id = ?",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    let certificates = sqlx::query_scalar::<_, i64>(
        "SELECT length(certificate) FROM sync_account_key_certificates WHERE account_id = ?",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    let revocations = sqlx::query_scalar::<_, i64>(
        "SELECT length(revocation) FROM sync_account_key_revocations WHERE account_id = ?",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    check_key_response_capacity(
        revision_from_sql(row.try_get("revision")?)?,
        [row.try_get("signing_len")?, row.try_get("kem_len")?, row.try_get("recovery_len")?],
        &wraps,
        &certificates,
        &revocations,
    )
}

async fn check_postgres_key_response_capacity(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: AccountId,
) -> Result<(), AccountKeyStoreError> {
    let row = sqlx::query(
        "SELECT revision, octet_length(account_signing_key)::bigint AS signing_len,
                octet_length(account_kem_key)::bigint AS kem_len,
                octet_length(recovery_blob)::bigint AS recovery_len
         FROM sync_account_key_bundles WHERE account_id = $1",
    )
    .bind(account_id.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else { return Ok(()) };
    let wraps = sqlx::query_scalar::<_, i64>(
        "SELECT octet_length(wrapped_ark)::bigint FROM sync_account_key_device_wraps WHERE account_id = $1",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    let certificates = sqlx::query_scalar::<_, i64>(
        "SELECT octet_length(certificate)::bigint FROM sync_account_key_certificates WHERE account_id = $1",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    let revocations = sqlx::query_scalar::<_, i64>(
        "SELECT octet_length(revocation)::bigint FROM sync_account_key_revocations WHERE account_id = $1",
    )
    .bind(account_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    check_key_response_capacity(
        revision_from_sql(row.try_get("revision")?)?,
        [row.try_get("signing_len")?, row.try_get("kem_len")?, row.try_get("recovery_len")?],
        &wraps,
        &certificates,
        &revocations,
    )
}

fn check_key_response_capacity(
    revision: u64,
    keys: [i64; 3],
    wraps: &[i64],
    certificates: &[i64],
    revocations: &[i64],
) -> Result<(), AccountKeyStoreError> {
    if wraps.is_empty() {
        return Err(AccountKeyStoreError::CorruptRow("device_wraps"));
    }
    // Deterministic CBOR: one seven-entry map, its text keys, one uint, four bstrs,
    // and two arrays of bstrs. The map header and seven text keys occupy 97 bytes.
    let mut base = 97 + cbor_argument_bytes(revision);
    for (field, length) in
        ["account_signing_key", "account_kem_key", "recovery_blob"].into_iter().zip(keys)
    {
        base = base.saturating_add(cbor_bstr_bytes(stored_artifact_length(length, field)?));
    }
    for (field, lengths) in [("certificate", certificates), ("revocation", revocations)] {
        base = base.saturating_add(cbor_argument_bytes(lengths.len() as u64));
        for &length in lengths {
            base = base.saturating_add(cbor_bstr_bytes(stored_artifact_length(length, field)?));
        }
    }
    for &length in wraps {
        let size =
            base.saturating_add(cbor_bstr_bytes(stored_artifact_length(length, "wrapped_ark")?));
        if size > MAX_KEY_BUNDLE_BYTES {
            return Err(AccountKeyStoreError::KeyResponseLimit);
        }
    }
    Ok(())
}

fn stored_artifact_length(length: i64, field: &'static str) -> Result<usize, AccountKeyStoreError> {
    let length = usize::try_from(length).map_err(|_| AccountKeyStoreError::CorruptRow(field))?;
    if !(1..=MAX_KEY_ARTIFACT_BYTES).contains(&length) {
        return Err(AccountKeyStoreError::CorruptRow(field));
    }
    Ok(length)
}

fn cbor_bstr_bytes(length: usize) -> usize {
    cbor_argument_bytes(length as u64) + length
}

fn cbor_argument_bytes(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

fn artifact_from_row(
    row: &sqlx::sqlite::SqliteRow,
    field: &'static str,
) -> Result<Vec<u8>, AccountKeyStoreError> {
    validate_artifact(row.try_get(field)?, field)
}

fn artifact_from_postgres_row(
    row: &PgRow,
    field: &'static str,
) -> Result<Vec<u8>, AccountKeyStoreError> {
    validate_artifact(row.try_get(field)?, field)
}

fn map_write_error(error: sqlx::Error) -> AccountKeyStoreError {
    match error {
        sqlx::Error::Database(_) => AccountKeyStoreError::Constraint(error),
        other => AccountKeyStoreError::Database(other),
    }
}

fn revision_from_sql(value: i64) -> Result<u64, AccountKeyStoreError> {
    if value <= 0 {
        return Err(AccountKeyStoreError::CorruptRow("revision"));
    }
    u64::try_from(value).map_err(|_| AccountKeyStoreError::CorruptRow("revision"))
}

fn revision_to_sql(value: u64) -> Result<i64, AccountKeyStoreError> {
    i64::try_from(value).map_err(|_| AccountKeyStoreError::RevisionExhausted)
}

fn now_ms() -> Result<i64, AccountKeyStoreError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AccountKeyStoreError::CorruptRow("system time"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| AccountKeyStoreError::RevisionExhausted)
}
