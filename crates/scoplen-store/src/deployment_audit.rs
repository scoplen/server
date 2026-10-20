// SPDX-License-Identifier: AGPL-3.0-only
//! Durable audit chain for events with no organization.

use futures_util::TryStreamExt;
use scoplen_audit::{
    AuditError, CHECKPOINT_SIGNATURE_BYTES, HASH_BYTES, deployment_checkpoint_payload, event_hash,
    validate_event,
};
use sqlx::{Postgres, Row, Sqlite, Transaction};

use crate::{PostgresStore, RelationalStore, SqliteStore, audit::AuditStoreError};

const CHECKPOINT_INTERVAL_MS: i64 = 60 * 60 * 1000;

/// The committed position of one deployment event. Event contents are intentionally omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentAuditEvent {
    /// One-based, gap-free sequence.
    pub sequence: u64,
    /// Hash preceding this event.
    pub previous_hash: [u8; HASH_BYTES],
    /// Hash of the previous hash and canonical event bytes.
    pub event_hash: [u8; HASH_BYTES],
    /// Creation time in Unix milliseconds.
    pub created_at_ms: i64,
}

/// Current head of the independent deployment chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentAuditChainHead {
    /// One-based sequence of the head event.
    pub sequence: u64,
    /// Hash at `sequence`.
    pub head_hash: [u8; HASH_BYTES],
}

/// Signed deployment chain checkpoint. The signing key is never held by this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentAuditCheckpoint {
    /// Chain sequence covered by this checkpoint.
    pub sequence: u64,
    /// Hash at `sequence`.
    pub head_hash: [u8; HASH_BYTES],
    /// Signature over the domain-separated deployment checkpoint payload.
    pub signature: [u8; CHECKPOINT_SIGNATURE_BYTES],
    /// Signature time in Unix milliseconds.
    pub signed_at_ms: i64,
}

impl SqliteStore {
    /// Append a deployment event in its own transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] for an invalid event, time, or database failure.
    pub async fn append_deployment_audit_event(
        &self,
        event_bytes: &[u8],
        created_at_ms: i64,
    ) -> Result<DeploymentAuditEvent, AuditStoreError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let event = append_deployment_audit_event_in_transaction(
            &mut transaction,
            event_bytes,
            created_at_ms,
        )
        .await?;
        transaction.commit().await?;
        Ok(event)
    }

    /// Return the current deployment head, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] for an invalid stored row or database failure.
    pub async fn deployment_audit_head(
        &self,
    ) -> Result<Option<DeploymentAuditChainHead>, AuditStoreError> {
        let row = sqlx::query(
            "SELECT sequence, event_hash FROM deployment_audit_events ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok(DeploymentAuditChainHead {
                sequence: sql_to_u64(row.try_get("sequence")?)?,
                head_hash: fixed_bytes(&row.try_get::<Vec<u8>, _>("event_hash")?)?,
            })
        })
        .transpose()
    }

    /// Verify a consistent committed prefix with bounded memory and return its head.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError::CorruptChain`] for a gap or changed stored field.
    pub async fn verify_deployment_audit_chain(
        &self,
    ) -> Result<Option<DeploymentAuditChainHead>, AuditStoreError> {
        let mut transaction = self.pool().begin().await?;
        let mut rows = sqlx::query(
            "SELECT sequence, previous_hash, event_bytes, event_hash
             FROM deployment_audit_events ORDER BY sequence ASC",
        )
        .fetch(&mut *transaction);
        let mut head = None;
        while let Some(row) = rows.try_next().await? {
            verify_row(&row, &mut head)?;
        }
        drop(rows);
        transaction.commit().await?;
        Ok(head)
    }

    /// Read the newest deployment checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] for an invalid stored row or database failure.
    pub async fn latest_deployment_audit_checkpoint(
        &self,
    ) -> Result<Option<DeploymentAuditCheckpoint>, AuditStoreError> {
        let row = sqlx::query(
            "SELECT sequence, head_hash, signature, signed_at_ms
             FROM deployment_audit_checkpoints ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| checkpoint_from_row(&row)).transpose()
    }

    /// Persist a deployment checkpoint in its own transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] when it does not cover a stored prefix, is deferred, conflicts,
    /// or storage fails.
    pub async fn write_deployment_audit_checkpoint(
        &self,
        checkpoint: &DeploymentAuditCheckpoint,
    ) -> Result<(), AuditStoreError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        write_deployment_audit_checkpoint_in_transaction(&mut transaction, checkpoint).await?;
        transaction.commit().await?;
        Ok(())
    }
}

impl PostgresStore {
    /// Append a deployment event in its own PostgreSQL transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] for an invalid event, time, or database failure.
    pub async fn append_deployment_audit_event(
        &self,
        event_bytes: &[u8],
        created_at_ms: i64,
    ) -> Result<DeploymentAuditEvent, AuditStoreError> {
        let mut transaction = self.pool().begin().await?;
        let event = append_deployment_audit_event_in_postgres_transaction(
            &mut transaction,
            event_bytes,
            created_at_ms,
        )
        .await?;
        transaction.commit().await?;
        Ok(event)
    }

    /// Return the current deployment head, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] for an invalid stored row or database failure.
    pub async fn deployment_audit_head(
        &self,
    ) -> Result<Option<DeploymentAuditChainHead>, AuditStoreError> {
        let row = sqlx::query(
            "SELECT sequence, event_hash FROM deployment_audit_events ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok(DeploymentAuditChainHead {
                sequence: sql_to_u64(row.try_get("sequence")?)?,
                head_hash: fixed_bytes(&row.try_get::<Vec<u8>, _>("event_hash")?)?,
            })
        })
        .transpose()
    }

    /// Verify a consistent committed prefix with bounded memory and return its head.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError::CorruptChain`] for a gap or changed stored field.
    pub async fn verify_deployment_audit_chain(
        &self,
    ) -> Result<Option<DeploymentAuditChainHead>, AuditStoreError> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let mut rows = sqlx::query(
            "SELECT sequence, previous_hash, event_bytes, event_hash
             FROM deployment_audit_events ORDER BY sequence ASC",
        )
        .fetch(&mut *transaction);
        let mut head = None;
        while let Some(row) = rows.try_next().await? {
            verify_row(&row, &mut head)?;
        }
        drop(rows);
        transaction.commit().await?;
        Ok(head)
    }

    /// Read the newest deployment checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] for an invalid stored row or database failure.
    pub async fn latest_deployment_audit_checkpoint(
        &self,
    ) -> Result<Option<DeploymentAuditCheckpoint>, AuditStoreError> {
        let row = sqlx::query(
            "SELECT sequence, head_hash, signature, signed_at_ms
             FROM deployment_audit_checkpoints ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| checkpoint_from_row(&row)).transpose()
    }

    /// Persist a deployment checkpoint in its own PostgreSQL transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] when it does not cover a stored prefix, is deferred, conflicts,
    /// or storage fails.
    pub async fn write_deployment_audit_checkpoint(
        &self,
        checkpoint: &DeploymentAuditCheckpoint,
    ) -> Result<(), AuditStoreError> {
        let mut transaction = self.pool().begin().await?;
        write_deployment_audit_checkpoint_in_postgres_transaction(&mut transaction, checkpoint)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

/// Append within the caller's SQLite transaction. It obtains the database write lock before
/// reading the head; the caller can commit the event together with its business mutation.
///
/// # Errors
///
/// Returns [`AuditStoreError`] for invalid input or storage failure.
pub async fn append_deployment_audit_event_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    event_bytes: &[u8],
    created_at_ms: i64,
) -> Result<DeploymentAuditEvent, AuditStoreError> {
    validate_input(event_bytes, created_at_ms)?;
    lock_sqlite_chain(transaction).await?;
    let latest = sqlx::query(
        "SELECT sequence, event_hash FROM deployment_audit_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    let (sequence, previous_hash) = next_position(latest)?;
    let hash = event_hash(&previous_hash, event_bytes)?;
    sqlx::query(
        "INSERT INTO deployment_audit_events
         (sequence, previous_hash, event_bytes, event_hash, created_at_ms)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(sql_integer(sequence)?)
    .bind(previous_hash.as_slice())
    .bind(event_bytes)
    .bind(hash.as_slice())
    .bind(created_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(DeploymentAuditEvent { sequence, previous_hash, event_hash: hash, created_at_ms })
}

/// Append within the caller's PostgreSQL transaction under a deployment-wide database lock.
///
/// # Errors
///
/// Returns [`AuditStoreError`] for invalid input or storage failure.
pub async fn append_deployment_audit_event_in_postgres_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    event_bytes: &[u8],
    created_at_ms: i64,
) -> Result<DeploymentAuditEvent, AuditStoreError> {
    validate_input(event_bytes, created_at_ms)?;
    lock_postgres_chain(transaction).await?;
    let latest = sqlx::query(
        "SELECT sequence, event_hash FROM deployment_audit_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    let (sequence, previous_hash) = next_position(latest)?;
    let hash = event_hash(&previous_hash, event_bytes)?;
    sqlx::query(
        "INSERT INTO deployment_audit_events
         (sequence, previous_hash, event_bytes, event_hash, created_at_ms)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(sql_integer(sequence)?)
    .bind(previous_hash.as_slice())
    .bind(event_bytes)
    .bind(hash.as_slice())
    .bind(created_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(DeploymentAuditEvent { sequence, previous_hash, event_hash: hash, created_at_ms })
}

/// Persist a checkpoint in a caller-owned SQLite transaction.
///
/// # Errors
///
/// Returns [`AuditStoreError`] for a mismatched prefix, deferred checkpoint, conflict, or storage
/// failure.
pub async fn write_deployment_audit_checkpoint_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    checkpoint: &DeploymentAuditCheckpoint,
) -> Result<(), AuditStoreError> {
    validate_checkpoint(checkpoint)?;
    lock_sqlite_chain(transaction).await?;
    let existing = sqlx::query(
        "SELECT sequence, head_hash, signature, signed_at_ms
         FROM deployment_audit_checkpoints WHERE sequence = ?",
    )
    .bind(sql_integer(checkpoint.sequence)?)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(row) = existing {
        return compare_checkpoint(&checkpoint_from_row(&row)?, checkpoint);
    }
    let head =
        sqlx::query("SELECT sequence, event_hash FROM deployment_audit_events WHERE sequence = ?")
            .bind(sql_integer(checkpoint.sequence)?)
            .fetch_optional(&mut **transaction)
            .await?;
    check_head(head, checkpoint)?;
    let latest = sqlx::query(
        "SELECT sequence, signed_at_ms FROM deployment_audit_checkpoints
         ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    check_checkpoint_cadence(latest, checkpoint)?;
    sqlx::query(
        "INSERT INTO deployment_audit_checkpoints (sequence, head_hash, signature, signed_at_ms)
         VALUES (?, ?, ?, ?)",
    )
    .bind(sql_integer(checkpoint.sequence)?)
    .bind(checkpoint.head_hash.as_slice())
    .bind(checkpoint.signature.as_slice())
    .bind(checkpoint.signed_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Persist a checkpoint in a caller-owned PostgreSQL transaction.
///
/// # Errors
///
/// Returns [`AuditStoreError`] for a mismatched prefix, deferred checkpoint, conflict, or storage
/// failure.
pub async fn write_deployment_audit_checkpoint_in_postgres_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    checkpoint: &DeploymentAuditCheckpoint,
) -> Result<(), AuditStoreError> {
    validate_checkpoint(checkpoint)?;
    lock_postgres_chain(transaction).await?;
    let existing = sqlx::query(
        "SELECT sequence, head_hash, signature, signed_at_ms
         FROM deployment_audit_checkpoints WHERE sequence = $1",
    )
    .bind(sql_integer(checkpoint.sequence)?)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(row) = existing {
        return compare_checkpoint(&checkpoint_from_row(&row)?, checkpoint);
    }
    let head =
        sqlx::query("SELECT sequence, event_hash FROM deployment_audit_events WHERE sequence = $1")
            .bind(sql_integer(checkpoint.sequence)?)
            .fetch_optional(&mut **transaction)
            .await?;
    check_head(head, checkpoint)?;
    let latest = sqlx::query(
        "SELECT sequence, signed_at_ms FROM deployment_audit_checkpoints
         ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    check_checkpoint_cadence(latest, checkpoint)?;
    sqlx::query(
        "INSERT INTO deployment_audit_checkpoints (sequence, head_hash, signature, signed_at_ms)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(sql_integer(checkpoint.sequence)?)
    .bind(checkpoint.head_hash.as_slice())
    .bind(checkpoint.signature.as_slice())
    .bind(checkpoint.signed_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn lock_sqlite_chain(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), AuditStoreError> {
    // Even a caller's deferred transaction obtains SQLite's database write reservation here.
    sqlx::query(
        "UPDATE deployment_audit_events SET created_at_ms = created_at_ms WHERE sequence = 0",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn lock_postgres_chain(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), AuditStoreError> {
    // Fixed pair denotes the only deployment audit chain in this database.
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1145132356)")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(())
}

fn validate_input(event_bytes: &[u8], created_at_ms: i64) -> Result<(), AuditStoreError> {
    validate_event(event_bytes)?;
    if created_at_ms <= 0 {
        return Err(AuditStoreError::Primitive(AuditError::InvalidPosition));
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &DeploymentAuditCheckpoint) -> Result<(), AuditStoreError> {
    deployment_checkpoint_payload(
        checkpoint.sequence,
        &checkpoint.head_hash,
        u64::try_from(checkpoint.signed_at_ms).map_err(|_| AuditStoreError::IntegerRange)?,
    )?;
    Ok(())
}

fn next_position<R: Row>(row: Option<R>) -> Result<(u64, [u8; HASH_BYTES]), AuditStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    match row {
        Some(row) => {
            let sequence = sql_to_u64(row.try_get("sequence")?)?
                .checked_add(1)
                .ok_or(AuditStoreError::IntegerRange)?;
            let previous = fixed_bytes(&row.try_get::<Vec<u8>, _>("event_hash")?)?;
            Ok((sequence, previous))
        }
        None => Ok((1, [0; HASH_BYTES])),
    }
}

fn check_head<R: Row>(
    row: Option<R>,
    checkpoint: &DeploymentAuditCheckpoint,
) -> Result<(), AuditStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let Some(row) = row else {
        return Err(AuditStoreError::CheckpointMismatch);
    };
    if sql_to_u64(row.try_get("sequence")?)? != checkpoint.sequence
        || fixed_bytes::<HASH_BYTES>(&row.try_get::<Vec<u8>, _>("event_hash")?)?
            != checkpoint.head_hash
    {
        return Err(AuditStoreError::CheckpointMismatch);
    }
    Ok(())
}

fn check_checkpoint_cadence<R: Row>(
    row: Option<R>,
    checkpoint: &DeploymentAuditCheckpoint,
) -> Result<(), AuditStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    if let Some(row) = row {
        let previous_sequence = sql_to_u64(row.try_get("sequence")?)?;
        let previous_time: i64 = row.try_get("signed_at_ms")?;
        if previous_sequence == 0 || previous_time <= 0 {
            return Err(AuditStoreError::CorruptChain);
        }
        if previous_sequence >= checkpoint.sequence
            || checkpoint.signed_at_ms.saturating_sub(previous_time) < CHECKPOINT_INTERVAL_MS
        {
            return Err(AuditStoreError::CheckpointDeferred);
        }
    }
    Ok(())
}

fn compare_checkpoint(
    stored: &DeploymentAuditCheckpoint,
    proposed: &DeploymentAuditCheckpoint,
) -> Result<(), AuditStoreError> {
    if stored == proposed { Ok(()) } else { Err(AuditStoreError::CheckpointConflict) }
}

fn checkpoint_from_row<R: Row>(row: &R) -> Result<DeploymentAuditCheckpoint, AuditStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let checkpoint = DeploymentAuditCheckpoint {
        sequence: sql_to_u64(row.try_get("sequence")?)?,
        head_hash: fixed_bytes(&row.try_get::<Vec<u8>, _>("head_hash")?)?,
        signature: fixed_bytes(&row.try_get::<Vec<u8>, _>("signature")?)?,
        signed_at_ms: row.try_get("signed_at_ms")?,
    };
    if checkpoint.sequence == 0 || checkpoint.signed_at_ms <= 0 {
        return Err(AuditStoreError::CorruptChain);
    }
    Ok(checkpoint)
}

fn verify_row<R: Row>(
    row: &R,
    head: &mut Option<DeploymentAuditChainHead>,
) -> Result<(), AuditStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let sequence = sql_to_u64(row.try_get("sequence")?)?;
    let (expected_sequence, previous_hash) = match head {
        Some(previous) => (
            previous.sequence.checked_add(1).ok_or(AuditStoreError::CorruptChain)?,
            previous.head_hash,
        ),
        None => (1, [0; HASH_BYTES]),
    };
    let stored_previous = fixed_bytes(&row.try_get::<Vec<u8>, _>("previous_hash")?)?;
    let event_bytes: Vec<u8> = row.try_get("event_bytes")?;
    let stored_hash = fixed_bytes(&row.try_get::<Vec<u8>, _>("event_hash")?)?;
    if sequence != expected_sequence
        || stored_previous != previous_hash
        || event_hash(&previous_hash, &event_bytes).map_err(|_| AuditStoreError::CorruptChain)?
            != stored_hash
    {
        return Err(AuditStoreError::CorruptChain);
    }
    *head = Some(DeploymentAuditChainHead { sequence, head_hash: stored_hash });
    Ok(())
}

fn sql_integer(value: u64) -> Result<i64, AuditStoreError> {
    i64::try_from(value).map_err(|_| AuditStoreError::IntegerRange)
}

fn sql_to_u64(value: i64) -> Result<u64, AuditStoreError> {
    u64::try_from(value).map_err(|_| AuditStoreError::CorruptChain)
}

fn fixed_bytes<const N: usize>(value: &[u8]) -> Result<[u8; N], AuditStoreError> {
    value.try_into().map_err(|_| AuditStoreError::CorruptChain)
}
