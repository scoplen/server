// SPDX-License-Identifier: AGPL-3.0-only
//! SQLite persistence for per-organization audit chains.

use scoplen_audit::{
    AuditError, CHECKPOINT_SIGNATURE_BYTES, HASH_BYTES, checkpoint_payload, event_hash,
    validate_event, verify_chain,
};
use sqlx::{Row, Sqlite, Transaction};
use thiserror::Error;

use crate::{RelationalStore, SqliteStore};

/// A durable audit event and its chain position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Organization that owns the chain.
    pub organization_id: [u8; 16],
    /// One-based, gap-free chain sequence.
    pub sequence: u64,
    /// Hash that preceded this event.
    pub previous_hash: [u8; HASH_BYTES],
    /// Canonical event bytes supplied by the control-plane boundary.
    pub event_bytes: Vec<u8>,
    /// Hash of `previous_hash || event_bytes`.
    pub event_hash: [u8; HASH_BYTES],
    /// Event creation time in Unix milliseconds.
    pub created_at_ms: i64,
}

/// Durable signed checkpoint for an audit chain head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCheckpoint {
    /// Organization that owns the chain.
    pub organization_id: [u8; 16],
    /// Chain sequence covered by this checkpoint.
    pub sequence: u64,
    /// Hash at `sequence`.
    pub head_hash: [u8; HASH_BYTES],
    /// Deployment audit-key signature over [`checkpoint_payload`].
    pub signature: [u8; CHECKPOINT_SIGNATURE_BYTES],
    /// Signature creation time in Unix milliseconds.
    pub signed_at_ms: i64,
}

/// Audit storage failures.
#[derive(Debug, Error)]
pub enum AuditStoreError {
    /// The database rejected a query or transaction.
    #[error("audit database error: {0}")]
    Database(#[from] sqlx::Error),
    /// The supplied event or checkpoint failed primitive validation.
    #[error("audit primitive error: {0}")]
    Primitive(#[from] AuditError),
    /// A sequence or timestamp cannot fit the storage representation.
    #[error("audit value is outside the supported integer range")]
    IntegerRange,
    /// The checkpoint does not cover the current chain head.
    #[error("audit checkpoint does not match the chain head")]
    CheckpointMismatch,
    /// A checkpoint already exists with different contents.
    #[error("audit checkpoint conflicts with an existing checkpoint")]
    CheckpointConflict,
    /// A stored chain row failed its integrity checks.
    #[error("audit chain contains invalid stored data")]
    CorruptChain,
}

impl SqliteStore {
    /// Append an event in its own transaction.
    ///
    /// Callers that mutate other state should use [`append_audit_event_in_transaction`] with the
    /// same transaction so the state change and audit record commit or roll back together.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] when validation, hashing, or the database transaction fails.
    pub async fn append_audit_event(
        &self,
        organization_id: [u8; 16],
        event_bytes: &[u8],
        created_at_ms: i64,
    ) -> Result<AuditEvent, AuditStoreError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let event = append_audit_event_in_transaction(
            &mut transaction,
            organization_id,
            event_bytes,
            created_at_ms,
        )
        .await?;
        transaction.commit().await?;
        Ok(event)
    }

    /// Persist a signed checkpoint in its own transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError`] when the checkpoint does not match the chain head or the
    /// database transaction fails.
    pub async fn write_audit_checkpoint(
        &self,
        checkpoint: &AuditCheckpoint,
    ) -> Result<(), AuditStoreError> {
        let mut transaction = self.pool().begin().await?;
        write_audit_checkpoint_in_transaction(&mut transaction, checkpoint).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Verify every stored event in an organization and return the current chain head.
    ///
    /// # Errors
    ///
    /// Returns [`AuditStoreError::CorruptChain`] when stored rows fail hash or sequence checks,
    /// or a database/primitive error occurs.
    pub async fn verify_audit_chain(
        &self,
        organization_id: [u8; 16],
    ) -> Result<[u8; HASH_BYTES], AuditStoreError> {
        let rows = sqlx::query(
            "SELECT sequence, previous_hash, event_bytes, event_hash
             FROM audit_events WHERE organization_id = ? ORDER BY sequence ASC",
        )
        .bind(organization_id.as_slice())
        .fetch_all(self.pool())
        .await?;
        let mut events = Vec::with_capacity(rows.len());
        let mut previous = [0; HASH_BYTES];
        for row in rows {
            let sequence = sql_to_u64(row.try_get("sequence")?)?;
            let stored_previous =
                fixed_bytes::<HASH_BYTES>(&row.try_get::<Vec<u8>, _>("previous_hash")?)?;
            let event_bytes: Vec<u8> = row.try_get("event_bytes")?;
            let stored_hash = fixed_bytes::<HASH_BYTES>(&row.try_get::<Vec<u8>, _>("event_hash")?)?;
            if stored_previous != previous || event_hash(&previous, &event_bytes)? != stored_hash {
                return Err(AuditStoreError::CorruptChain);
            }
            events.push((sequence, event_bytes));
            previous = stored_hash;
        }
        Ok(verify_chain(events.iter().map(|(sequence, event)| (*sequence, event.as_slice())))?)
    }
}

/// Append an event to a caller-owned transaction.
///
/// # Errors
///
/// Returns [`AuditStoreError`] when validation, hashing, or the transaction insert fails.
pub async fn append_audit_event_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    organization_id: [u8; 16],
    event_bytes: &[u8],
    created_at_ms: i64,
) -> Result<AuditEvent, AuditStoreError> {
    validate_event(event_bytes)?;
    if created_at_ms <= 0 {
        return Err(AuditStoreError::Primitive(AuditError::InvalidPosition));
    }
    let latest = sqlx::query(
        "SELECT sequence, event_hash FROM audit_events
         WHERE organization_id = ? ORDER BY sequence DESC LIMIT 1",
    )
    .bind(organization_id.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let (sequence, previous_hash) = match latest {
        Some(row) => {
            let previous_sequence = sql_to_u64(row.try_get("sequence")?)?;
            let sequence = previous_sequence.checked_add(1).ok_or(AuditStoreError::IntegerRange)?;
            let previous_hash =
                fixed_bytes::<HASH_BYTES>(&row.try_get::<Vec<u8>, _>("event_hash")?)?;
            (sequence, previous_hash)
        }
        None => (1, [0; HASH_BYTES]),
    };
    let hash = event_hash(&previous_hash, event_bytes)?;
    sqlx::query(
        "INSERT INTO audit_events
         (organization_id, sequence, previous_hash, event_bytes, event_hash, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(organization_id.as_slice())
    .bind(sql_integer(sequence)?)
    .bind(previous_hash.as_slice())
    .bind(event_bytes)
    .bind(hash.as_slice())
    .bind(created_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(AuditEvent {
        organization_id,
        sequence,
        previous_hash,
        event_bytes: event_bytes.to_vec(),
        event_hash: hash,
        created_at_ms,
    })
}

/// Persist a checkpoint in a caller-owned transaction after checking its chain head.
///
/// # Errors
///
/// Returns [`AuditStoreError::CheckpointMismatch`] when the checkpoint is not the current chain
/// head, or a validation, conflict, or database error occurs.
pub async fn write_audit_checkpoint_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    checkpoint: &AuditCheckpoint,
) -> Result<(), AuditStoreError> {
    if checkpoint.sequence == 0 || checkpoint.signed_at_ms <= 0 {
        return Err(AuditStoreError::Primitive(AuditError::InvalidPosition));
    }
    let head = sqlx::query(
        "SELECT event_hash FROM audit_events WHERE organization_id = ? AND sequence = ?",
    )
    .bind(checkpoint.organization_id.as_slice())
    .bind(sql_integer(checkpoint.sequence)?)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AuditStoreError::CheckpointMismatch)?;
    let stored_hash = fixed_bytes::<HASH_BYTES>(&head.try_get::<Vec<u8>, _>("event_hash")?)?;
    if stored_hash != checkpoint.head_hash {
        return Err(AuditStoreError::CheckpointMismatch);
    }
    checkpoint_payload(
        &checkpoint.organization_id,
        checkpoint.sequence,
        &checkpoint.head_hash,
        u64::try_from(checkpoint.signed_at_ms).map_err(|_| AuditStoreError::IntegerRange)?,
    )?;
    let existing = sqlx::query(
        "SELECT head_hash, signature, signed_at_ms FROM audit_checkpoints
         WHERE organization_id = ? AND sequence = ?",
    )
    .bind(checkpoint.organization_id.as_slice())
    .bind(sql_integer(checkpoint.sequence)?)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(row) = existing {
        let same = fixed_bytes::<HASH_BYTES>(&row.try_get::<Vec<u8>, _>("head_hash")?)?
            == checkpoint.head_hash
            && fixed_bytes::<CHECKPOINT_SIGNATURE_BYTES>(&row.try_get::<Vec<u8>, _>("signature")?)?
                == checkpoint.signature
            && row.try_get::<i64, _>("signed_at_ms")? == checkpoint.signed_at_ms;
        return if same { Ok(()) } else { Err(AuditStoreError::CheckpointConflict) };
    }
    sqlx::query(
        "INSERT INTO audit_checkpoints
         (organization_id, sequence, head_hash, signature, signed_at_ms)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(checkpoint.organization_id.as_slice())
    .bind(sql_integer(checkpoint.sequence)?)
    .bind(checkpoint.head_hash.as_slice())
    .bind(checkpoint.signature.as_slice())
    .bind(checkpoint.signed_at_ms)
    .execute(&mut **transaction)
    .await?;
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
