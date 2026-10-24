// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    ChangePage, MAX_PAGE_SIZE, ObjectId, SyncChange, SyncStoreError, VaultId, bool_from_sql,
    cbor_argument_bytes, change_from_postgres_row, change_from_row, epoch_from_sql, id_from_bytes,
    sequence_from_sql, sequence_to_sql, vault_state,
};
use crate::{PostgresStore, RelationalStore, SqliteStore};
use scoplen_api::sync::{self as api, SyncReadLimits};
use sqlx::Row;
use uuid::Uuid;

#[cfg(test)]
mod tests;

struct Metadata {
    change: SyncChange,
    bytes: usize,
}

impl Metadata {
    fn wire(&self) -> api::SyncChange {
        api::SyncChange {
            object_id: Uuid::from_bytes(self.change.object_id),
            seq: self.change.sequence,
            payload: Vec::new(),
            tombstone: self.change.tombstone,
            signer_device_id: self.change.signer_device_id.map(Uuid::from_bytes),
        }
    }

    fn encoded_bytes(&self, limits: SyncReadLimits) -> Result<usize, SyncStoreError> {
        if self.bytes > limits.max_envelope_bytes {
            return Err(SyncStoreError::ReadBudgetExceeded);
        }
        self.bytes
            .checked_add(
                24 + cbor_argument_bytes(self.change.sequence)
                    + cbor_argument_bytes(self.bytes as u64)
                    + if self.change.signer_device_id.is_some() { 17 } else { 1 },
            )
            .ok_or(SyncStoreError::ReadBudgetExceeded)
    }

    fn matches(&self, actual: &SyncChange) -> bool {
        self.bytes == actual.envelope.len()
            && self.change.object_id == actual.object_id
            && self.change.sequence == actual.sequence
            && self.change.key_epoch == actual.key_epoch
            && self.change.tombstone == actual.tombstone
            && self.change.signer_device_id == actual.signer_device_id
    }
}

struct Selection {
    count: usize,
    cursor: u64,
    more: bool,
}

fn validate_limits(limits: Option<SyncReadLimits>) -> Result<(), SyncStoreError> {
    if let Some(limits) = limits {
        limits.validate().map_err(|_| SyncStoreError::InvalidReadLimits)?;
    }
    Ok(())
}

fn page_bytes(entries_bytes: usize, count: usize, cursor: u64) -> Option<usize> {
    entries_bytes.checked_add(27 + cbor_argument_bytes(count as u64) + cbor_argument_bytes(cursor))
}

fn select_page(
    metadata: &[Metadata],
    query: api::SyncChangesQuery,
    current_seq: u64,
    more: bool,
    limits: Option<SyncReadLimits>,
) -> Result<Selection, SyncStoreError> {
    let cursor = if more {
        metadata.last().expect("nonempty non-final metadata").change.sequence
    } else {
        current_seq
    };
    let Some(limits) = limits else {
        return Ok(Selection { count: metadata.len(), cursor, more });
    };
    // Empty payloads are structural stand-ins, never actual envelope allocations. Validate the
    // complete requested source page, including a tail that the budget may later exclude.
    api::SyncChangesResponse {
        changes: metadata.iter().map(Metadata::wire).collect(),
        next_cursor: cursor,
        more,
    }
    .validate_for_query_with_limits(
        &query,
        SyncReadLimits { max_envelope_bytes: 1, max_body_bytes: usize::MAX },
    )
    .map_err(|_| SyncStoreError::CorruptRow("sync page metadata"))?;
    let mut total = 0usize;
    let mut selected = 0;
    for (index, entry) in metadata.iter().enumerate() {
        let Ok(bytes) = entry.encoded_bytes(limits) else { break };
        let Some(next) = total.checked_add(bytes) else { break };
        let final_page = index + 1 == metadata.len() && !more;
        let candidate_cursor = if final_page { current_seq } else { entry.change.sequence };
        if page_bytes(next, index + 1, candidate_cursor)
            .is_none_or(|size| size > limits.max_body_bytes)
        {
            break;
        }
        total = next;
        selected = index + 1;
    }
    if selected == metadata.len() {
        if page_bytes(total, selected, cursor).is_none_or(|size| size > limits.max_body_bytes) {
            return Err(SyncStoreError::ReadBudgetExceeded);
        }
        return Ok(Selection { count: selected, cursor, more });
    }
    if selected == 0 {
        return Err(SyncStoreError::ReadBudgetExceeded);
    }
    Ok(Selection { count: selected, cursor: metadata[selected - 1].change.sequence, more: true })
}

fn validate_history(
    metadata: &[Metadata],
    object_id: ObjectId,
    limits: Option<SyncReadLimits>,
) -> Result<(), SyncStoreError> {
    let Some(limits) = limits else { return Ok(()) };
    api::SyncVersionsResponse { versions: metadata.iter().map(Metadata::wire).collect() }
        .validate_for_object_with_limits(
            Uuid::from_bytes(object_id),
            SyncReadLimits { max_envelope_bytes: 1, max_body_bytes: usize::MAX },
        )
        .map_err(|_| SyncStoreError::CorruptRow("sync history metadata"))?;
    let mut total = 10 + cbor_argument_bytes(metadata.len() as u64);
    for entry in metadata {
        total = total
            .checked_add(entry.encoded_bytes(limits)?)
            .ok_or(SyncStoreError::ReadBudgetExceeded)?;
        if total > limits.max_body_bytes {
            return Err(SyncStoreError::ReadBudgetExceeded);
        }
    }
    Ok(())
}

fn payload_bound(metadata: &[Metadata]) -> i64 {
    i64::try_from(metadata.iter().map(|entry| entry.bytes).max().unwrap_or(0))
        .expect("length came from SQL i64")
}

fn verify_payloads(metadata: &[Metadata], payloads: &[SyncChange]) -> Result<(), SyncStoreError> {
    if metadata.len() != payloads.len()
        || metadata.iter().zip(payloads).any(|(expected, actual)| !expected.matches(actual))
    {
        return Err(SyncStoreError::CorruptRow("sync payload snapshot"));
    }
    Ok(())
}

fn sqlite_metadata(
    row: &sqlx::sqlite::SqliteRow,
    object: Option<ObjectId>,
) -> Result<Metadata, SyncStoreError> {
    if row.try_get::<String, _>("envelope_type")? != "blob" {
        return Err(SyncStoreError::CorruptRow("envelope type"));
    }
    let object_id = match object {
        Some(id) => id,
        None => id_from_bytes(&row.try_get::<Vec<u8>, _>("object_id")?, "object_id")?,
    };
    Ok(Metadata {
        bytes: usize::try_from(row.try_get::<i64, _>("envelope_bytes")?)
            .map_err(|_| SyncStoreError::CorruptRow("envelope length"))?,
        change: SyncChange {
            object_id,
            sequence: sequence_from_sql(row.try_get("sequence")?)?,
            envelope: Vec::new(),
            key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
            tombstone: bool_from_sql(row.try_get("tombstone")?)?,
            signer_device_id: row
                .try_get::<Option<Vec<u8>>, _>("signer_device_id")?
                .map(|bytes| id_from_bytes(&bytes, "signer_device_id"))
                .transpose()?,
        },
    })
}

fn postgres_metadata(
    row: &sqlx::postgres::PgRow,
    object: Option<ObjectId>,
) -> Result<Metadata, SyncStoreError> {
    let object_id = match object {
        Some(id) => id,
        None => id_from_bytes(&row.try_get::<Vec<u8>, _>("object_id")?, "object_id")?,
    };
    Ok(Metadata {
        bytes: usize::try_from(row.try_get::<i64, _>("envelope_bytes")?)
            .map_err(|_| SyncStoreError::CorruptRow("envelope length"))?,
        change: SyncChange {
            object_id,
            sequence: sequence_from_sql(row.try_get("sequence")?)?,
            envelope: Vec::new(),
            key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
            tombstone: row.try_get("tombstone")?,
            signer_device_id: row
                .try_get::<Option<Vec<u8>>, _>("signer_device_id")?
                .map(|bytes| id_from_bytes(&bytes, "signer_device_id"))
                .transpose()?,
        },
    })
}

pub(super) async fn sqlite_page(
    store: &SqliteStore,
    vault: VaultId,
    after: u64,
    limit: u16,
    purge: bool,
    limits: Option<SyncReadLimits>,
) -> Result<ChangePage, SyncStoreError> {
    validate_limits(limits)?;
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(SyncStoreError::InvalidPageSize);
    }
    let mut tx = store.pool().begin().await?;
    let (current_seq, horizon) = vault_state(&mut tx, vault).await?;
    if purge && after < horizon {
        return Err(SyncStoreError::CursorExpired { purge_horizon: horizon });
    }
    if after > current_seq {
        return Err(SyncStoreError::CursorAhead { cursor: after, current: current_seq });
    }
    let rows = sqlx::query("SELECT CASE WHEN length(object_id) = 16 THEN object_id ELSE X'' END AS object_id, sequence, tombstone, CASE WHEN signer_device_id IS NULL OR length(signer_device_id) = 16 THEN signer_device_id ELSE X'' END AS signer_device_id, key_epoch, length(envelope) AS envelope_bytes, typeof(envelope) AS envelope_type FROM sync_objects WHERE vault_id = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?")
        .bind(vault.as_slice()).bind(sequence_to_sql(after)?).bind(i64::from(limit) + 1).fetch_all(&mut *tx).await?;
    let more = rows.len() > usize::from(limit);
    let metadata = rows
        .iter()
        .take(usize::from(limit))
        .map(|row| sqlite_metadata(row, None))
        .collect::<Result<Vec<_>, _>>()?;
    let selected =
        select_page(&metadata, api::SyncChangesQuery { after, limit }, current_seq, more, limits)?;
    let metadata = &metadata[..selected.count];
    let mut changes = Vec::new();
    if let Some(last) = metadata.last() {
        #[cfg(test)]
        tests::payload_query(vault);
        let rows = sqlx::query("SELECT object_id, sequence, envelope, tombstone, signer_device_id, key_epoch FROM sync_objects WHERE vault_id = ? AND sequence > ? AND sequence <= ? AND length(envelope) <= ? ORDER BY sequence ASC LIMIT ?")
            .bind(vault.as_slice()).bind(sequence_to_sql(after)?).bind(sequence_to_sql(last.change.sequence)?).bind(payload_bound(metadata)).bind(i64::try_from(metadata.len()).expect("bounded page count"))
            .fetch_all(&mut *tx).await?;
        for row in rows {
            let change = change_from_row(
                id_from_bytes(&row.try_get::<Vec<u8>, _>("object_id")?, "object_id")?,
                &row,
            )?;
            #[cfg(test)]
            tests::payload_loaded(vault, change.envelope.len());
            changes.push(change);
        }
    }
    verify_payloads(metadata, &changes)?;
    tx.commit().await?;
    Ok(ChangePage { changes, next_cursor: selected.cursor, more: selected.more })
}

pub(super) async fn postgres_page(
    store: &PostgresStore,
    vault: VaultId,
    after: u64,
    limit: u16,
    purge: bool,
    limits: Option<SyncReadLimits>,
) -> Result<ChangePage, SyncStoreError> {
    validate_limits(limits)?;
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(SyncStoreError::InvalidPageSize);
    }
    let mut tx = store.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT current_seq, purge_horizon FROM sync_vaults WHERE vault_id = $1")
        .bind(vault.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(SyncStoreError::VaultNotFound)?;
    let current_seq = sequence_from_sql(row.try_get("current_seq")?)?;
    let horizon = sequence_from_sql(row.try_get("purge_horizon")?)?;
    if purge && after < horizon {
        return Err(SyncStoreError::CursorExpired { purge_horizon: horizon });
    }
    if after > current_seq {
        return Err(SyncStoreError::CursorAhead { cursor: after, current: current_seq });
    }
    let rows = sqlx::query("SELECT CASE WHEN octet_length(object_id) = 16 THEN object_id ELSE ''::BYTEA END AS object_id, sequence, tombstone, CASE WHEN signer_device_id IS NULL OR octet_length(signer_device_id) = 16 THEN signer_device_id ELSE ''::BYTEA END AS signer_device_id, key_epoch, octet_length(envelope)::BIGINT AS envelope_bytes FROM sync_objects WHERE vault_id = $1 AND sequence > $2 ORDER BY sequence ASC LIMIT $3")
        .bind(vault.as_slice()).bind(sequence_to_sql(after)?).bind(i64::from(limit) + 1).fetch_all(&mut *tx).await?;
    let more = rows.len() > usize::from(limit);
    let metadata = rows
        .iter()
        .take(usize::from(limit))
        .map(|row| postgres_metadata(row, None))
        .collect::<Result<Vec<_>, _>>()?;
    let selected =
        select_page(&metadata, api::SyncChangesQuery { after, limit }, current_seq, more, limits)?;
    let metadata = &metadata[..selected.count];
    let mut changes = Vec::new();
    if let Some(last) = metadata.last() {
        #[cfg(test)]
        tests::payload_query(vault);
        let rows = sqlx::query("SELECT object_id, sequence, envelope, tombstone, signer_device_id, key_epoch FROM sync_objects WHERE vault_id = $1 AND sequence > $2 AND sequence <= $3 AND octet_length(envelope) <= $4 ORDER BY sequence ASC LIMIT $5")
            .bind(vault.as_slice()).bind(sequence_to_sql(after)?).bind(sequence_to_sql(last.change.sequence)?).bind(payload_bound(metadata)).bind(i64::try_from(metadata.len()).expect("bounded page count"))
            .fetch_all(&mut *tx).await?;
        for row in rows {
            let change = change_from_postgres_row(
                id_from_bytes(&row.try_get::<Vec<u8>, _>("object_id")?, "object_id")?,
                &row,
            )?;
            #[cfg(test)]
            tests::payload_loaded(vault, change.envelope.len());
            changes.push(change);
        }
    }
    verify_payloads(metadata, &changes)?;
    tx.commit().await?;
    Ok(ChangePage { changes, next_cursor: selected.cursor, more: selected.more })
}

pub(super) async fn sqlite_versions(
    store: &SqliteStore,
    vault: VaultId,
    object: ObjectId,
    limits: Option<SyncReadLimits>,
) -> Result<Vec<SyncChange>, SyncStoreError> {
    validate_limits(limits)?;
    let mut tx = store.pool().begin().await?;
    vault_state(&mut tx, vault).await?;
    let rows = sqlx::query("SELECT sequence, tombstone, CASE WHEN signer_device_id IS NULL OR length(signer_device_id) = 16 THEN signer_device_id ELSE X'' END AS signer_device_id, key_epoch, length(envelope) AS envelope_bytes, typeof(envelope) AS envelope_type FROM sync_object_versions WHERE vault_id = ? AND object_id = ? ORDER BY sequence DESC LIMIT 21")
        .bind(vault.as_slice()).bind(object.as_slice()).fetch_all(&mut *tx).await?;
    let mut metadata =
        rows.iter().map(|row| sqlite_metadata(row, Some(object))).collect::<Result<Vec<_>, _>>()?;
    if metadata.is_empty() {
        return Err(SyncStoreError::ObjectNotFound);
    }
    metadata.reverse();
    validate_history(&metadata, object, limits)?;
    #[cfg(test)]
    tests::payload_query(vault);
    let rows = sqlx::query("SELECT sequence, envelope, tombstone, signer_device_id, key_epoch FROM sync_object_versions WHERE vault_id = ? AND object_id = ? AND sequence >= ? AND sequence <= ? AND length(envelope) <= ? ORDER BY sequence ASC LIMIT 21")
        .bind(vault.as_slice()).bind(object.as_slice()).bind(sequence_to_sql(metadata[0].change.sequence)?).bind(sequence_to_sql(metadata.last().expect("nonempty history").change.sequence)?).bind(payload_bound(&metadata)).fetch_all(&mut *tx).await?;
    let mut versions = Vec::new();
    for row in rows {
        let change = change_from_row(object, &row)?;
        #[cfg(test)]
        tests::payload_loaded(vault, change.envelope.len());
        versions.push(change);
    }
    verify_payloads(&metadata, &versions)?;
    tx.commit().await?;
    Ok(versions)
}

pub(super) async fn postgres_versions(
    store: &PostgresStore,
    vault: VaultId,
    object: ObjectId,
    limits: Option<SyncReadLimits>,
) -> Result<Vec<SyncChange>, SyncStoreError> {
    validate_limits(limits)?;
    let mut tx = store.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    if sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT FROM sync_vaults WHERE vault_id = $1")
        .bind(vault.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
    {
        return Err(SyncStoreError::VaultNotFound);
    }
    let rows = sqlx::query("SELECT sequence, tombstone, CASE WHEN signer_device_id IS NULL OR octet_length(signer_device_id) = 16 THEN signer_device_id ELSE ''::BYTEA END AS signer_device_id, key_epoch, octet_length(envelope)::BIGINT AS envelope_bytes FROM sync_object_versions WHERE vault_id = $1 AND object_id = $2 ORDER BY sequence DESC LIMIT 21")
        .bind(vault.as_slice()).bind(object.as_slice()).fetch_all(&mut *tx).await?;
    let mut metadata = rows
        .iter()
        .map(|row| postgres_metadata(row, Some(object)))
        .collect::<Result<Vec<_>, _>>()?;
    if metadata.is_empty() {
        return Err(SyncStoreError::ObjectNotFound);
    }
    metadata.reverse();
    validate_history(&metadata, object, limits)?;
    #[cfg(test)]
    tests::payload_query(vault);
    let rows = sqlx::query("SELECT sequence, envelope, tombstone, signer_device_id, key_epoch FROM sync_object_versions WHERE vault_id = $1 AND object_id = $2 AND sequence >= $3 AND sequence <= $4 AND octet_length(envelope) <= $5 ORDER BY sequence ASC LIMIT 21")
        .bind(vault.as_slice()).bind(object.as_slice()).bind(sequence_to_sql(metadata[0].change.sequence)?).bind(sequence_to_sql(metadata.last().expect("nonempty history").change.sequence)?).bind(payload_bound(&metadata)).fetch_all(&mut *tx).await?;
    let mut versions = Vec::new();
    for row in rows {
        let change = change_from_postgres_row(object, &row)?;
        #[cfg(test)]
        tests::payload_loaded(vault, change.envelope.len());
        versions.push(change);
    }
    verify_payloads(&metadata, &versions)?;
    tx.commit().await?;
    Ok(versions)
}
