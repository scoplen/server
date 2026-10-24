// SPDX-License-Identifier: AGPL-3.0-only
//! Retention with transaction-current Personal membership and acknowledgements.

use std::collections::BTreeMap;

use futures_util::TryStreamExt as _;
use scoplen_api::account_devices::MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES;
use scoplen_crypto::{DeviceCertificate, RevocationStatement, verify_device_list};
use sqlx::{Postgres, Row, Sqlite, Transaction};

use super::{
    AccountId, DeviceId, MILLIS_PER_DAY, PurgeReport, SyncStoreError, TOMBSTONE_PURGE_AFTER_DAYS,
    VERSION_RETENTION_DAYS, VaultId, id_from_bytes, lock_vault, lock_vault_postgres,
    sequence_from_sql, sequence_to_sql, vault_state, vault_state_postgres,
};
use crate::{
    PostgresStore, RelationalStore, SqliteStore, account_devices::StatementKind,
    account_keys::MAX_DEVICE_WRAPS, device_authentication::verify_current_certificate,
};

fn verified_devices(
    account: AccountId,
    root: &[u8; 32],
    certificates: Vec<Vec<u8>>,
    revocations: &[Vec<u8>],
) -> Result<Vec<(DeviceId, Vec<u8>)>, SyncStoreError> {
    let mut encoded = BTreeMap::new();
    let mut decoded = Vec::with_capacity(certificates.len());
    for bytes in certificates {
        let certificate = DeviceCertificate::decode(&bytes)
            .map_err(|_| SyncStoreError::CorruptRow("retention certificate"))?;
        if certificate.account_id.into_bytes() != account {
            return Err(SyncStoreError::CorruptRow("retention certificate account"));
        }
        if encoded.insert(certificate.device_id.into_bytes(), bytes).is_some() {
            return Err(SyncStoreError::CorruptRow("retention duplicate certificate"));
        }
        decoded.push(certificate);
    }
    let revocations = revocations
        .iter()
        .map(|bytes| {
            RevocationStatement::decode(bytes)
                .map_err(|_| SyncStoreError::CorruptRow("retention revocation"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let active = verify_device_list(&decoded, &revocations, root)
        .map_err(|_| SyncStoreError::CorruptRow("retention signed statements"))?;
    if active.len() > MAX_DEVICE_WRAPS {
        return Err(SyncStoreError::CorruptRow("retention device limit"));
    }
    active
        .into_iter()
        .map(|certificate| {
            let id = certificate.device_id.into_bytes();
            let bytes = encoded
                .remove(&id)
                .ok_or(SyncStoreError::CorruptRow("retention certificate set"))?;
            Ok((id, bytes))
        })
        .collect()
}

macro_rules! retention {
    ($module:ident, $store:ty, $db:ty, $postgres:literal, $statements:ident, $purge:ident, $lock:ident, $state:ident) => {
        mod $module {
            use super::*;
            use crate::account_devices::$statements;

            fn sql(source: &str) -> String {
                if !$postgres {
                    return source.to_owned();
                }
                let mut parameter = 0;
                source
                    .chars()
                    .map(|c| {
                        if c == '?' {
                            parameter += 1;
                            format!("${parameter}")
                        } else {
                            c.to_string()
                        }
                    })
                    .collect()
            }

            async fn owner(
                tx: &mut Transaction<'_, $db>,
                vault: VaultId,
            ) -> Result<Option<AccountId>, SyncStoreError> {
                let row = sqlx::query(&sql(
                    "SELECT v.kind,p.account_id FROM sync_vaults AS v
                     LEFT JOIN sync_personal_vaults AS p ON p.vault_id=v.vault_id
                     WHERE v.vault_id=?",
                ))
                .bind(vault.as_slice())
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(SyncStoreError::VaultNotFound)?;
                match row.try_get::<&str, _>("kind")? {
                    "personal" => row
                        .try_get::<Option<Vec<u8>>, _>("account_id")?
                        .map(|bytes| id_from_bytes(&bytes, "retention owner"))
                        .transpose(),
                    "shared" | "organization" => Ok(None),
                    _ => Err(SyncStoreError::CorruptRow("retention vault kind")),
                }
            }

            async fn devices(
                tx: &mut Transaction<'_, $db>,
                account: AccountId,
            ) -> Result<Option<Vec<DeviceId>>, SyncStoreError> {
                let mut query = sql(
                    "SELECT a.account_signing_public_key FROM identity_accounts AS a
                     JOIN sync_account_key_bundles AS b ON b.account_id=a.account_id
                     WHERE a.account_id=?",
                );
                if $postgres {
                    query.push_str(" FOR SHARE OF a");
                }
                let root = sqlx::query_scalar::<_, Vec<u8>>(&query)
                    .bind(account.as_slice())
                    .fetch_optional(&mut **tx)
                    .await?;
                let Some(root) = root else {
                    return Ok(None);
                };
                let root: [u8; 32] = root.try_into()
                    .map_err(|_| SyncStoreError::CorruptRow("retention account root"))?;
                let mut total = 0;
                let certificates = $statements(tx, &account, StatementKind::Certificate, &mut total)
                    .await
                    .map_err(|_| SyncStoreError::AuthorizationUnavailable)?;
                let revocations = $statements(tx, &account, StatementKind::Revocation, &mut total)
                    .await
                    .map_err(|_| SyncStoreError::AuthorizationUnavailable)?;
                let certified = verified_devices(account, &root, certificates, &revocations)?;
                if certified.is_empty() {
                    return Ok(None);
                }
                let mut certified: BTreeMap<_, _> = certified.into_iter().collect();
                let mut devices = Vec::with_capacity(certified.len());
                let mut complete = true;
                let length = if $postgres { "octet_length" } else { "length" };
                let active = if $postgres { "active" } else { "active=1 AS active" };
                let placeholders = std::iter::repeat_n("?", certified.len()).collect::<Vec<_>>().join(",");
                let mut query = sql(&format!(
                    "SELECT device_id,account_id,{active},CASE WHEN {length}(certificate) BETWEEN 1 AND {MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES}
                     THEN certificate END AS certificate FROM identity_devices
                     WHERE device_id IN ({placeholders}) ORDER BY device_id",
                ));
                if $postgres {
                    query.push_str(" FOR SHARE");
                }
                let mut query = sqlx::query(&query);
                for id in certified.keys() {
                    query = query.bind(id.to_vec());
                }
                let mut rows = query.fetch(&mut **tx);
                while let Some(row) = rows.try_next().await? {
                    let id = id_from_bytes(&row.try_get::<Vec<u8>, _>("device_id")?, "retention device")?;
                    let expected = certified.remove(&id)
                        .ok_or(SyncStoreError::CorruptRow("retention current device set"))?;
                    let certificate: Vec<u8> = row.try_get("certificate")?;
                    if certificate != expected {
                        return Err(SyncStoreError::CorruptRow("retention current certificate"));
                    }
                    // Exact membership in the fully verified snapshot proves publication and
                    // non-revocation without rereading every revocation for each device.
                    let principal = verify_current_certificate(
                        row.try_get("account_id")?, id, &root, &certificate, true,
                    ).map_err(|_| SyncStoreError::AuthorizationUnavailable)?;
                    if principal.account_id != account {
                        return Err(SyncStoreError::CorruptRow("retention current identity"));
                    }
                    devices.push(id);
                    complete &= row.try_get::<bool, _>("active")?;
                }
                // An unsigned admission projection must never shrink the signed set.
                Ok((complete && certified.is_empty()).then_some(devices))
            }

            async fn floor(
                tx: &mut Transaction<'_, $db>,
                vault: VaultId,
                devices: Option<Vec<DeviceId>>,
            ) -> Result<Option<u64>, SyncStoreError> {
                let Some(devices) = devices else {
                    return Ok(None);
                };
                let (current, _) = $state(tx, vault).await?;
                let mut minimum = None;
                for device in devices {
                    let cursor = sqlx::query_scalar::<_, i64>(&sql(
                        "SELECT cursor FROM sync_acks WHERE vault_id=? AND device_id=?",
                    ))
                    .bind(vault.as_slice())
                    .bind(device.as_slice())
                    .fetch_optional(&mut **tx)
                    .await?
                    .map(sequence_from_sql)
                    .transpose()?
                    .unwrap_or(0);
                    if cursor > current {
                        return Err(SyncStoreError::CorruptRow("retention acknowledgement"));
                    }
                    minimum = Some(minimum.map_or(cursor, |previous: u64| previous.min(cursor)));
                }
                Ok(minimum)
            }

            impl $store {
                /// Prune versions and tombstones using a trusted caller-supplied ACK floor.
                ///
                /// `None` retains only the 180-day tombstone policy. The caller is responsible for
                /// the complete current device set; workers use
                /// [`Self::purge_sync_history_for_worker`] to bind membership and purge atomically.
                /// Both entry points keep the current version plus at most 20 previous versions
                /// for 30 days, remove all history with an eligible tombstone, and advance the
                /// purge horizon monotonically.
                ///
                /// # Errors
                /// Returns a missing-vault, ahead-cursor, negative-time or storage error.
                pub async fn purge_sync_history(
                    &self,
                    vault: VaultId,
                    acknowledged_through: Option<u64>,
                    now: i64,
                ) -> Result<PurgeReport, SyncStoreError> {
                    if now < 0 {
                        return Err(SyncStoreError::InvalidRetentionTime);
                    }
                    let mut tx = if $postgres {
                        self.pool().begin().await?
                    } else {
                        self.pool().begin_with("BEGIN IMMEDIATE").await?
                    };
                    $lock(&mut tx, vault).await?;
                    let report = $purge(&mut tx, vault, acknowledged_through, now).await?;
                    tx.commit().await?;
                    Ok(report)
                }

                /// Atomically derive a Personal ACK floor, prune history and advance the horizon.
                ///
                /// Every published certificate and revocation is verified before current identity
                /// admission and ACKs are checked. Missing ACKs count as zero. Unsupported vaults,
                /// absent enrollment state and incomplete or empty admitted device sets keep the
                /// 180-day policy. Inactive rows cannot silently remove signed, unrevoked peers.
                ///
                /// # Errors
                /// Returns a missing-vault, negative-time, invalid identity/ACK or storage error.
                /// Failed checks cannot partially prune history or advance the purge horizon.
                pub async fn purge_sync_history_for_worker(
                    &self,
                    vault: VaultId,
                    now: i64,
                ) -> Result<PurgeReport, SyncStoreError> {
                    if now < 0 {
                        return Err(SyncStoreError::InvalidRetentionTime);
                    }
                    let mut tx = if $postgres {
                        self.pool().begin().await?
                    } else {
                        self.pool().begin_with("BEGIN IMMEDIATE").await?
                    };
                    let candidate = owner(&mut tx, vault).await?;
                    let mut eligible = None;
                    if let Some(account) = candidate {
                        if $postgres {
                            // Account-key publication/pairing take this same seed-0 lock exclusively.
                            sqlx::query(&sql(
                                "SELECT pg_advisory_xact_lock_shared(hashtextextended(encode(?, 'hex'), 0))",
                            ))
                            .bind(account.as_slice())
                            .execute(&mut *tx)
                            .await?;
                        }
                        eligible = devices(&mut tx, account).await?;
                        if $postgres {
                            let current = sqlx::query_scalar::<_, Vec<u8>>(&sql(
                                "SELECT account_id FROM sync_personal_vaults WHERE vault_id=? FOR SHARE",
                            ))
                            .bind(vault.as_slice())
                            .fetch_optional(&mut *tx)
                            .await?;
                            if current.as_deref() != Some(account.as_slice()) {
                                eligible = None;
                            }
                        }
                    }
                    $lock(&mut tx, vault).await?;
                    if owner(&mut tx, vault).await? != candidate {
                        eligible = None;
                    }
                    let acknowledged_through = floor(&mut tx, vault, eligible).await?;
                    let report = $purge(&mut tx, vault, acknowledged_through, now).await?;
                    tx.commit().await?;
                    Ok(report)
                }
            }
        }
    };
}

retention!(
    sqlite,
    SqliteStore,
    Sqlite,
    false,
    sqlite_statements,
    sqlite_purge,
    lock_vault,
    vault_state
);
retention!(
    postgres,
    PostgresStore,
    Postgres,
    true,
    postgres_statements,
    postgres_purge,
    lock_vault_postgres,
    vault_state_postgres
);

#[allow(clippy::too_many_lines)]
async fn sqlite_purge(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
    acknowledged_through: Option<u64>,
    now_ms: i64,
) -> Result<PurgeReport, SyncStoreError> {
    let (current_seq, existing_horizon) = vault_state(transaction, vault_id).await?;
    if let Some(cursor) = acknowledged_through
        && cursor > current_seq
    {
        return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
    }

    let mut highest_removed = existing_horizon;
    let mut pruned_versions = 0_u64;
    let version_cutoff_ms = now_ms.saturating_sub(VERSION_RETENTION_DAYS * MILLIS_PER_DAY);
    let tombstone_cutoff_ms = now_ms.saturating_sub(TOMBSTONE_PURGE_AFTER_DAYS * MILLIS_PER_DAY);

    let old_version_max = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(sequence) FROM (\
         SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank \
         FROM sync_object_versions WHERE vault_id = ? \
         ) WHERE rank > 21 OR (rank > 1 AND written_at_ms < ?)",
    )
    .bind(vault_id.as_slice())
    .bind(version_cutoff_ms)
    .fetch_one(&mut **transaction)
    .await?
    .map(sequence_from_sql)
    .transpose()?;
    if let Some(max_sequence) = old_version_max {
        highest_removed = highest_removed.max(max_sequence);
    }
    let old_versions_result = sqlx::query(
        "DELETE FROM sync_object_versions WHERE vault_id = ? AND sequence IN (\
         SELECT sequence FROM (\
           SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank \
           FROM sync_object_versions WHERE vault_id = ? \
         ) WHERE rank > 21 OR (rank > 1 AND written_at_ms < ?))",
    )
    .bind(vault_id.as_slice())
    .bind(vault_id.as_slice())
    .bind(version_cutoff_ms)
    .execute(&mut **transaction)
    .await?;
    pruned_versions = pruned_versions.saturating_add(old_versions_result.rows_affected());

    let mut tombstone_query = String::from(
        "SELECT object_id, sequence FROM sync_objects WHERE vault_id = ? AND tombstone = 1 AND written_at_ms <= ?",
    );
    if acknowledged_through.is_some() {
        tombstone_query.push_str(" OR (vault_id = ? AND tombstone = 1 AND sequence <= ?)");
    }
    let mut query =
        sqlx::query(&tombstone_query).bind(vault_id.as_slice()).bind(tombstone_cutoff_ms);
    if let Some(cursor) = acknowledged_through {
        query = query.bind(vault_id.as_slice()).bind(sequence_to_sql(cursor)?);
    }
    let tombstones = query.fetch_all(&mut **transaction).await?;
    let mut purged_tombstones = 0_u64;
    for row in tombstones {
        let object_id_bytes: Vec<u8> = row.try_get("object_id")?;
        let object_id = id_from_bytes(&object_id_bytes, "object_id")?;
        let tombstone_sequence = sequence_from_sql(row.try_get("sequence")?)?;
        highest_removed = highest_removed.max(tombstone_sequence);
        let history =
            sqlx::query("DELETE FROM sync_object_versions WHERE vault_id = ? AND object_id = ?")
                .bind(vault_id.as_slice())
                .bind(object_id.as_slice())
                .execute(&mut **transaction)
                .await?;
        pruned_versions = pruned_versions.saturating_add(history.rows_affected());
        sqlx::query("DELETE FROM sync_objects WHERE vault_id = ? AND object_id = ?")
            .bind(vault_id.as_slice())
            .bind(object_id.as_slice())
            .execute(&mut **transaction)
            .await?;
        purged_tombstones = purged_tombstones.saturating_add(1);
    }

    if highest_removed > existing_horizon {
        sqlx::query("UPDATE sync_vaults SET purge_horizon = ? WHERE vault_id = ?")
            .bind(sequence_to_sql(highest_removed)?)
            .bind(vault_id.as_slice())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(PurgeReport { pruned_versions, purged_tombstones, purge_horizon: highest_removed })
}

#[allow(clippy::too_many_lines)]
async fn postgres_purge(
    transaction: &mut Transaction<'_, Postgres>,
    vault_id: VaultId,
    acknowledged_through: Option<u64>,
    now_ms: i64,
) -> Result<PurgeReport, SyncStoreError> {
    let (current_seq, existing_horizon) = vault_state_postgres(transaction, vault_id).await?;
    if let Some(cursor) = acknowledged_through
        && cursor > current_seq
    {
        return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
    }

    let mut highest_removed = existing_horizon;
    let version_cutoff_ms = now_ms.saturating_sub(VERSION_RETENTION_DAYS * MILLIS_PER_DAY);
    let tombstone_cutoff_ms = now_ms.saturating_sub(TOMBSTONE_PURGE_AFTER_DAYS * MILLIS_PER_DAY);
    let old_version_max = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(sequence) FROM (
         SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank
         FROM sync_object_versions WHERE vault_id = $1
         ) AS retained WHERE rank > 21 OR (rank > 1 AND written_at_ms < $2)",
    )
    .bind(vault_id.as_slice())
    .bind(version_cutoff_ms)
    .fetch_one(&mut **transaction)
    .await?
    .map(sequence_from_sql)
    .transpose()?;
    if let Some(max_sequence) = old_version_max {
        highest_removed = highest_removed.max(max_sequence);
    }
    let old_versions_result = sqlx::query(
        "DELETE FROM sync_object_versions WHERE vault_id = $1 AND sequence IN (
         SELECT sequence FROM (
           SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank
           FROM sync_object_versions WHERE vault_id = $2
         ) AS retained WHERE rank > 21 OR (rank > 1 AND written_at_ms < $3))",
    )
    .bind(vault_id.as_slice())
    .bind(vault_id.as_slice())
    .bind(version_cutoff_ms)
    .execute(&mut **transaction)
    .await?;
    let pruned_versions = old_versions_result.rows_affected();

    let mut tombstone_query = String::from(
        "SELECT object_id, sequence FROM sync_objects
         WHERE vault_id = $1 AND tombstone = TRUE AND written_at_ms <= $2",
    );
    if acknowledged_through.is_some() {
        tombstone_query.push_str(" OR (vault_id = $3 AND tombstone = TRUE AND sequence <= $4)");
    }
    let mut query =
        sqlx::query(&tombstone_query).bind(vault_id.as_slice()).bind(tombstone_cutoff_ms);
    if let Some(cursor) = acknowledged_through {
        query = query.bind(vault_id.as_slice()).bind(sequence_to_sql(cursor)?);
    }
    let tombstones = query.fetch_all(&mut **transaction).await?;
    let mut purged_tombstones = 0_u64;
    let mut pruned_versions = pruned_versions;
    for row in tombstones {
        let object_id = id_from_bytes(&row.try_get::<Vec<u8>, _>("object_id")?, "object_id")?;
        highest_removed = highest_removed.max(sequence_from_sql(row.try_get("sequence")?)?);
        let history =
            sqlx::query("DELETE FROM sync_object_versions WHERE vault_id = $1 AND object_id = $2")
                .bind(vault_id.as_slice())
                .bind(object_id.as_slice())
                .execute(&mut **transaction)
                .await?;
        pruned_versions = pruned_versions.saturating_add(history.rows_affected());
        sqlx::query("DELETE FROM sync_objects WHERE vault_id = $1 AND object_id = $2")
            .bind(vault_id.as_slice())
            .bind(object_id.as_slice())
            .execute(&mut **transaction)
            .await?;
        purged_tombstones = purged_tombstones.saturating_add(1);
    }
    if highest_removed > existing_horizon {
        sqlx::query("UPDATE sync_vaults SET purge_horizon = $1 WHERE vault_id = $2")
            .bind(sequence_to_sql(highest_removed)?)
            .bind(vault_id.as_slice())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(PurgeReport { pruned_versions, purged_tombstones, purge_horizon: highest_removed })
}
