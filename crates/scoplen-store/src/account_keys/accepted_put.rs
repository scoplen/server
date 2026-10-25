// SPDX-License-Identifier: AGPL-3.0-only
//! Verified acceptance evidence, distinct from a lower-level serving projection.

use scoplen_api::sync::SyncAccountKeyBundleUpdate;
use sqlx::{Postgres, QueryBuilder, Row, Sqlite, Transaction};

use super::{AccountId, AccountKeyStoreError, MAX_DEVICE_WRAPS};
use crate::{PostgresStore, RelationalStore, SqliteStore};

fn corrupt() -> AccountKeyStoreError {
    AccountKeyStoreError::CorruptRow("accepted account key PUT")
}

macro_rules! accepted_put_reader {
    ($store:ty, $db:ty, $read:ident, $postgres:literal) => {
        impl $store {
            /// Read the complete current PUT saved by a verified production mutation.
            ///
            /// This storage read grants no authorization. `None` means the current projection
            /// has no acceptance evidence, including legacy rows and lower-level new revisions.
            /// Exact replay never backfills that evidence. All current fields and wraps must
            /// agree with the strict canonical PUT before its bytes are returned.
            /// This does not replace complete bootstrap signature and recipient validation.
            ///
            /// # Errors
            /// Returns `BundleNotFound` for an absent bundle, `CorruptRow` for invalid or
            /// inconsistent evidence, or a database error without disclosing a partial result.
            pub async fn read_accepted_account_key_put(
                &self,
                account_id: AccountId,
            ) -> Result<Option<Vec<u8>>, AccountKeyStoreError> {
                let mut tx = self.pool().begin().await?;
                if $postgres {
                    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended(encode($1, 'hex'), 0))")
                        .bind(account_id.as_slice())
                        .execute(&mut *tx)
                        .await?;
                }
                let result = $read(&mut tx, account_id).await?;
                tx.commit().await?;
                Ok(result)
            }
        }

        #[allow(clippy::too_many_lines)]
        async fn $read(
            tx: &mut Transaction<'_, $db>,
            account_id: AccountId,
        ) -> Result<Option<Vec<u8>>, AccountKeyStoreError> {
            let length = |field: &str| {
                if $postgres {
                    format!("octet_length({field})::bigint")
                } else {
                    format!("length(CAST({field} AS BLOB))")
                }
            };
            let mut metadata = QueryBuilder::<$db>::new(format!(
                "SELECT revision, {} AS put_bytes, {} AS signing_bytes, {} AS kem_bytes, \
                 {} AS recovery_bytes, {} AS signature_bytes FROM sync_account_key_bundles \
                 WHERE account_id = ",
                length("accepted_put_cbor"), length("account_signing_key"),
                length("account_kem_key"), length("recovery_blob"), length("signature"),
            ));
            let row = metadata.push_bind(account_id.as_slice()).build()
                .fetch_optional(&mut **tx).await?.ok_or(AccountKeyStoreError::BundleNotFound)?;
            let Some(put_bytes) = row.try_get::<Option<i64>, _>("put_bytes")? else {
                return Ok(None);
            };
            if !(1..=4_194_304).contains(&put_bytes)
                || row.try_get::<i64, _>("signature_bytes")? != 64
            {
                return Err(corrupt());
            }
            let revision = super::revision_from_sql(row.try_get("revision")?)?;
            let mut projection_bytes = 64_i64;
            for field in ["signing_bytes", "kem_bytes", "recovery_bytes"] {
                let size: i64 = row.try_get(field)?;
                if !(1..=65_536).contains(&size) {
                    return Err(corrupt());
                }
                projection_bytes = projection_bytes.checked_add(size).ok_or_else(corrupt)?;
            }
            let mut wraps = QueryBuilder::<$db>::new(format!(
                "SELECT {} AS device_bytes, {} AS wrap_bytes \
                 FROM sync_account_key_device_wraps WHERE account_id = ",
                length("device_id"), length("wrapped_ark"),
            ));
            let rows = wraps.push_bind(account_id.as_slice()).push(" LIMIT 1001")
                .build().fetch_all(&mut **tx).await?;
            if rows.is_empty() || rows.len() > MAX_DEVICE_WRAPS {
                return Err(corrupt());
            }
            for row in &rows {
                let size: i64 = row.try_get("wrap_bytes")?;
                if row.try_get::<i64, _>("device_bytes")? != 16 || !(1..=65_536).contains(&size) {
                    return Err(corrupt());
                }
                projection_bytes = projection_bytes.checked_add(size + 16).ok_or_else(corrupt)?;
            }
            if projection_bytes > put_bytes {
                return Err(corrupt());
            }

            // Load only the admitted PUT. Projection bytes are compared inside SQL, never
            // materialized from a damaged database into an unbounded application collection.
            let mut body = QueryBuilder::<$db>::new(
                "SELECT substr(accepted_put_cbor, 1, 4194305) AS accepted_put_cbor \
                 FROM sync_account_key_bundles WHERE account_id = ",
            );
            let row = body.push_bind(account_id.as_slice()).build().fetch_one(&mut **tx).await?;
            let bytes: Vec<u8> = row.try_get("accepted_put_cbor")?;
            let update = SyncAccountKeyBundleUpdate::from_cbor(&bytes).map_err(|_| corrupt())?;
            if i64::try_from(bytes.len()).ok() != Some(put_bytes)
                || update.to_cbor().map_err(|_| corrupt())? != bytes
                || update.revision != revision
                || update.device_wraps.len() != rows.len()
            {
                return Err(corrupt());
            }
            let mut fields = QueryBuilder::<$db>::new(
                "SELECT COUNT(*) FROM sync_account_key_bundles WHERE account_id = ",
            );
            fields.push_bind(account_id.as_slice())
                .push(" AND revision = ").push_bind(super::revision_to_sql(update.revision)?)
                .push(" AND account_signing_key = ").push_bind(&update.account_signing_key)
                .push(" AND account_kem_key = ").push_bind(&update.account_kem_key)
                .push(" AND recovery_blob = ").push_bind(&update.recovery_blob)
                .push(" AND signature = ").push_bind(&update.signature);
            if fields.build_query_scalar::<i64>().fetch_one(&mut **tx).await? != 1 {
                return Err(corrupt());
            }
            let mut matches = QueryBuilder::<$db>::new(
                "WITH expected(device_id, wrapped_ark) AS (",
            );
            matches.push_values(&update.device_wraps, |mut row, wrap| {
                row.push_bind(wrap.device_id.as_bytes().as_slice()).push_bind(&wrap.wrapped_ark);
            });
            matches.push(
                ") SELECT COUNT(*) FROM sync_account_key_device_wraps AS actual \
                 JOIN expected ON actual.device_id = expected.device_id \
                 AND actual.wrapped_ark = expected.wrapped_ark WHERE actual.account_id = ",
            ).push_bind(account_id.as_slice());
            if matches.build_query_scalar::<i64>().fetch_one(&mut **tx).await?
                != i64::try_from(update.device_wraps.len()).map_err(|_| corrupt())?
            {
                return Err(corrupt());
            }
            Ok(Some(bytes))
        }
    };
}

accepted_put_reader!(SqliteStore, Sqlite, read_sqlite_accepted_put, false);
accepted_put_reader!(PostgresStore, Postgres, read_postgres_accepted_put, true);
