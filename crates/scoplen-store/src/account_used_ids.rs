// SPDX-License-Identifier: AGPL-3.0-only
//! Deployment-lifetime Account-id retention, independent of ordinary Account state.

use std::time::{SystemTime, UNIX_EPOCH};

use scoplen_crypto::account_used_id_digest;
use sqlx::{Postgres, QueryBuilder, Row, Sqlite, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    audit::AuditStoreError,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
};

/// Default admitted number of permanent, 32-byte Account-id digests.
pub const DEFAULT_ACCOUNT_ID_CEILING: u64 = 1_048_576;

/// Content-free capacity warning for the deployment operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountIdPressure {
    /// Less than ninety percent of the admitted ceiling is used.
    Normal,
    /// At least ninety percent is used, with room for another registration.
    Warning,
    /// Only new registrations are blocked by this ceiling.
    Exhausted,
}

/// Durable capacity and explicit maintenance state; contains no Account identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountIdRetentionSummary {
    /// Number of retained digests.
    pub used: u64,
    /// Admitted deployment-wide ceiling.
    pub ceiling: u64,
    /// Registration writers are quiesced for explicit retention maintenance.
    pub maintenance: bool,
    /// Fixed non-identifying pressure classification.
    pub pressure: AccountIdPressure,
}

/// Retention failures, without identifying the conflicting Account or stored digest.
#[derive(Debug, Error)]
pub enum AccountIdRetentionError {
    /// An id or ceiling violates the fixed contract or checked size bound.
    #[error("Account retention configuration is invalid")]
    InvalidConfiguration,
    /// An instance supplied a ceiling different from the durable admitted value.
    #[error("Account retention configuration differs from its admitted ceiling")]
    ConfigurationMismatch,
    /// The explicit upgrade reservation has not committed.
    #[error("Account retention has not been initialized")]
    NotInitialized,
    /// The current maintenance state does not permit this operation.
    #[error("Account retention maintenance state does not permit this operation")]
    Maintenance,
    /// The Account-id digest was already retained.
    #[error("Account registration identity conflicts")]
    Conflict,
    /// The single required new digest would exceed the admitted ceiling.
    #[error("Account registration retention capacity is exhausted")]
    QuotaExceeded,
    /// Persisted metadata or an existing Account id cannot be validated.
    #[error("Account retention state is inconsistent")]
    Integrity,
    /// A valid timestamp for the mandatory maintenance audit is unavailable.
    #[error("Account retention clock is unavailable")]
    Clock,
    /// A relational operation failed.
    #[error("Account retention storage is unavailable")]
    Storage(#[from] sqlx::Error),
    /// The mandatory deployment audit could not be appended.
    #[error("Account retention audit is unavailable")]
    Audit(#[from] AuditStoreError),
    /// A maintenance COMMIT was sent without a confirmed result.
    #[error("Account retention commit outcome is unknown")]
    CommitOutcomeUnknown,
}

struct Guard {
    ceiling: Option<u64>,
    maintenance: bool,
    used: u64,
}

impl Guard {
    fn summary(&self) -> Result<AccountIdRetentionSummary, AccountIdRetentionError> {
        let ceiling = self.ceiling.ok_or(AccountIdRetentionError::NotInitialized)?;
        validate_ceiling(ceiling).map_err(|_| AccountIdRetentionError::Integrity)?;
        if self.used > ceiling {
            return Err(AccountIdRetentionError::Integrity);
        }
        let pressure = if self.used == ceiling {
            AccountIdPressure::Exhausted
        } else if self.used >= ceiling - ceiling / 10 {
            AccountIdPressure::Warning
        } else {
            AccountIdPressure::Normal
        };
        Ok(AccountIdRetentionSummary {
            used: self.used,
            ceiling,
            maintenance: self.maintenance,
            pressure,
        })
    }

    fn check_ceiling(&self, expected: u64) -> Result<(), AccountIdRetentionError> {
        validate_ceiling(expected)?;
        if self.summary()?.ceiling != expected {
            return Err(AccountIdRetentionError::ConfigurationMismatch);
        }
        Ok(())
    }
}

fn validate_ceiling(ceiling: u64) -> Result<(), AccountIdRetentionError> {
    if ceiling == 0 || ceiling.checked_mul(32).is_none() {
        return Err(AccountIdRetentionError::InvalidConfiguration);
    }
    Ok(())
}

fn audit_event(kind: u8, summary: AccountIdRetentionSummary) -> Vec<u8> {
    let mut bytes = b"spl-account-id-retention-v1".to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(&summary.used.to_be_bytes());
    bytes.extend_from_slice(&summary.ceiling.to_be_bytes());
    bytes.push(u8::from(summary.maintenance));
    bytes
}

fn now_ms() -> Result<i64, AccountIdRetentionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_millis()).ok())
        .filter(|time| *time > 0)
        .ok_or(AccountIdRetentionError::Clock)
}

async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<Transaction<'_, Sqlite>, AccountIdRetentionError> {
    Ok(store.pool().begin_with("BEGIN IMMEDIATE").await?)
}

async fn postgres_begin(
    store: &PostgresStore,
) -> Result<Transaction<'_, Postgres>, AccountIdRetentionError> {
    Ok(store.pool().begin().await?)
}

macro_rules! retention_store {
    ($store:ty, $db:ty, $begin:ident, $read:ident, $insert:ident, $reserve:ident,
     $append:ident, $postgres:literal) => {
        impl $store {
            /// Admit a ceiling and reserve all current Account ids before enabling registration.
            ///
            /// The first call is an upgrade transaction: bounded pages reserve every existing
            /// identity and commit with mandatory audit. All deployed registration writers must
            /// use this boundary before accepting new Accounts. Later calls require exactly the
            /// already admitted ceiling and never reset maintenance or evict retained digests.
            /// This does not mount a registration endpoint or migrate credentials.
            ///
            /// # Errors
            /// Fails closed on capacity, invalid legacy ids, configuration drift, missing guards,
            /// storage/audit failures or an unconfirmed initialization commit.
            pub async fn initialize_account_id_retention(
                &self,
                ceiling: u64,
            ) -> Result<AccountIdRetentionSummary, AccountIdRetentionError> {
                validate_ceiling(ceiling)?;
                let mut tx = $begin(self).await?;
                let mut guard = $read(&mut tx).await?;
                if guard.ceiling.is_some() {
                    guard.check_ceiling(ceiling)?;
                    let summary = guard.summary()?;
                    tx.commit().await?;
                    return Ok(summary);
                }
                if guard.used != 0 || !guard.maintenance {
                    return Err(AccountIdRetentionError::Integrity);
                }
                if $postgres {
                    sqlx::query("LOCK TABLE identity_accounts IN SHARE ROW EXCLUSIVE MODE")
                        .execute(&mut *tx).await?;
                }
                let mut update = QueryBuilder::<$db>::new(
                    "UPDATE account_id_retention_guard SET row_ceiling = ",
                );
                update.push_bind(i64::try_from(ceiling)
                    .map_err(|_| AccountIdRetentionError::InvalidConfiguration)?)
                    .push(" WHERE singleton = 1").build().execute(&mut *tx).await?;
                guard.ceiling = Some(ceiling);
                let mut after: Option<Vec<u8>> = None;
                loop {
                    let rows = {
                        let mut page = QueryBuilder::<$db>::new(
                            "SELECT account_id FROM identity_accounts",
                        );
                        if let Some(after) = &after {
                            page.push(" WHERE account_id > ").push_bind(after);
                        }
                        page.push(" ORDER BY account_id LIMIT 256").build()
                            .fetch_all(&mut *tx).await?
                    };
                    if rows.is_empty() { break; }
                    for row in rows {
                        let bytes: Vec<u8> = row.try_get("account_id")
                            .map_err(|_| AccountIdRetentionError::Integrity)?;
                        let id = Uuid::from_slice(&bytes)
                            .map_err(|_| AccountIdRetentionError::Integrity)?;
                        let digest = account_used_id_digest(id)
                            .map_err(|_| AccountIdRetentionError::Integrity)?;
                        $insert(&mut tx, &mut guard, &digest).await?;
                        after = Some(bytes);
                    }
                }
                sqlx::query(
                    "UPDATE account_id_retention_guard SET maintenance = FALSE WHERE singleton = 1",
                ).execute(&mut *tx).await?;
                guard.maintenance = false;
                let summary = guard.summary()?;
                $append(&mut tx, &audit_event(1, summary), now_ms()?).await?;
                tx.commit().await.map_err(|_| AccountIdRetentionError::CommitOutcomeUnknown)?;
                Ok(summary)
            }

            /// Read pressure without changing or replenishing the admitted retention budget.
            ///
            /// # Errors
            /// Rejects uninitialized/corrupt state and storage failures.
            pub async fn account_id_retention_summary(
                &self,
            ) -> Result<AccountIdRetentionSummary, AccountIdRetentionError> {
                let mut tx = $begin(self).await?;
                let summary = $read(&mut tx).await?.summary()?;
                tx.commit().await?;
                Ok(summary)
            }

            /// Explicitly quiesce or resume registration writers, with mandatory audit.
            ///
            /// This is a trusted storage operation, not an authenticated operator endpoint.
            /// # Errors
            /// Rejects stale configuration, corrupt state and unavailable or uncertain commits.
            pub async fn set_account_id_retention_maintenance(
                &self,
                expected_ceiling: u64,
                maintenance: bool,
            ) -> Result<AccountIdRetentionSummary, AccountIdRetentionError> {
                let mut tx = $begin(self).await?;
                let mut guard = $read(&mut tx).await?;
                guard.check_ceiling(expected_ceiling)?;
                if guard.maintenance == maintenance {
                    let summary = guard.summary()?;
                    tx.commit().await?;
                    return Ok(summary);
                }
                let mut update = QueryBuilder::<$db>::new(
                    "UPDATE account_id_retention_guard SET maintenance = ",
                );
                update.push_bind(maintenance).push(" WHERE singleton = 1")
                    .build().execute(&mut *tx).await?;
                guard.maintenance = maintenance;
                let summary = guard.summary()?;
                $append(&mut tx, &audit_event(2, summary), now_ms()?).await?;
                tx.commit().await.map_err(|_| AccountIdRetentionError::CommitOutcomeUnknown)?;
                Ok(summary)
            }

            /// Raise the durable ceiling during explicit registration maintenance.
            ///
            /// No digest is removed and no automatic growth occurs. Other Account operations
            /// do not use this registration-only guard.
            /// # Errors
            /// Rejects missing maintenance, decreases, stale configuration or failed audit/commit.
            pub async fn increase_account_id_retention_ceiling(
                &self,
                expected_ceiling: u64,
                ceiling: u64,
            ) -> Result<AccountIdRetentionSummary, AccountIdRetentionError> {
                validate_ceiling(ceiling)?;
                let mut tx = $begin(self).await?;
                let mut guard = $read(&mut tx).await?;
                guard.check_ceiling(expected_ceiling)?;
                if !guard.maintenance {
                    return Err(AccountIdRetentionError::Maintenance);
                }
                if ceiling < expected_ceiling {
                    return Err(AccountIdRetentionError::InvalidConfiguration);
                }
                if ceiling == expected_ceiling {
                    let summary = guard.summary()?;
                    tx.commit().await?;
                    return Ok(summary);
                }
                let mut update = QueryBuilder::<$db>::new(
                    "UPDATE account_id_retention_guard SET row_ceiling = ",
                );
                update.push_bind(i64::try_from(ceiling)
                    .map_err(|_| AccountIdRetentionError::InvalidConfiguration)?)
                    .push(" WHERE singleton = 1").build().execute(&mut *tx).await?;
                guard.ceiling = Some(ceiling);
                let summary = guard.summary()?;
                $append(&mut tx, &audit_event(3, summary), now_ms()?).await?;
                tx.commit().await.map_err(|_| AccountIdRetentionError::CommitOutcomeUnknown)?;
                Ok(summary)
            }
        }

        /// Reserve one new Account-id digest inside the registration business/audit transaction.
        ///
        /// Call before acquiring Account/vault locks. The shared guard serializes capacity across
        /// instances. The caller must atomically create the verified Account, receipt and audit,
        /// and disclose no success until COMMIT is confirmed. Never call for Device admission or
        /// historical confirmation. This helper neither authorizes registration nor commits.
        ///
        /// # Errors
        /// Rejects invalid ids, stale configuration, maintenance, reused ids, capacity or storage.
        pub async fn $reserve(
            tx: &mut Transaction<'_, $db>,
            account_id: Uuid,
            expected_ceiling: u64,
        ) -> Result<AccountIdRetentionSummary, AccountIdRetentionError> {
            let digest = account_used_id_digest(account_id)
                .map_err(|_| AccountIdRetentionError::InvalidConfiguration)?;
            let mut guard = $read(tx).await?;
            guard.check_ceiling(expected_ceiling)?;
            if guard.maintenance { return Err(AccountIdRetentionError::Maintenance); }
            $insert(tx, &mut guard, &digest).await?;
            guard.summary()
        }

        async fn $read(
            tx: &mut Transaction<'_, $db>,
        ) -> Result<Guard, AccountIdRetentionError> {
            // Reserve SQLite's writer and version the PostgreSQL guard, so a stale
            // repeatable-read snapshot fails before it can reuse the final capacity slot.
            sqlx::query(
                "UPDATE account_id_retention_guard SET maintenance = maintenance WHERE singleton = 1",
            ).execute(&mut **tx).await?;
            let mut query = QueryBuilder::<$db>::new(
                "SELECT row_ceiling, maintenance FROM account_id_retention_guard WHERE singleton = 1",
            );
            if $postgres { query.push(" FOR UPDATE"); }
            let row = query.build().fetch_optional(&mut **tx).await?
                .ok_or(AccountIdRetentionError::Integrity)?;
            let ceiling = row.try_get::<Option<i64>, _>("row_ceiling")?
                .map(|value| u64::try_from(value).map_err(|_| AccountIdRetentionError::Integrity))
                .transpose()?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_used_ids")
                .fetch_one(&mut **tx).await?;
            let guard = Guard {
                ceiling,
                maintenance: row.try_get("maintenance")?,
                used: u64::try_from(count).map_err(|_| AccountIdRetentionError::Integrity)?,
            };
            if guard.ceiling.is_some() { guard.summary()?; }
            Ok(guard)
        }

        async fn $insert(
            tx: &mut Transaction<'_, $db>,
            guard: &mut Guard,
            digest: &[u8; 32],
        ) -> Result<(), AccountIdRetentionError> {
            let mut existing = QueryBuilder::<$db>::new(
                "SELECT COUNT(*) FROM account_used_ids WHERE digest = ",
            );
            let count: i64 = existing.push_bind(digest.as_slice()).build_query_scalar()
                .fetch_one(&mut **tx).await?;
            if count != 0 { return Err(AccountIdRetentionError::Conflict); }
            let next = guard.used.checked_add(1).ok_or(AccountIdRetentionError::Integrity)?;
            if next > guard.summary()?.ceiling {
                return Err(AccountIdRetentionError::QuotaExceeded);
            }
            let mut insert = QueryBuilder::<$db>::new("INSERT INTO account_used_ids (digest) VALUES (");
            insert.push_bind(digest.as_slice()).push(")").build().execute(&mut **tx).await?;
            guard.used = next;
            Ok(())
        }
    };
}

retention_store!(
    SqliteStore,
    Sqlite,
    sqlite_begin,
    sqlite_guard,
    sqlite_insert,
    reserve_sqlite_account_id,
    append_deployment_audit_event_in_transaction,
    false
);
retention_store!(
    PostgresStore,
    Postgres,
    postgres_begin,
    postgres_guard,
    postgres_insert,
    reserve_postgres_account_id,
    append_deployment_audit_event_in_postgres_transaction,
    true
);
