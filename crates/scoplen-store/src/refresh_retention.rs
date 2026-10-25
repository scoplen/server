// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded retirement of expired device and independent Operator refresh credentials.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::Row;
use thiserror::Error;

use crate::{PostgresStore, SqliteStore};

const FAMILY_LIMIT: i64 = 16;
const TOKEN_LIMIT: u64 = 256;

/// Confirmed removals from one atomic refresh-retention pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RefreshCleanupReport {
    /// Expired device-family token digests removed, at most 256.
    pub device_tokens: u64,
    /// Empty expired device families removed, at most 16.
    pub device_families: u64,
    /// Expired Operator-family token digests removed, at most 256.
    pub operator_tokens: u64,
    /// Empty expired Operator families removed, at most 16.
    pub operator_families: u64,
}

/// Fixed, content-free refresh-retention failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum RefreshCleanupError {
    #[error("refresh retention storage unavailable")]
    Database,
    #[error("refresh retention trusted clock unavailable")]
    Clock,
    #[error("refresh retention commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for RefreshCleanupError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

fn now_ms() -> Result<i64, RefreshCleanupError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or(RefreshCleanupError::Clock)
}

#[derive(Clone, Copy)]
enum PrincipalKind {
    Device,
    Operator,
}

impl PrincipalKind {
    fn tables(self) -> (&'static str, &'static str) {
        match self {
            Self::Device => ("device_refresh_families", "device_refresh_tokens"),
            Self::Operator => ("operator_refresh_families", "operator_refresh_tokens"),
        }
    }
}

macro_rules! retention_store {
    ($module:ident, $store:ty, $db:ty, $begin:expr, $lock:expr, $suffix:literal) => {
        mod $module {
            use super::*;

            async fn retire(
                tx: &mut sqlx::Transaction<'_, $db>,
                kind: PrincipalKind,
                clock: &impl Fn() -> Result<i64, RefreshCleanupError>,
            ) -> Result<(u64, u64), RefreshCleanupError> {
                let (families, tokens) = kind.tables();
                // The first clock only selects indexed candidates. Recheck expiry after the
                // family locks, in the same family-before-token order used by refresh.
                let rows = sqlx::query::<$db>(&format!(
                    "SELECT family_id, expires_at_ms FROM {families} WHERE expires_at_ms <= $1 \
                     ORDER BY expires_at_ms LIMIT {FAMILY_LIMIT}{}", $suffix
                ))
                .bind(clock()?)
                .fetch_all(&mut **tx)
                .await?;
                let now = clock()?;
                let mut removed_tokens = 0;
                let mut removed_families = 0;
                for row in rows {
                    if row.try_get::<i64, _>("expires_at_ms")? > now {
                        continue;
                    }
                    let family: Vec<u8> = row.try_get("family_id")?;
                    let remaining = TOKEN_LIMIT - removed_tokens;
                    if remaining > 0 {
                        removed_tokens += sqlx::query::<$db>(&format!(
                            "DELETE FROM {tokens} WHERE token_digest IN \
                             (SELECT token_digest FROM {tokens} WHERE family_id=$1 LIMIT $2)"
                        ))
                        .bind(&family)
                        .bind(i64::try_from(remaining).map_err(|_| RefreshCleanupError::Database)?)
                        .execute(&mut **tx)
                        .await?
                        .rows_affected();
                    }
                    // Deleting only empty families makes ON DELETE CASCADE unable to bypass
                    // the digest-row budget, even for a heavily rotated expired family.
                    removed_families += sqlx::query::<$db>(&format!(
                        "DELETE FROM {families} WHERE family_id=$1 AND expires_at_ms <= $2 \
                         AND NOT EXISTS (SELECT 1 FROM {tokens} WHERE family_id=$1)"
                    ))
                    .bind(&family)
                    .bind(now)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected();
                }
                Ok((removed_tokens, removed_families))
            }

            pub(super) async fn cleanup(
                store: &$store,
                clock: impl Fn() -> Result<i64, RefreshCleanupError>,
            ) -> Result<RefreshCleanupReport, RefreshCleanupError> {
                let mut tx = ($begin)(store).await?;
                ($lock)(&mut tx).await?;
                let result = async {
                    let (device_tokens, device_families) =
                        retire(&mut tx, PrincipalKind::Device, &clock).await?;
                    let (operator_tokens, operator_families) =
                        retire(&mut tx, PrincipalKind::Operator, &clock).await?;
                    Ok::<_, RefreshCleanupError>(RefreshCleanupReport {
                        device_tokens,
                        device_families,
                        operator_tokens,
                        operator_families,
                    })
                }
                .await;
                match result {
                    Ok(report) if report == RefreshCleanupReport::default() => {
                        tx.rollback().await?;
                        Ok(report)
                    }
                    Ok(report) => {
                        tx.commit().await.map_err(|_| RefreshCleanupError::CommitOutcomeUnknown)?;
                        Ok(report)
                    }
                    Err(error) => {
                        tx.rollback().await?;
                        Err(error)
                    }
                }
            }
        }

        impl $store {
            /// Retire one bounded batch of expired device and Operator refresh credentials.
            ///
            /// Each principal kind examines at most 16 expired families and removes at most
            /// 256 digests and 16 empty families. All unexpired families, including revoked
            /// families and spent digests, remain intact. Both kinds commit atomically.
            ///
            /// # Errors
            /// Returns a fixed storage, clock or unconfirmed-commit error. Counts are returned
            /// only after a confirmed commit; no credential or principal data is exposed.
            pub async fn cleanup_refresh_families(
                &self,
            ) -> Result<RefreshCleanupReport, RefreshCleanupError> {
                $module::cleanup(self, now_ms).await
            }
        }
    };
}

retention_store!(
    sqlite,
    SqliteStore,
    sqlx::Sqlite,
    crate::operator_sessions::sqlite_begin,
    crate::operator_sessions::sqlite_lock,
    ""
);
retention_store!(
    postgres,
    PostgresStore,
    sqlx::Postgres,
    crate::operator_sessions::postgres_begin,
    crate::operator_sessions::postgres_lock,
    " FOR UPDATE"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RelationalStore;
    use std::cell::Cell;

    #[tokio::test]
    async fn exact_expiry_and_post_lock_clock_reversal_preserve_retention_boundary() {
        let directory =
            std::env::temp_dir().join(format!("scoplen-refresh-clock-{}", uuid::Uuid::now_v7()));
        let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
        let principal = [1_u8; 16];
        sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
            .bind(principal.as_slice()).bind([1_u8;32].as_slice()).execute(store.pool()).await.expect("account");
        sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES ($1,$1,$2,1,1)")
            .bind(principal.as_slice()).bind([1_u8].as_slice()).execute(store.pool()).await.expect("device");
        sqlx::query(
            "INSERT INTO deployment_operators (operator_id,active,created_at_s) VALUES ($1,1,1)",
        )
        .bind(principal.as_slice())
        .execute(store.pool())
        .await
        .expect("operator");
        sqlx::query("INSERT INTO operator_credentials (credential_id,operator_id,user_handle,trusted_origin,rp_id,credential_version,credential_state,active,created_at_s) VALUES ($1,$1,$1,'https://refresh.example.test','refresh.example.test',1,$2,1,1)")
            .bind(principal.as_slice()).bind([1_u8].as_slice()).execute(store.pool()).await.expect("credential");
        let boundary = 10_000_000_000_i64;
        for (families, tokens) in [PrincipalKind::Device.tables(), PrincipalKind::Operator.tables()]
        {
            let columns = if families.starts_with("device") {
                "account_id,device_id"
            } else {
                "operator_id,credential_id"
            };
            let tail =
                if families.starts_with("device") { "" } else { ",principal_kind,trusted_origin" };
            let values = if families.starts_with("device") {
                ""
            } else {
                ",'operator','https://refresh.example.test'"
            };
            let audience = if families.starts_with("device") { "spl-api/1" } else { "spl-admin/1" };
            sqlx::query(&format!("INSERT INTO {families} (family_id,{columns},dpop_jkt,audience,scope,created_at_ms,expires_at_ms{tail}) VALUES ($1,$1,$1,$2,$3,'test',$4,$5{values})"))
                .bind(principal.as_slice()).bind("a".repeat(43)).bind(audience)
                .bind(boundary-2_592_000_000_i64).bind(boundary)
                .execute(store.pool()).await.expect("boundary family");
            sqlx::query(&format!("INSERT INTO {tokens} (token_digest,family_id,issued_at_ms,spent_at_ms) VALUES ($1,$2,1,2)"))
                .bind([1_u8;32].as_slice()).bind(principal.as_slice())
                .execute(store.pool()).await.expect("spent boundary digest");
        }
        assert_eq!(
            sqlite::cleanup(&store, || Ok(boundary - 1)).await.expect("before expiry"),
            RefreshCleanupReport::default()
        );
        let calls = Cell::new(0);
        let reverse_after_lock = || {
            let call = calls.get();
            calls.set(call + 1);
            Ok(if call % 2 == 0 { boundary } else { boundary - 1 })
        };
        assert_eq!(
            sqlite::cleanup(&store, reverse_after_lock).await.expect("clock reversal"),
            RefreshCleanupReport::default()
        );
        assert_eq!(
            sqlite::cleanup(&store, || Ok(boundary)).await.expect("exact expiry"),
            RefreshCleanupReport {
                device_tokens: 1,
                device_families: 1,
                operator_tokens: 1,
                operator_families: 1,
            }
        );
        store.pool().close().await;
        crate::test_support::remove_test_directory(directory).await;
    }
}
