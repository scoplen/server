// SPDX-License-Identifier: AGPL-3.0-only
//! Current-account reads bound to the genuine Device or Account-browser actor.

use std::fmt::Write as _;

use scoplen_api::account_profile::AccountProfile;
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    PostgresStore, SqliteStore,
    device_authentication::{DeviceAuthenticationError, lock_postgres_account_key_state},
    organizations::{OrganizationPrincipal, OrganizationStoreError, postgres_actor, sqlite_actor},
};

fn representation(
    account_id: [u8; 16],
    created_at_ms: i64,
    email: Option<String>,
) -> Result<AccountProfile, DeviceAuthenticationError> {
    if created_at_ms <= 0 {
        return Err(DeviceAuthenticationError::Database);
    }
    let created_at =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(created_at_ms) * 1_000_000)
            .ok()
            .and_then(|value| value.format(&Rfc3339).ok())
            .ok_or(DeviceAuthenticationError::Database)?;
    // Profiles currently have no mutation operation: both timestamps describe enrollment.
    let mut profile = AccountProfile::new(
        Uuid::from_bytes(account_id),
        "\"pending\"",
        created_at.clone(),
        created_at,
        email,
    )
    .map_err(|_| DeviceAuthenticationError::Database)?;
    // Hash the canonical representation with a fixed ETag slot to avoid self-reference.
    let mut hash = Sha256::new();
    hash.update(b"scoplen-account-profile-v1\0");
    hash.update(profile.to_json().map_err(|_| DeviceAuthenticationError::Database)?);
    let mut etag = String::from("\"sha256-");
    for byte in hash.finalize() {
        write!(etag, "{byte:02x}").expect("write to String");
    }
    etag.push('"');
    profile.etag = etag;
    profile.to_json().map_err(|_| DeviceAuthenticationError::Database)?;
    Ok(profile)
}

impl SqliteStore {
    /// Read only the authenticated actor's account after transaction-local authorization checks.
    ///
    /// # Errors
    /// Returns a disclosure-free error for stale identity, missing/corrupt state, or storage failure.
    pub async fn read_account_profile(
        &self,
        expected: &impl OrganizationPrincipal,
    ) -> Result<AccountProfile, DeviceAuthenticationError> {
        let mut tx = self.pool.begin().await?;
        sqlite_actor(&mut tx, expected, u64::MAX).await.map_err(actor_error)?;
        let row = sqlx::query(
            "SELECT created_at_ms,
             CASE WHEN length(CAST(email AS BLOB)) <= 320 THEN email
                  WHEN email IS NULL THEN NULL ELSE '' END AS email
             FROM identity_accounts WHERE account_id=?",
        )
        .bind(expected.account_id().as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(DeviceAuthenticationError::Database)?;
        let profile = representation(
            expected.account_id(),
            row.try_get("created_at_ms")?,
            row.try_get("email")?,
        )?;
        sqlite_actor(&mut tx, expected, u64::MAX).await.map_err(actor_error)?;
        tx.commit().await?;
        Ok(profile)
    }
}

impl PostgresStore {
    /// Read only the authenticated actor's account while holding current-key and identity locks.
    ///
    /// # Errors
    /// Returns a disclosure-free error for stale identity, missing/corrupt state, or storage failure.
    pub async fn read_account_profile(
        &self,
        expected: &impl OrganizationPrincipal,
    ) -> Result<AccountProfile, DeviceAuthenticationError> {
        let mut tx = self.pool.begin().await?;
        lock_postgres_account_key_state(&mut tx, &expected.account_id()).await?;
        postgres_actor(&mut tx, expected, u64::MAX).await.map_err(actor_error)?;
        let row = sqlx::query(
            "SELECT created_at_ms,
             CASE WHEN octet_length(email) <= 320 THEN email
                  WHEN email IS NULL THEN NULL ELSE '' END AS email
             FROM identity_accounts WHERE account_id=$1",
        )
        .bind(expected.account_id().as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(DeviceAuthenticationError::Database)?;
        let profile = representation(
            expected.account_id(),
            row.try_get("created_at_ms")?,
            row.try_get("email")?,
        )?;
        postgres_actor(&mut tx, expected, u64::MAX).await.map_err(actor_error)?;
        tx.commit().await?;
        Ok(profile)
    }
}

fn actor_error(error: OrganizationStoreError) -> DeviceAuthenticationError {
    match error {
        OrganizationStoreError::AuthenticationRequired => {
            DeviceAuthenticationError::Denied { changed: false }
        }
        _ => DeviceAuthenticationError::Database,
    }
}
