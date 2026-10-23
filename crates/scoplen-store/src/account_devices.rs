// SPDX-License-Identifier: AGPL-3.0-only
//! Complete signed device statements read with current account authorization.

use std::collections::BTreeSet;

use futures_util::TryStreamExt as _;
use scoplen_api::account_devices::{
    AccountDeviceStatements, MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES, MAX_ACCOUNT_DEVICE_DECODED_BYTES,
};
use scoplen_crypto::{DeviceCertificate, RevocationStatement};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::{
    PostgresStore, SqliteStore,
    device_authentication::{
        CurrentPrincipal, DeviceAuthenticationError, load_postgres_principal,
        load_sqlite_principal, lock_postgres_account_key_state,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum StatementKind {
    Certificate,
    Revocation,
}

impl StatementKind {
    fn query(self, postgres: bool) -> String {
        let (table, field) = match self {
            Self::Certificate => ("sync_account_key_certificates", "certificate"),
            Self::Revocation => ("sync_account_key_revocations", "revocation"),
        };
        let (length, parameter) = if postgres { ("octet_length", "$1") } else { ("length", "?") };
        // A corrupt oversized blob must not be transferred before its size is checked.
        format!(
            "SELECT CASE WHEN {length}({field}) BETWEEN 1 AND {MAX_ACCOUNT_DEVICE_ARTIFACT_BYTES}
             THEN {field} END AS artifact FROM {table} WHERE account_id={parameter}
             ORDER BY {field}"
        )
    }

    fn check(self, bytes: &[u8], total: &mut usize) -> Result<(), DeviceAuthenticationError> {
        *total = total.checked_add(bytes.len()).ok_or(DeviceAuthenticationError::Database)?;
        if *total > MAX_ACCOUNT_DEVICE_DECODED_BYTES {
            return Err(DeviceAuthenticationError::Database);
        }
        match self {
            Self::Certificate => DeviceCertificate::decode(bytes).map(|_| ()),
            Self::Revocation => RevocationStatement::decode(bytes).map(|_| ()),
        }
        .map_err(|_| DeviceAuthenticationError::Database)
    }
}

pub(crate) async fn sqlite_statements(
    tx: &mut Transaction<'_, Sqlite>,
    account_id: &[u8],
    kind: StatementKind,
    total: &mut usize,
) -> Result<Vec<Vec<u8>>, DeviceAuthenticationError> {
    let query = kind.query(false);
    let mut rows = sqlx::query(&query).bind(account_id).fetch(&mut **tx);
    let mut statements = Vec::new();
    while let Some(row) = rows.try_next().await? {
        let bytes: Vec<u8> = row.try_get("artifact")?;
        kind.check(&bytes, total)?;
        statements.push(bytes);
    }
    Ok(statements)
}

pub(crate) async fn postgres_statements(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &[u8],
    kind: StatementKind,
    total: &mut usize,
) -> Result<Vec<Vec<u8>>, DeviceAuthenticationError> {
    let query = kind.query(true);
    let mut rows = sqlx::query(&query).bind(account_id).fetch(&mut **tx);
    let mut statements = Vec::new();
    while let Some(row) = rows.try_next().await? {
        let bytes: Vec<u8> = row.try_get("artifact")?;
        kind.check(&bytes, total)?;
        statements.push(bytes);
    }
    Ok(statements)
}

fn current_identity(
    current: Option<CurrentPrincipal>,
    expected: &CurrentPrincipal,
) -> Result<(), DeviceAuthenticationError> {
    let current = current.ok_or(DeviceAuthenticationError::Denied { changed: false })?;
    if current.account_id != expected.account_id
        || current.device_id != expected.device_id
        || current.jkt != expected.jkt
    {
        return Err(DeviceAuthenticationError::Denied { changed: false });
    }
    Ok(())
}

fn verified_snapshot(
    expected: &CurrentPrincipal,
    key: Vec<u8>,
    certificates: Vec<Vec<u8>>,
    revocations: Vec<Vec<u8>>,
) -> Result<AccountDeviceStatements, DeviceAuthenticationError> {
    let key: [u8; 32] = key.try_into().map_err(|_| DeviceAuthenticationError::Database)?;
    let mut ids = BTreeSet::new();
    for bytes in &certificates {
        let certificate =
            DeviceCertificate::decode(bytes).map_err(|_| DeviceAuthenticationError::Database)?;
        certificate.verify(&key).map_err(|_| DeviceAuthenticationError::Database)?;
        if certificate.account_id.into_bytes() != expected.account_id
            || !ids.insert(certificate.device_id)
        {
            return Err(DeviceAuthenticationError::Database);
        }
    }
    if !ids.contains(&Uuid::from_bytes(expected.device_id)) {
        return Err(DeviceAuthenticationError::Database);
    }
    ids.clear();
    for bytes in &revocations {
        let statement =
            RevocationStatement::decode(bytes).map_err(|_| DeviceAuthenticationError::Database)?;
        statement.verify(&key).map_err(|_| DeviceAuthenticationError::Database)?;
        if !ids.insert(statement.device_id) {
            return Err(DeviceAuthenticationError::Database);
        }
    }
    AccountDeviceStatements::new(Uuid::from_bytes(expected.account_id), certificates, revocations)
        .map_err(|_| DeviceAuthenticationError::Database)
}

impl SqliteStore {
    /// Read every signed statement in the same snapshot as current caller authorization.
    ///
    /// # Errors
    /// Returns a denial for stale caller identity, or a disclosure-free storage error for a
    /// missing key bundle, corrupt/oversized set, or unavailable database.
    pub async fn read_account_device_statements(
        &self,
        expected: &CurrentPrincipal,
    ) -> Result<AccountDeviceStatements, DeviceAuthenticationError> {
        let mut tx = self.pool.begin().await?;
        current_identity(load_sqlite_principal(&mut tx, expected.device_id).await?, expected)?;
        let key = sqlx::query_scalar(
            "SELECT a.account_signing_public_key FROM identity_accounts AS a
             JOIN sync_account_key_bundles AS b ON b.account_id=a.account_id
             WHERE a.account_id=?",
        )
        .bind(expected.account_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(DeviceAuthenticationError::Database)?;
        let mut total = 0;
        let certificates = sqlite_statements(
            &mut tx,
            &expected.account_id,
            StatementKind::Certificate,
            &mut total,
        )
        .await?;
        let revocations =
            sqlite_statements(&mut tx, &expected.account_id, StatementKind::Revocation, &mut total)
                .await?;
        let result = verified_snapshot(expected, key, certificates, revocations)?;
        tx.commit().await?;
        Ok(result)
    }
}

impl PostgresStore {
    /// Read every signed statement while holding the account-key and current-identity locks.
    ///
    /// # Errors
    /// Returns a denial for stale caller identity, or a disclosure-free storage error for a
    /// missing key bundle, corrupt/oversized set, or unavailable database.
    pub async fn read_account_device_statements(
        &self,
        expected: &CurrentPrincipal,
    ) -> Result<AccountDeviceStatements, DeviceAuthenticationError> {
        let mut tx = self.pool.begin().await?;
        lock_postgres_account_key_state(&mut tx, &expected.account_id).await?;
        current_identity(
            load_postgres_principal(&mut tx, expected.device_id, true).await?,
            expected,
        )?;
        let key = sqlx::query_scalar(
            "SELECT a.account_signing_public_key FROM identity_accounts AS a
             JOIN sync_account_key_bundles AS b ON b.account_id=a.account_id
             WHERE a.account_id=$1",
        )
        .bind(expected.account_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(DeviceAuthenticationError::Database)?;
        let mut total = 0;
        let certificates = postgres_statements(
            &mut tx,
            &expected.account_id,
            StatementKind::Certificate,
            &mut total,
        )
        .await?;
        let revocations = postgres_statements(
            &mut tx,
            &expected.account_id,
            StatementKind::Revocation,
            &mut total,
        )
        .await?;
        let result = verified_snapshot(expected, key, certificates, revocations)?;
        tx.commit().await?;
        Ok(result)
    }
}
