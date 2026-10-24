// SPDX-License-Identifier: AGPL-3.0-only
//! D-115 publication with request-bound identity and account state in one transaction.

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_api::sync::SyncAccountKeyBundleUpdate;
use scoplen_crypto::{DeviceCertificate, RevocationStatement, ed25519_verify, verify_device_list};
use sqlx::{Postgres, Row, Sqlite, Transaction};

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    account_devices::StatementKind,
    account_keys::{AccountKeyBundlePut, AccountKeyBundleUpdate, AccountKeyStoreError},
    device_authentication::{CurrentPrincipal, DeviceAuthenticationError},
};

fn current(
    actual: Option<CurrentPrincipal>,
    expected: &CurrentPrincipal,
) -> Result<(), AccountKeyStoreError> {
    if actual.is_some_and(|actual| {
        actual.account_id == expected.account_id
            && actual.device_id == expected.device_id
            && actual.jkt == expected.jkt
            && actual.signing_public_key == expected.signing_public_key
            && actual.certificate == expected.certificate
    }) {
        Ok(())
    } else {
        Err(AccountKeyStoreError::AuthenticationDenied)
    }
}

fn identity_error(error: &DeviceAuthenticationError) -> AccountKeyStoreError {
    match error {
        DeviceAuthenticationError::Denied { .. } => AccountKeyStoreError::AuthenticationDenied,
        _ => AccountKeyStoreError::CorruptRow("account publication identity state"),
    }
}

fn verify(
    account: [u8; 16],
    key: &[u8],
    certificates: &[Vec<u8>],
    revocations: &[Vec<u8>],
    update: &SyncAccountKeyBundleUpdate,
) -> Result<(), AccountKeyStoreError> {
    let key: [u8; 32] =
        key.try_into().map_err(|_| AccountKeyStoreError::CorruptRow("account signing root"))?;
    let certificates = certificates
        .iter()
        .map(|bytes| {
            let certificate = DeviceCertificate::decode(bytes)
                .map_err(|_| AccountKeyStoreError::CorruptRow("device certificate"))?;
            if certificate.account_id.as_bytes() != &account {
                return Err(AccountKeyStoreError::CorruptRow("certificate account binding"));
            }
            Ok(certificate)
        })
        .collect::<Result<Vec<_>, AccountKeyStoreError>>()?;
    let revocations = revocations
        .iter()
        .map(|bytes| {
            RevocationStatement::decode(bytes)
                .map_err(|_| AccountKeyStoreError::CorruptRow("device revocation"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certified = verify_device_list(&certificates, &revocations, &key)
        .map_err(|_| AccountKeyStoreError::CorruptRow("signed device statements"))?;
    let expected: BTreeSet<_> = certified.iter().map(|certificate| certificate.device_id).collect();
    let supplied: BTreeSet<_> = update.device_wraps.iter().map(|wrap| wrap.device_id).collect();
    if expected != supplied {
        return Err(AccountKeyStoreError::InvalidDeviceWraps);
    }
    ed25519_verify(
        &key,
        &update.signature_input().map_err(|_| AccountKeyStoreError::InvalidSignature)?,
        &update.signature,
    )
    .map_err(|_| AccountKeyStoreError::InvalidSignature)
}

fn now_ms() -> Result<i64, AccountKeyStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| i64::try_from(now.as_millis()).ok())
        .filter(|now| *now > 0)
        .ok_or(AccountKeyStoreError::CorruptRow("publication clock"))
}

fn live_authorization(expires_at: u64) -> Result<(), AccountKeyStoreError> {
    let issued_at = expires_at
        .checked_sub(scoplen_api::auth::ACCESS_TOKEN_EXPIRES_IN)
        .ok_or(AccountKeyStoreError::CorruptRow("publication grant lifetime"))?;
    let now = u64::try_from(now_ms()?.div_euclid(1000))
        .map_err(|_| AccountKeyStoreError::CorruptRow("publication clock"))?;
    if issued_at <= now && now < expires_at {
        Ok(())
    } else {
        Err(AccountKeyStoreError::AuthenticationDenied)
    }
}

fn audit(expected: &CurrentPrincipal, now: i64, revision: u64) -> Vec<u8> {
    let mut bytes = b"spl-account-key-publication-audit-v1".to_vec();
    bytes.extend_from_slice(&now.to_be_bytes());
    bytes.extend_from_slice(&expected.account_id);
    bytes.extend_from_slice(&expected.device_id);
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}

async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}

async fn sqlite_load(
    tx: &mut Transaction<'_, Sqlite>,
    device: [u8; 16],
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    crate::device_authentication::load_sqlite_principal(tx, device).await
}

async fn postgres_load(
    tx: &mut Transaction<'_, Postgres>,
    device: [u8; 16],
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    crate::device_authentication::load_postgres_principal(tx, device, true).await
}

macro_rules! publication {
    ($module:ident, $store:ty, $begin:ident, $load:ident, $statements:ident, $matches:ident, $capacity:ident, $append:ident, $postgres:literal) => {
        mod $module {
            use super::*;
            use crate::{account_devices::$statements, account_keys::{$matches, $capacity}, $append};

            fn sql(source: &str) -> String {
                if !$postgres { return source.to_owned(); }
                let mut parameter = 0;
                source.chars().map(|c| if c == '?' { parameter += 1; format!("${parameter}") } else { c.to_string() }).collect()
            }

            impl $store {
                /// Publish a complete signed bundle under the original authenticated binding.
                ///
                /// # Errors
                /// `expires_at` is the expiry of the original verified keys:write token.
                /// Rejects expired authority, stale identity, invalid signatures/recipients, revision conflicts,
                /// capacity or audit failures, and preserves attempted-COMMIT uncertainty.
                #[allow(clippy::too_many_lines)]
                pub async fn publish_account_key_bundle(&self, expected: &CurrentPrincipal, expires_at: u64, update: &SyncAccountKeyBundleUpdate)
                    -> Result<AccountKeyBundlePut, AccountKeyStoreError> {
                    let mut tx = $begin(self).await?;
                    let mut changed = false;
                    let result = async {
                        if $postgres {
                            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
                                .bind(expected.account_id.as_slice()).execute(&mut *tx).await?;
                        }
                        current($load(&mut tx, expected.device_id).await.map_err(|error| identity_error(&error))?, expected)?;
                        live_authorization(expires_at)?;
                        let account = expected.account_id.as_slice();
                        let query = sql("SELECT revision,account_signing_key,account_kem_key,recovery_blob,signature FROM sync_account_key_bundles WHERE account_id=?");
                        let row = sqlx::query(&query).bind(account).fetch_optional(&mut *tx).await?.ok_or(AccountKeyStoreError::BundleNotFound)?;
                        let current_revision: i64 = row.try_get("revision")?;
                        let current_revision = u64::try_from(current_revision).ok().filter(|value| *value > 0).ok_or(AccountKeyStoreError::CorruptRow("bundle revision"))?;
                        if update.revision == current_revision {
                            let stored = AccountKeyBundleUpdate::try_from(update)?;
                            if $matches(&mut tx, expected.account_id, &stored, &row).await? {
                                return Ok(AccountKeyBundlePut::Replay { revision: current_revision });
                            }
                            return Err(AccountKeyStoreError::Conflict { current_revision });
                        }
                        if current_revision.checked_add(1) != Some(update.revision) {
                            return Err(AccountKeyStoreError::Conflict { current_revision });
                        }
                        AccountKeyBundleUpdate::try_from(update)?;
                        let revision = i64::try_from(update.revision).map_err(|_| AccountKeyStoreError::RevisionExhausted)?;
                        let key: Vec<u8> = sqlx::query_scalar(&sql("SELECT account_signing_public_key FROM identity_accounts WHERE account_id=?"))
                            .bind(account).fetch_one(&mut *tx).await?;
                        let mut total = 0;
                        let certificates = $statements(&mut tx, account, StatementKind::Certificate, &mut total).await.map_err(|error| identity_error(&error))?;
                        let revocations = $statements(&mut tx, account, StatementKind::Revocation, &mut total).await.map_err(|error| identity_error(&error))?;
                        verify(expected.account_id, &key, &certificates, &revocations, update)?;
                        let now = now_ms()?;
                        sqlx::query(&sql("UPDATE sync_account_key_bundles SET revision=?,account_signing_key=?,account_kem_key=?,recovery_blob=?,signature=?,updated_at_ms=? WHERE account_id=?"))
                            .bind(revision).bind(&update.account_signing_key).bind(&update.account_kem_key).bind(&update.recovery_blob).bind(&update.signature).bind(now).bind(account).execute(&mut *tx).await?;
                        sqlx::query(&sql("DELETE FROM sync_account_key_device_wraps WHERE account_id=?")).bind(account).execute(&mut *tx).await?;
                        for wrap in &update.device_wraps {
                            sqlx::query(&sql("INSERT INTO sync_account_key_device_wraps (account_id,device_id,wrapped_ark) VALUES (?,?,?)"))
                                .bind(account).bind(wrap.device_id.as_bytes().as_slice()).bind(&wrap.wrapped_ark).execute(&mut *tx).await?;
                        }
                        $capacity(&mut tx, expected.account_id).await?;
                        $append(&mut tx, &audit(expected, now, update.revision), now).await.map_err(|_| AccountKeyStoreError::CorruptRow("publication audit"))?;
                        changed = true;
                        Ok(AccountKeyBundlePut::Applied { revision: update.revision })
                    }.await;
                    let result = result.and_then(|value| live_authorization(expires_at).map(|()| value));
                    match result {
                        Ok(value) => {
                            tx.commit().await.map_err(|error| if changed { AccountKeyStoreError::CommitOutcomeUnknown } else { AccountKeyStoreError::Database(error) })?;
                            Ok(value)
                        }
                        Err(error) => { tx.rollback().await?; Err(error) }
                    }
                }
            }
        }
    };
}

publication!(
    sqlite,
    SqliteStore,
    sqlite_begin,
    sqlite_load,
    sqlite_statements,
    update_matches_current,
    check_sqlite_key_response_capacity,
    append_deployment_audit_event_in_transaction,
    false
);
publication!(
    postgres,
    PostgresStore,
    postgres_begin,
    postgres_load,
    postgres_statements,
    update_matches_current_postgres,
    check_postgres_key_response_capacity,
    append_deployment_audit_event_in_postgres_transaction,
    true
);
