// SPDX-License-Identifier: AGPL-3.0-only
//! Transaction-local initial password Account persistence, without protocol authorization.
//!
//! These operations do not implement registration or login. The caller must first authenticate
//! the original live challenge and both possession proofs, check deployment-wide Device/key
//! freshness and admission, then atomically add the receipt, challenge consumption and mandatory
//! audit to this same transaction. Never disclose a staged result before confirmed COMMIT.
//! Any error requires rollback of the entire caller transaction; absence is no negative receipt.
//! Password ownership is fixed on Account creation. Missing credential state on a password-owned
//! Account fails closed and never reclassifies it as a legacy Account.
//! Before creation, the protocol coordinator must hold the Account-entry singleton lock and
//! validate deployment-wide Device/key freshness. It precedes D-129 and Account/vault locks.

use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountPersonalBootstrap, AccountPersonalEpoch,
        AccountRegistrationPayload,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::SecretVec;
use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    account_devices::{StatementKind, postgres_statements, sqlite_statements},
    account_keys::{
        AccountKeyBundleUpdate, AccountKeyStoreError, check_postgres_key_response_capacity,
        check_sqlite_key_response_capacity, read_postgres_accepted_put, read_sqlite_accepted_put,
    },
    account_used_ids::{
        AccountIdRetentionError, reserve_postgres_account_id, reserve_sqlite_account_id,
    },
};

/// Content-free persistence failure, never a registration/login or receipt result.
#[derive(Error)]
pub enum AccountBootstrapError {
    /// Invalid initial public material or trusted context.
    #[error("invalid initial Account bootstrap")]
    InvalidInput,
    /// A current Account, username, Device or vault conflicts.
    #[error("Account bootstrap identity conflicts")]
    Conflict,
    /// This Account has no established password bootstrap; legacy state is not converted.
    #[error("Account password bootstrap is unavailable")]
    NotEstablished,
    /// A credential/root/Personal transition has no supported complete representation.
    #[error("Account bootstrap transition is unsupported")]
    UnsupportedState,
    /// Persisted state is incomplete, corrupt, oversized or inconsistent.
    #[error("Account bootstrap state is inconsistent")]
    Integrity,
    /// Deployment-lifetime id admission failed.
    #[error("Account id admission failed")]
    Retention(#[from] AccountIdRetentionError),
    /// Storage is unavailable; no business COMMIT is performed by this module.
    #[error("Account bootstrap storage is unavailable")]
    Storage(#[source] sqlx::Error),
}

impl std::fmt::Debug for AccountBootstrapError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl From<sqlx::Error> for AccountBootstrapError {
    fn from(error: sqlx::Error) -> Self {
        if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
            Self::Conflict
        } else {
            Self::Storage(error)
        }
    }
}

fn key_error(error: AccountKeyStoreError) -> AccountBootstrapError {
    match error {
        AccountKeyStoreError::Database(error) | AccountKeyStoreError::Constraint(error) => {
            AccountBootstrapError::Storage(error)
        }
        _ => AccountBootstrapError::Integrity,
    }
}

fn protection_error(error: AccountBootstrapError) -> AccountKeyStoreError {
    match error {
        AccountBootstrapError::Storage(error) => AccountKeyStoreError::Database(error),
        AccountBootstrapError::UnsupportedState => AccountKeyStoreError::UnsupportedTransition,
        _ => AccountKeyStoreError::CorruptRow("password Account bootstrap"),
    }
}

fn inserted(rows: u64) -> Result<(), AccountBootstrapError> {
    if rows == 1 { Ok(()) } else { Err(AccountBootstrapError::Integrity) }
}

macro_rules! bootstrap {
    ($db:ty, $create:ident, $read:ident, $present:ident, $protect:ident, $accepted:ident,
     $statements:ident, $capacity:ident, $reserve:ident, $postgres:literal) => {
        /// Create the complete initial aggregate inside the caller's business transaction.
        ///
        /// Only new Accounts are accepted: no legacy credential attachment, overwrite, replay,
        /// challenge, receipt, audit or authorization is supplied here. Reserve the D-129 guard
        /// before Account/vault locks. The caller must roll back on error and commit all required
        /// protocol state/audit together; this helper never commits or returns a capability.
        /// # Errors
        /// Rejects invalid public bindings, namespace/capacity conflicts and storage failures.
        pub async fn $create(
            tx: &mut Transaction<'_, $db>,
            trusted_origin: &str,
            expected_ceiling: u64,
            payload: &AccountRegistrationPayload,
            created_at_ms: i64,
        ) -> Result<SecretVec, AccountBootstrapError> {
            payload.to_cbor().map_err(|_| AccountBootstrapError::InvalidInput)?;
            if payload.origin != trusted_origin || created_at_ms <= 0 {
                return Err(AccountBootstrapError::InvalidInput);
            }
            $reserve(tx, payload.account_id, expected_ceiling).await?;
            if $postgres {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
                    .bind(payload.account_id.as_bytes().as_slice()).execute(&mut **tx).await?;
            }
            let sql = |source: &str| parameterized(source, $postgres);
            let account = payload.account_id.as_bytes().as_slice();
            let device = payload.device_id.as_bytes().as_slice();
            let vault = payload.personal_vault_id.as_bytes().as_slice();
            let update = SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle)
                .map_err(|_| AccountBootstrapError::InvalidInput)?;
            inserted(sqlx::query(&sql("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms,password_owned) VALUES (?,?,?,?,TRUE)"))
                .bind(account).bind(payload.account_signing_public_key.as_slice())
                .bind(payload.account_kem_public_key.as_slice()).bind(created_at_ms).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES (?,?,?,?,?)"))
                .bind(device).bind(account).bind(&payload.device_certificate).bind(true)
                .bind(created_at_ms).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO sync_vaults (vault_id,kind) VALUES (?,'personal')"))
                .bind(vault).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO sync_personal_vaults (account_id,vault_id,key_epoch,wrapped_vault_key) VALUES (?,?,1,?)"))
                .bind(account).bind(vault).bind(payload.personal_wrapped_key.as_slice()).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO sync_account_key_bundles (account_id,revision,account_signing_key,account_kem_key,recovery_blob,signature,updated_at_ms,accepted_put_cbor) VALUES (?,1,?,?,?,?,?,?)"))
                .bind(account).bind(&update.account_signing_key).bind(&update.account_kem_key)
                .bind(&update.recovery_blob).bind(&update.signature).bind(created_at_ms)
                .bind(&payload.key_bundle).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO sync_account_key_device_wraps (account_id,device_id,wrapped_ark) VALUES (?,?,?)"))
                .bind(account).bind(device).bind(&update.device_wraps[0].wrapped_ark).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES (?,?)"))
                .bind(account).bind(&payload.device_certificate).execute(&mut **tx).await?.rows_affected())?;
            inserted(sqlx::query(&sql("INSERT INTO account_password_bootstrap (account_id,origin,username,credential_generation,password_profile,password_salt,verifier,password_ark,personal_vault_id,account_signing_public_key,account_kem_public_key) VALUES (?,?,?,1,1,?,?,?,?,?,?)"))
                .bind(account).bind(&payload.origin).bind(&payload.username)
                .bind(payload.password_salt.as_slice()).bind(payload.verifier.as_slice())
                .bind(payload.password_ark.as_slice()).bind(vault)
                .bind(payload.account_signing_public_key.as_slice()).bind(payload.account_kem_public_key.as_slice())
                .execute(&mut **tx).await?.rows_affected())?;
            $capacity(tx, payload.account_id.into_bytes()).await.map_err(key_error)?;
            $read(tx, trusted_origin, payload.account_id).await
        }

        /// Read and verify the complete current initial password bootstrap in one transaction.
        ///
        /// This grants no authority, verifies no password, and returns no session/capability.
        /// Call only inside an authorized protocol transaction; disclose after its confirmed commit.
        /// Initial generation/Personal epoch one are the only supported lifecycle. No historical
        /// Personal keys are fabricated from the current-key projection.
        /// # Errors
        /// Rejects missing, corrupt, incomplete, oversized, stale-snapshot or unsupported state.
        pub async fn $read(
            tx: &mut Transaction<'_, $db>,
            trusted_origin: &str,
            account_id: Uuid,
        ) -> Result<SecretVec, AccountBootstrapError> {
            let sql = |source: &str| parameterized(source, $postgres);
            let account = account_id.as_bytes().as_slice();
            if $postgres {
                sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended(encode($1, 'hex'), 0))")
                    .bind(account).execute(&mut **tx).await?;
            }
            if !$present(tx, account).await? { return Err(AccountBootstrapError::NotEstablished); }
            // Read only fixed-size or bounded metadata; never transfer damaged oversized blobs.
            let size = |field: &str, maximum: usize| {
                let length = if $postgres { format!("octet_length({field})") } else { format!("length(CAST({field} AS BLOB))") };
                format!("CASE WHEN {length} <= {maximum} THEN {field} END AS {field}")
            };
            let fields = [size("origin", 2048), size("username", 64), size("password_salt", 16),
                size("password_ark", 73), size("personal_vault_id", 16),
                size("account_signing_public_key", 32), size("account_kem_public_key", 32)].join(",");
            let verifier_valid = if $postgres { "octet_length(verifier)=32" } else { "typeof(verifier)='blob' AND length(verifier)=32" };
            let row = sqlx::query(&sql(&format!("SELECT {fields},credential_generation,password_profile,({verifier_valid}) AS verifier_valid FROM account_password_bootstrap WHERE account_id=?")))
                .bind(account).fetch_one(&mut **tx).await?;
            let origin: String = row.try_get("origin").map_err(|_| AccountBootstrapError::Integrity)?;
            if origin != trusted_origin || !row.try_get::<bool,_>("verifier_valid").map_err(|_| AccountBootstrapError::Integrity)? {
                return Err(AccountBootstrapError::Integrity);
            }
            if row.try_get::<i64,_>("credential_generation")? != 1 || row.try_get::<i64,_>("password_profile")? != 1 {
                return Err(AccountBootstrapError::UnsupportedState);
            }
            let fixed = |name: &str| row.try_get::<Vec<u8>,_>(name).map_err(|_| AccountBootstrapError::Integrity);
            let signing: [u8;32] = fixed("account_signing_public_key")?.try_into().map_err(|_| AccountBootstrapError::Integrity)?;
            let kem: [u8;32] = fixed("account_kem_public_key")?.try_into().map_err(|_| AccountBootstrapError::Integrity)?;
            let vault: [u8;16] = fixed("personal_vault_id")?.try_into().map_err(|_| AccountBootstrapError::Integrity)?;
            let length = if $postgres { "octet_length" } else { "length" };
            let identity = sqlx::query(&sql(&format!("SELECT CASE WHEN {length}(account_signing_public_key)=32 THEN account_signing_public_key END AS signing,CASE WHEN {length}(account_kem_public_key)=32 THEN account_kem_public_key END AS kem FROM identity_accounts WHERE account_id=?")))
                .bind(account).fetch_optional(&mut **tx).await?.ok_or(AccountBootstrapError::Integrity)?;
            if identity.try_get::<Vec<u8>,_>("signing").map_err(|_| AccountBootstrapError::Integrity)? != signing
                || identity.try_get::<Vec<u8>,_>("kem").map_err(|_| AccountBootstrapError::Integrity)? != kem {
                return Err(AccountBootstrapError::UnsupportedState);
            }
            let personal = sqlx::query(&sql(&format!("SELECT CASE WHEN {length}(p.vault_id)=16 THEN p.vault_id END AS vault_id,p.key_epoch,v.rotation_pending,CASE WHEN {length}(p.wrapped_vault_key)=73 THEN p.wrapped_vault_key END AS wrapped_key FROM sync_personal_vaults p JOIN sync_vaults v ON v.vault_id=p.vault_id WHERE p.account_id=? AND v.kind='personal'")))
                .bind(account).fetch_optional(&mut **tx).await?.ok_or(AccountBootstrapError::Integrity)?;
            let actual_vault: Vec<u8> = personal.try_get("vault_id").map_err(|_| AccountBootstrapError::Integrity)?;
            if actual_vault != vault || personal.try_get::<i64,_>("key_epoch")? != 1 || personal.try_get::<bool,_>("rotation_pending")? {
                return Err(AccountBootstrapError::UnsupportedState);
            }
            let key_bundle = $accepted(tx, account_id.into_bytes()).await.map_err(key_error)?
                .ok_or(AccountBootstrapError::Integrity)?;
            let mut total = 0;
            let certificates = $statements(tx, account, StatementKind::Certificate, &mut total).await.map_err(|_| AccountBootstrapError::Integrity)?;
            let revocations = $statements(tx, account, StatementKind::Revocation, &mut total).await.map_err(|_| AccountBootstrapError::Integrity)?;
            let snapshot = AccountBootstrapSnapshot {
                origin, username: row.try_get("username").map_err(|_| AccountBootstrapError::Integrity)?,
                account_id, personal_vault_id: Uuid::from_bytes(vault), account_signing_public_key: signing,
                account_kem_public_key: kem, credential_generation: 1,
                password_salt: fixed("password_salt")?.try_into().map_err(|_| AccountBootstrapError::Integrity)?,
                password_ark: fixed("password_ark")?.try_into().map_err(|_| AccountBootstrapError::Integrity)?,
                key_bundle, certificates, revocations,
                personal: AccountPersonalBootstrap { current_epoch: 1, rotation_pending: false,
                    epochs: vec![AccountPersonalEpoch { epoch: 1, wrapped_key: personal.try_get::<Vec<u8>,_>("wrapped_key").map_err(|_| AccountBootstrapError::Integrity)?.try_into().map_err(|_| AccountBootstrapError::Integrity)? }] },
            };
            Ok(SecretVec::new(snapshot.to_cbor().map_err(|_| AccountBootstrapError::Integrity)?))
        }

        pub(crate) async fn $present(tx: &mut Transaction<'_, $db>, account: &[u8]) -> Result<bool, sqlx::Error> {
            let password_owned: Option<bool> = sqlx::query_scalar(&parameterized("SELECT password_owned FROM identity_accounts WHERE account_id=?", $postgres))
                .bind(account).fetch_optional(&mut **tx).await?;
            if !password_owned.unwrap_or(false) {
                let unexpected: i64 = sqlx::query_scalar(&parameterized("SELECT COUNT(*) FROM account_password_bootstrap WHERE account_id=?", $postgres))
                    .bind(account).fetch_one(&mut **tx).await?;
                return if unexpected == 0 { Ok(false) } else { Err(sqlx::Error::Protocol("unexpected legacy Account password state".into())) };
            }
            // Updating an existing row versions mutable bootstrap state for PostgreSQL's
            // stronger isolation levels and reserves SQLite's writer before reading artifacts.
            let rows = sqlx::query(&parameterized("UPDATE account_password_bootstrap SET credential_generation=credential_generation WHERE account_id=?", $postgres))
                .bind(account).execute(&mut **tx).await?.rows_affected();
            if rows != 1 { return Err(sqlx::Error::Protocol("missing Account password bootstrap".into())); }
            Ok(true)
        }

        pub(crate) async fn $protect(tx: &mut Transaction<'_, $db>, account: [u8;16], candidate: &AccountKeyBundleUpdate) -> Result<(), AccountKeyStoreError> {
            if !$present(tx, &account).await? { return Ok(()); }
            let length = if $postgres { "octet_length(origin)" } else { "length(CAST(origin AS BLOB))" };
            let origin: String = sqlx::query_scalar(&parameterized(&format!("SELECT CASE WHEN {length} BETWEEN 1 AND 2048 THEN origin END FROM account_password_bootstrap WHERE account_id=?"), $postgres))
                .bind(account.as_slice()).fetch_one(&mut **tx).await?;
            let snapshot = $read(tx, &origin, Uuid::from_bytes(account)).await.map_err(protection_error)?;
            let snapshot = AccountBootstrapSnapshot::from_cbor(snapshot.as_bytes())
                .map_err(|_| AccountKeyStoreError::CorruptRow("password Account bootstrap"))?;
            let current = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle)
                .map_err(|_| AccountKeyStoreError::CorruptRow("password Account accepted PUT"))?;
            let current = AccountKeyBundleUpdate::try_from(&current)?;
            if candidate.account_signing_key != current.account_signing_key
                || candidate.account_kem_key != current.account_kem_key
                || candidate.recovery_blob != current.recovery_blob
                || candidate.device_wraps != current.device_wraps {
                return Err(AccountKeyStoreError::UnsupportedTransition);
            }
            Ok(())
        }
    };
}

fn parameterized(source: &str, postgres: bool) -> String {
    if !postgres {
        return source.to_owned();
    }
    let mut parameter = 0;
    source
        .chars()
        .map(|character| {
            if character == '?' {
                parameter += 1;
                format!("${parameter}")
            } else {
                character.to_string()
            }
        })
        .collect()
}

bootstrap!(
    Sqlite,
    create_sqlite_password_account_in_transaction,
    read_sqlite_password_bootstrap_in_transaction,
    sqlite_password_account,
    protect_sqlite_password_bundle,
    read_sqlite_accepted_put,
    sqlite_statements,
    check_sqlite_key_response_capacity,
    reserve_sqlite_account_id,
    false
);
bootstrap!(
    Postgres,
    create_postgres_password_account_in_transaction,
    read_postgres_password_bootstrap_in_transaction,
    postgres_password_account,
    protect_postgres_password_bundle,
    read_postgres_accepted_put,
    postgres_statements,
    check_postgres_key_response_capacity,
    reserve_postgres_account_id,
    true
);
