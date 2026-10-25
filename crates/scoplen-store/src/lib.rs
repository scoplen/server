// SPDX-License-Identifier: AGPL-3.0-only
//! Relational storage boundary for the server.

#![forbid(unsafe_code)]

pub mod account_devices;
pub mod account_key_publication;
pub mod account_keys;
pub mod account_profile;
pub mod audit;
pub mod deployment_audit;
pub mod device_authentication;
pub mod device_token_keys;
pub mod jobs;
pub mod kms;
pub mod object_storage;
pub mod operator_admission;
pub mod operator_invitations;
pub mod operator_sessions;
pub mod operator_setup;
pub mod operator_token_keys;
pub mod pairing;
pub mod pairing_admission;
pub mod personal_admission;
pub mod personal_enrollment;
mod pre_migration;
pub mod refresh_retention;
#[cfg(test)]
mod schema;
pub mod sync;
pub mod sync_notifications;
pub mod sync_write_admission;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

pub use audit::{
    AuditChainHead, AuditCheckpoint, AuditEvent, AuditStoreError,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    write_audit_checkpoint_in_postgres_transaction, write_audit_checkpoint_in_transaction,
};
pub use deployment_audit::{
    DeploymentAuditChainHead, DeploymentAuditCheckpoint, DeploymentAuditEvent,
    append_deployment_audit_event_in_postgres_transaction,
    append_deployment_audit_event_in_transaction,
    write_deployment_audit_checkpoint_in_postgres_transaction,
    write_deployment_audit_checkpoint_in_transaction,
};
pub use jobs::{Job, JobId, JobQueueError};
pub use object_storage::{
    ObjectStorage, ObjectStorageConfig, ObjectStorageError, S3ObjectStorageConfig,
};
pub use personal_enrollment::{
    EnrolledPersonalDevice, IssuedPersonalInvitation, PersonalEnrollmentReceipt,
    PersonalInvitationStoreError,
};

use std::{fs::File, path::Path, sync::Arc, time::Duration};

use sqlx::{
    Connection, PgPool, Pool, Postgres, Sqlite, SqlitePool, TransactionManager,
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteTransactionManager,
    },
};
use thiserror::Error;

static SQLITE_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/postgres");

/// A database pool whose backend is selected by the deployment.
///
/// Services can use a transaction from this pool to commit state and its audit event together.
pub trait RelationalStore {
    /// The `sqlx` database driver used by this store.
    type Database: sqlx::Database;

    /// Return the pool used for transactions and read queries.
    fn pool(&self) -> &Pool<Self::Database>;
}

/// SQLite storage for a single-node deployment.
#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
    sync_cardinality_limits: sync::SyncCardinalityLimits,
    sync_write_limits: scoplen_api::sync::SyncWriteLimits,
    _deployment_lease: Option<Arc<File>>,
}

impl SqliteStore {
    /// Open SQLite in WAL mode, snapshot an existing schema before upgrades, and migrate.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, the database cannot be
    /// opened, or a migration fails. A failed migration prevents server startup.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_sync_limits(
            path,
            sync::SyncCardinalityLimits::default(),
            scoplen_api::sync::SyncWriteLimits::default(),
        )
        .await
    }

    /// Open SQLite with validated per-deployment cardinality and write-exchange limits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, an unusable path, database failure, or migration failure.
    pub async fn open_with_sync_limits(
        path: &Path,
        sync_cardinality_limits: sync::SyncCardinalityLimits,
        sync_write_limits: scoplen_api::sync::SyncWriteLimits,
    ) -> Result<Self, StoreError> {
        Self::open_with_sync_limits_inner(path, sync_cardinality_limits, sync_write_limits, None)
            .await
    }

    /// Open SQLite while retaining an already locked deployment file through migrations and
    /// every clone of this store.
    ///
    /// # Errors
    ///
    /// Returns the same validation, database, and migration errors as
    /// [`Self::open_with_sync_limits`]. The caller must acquire the file lock before calling.
    pub async fn open_with_sync_limits_and_lease(
        path: &Path,
        sync_cardinality_limits: sync::SyncCardinalityLimits,
        sync_write_limits: scoplen_api::sync::SyncWriteLimits,
        deployment_lease: Arc<File>,
    ) -> Result<Self, StoreError> {
        Self::open_with_sync_limits_inner(
            path,
            sync_cardinality_limits,
            sync_write_limits,
            Some(deployment_lease),
        )
        .await
    }

    async fn open_with_sync_limits_inner(
        path: &Path,
        sync_cardinality_limits: sync::SyncCardinalityLimits,
        sync_write_limits: scoplen_api::sync::SyncWriteLimits,
        deployment_lease: Option<Arc<File>>,
    ) -> Result<Self, StoreError> {
        sync_cardinality_limits.validate().map_err(StoreError::InvalidSyncLimits)?;
        sync_write_limits
            .validate()
            .map_err(|error| StoreError::InvalidSyncLimits(error.to_string()))?;
        if path.as_os_str().is_empty() {
            return Err(StoreError::EmptyPath);
        }
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(StoreError::CreateDirectory)?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool_lease = deployment_lease.clone();
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .after_release(move |connection, _| {
                let lease = pool_lease.clone();
                Box::pin(async move {
                    let _deployment_lease = lease;
                    // SQLx custom BEGIN validates the handle after acknowledgement. Cancellation
                    // there has no Transaction guard, so clean before another request can acquire it.
                    if connection.is_in_transaction()
                        && SqliteTransactionManager::rollback(connection).await.is_err()
                    {
                        return Ok(false);
                    }
                    Ok(!connection.is_in_transaction())
                })
            })
            .connect_with(options)
            .await?;
        if let Err(error) = pre_migration::migrate(&pool, path, deployment_lease.clone()).await {
            pool.close().await;
            return Err(error);
        }
        Ok(Self {
            pool,
            sync_cardinality_limits,
            sync_write_limits,
            _deployment_lease: deployment_lease,
        })
    }

    /// Return the limits enforced by this SQLite store.
    #[must_use]
    pub fn sync_cardinality_limits(&self) -> sync::SyncCardinalityLimits {
        self.sync_cardinality_limits
    }

    /// Return the write-exchange limits enforced before every storage mutation.
    #[must_use]
    pub fn sync_write_limits(&self) -> scoplen_api::sync::SyncWriteLimits {
        self.sync_write_limits
    }

    /// Check whether the database can execute a query for readiness checks.
    ///
    /// # Errors
    ///
    /// Returns the driver error when the database is unavailable.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

impl RelationalStore for SqliteStore {
    type Database = Sqlite;

    fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// PostgreSQL storage connection with the parallel forward migration set applied.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    sync_cardinality_limits: sync::SyncCardinalityLimits,
    sync_write_limits: scoplen_api::sync::SyncWriteLimits,
}

impl PostgresStore {
    /// Connect to PostgreSQL and apply the embedded forward migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection or migration fails. A failed migration prevents
    /// callers from using the store.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        Self::connect_with_sync_limits(
            database_url,
            sync::SyncCardinalityLimits::default(),
            scoplen_api::sync::SyncWriteLimits::default(),
        )
        .await
    }

    /// Connect to PostgreSQL with validated per-deployment cardinality and write-exchange limits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, connection failure, or migration failure.
    pub async fn connect_with_sync_limits(
        database_url: &str,
        sync_cardinality_limits: sync::SyncCardinalityLimits,
        sync_write_limits: scoplen_api::sync::SyncWriteLimits,
    ) -> Result<Self, StoreError> {
        sync_cardinality_limits.validate().map_err(StoreError::InvalidSyncLimits)?;
        sync_write_limits
            .validate()
            .map_err(|error| StoreError::InvalidSyncLimits(error.to_string()))?;
        let pool = PgPoolOptions::new().max_connections(5).connect(database_url).await?;
        POSTGRES_MIGRATIONS.run(&pool).await?;
        Ok(Self { pool, sync_cardinality_limits, sync_write_limits })
    }

    /// Return the limits enforced by this PostgreSQL store.
    #[must_use]
    pub fn sync_cardinality_limits(&self) -> sync::SyncCardinalityLimits {
        self.sync_cardinality_limits
    }

    /// Return the write-exchange limits enforced before every storage mutation.
    #[must_use]
    pub fn sync_write_limits(&self) -> scoplen_api::sync::SyncWriteLimits {
        self.sync_write_limits
    }

    /// Check whether the database can execute a query for readiness checks.
    ///
    /// # Errors
    ///
    /// Returns the driver error when the database is unavailable.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

impl RelationalStore for PostgresStore {
    type Database = Postgres;

    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Storage initialization errors.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The configured sync limits cannot be enforced safely.
    #[error("invalid sync limits: {0}")]
    InvalidSyncLimits(String),
    /// The database path was empty.
    #[error("storage database path must not be empty")]
    EmptyPath,
    /// The parent directory could not be created.
    #[error("could not create storage directory: {0}")]
    CreateDirectory(std::io::Error),
    /// The relational database could not be opened or queried.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// A forward migration could not be applied.
    #[error("database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// SQLite upgrade protection could not complete safely.
    #[error(
        "SQLite upgrade protection failed ({0}); startup stopped; check private snapshot storage and available space before restarting"
    )]
    MigrationSnapshot(&'static str),
}
