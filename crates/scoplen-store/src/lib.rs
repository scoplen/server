// SPDX-License-Identifier: AGPL-3.0-only
//! Relational storage boundary for the server.

#![forbid(unsafe_code)]

pub mod account_keys;
pub mod audit;
pub mod jobs;
pub mod kms;
pub mod object_storage;
#[cfg(test)]
mod schema;
pub mod sync;

pub use audit::{
    AuditChainHead, AuditCheckpoint, AuditEvent, AuditStoreError,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    write_audit_checkpoint_in_postgres_transaction, write_audit_checkpoint_in_transaction,
};
pub use jobs::{Job, JobId, JobQueueError};
pub use object_storage::{
    ObjectStorage, ObjectStorageConfig, ObjectStorageError, S3ObjectStorageConfig,
};

use std::{path::Path, time::Duration};

use sqlx::{
    PgPool, Pool, Postgres, Sqlite, SqlitePool,
    migrate::Migrator,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
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
}

impl SqliteStore {
    /// Open a SQLite file in WAL mode and apply all forward migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, the database cannot be
    /// opened, or a migration fails. A failed migration prevents server startup.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_sync_limits(path, sync::SyncCardinalityLimits::default()).await
    }

    /// Open SQLite with validated per-deployment sync cardinality limits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, an unusable path, database failure, or migration failure.
    pub async fn open_with_sync_limits(
        path: &Path,
        sync_cardinality_limits: sync::SyncCardinalityLimits,
    ) -> Result<Self, StoreError> {
        sync_cardinality_limits.validate().map_err(StoreError::InvalidSyncLimits)?;
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
        let pool = SqlitePoolOptions::new().max_connections(5).connect_with(options).await?;
        SQLITE_MIGRATIONS.run(&pool).await?;
        Ok(Self { pool, sync_cardinality_limits })
    }

    /// Return the limits enforced by this SQLite store.
    #[must_use]
    pub fn sync_cardinality_limits(&self) -> sync::SyncCardinalityLimits {
        self.sync_cardinality_limits
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
///
/// Server roles continue to select SQLite until their queries also support PostgreSQL.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to PostgreSQL and apply the embedded forward migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection or migration fails. A failed migration prevents
    /// callers from using the store.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new().max_connections(5).connect(database_url).await?;
        POSTGRES_MIGRATIONS.run(&pool).await?;
        Ok(Self { pool })
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
    /// The configured SQLite sync limits cannot be enforced safely.
    #[error("invalid sync cardinality limits: {0}")]
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
}
