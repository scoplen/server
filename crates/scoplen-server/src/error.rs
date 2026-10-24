// SPDX-License-Identifier: AGPL-3.0-only
//! Errors for the server process boundary.

use std::path::PathBuf;

use thiserror::Error;

/// Errors returned while loading, validating, or running a deployment.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Configuration could not be read or parsed.
    #[error("configuration error: {0}")]
    Config(#[from] crate::ConfigError),
    /// Persistent storage could not be initialized.
    #[error("storage error: {0}")]
    Storage(#[from] scoplen_store::StoreError),
    /// Object storage could not be initialized or reached.
    #[error("object storage error: {0}")]
    ObjectStorage(#[from] scoplen_store::ObjectStorageError),
    /// Key-management backend could not be initialized.
    #[error("key-management error: {0}")]
    KeyManagement(#[from] scoplen_store::kms::KmsError),
    /// First-operator entitlement storage, configuration or mandatory audit failed.
    #[error("operator setup error: {0}")]
    OperatorSetup(#[from] scoplen_store::operator_setup::OperatorSetupError),
    /// A database-backed role was started without initialized storage.
    #[error("api, worker, and edge roles require initialized storage")]
    MissingStore,
    /// A database-backed role was started without initialized key management.
    #[error("api, worker, and edge roles require initialized key management")]
    MissingKeyManagement,
    /// A database-backed role was started without deployment admission.
    #[error("api, worker, and edge roles require a deployment lease")]
    MissingDeploymentLease,
    /// The data directory could not be initialized.
    #[error("could not initialize data directory {path}: {source}")]
    DataDirectory {
        /// Directory that failed to initialize.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// Windows permission admission failed without changing existing access controls.
    #[cfg(windows)]
    #[error("private deployment storage is unavailable: {0}")]
    PrivateMaterialAccess(#[source] std::io::Error),
    /// A server or offline operation holds an incompatible deployment lease.
    #[error("deployment state is in use; stop the active server or local operation and retry")]
    DeploymentLeaseOccupied,
    /// The lease file cannot be safely opened or locked.
    #[error(
        "deployment lease is unsafe or unavailable; check the private data directory and retry"
    )]
    DeploymentLeaseUnavailable(#[source] std::io::Error),
    /// A generated deployment material file could not be written.
    #[error("could not write deployment material {path}: {source}")]
    Material {
        /// File that failed to write.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A listener or request-serving task failed.
    #[error("runtime error: {0}")]
    Runtime(#[from] std::io::Error),
    /// Shutdown could not prove local deployment state is quiescent within the deadline.
    #[error(
        "server shutdown exceeded 10 seconds; the deployment lease remains held until this process exits. Exit this process before an offline backup or restore"
    )]
    ShutdownTimedOut,
    /// TLS configuration could not be created.
    #[error("TLS error: {0}")]
    Tls(String),
    /// A task returned an unexpected error.
    #[error("role task failed: {0}")]
    Task(String),
}
