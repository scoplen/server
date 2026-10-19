// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration, role selection, and listener supervision for `spl-server`.

#![forbid(unsafe_code)]

mod config;
mod error;
mod private_material;
mod roles;
mod runtime;

pub use config::{
    Config, ConfigError, KmsSettings, ObjectStorageSettings, SecretValue, StorageSettings, TlsMode,
};
pub use error::ServerError;
pub use roles::{Role, RoleError, resolve_roles};
pub use runtime::{BootstrapResult, PreparedRoles, bootstrap, prepare_roles, run_roles};

/// The server's current package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
