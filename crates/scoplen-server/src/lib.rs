// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration, role selection, and listener supervision for `spl-server`.

#![forbid(unsafe_code)]

mod account_devices;
mod account_profile;
mod config;
mod console;
pub mod deployment_lease;
mod device_auth;
mod error;
mod operator_auth;
mod operator_logout;
mod personal_sync;
mod private_material;
mod roles;
mod runtime;
#[cfg(windows)]
#[path = "private_material/windows.rs"]
mod windows_private_directory;

#[cfg(test)]
#[path = "../../scoplen-store/tests/support/legacy_identity.rs"]
mod test_legacy_identity;
#[cfg(all(test, feature = "postgres-integration"))]
#[path = "../../scoplen-store/tests/support/lost_commit.rs"]
mod test_lost_commit;
#[cfg(test)]
#[path = "../../scoplen-store/tests/support/passkey.rs"]
mod test_passkey;
#[cfg(test)]
#[path = "../../scoplen-store/tests/support/mod.rs"]
mod test_support;

pub use config::{
    Config, ConfigError, ConsoleSettings, KmsSettings, ObjectStorageSettings, SecretValue,
    StorageSettings, TlsMode,
};
pub use error::ServerError;
pub use roles::{Role, RoleError, resolve_roles};
pub use runtime::{
    PreparedRoles, admit_local_deployment, bootstrap, prepare_roles, reissue_operator_setup,
    run_roles,
};

/// The server's current package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
