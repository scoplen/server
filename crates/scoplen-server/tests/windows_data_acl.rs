// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(windows)]

use std::{
    fs,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

use scoplen_server::{Config, Role, bootstrap, prepare_roles};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .join(format!("scoplen-windows-bootstrap-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("new owned test root");
        Self(root)
    }

    fn config(&self) -> Config {
        let mut config = Config::default();
        config.server.data_dir = self.0.join("data");
        config.server.public_host = "example.com".into();
        config
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove exact owned test root");
    }
}

fn add_public_read(path: &Path, directory: bool) {
    let script = if directory {
        "$path = $env:SCOPLEN_ACL_TEST_PATH; $acl = [System.IO.Directory]::GetAccessControl($path); $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow)); [System.IO.Directory]::SetAccessControl($path, $acl)"
    } else {
        "$path = $env:SCOPLEN_ACL_TEST_PATH; $acl = [System.IO.File]::GetAccessControl($path); $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow)); [System.IO.File]::SetAccessControl($path, $acl)"
    };
    let executable = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output = Command::new(executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("SCOPLEN_ACL_TEST_PATH", path)
        .creation_flags(0x0800_0000)
        .output()
        .expect("owned fixture permissions");
    assert!(output.status.success(), "fixture ACL update failed");
}

#[test]
fn public_bootstrap_creates_private_material_and_preserves_it_after_reopen() {
    let fixture = Fixture::new();
    let config = fixture.config();
    bootstrap(&config).expect("private creation");
    let names = ["deployment.key", "audit-signing.key", "internal-ca-key.pem", "internal-ca.pem"];
    let retained: Vec<_> = names
        .iter()
        .map(|name| fs::read(config.server.data_dir.join(name)).expect("created material"))
        .collect();
    bootstrap(&config).expect("private existing deployment");
    for (name, contents) in names.iter().zip(retained) {
        assert!(
            fs::read(config.server.data_dir.join(name)).expect("retained material") == contents,
            "existing material changed"
        );
    }
}

#[tokio::test]
async fn unsafe_directory_is_rejected_by_public_bootstrap_and_before_storage_creation() {
    let fixture = Fixture::new();
    let config = fixture.config();
    fs::create_dir(&config.server.data_dir).expect("owned unsafe directory");
    add_public_read(&config.server.data_dir, true);
    for error in [
        bootstrap(&config).expect_err("bootstrap must reject"),
        prepare_roles(&config, &[Role::Api]).await.err().expect("startup must reject"),
    ] {
        let message = error.to_string();
        assert!(message.contains("permissions are unsafe or unsupported"));
        assert!(!message.contains(config.server.data_dir.to_str().expect("test path")));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_spl-server"))
        .args(["--role", "api"])
        .arg("--config")
        .arg(fixture.0.join("not-present.toml"))
        .current_dir(&fixture.0)
        .env("SPL_SERVER_DATA_DIR", &config.server.data_dir)
        .env("SPL_SERVER_PUBLIC_HOST", "example.com")
        .env("SPL_STORAGE_BACKEND", "sqlite")
        .creation_flags(0x0800_0000)
        .output()
        .expect("public unsafe-directory startup");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "startup disclosed bootstrap output");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("permissions are unsafe or unsupported"));
    assert!(!error.contains(fixture.0.to_str().expect("test path")));
    assert_eq!(fs::read_dir(&config.server.data_dir).expect("retained empty directory").count(), 0);
}

#[test]
fn unsafe_existing_key_is_rejected_without_replacement() {
    let fixture = Fixture::new();
    let config = fixture.config();
    bootstrap(&config).expect("private creation");
    let key = config.server.data_dir.join("deployment.key");
    let retained = fs::read(&key).expect("existing key");
    add_public_read(&key, false);
    let error = bootstrap(&config).expect_err("unsafe key must reject");
    assert!(error.to_string().contains("permissions are unsafe or unsupported"));
    assert!(fs::read(&key).expect("retained key") == retained, "key bytes changed");
}

#[test]
fn public_process_refuses_a_missing_acl_runtime_without_disclosing_a_path_or_creating_storage() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let output = Command::new(env!("CARGO_BIN_EXE_spl-server"))
        .args(["--role", "worker"])
        .arg("--config")
        .arg(fixture.0.join("not-present.toml"))
        .current_dir(&fixture.0)
        .env("SPL_SERVER_DATA_DIR", &config.server.data_dir)
        .env("SPL_SERVER_PUBLIC_HOST", "example.com")
        .env("SPL_STORAGE_BACKEND", "sqlite")
        .env("SystemRoot", fixture.0.join("missing-os"))
        .creation_flags(0x0800_0000)
        .output()
        .expect("public CLI invocation");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("Windows PowerShell 5.1"));
    assert!(!error.contains(fixture.0.to_str().expect("test path")));
    assert!(output.stdout.is_empty(), "startup disclosed bootstrap output");
    assert!(!config.server.data_dir.exists());
}

#[tokio::test]
async fn migration_snapshots_inherit_private_permissions_and_unsafe_existing_acl_blocks_startup() {
    use scoplen_store::RelationalStore;
    let fixture = Fixture::new();
    let config = fixture.config();
    let prepared = prepare_roles(&config, &[Role::Api]).await.expect("private initial startup");
    let store = prepared.store.expect("SQLite store");
    sqlx::query(
        "DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)",
    )
    .execute(store.pool())
    .await
    .expect("owned fixture pending migration");
    store.pool().close().await;
    drop(store);
    let prepared = prepare_roles(&config, &[Role::Api]).await.expect("private protected upgrade");
    let store = prepared.store.expect("upgraded SQLite store");
    store.pool().close().await;
    drop(store);
    let directory = config.server.data_dir.join("scoplen.sqlite.migration-snapshots");
    let snapshots: Vec<_> = fs::read_dir(&directory)
        .expect("snapshot directory")
        .map(|entry| entry.expect("snapshot entry").path())
        .collect();
    assert_eq!(snapshots.len(), 1);
    bootstrap(&config).expect("snapshot directory, file and migration lock pass native ACL checks");
    let retained = fs::read(&snapshots[0]).expect("retained snapshot");
    add_public_read(&snapshots[0], false);
    let error = prepare_roles(&config, &[Role::Api])
        .await
        .err()
        .expect("unsafe snapshot ACL blocks startup");
    assert!(error.to_string().contains("permissions are unsafe or unsupported"));
    assert!(!error.to_string().contains(directory.to_str().expect("fixture path")));
    assert_eq!(fs::read(&snapshots[0]).expect("unchanged recovery point"), retained);
}
