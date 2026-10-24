// SPDX-License-Identifier: AGPL-3.0-only

use std::{fs, process::Command};

use scoplen_server::{Config, ServerError, bootstrap, deployment_lease::DeploymentLease};

#[test]
fn local_pending_reissue_requires_explicit_flag_and_discloses_only_stdout() {
    let directory = std::env::temp_dir().join(format!(
        "scoplen-ctl-setup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir(&directory).expect("fixture directory");
    let config = directory.join("server.toml");
    let data = directory.join("data");
    fs::write(
        &config,
        format!(
            "[server]\npublic_host = 'setup.example.com'\ndata_dir = '{}'\n",
            data.to_str().expect("fixture path").replace('\\', "/")
        ),
    )
    .expect("local fixture configuration");
    let missing_flag = Command::new(env!("CARGO_BIN_EXE_splctl"))
        .args(["bootstrap", "--config"])
        .arg(&config)
        .output()
        .expect("run CLI");
    assert!(!missing_flag.status.success());
    assert!(!data.exists(), "missing explicit flag cannot mutate deployment state");
    let first = reissue(&config);
    let second = reissue(&config);
    assert!(first != second, "explicit pending reissue returns a new secret");
    assert!(!data.join("setup-link.txt").exists());
    for file in ["deployment.key", "audit-signing.key", "scoplen.sqlite"] {
        assert!(data.join(file).is_file(), "configured deployment material exists");
    }
    fs::remove_dir_all(directory).expect("remove owned CLI fixture");
}

#[test]
fn exclusive_deployment_lease_rejects_local_reissue_without_creating_storage() {
    let directory = std::env::temp_dir().join(format!(
        "scoplen-ctl-lease-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir(&directory).expect("owned fixture directory");
    let config_file = directory.join("server.toml");
    let mut config = Config::default();
    config.server.public_host = "setup.example.com".into();
    config.server.data_dir = directory.join("data");
    fs::write(
        &config_file,
        format!(
            "[server]\npublic_host = 'setup.example.com'\ndata_dir = '{}'\n",
            config.server.data_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("local fixture configuration");
    bootstrap(&config).expect("private fixture material");
    let exclusive = DeploymentLease::try_exclusive(&config.server.data_dir)
        .expect("offline operation owns deployment");
    let output = Command::new(env!("CARGO_BIN_EXE_splctl"))
        .args(["bootstrap", "--reissue-pending", "--config"])
        .arg(&config_file)
        .output()
        .expect("run local reissue while occupied");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "occupied state cannot disclose a setup link");
    assert!(
        matches!(
            DeploymentLease::try_shared(&config.server.data_dir),
            Err(ServerError::DeploymentLeaseOccupied)
        ),
        "exclusive holder remains intact after rejected command"
    );
    assert!(!config.server.data_dir.join("scoplen.sqlite").exists());
    drop(exclusive);
    reissue(&config_file);
    fs::remove_dir_all(directory).expect("remove owned CLI fixture");
}

fn reissue(config: &std::path::Path) -> Vec<u8> {
    let output = Command::new(env!("CARGO_BIN_EXE_splctl"))
        .args(["bootstrap", "--reissue-pending", "--config"])
        .arg(config)
        .output()
        .expect("run local reissue");
    assert!(output.status.success(), "local reissue must succeed");
    assert!(output.stderr.is_empty(), "bootstrap secrets never enter diagnostics");
    let text = std::str::from_utf8(&output.stdout).expect("UTF-8 local output");
    assert_eq!(text.lines().count(), 1);
    let secret = text
        .trim_end()
        .split("https://setup.example.com/setup#token=")
        .nth(1)
        .expect("one-time local fragment link");
    assert_eq!(secret.len(), 43);
    assert!(secret.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
    output.stdout
}
