// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("scoplen-account-settings-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).expect("owned configuration fixture");
        Self(directory)
    }

    fn validate(&self, enabled: &str, limit: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_spl-server"));
        command
            .args(["--role", "api", "--validate-config", "--config"])
            .arg(self.0.join("missing.toml"))
            .env("SPL_SERVER_DATA_DIR", self.0.join("data"))
            .env("SPL_SERVER_PUBLIC_HOST", "localhost")
            .env("SPL_TLS_MODE", "plain")
            .env("SPL_STORAGE_BACKEND", "sqlite")
            .env("SPL_ACCOUNTS_REGISTRATION_ENABLED", enabled)
            .env("SPL_ACCOUNTS_USED_ACCOUNT_ID_LIMIT", limit);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        command.output().expect("public configuration validation")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned configuration fixture");
    }
}

#[test]
fn account_environment_overrides_are_validated_without_creating_material() {
    let fixture = Fixture::new();
    for (enabled, limit) in [("false", "25"), ("true", "1048576"), ("", "")] {
        let output = fixture.validate(enabled, limit);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(!fixture.0.join("data").exists());
    }
}

#[test]
fn invalid_account_environment_overrides_fail_before_startup() {
    let fixture = Fixture::new();
    for (enabled, limit, expected) in [
        ("enabled", "25", "SPL_ACCOUNTS_REGISTRATION_ENABLED"),
        ("true", "-1", "SPL_ACCOUNTS_USED_ACCOUNT_ID_LIMIT"),
        ("true", "abc", "SPL_ACCOUNTS_USED_ACCOUNT_ID_LIMIT"),
        ("true", "0", "accounts.used_account_id_limit"),
        ("false", "18446744073709551615", "accounts.used_account_id_limit"),
    ] {
        let output = fixture.validate(enabled, limit);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        assert!(!fixture.0.join("data").exists());
    }
}

#[test]
fn configuration_parse_failures_do_not_disclose_source_or_values() {
    let fixture = Fixture::new();
    let config = fixture.0.join("invalid.toml");
    let marker = "scoplen-test-credential-marker";
    for source in [
        format!("[storage]\ndatabase_url = 'postgres://{marker}\n"),
        format!("[server]\nlisten_port = '{marker}'\n"),
        format!("[tls]\nmode = '{marker}'\n"),
    ] {
        fs::write(&config, source).expect("malformed configuration fixture");
        let mut command = Command::new(env!("CARGO_BIN_EXE_spl-server"));
        command
            .args(["--validate-config", "--config"])
            .arg(&config)
            .env("SPL_SERVER_DATA_DIR", fixture.0.join("data"));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let output = command.output().expect("public configuration validation");
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout.as_slice(), b"");
        let diagnostic = String::from_utf8(output.stderr).expect("UTF-8 configuration diagnostic");
        assert!(diagnostic.contains("could not parse configuration file"));
        assert!(diagnostic.contains(&config.display().to_string()));
        assert!(diagnostic.contains("check TOML syntax and value types"));
        assert!(!diagnostic.contains(marker));
        assert!(!diagnostic.contains("postgres://"));
        assert!(!fixture.0.join("data").exists());
    }
}
