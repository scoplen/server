// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("scoplen-backup-settings-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("owned configuration fixture");
        fs::write(root.join("server.toml"), "[backup]\nenabled = false\ndaily_utc = '00:01'\n")
            .expect("TOML defaults");
        Self(root)
    }

    fn validate(
        &self,
        enabled: &str,
        daily_utc: &str,
        directory: &str,
        passphrase: &str,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_spl-server"));
        command
            .args(["--role", "api", "--validate-config", "--config"])
            .arg(self.0.join("server.toml"))
            .env("SPL_SERVER_DATA_DIR", self.0.join("source"))
            .env("SPL_SERVER_PUBLIC_HOST", "localhost")
            .env("SPL_TLS_MODE", "plain")
            .env("SPL_STORAGE_BACKEND", "sqlite")
            .env("SPL_BACKUP_ENABLED", enabled)
            .env("SPL_BACKUP_DAILY_UTC", daily_utc)
            .env("SPL_BACKUP_DIRECTORY", directory)
            .env("SPL_BACKUP_PASSPHRASE_FILE", passphrase);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        command.output().expect("public configuration command")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned configuration fixture");
    }
}

#[test]
fn backup_environment_is_validated_before_starting_any_role() {
    let fixture = Fixture::new();
    for (enabled, daily, directory, passphrase, expected) in [
        ("false", "23:59", "", "", None),
        ("", "", "", "", None),
        ("enabled", "03:00", "", "", Some("SPL_BACKUP_ENABLED")),
        ("false", "24:00", "", "", Some("backup.daily_utc")),
        ("false", "3:00", "", "", Some("backup.daily_utc")),
        ("true", "03:00", "", "", Some("requires backup.directory")),
        ("true", "03:00", "archives", "", Some("requires backup.directory")),
        ("true", "03:00", "", "passphrase", Some("requires backup.directory")),
        ("true", "03:00", "missing-archive-root", "missing-passphrase", Some("backup failed")),
    ] {
        let output = fixture.validate(enabled, daily, directory, passphrase);
        if let Some(expected) = expected {
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        } else {
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        }
        assert!(!fixture.0.join("source").exists());
    }
}
