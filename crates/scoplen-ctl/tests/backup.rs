// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use scoplen_server::{Config, bootstrap, deployment_lease::DeploymentLease};
use uuid::Uuid;

const PASSPHRASE: &[u8] = b"synthetic-offline-archive-passphrase";
const OBJECT: &[u8] = b"\x00\xff\x01binary\x00archive\xfeobject\n";

struct Fixture {
    directory: PathBuf,
    config: PathBuf,
    data: PathBuf,
    passphrase: PathBuf,
    archive: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = std::env::temp_dir();
        #[cfg(not(windows))]
        let temporary =
            temporary.canonicalize().expect("existing operating-system temporary parent");
        let directory = temporary.join(format!("scoplen-backup-cli-{}", Uuid::now_v7()));
        let mut parent = Config::default();
        parent.server.public_host = "backup.example.com".into();
        parent.server.data_dir.clone_from(&directory);
        bootstrap(&parent).expect("private owned fixture parent");
        let config = directory.join("server.toml");
        let data = directory.join("source");
        fs::write(&config, configuration(&data)).expect("source configuration");
        let initialized = cli(&["bootstrap", "--reissue-pending", "--config"], &[&config]);
        assert!(initialized.status.success(), "public initialization must succeed");
        assert!(initialized.stderr.is_empty(), "setup secret must remain in captured stdout");
        let passphrase = directory.join("passphrase.txt");
        private_write(&passphrase, PASSPHRASE);
        fs::create_dir_all(data.join("objects/nested")).expect("object parent");
        private_write(&data.join("objects/nested/binary-object"), OBJECT);
        private_write(&data.join("unrelated-file"), b"excluded deployment file");
        Self { archive: directory.join("backup.age"), directory, config, data, passphrase }
    }

    fn create(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_splctl"))
            .args(["backup", "create", "--config"])
            .arg(&self.config)
            .arg("--output")
            .arg(&self.archive)
            .arg("--passphrase-file")
            .arg(&self.passphrase)
            .output()
            .expect("public backup create")
    }

    fn verify(archive: &Path, passphrase: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_splctl"))
            .args(["backup", "verify", "--archive"])
            .arg(archive)
            .arg("--passphrase-file")
            .arg(passphrase)
            .output()
            .expect("public backup verify")
    }

    fn restore(archive: &Path, target: &Path, passphrase: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_splctl"))
            .args(["backup", "restore", "--archive"])
            .arg(archive)
            .arg("--data-dir")
            .arg(target)
            .arg("--passphrase-file")
            .arg(passphrase)
            .output()
            .expect("public backup restore")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).expect("remove owned backup fixture");
    }
}

fn configuration(data: &Path) -> String {
    format!(
        "[server]\npublic_host = 'backup.example.com'\ndata_dir = '{}'\n",
        data.to_string_lossy().replace('\\', "/")
    )
}

fn private_write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("private fixture file");
    file.write_all(bytes).expect("fixture contents");
}

fn cli(prefix: &[&str], paths: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_splctl"))
        .args(prefix)
        .args(paths)
        .output()
        .expect("public CLI")
}

fn success(output: &Output, first_line: &str) {
    let diagnostic = std::str::from_utf8(&output.stderr)
        .ok()
        .map(str::trim_end)
        .filter(|text| {
            text.strip_prefix("splctl: backup failed: ").is_some_and(|phase| {
                phase.len() <= 256
                    && phase.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b',' | b';' | b'-')
                    })
            })
        })
        .unwrap_or("unrecognized or absent backup diagnostic");
    assert_eq!(output.status.code(), Some(0), "public command must succeed: {diagnostic}");
    assert!(output.stderr.is_empty(), "successful command has no diagnostic");
    assert_eq!(
        std::str::from_utf8(&output.stdout).expect("UTF-8 command output").lines().next(),
        Some(first_line)
    );
    assert!(!output.stdout.windows(PASSPHRASE.len()).any(|bytes| bytes == PASSPHRASE));
}

fn failure(output: &Output) {
    assert_eq!(output.status.code(), Some(1), "runtime rejection uses the documented exit code");
    assert!(output.stdout.is_empty(), "failed commands publish no success result");
    assert!(!output.stderr.is_empty(), "rejection provides an actionable diagnostic");
    assert!(!output.stderr.windows(PASSPHRASE.len()).any(|bytes| bytes == PASSPHRASE));
}

#[test]
fn public_archive_round_trip_retains_database_keys_and_binary_objects() {
    let fixture = Fixture::new();
    let database = fs::read(fixture.data.join("scoplen.sqlite")).expect("initialized database");
    success(&fixture.create(), "Backup created.");
    let encrypted = fs::read(&fixture.archive).expect("encrypted archive");
    assert!(!encrypted.windows(OBJECT.len()).any(|bytes| bytes == OBJECT));
    success(&Fixture::verify(&fixture.archive, &fixture.passphrase), "Backup verified.");
    let restored = fixture.directory.join("restored");
    success(
        &Fixture::restore(&fixture.archive, &restored, &fixture.passphrase),
        "Backup restored.",
    );
    for name in ["deployment.key", "audit-signing.key", "internal-ca.pem", "internal-ca-key.pem"] {
        assert!(
            fs::read(restored.join(name)).expect("restored key material")
                == fs::read(fixture.data.join(name)).expect("original key material"),
            "required key bytes are retained"
        );
    }
    assert!(
        fs::read(restored.join("kms.key")).expect("restored KMS mapping")
            == fs::read(fixture.data.join("deployment.key")).expect("original KMS key"),
        "configured KMS bytes are retained"
    );
    assert_eq!(
        fs::read(restored.join("objects/nested/binary-object")).expect("restored binary object"),
        OBJECT
    );
    assert!(
        fs::read(fixture.data.join("scoplen.sqlite")).expect("source database") == database,
        "archive creation preserves the source database"
    );
    for name in [
        "unrelated-file",
        "deployment.lease",
        "scoplen.sqlite-wal",
        "scoplen.sqlite-shm",
        "scoplen.sqlite.migration-snapshots",
    ] {
        assert!(
            !restored.join(name).exists(),
            "operational and unrelated source files are excluded"
        );
    }
    let restored_config = fixture.directory.join("restored.toml");
    fs::write(
        &restored_config,
        format!(
            "{}\n[storage.kms]\nkey_file = '{}'\n",
            configuration(&restored),
            restored.join("kms.key").to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("restored configuration mapping");
    let reopened = cli(&["bootstrap", "--reissue-pending", "--config"], &[&restored_config]);
    assert!(
        reopened.status.success(),
        "public runtime can reopen the restored origin and audit state"
    );
    assert!(reopened.stderr.is_empty(), "setup secret remains captured privately");
}

#[test]
fn wrong_password_and_damaged_archives_never_publish_a_restore() {
    let fixture = Fixture::new();
    success(&fixture.create(), "Backup created.");
    let wrong = fixture.directory.join("wrong-passphrase.txt");
    private_write(&wrong, b"different-synthetic-archive-passphrase");
    failure(&Fixture::verify(&fixture.archive, &wrong));
    let destination = fixture.directory.join("wrong-password-restore");
    failure(&Fixture::restore(&fixture.archive, &destination, &wrong));
    assert!(!destination.exists());
    let bytes = fs::read(&fixture.archive).expect("archive bytes");
    for (name, damaged) in [
        ("truncated.age", bytes[..bytes.len() / 2].to_vec()),
        ("tampered.age", {
            let mut value = bytes.clone();
            let last = value.len() - 1;
            value[last] ^= 1;
            value
        }),
    ] {
        let archive = fixture.directory.join(name);
        private_write(&archive, &damaged);
        failure(&Fixture::verify(&archive, &fixture.passphrase));
        let destination = fixture.directory.join(format!("{name}-restore"));
        failure(&Fixture::restore(&archive, &destination, &fixture.passphrase));
        assert!(!destination.exists(), "invalid input cannot publish a partial deployment");
    }
    assert!(
        !fs::read_dir(&fixture.directory).expect("fixture entries").any(|entry| entry
            .expect("fixture entry")
            .file_name()
            .to_string_lossy()
            .starts_with(".scoplen-backup-")),
        "failed restores remove their own private staging"
    );
}

#[test]
fn occupied_source_missing_keys_and_existing_destinations_are_preserved() {
    let fixture = Fixture::new();
    let lease =
        DeploymentLease::try_shared(&fixture.data).expect("ordinary local deployment admission");
    failure(&fixture.create());
    assert!(!fixture.archive.exists());
    drop(lease);
    success(&fixture.create(), "Backup created.");
    let original_archive = fs::read(&fixture.archive).expect("original archive");
    failure(&fixture.create());
    assert_eq!(fs::read(&fixture.archive).expect("retained archive"), original_archive);
    let existing = fixture.directory.join("existing");
    fs::create_dir(&existing).expect("existing destination");
    private_write(&existing.join("sentinel"), b"retained existing deployment");
    failure(&Fixture::restore(&fixture.archive, &existing, &fixture.passphrase));
    assert_eq!(
        fs::read(existing.join("sentinel")).expect("existing data retained"),
        b"retained existing deployment"
    );
    fs::remove_file(&fixture.archive).expect("remove owned archive for independent key rejection");
    let audit_key = fixture.data.join("audit-signing.key");
    let retained_key = fs::read(&audit_key).expect("required audit key");
    fs::remove_file(&audit_key).expect("remove owned required key fixture");
    failure(&fixture.create());
    assert!(!fixture.archive.exists());
    assert!(!audit_key.exists(), "backup never generates missing deployment keys");
    private_write(&audit_key, &retained_key);
}
