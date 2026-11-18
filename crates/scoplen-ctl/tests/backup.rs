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
        self.capture(false)
    }

    fn create_online(&self) -> Output {
        self.capture(true)
    }

    fn capture(&self, online: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_splctl"));
        command.args(["backup", "create"]);
        if online {
            command.arg("--online");
        }
        command
            .arg("--config")
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

#[tokio::test]
async fn online_shared_admission_never_authorizes_the_offline_library_entry() {
    let fixture = Fixture::new();
    let config = Config::load(&fixture.config).expect("existing source config");
    let shared = DeploymentLease::try_shared(&fixture.data).expect("running deployment lease");
    assert!(
        scoplen_server::backup::create(&config, &fixture.archive, &fixture.passphrase, &shared,)
            .await
            .is_err()
    );
    assert!(!fixture.archive.exists());
    failure(&fixture.create());
    success(&fixture.create_online(), "Backup created.");
    success(&Fixture::verify(&fixture.archive, &fixture.passphrase), "Backup verified.");
    let restored = fixture.directory.join("online-restored");
    success(
        &Fixture::restore(&fixture.archive, &restored, &fixture.passphrase),
        "Backup restored.",
    );
    assert_eq!(
        fs::read(restored.join("objects/nested/binary-object")).expect("retained object"),
        OBJECT
    );
    drop(shared);
    fs::remove_file(&fixture.archive).expect("remove owned archive");
    let exclusive = DeploymentLease::try_exclusive(&fixture.data).expect("offline operation lease");
    failure(&fixture.create_online());
    assert!(!fixture.archive.exists());
    drop(exclusive);
}

#[test]
fn online_refuses_every_managed_cache_path_and_missing_keys_without_repair() {
    let fixture = Fixture::new();
    let cache = fixture.data.join("acme-cache");
    fs::create_dir(&cache).expect("empty managed cache");
    failure(&fixture.create_online());
    assert!(cache.is_dir());
    fs::remove_dir(&cache).expect("remove owned cache");
    private_write(&cache, b"not a directory");
    failure(&fixture.create_online());
    fs::remove_file(&cache).expect("remove owned cache file");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(fixture.data.join("absent-cache"), &cache)
            .expect("dangling cache link");
        failure(&fixture.create_online());
        fs::remove_file(&cache).expect("remove owned cache link");
    }
    let key = fixture.data.join("audit-signing.key");
    fs::remove_file(&key).expect("remove owned required key");
    failure(&fixture.create_online());
    assert!(!key.exists());
    assert!(!fixture.archive.exists());
}

#[test]
fn online_refuses_valid_unsupported_profiles_and_source_overlap() {
    let fixture = Fixture::new();
    for (extra, phase) in [
        (
            "[tls]\nmode = 'acme'\nacme_email = 'operator@example.com'\n",
            "online backup does not support ACME",
        ),
        (
            "[storage]\nbackend = 'postgres'\ndatabase_url = 'postgres://localhost/scoplen'\n",
            "this backup profile supports only SQLite",
        ),
        (
            "[storage.object]\nbackend = 's3'\ns3_bucket = 'scoplen-synthetic-backup-test'\n",
            "this backup profile requires local filesystem objects",
        ),
    ] {
        fs::write(&fixture.config, format!("{}\n{extra}", configuration(&fixture.data)))
            .expect("unsupported config");
        let config = Config::load(&fixture.config).expect("valid deployment configuration");
        config
            .validate_for_roles(&[scoplen_server::Role::Api])
            .expect("valid API-role configuration");
        let output = fixture.create_online();
        failure(&output);
        assert_eq!(
            std::str::from_utf8(&output.stderr).unwrap(),
            format!("splctl: backup failed: {phase}\n")
        );
        assert!(!fixture.archive.exists());
    }
    fs::write(&fixture.config, configuration(&fixture.data)).expect("restore owned config");
    let output = fixture.data.join("forbidden.age");
    let rejected = Command::new(env!("CARGO_BIN_EXE_splctl"))
        .args(["backup", "create", "--online", "--config"])
        .arg(&fixture.config)
        .arg("--output")
        .arg(&output)
        .arg("--passphrase-file")
        .arg(&fixture.passphrase)
        .output()
        .expect("overlap rejection");
    failure(&rejected);
    assert!(!output.exists());
}

#[test]
fn online_refuses_kms_configuration_unsupported_by_the_server_baseline() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.config,
        format!("{}\n[storage.kms]\nbackend = 'external'\n", configuration(&fixture.data)),
    )
    .expect("unsupported baseline KMS config");
    let config = Config::load(&fixture.config).expect("syntactically valid KMS configuration");
    assert!(config.validate_for_roles(&[scoplen_server::Role::Api]).is_err());
    failure(&fixture.create_online());
    assert!(!fixture.archive.exists());
}

#[test]
fn online_static_tls_preserves_managed_files_and_existing_output() {
    let fixture = Fixture::new();
    let certificate = fixture.data.join("internal-ca.pem");
    let key = fixture.data.join("internal-ca-key.pem");
    fs::write(
        &fixture.config,
        format!(
            "{}\n[tls]\nmode = 'files'\ncert_file = '{}'\nkey_file = '{}'\n",
            configuration(&fixture.data),
            certificate.display().to_string().replace('\\', "/"),
            key.display().to_string().replace('\\', "/"),
        ),
    )
    .expect("managed static TLS config");
    success(&fixture.create_online(), "Backup created.");
    let archive = fs::read(&fixture.archive).expect("completed online archive");
    failure(&fixture.create_online());
    assert!(
        fs::read(&fixture.archive).expect("preserved archive") == archive,
        "existing online archive must be preserved"
    );
    let restored = fixture.directory.join("static-tls-restored");
    success(
        &Fixture::restore(&fixture.archive, &restored, &fixture.passphrase),
        "Backup restored.",
    );
    assert!(
        fs::read(restored.join("tls/certificate.pem")).expect("restored cert")
            == fs::read(certificate).expect("original cert"),
        "managed certificate bytes must be retained"
    );
    assert!(
        fs::read(restored.join("tls/private-key.pem")).expect("restored key")
            == fs::read(key).expect("original key"),
        "managed private-key bytes must be retained"
    );
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
fn missing_passphrase_refuses_create_verify_and_restore_without_repair() {
    let fixture = Fixture::new();
    success(&fixture.create(), "Backup created.");
    let completed = fixture.directory.join("completed.age");
    fs::rename(&fixture.archive, &completed).expect("retain completed archive");
    let original = fs::read(&completed).expect("retained archive bytes");
    fs::remove_file(&fixture.passphrase).expect("remove owned passphrase input");
    let restored = fixture.directory.join("missing-passphrase-restore");
    for output in [
        fixture.create(),
        fixture.create_online(),
        Fixture::verify(&completed, &fixture.passphrase),
        Fixture::restore(&completed, &restored, &fixture.passphrase),
    ] {
        failure(&output);
    }
    assert!(!fixture.archive.exists());
    assert!(!restored.exists());
    assert!(!fixture.passphrase.exists(), "failed commands must not replace the input");
    assert_eq!(fs::read(&completed).expect("unchanged completed archive"), original);
}

#[cfg(windows)]
#[test]
fn unreadable_passphrase_refuses_create_verify_and_restore_without_repair() {
    use std::os::windows::fs::OpenOptionsExt as _;

    let fixture = Fixture::new();
    success(&fixture.create(), "Backup created.");
    let completed = fixture.directory.join("completed.age");
    fs::rename(&fixture.archive, &completed).expect("retain completed archive");
    let original = fs::read(&completed).expect("retained archive bytes");
    // Mandatory sharing denies reads without changing the fixture's private ACLs.
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&fixture.passphrase)
        .expect("hold owned passphrase without read sharing");
    assert!(fs::read(&fixture.passphrase).is_err(), "the input must actually be unreadable");
    let restored = fixture.directory.join("unreadable-passphrase-restore");
    for output in [
        fixture.create(),
        fixture.create_online(),
        Fixture::verify(&completed, &fixture.passphrase),
        Fixture::restore(&completed, &restored, &fixture.passphrase),
    ] {
        failure(&output);
    }
    assert!(!fixture.archive.exists());
    assert!(!restored.exists());
    drop(held);
    assert_eq!(fs::read(&fixture.passphrase).expect("retained passphrase input"), PASSPHRASE);
    assert_eq!(fs::read(&completed).expect("unchanged completed archive"), original);
    success(&Fixture::verify(&completed, &fixture.passphrase), "Backup verified.");
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
