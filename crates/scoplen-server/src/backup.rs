// SPDX-License-Identifier: AGPL-3.0-only
//! Complete deployment archives. This module never initializes deployment state.

mod files;

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use scoplen_crypto::{PortableExportPassphrase, PortableExportReader, PortableExportWriter};
use scoplen_store::{
    ObjectStorageConfig,
    kms::{LocalAuditSigner, LocalKeyFile},
    object_storage::validate_object_key,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{BUILD_REVISION, Config, TlsMode, deployment_lease::DeploymentLease};
use files::{Staging, io_error};

const MAGIC: &[u8; 8] = b"SPLBKP1\n";
const MAX_ENTRIES: usize = 65_536;
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD: u64 = 64 * 1024 * 1024 * 1024;
const MAX_ARCHIVE: u64 = 65 * 1024 * 1024 * 1024;
const COPY_BUFFER: usize = 65_536;
const MAX_KEY_MATERIAL: u64 = 65_536;

type Result<T> = std::result::Result<T, BackupError>;

/// An actionable operation phase, without archive content or secret-bearing I/O diagnostics.
#[derive(Debug, Error)]
#[error("backup failed: {0}")]
pub struct BackupError(&'static str);

fn fail(phase: &'static str) -> BackupError {
    BackupError(phase)
}

/// Non-secret settings the operator must preserve when starting a restored deployment.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReport {
    /// The durable, original HTTPS origin.
    pub origin: String,
    /// The original effective TLS mode.
    pub tls_mode: String,
    /// The public host, supplied again through operator configuration.
    pub public_host: String,
    /// The public HTTPS port, supplied again through operator configuration.
    pub public_port: u16,
    /// The file certificate must be supplied separately.
    pub external_tls_certificate: bool,
    /// The file private key must be supplied separately.
    pub external_tls_key: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Migration {
    version: i64,
    checksum: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    source_revision: String,
    migrations: Vec<Migration>,
    settings: BackupReport,
    #[serde(deserialize_with = "deserialize_entries")]
    entries: Vec<Entry>,
}

fn deserialize_entries<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Entry>, D::Error> {
    struct Entries;
    impl<'de> serde::de::Visitor<'de> for Entries {
        type Value = Vec<Entry>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most 65536 payload entries")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            while entries.len() < MAX_ENTRIES {
                let Some(entry) = sequence.next_element()? else {
                    return Ok(entries);
                };
                entries.push(entry);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("too many payload entries"));
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(Entries)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    resource: Resource,
    length: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "kind", content = "key", rename_all = "snake_case", deny_unknown_fields)]
enum Resource {
    Database,
    DeploymentKey,
    KmsKey,
    AuditKey,
    InternalCaCertificate,
    InternalCaKey,
    TlsCertificate,
    TlsKey,
    Acme(String),
    Object(String),
}

impl Resource {
    fn key_material(&self) -> bool {
        !matches!(self, Self::Database | Self::Object(_) | Self::Acme(_))
    }

    fn destination(&self) -> Result<PathBuf> {
        let value = match self {
            Self::Database => "scoplen.sqlite".into(),
            Self::DeploymentKey => "deployment.key".into(),
            Self::KmsKey => "kms.key".into(),
            Self::AuditKey => "audit-signing.key".into(),
            Self::InternalCaCertificate => "internal-ca.pem".into(),
            Self::InternalCaKey => "internal-ca-key.pem".into(),
            Self::TlsCertificate => "tls/certificate.pem".into(),
            Self::TlsKey => "tls/private-key.pem".into(),
            Self::Acme(name) => {
                if !valid_acme_name(name) {
                    return Err(fail("unsupported ACME cache entry"));
                }
                format!("acme-cache/{name}")
            }
            Self::Object(key) => {
                validate_object_key(key).map_err(|_| fail("invalid object key"))?;
                format!("objects/{key}")
            }
        };
        let path = PathBuf::from(value);
        if path.is_absolute()
            || path.components().any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(fail("invalid logical resource destination"));
        }
        Ok(path)
    }
}

fn valid_acme_name(name: &str) -> bool {
    name.strip_prefix("cached_account_").or_else(|| name.strip_prefix("cached_cert_")).is_some_and(
        |digest| {
            digest.len() == 43
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        },
    )
}

fn revision() -> Result<&'static str> {
    BUILD_REVISION
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            fail("source revision is unknown; use a release built with SCOPLEN_BUILD_REVISION")
        })
}

fn passphrase(path: &Path) -> Result<PortableExportPassphrase> {
    let path = files::existing(path, false)?;
    let mut input = File::open(path).map_err(io_error("open passphrase file"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut input).take(4097).read_to_end(&mut bytes).map_err(io_error("read passphrase file"))?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(fail("passphrase file must contain 1 to 4096 exact UTF-8 bytes"));
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| fail("passphrase file must be UTF-8"))?;
    PortableExportPassphrase::new(value.to_owned()).map_err(|_| fail("invalid passphrase file"))
}

fn digest_file(path: &Path, mut output: Option<&mut dyn Write>) -> Result<(u64, String)> {
    let path = files::existing(path, false)?;
    let mut input = File::open(path).map_err(io_error("open payload"))?;
    let declared = input.metadata().map_err(io_error("read payload size"))?.len();
    if declared > MAX_PAYLOAD {
        return Err(fail("payload exceeds the 64 GiB archive profile"));
    }
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = Zeroizing::new(vec![0_u8; COPY_BUFFER]);
    loop {
        let read = input.read(&mut buffer[..]).map_err(io_error("read payload"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|length| *length <= declared)
            .ok_or_else(|| fail("payload changed during backup"))?;
        hash.update(&buffer[..read]);
        if let Some(output) = output.as_mut() {
            output.write_all(&buffer[..read]).map_err(io_error("write encrypted payload"))?;
        }
    }
    if total != declared {
        return Err(fail("payload changed during backup"));
    }
    Ok((total, hex(&hash.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("write to String");
    }
    value
}

fn walk(
    root: &Path,
    current: &Path,
    objects: bool,
    inventory: &mut Vec<(Resource, PathBuf)>,
) -> Result<()> {
    for item in fs::read_dir(current).map_err(io_error("enumerate local inventory"))? {
        let path = item.map_err(io_error("read local inventory entry"))?.path();
        let kind =
            fs::symlink_metadata(&path).map_err(io_error("read local inventory type"))?.file_type();
        if kind.is_symlink() {
            return Err(fail("links are not supported in the local inventory"));
        }
        if kind.is_dir() {
            files::existing(&path, true)?;
            walk(root, &path, objects, inventory)?;
        } else {
            let path = files::existing(&path, false)?;
            let relative =
                path.strip_prefix(root).map_err(|_| fail("local inventory escaped its root"))?;
            let key = relative
                .components()
                .map(|part| {
                    part.as_os_str()
                        .to_str()
                        .ok_or_else(|| fail("local resource names must be UTF-8"))
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            let resource = if objects { Resource::Object(key) } else { Resource::Acme(key) };
            resource.destination()?;
            if inventory.len() == MAX_ENTRIES {
                return Err(fail("archive exceeds 65536 payload entries"));
            }
            inventory.push((resource, path));
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.version != 1 || manifest.source_revision != revision()? {
        return Err(fail("archive requires its matching source revision"));
    }
    if manifest.entries.len() > MAX_ENTRIES {
        return Err(fail("archive exceeds 65536 payload entries"));
    }
    let mut destinations = BTreeSet::new();
    let mut total = 0_u64;
    for entry in &manifest.entries {
        if entry.resource.key_material() && entry.length > MAX_KEY_MATERIAL {
            return Err(fail(
                "required key or managed certificate material exceeds its supported encoding",
            ));
        }
        let destination = entry.resource.destination()?;
        if !destinations.insert(destination) {
            return Err(fail("duplicate archive resource"));
        }
        if entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(fail("invalid payload digest"));
        }
        total = total
            .checked_add(entry.length)
            .filter(|length| *length <= MAX_PAYLOAD)
            .ok_or_else(|| fail("archive payload exceeds 64 GiB"))?;
    }
    for required in [
        Resource::Database,
        Resource::DeploymentKey,
        Resource::KmsKey,
        Resource::AuditKey,
        Resource::InternalCaCertificate,
        Resource::InternalCaKey,
    ] {
        if !destinations.contains(&required.destination()?) {
            return Err(fail("archive is missing required deployment material"));
        }
    }
    let settings = &manifest.settings;
    let mut config = Config::default();
    config.server.public_host.clone_from(&settings.public_host);
    config.server.public_port = settings.public_port;
    if config.public_origin().map_err(|_| fail("invalid archived public origin"))?
        != settings.origin
    {
        return Err(fail("archive public origin is inconsistent"));
    }
    match settings.tls_mode.as_str() {
        "plain" | "acme"
            if !settings.external_tls_certificate
                && !settings.external_tls_key
                && !destinations.contains(&Resource::TlsCertificate.destination()?)
                && !destinations.contains(&Resource::TlsKey.destination()?) => {}
        "files" => {
            if destinations.contains(&Resource::TlsCertificate.destination()?)
                == settings.external_tls_certificate
                || destinations.contains(&Resource::TlsKey.destination()?)
                    == settings.external_tls_key
            {
                return Err(fail("archive TLS requirements are incomplete"));
            }
        }
        _ => return Err(fail("unsupported archived TLS settings")),
    }
    Ok(())
}

/// Create a complete encrypted archive under an already acquired exclusive deployment lease.
/// The CLI retains this lease until process exit, including every error path.
///
/// # Errors
/// Unsupported layouts, missing material, incompatible schema and publication failures refuse success.
pub async fn create(
    config: &Config,
    output: &Path,
    passphrase_file: &Path,
    lease: &DeploymentLease,
) -> Result<BackupReport> {
    if !lease.is_exclusive() {
        return Err(fail("offline backup requires exclusive deployment admission"));
    }
    create_archive(config, output, passphrase_file, lease, false).await
}

/// Capture an existing SQLite deployment beside ordinary database writers.
/// The caller retains deployment admission until process exit, including error paths.
///
/// # Errors
///
/// Refuses ACME or any managed cache path, unsupported storage and incomplete source state.
/// External writers to captured local files must be excluded by the operator.
pub async fn create_online(
    config: &Config,
    output: &Path,
    passphrase_file: &Path,
    lease: &DeploymentLease,
) -> Result<BackupReport> {
    validate_online_profile(config)?;
    create_archive(config, output, passphrase_file, lease, false).await
}

pub(crate) async fn create_scheduled(
    config: &Config,
    output: &Path,
    passphrase_file: &Path,
    lease: &DeploymentLease,
) -> Result<BackupReport> {
    create_archive(config, output, passphrase_file, lease, true).await
}

fn validate_online_profile(config: &Config) -> Result<()> {
    if config.tls.mode == TlsMode::Acme {
        return Err(fail("online backup does not support ACME"));
    }
    match fs::symlink_metadata(config.server.data_dir.join("acme-cache")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(fail("online backup requires an absent managed ACME cache path")),
    }
    Ok(())
}

pub(crate) fn validate_schedule(config: &Config) -> Result<()> {
    validate_online_profile(config)?;
    if !config.storage.backend.trim().eq_ignore_ascii_case("sqlite")
        || !config.storage.kms.backend.trim().eq_ignore_ascii_case("local")
    {
        return Err(fail("scheduled backup requires SQLite and local KMS"));
    }
    let ObjectStorageConfig::Filesystem { root } = config
        .storage
        .object_storage_config(&config.server.data_dir)
        .map_err(|_| fail("scheduled backup requires local objects"))?
    else {
        return Err(fail("scheduled backup requires local objects"));
    };
    let directory = files::existing(
        config
            .backup
            .directory
            .as_deref()
            .ok_or_else(|| fail("scheduled backup directory is required"))?,
        true,
    )?;
    #[cfg(windows)]
    crate::windows_private_directory::prepare_directory(&directory, &[])
        .map_err(|_| fail("private scheduled backup directory permissions"))?;
    let password = files::existing(
        config
            .backup
            .passphrase_file
            .as_deref()
            .ok_or_else(|| fail("scheduled backup passphrase file is required"))?,
        false,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for path in [&directory, &password] {
            if fs::metadata(path)
                .map_err(io_error("read scheduled backup permissions"))?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(fail("scheduled backup directory and passphrase must be private"));
            }
        }
    }
    #[cfg(windows)]
    crate::windows_private_directory::prepare_directory(
        password.parent().ok_or_else(|| fail("scheduled passphrase parent"))?,
        std::slice::from_ref(&password),
    )
    .map_err(|_| fail("private scheduled passphrase parent or file permissions"))?;
    for root in [&config.server.data_dir, &root] {
        let root = match fs::symlink_metadata(root) {
            Ok(_) => files::existing(root, true)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::path::absolute(root).map_err(io_error("resolve scheduled source root"))?
            }
            Err(_) => return Err(fail("read scheduled source root")),
        };
        if directory.starts_with(&root) || password.starts_with(&root) {
            return Err(fail("scheduled output and passphrase must be outside source roots"));
        }
    }
    Ok(())
}

async fn create_archive(
    config: &Config,
    output: &Path,
    passphrase_file: &Path,
    lease: &DeploymentLease,
    scheduled: bool,
) -> Result<BackupReport> {
    let runtime = tokio::runtime::Handle::current();
    let config = config.clone();
    let output = output.to_path_buf();
    let passphrase_file = passphrase_file.to_path_buf();
    let lease = lease.clone();
    // Hashing and age encryption are synchronous. The operation owns admission even when
    // its awaiting task is cancelled during the common runtime shutdown deadline.
    tokio::task::spawn_blocking(move || {
        if scheduled {
            validate_schedule(&config)?;
        }
        runtime.block_on(create_archive_inner(&config, &output, &passphrase_file, &lease))
    })
    .await
    .map_err(|_| fail("archive capture task stopped"))?
}

async fn create_archive_inner(
    config: &Config,
    output: &Path,
    passphrase_file: &Path,
    lease: &DeploymentLease,
) -> Result<BackupReport> {
    revision()?;
    let source = files::existing(&config.server.data_dir, true)?;
    if !config.storage.backend.trim().eq_ignore_ascii_case("sqlite") {
        return Err(fail("this backup profile supports only SQLite"));
    }
    let ObjectStorageConfig::Filesystem { root } = config
        .storage
        .object_storage_config(&config.server.data_dir)
        .map_err(|_| fail("unsupported object storage configuration"))?
    else {
        return Err(fail("this backup profile requires local filesystem objects"));
    };
    let objects = files::existing(&root, true)?;
    if source == objects || source.starts_with(&objects) {
        return Err(fail("object storage must not contain the deployment data root"));
    }
    let output = files::destination(output)?;
    let password_path = files::existing(passphrase_file, false)?;
    if [&source, &objects]
        .iter()
        .any(|root| output.starts_with(root) || password_path.starts_with(root))
    {
        return Err(fail(
            "archive output and passphrase input must be outside source data and object roots",
        ));
    }
    let passphrase = passphrase(&password_path)?;
    let staging = Staging::new(output.parent().ok_or_else(|| fail("archive output parent"))?)?;
    let image = staging.0.join("image.sqlite");
    let image_file = files::private_file(&image)?;
    let database = files::existing(&source.join("scoplen.sqlite"), false)?;
    if fs::metadata(&database).map_err(io_error("read source database size"))?.len() > MAX_PAYLOAD {
        return Err(fail("source database exceeds the archive profile"));
    }
    scoplen_store::offline::snapshot(&database, &image, lease.file())
        .await
        .map_err(|_| fail("create consistent existing-only SQLite snapshot"))?;
    drop(image_file);
    let (inventory, settings) = source_inventory(config, &source, &objects, image)?;
    let mut entries = Vec::with_capacity(inventory.len());
    for (resource, path) in &inventory {
        if resource.key_material()
            && fs::metadata(path).map_err(io_error("read key material size"))?.len()
                > MAX_KEY_MATERIAL
        {
            return Err(fail(
                "required key or managed certificate material exceeds its supported encoding",
            ));
        }
        let (length, sha256) = digest_file(path, None)?;
        entries.push(Entry { resource: resource.clone(), length, sha256 });
    }
    let metadata = verify_material(&inventory).await?;
    if metadata.origin != settings.origin {
        return Err(fail("configured origin differs from its durable database binding"));
    }
    let manifest = Manifest {
        version: 1,
        source_revision: revision()?.into(),
        migrations: metadata
            .migrations
            .into_iter()
            .map(|(version, checksum)| Migration { version, checksum })
            .collect(),
        settings,
        entries,
    };
    validate_manifest(&manifest)?;
    let mut encoded = BoundedWriter { inner: Vec::new(), written: 0, limit: MAX_MANIFEST as u64 };
    serde_json::to_writer(&mut encoded, &manifest)
        .map_err(|_| fail("archive manifest exceeds its 16 MiB encoding limit"))?;
    let encoded = encoded.inner;
    let encrypted_path = staging.0.join("archive.age");
    let file = files::private_file(&encrypted_path)?;
    let bounded = BoundedWriter { inner: file, written: 0, limit: MAX_ARCHIVE };
    let mut writer = PortableExportWriter::new(bounded, &passphrase)
        .map_err(|_| fail("initialize age encryption"))?;
    writer.write_all(MAGIC).map_err(io_error("write archive magic"))?;
    writer
        .write_all(&u32::try_from(encoded.len()).map_err(|_| fail("manifest size"))?.to_be_bytes())
        .map_err(io_error("write manifest length"))?;
    writer.write_all(&encoded).map_err(io_error("write manifest"))?;
    for ((_, path), entry) in inventory.iter().zip(&manifest.entries) {
        let (length, sha256) = digest_file(path, Some(&mut writer))?;
        if length != entry.length || sha256 != entry.sha256 {
            return Err(fail("source payload changed during backup"));
        }
    }
    let output_file = writer.finish().map_err(|_| fail("finish authenticated archive"))?.inner;
    output_file.sync_all().map_err(io_error("synchronize archive"))?;
    drop(output_file);
    fs::hard_link(&encrypted_path, &output)
        .map_err(io_error("publish archive without replacing an existing file"))?;
    files::sync_directory(output.parent().ok_or_else(|| fail("archive parent"))?)?;
    Ok(manifest.settings)
}

fn source_inventory(
    config: &Config,
    source: &Path,
    objects: &Path,
    image: PathBuf,
) -> Result<(Vec<(Resource, PathBuf)>, BackupReport)> {
    let mut inventory = vec![
        (Resource::Database, image),
        (Resource::DeploymentKey, source.join("deployment.key")),
        (
            Resource::KmsKey,
            config
                .storage
                .kms_key_file(&config.server.data_dir)
                .map_err(|_| fail("unsupported local KMS dependency"))?,
        ),
        (
            Resource::AuditKey,
            config
                .storage
                .kms_audit_key_file(&config.server.data_dir)
                .map_err(|_| fail("unsupported audit key dependency"))?,
        ),
        (Resource::InternalCaCertificate, source.join("internal-ca.pem")),
        (Resource::InternalCaKey, source.join("internal-ca-key.pem")),
    ];
    let mut settings = BackupReport {
        origin: config.public_origin().map_err(|_| fail("invalid configured public origin"))?,
        public_host: config.server.public_host.clone(),
        public_port: config.server.public_port,
        tls_mode: match config.tls.mode {
            TlsMode::Plain => "plain",
            TlsMode::Files => "files",
            TlsMode::Acme => "acme",
        }
        .into(),
        external_tls_certificate: false,
        external_tls_key: false,
    };
    if config.tls.mode == TlsMode::Files {
        for (resource, path, external) in [
            (
                Resource::TlsCertificate,
                config.tls.cert_file.as_ref(),
                &mut settings.external_tls_certificate,
            ),
            (Resource::TlsKey, config.tls.key_file.as_ref(), &mut settings.external_tls_key),
        ] {
            let path =
                path.ok_or_else(|| fail("file TLS requires certificate and key configuration"))?;
            let absolute =
                std::path::absolute(path).map_err(io_error("resolve TLS requirement"))?;
            let source_absolute = std::path::absolute(&config.server.data_dir)
                .map_err(io_error("resolve source root"))?;
            if absolute.starts_with(&source_absolute)
                || fs::canonicalize(path).is_ok_and(|path| path.starts_with(source))
            {
                inventory.push((resource, files::existing(path, false)?));
            } else {
                *external = true;
            }
        }
    }
    let acme = source.join("acme-cache");
    if fs::symlink_metadata(&acme).is_ok() {
        let acme = files::existing(&acme, true)?;
        walk(&acme, &acme, false, &mut inventory)?;
    }
    walk(objects, objects, true, &mut inventory)?;
    inventory.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok((inventory, settings))
}

async fn verify_material(
    inventory: &[(Resource, PathBuf)],
) -> Result<scoplen_store::offline::Metadata> {
    let find = |wanted: Resource| -> Result<&Path> {
        let destination = wanted.destination()?;
        inventory
            .iter()
            .find(|(resource, _)| resource.destination().ok().as_ref() == Some(&destination))
            .map(|(_, path)| path.as_path())
            .ok_or_else(|| fail("missing required key material"))
    };
    for (resource, path) in inventory {
        if resource.key_material()
            && fs::metadata(path).map_err(io_error("read key material size"))?.len()
                > MAX_KEY_MATERIAL
        {
            return Err(fail(
                "required key or managed certificate material exceeds its supported encoding",
            ));
        }
    }
    LocalKeyFile::load(find(Resource::DeploymentKey)?)
        .map_err(|_| fail("invalid deployment key"))?;
    let kms = LocalKeyFile::load(find(Resource::KmsKey)?)
        .map_err(|_| fail("invalid configured KMS key"))?;
    let audit = LocalAuditSigner::load(find(Resource::AuditKey)?)
        .map_err(|_| fail("invalid audit signing key"))?;
    verify_certificate_pair(
        find(Resource::InternalCaCertificate)?,
        find(Resource::InternalCaKey)?,
    )?;
    if let (Ok(certificate), Ok(key)) = (find(Resource::TlsCertificate), find(Resource::TlsKey)) {
        verify_certificate_pair(certificate, key)?;
    }
    let metadata = scoplen_store::offline::verify(find(Resource::Database)?, &kms, &audit)
        .await
        .map_err(|_| fail("verify SQLite integrity, migrations, retained keys and audit proofs"))?;
    Ok(metadata)
}

fn verify_certificate_pair(certificate: &Path, key: &Path) -> Result<()> {
    let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(
        File::open(certificate).map_err(io_error("open certificate"))?,
    ))
    .collect::<std::io::Result<Vec<_>>>()
    .map_err(io_error("parse certificate"))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        File::open(key).map_err(io_error("open private key"))?,
    ))
    .map_err(io_error("parse private key"))?
    .ok_or_else(|| fail("missing private key"))?;
    rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| fail("prepare certificate verification"))?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| fail("certificate and private key do not match"))?;
    Ok(())
}

struct BoundedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.written.checked_add(bytes.len() as u64).is_none_or(|length| length > self.limit) {
            return Err(std::io::Error::other("archive size bound"));
        }
        let written = self.inner.write(bytes)?;
        self.written += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0];
            return if self.inner.read(&mut probe)? == 0 {
                Ok(0)
            } else {
                Err(std::io::Error::other("archive size bound"))
            };
        }
        let count = output.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut output[..count])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// Verify a complete archive in private scratch storage, without migrating or starting it.
///
/// # Errors
/// Fails for an incompatible, incomplete, unsafe or corrupt archive or required material.
pub async fn verify(archive: &Path, passphrase_file: &Path) -> Result<BackupReport> {
    #[cfg(not(windows))]
    let temporary =
        fs::canonicalize(std::env::temp_dir()).map_err(io_error("resolve temporary storage"))?;
    #[cfg(windows)]
    let temporary = std::env::temp_dir();
    let temporary = files::existing(&temporary, true)?;
    let staging = Staging::new(&temporary)?;
    unpack_and_verify(archive, passphrase_file, &staging.0).await
}

/// Restore only to an absent child directory using atomic no-replace publication.
///
/// # Errors
/// Leaves existing deployments unchanged on authentication, validation or publication failure.
pub async fn restore(
    archive: &Path,
    data_dir: &Path,
    passphrase_file: &Path,
) -> Result<BackupReport> {
    let destination = files::destination(data_dir)?;
    let staging = Staging::new(destination.parent().ok_or_else(|| fail("restore parent"))?)?;
    let report = unpack_and_verify(archive, passphrase_file, &staging.0).await?;
    files::sync_tree(&staging.0)?;
    files::publish_directory(&staging.0, &destination)?;
    Ok(report)
}

async fn unpack_and_verify(
    archive: &Path,
    passphrase_file: &Path,
    root: &Path,
) -> Result<BackupReport> {
    let passphrase = passphrase(passphrase_file)?;
    let archive = files::existing(archive, false)?;
    let input = File::open(&archive).map_err(io_error("open archive"))?;
    if input.metadata().map_err(io_error("read archive length"))?.len() > MAX_ARCHIVE {
        return Err(fail("encrypted archive exceeds 65 GiB"));
    }
    let mut reader = PortableExportReader::new(
        BoundedReader { inner: input, remaining: MAX_ARCHIVE },
        &passphrase,
    )
    .map_err(|_| fail("authenticate age header or unsupported age work factor"))?;
    let mut magic = [0_u8; 8];
    reader.read_exact(&mut magic).map_err(io_error("read archive magic"))?;
    if &magic != MAGIC {
        return Err(fail("unsupported archive framing"));
    }
    let mut length = [0; 4];
    reader.read_exact(&mut length).map_err(io_error("read manifest length"))?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| fail("manifest length"))?;
    if length == 0 || length > MAX_MANIFEST {
        return Err(fail("archive manifest exceeds 16 MiB"));
    }
    let mut encoded = vec![0; length];
    reader.read_exact(&mut encoded).map_err(io_error("read complete manifest"))?;
    let manifest: Manifest =
        serde_json::from_slice(&encoded).map_err(|_| fail("invalid or unknown manifest fields"))?;
    validate_manifest(&manifest)?;
    files::private_directory(&root.join("objects"))?;
    let mut inventory = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let path = root.join(entry.resource.destination()?);
        files::parents(root, &path)?;
        let mut output = files::private_file(&path)?;
        let mut hash = Sha256::new();
        let mut remaining = entry.length;
        let mut buffer = Zeroizing::new(vec![0_u8; COPY_BUFFER]);
        while remaining != 0 {
            let count = usize::try_from(remaining.min(COPY_BUFFER as u64))
                .map_err(|_| fail("payload length"))?;
            reader
                .read_exact(&mut buffer[..count])
                .map_err(io_error("read authenticated payload"))?;
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count]).map_err(io_error("write private payload"))?;
            remaining -= count as u64;
        }
        if hex(&hash.finalize()) != entry.sha256 {
            return Err(fail("payload digest mismatch"));
        }
        output.sync_all().map_err(io_error("synchronize restored payload"))?;
        drop(output);
        inventory.push((entry.resource.clone(), path));
    }
    reader
        .finish()
        .map_err(|_| fail("archive has trailing plaintext or incomplete age authentication"))?;
    let metadata = verify_material(&inventory).await?;
    if metadata.origin != manifest.settings.origin
        || metadata.migrations.len() != manifest.migrations.len()
        || metadata.migrations.iter().zip(&manifest.migrations).any(
            |((version, checksum), expected)| {
                *version != expected.version || *checksum != expected.checksum
            },
        )
    {
        return Err(fail(
            "manifest does not match the durable database origin or migration history",
        ));
    }
    Ok(manifest.settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(entries: &str) -> String {
        format!(
            r#"{{"version":1,"source_revision":"test","migrations":[],"settings":{{"origin":"https://localhost","tls_mode":"plain","public_host":"localhost","public_port":443,"external_tls_certificate":false,"external_tls_key":false}},"entries":[{entries}]}}"#
        )
    }

    #[test]
    fn closed_schema_refuses_unknown_and_duplicate_fields_and_resources() {
        let valid = encoded("");
        assert!(serde_json::from_str::<Manifest>(&valid).is_ok());
        for invalid in [
            valid.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            valid.replacen("\"version\":1", "\"version\":1,\"future\":true", 1),
            encoded(r#"{"resource":{"kind":"unknown"},"length":0,"sha256":""}"#),
            encoded(
                r#"{"resource":{"kind":"database","path":"/tmp/override"},"length":0,"sha256":""}"#,
            ),
        ] {
            assert!(serde_json::from_str::<Manifest>(&invalid).is_err());
        }
    }

    #[test]
    fn manifest_entry_count_is_bounded_during_decode() {
        let entry = r#"{"resource":{"kind":"database"},"length":0,"sha256":""}"#;
        let entries = vec![entry; MAX_ENTRIES + 1].join(",");
        assert!(serde_json::from_str::<Manifest>(&encoded(&entries)).is_err());
    }

    #[test]
    fn resource_destinations_preserve_valid_keys_and_refuse_escaping_names() {
        assert_eq!(
            Resource::Object("a/b".into()).destination().expect("valid unchanged key"),
            PathBuf::from("objects/a/b")
        );
        #[cfg(not(windows))]
        assert!(Resource::Object("a/b:c".into()).destination().is_ok());
        assert!(Resource::Object("x".repeat(1025)).destination().is_err());
        for name in ["../escape", "/absolute", "a/../../escape", "a\\escape"] {
            assert!(Resource::Object(name.into()).destination().is_err());
        }
        assert!(Resource::Acme(format!("cached_cert_{}", "a".repeat(43))).destination().is_ok());
        assert!(Resource::Acme("unknown".into()).destination().is_err());
    }

    #[test]
    fn stream_limits_reject_overflow_before_writing_and_never_fake_eof() {
        let mut writer = BoundedWriter { inner: Vec::new(), written: 0, limit: 3 };
        writer.write_all(b"abc").expect("at bound");
        assert!(writer.write_all(b"d").is_err());
        assert_eq!(writer.inner, b"abc");
        let mut reader = BoundedReader { inner: &b"abcd"[..], remaining: 3 };
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
        assert_eq!(output, b"abc");
    }

    #[tokio::test]
    async fn local_objects_keep_colon_and_literal_percent_key_access_after_restore() {
        #[cfg(not(windows))]
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("test temporary directory");
        #[cfg(windows)]
        let temporary = std::env::temp_dir();
        let fixture = Staging::new(&temporary).expect("private test parent");
        let mut config = Config::default();
        config.server.public_host = "backup.example.com".into();
        config.server.data_dir = fixture.0.join("source");
        crate::reissue_operator_setup(&config).await.expect("existing initialized deployment");
        let source = scoplen_store::ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: config.server.data_dir.join("objects"),
        })
        .expect("existing local object store");
        for (key, bytes) in
            [("nested/colon:a", b"colon".as_slice()), ("nested/literal%3Ab", b"percent".as_slice())]
        {
            source.put(key, bytes.to_vec()).await.expect("public object write");
            assert_eq!(source.get(key).await.expect("public original read").as_ref(), bytes);
        }
        let password = fixture.0.join("passphrase");
        private_test_file(&password, b"synthetic-exact-passphrase\n");
        let archive = fixture.0.join("backup.age");
        let lease = DeploymentLease::try_exclusive(&config.server.data_dir).expect("offline lease");
        create(&config, &archive, &password, &lease).await.expect("complete archive");
        let destination = fixture.0.join("restored");
        restore(&archive, &destination, &password).await.expect("verified restore");
        let restored =
            scoplen_store::ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
                root: destination.join("objects"),
            })
            .expect("restored local object store");
        for (key, bytes) in
            [("nested/colon:a", b"colon".as_slice()), ("nested/literal%3Ab", b"percent".as_slice())]
        {
            assert_eq!(restored.get(key).await.expect("public restored read").as_ref(), bytes);
        }
    }

    fn private_test_file(path: &Path, bytes: &[u8]) {
        files::private_file(path)
            .expect("private fixture file")
            .write_all(bytes)
            .expect("fixture bytes");
    }
}
