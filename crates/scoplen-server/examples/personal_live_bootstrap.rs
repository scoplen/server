// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable, loopback-only public HTTPS bootstrap for independent integration consumers.

use std::{
    fmt::Write as _,
    fs,
    io::Read as _,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{body::Bytes, http::Request};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use scoplen_api::{
    ProblemDetails,
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthRefreshRequest,
        AuthTokenResponse, BrowserAuthTokenResponse,
    },
    operator_auth::{
        OperatorLoginFinishRequest, OperatorLoginOptionsResponse, OperatorSetupFinishRequest,
        OperatorSetupFinishResponse, OperatorSetupOptionsRequest, OperatorSetupOptionsResponse,
    },
    personal_enrollment::{
        PersonalEnrollmentRequest, PersonalEnrollmentResponse, PersonalInvitationResponse,
    },
    sync::{
        SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate, SyncAckRequest, SyncAckResponse,
        SyncChangesResponse, SyncSessionRequest, SyncSessionResponse, SyncWrite, SyncWriteBatch,
        SyncWriteBatchResponse,
    },
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceAuthContext, DeviceCertificate,
    DeviceKeys, DpopProof, DpopTarget, DpopToken, ObjectEnvelope, P256SigningKey,
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext, PersonalVaultKeyWrap, RecoveryBlob,
    RecoveryKey, SymmetricKey, generate_account_keys, generate_device_keys, generate_symmetric_key,
};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};
use scoplen_server::{Config, TlsMode};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsConnector;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

#[path = "../../scoplen-store/tests/support/passkey.rs"]
mod passkey;
#[path = "../src/private_material.rs"]
mod private_material;

type Result<T> = std::result::Result<T, &'static str>;
const MARKER: &str = "disposable-scoplen-public-https-v1";
const SETUP_PREFIX: &str = "one-time operator setup link (keep private): ";
const SETUP_OPTIONS: &str = "/api/v1/auth/operator/setup/options";
const SETUP_FINISH: &str = "/api/v1/auth/operator/setup/finish";
const LOGIN_OPTIONS: &str = "/api/v1/auth/operator/login/options";
const LOGIN_FINISH: &str = "/api/v1/auth/operator/login/finish";
const INVITATIONS: &str = "/api/v1/admin/personal-invitations";

#[derive(Parser)]
#[command(about = "Disposable loopback HTTPS fixture; never use a real deployment or passkey")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new fixture directory. The caller starts/stops spl-server and owns its database.
    Prepare {
        directory: PathBuf,
        /// Private JSON containing only `database_url` for an empty `scoplen_fixture_*` database.
        #[arg(long)]
        postgres_config: Option<PathBuf>,
        /// Fixed unprivileged port, or a currently available port when omitted.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1024..))]
        port: Option<u16>,
    },
    /// Once only: perform public Operator setup/login and issue a Personal invitation.
    Bootstrap {
        directory: PathBuf,
        /// Private stdout capture from the first production server startup; defaults to server.log.
        #[arg(long)]
        server_log: Option<PathBuf>,
    },
    /// Enroll, save a Host, and retain native credentials in RAM across a caller-owned restart.
    CheckNativeRestart { directory: PathBuf },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresConfig {
    database_url: String,
}

#[derive(Serialize)]
struct Descriptor<'a> {
    disposable: bool,
    origin: &'a str,
    invitation_url: &'a str,
    ca_certificate: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("personal_live_bootstrap: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<()> {
    if std::env::vars_os()
        .any(|(name, _)| name.to_string_lossy().to_ascii_uppercase().starts_with("SPL_"))
    {
        return Err("unset SPL_* overrides before preparing or using a disposable fixture");
    }
    match command {
        Command::Prepare { directory, postgres_config, port } => {
            prepare(&directory, postgres_config.as_deref(), port)?;
            println!("fixture prepared");
        }
        Command::Bootstrap { directory, server_log } => {
            bootstrap(&directory, server_log.as_deref()).await?;
            println!("fixture descriptor ready");
        }
        Command::CheckNativeRestart { directory } => {
            tokio::time::timeout(Duration::from_secs(240), check_native_restart(&directory))
                .await
                .map_err(
                    |_| "native restart check exceeded its deadline; abandon this fixture",
                )??;
            println!("native restart check passed");
        }
    }
    Ok(())
}

fn prepare(directory: &Path, postgres_config: Option<&Path>, port: Option<u16>) -> Result<()> {
    let parent = fs::canonicalize(
        directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )
    .map_err(|_| "fixture parent must already exist")?;
    if parent.ancestors().any(|path| path.join(".git").exists()) {
        return Err("fixture directory must be outside every Git checkout");
    }
    let postgres = postgres_config
        .map(|path| {
            let source = read_bounded(path, 16_384)?;
            let config: PostgresConfig =
                serde_json::from_str(&source).map_err(|_| "invalid private PostgreSQL JSON")?;
            validate_postgres(&config.database_url)?;
            Ok::<_, &'static str>(Zeroizing::new(config.database_url))
        })
        .transpose()?;
    let port = port.map_or_else(
        || {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .and_then(|listener| listener.local_addr())
                .map(|address| address.port())
                .map_err(|_| "could not select a loopback port")
        },
        Ok,
    )?;
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    let directory = parent.join(directory.file_name().ok_or("fixture directory name missing")?);
    builder
        .create(&directory)
        .map_err(|_| "fixture directory must be new with an existing private parent")?;
    let result = prepare_files(&directory, postgres.as_deref().map(String::as_str), port);
    if result.is_err() {
        // This path was just exclusively created above; it never names an existing deployment.
        if fs::remove_dir_all(&directory).is_err() {
            return Err(
                "prepare failed; remove the newly created private fixture directory manually",
            );
        }
    }
    result
}

fn prepare_files(directory: &Path, postgres: Option<&str>, port: u16) -> Result<()> {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| "CA parameters failed")?;
    ca_params.distinguished_name.push(DnType::CommonName, "Scoplen disposable fixture CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().map_err(|_| "CA generation failed")?;
    let ca = ca_params.self_signed(&ca_key).map_err(|_| "CA signing failed")?;
    let leaf_key = KeyPair::generate().map_err(|_| "TLS key generation failed")?;
    let leaf = CertificateParams::new(vec!["localhost".into()])
        .map_err(|_| "TLS parameters failed")?
        .signed_by(&leaf_key, &ca, &ca_key)
        .map_err(|_| "TLS certificate signing failed")?;
    write_private(&directory.join("ca.pem"), &ca.pem())?;
    write_private(&directory.join("localhost.pem"), &format!("{}{}", leaf.pem(), ca.pem()))?;
    write_private(&directory.join("localhost-key.pem"), &Zeroizing::new(leaf_key.serialize_pem()))?;
    let mut value = serde_json::json!({
        "server": {
            "listen_addr": "127.0.0.1", "listen_port": port,
            "public_host": "localhost", "public_port": port, "data_dir": directory.join("data"),
        },
        "tls": { "mode": "files", "cert_file": directory.join("localhost.pem"),
                 "key_file": directory.join("localhost-key.pem") },
        "roles": { "names": ["api"] },
        "console": { "assets_dir": directory.join("unused-console") },
        "storage": { "backend": if postgres.is_some() { "postgres" } else { "sqlite" } },
    });
    if let Some(url) = postgres {
        value["storage"]["database_url"] = url.into();
    }
    let config = Zeroizing::new(toml::to_string(&value).map_err(|_| "config encoding failed")?);
    write_private(&directory.join("server.toml"), &config)?;
    write_private(&directory.join(".scoplen-disposable-fixture"), MARKER)
}

fn validate_postgres(value: &str) -> Result<()> {
    let url = Url::parse(value).map_err(|_| "invalid private PostgreSQL URL")?;
    let name = url.path().strip_prefix('/').unwrap_or_default();
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        || !name.starts_with("scoplen_fixture_")
        || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "PostgreSQL must be loopback with an empty disposable scoplen_fixture_* database and no URL query",
        );
    }
    Ok(())
}

fn write_private(path: &Path, value: &str) -> Result<()> {
    private_material::write_private(path, value)
        .map_err(|_| "could not exclusively write private fixture material")
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)
        .and_then(|file| file.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "could not read private fixture input")?;
    if bytes.len() > maximum {
        return Err("private fixture input exceeds its size limit");
    }
    std::str::from_utf8(&bytes)
        .map(|value| Zeroizing::new(value.to_owned()))
        .map_err(|_| "private fixture input is not UTF-8")
}

fn fixture_config(directory: &Path) -> Result<Config> {
    if read_bounded(&directory.join(".scoplen-disposable-fixture"), 128)?.as_str()
        != format!("{MARKER}\n")
    {
        return Err("directory is not a prepared disposable fixture");
    }
    let source = read_bounded(&directory.join("server.toml"), 16_384)?;
    let config: Config = toml::from_str(&source).map_err(|_| "prepared config is invalid")?;
    if config.server.listen_addr != "127.0.0.1"
        || config.server.public_host != "localhost"
        || config.server.listen_port < 1024
        || config.server.listen_port != config.server.public_port
        || config.server.data_dir != directory.join("data")
        || config.tls.mode != TlsMode::Files
        || config.tls.cert_file.as_deref() != Some(directory.join("localhost.pem").as_path())
        || config.tls.key_file.as_deref() != Some(directory.join("localhost-key.pem").as_path())
    {
        return Err("prepared config must retain its owned loopback HTTPS boundary");
    }
    match config.storage.backend.as_str() {
        "sqlite" if config.storage.database_url.is_none() => {}
        "postgres" => {
            let value: toml::Value =
                toml::from_str(&source).map_err(|_| "prepared config is invalid")?;
            validate_postgres(
                value
                    .get("storage")
                    .and_then(|v| v.get("database_url"))
                    .and_then(toml::Value::as_str)
                    .ok_or("PostgreSQL URL missing")?,
            )?;
        }
        _ => return Err("prepared storage backend is invalid"),
    }
    Ok(config)
}

fn setup_token(log: &str, origin: &str) -> Result<[u8; 32]> {
    let mut links = log.lines().filter_map(|line| line.strip_prefix(SETUP_PREFIX));
    let link = links.next().ok_or("first-start setup link missing from private server log")?;
    if links.next().is_some() {
        return Err("private server log contains multiple setup links; use a fresh fixture");
    }
    let token = link
        .strip_prefix(&format!("{origin}/setup#token="))
        .ok_or("setup link does not match prepared origin")?;
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "invalid setup token")?
        .try_into()
        .map_err(|_| "invalid setup token length")?;
    if URL_SAFE_NO_PAD.encode(bytes) != token {
        return Err("invalid setup token encoding");
    }
    Ok(bytes)
}

async fn bootstrap(directory: &Path, server_log: Option<&Path>) -> Result<()> {
    let directory = fs::canonicalize(directory).map_err(|_| "fixture directory missing")?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin is invalid")?;
    let log = read_bounded(server_log.unwrap_or(&directory.join("server.log")), 4_194_304)?;
    let token = setup_token(&log, &origin)?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    if directory.join("descriptor.json").exists() {
        return Err("descriptor already exists; use a fresh fixture");
    }
    write_private(
        &directory.join("bootstrap.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    let invitation = public_flow(&https, token).await?;
    let descriptor = Descriptor {
        disposable: true,
        origin: &https.origin,
        invitation_url: &invitation.invitation_url,
        ca_certificate: directory.join("ca.pem"),
    };
    let json = Zeroizing::new(
        serde_json::to_string_pretty(&descriptor).map_err(|_| "descriptor encoding failed")?,
    );
    if json.len() > 8_192 {
        return Err("descriptor exceeds consumer size limit; use a shorter fixture path");
    }
    let pending = directory.join("descriptor.pending");
    let result = write_private(&pending, &json).and_then(|()| {
        fs::rename(&pending, directory.join("descriptor.json"))
            .map_err(|_| "descriptor publication failed")
    });
    if result.is_err() {
        let _ = fs::remove_file(pending);
    }
    result
}

async fn public_flow(https: &Https, token: [u8; 32]) -> Result<PersonalInvitationResponse> {
    let key =
        scoplen_crypto::generate_p256_signing_key().map_err(|_| "DPoP key generation failed")?;
    let mut authenticator = passkey::ResidentPasskey::authenticator();
    let request = OperatorSetupOptionsRequest { setup_token: token }
        .to_json()
        .map_err(|_| "setup options encoding failed")?;
    let reply = https.post(SETUP_OPTIONS, &request, &key, None, 200).await?;
    let setup = OperatorSetupOptionsResponse::from_json(&reply)
        .map_err(|_| "setup options response invalid")?;
    let options: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|_| "setup options JSON invalid")?;
    let credential = authenticator
        .do_registration(
            Url::parse(&https.origin).map_err(|_| "fixture origin invalid")?,
            passkey::creation(&options["public_key"]),
        )
        .map_err(|_| "software passkey registration failed")?;
    let request = OperatorSetupFinishRequest {
        setup_token: token,
        ceremony_id: setup.ceremony_id,
        credential_id: credential.raw_id.as_ref().to_vec(),
        client_data_json: credential.response.client_data_json.as_ref().to_vec(),
        attestation_object: credential.response.attestation_object.as_ref().to_vec(),
    }
    .to_json()
    .map_err(|_| "setup finish encoding failed")?;
    let reply = https.post(SETUP_FINISH, &request, &key, None, 201).await?;
    OperatorSetupFinishResponse::from_json(&reply).map_err(|_| "setup finish response invalid")?;
    let reply = https.post(LOGIN_OPTIONS, b"{}", &key, None, 200).await?;
    let login = OperatorLoginOptionsResponse::from_json(&reply)
        .map_err(|_| "login options response invalid")?;
    let options: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|_| "login options JSON invalid")?;
    let assertion = authenticator
        .do_authentication(
            Url::parse(&https.origin).map_err(|_| "fixture origin invalid")?,
            passkey::authentication(&options["public_key"]),
        )
        .map_err(|_| "software passkey assertion failed")?;
    let request = OperatorLoginFinishRequest {
        ceremony_id: login.ceremony_id,
        credential_id: assertion.raw_id.as_ref().to_vec(),
        client_data_json: assertion.response.client_data_json.as_ref().to_vec(),
        authenticator_data: assertion.response.authenticator_data.as_ref().to_vec(),
        signature: assertion.response.signature.as_ref().to_vec(),
        user_handle: assertion
            .response
            .user_handle
            .ok_or("resident user handle missing")?
            .as_ref()
            .try_into()
            .map_err(|_| "resident user handle invalid")?,
    }
    .to_json()
    .map_err(|_| "login finish encoding failed")?;
    let reply = https.post(LOGIN_FINISH, &request, &key, None, 200).await?;
    let session = BrowserAuthTokenResponse::from_json(
        std::str::from_utf8(&reply).map_err(|_| "login response is not UTF-8")?,
    )
    .map_err(|_| "login response invalid")?;
    let reply = https.post(INVITATIONS, b"{}", &key, Some(&session.access_token), 201).await?;
    let invitation =
        PersonalInvitationResponse::from_json(&reply).map_err(|_| "invitation response invalid")?;
    if !invitation.invitation_url.starts_with(&format!("{}/invite#token=", https.origin)) {
        return Err("invitation origin does not match prepared fixture");
    }
    Ok(invitation)
}

struct NativeDevice {
    account: Uuid,
    device: Uuid,
    vault: Uuid,
    keys: DeviceKeys,
    vault_key: SymmetricKey,
}

impl NativeDevice {
    fn enrollment(origin: &str, invitation: [u8; 32]) -> Result<(Self, PersonalEnrollmentRequest)> {
        let account = Uuid::now_v7();
        let device = Uuid::now_v7();
        let vault = Uuid::now_v7();
        let keys = generate_device_keys().map_err(|_| "device key generation failed")?;
        let account_keys = generate_account_keys().map_err(|_| "account key generation failed")?;
        let account_kem_public_key: [u8; 32] = account_keys
            .kem
            .public_key()
            .try_into()
            .map_err(|_| "account KEM public key invalid")?;
        let ark = generate_symmetric_key().map_err(|_| "ARK generation failed")?;
        let vault_key = generate_symmetric_key().map_err(|_| "vault key generation failed")?;
        let mut bundle = SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![SyncAccountDeviceWrap {
                device_id: device,
                wrapped_ark: DeviceArkWrap::seal(account, device, keys.kem.public_key(), &ark)
                    .map_err(|_| "device ARK wrapping failed")?
                    .encode()
                    .to_vec(),
            }],
            account_signing_key: AccountSigningKeyWrap::seal(account, &ark, &account_keys.signing)
                .map_err(|_| "account signing key wrapping failed")?
                .encode()
                .to_vec(),
            account_kem_key: AccountKemKeyWrap::seal(account, &ark, &account_keys.kem)
                .map_err(|_| "account KEM wrapping failed")?
                .encode()
                .to_vec(),
            recovery_blob: RecoveryBlob::wrap(
                &RecoveryKey::generate().map_err(|_| "recovery key generation failed")?,
                account,
                &ark,
            )
            .and_then(|blob| blob.encode())
            .map_err(|_| "recovery wrapping failed")?,
            signature: vec![0; 64],
        };
        bundle.signature = account_keys
            .signing
            .sign(&bundle.signature_input().map_err(|_| "account bundle signing input invalid")?)
            .to_vec();
        let certificate = DeviceCertificate::issue(
            &account_keys.signing,
            device,
            account,
            keys.signing.public_key_sec1(),
            keys.kem.public_key().to_vec(),
            "Disposable restart device".into(),
            std::env::consts::OS.into(),
            u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock invalid")?
                    .as_millis(),
            )
            .map_err(|_| "device certificate clock exceeds its bound")?,
        )
        .map_err(|_| "device certificate signing failed")?;
        let wrapped = PersonalVaultKeyWrap::seal(account, vault, 1, &ark, &vault_key)
            .map_err(|_| "Personal vault key wrapping failed")?
            .encode()
            .to_vec();
        let signature = PersonalEnrollmentContext::new(
            origin,
            &invitation,
            account,
            vault,
            PersonalEnrollmentArtifacts {
                account_signing_public_key: &account_keys.signing.public_key(),
                account_kem_public_key: &account_kem_public_key,
                key_bundle_update: &bundle
                    .to_cbor()
                    .map_err(|_| "account bundle encoding failed")?,
                device_certificate: &certificate
                    .encode()
                    .map_err(|_| "certificate encoding failed")?,
                wrapped_personal_vault_key: &wrapped,
            },
        )
        .map_err(|_| "enrollment context invalid")?
        .sign(&keys.signing)
        .map_err(|_| "enrollment signing failed")?;
        let request = PersonalEnrollmentRequest {
            invitation_token: invitation,
            account_id: account,
            personal_vault_id: vault,
            account_signing_public_key: account_keys.signing.public_key(),
            account_kem_public_key,
            key_bundle_update: bundle,
            device_certificate: certificate,
            wrapped_personal_vault_key: wrapped,
            device_signature: signature,
        };
        Ok((Self { account, device, vault, keys, vault_key }, request))
    }

    async fn save_host(&self, https: &Https, token: &str) -> Result<(Object, Vec<u8>)> {
        let mut object = Object::new(Uuid::now_v7(), ObjectType::HOST, 1)
            .map_err(|_| "Host construction failed")?;
        for (field, value) in [(1, "Restart acceptance"), (2, "restart.example.com")] {
            object
                .insert(
                    FieldPath::field(field).map_err(|_| "Host field invalid")?,
                    FieldEntry::new(
                        cbor::Value::Text(value.into()),
                        Hlc::at(1).map_err(|_| "Host clock invalid")?,
                        self.device,
                    )
                    .map_err(|_| "Host field value invalid")?,
                )
                .map_err(|_| "Host field insertion failed")?;
        }
        let payload = ObjectEnvelope::encrypt(
            self.vault,
            1,
            &object,
            &self.vault_key,
            self.device,
            &self.keys.signing,
        )
        .and_then(|envelope| envelope.encode())
        .map_err(|_| "Host encryption failed")?;
        let writes = SyncWriteBatch {
            writes: vec![SyncWrite {
                object_id: object.id,
                base_seq: None,
                payload: payload.clone(),
                tombstone: false,
            }],
        }
        .to_cbor()
        .map_err(|_| "Host write encoding failed")?;
        let path = format!("/sync/v1/vaults/{}/objects", self.vault);
        let reply = https
            .exchange("POST", &path, &writes, Some((&self.keys.signing, Some(token))), 200)
            .await?;
        let assignments =
            SyncWriteBatchResponse::from_cbor(&reply).map_err(|_| "Host write receipt invalid")?;
        if assignments.assignments.len() != 1
            || assignments.assignments[0].seq != 1
            || assignments.assignments[0].object_id != object.id
        {
            return Err("Host write was not committed at the initial sequence");
        }
        self.read_host(https, token, &object, &payload, 1).await?;
        Ok((object, payload))
    }

    async fn authenticate(&self, https: &Https) -> Result<(AuthTokenResponse, Zeroizing<String>)> {
        let request = AuthChallengeRequest::new(self.device)
            .and_then(|value| value.to_json())
            .map_err(|_| "challenge request invalid")?;
        let reply =
            https.exchange("POST", "/api/v1/auth/challenge", request.as_bytes(), None, 200).await?;
        let challenge = AuthChallengeResponse::from_json(
            std::str::from_utf8(&reply).map_err(|_| "challenge response is not UTF-8")?,
        )
        .map_err(|_| "challenge response invalid")?;
        let context = DeviceAuthContext::new(&https.origin, &challenge.nonce, self.device)
            .map_err(|_| "device authentication context invalid")?;
        let mut signature = String::with_capacity(128);
        for byte in self.keys.signing.sign(&context.signature_input()) {
            write!(signature, "{byte:02x}").map_err(|_| "device signature encoding failed")?;
        }
        let request = Zeroizing::new(
            AuthDeviceRequest::new(self.device, challenge.nonce, signature)
                .and_then(|value| value.to_json())
                .map_err(|_| "device authentication request invalid")?,
        );
        let reply =
            https.exchange("POST", "/api/v1/auth/device", request.as_bytes(), None, 200).await?;
        Ok((native_tokens(&reply)?, request))
    }

    async fn refresh(&self, https: &Https, token: &str) -> Result<AuthTokenResponse> {
        let request = Zeroizing::new(
            AuthRefreshRequest::new(token)
                .and_then(|value| value.to_json())
                .map_err(|_| "native refresh request invalid")?,
        );
        let reply = https
            .post("/api/v1/auth/refresh", request.as_bytes(), &self.keys.signing, None, 200)
            .await?;
        native_tokens(&reply)
    }

    async fn denied_refresh(&self, https: &Https, token: &str, changed: bool) -> Result<()> {
        let request = Zeroizing::new(
            AuthRefreshRequest::new(token)
                .and_then(|value| value.to_json())
                .map_err(|_| "native refresh request invalid")?,
        );
        let reply = https
            .post("/api/v1/auth/refresh", request.as_bytes(), &self.keys.signing, None, 401)
            .await?;
        authentication_denied(&reply, changed)
    }

    async fn read_host(
        &self,
        https: &Https,
        token: &str,
        object: &Object,
        payload: &[u8],
        ack_cursor: u64,
    ) -> Result<()> {
        let session = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: self.device,
        }
        .to_cbor()
        .map_err(|_| "sync session request invalid")?;
        let proof = Some((&self.keys.signing, Some(token)));
        let reply = https.exchange("POST", "/sync/v1/session", &session, proof, 200).await?;
        let session =
            SyncSessionResponse::from_cbor(&reply).map_err(|_| "sync session response invalid")?;
        if session.vaults.len() != 1 || session.vaults[0].id != self.vault {
            return Err("restarted session lost the enrolled Personal vault");
        }
        let path = format!("/sync/v1/vaults/{}/changes?after=0&limit=10", self.vault);
        let reply = https.exchange("GET", &path, &[], proof, 200).await?;
        let changes =
            SyncChangesResponse::from_cbor(&reply).map_err(|_| "sync changes response invalid")?;
        if changes.changes.len() != 1
            || changes.next_cursor != 1
            || changes.more
            || changes.changes[0].payload != payload
            || changes.changes[0].seq != 1
            || changes.changes[0].object_id != object.id
            || changes.changes[0].tombstone
        {
            return Err("restarted sync did not return the exact saved Host and sequence");
        }
        let downloaded = ObjectEnvelope::decode(&changes.changes[0].payload)
            .and_then(|envelope| {
                envelope.decrypt(
                    self.vault,
                    object.id,
                    &self.vault_key,
                    &self.keys.signing.public_key_sec1(),
                )
            })
            .map_err(|_| "downloaded Host signature verification or decryption failed")?;
        if downloaded.encode().map_err(|_| "downloaded Host encoding failed")?
            != object.encode().map_err(|_| "saved Host encoding failed")?
        {
            return Err("downloaded Host differs from the saved object");
        }
        let ack =
            SyncAckRequest { cursor: ack_cursor }.to_cbor().map_err(|_| "ACK encoding failed")?;
        let path = format!("/sync/v1/vaults/{}/ack", self.vault);
        let reply = https.exchange("POST", &path, &ack, proof, 200).await?;
        if SyncAckResponse::from_cbor(&reply).map_err(|_| "ACK response invalid")?.cursor != 1 {
            return Err("saved Host ACK was not retained");
        }
        Ok(())
    }
}

fn native_tokens(reply: &[u8]) -> Result<AuthTokenResponse> {
    let tokens = AuthTokenResponse::from_json(
        std::str::from_utf8(reply).map_err(|_| "native token response is not UTF-8")?,
    )
    .map_err(|_| "native token response invalid")?;
    tokens.validate().map_err(|_| "native token response invalid")?;
    Ok(tokens)
}

fn authentication_denied(reply: &[u8], changed: bool) -> Result<()> {
    let problem: ProblemDetails =
        serde_json::from_slice(reply).map_err(|_| "authentication problem invalid")?;
    if problem.code.as_str() != "auth.authentication_required"
        || problem.changed != changed
        || problem.retryable
    {
        return Err("authentication denial has unexpected recovery semantics");
    }
    Ok(())
}

async fn check_native_restart(directory: &Path) -> Result<()> {
    let directory = fs::canonicalize(directory).map_err(|_| "fixture directory missing")?;
    let config = fixture_config(&directory)?;
    let origin = config.public_origin().map_err(|_| "prepared origin invalid")?;
    let descriptor = read_bounded(&directory.join("descriptor.json"), 8_192)?;
    let descriptor: serde_json::Value =
        serde_json::from_str(&descriptor).map_err(|_| "descriptor invalid")?;
    if descriptor["disposable"] != true
        || descriptor["origin"] != origin
        || descriptor["ca_certificate"].as_str() != directory.join("ca.pem").to_str()
    {
        return Err("descriptor does not match the prepared disposable fixture");
    }
    let invitation: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            descriptor["invitation_url"]
                .as_str()
                .and_then(|url| url.strip_prefix(&format!("{origin}/invite#token=")))
                .ok_or("fixture invitation origin invalid")?,
        )
        .map_err(|_| "fixture invitation invalid")?
        .try_into()
        .map_err(|_| "fixture invitation length invalid")?;
    write_private(
        &directory.join("native-restart.started"),
        "One attempt only; discard this fixture after any failure.",
    )?;
    let https = Https::new(&directory, config.server.listen_port, origin)?;
    let (device, request) = NativeDevice::enrollment(&https.origin, invitation)?;
    let request = Zeroizing::new(request.to_json().map_err(|_| "enrollment encoding failed")?);
    let reply = https.exchange("POST", "/api/v1/auth/personal-enroll", &request, None, 201).await?;
    let receipt =
        PersonalEnrollmentResponse::from_json(&reply).map_err(|_| "enrollment receipt invalid")?;
    if receipt.account_id != device.account
        || receipt.device_id != device.device
        || receipt.personal_vault_id != device.vault
    {
        return Err("enrollment receipt changed the requested identity");
    }
    let (issued, _) = device.authenticate(&https).await?;
    if issued.refresh_expires_in <= 240 {
        return Err("fresh refresh lifetime cannot span the bounded restart check");
    }
    let (object, payload) = device.save_host(&https, &issued.access_token).await?;
    println!("native restart check: Host saved and original refresh retained");
    write_private(&directory.join("native-restart.ready"), "ready")?;
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match fs::metadata(directory.join("native-restart.resume")) {
                Ok(_) => {
                    return read_bounded(&directory.join("native-restart.resume"), 16).and_then(
                        |value| {
                            if value.as_str() == "resume\n" {
                                Ok(())
                            } else {
                                Err("invalid native restart resume signal")
                            }
                        },
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => return Err("could not inspect native restart resume signal"),
            }
        }
    })
    .await
    .map_err(|_| "controller did not restart the server before the deadline")??;
    // The first post-restart authentication operation must rotate this original credential.
    println!("native restart check: original native refresh after restart");
    let rotated = device.refresh(&https, &issued.refresh_token).await?;
    if rotated.refresh_token == issued.refresh_token
        || rotated.refresh_expires_in > issued.refresh_expires_in
    {
        return Err("native refresh did not preserve single-use absolute-expiry rotation");
    }
    // A lower ACK must return the persisted maximum; re-sending 1 could repair a lost ACK.
    device.read_host(&https, &rotated.access_token, &object, &payload, 0).await?;
    println!("native restart check: saved Host verified with refreshed access token");
    device.denied_refresh(&https, &issued.refresh_token, true).await?;
    // D-106 / server architecture section 2 sets a one-second first-denial cooldown.
    // Wait before the successor's first attempt so a 429 cannot hide family-revocation behavior.
    tokio::time::sleep(Duration::from_secs(1)).await;
    device.denied_refresh(&https, &rotated.refresh_token, false).await?;
    println!("native restart check: spent credential reuse revoked its family");
    let (recovered, consumed_challenge) = device.authenticate(&https).await?;
    let reply = https
        .exchange("POST", "/api/v1/auth/device", consumed_challenge.as_bytes(), None, 401)
        .await?;
    authentication_denied(&reply, false)?;
    device.read_host(&https, &recovered.access_token, &object, &payload, 1).await?;
    println!("native restart check: fresh challenge recovered and consumed challenge rejected");
    Ok(())
}

struct Https {
    origin: String,
    port: u16,
    connector: TlsConnector,
}

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Https {
    fn new(directory: &Path, port: u16, origin: String) -> Result<Self> {
        let pem = read_bounded(&directory.join("ca.pem"), 65_536)?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
            roots
                .add(cert.map_err(|_| "fixture CA PEM invalid")?)
                .map_err(|_| "fixture CA invalid")?;
        }
        let mut tls = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS 1.3 unavailable")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self { origin, port, connector: TlsConnector::from(Arc::new(tls)) })
    }

    async fn post(
        &self,
        path: &str,
        body: &[u8],
        key: &P256SigningKey,
        token: Option<&str>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.exchange("POST", path, body, Some((key, token)), expected).await
    }

    async fn exchange(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        proof: Option<(&P256SigningKey, Option<&str>)>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        tokio::time::timeout(
            Duration::from_secs(15),
            self.request(method, path, body, proof, expected),
        )
        .await
        .map_err(|_| "HTTPS request timed out; abandon this fixture after an uncertain operation")?
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        proof: Option<(&P256SigningKey, Option<&str>)>,
        expected: u16,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.origin))
            .header(
                "Content-Type",
                if path.starts_with("/sync/") { "application/cbor" } else { "application/json" },
            )
            .header("Origin", &self.origin);
        if let Some((key, token)) = proof {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock invalid")?
                .as_secs();
            let proof = DpopProof::sign(
                key,
                &key.public_key_sec1(),
                &DpopTarget::new(
                    method,
                    &self.origin,
                    path.split('?').next().ok_or("DPoP path missing")?,
                )
                .map_err(|_| "DPoP target invalid")?,
                token.map_or(DpopToken::Refresh, DpopToken::Protected),
                now,
                None,
            )
            .map_err(|_| "DPoP signing failed")?;
            request = request.header("DPoP", proof.as_str());
            if let Some(token) = token {
                request = request.header("Authorization", format!("DPoP {token}"));
            }
        }
        let tcp =
            tokio::net::TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)))
                .await
                .map_err(|_| "loopback server is not running")?;
        let tls = self
            .connector
            .connect(ServerName::try_from("localhost").map_err(|_| "TLS name invalid")?, tcp)
            .await
            .map_err(|_| "fixture TLS certificate verification failed")?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("fixture server did not negotiate HTTP/2");
        }
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .max_header_list_size(16_384)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(|_| "HTTPS connection failed")?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let reply = sender
            .send_request(
                request
                    .body(Full::new(Bytes::copy_from_slice(body)))
                    .map_err(|_| "HTTPS request encoding failed")?,
            )
            .await
            .map_err(|_| "HTTPS request failed; operation outcome may be unknown")?;
        if reply.status().as_u16() != expected {
            return Err(
                "public fixture API rejected request; abandon the fixture and inspect only private server diagnostics",
            );
        }
        let content_type = if expected >= 400 {
            "application/problem+json"
        } else if path.starts_with("/sync/") {
            "application/cbor"
        } else {
            "application/json"
        };
        if reply.headers().get("content-type").and_then(|v| v.to_str().ok()) != Some(content_type)
            || reply.headers().get("cache-control").and_then(|v| v.to_str().ok())
                != Some("no-store")
        {
            return Err("public fixture API response privacy headers invalid");
        }
        if matches!(
            path,
            "/api/v1/auth/device" | "/api/v1/auth/refresh" | "/api/v1/auth/personal-enroll"
        ) && reply.headers().contains_key("set-cookie")
        {
            return Err("native device API unexpectedly returned a browser cookie");
        }
        let bytes = Limited::new(
            reply.into_body(),
            if path.starts_with("/sync/") { 65_536 } else { 8_192 },
        )
        .collect()
        .await
        .map_err(|_| "public bootstrap response exceeds limit or is incomplete")?
        .to_bytes();
        Ok(Zeroizing::new(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            Self(
                std::env::temp_dir().join(format!("scoplen-live-fixture-{}", uuid::Uuid::new_v4())),
            )
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove exclusively owned fixture");
            }
        }
    }

    #[test]
    fn only_explicit_loopback_disposable_databases_are_accepted() {
        for value in [
            "postgres://fixture:synthetic@127.0.0.1:5432/scoplen_fixture_test",
            "postgresql://fixture:synthetic@localhost/scoplen_fixture_test",
            "postgres://fixture:synthetic@[::1]:5432/scoplen_fixture_test",
        ] {
            validate_postgres(value).expect("explicit disposable database");
        }
        for value in [
            "postgres://fixture:synthetic@db.example.com/scoplen_fixture_test",
            "postgres://fixture:synthetic@127.0.0.1/production",
            "postgres://fixture:synthetic@127.0.0.1/scoplen_fixture_test?host=db.example.com",
            "postgres://fixture:synthetic@127.0.0.1/scoplen_fixture_test%2fproduction",
            "file:///scoplen_fixture_test",
        ] {
            assert!(validate_postgres(value).is_err());
        }
    }

    #[test]
    fn prepare_preserves_existing_directories_and_requires_owned_loopback_config() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, Some(18443)).expect("prepare");
        let directory = fs::canonicalize(&scratch.0).expect("canonical fixture");
        let config = fixture_config(&directory).expect("owned config");
        assert_eq!(config.public_origin().unwrap(), "https://localhost:18443");
        let key = fs::read(directory.join("localhost-key.pem")).expect("private key");
        assert!(prepare(&scratch.0, None, Some(18444)).is_err());
        assert_eq!(fs::read(directory.join("localhost-key.pem")).unwrap(), key);
        let path = directory.join("server.toml");
        let config = fs::read_to_string(&path).unwrap().replace("127.0.0.1", "0.0.0.0");
        fs::write(path, config).unwrap();
        assert!(fixture_config(&directory).is_err());
        assert!(!directory.join("descriptor.json").exists());
    }

    #[test]
    fn prepared_ca_and_leaf_have_distinct_subjects_for_schannel_chain_building() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, Some(18443)).expect("prepare");
        let subjects = ["ca.pem", "localhost.pem"].map(|name| {
            let pem = fs::read(scratch.0.join(name)).unwrap();
            let cert = rustls_pemfile::certs(&mut pem.as_slice()).next().unwrap().unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert).unwrap();
            roots.roots[0].subject.as_ref().to_vec()
        });
        assert_ne!(subjects[0], subjects[1]);
    }

    #[test]
    fn setup_capture_requires_one_exact_origin_and_bounded_inputs() {
        let token = URL_SAFE_NO_PAD.encode([7; 32]);
        let log = format!("{SETUP_PREFIX}https://localhost:18443/setup#token={token}\n");
        assert_eq!(setup_token(&log, "https://localhost:18443").unwrap(), [7; 32]);
        assert!(setup_token(&log, "https://localhost:18444").is_err());
        assert!(setup_token(&format!("{log}{log}"), "https://localhost:18443").is_err());
        let scratch = Scratch::new();
        fs::create_dir(&scratch.0).unwrap();
        let path = scratch.0.join("input");
        write_private(&path, "12345678").unwrap();
        assert!(read_bounded(&path, 8).is_err());
        assert!(read_bounded(&path, 9).is_ok());
    }

    #[tokio::test]
    async fn failed_bootstrap_publishes_nothing_and_cannot_repeat_an_uncertain_attempt() {
        let scratch = Scratch::new();
        prepare(&scratch.0, None, None).expect("prepare");
        let directory = fs::canonicalize(&scratch.0).unwrap();
        let config = fixture_config(&directory).unwrap();
        let token = URL_SAFE_NO_PAD.encode([7; 32]);
        write_private(
            &directory.join("server.log"),
            &format!("{SETUP_PREFIX}{}/setup#token={token}", config.public_origin().unwrap()),
        )
        .unwrap();
        assert!(bootstrap(&directory, None).await.is_err());
        assert!(directory.join("bootstrap.started").is_file());
        assert!(!directory.join("descriptor.json").exists());
        assert!(!directory.join("descriptor.pending").exists());
        assert_eq!(
            bootstrap(&directory, None).await.unwrap_err(),
            "could not exclusively write private fixture material"
        );
    }

    #[test]
    fn descriptor_has_only_the_four_consumer_contract_fields() {
        let descriptor = Descriptor {
            disposable: true,
            origin: "https://localhost:18443",
            invitation_url: "https://localhost:18443/invite#token=synthetic",
            ca_certificate: PathBuf::from("/private/fixture/ca.pem"),
        };
        let value = serde_json::to_value(descriptor).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ca_certificate", "disposable", "invitation_url", "origin"]);
    }
}
