// SPDX-License-Identifier: AGPL-3.0-only
//! Private three-phase handoff; independent consumers own certificate issuance and SSH/SFTP.

use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use scoplen_api::inventory::{InventoryFields, InventoryReplaceRequest, InventoryResource};
use serde::{Deserialize, Serialize};

use super::{
    Browser, GrantFields, Https, InventoryType, ObjectType, Registration, Result, SimpleRule,
    SimpleRuleSelector, Uuid, asset, ca, create, create_team, exchange, inventory, invite, json,
    native, rule, withdraw,
};
use crate::{read_bounded, write_private};

#[path = "requests_handoff.rs"]
mod requests;

pub(super) async fn prepare_request_client(
    https: &Https,
    directory: &Path,
    openssh_descriptor: &Path,
) -> Result<()> {
    requests::prepare(https, directory, openssh_descriptor).await
}

const PHASES: [&str; 3] = ["before", "active", "withdrawn"];
const MAX_DESCRIPTOR_BYTES: usize = 8_192;
const SSH_LABEL: &str = "com.scoplen.fixture";
const SSH_PORT: &str = "2222/tcp";
const SSH_USER: &str = "smoke";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedOpenSsh {
    disposable: bool,
    container: String,
    owner: String,
    port: u16,
}

#[derive(Deserialize)]
struct Inspection {
    running: bool,
    labels: BTreeMap<String, String>,
    ports: BTreeMap<String, Option<Vec<PortBinding>>>,
}

#[derive(Deserialize)]
struct PortBinding {
    #[serde(rename = "HostIp")]
    host_ip: String,
    #[serde(rename = "HostPort")]
    host_port: String,
}

impl OwnedOpenSsh {
    fn load(path: &Path) -> Result<Self> {
        let source = read_bounded(path, MAX_DESCRIPTOR_BYTES)?;
        let value: Self = serde_json::from_str(&source)
            .map_err(|_| "owned OpenSSH descriptor must have exactly four fields")?;
        if !value.disposable
            || !value.container.starts_with("scoplen-team-ssh-")
            || value.container.len() > 128
            || !value.container.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || Uuid::parse_str(&value.owner).is_err()
            || value.port < 1_024
        {
            return Err("owned OpenSSH descriptor is not a disposable loopback fixture");
        }
        Ok(value)
    }

    fn validate_inspection(&self, source: &[u8]) -> Result<()> {
        let value: Inspection =
            serde_json::from_slice(source).map_err(|_| "owned OpenSSH inspection is invalid")?;
        let bindings = value
            .ports
            .get(SSH_PORT)
            .and_then(Option::as_ref)
            .ok_or("owned OpenSSH loopback binding is missing")?;
        if !value.running
            || value.labels.get(SSH_LABEL) != Some(&self.owner)
            || bindings.len() != 1
            || bindings[0].host_ip != "127.0.0.1"
            || bindings[0].host_port != self.port.to_string()
        {
            return Err("owned OpenSSH ownership, running state or loopback port differs");
        }
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        let mut command = Command::new("docker");
        command
            .args([
                "inspect",
                "--type",
                "container",
                "--format",
                r#"{"running":{{json .State.Running}},"labels":{{json .Config.Labels}},"ports":{{json .NetworkSettings.Ports}}}"#,
                &self.container,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            command.creation_flags(0x0800_0000);
        }
        let mut child = InspectionProcess(
            command.spawn().map_err(|_| "could not inspect owned OpenSSH container")?,
        );
        let status = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = child.0.try_wait().map_err(|_| "OpenSSH inspection failed")? {
                    return Ok::<_, &'static str>(status);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "owned OpenSSH inspection exceeded its deadline")??;
        if !status.success() {
            return Err("could not confirm owned OpenSSH container");
        }
        let mut output = Vec::new();
        child
            .0
            .stdout
            .take()
            .ok_or("OpenSSH inspection output missing")?
            .take(MAX_DESCRIPTOR_BYTES as u64 + 1)
            .read_to_end(&mut output)
            .map_err(|_| "could not read owned OpenSSH inspection")?;
        if output.len() > MAX_DESCRIPTOR_BYTES {
            return Err("owned OpenSSH inspection exceeds its bound");
        }
        self.validate_inspection(&output)
    }
}

struct InspectionProcess(Child);

impl Drop for InspectionProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    IssuanceDenied,
    SshSftp,
}

#[derive(Serialize)]
struct Descriptor<'a> {
    disposable: bool,
    origin: &'a str,
    ca_certificate: PathBuf,
    organization_id: Uuid,
    host_id: Uuid,
    profile_id: Uuid,
    owner_username: &'a str,
    owner_password_file: PathBuf,
    member_username: &'a str,
    member_password_file: PathBuf,
    expected_outcome: ExpectedOutcome,
    certificate_not_after: Option<u64>,
}

fn descriptor_json(descriptor: &Descriptor<'_>) -> Result<String> {
    if !descriptor.disposable
        || !descriptor.ca_certificate.is_absolute()
        || !descriptor.owner_password_file.is_absolute()
        || !descriptor.member_password_file.is_absolute()
        || !matches!(
            (descriptor.expected_outcome, descriptor.certificate_not_after),
            (ExpectedOutcome::IssuanceDenied, None)
                | (ExpectedOutcome::SshSftp, Some(1..=253_402_300_799))
        )
    {
        return Err("Grant client descriptor context is invalid");
    }
    let value =
        serde_json::to_string(descriptor).map_err(|_| "Grant client descriptor encoding failed")?;
    if value.len() >= MAX_DESCRIPTOR_BYTES {
        return Err("Grant client descriptor exceeds its bound");
    }
    Ok(value)
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("Grant client handoff files already exist; abandon this fixture"),
        Err(_) => Err("could not inspect Grant client handoff path"),
    }
}

async fn phase(directory: &Path, name: &str, descriptor: &Descriptor<'_>) -> Result<()> {
    let complete = directory.join(format!("grant-client-{name}.complete"));
    require_absent(&complete)?;
    write_private(
        &directory.join(format!("grant-client-{name}.json")),
        &descriptor_json(descriptor)?,
    )?;
    write_private(&directory.join(format!("grant-client-{name}.ready")), "ready")?;
    println!("Grant client phase ready: {name}");
    tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            match fs::symlink_metadata(&complete) {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        return Err("Grant client completion signal is invalid");
                    }
                    let signal = read_bounded(&complete, 16)?;
                    if signal.as_str() == "passed\n" {
                        return Ok(());
                    }
                    if !"passed\n".starts_with(signal.as_str()) {
                        return Err("Grant client completion signal is invalid");
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => return Err("could not inspect Grant client completion signal"),
            }
        }
    })
    .await
    .map_err(|_| "Grant client phase exceeded its deadline; abandon this fixture")?
}

struct Prepared {
    owner: Registration,
    member: Registration,
    owner_browser: Browser,
    org: Uuid,
    membership: Uuid,
    host: InventoryResource,
    profile: InventoryResource,
}

async fn prepare_target(https: &Https, openssh_descriptor: &Path) -> Result<Prepared> {
    let ssh = OwnedOpenSsh::load(openssh_descriptor)?;
    ssh.verify().await?;
    let owner = Registration::new(&https.origin)?;
    owner.register(https).await?;
    let member = Registration::new(&https.origin)?;
    member.register(https).await?;
    let owner_browser = Browser::login(https, &owner).await?;
    let member_browser = Browser::login(https, &member).await?;
    let org = create_team(https, owner_browser.actor()).await?.id;
    let membership =
        invite(https, owner_browser.actor(), member_browser.actor(), &member, org).await?;
    let owner_token = owner.device.authenticate(https).await?;
    ca(https, native(&owner, &owner_token), org).await?;
    let host_fields = json!({
        "name":"Owned Grant SSH target", "address":"127.0.0.1", "port":ssh.port,
    });
    let initial =
        asset(https, owner_browser.actor(), org, InventoryType::Host, host_fields.clone()).await?;
    let profile = asset(
        https,
        owner_browser.actor(),
        org,
        InventoryType::AccessProfile,
        json!({"host":initial.id,"username":SSH_USER,"route":0}),
    )
    .await?;
    let profile_fields = InventoryFields::from_json(
        InventoryType::AccessProfile,
        &serde_json::to_vec(&json!({"host":initial.id,"username":SSH_USER,"route":0}))
            .map_err(|_| "Grant Login fields encoding failed")?,
    )
    .map_err(|_| "Grant Login fields invalid")?;
    if profile.fields != profile_fields {
        return Err("Grant Login Host, user or direct route differs");
    }
    let mut host_fields = host_fields;
    host_fields["default_profile"] = json!(profile.id);
    let request = InventoryReplaceRequest {
        fields: InventoryFields::from_json(
            InventoryType::Host,
            &serde_json::to_vec(&host_fields).map_err(|_| "Grant Host fields encoding failed")?,
        )
        .map_err(|_| "Grant Host replacement fields invalid")?,
    };
    let host = inventory(
        &exchange(
            https,
            owner_browser.actor(),
            "PUT",
            &format!("/api/v1/orgs/{org}/hosts/{}", initial.id),
            &request.to_json().map_err(|_| "Grant Host replacement request invalid")?,
            &[("If-Match", &initial.etag)],
            200,
        )
        .await?,
        InventoryType::Host,
        initial.id,
    )?;
    if host.fields != request.fields {
        return Err("Grant Host default Login differs");
    }
    rule(
        https,
        owner_browser.actor(),
        org,
        membership,
        SimpleRule::View {
            resources: vec![
                SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id },
                SimpleRuleSelector { object_type: ObjectType::ACCESS_PROFILE, id: profile.id },
            ],
        },
    )
    .await?;
    for (kind, expected) in [(InventoryType::Host, &host), (InventoryType::AccessProfile, &profile)]
    {
        let current = inventory(
            &exchange(
                https,
                member_browser.actor(),
                "GET",
                &format!("/api/v1/orgs/{org}/{}/{}", kind.segment(), expected.id),
                &[],
                &[],
                200,
            )
            .await?,
            kind,
            expected.id,
        )?;
        if current != *expected {
            return Err("Grant member cannot read the prepared Host and Login unchanged");
        }
    }
    Ok(Prepared { owner, member, owner_browser, org, membership, host, profile })
}

pub(super) async fn prepare(
    https: &Https,
    directory: &Path,
    openssh_descriptor: &Path,
) -> Result<()> {
    for name in PHASES {
        for suffix in ["json", "ready", "complete"] {
            require_absent(&directory.join(format!("grant-client-{name}.{suffix}")))?;
        }
    }
    let Prepared { owner, member, mut owner_browser, org, membership, host, profile } =
        prepare_target(https, openssh_descriptor).await?;
    let owner_password_file = directory.join("grant-client-owner-password.txt");
    let member_password_file = directory.join("grant-client-member-password.txt");
    super::super::write_browser_password(&owner_password_file, &owner.password)?;
    super::super::write_browser_password(&member_password_file, &member.password)?;
    let mut descriptor = Descriptor {
        disposable: true,
        origin: &https.origin,
        ca_certificate: directory.join("ca.pem"),
        organization_id: org,
        host_id: host.id,
        profile_id: profile.id,
        owner_username: &owner.payload.username,
        owner_password_file,
        member_username: &member.payload.username,
        member_password_file,
        expected_outcome: ExpectedOutcome::IssuanceDenied,
        certificate_not_after: None,
    };
    phase(directory, PHASES[0], &descriptor).await?;
    owner_browser.refresh(https).await?;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| "Grant client preparation clock invalid")?;
    let cutoff = now.checked_add(600).ok_or("Grant client cutoff invalid")?;
    let grant = create(
        https,
        owner_browser.actor(),
        org,
        GrantFields {
            membership,
            host: host.id,
            remote_user: SSH_USER.into(),
            valid_from: now,
            valid_until: Some(cutoff),
        },
    )
    .await?;
    descriptor.expected_outcome = ExpectedOutcome::SshSftp;
    descriptor.certificate_not_after = Some(cutoff);
    phase(directory, PHASES[1], &descriptor).await?;
    owner_browser.refresh(https).await?;
    withdraw(https, owner_browser.actor(), org, &grant.resource).await?;
    descriptor.expected_outcome = ExpectedOutcome::IssuanceDenied;
    descriptor.certificate_not_after = None;
    phase(directory, PHASES[2], &descriptor).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_requires_current_owned_container_and_exact_private_port() {
        let owner = Uuid::new_v4().to_string();
        let ssh = OwnedOpenSsh {
            disposable: true,
            container: format!("scoplen-team-ssh-{owner}"),
            owner: owner.clone(),
            port: 42_222,
        };
        let correct = json!({
            "running":true, "labels":{SSH_LABEL:owner},
            "ports":{SSH_PORT:[{"HostIp":"127.0.0.1","HostPort":"42222"}]},
        });
        let inspect = |value: &serde_json::Value| {
            ssh.validate_inspection(&serde_json::to_vec(value).unwrap())
        };
        assert!(inspect(&correct).is_ok());
        for changed in [
            json!({"running":false,"labels":correct["labels"],"ports":correct["ports"]}),
            json!({"running":true,"labels":{SSH_LABEL:Uuid::new_v4()},"ports":correct["ports"]}),
            json!({"running":true,"labels":correct["labels"],"ports":{"22/tcp":correct["ports"][SSH_PORT]}}),
            json!({"running":true,"labels":correct["labels"],"ports":{SSH_PORT:[{"HostIp":"0.0.0.0","HostPort":"42222"}]}}),
            json!({"running":true,"labels":correct["labels"],"ports":{SSH_PORT:[{"HostIp":"127.0.0.1","HostPort":"42223"}]}}),
        ] {
            assert!(inspect(&changed).is_err());
        }
    }

    #[test]
    fn descriptor_has_exact_twelve_fields_and_explicit_outcome_bound() {
        let root = std::env::temp_dir();
        let mut descriptor = Descriptor {
            disposable: true,
            origin: "https://localhost:18443",
            ca_certificate: root.join("ca.pem"),
            organization_id: Uuid::now_v7(),
            host_id: Uuid::now_v7(),
            profile_id: Uuid::now_v7(),
            owner_username: "synthetic-owner",
            owner_password_file: root.join("synthetic-owner.txt"),
            member_username: "synthetic-member",
            member_password_file: root.join("synthetic-member.txt"),
            expected_outcome: ExpectedOutcome::IssuanceDenied,
            certificate_not_after: None,
        };
        let bytes = descriptor_json(&descriptor).unwrap();
        let value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
        let mut fields = value.as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "ca_certificate",
                "certificate_not_after",
                "disposable",
                "expected_outcome",
                "host_id",
                "member_password_file",
                "member_username",
                "organization_id",
                "origin",
                "owner_password_file",
                "owner_username",
                "profile_id",
            ]
        );
        assert_eq!(value["certificate_not_after"], serde_json::Value::Null);
        assert_eq!(value["expected_outcome"], "issuance_denied");
        assert!(bytes.len() < MAX_DESCRIPTOR_BYTES);
        descriptor.expected_outcome = ExpectedOutcome::SshSftp;
        assert!(descriptor_json(&descriptor).is_err());
        descriptor.certificate_not_after = Some(1_800_000_600);
        let value: serde_json::Value =
            serde_json::from_str(&descriptor_json(&descriptor).unwrap()).unwrap();
        assert_eq!(value["expected_outcome"], "ssh_sftp");
        assert_eq!(value["certificate_not_after"], 1_800_000_600_u64);
        descriptor.certificate_not_after = Some(253_402_300_800);
        assert!(descriptor_json(&descriptor).is_err());
        descriptor.certificate_not_after = Some(0);
        assert!(descriptor_json(&descriptor).is_err());
    }
}
