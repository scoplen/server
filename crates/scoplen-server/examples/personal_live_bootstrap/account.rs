// SPDX-License-Identifier: AGPL-3.0-only
//! Independent consumer of published Account/Device/sync contracts; no database access.

use scoplen_api::{
    ProblemDetails,
    account_admission::{
        AccountBootstrapSnapshot, AccountCommittedConfirmation, AccountDeviceAdmissionPayload,
        AccountDeviceAdmissionRequest, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
        AccountPasswordOptionsRequest, AccountPasswordOptionsResponse, AccountRegistrationPayload,
        AccountRegistrationRequest, AccountRequestChallengeRequest,
        AccountRequestChallengeResponse,
    },
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthRefreshRequest,
        AuthTokenResponse,
    },
    organization::{
        MAX_ORGANIZATION_PROBLEM_BYTES, OrganizationCreateRequest, OrganizationListQuery,
        OrganizationPage, OrganizationResource, OrganizationUpdateRequest,
    },
    sync::{
        SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundleUpdate,
        SyncSnapshotResponse, SyncVaultKeysResponse, SyncWrite, SyncWriteBatch,
        SyncWriteBatchResponse,
    },
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountKeys, AccountRequestIntent, AccountRequestKind, AccountRequestProof,
    AccountRequestSignatureInput, AccountSigningKeyWrap, DeviceArkWrap, DeviceAuthContext,
    DeviceCertificate, DeviceKeys, Ed25519SigningKey, ObjectEnvelope, P256SigningKey,
    PASSWORD_BOOTSTRAP_PROFILE, PasswordArkWrap, PasswordBootstrap, PasswordBootstrapContext,
    PasswordKdfContext, PasswordSecrets, PersonalVaultKeyWrap, RecoveryBlob, RecoveryKey,
    SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest,
    generate_account_keys, generate_device_keys, random_key, verify_device_list,
};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor};
use uuid::Uuid;

use super::{Https, Result, URL_SAFE_NO_PAD};
use base64::Engine as _;
use std::{fmt::Write as _, path::Path, time::Duration};

const CHALLENGE: &str = "/api/v1/auth/accounts/requests/challenge";
const REGISTER: &str = "/api/v1/auth/accounts/register";
const OPTIONS: &str = "/api/v1/auth/accounts/password/options";
const LOGIN: &str = "/api/v1/auth/accounts/password/login";
const ADMIT: &str = "/api/v1/auth/accounts/device-admissions";

struct Device {
    id: Uuid,
    keys: DeviceKeys,
}

impl Device {
    fn new() -> Result<Self> {
        Ok(Self {
            id: Uuid::now_v7(),
            keys: generate_device_keys().map_err(|_| "Device key generation failed")?,
        })
    }

    fn certificate(&self, account: Uuid, keys: &AccountKeys) -> Result<Vec<u8>> {
        DeviceCertificate::issue(
            &keys.signing,
            self.id,
            account,
            self.keys.signing.public_key_sec1(),
            self.keys.kem.public_key().to_vec(),
            "Disposable HTTPS consumer".into(),
            "test".into(),
            1,
        )
        .and_then(|certificate| certificate.encode())
        .map_err(|_| "Device certificate creation failed")
    }

    fn wrap(&self, account: Uuid, ark: &SecretBytes<32>) -> Result<SyncAccountDeviceWrap> {
        Ok(SyncAccountDeviceWrap {
            device_id: self.id,
            wrapped_ark: DeviceArkWrap::seal(account, self.id, self.keys.kem.public_key(), ark)
                .map_err(|_| "Device ARK wrapping failed")?
                .encode()
                .to_vec(),
        })
    }

    async fn authenticate(&self, https: &Https) -> Result<AuthTokenResponse> {
        let body = AuthChallengeRequest::new(self.id)
            .and_then(|request| request.to_json())
            .map_err(|_| "Device challenge request invalid")?;
        let bytes =
            https.exchange("POST", "/api/v1/auth/challenge", body.as_bytes(), None, 200).await?;
        let challenge = AuthChallengeResponse::from_json(
            std::str::from_utf8(&bytes).map_err(|_| "Device challenge response is not UTF-8")?,
        )
        .map_err(|_| "Device challenge response invalid")?;
        let input = DeviceAuthContext::new(&https.origin, &challenge.nonce, self.id)
            .map_err(|_| "Device authentication context invalid")?;
        let signature = self.keys.signing.sign(&input.signature_input());
        let mut signature_hex = String::with_capacity(128);
        for byte in signature {
            write!(signature_hex, "{byte:02x}").map_err(|_| "Device signature encoding failed")?;
        }
        let request = AuthDeviceRequest::new(self.id, challenge.nonce, signature_hex)
            .and_then(|request| request.to_json())
            .map_err(|_| "Device authentication request invalid")?;
        let bytes =
            https.exchange("POST", "/api/v1/auth/device", request.as_bytes(), None, 200).await?;
        AuthTokenResponse::from_json(
            std::str::from_utf8(&bytes).map_err(|_| "Device token response is not UTF-8")?,
        )
        .map_err(|_| "Device token response invalid")
    }

    async fn refresh(&self, https: &Https, token: AuthTokenResponse) -> Result<AuthTokenResponse> {
        let request = AuthRefreshRequest::new(token.refresh_token)
            .and_then(|request| request.to_json())
            .map_err(|_| "Native refresh request invalid")?;
        let bytes = https
            .post("/api/v1/auth/refresh", request.as_bytes(), &self.keys.signing, None, 200)
            .await?;
        AuthTokenResponse::from_json(
            std::str::from_utf8(&bytes).map_err(|_| "Refreshed Device response is not UTF-8")?,
        )
        .map_err(|_| "Refreshed Device token response invalid")
    }
}

struct Registration {
    payload: AccountRegistrationPayload,
    keys: AccountKeys,
    device: Device,
    password: SecretVec,
    vault_key: SecretBytes<32>,
}

impl Registration {
    fn new(origin: &str) -> Result<Self> {
        let keys = generate_account_keys().map_err(|_| "Account key generation failed")?;
        let device = Device::new()?;
        let account = Uuid::now_v7();
        let vault = Uuid::now_v7();
        let ark = random_key().map_err(|_| "ARK generation failed")?;
        let vault_key = random_key().map_err(|_| "Vault key generation failed")?;
        let password = SecretVec::new(
            URL_SAFE_NO_PAD
                .encode(random_key().map_err(|_| "Password generation failed")?.as_bytes())
                .into_bytes(),
        );
        let username = format!("fixture-{}", Uuid::now_v7().simple());
        let secrets = PasswordSecrets::create(origin, &username, password.clone())
            .map_err(|_| "Registration password derivation failed")?;
        let signing_public = keys.signing.public_key();
        let kem_public: [u8; 32] =
            keys.kem.public_key().try_into().map_err(|_| "Account KEM public key invalid")?;
        let context = PasswordBootstrapContext::new(
            secrets.context().clone(),
            account,
            vault,
            &signing_public,
            &kem_public,
            1,
        )
        .map_err(|_| "Registration password context invalid")?;
        let mut bundle = SyncAccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![device.wrap(account, &ark)?],
            account_signing_key: AccountSigningKeyWrap::seal(account, &ark, &keys.signing)
                .map_err(|_| "Account signing-key wrapping failed")?
                .encode()
                .to_vec(),
            account_kem_key: AccountKemKeyWrap::seal(account, &ark, &keys.kem)
                .map_err(|_| "Account KEM-key wrapping failed")?
                .encode()
                .to_vec(),
            recovery_blob: RecoveryBlob::wrap(
                &RecoveryKey::generate().map_err(|_| "Recovery key generation failed")?,
                account,
                &ark,
            )
            .and_then(|blob| blob.encode())
            .map_err(|_| "Recovery wrapping failed")?,
            signature: Vec::new(),
        };
        bundle.signature = keys
            .signing
            .sign(&bundle.signature_input().map_err(|_| "Initial bundle signature input invalid")?)
            .to_vec();
        let payload = AccountRegistrationPayload {
            operation_id: Uuid::now_v7(),
            origin: origin.into(),
            username,
            account_id: account,
            personal_vault_id: vault,
            device_id: device.id,
            account_signing_public_key: signing_public,
            account_kem_public_key: kem_public,
            password_salt: *secrets.context().salt(),
            verifier: *secrets.verifier().as_bytes(),
            password_ark: PasswordArkWrap::seal(&secrets, &context, &ark)
                .map_err(|_| "Password ARK wrapping failed")?
                .encode(),
            device_certificate: device.certificate(account, &keys)?,
            key_bundle: bundle.to_cbor().map_err(|_| "Initial bundle encoding failed")?,
            personal_wrapped_key: PersonalVaultKeyWrap::seal(account, vault, 1, &ark, &vault_key)
                .map_err(|_| "Personal vault-key wrapping failed")?
                .encode(),
        };
        payload.validate().map_err(|_| "Registration public bindings invalid")?;
        Ok(Self { payload, keys, device, password, vault_key })
    }

    async fn register(&self, https: &Https) -> Result<()> {
        let payload = self.payload.to_cbor().map_err(|_| "Registration payload encoding failed")?;
        let (challenge, account_signature, device_proof) = fresh_proof(
            https,
            AccountRequestKind::Register,
            self.payload.operation_id,
            self.device.id,
            &payload,
            &self.keys.signing,
            &self.device.keys.signing,
        )
        .await?;
        let request = AccountRegistrationRequest {
            intent: AccountRequestIntent::Submit,
            payload: SecretVec::new(payload),
            account_signature,
            attempt_id: challenge.attempt_id,
            nonce: challenge.nonce,
            device_proof,
        };
        let body = request.to_json().map_err(|_| "Registration request encoding failed")?;
        let bytes = https.exchange("POST", REGISTER, &body, None, 201).await?;
        committed(
            &bytes,
            AccountRequestKind::Register,
            request.payload.as_bytes(),
            &account_signature,
        )
    }
}

async fn fresh_proof(
    https: &Https,
    kind: AccountRequestKind,
    operation_id: Uuid,
    device_id: Uuid,
    payload: &[u8],
    root: &Ed25519SigningKey,
    device: &P256SigningKey,
) -> Result<(AccountRequestChallengeResponse, [u8; 64], [u8; 64])> {
    let body = AccountRequestChallengeRequest {
        kind,
        intent: AccountRequestIntent::Submit,
        operation_id,
        device_id,
    }
    .to_json()
    .map_err(|_| "Account challenge request invalid")?;
    let bytes = https.exchange("POST", CHALLENGE, &body, None, 200).await?;
    let challenge = AccountRequestChallengeResponse::from_json(&bytes)
        .map_err(|_| "Account challenge response invalid")?;
    let input = AccountRequestSignatureInput::new(kind, payload)
        .map_err(|_| "Account signature input invalid")?;
    let signature = input.sign(root);
    let proof = AccountRequestProof::new(
        kind,
        AccountRequestIntent::Submit,
        &https.origin,
        challenge.attempt_id.as_bytes(),
        challenge.nonce.as_bytes(),
        operation_id,
        device_id,
        &input.request_digest(&signature),
    )
    .map_err(|_| "Fresh Account Device proof context invalid")?
    .sign(device)
    .map_err(|_| "Fresh Account Device proof failed")?;
    Ok((challenge, signature, proof))
}

fn committed(
    bytes: &[u8],
    kind: AccountRequestKind,
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    AccountCommittedConfirmation::from_json(bytes)
        .and_then(|receipt| receipt.validate_for_request(kind, payload, signature))
        .map_err(|_| "Account committed confirmation does not match original request")
}

async fn password_login(
    https: &Https,
    username: &str,
    password: SecretVec,
) -> Result<(AccountPasswordLoginResponse, AccountBootstrapSnapshot, PasswordBootstrap)> {
    let body = AccountPasswordOptionsRequest { username: username.into() }
        .to_json()
        .map_err(|_| "Password options request invalid")?;
    let bytes = https.exchange("POST", OPTIONS, &body, None, 200).await?;
    let options = AccountPasswordOptionsResponse::from_json(&bytes)
        .map_err(|_| "Password options response invalid")?;
    let secrets =
        PasswordKdfContext::new(&https.origin, username, PASSWORD_BOOTSTRAP_PROFILE, &options.salt)
            .and_then(|context| context.derive(password))
            .map_err(|_| "Independent password derivation failed")?;
    let body = AccountPasswordLoginRequest {
        attempt_id: options.attempt_id,
        auth_secret: secrets.auth_secret().clone(),
    }
    .to_json()
    .map_err(|_| "Password login request invalid")?;
    let bytes = https.exchange("POST", LOGIN, body.as_bytes(), None, 200).await?;
    let login = AccountPasswordLoginResponse::from_json(&bytes)
        .map_err(|_| "Password login response invalid")?;
    let snapshot = AccountBootstrapSnapshot::from_cbor(login.snapshot.as_bytes())
        .map_err(|_| "Signed password bootstrap invalid")?;
    if snapshot.origin != https.origin
        || snapshot.username != username
        || snapshot.password_salt != options.salt
    {
        return Err("Password bootstrap does not match requested identity and options");
    }
    let context = PasswordBootstrapContext::new(
        secrets.context().clone(),
        snapshot.account_id,
        snapshot.personal_vault_id,
        &snapshot.account_signing_public_key,
        &snapshot.account_kem_public_key,
        snapshot.credential_generation,
    )
    .map_err(|_| "Password bootstrap context invalid")?;
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle)
        .map_err(|_| "Signed bootstrap bundle invalid")?;
    let bootstrap = secrets
        .open_bootstrap(
            &context,
            &PasswordArkWrap::decode(&snapshot.password_ark).map_err(|_| "Password ARK invalid")?,
            &AccountSigningKeyWrap::decode(&bundle.account_signing_key)
                .map_err(|_| "Account signing wrap invalid")?,
            &AccountKemKeyWrap::decode(&bundle.account_kem_key)
                .map_err(|_| "Account KEM wrap invalid")?,
        )
        .map_err(|_| "Independent password bootstrap decryption failed")?;
    Ok((login, snapshot, bootstrap))
}

async fn admit(
    https: &Https,
    device: &Device,
    login: AccountPasswordLoginResponse,
    snapshot: &AccountBootstrapSnapshot,
    bootstrap: &PasswordBootstrap,
) -> Result<()> {
    let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle)
        .map_err(|_| "Admission original bundle invalid")?;
    bundle.revision += 1;
    bundle.device_wraps.push(device.wrap(snapshot.account_id, bootstrap.ark())?);
    bundle.device_wraps.sort_by_key(|wrap| wrap.device_id);
    bundle.signature = bootstrap
        .keys()
        .signing
        .sign(&bundle.signature_input().map_err(|_| "Admission next bundle input invalid")?)
        .to_vec();
    let payload = AccountDeviceAdmissionPayload {
        operation_id: Uuid::now_v7(),
        origin: https.origin.clone(),
        username: snapshot.username.clone(),
        account_id: snapshot.account_id,
        personal_vault_id: snapshot.personal_vault_id,
        device_id: device.id,
        credential_generation: snapshot.credential_generation,
        snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
        capability_digest: account_capability_digest(login.admission_token.as_bytes()),
        device_certificate: device.certificate(snapshot.account_id, bootstrap.keys())?,
        key_bundle: bundle.to_cbor().map_err(|_| "Admission next bundle encoding failed")?,
    };
    let payload = payload.to_cbor().map_err(|_| "Admission payload invalid")?;
    let operation = AccountDeviceAdmissionPayload::from_cbor(&payload)
        .map_err(|_| "Admission payload binding invalid")?
        .operation_id;
    let (challenge, account_signature, device_proof) = fresh_proof(
        https,
        AccountRequestKind::Admit,
        operation,
        device.id,
        &payload,
        &bootstrap.keys().signing,
        &device.keys.signing,
    )
    .await?;
    let request = AccountDeviceAdmissionRequest {
        intent: AccountRequestIntent::Submit,
        payload: SecretVec::new(payload),
        account_signature,
        attempt_id: challenge.attempt_id,
        nonce: challenge.nonce,
        device_proof,
        admission_token: Some(login.admission_token),
    };
    let body = request.to_json().map_err(|_| "Admission request encoding failed")?;
    let bytes = https.exchange("POST", ADMIT, &body, None, 201).await?;
    committed(&bytes, AccountRequestKind::Admit, request.payload.as_bytes(), &account_signature)
}

fn host(device: Uuid) -> Result<Object> {
    let mut object =
        Object::new(Uuid::now_v7(), ObjectType::HOST, 1).map_err(|_| "Host object invalid")?;
    for (field, text) in [(1, "Disposable HTTPS Host"), (2, "host.example")] {
        object
            .insert(
                FieldPath::field(field).map_err(|_| "Host field path invalid")?,
                FieldEntry::new(
                    cbor::Value::Text(text.into()),
                    Hlc::at(1).map_err(|_| "Host clock invalid")?,
                    device,
                )
                .map_err(|_| "Host field invalid")?,
            )
            .map_err(|_| "Host field insertion failed")?;
    }
    object.validate().map_err(|_| "Host schema invalid")?;
    Ok(object)
}

async fn upload(
    https: &Https,
    device: &Device,
    token: &AuthTokenResponse,
    vault: Uuid,
    key: &SecretBytes<32>,
    object: &Object,
    base: Option<u64>,
) -> Result<()> {
    let payload = ObjectEnvelope::encrypt(vault, 1, object, key, device.id, &device.keys.signing)
        .and_then(|envelope| envelope.encode())
        .map_err(|_| "Host envelope encryption failed")?;
    let body = SyncWriteBatch {
        writes: vec![SyncWrite { object_id: object.id, base_seq: base, payload, tombstone: false }],
    }
    .to_cbor()
    .map_err(|_| "Host write batch invalid")?;
    let bytes = https
        .post(
            &format!("/sync/v1/vaults/{vault}/objects"),
            &body,
            &device.keys.signing,
            Some(&token.access_token),
            200,
        )
        .await?;
    let response =
        SyncWriteBatchResponse::from_cbor(&bytes).map_err(|_| "Host write response invalid")?;
    if response.assignments.len() != 1
        || response.assignments[0].object_id != object.id
        || response.assignments[0].seq != base.unwrap_or(0) + 1
    {
        return Err("Host write sequence assignment invalid");
    }
    Ok(())
}

async fn download(
    https: &Https,
    device: &Device,
    token: &AuthTokenResponse,
    vault: (Uuid, &SecretBytes<32>),
    writer: &Device,
    expected: &Object,
    sequence: u64,
) -> Result<()> {
    let (vault, key) = vault;
    let bytes = https
        .exchange(
            "GET",
            &format!("/sync/v1/vaults/{vault}/snapshot?after=0&limit=10"),
            &[],
            Some((&device.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let snapshot =
        SyncSnapshotResponse::from_cbor(&bytes).map_err(|_| "Host snapshot response invalid")?;
    if snapshot.objects.len() != 1 || snapshot.next_cursor != sequence || snapshot.more {
        return Err("Host snapshot completeness invalid");
    }
    let retained = &snapshot.objects[0];
    if retained.object_id != expected.id
        || retained.signer_device_id != Some(writer.id)
        || retained.seq != sequence
    {
        return Err("Host snapshot identity or sequence invalid");
    }
    let opened = ObjectEnvelope::decode(&retained.payload)
        .and_then(|envelope| {
            envelope.decrypt(vault, expected.id, key, &writer.keys.signing.public_key_sec1())
        })
        .map_err(|_| "Received Host signature or authenticated decryption failed")?;
    if &opened != expected {
        return Err("Received Host content differs from original");
    }
    Ok(())
}

async fn admitted_vault_key(
    https: &Https,
    second: &Device,
    token: &AuthTokenResponse,
    snapshot: &AccountBootstrapSnapshot,
    bootstrap: &PasswordBootstrap,
    first: Uuid,
) -> Result<SecretBytes<32>> {
    let bytes = https
        .exchange(
            "GET",
            "/sync/v1/keys",
            &[],
            Some((&second.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let bundle =
        SyncAccountKeyBundle::from_cbor(&bytes).map_err(|_| "Current Device key bundle invalid")?;
    let ark = DeviceArkWrap::decode(&bundle.wrapped_ark)
        .and_then(|wrap| wrap.open(snapshot.account_id, second.id, &second.keys.kem))
        .map_err(|_| "Admitted Device ARK cannot be opened")?;
    if &ark != bootstrap.ark() || bundle.revision != 2 {
        return Err("Admitted Device key state differs from password bootstrap");
    }
    let certificates = bundle
        .certificates
        .iter()
        .map(|bytes| DeviceCertificate::decode(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "Current Device certificates invalid")?;
    let active = verify_device_list(&certificates, &[], &snapshot.account_signing_public_key)
        .map_err(|_| "Current Device membership signatures invalid")?;
    if !bundle.revocations.is_empty()
        || active.len() != 2
        || !active.iter().any(|certificate| certificate.device_id == first)
        || !active.iter().any(|certificate| certificate.device_id == second.id)
    {
        return Err("Current Device membership is incomplete");
    }
    let bytes = https
        .exchange(
            "GET",
            &format!("/sync/v1/vaults/{}/keys", snapshot.personal_vault_id),
            &[],
            Some((&second.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let keys = SyncVaultKeysResponse::from_cbor(&bytes)
        .map_err(|_| "Personal vault-key response invalid")?;
    if keys.keys.len() != 1 || keys.keys[0].epoch != 1 {
        return Err("Personal vault epoch state invalid");
    }
    PersonalVaultKeyWrap::decode(&keys.keys[0].wrapped_vault_key)
        .and_then(|wrap| wrap.open(snapshot.account_id, snapshot.personal_vault_id, 1, &ark))
        .map_err(|_| "Personal vault-key decryption failed")
}

struct Team {
    resource: OrganizationResource,
    creation_body: Vec<u8>,
    idempotency_key: Uuid,
}

async fn verify_team(
    https: &Https,
    device: &Device,
    token: &AuthTokenResponse,
    account_id: Uuid,
) -> Result<Team> {
    let proof = Some((&device.keys.signing, Some(token.access_token.as_str())));
    let bytes = https.exchange("GET", "/api/v1/orgs", b"", proof, 200).await?;
    let before = OrganizationPage::from_json(&bytes)
        .map_err(|_| "initial team discovery response invalid")?;
    before
        .validate_for_account(account_id, OrganizationListQuery::default())
        .map_err(|_| "initial team discovery belongs to another Account")?;
    if !before.items.is_empty() || before.next_cursor.is_some() {
        return Err("new Account unexpectedly belongs to a team");
    }
    let request = OrganizationCreateRequest::new("Disposable HTTPS team")
        .and_then(|request| request.to_json())
        .map_err(|_| "team creation request invalid")?;
    let key = Uuid::now_v7();
    let bytes =
        https.create_organization(&request, &device.keys.signing, &token.access_token, key).await?;
    let created =
        OrganizationResource::from_json(&bytes).map_err(|_| "created team Resource invalid")?;
    created
        .validate_for_account(account_id)
        .map_err(|_| "created team belongs to another Account")?;
    if created.name != "Disposable HTTPS team" || created.membership.roles != ["owner"] {
        return Err("created team name or owner membership differs");
    }
    let mut team = Team { resource: created, creation_body: request, idempotency_key: key };
    read_team(https, device, token, account_id, &team).await?;
    let name = "Renamed HTTPS team";
    let update = OrganizationUpdateRequest::new(name)
        .and_then(|request| request.to_json())
        .map_err(|_| "team name request invalid")?;
    let path = format!("/api/v1/orgs/{}", team.resource.id);
    let original_etag = team.resource.etag.clone();
    let bytes = https
        .update_organization(
            &path,
            &update,
            &device.keys.signing,
            &token.access_token,
            &original_etag,
            200,
        )
        .await?;
    let updated =
        OrganizationResource::from_json(&bytes).map_err(|_| "updated team Resource invalid")?;
    let mut expected = team.resource.clone();
    expected.name = name.into();
    expected.updated_at = updated.updated_at.clone();
    expected.etag = updated.etag.clone();
    if updated != expected
        || updated.etag == original_etag
        || updated.updated_at < team.resource.updated_at
    {
        return Err("team name update changed unrelated state or retained its old version");
    }
    team.resource = updated;
    let bytes = https
        .update_organization(
            &path,
            &update,
            &device.keys.signing,
            &token.access_token,
            &original_etag,
            412,
        )
        .await?;
    let problem = ProblemDetails::from_json(&bytes, MAX_ORGANIZATION_PROBLEM_BYTES)
        .map_err(|_| "stale team name problem invalid")?;
    if problem.status != 412
        || problem.code.as_str() != "organization.precondition_failed"
        || problem.changed
        || problem.retryable
    {
        return Err("stale team name update did not retain its refusal semantics");
    }
    let bytes = https
        .update_organization(
            &path,
            &update,
            &device.keys.signing,
            &token.access_token,
            &team.resource.etag,
            200,
        )
        .await?;
    if OrganizationResource::from_json(&bytes).map_err(|_| "no-op team Resource invalid")?
        != team.resource
    {
        return Err("unchanged team name changed the Resource");
    }
    read_team(https, device, token, account_id, &team).await?;
    Ok(team)
}

async fn read_team(
    https: &Https,
    device: &Device,
    token: &AuthTokenResponse,
    account_id: Uuid,
    team: &Team,
) -> Result<()> {
    let proof = Some((&device.keys.signing, Some(token.access_token.as_str())));
    let bytes = https
        .exchange("GET", &format!("/api/v1/orgs/{}", team.resource.id), b"", proof, 200)
        .await?;
    if OrganizationResource::from_json(&bytes).map_err(|_| "team read response invalid")?
        != team.resource
    {
        return Err("team read differs from the retained current Resource");
    }
    let bytes = https
        .create_organization(
            &team.creation_body,
            &device.keys.signing,
            &token.access_token,
            team.idempotency_key,
        )
        .await?;
    if OrganizationResource::from_json(&bytes).map_err(|_| "team confirmation response invalid")?
        != team.resource
    {
        return Err("team confirmation differs from the retained current Resource");
    }
    let bytes = https.exchange("GET", "/api/v1/orgs", b"", proof, 200).await?;
    let after = OrganizationPage::from_json(&bytes)
        .map_err(|_| "current team discovery response invalid")?;
    after
        .validate_for_account(account_id, OrganizationListQuery::default())
        .map_err(|_| "current team discovery belongs to another Account")?;
    if after.items.as_slice() != std::slice::from_ref(&team.resource) || after.next_cursor.is_some()
    {
        return Err("team confirmation duplicated or lost membership");
    }
    Ok(())
}

async fn await_restart(directory: &Path) -> Result<()> {
    super::write_private(&directory.join("team-restart.ready"), "ready")?;
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match std::fs::metadata(directory.join("team-restart.resume")) {
                Ok(_) => {
                    return if super::read_bounded(&directory.join("team-restart.resume"), 16)?
                        .as_str()
                        == "resume\n"
                    {
                        Ok(())
                    } else {
                        Err("invalid team restart resume signal")
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => return Err("could not inspect team restart resume signal"),
            }
        }
    })
    .await
    .map_err(|_| "controller did not restart the server before the deadline")?
}

pub(super) async fn verify(
    https: &Https,
    with_team: bool,
    restart_directory: Option<&Path>,
) -> Result<()> {
    let account = Registration::new(&https.origin)?;
    account.register(https).await?;
    let first_token = account.device.authenticate(https).await?;
    let mut object = host(account.device.id)?;
    upload(
        https,
        &account.device,
        &first_token,
        account.payload.personal_vault_id,
        &account.vault_key,
        &object,
        None,
    )
    .await?;

    let (login, snapshot, bootstrap) =
        password_login(https, &account.payload.username, account.password.clone()).await?;
    if snapshot.account_id != account.payload.account_id
        || snapshot.personal_vault_id != account.payload.personal_vault_id
        || snapshot.account_signing_public_key != account.payload.account_signing_public_key
    {
        return Err("Independent password login recovered a different Account");
    }
    let second = Device::new()?;
    admit(https, &second, login, &snapshot, &bootstrap).await?;
    let token = second.authenticate(https).await?;
    let token = second.refresh(https, token).await?;
    let team = if with_team {
        Some(verify_team(https, &second, &token, snapshot.account_id).await?)
    } else {
        None
    };
    let token = if with_team { second.refresh(https, token).await? } else { token };
    let vault_key =
        admitted_vault_key(https, &second, &token, &snapshot, &bootstrap, account.device.id)
            .await?;
    download(
        https,
        &second,
        &token,
        (snapshot.personal_vault_id, &vault_key),
        &account.device,
        &object,
        1,
    )
    .await?;
    object
        .insert(
            FieldPath::field(1).map_err(|_| "Host edit path invalid")?,
            FieldEntry::new(
                cbor::Value::Text("Edited by independent Device".into()),
                Hlc::at(2).map_err(|_| "Host edit clock invalid")?,
                second.id,
            )
            .map_err(|_| "Host edit field invalid")?,
        )
        .map_err(|_| "Host edit failed")?;
    upload(https, &second, &token, snapshot.personal_vault_id, &vault_key, &object, Some(1))
        .await?;
    let first_token = account.device.refresh(https, first_token).await?;
    download(
        https,
        &account.device,
        &first_token,
        (snapshot.personal_vault_id, &account.vault_key),
        &second,
        &object,
        2,
    )
    .await?;
    if let Some(directory) = restart_directory {
        let team = team.as_ref().ok_or("restart acceptance requires a created team")?;
        if token.refresh_expires_in <= 240 {
            return Err("native refresh lifetime cannot span the bounded restart check");
        }
        await_restart(directory).await?;
        let token = second.refresh(https, token).await?;
        read_team(https, &second, &token, snapshot.account_id, team).await?;
        download(
            https,
            &second,
            &token,
            (snapshot.personal_vault_id, &vault_key),
            &second,
            &object,
            2,
        )
        .await?;
    }
    Ok(())
}
