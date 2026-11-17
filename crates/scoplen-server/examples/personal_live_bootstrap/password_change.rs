// SPDX-License-Identifier: AGPL-3.0-only
//! Independent ordinary-password lifecycle through verified public HTTPS only.

use std::{net::Ipv4Addr, time::SystemTime};

use axum::{body::Bytes, http::Request};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use scoplen_api::{
    account_admission::{
        AccountPasswordChangeConfirmation, AccountPasswordChangePayload,
        AccountPasswordChangeRequest,
    },
    account_browser::{
        AccountBrowserAccessToken, AccountBrowserPasswordLoginRequest,
        AccountBrowserPasswordLoginResponse, AccountBrowserPasswordOptionsRequest,
        AccountBrowserPasswordOptionsResponse, AccountBrowserRefreshResponse,
        AccountBrowserRefreshToken,
    },
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken, generate_p256_signing_key};
use zeroize::Zeroizing;

use super::*;

const CHANGE: &str = "/api/v1/auth/accounts/password-changes";
const BROWSER_OPTIONS: &str = "/api/v1/auth/accounts/browser/password/options";
const BROWSER_LOGIN: &str = "/api/v1/auth/accounts/browser/password/login";
const BROWSER_REFRESH: &str = "/api/v1/auth/accounts/browser/refresh";
const PROFILE: &str = "/api/v1/accounts/me";

struct Change {
    payload: AccountPasswordChangePayload,
    password: SecretVec,
    token: SecretBytes<32>,
}

impl Change {
    fn new(
        https: &Https,
        device: &Device,
        login: &AccountPasswordLoginResponse,
        snapshot: &AccountBootstrapSnapshot,
        bootstrap: &PasswordBootstrap,
    ) -> Result<Self> {
        let password = SecretVec::new(
            URL_SAFE_NO_PAD
                .encode(random_key().map_err(|_| "New password generation failed")?.as_bytes())
                .into_bytes(),
        );
        let secrets = PasswordSecrets::create(&https.origin, &snapshot.username, password.clone())
            .map_err(|_| "New password derivation failed")?;
        let next = snapshot.credential_generation.checked_add(1).ok_or("Generation exhausted")?;
        let context = PasswordBootstrapContext::new(
            secrets.context().clone(),
            snapshot.account_id,
            snapshot.personal_vault_id,
            &snapshot.account_signing_public_key,
            &snapshot.account_kem_public_key,
            next,
        )
        .map_err(|_| "New password context invalid")?;
        let wrapper = PasswordArkWrap::seal(&secrets, &context, bootstrap.ark())
            .map_err(|_| "New password wrapping failed")?;
        if wrapper.open(&secrets, &context).map_err(|_| "New password wrapper cannot open")?
            != *bootstrap.ark()
        {
            return Err("New password wrapper changed the ARK");
        }
        let payload = AccountPasswordChangePayload {
            operation_id: Uuid::now_v7(),
            origin: https.origin.clone(),
            username: snapshot.username.clone(),
            account_id: snapshot.account_id,
            personal_vault_id: snapshot.personal_vault_id,
            device_id: device.id,
            credential_generation: snapshot.credential_generation,
            new_credential_generation: next,
            snapshot_digest: account_bootstrap_digest(login.snapshot.as_bytes()),
            capability_digest: account_capability_digest(login.admission_token.as_bytes()),
            password_salt: *secrets.context().salt(),
            verifier: *secrets.verifier().as_bytes(),
            password_ark: wrapper.encode(),
        };
        payload
            .validate_for_snapshot(
                snapshot,
                login.snapshot.as_bytes(),
                login.admission_token.as_bytes(),
            )
            .map_err(|_| "Password change is not bound to the current existing Device")?;
        Ok(Self { payload, password, token: login.admission_token.clone() })
    }

    async fn request(
        &self,
        https: &Https,
        device: &Device,
        root: &Ed25519SigningKey,
        intent: AccountRequestIntent,
    ) -> Result<AccountPasswordChangeRequest> {
        let body = AccountRequestChallengeRequest {
            kind: AccountRequestKind::PasswordChange,
            intent,
            operation_id: self.payload.operation_id,
            device_id: self.payload.device_id,
        }
        .to_json()
        .map_err(|_| "Password-change challenge request invalid")?;
        let (bytes, _) = exchange(https, "POST", CHALLENGE, &body, None, None, 200).await?;
        let challenge = AccountRequestChallengeResponse::from_json(&bytes)
            .map_err(|_| "Password-change challenge response invalid")?;
        let payload = self.payload.to_cbor().map_err(|_| "Password-change payload invalid")?;
        let input = AccountRequestSignatureInput::new(AccountRequestKind::PasswordChange, &payload)
            .map_err(|_| "Password-change signature input invalid")?;
        let account_signature = input.sign(root);
        let device_proof = AccountRequestProof::new(
            AccountRequestKind::PasswordChange,
            intent,
            &https.origin,
            challenge.attempt_id.as_bytes(),
            challenge.nonce.as_bytes(),
            self.payload.operation_id,
            device.id,
            &input.request_digest(&account_signature),
        )
        .map_err(|_| "Password-change Device context invalid")?
        .sign(&device.keys.signing)
        .map_err(|_| "Password-change Device proof failed")?;
        Ok(AccountPasswordChangeRequest {
            intent,
            payload: SecretVec::new(payload),
            account_signature,
            attempt_id: challenge.attempt_id,
            nonce: challenge.nonce,
            device_proof,
            admission_token: (intent == AccountRequestIntent::Submit).then(|| self.token.clone()),
        })
    }
}

async fn change(
    https: &Https,
    operation: &Change,
    device: &Device,
    root: &Ed25519SigningKey,
    intent: AccountRequestIntent,
) -> Result<Zeroizing<Vec<u8>>> {
    let request = operation.request(https, device, root, intent).await?;
    let body = request.to_json().map_err(|_| "Password-change request encoding failed")?;
    let expected = if intent == AccountRequestIntent::Submit { 201 } else { 200 };
    let (bytes, _) = exchange(https, "POST", CHANGE, &body, None, None, expected).await?;
    let fields: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "Password-change receipt JSON invalid")?;
    if fields.as_object().is_none_or(|fields| fields.len() != 8) {
        return Err("Password-change receipt has an unexpected shape");
    }
    AccountPasswordChangeConfirmation::from_json(&bytes)
        .and_then(|receipt| {
            receipt.validate_for_request(request.payload.as_bytes(), &request.account_signature)
        })
        .map_err(|_| "Password-change receipt does not match the exact original operation")?;
    Ok(bytes)
}

fn unchanged(
    before: &AccountBootstrapSnapshot,
    after: &AccountBootstrapSnapshot,
    change: &Change,
) -> Result<()> {
    let mut expected = before.clone();
    expected.credential_generation = change.payload.new_credential_generation;
    expected.password_salt = change.payload.password_salt;
    expected.password_ark = change.payload.password_ark;
    if &expected != after {
        return Err("Password change modified protected Account, Device or Personal state");
    }
    Ok(())
}

fn problem(bytes: &[u8], status: u16, code: &str) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "Password-change problem JSON invalid")?;
    if value["status"] != status
        || value["code"] != code
        || value["changed"] != false
        || value["retryable"] != false
    {
        return Err("Password-change denial has incorrect code or outcome flags");
    }
    Ok(())
}

struct Browser {
    key: P256SigningKey,
    access: Zeroizing<String>,
    cookie: Zeroizing<String>,
    account_id: Uuid,
}

impl Browser {
    async fn attempt(
        https: &Https,
        key: &P256SigningKey,
        username: &str,
        password: SecretVec,
    ) -> Result<(AccountBrowserPasswordLoginRequest, [u8; 16])> {
        let body = AccountBrowserPasswordOptionsRequest(AccountPasswordOptionsRequest {
            username: username.into(),
        })
        .to_json()
        .map_err(|_| "Browser options request invalid")?;
        let (bytes, _) =
            exchange(https, "POST", BROWSER_OPTIONS, &body, Some((key, None)), None, 200).await?;
        let options = AccountBrowserPasswordOptionsResponse::from_json(&bytes)
            .map_err(|_| "Browser options response invalid")?
            .0;
        let secrets = PasswordKdfContext::new(
            &https.origin,
            username,
            PASSWORD_BOOTSTRAP_PROFILE,
            &options.salt,
        )
        .and_then(|context| context.derive(password))
        .map_err(|_| "Browser password derivation failed")?;
        Ok((
            AccountBrowserPasswordLoginRequest(AccountPasswordLoginRequest {
                attempt_id: options.attempt_id,
                auth_secret: secrets.auth_secret().clone(),
            }),
            options.salt,
        ))
    }

    fn credentials(
        bytes: &[u8],
        cookie: Option<Zeroizing<String>>,
        initial: bool,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
        let token = if initial {
            AccountBrowserPasswordLoginResponse::from_json(bytes)
                .map_err(|_| "Browser login response invalid")?
                .0
        } else {
            AccountBrowserRefreshResponse::from_json(bytes)
                .map_err(|_| "Browser refresh response invalid")?
                .0
        };
        AccountBrowserAccessToken::parse(&token.access_token)
            .map_err(|_| "Browser access credential profile invalid")?;
        if token.token_type != "DPoP"
            || token.expires_in != 600
            || !(1..=2_592_000).contains(&token.refresh_expires_in)
            || (initial && token.refresh_expires_in != 2_592_000)
        {
            return Err("Browser session lifetime or type invalid");
        }
        let cookie = cookie.ok_or("Browser refresh cookie missing")?;
        if !cookie.ends_with(&format!("; Max-Age={}", token.refresh_expires_in)) {
            return Err("Browser refresh cookie lifetime invalid");
        }
        let pair = cookie.split(';').next().ok_or("Browser refresh cookie pair missing")?;
        AccountBrowserRefreshToken::parse(
            pair.strip_prefix("__Secure-spl-account-refresh=")
                .ok_or("Browser refresh cookie name invalid")?,
        )
        .map_err(|_| "Browser refresh credential profile invalid")?;
        Ok((Zeroizing::new(token.access_token), Zeroizing::new(pair.into())))
    }

    async fn login(
        https: &Https,
        account_id: Uuid,
        username: &str,
        password: SecretVec,
    ) -> Result<Self> {
        let key = generate_p256_signing_key().map_err(|_| "Browser proof key generation failed")?;
        let (attempt, _) = Self::attempt(https, &key, username, password).await?;
        let body = attempt.to_json().map_err(|_| "Browser login request invalid")?;
        let (bytes, cookie) =
            exchange(https, "POST", BROWSER_LOGIN, body.as_bytes(), Some((&key, None)), None, 200)
                .await?;
        let (access, cookie) = Self::credentials(&bytes, cookie, true)?;
        Ok(Self { key, access, cookie, account_id })
    }

    async fn refresh(mut self, https: &Https) -> Result<Self> {
        let (bytes, cookie) = exchange(
            https,
            "POST",
            BROWSER_REFRESH,
            b"{}",
            Some((&self.key, None)),
            Some(&self.cookie),
            200,
        )
        .await?;
        let (access, cookie) = Self::credentials(&bytes, cookie, false)?;
        if access == self.access || cookie == self.cookie {
            return Err("Browser refresh did not rotate both current credentials");
        }
        self.access = access;
        self.cookie = cookie;
        Ok(self)
    }

    async fn profile(&self, https: &Https, status: u16) -> Result<()> {
        let (bytes, _) = exchange(
            https,
            "GET",
            PROFILE,
            &[],
            Some((&self.key, Some(&self.access))),
            None,
            status,
        )
        .await?;
        if status == 401 {
            problem(&bytes, status, "auth.authentication_required")?;
        } else if scoplen_api::account_profile::AccountProfile::from_json(&bytes)
            .map_err(|_| "Browser Account profile invalid")?
            .id
            != self.account_id
        {
            return Err("Browser signed into a different Account");
        }
        Ok(())
    }

    async fn denied_refresh(&self, https: &Https) -> Result<()> {
        let (bytes, _) = exchange(
            https,
            "POST",
            BROWSER_REFRESH,
            b"{}",
            Some((&self.key, None)),
            Some(&self.cookie),
            401,
        )
        .await?;
        problem(&bytes, 401, "auth.authentication_required")
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exchange(
    https: &Https,
    method: &str,
    path: &str,
    body: &[u8],
    auth: Option<(&P256SigningKey, Option<&str>)>,
    cookie: Option<&str>,
    expected: u16,
) -> Result<(Zeroizing<Vec<u8>>, Option<Zeroizing<String>>)> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", https.origin))
            .header("Origin", &https.origin);
        if method == "POST" {
            request = request.header("Content-Type", "application/json");
        }
        if let Some((key, access)) = auth {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "System clock invalid")?
                .as_secs();
            let proof = DpopProof::sign(
                key,
                &key.public_key_sec1(),
                &DpopTarget::new(method, &https.origin, path)
                    .map_err(|_| "HTTPS proof target invalid")?,
                access.map_or(DpopToken::Refresh, DpopToken::Protected),
                now,
                None,
            )
            .map_err(|_| "HTTPS proof signing failed")?;
            request = request.header("DPoP", proof.as_str());
            if let Some(access) = access {
                request = request.header("Authorization", format!("DPoP {access}"));
            }
        }
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let tcp = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, https.port))
            .await
            .map_err(|_| "Password-change loopback connection failed")?;
        let tls = https
            .connector
            .connect(ServerName::try_from("localhost").map_err(|_| "TLS name invalid")?, tcp)
            .await
            .map_err(|_| "Password-change TLS verification failed")?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("Password-change consumer requires verified HTTP/2");
        }
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .max_header_list_size(16_384)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(|_| "Password-change HTTP/2 handshake failed")?;
        let _driver = crate::Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender
            .send_request(
                request
                    .body(Full::new(Bytes::copy_from_slice(body)))
                    .map_err(|_| "Password-change HTTPS request invalid")?,
            )
            .await
            .map_err(|_| "Password-change HTTPS outcome uncertain; abandon fixture")?;
        let status = response.status().as_u16();
        if status != expected {
            eprintln!(
                "password-change consumer HTTP status: expected {expected}, received {status}"
            );
            return Err(
                "Password-change public API returned an unexpected status; abandon fixture",
            );
        }
        let header =
            |name: &str| response.headers().get(name).and_then(|value| value.to_str().ok());
        let cookie_allowed = status == 200 && matches!(path, BROWSER_LOGIN | BROWSER_REFRESH);
        if header("cache-control") != Some("no-store")
            || header("pragma") != Some("no-cache")
            || header("x-request-id").is_none_or(str::is_empty)
            || header("content-type")
                != Some(if status >= 400 { "application/problem+json" } else { "application/json" })
            || (!cookie_allowed && response.headers().contains_key("set-cookie"))
            || response.headers().contains_key("access-control-allow-origin")
            || response.headers().contains_key("access-control-allow-credentials")
        {
            return Err("Password-change HTTPS response metadata invalid");
        }
        let cookie = if cookie_allowed {
            let cookie = header("set-cookie").ok_or("Browser refresh cookie missing")?;
            if response.headers().get_all("set-cookie").iter().count() != 1
                || !cookie.starts_with("__Secure-spl-account-refresh=ar1_")
                || !cookie.contains("; Path=/api/v1/auth/accounts/browser/refresh;")
                || cookie.contains("Domain=")
                || ["HttpOnly", "Secure", "SameSite=Strict"]
                    .iter()
                    .any(|required| !cookie.split("; ").any(|attribute| attribute == *required))
            {
                return Err("Browser refresh cookie profile invalid");
            }
            Some(Zeroizing::new(cookie.into()))
        } else {
            None
        };
        let maximum = if status >= 400 {
            4_096
        } else if matches!(path, CHANGE | CHALLENGE | BROWSER_OPTIONS) {
            1_024
        } else {
            8_192
        };
        let bytes = Limited::new(response.into_body(), maximum)
            .collect()
            .await
            .map_err(|_| "Password-change HTTPS response incomplete or oversized")?
            .to_bytes();
        Ok((Zeroizing::new(bytes.to_vec()), cookie))
    })
    .await
    .map_err(|_| "Password-change HTTPS timeout; abandon fixture")?
}

async fn password_attempt(
    https: &Https,
    username: &str,
    password: SecretVec,
) -> Result<AccountPasswordLoginRequest> {
    let body = AccountPasswordOptionsRequest { username: username.into() }
        .to_json()
        .map_err(|_| "Old-password options request invalid")?;
    let bytes = https.exchange("POST", OPTIONS, &body, None, 200).await?;
    let options = AccountPasswordOptionsResponse::from_json(&bytes)
        .map_err(|_| "Old-password options response invalid")?;
    let secrets =
        PasswordKdfContext::new(&https.origin, username, PASSWORD_BOOTSTRAP_PROFILE, &options.salt)
            .and_then(|context| context.derive(password))
            .map_err(|_| "Old-password derivation failed")?;
    Ok(AccountPasswordLoginRequest {
        attempt_id: options.attempt_id,
        auth_secret: secrets.auth_secret().clone(),
    })
}

async fn denied_login(https: &Https, attempt: &AccountPasswordLoginRequest) -> Result<()> {
    let body = attempt.to_json().map_err(|_| "Old-password login request invalid")?;
    let (bytes, _) = exchange(https, "POST", LOGIN, body.as_bytes(), None, None, 401).await?;
    problem(&bytes, 401, "auth.authentication_required")
}

async fn third_vault_key(
    https: &Https,
    third: &Device,
    token: &AuthTokenResponse,
    snapshot: &AccountBootstrapSnapshot,
    bootstrap: &PasswordBootstrap,
    original: &[Uuid],
) -> Result<SecretBytes<32>> {
    let bytes = https
        .exchange(
            "GET",
            "/sync/v1/keys",
            &[],
            Some((&third.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let bundle =
        SyncAccountKeyBundle::from_cbor(&bytes).map_err(|_| "Third Device key bundle invalid")?;
    let ark = DeviceArkWrap::decode(&bundle.wrapped_ark)
        .and_then(|wrap| wrap.open(snapshot.account_id, third.id, &third.keys.kem))
        .map_err(|_| "Third Device ARK cannot be opened")?;
    let certificates = bundle
        .certificates
        .iter()
        .map(|bytes| DeviceCertificate::decode(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "Third Device certificates invalid")?;
    let active = verify_device_list(&certificates, &[], &snapshot.account_signing_public_key)
        .map_err(|_| "Third Device membership signatures invalid")?;
    if ark != *bootstrap.ark()
        || bundle.revision != 3
        || !bundle.revocations.is_empty()
        || active.len() != 3
        || original
            .iter()
            .chain(std::iter::once(&third.id))
            .any(|id| !active.iter().any(|certificate| certificate.device_id == *id))
    {
        return Err("Third Device changed Account material or lost an original Device");
    }
    let bytes = https
        .exchange(
            "GET",
            &format!("/sync/v1/vaults/{}/keys", snapshot.personal_vault_id),
            &[],
            Some((&third.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let keys = SyncVaultKeysResponse::from_cbor(&bytes)
        .map_err(|_| "Third Device Personal keys invalid")?;
    if keys.keys.len() != 1 || keys.keys[0].epoch != 1 {
        return Err("Third Device received changed Personal epochs");
    }
    PersonalVaultKeyWrap::decode(&keys.keys[0].wrapped_vault_key)
        .and_then(|wrap| wrap.open(snapshot.account_id, snapshot.personal_vault_id, 1, &ark))
        .map_err(|_| "Third Device Personal key cannot be opened")
}

#[allow(clippy::too_many_lines)]
pub(super) async fn verify(https: &Https) -> Result<()> {
    let account = Registration::new(&https.origin)?;
    account.register(https).await?;
    let second = Device::new()?;
    let password_window_started = tokio::time::Instant::now();
    let (login, initial, bootstrap) =
        password_login(https, &account.payload.username, account.password.clone()).await?;
    admit(https, &second, login, &initial, &bootstrap).await?;
    let first_token = account.device.authenticate(https).await?;
    let second_token = second.authenticate(https).await?;
    let object = host(account.device.id)?;
    let vault = account.payload.personal_vault_id;
    upload(https, &account.device, &first_token, vault, &account.vault_key, &object, None).await?;
    download(
        https,
        &second,
        &second_token,
        (vault, &account.vault_key),
        &account.device,
        &object,
        1,
    )
    .await?;
    let browser = Browser::login(
        https,
        account.payload.account_id,
        &account.payload.username,
        account.password.clone(),
    )
    .await?;
    browser.profile(https, 200).await?;
    let browser = browser.refresh(https).await?;
    browser.profile(https, 200).await?;
    let (stale_login, stale_snapshot, stale_bootstrap) =
        password_login(https, &account.payload.username, account.password.clone()).await?;
    let stale =
        Change::new(https, &account.device, &stale_login, &stale_snapshot, &stale_bootstrap)?;
    let (login, before, bootstrap) =
        password_login(https, &account.payload.username, account.password.clone()).await?;
    if before.account_id != account.payload.account_id
        || before.personal_vault_id != vault
        || before.account_signing_public_key != account.payload.account_signing_public_key
        || before.account_kem_public_key != account.payload.account_kem_public_key
        || before.credential_generation != 1
        || bootstrap.ark() != stale_bootstrap.ark()
    {
        return Err("Old-password bootstrap does not match installed Account anchors");
    }
    let second_key =
        admitted_vault_key(https, &second, &second_token, &before, &bootstrap, account.device.id)
            .await?;
    if second_key != account.vault_key {
        return Err("Second Device changed Personal key");
    }
    let operation = Change::new(https, &account.device, &login, &before, &bootstrap)?;
    let old_attempt =
        password_attempt(https, &account.payload.username, account.password.clone()).await?;
    let (old_browser_attempt, browser_salt) =
        Browser::attempt(https, &browser.key, &account.payload.username, account.password.clone())
            .await?;
    if browser_salt != before.password_salt {
        return Err("Outstanding browser attempt does not use the verified old credential salt");
    }
    let receipt = change(
        https,
        &operation,
        &account.device,
        &account.keys.signing,
        AccountRequestIntent::Submit,
    )
    .await?;
    browser.profile(https, 401).await?;
    browser.denied_refresh(https).await?;
    let old_browser_body =
        old_browser_attempt.to_json().map_err(|_| "Old browser attempt encoding failed")?;
    let (bytes, _) = exchange(
        https,
        "POST",
        BROWSER_LOGIN,
        old_browser_body.as_bytes(),
        Some((&browser.key, None)),
        None,
        401,
    )
    .await?;
    problem(&bytes, 401, "auth.authentication_required")?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    denied_login(https, &old_attempt).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let wrong_password =
        password_attempt(https, &account.payload.username, account.password.clone()).await?;
    denied_login(https, &wrong_password).await?;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let stale_request = stale
        .request(https, &account.device, &account.keys.signing, AccountRequestIntent::Submit)
        .await?;
    let (bytes, _) = exchange(
        https,
        "POST",
        CHANGE,
        &stale_request.to_json().map_err(|_| "Stale request invalid")?,
        None,
        None,
        409,
    )
    .await?;
    problem(&bytes, 409, "auth.admission_conflict")?;
    let first_token = account.device.refresh(https, first_token).await?;
    let second_token = second.refresh(https, second_token).await?;
    for (device, token) in [(&account.device, &first_token), (&second, &second_token)] {
        download(https, device, token, (vault, &account.vault_key), &account.device, &object, 1)
            .await?;
        let fresh = device.authenticate(https).await?;
        download(https, device, &fresh, (vault, &account.vault_key), &account.device, &object, 1)
            .await?;
    }
    let (login, after, opened) =
        password_login(https, &account.payload.username, operation.password.clone()).await?;
    unchanged(&before, &after, &operation)?;
    if opened.ark() != bootstrap.ark() {
        return Err("New password recovered a different ARK");
    }
    let confirmed = change(
        https,
        &operation,
        &account.device,
        &account.keys.signing,
        AccountRequestIntent::Confirm,
    )
    .await?;
    if receipt != confirmed {
        return Err("Original password-change receipt changed");
    }
    let new_browser = Browser::login(
        https,
        account.payload.account_id,
        &account.payload.username,
        operation.password.clone(),
    )
    .await?;
    new_browser.profile(https, 200).await?;
    let third = Device::new()?;
    admit(https, &third, login, &after, &opened).await?;
    let third_token = third.authenticate(https).await?;
    let third_token = third.refresh(https, third_token).await?;
    let third_key = third_vault_key(
        https,
        &third,
        &third_token,
        &after,
        &opened,
        &[account.device.id, second.id],
    )
    .await?;
    if third_key != account.vault_key {
        return Err("Third Device recovered a different Personal key");
    }
    download(https, &third, &third_token, (vault, &third_key), &account.device, &object, 1).await?;
    let (login, current, current_bootstrap) =
        password_login(https, &account.payload.username, operation.password.clone()).await?;
    let later = Change::new(https, &account.device, &login, &current, &current_bootstrap)?;
    change(https, &later, &account.device, &account.keys.signing, AccountRequestIntent::Submit)
        .await?;
    let historical = change(
        https,
        &operation,
        &account.device,
        &account.keys.signing,
        AccountRequestIntent::Confirm,
    )
    .await?;
    if historical != receipt {
        return Err("Later password change altered an immutable historical receipt");
    }
    // Native and browser options/login share ten attempts per username per minute.
    tokio::time::sleep_until(password_window_started + Duration::from_secs(61)).await;
    let (_, final_snapshot, final_bootstrap) =
        password_login(https, &account.payload.username, later.password.clone()).await?;
    unchanged(&current, &final_snapshot, &later)?;
    if final_bootstrap.ark() != bootstrap.ark() {
        return Err("Later password change changed the ARK");
    }
    Ok(())
}
