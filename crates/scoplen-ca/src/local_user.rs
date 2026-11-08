// SPDX-License-Identifier: AGPL-3.0-only
//! Private local signing material; authorization and transaction ownership remain with the store.

use std::fmt;

use scoplen_api::certificate::{CertificateIssuanceRequest, CertificateTargets};
use scoplen_crypto::{
    SymmetricKey, XChaChaNonce, random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use ssh_key::{PrivateKey, PublicKey, certificate::Builder, private::Ed25519Keypair};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Initial direct-SSH profile's actual lifetime ceiling, before a shorter requested lifetime.
pub const DEFAULT_USER_CERTIFICATE_TTL_SECONDS: u32 = 1_800;
const KEY_ENVELOPE_BYTES: usize = 73;
const KEY_ENVELOPE_VERSION: u8 = 1;
const KEY_AAD_DOMAIN: &[u8] = b"spl-organization-local-user-ca\0v1\0";

/// Redacted local signing/custody failure; no seed, key or submitted certificate is disclosed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalUserCaError {
    #[error("local user-CA entropy unavailable")]
    Entropy,
    #[error("invalid local user-CA context")]
    InvalidContext,
    #[error("local user-CA key integrity check failed")]
    KeyIntegrity,
    #[error("local user-CA certificate signing failed")]
    Certificate,
}

/// Transaction-current identities and allocated serial supplied only after target authorization.
pub struct UserCertificateContext {
    /// Immutable team owning this CA and every selected target.
    pub organization: Uuid,
    /// Currently active Account making the request.
    pub account: Uuid,
    /// Currently enrolled and authenticated Device.
    pub device: Uuid,
    /// Server-generated issued Resource identifier.
    pub certificate: Uuid,
    /// Unique positive serial allocated under the authority lock.
    pub serial: u64,
    /// Trusted current server time in Unix seconds.
    pub now_seconds: u64,
}

/// Independent OS-random Ed25519 user-CA seed, erased when released.
pub struct LocalUserCa(Zeroizing<[u8; 32]>);

impl fmt::Debug for LocalUserCa {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalUserCa([REDACTED])")
    }
}

fn aad(organization: Uuid, authority: Uuid) -> Result<Vec<u8>, LocalUserCaError> {
    for id in [organization, authority] {
        scoplen_model::validate_uuid_v7(id).map_err(|_| LocalUserCaError::InvalidContext)?;
    }
    let mut bytes = Vec::with_capacity(KEY_AAD_DOMAIN.len() + 32);
    bytes.extend_from_slice(KEY_AAD_DOMAIN);
    bytes.extend_from_slice(organization.as_bytes());
    bytes.extend_from_slice(authority.as_bytes());
    Ok(bytes)
}

impl LocalUserCa {
    /// Generate a signing seed independently of deployment and Account keys.
    /// # Errors
    /// Returns a fixed error if the OS random source fails.
    pub fn generate() -> Result<Self, LocalUserCaError> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| LocalUserCaError::Entropy)?;
        Ok(Self(seed))
    }

    /// Public canonical Ed25519 OpenSSH key, without a comment.
    /// # Errors
    /// Returns a fixed error if public encoding fails.
    pub fn public_key(&self) -> Result<String, LocalUserCaError> {
        let key = Ed25519Keypair::from_seed(&self.0);
        PublicKey::new(key.public.into(), "")
            .to_openssh()
            .map_err(|_| LocalUserCaError::KeyIntegrity)
    }

    /// Encrypt this seed under the deployment KMS with immutable owner/purpose binding.
    /// # Errors
    /// Rejects invalid ids, invalid deployment keys, entropy or encryption failure.
    pub fn seal(
        &self,
        deployment_key: &[u8; 32],
        organization: Uuid,
        authority: Uuid,
    ) -> Result<Vec<u8>, LocalUserCaError> {
        if deployment_key == &[0; 32] {
            return Err(LocalUserCaError::KeyIntegrity);
        }
        let aad = aad(organization, authority)?;
        let nonce = random_nonce().map_err(|_| LocalUserCaError::Entropy)?;
        let ciphertext = xchacha20poly1305_seal(
            &SymmetricKey::new(*deployment_key),
            &nonce,
            self.0.as_ref(),
            &aad,
        )
        .map_err(|_| LocalUserCaError::KeyIntegrity)?;
        let mut envelope = Vec::with_capacity(KEY_ENVELOPE_BYTES);
        envelope.push(KEY_ENVELOPE_VERSION);
        envelope.extend_from_slice(nonce.as_ref());
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Open an existing seed; corruption or owner mismatch never generates a replacement.
    /// # Errors
    /// Rejects malformed envelopes, invalid ids/keys and failed owner-bound authentication.
    pub fn open(
        envelope: &[u8],
        deployment_key: &[u8; 32],
        organization: Uuid,
        authority: Uuid,
    ) -> Result<Self, LocalUserCaError> {
        if envelope.len() != KEY_ENVELOPE_BYTES
            || envelope[0] != KEY_ENVELOPE_VERSION
            || deployment_key == &[0; 32]
        {
            return Err(LocalUserCaError::KeyIntegrity);
        }
        let nonce =
            XChaChaNonce::from_slice(&envelope[1..25]).ok_or(LocalUserCaError::KeyIntegrity)?;
        let plaintext = Zeroizing::new(
            xchacha20poly1305_open(
                &SymmetricKey::new(*deployment_key),
                &nonce,
                &envelope[25..],
                &aad(organization, authority)?,
            )
            .map_err(|_| LocalUserCaError::KeyIntegrity)?,
        );
        if plaintext.len() != 32 {
            return Err(LocalUserCaError::KeyIntegrity);
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&plaintext);
        Ok(Self(seed))
    }

    /// Sign exactly the authorized selectors with scoped principals and the initial PTY profile.
    /// This method grants no authority: the caller must recheck every current target and persist
    /// the serial, Resource, original receipt and audit in one transaction before disclosure.
    /// # Errors
    /// Rejects invalid requests/identities/serials, invalid time or signing failure.
    pub fn issue(
        &self,
        request: &CertificateIssuanceRequest,
        context: &UserCertificateContext,
    ) -> Result<String, LocalUserCaError> {
        request.validate().map_err(|_| LocalUserCaError::InvalidContext)?;
        for id in [context.organization, context.account, context.device, context.certificate] {
            scoplen_model::validate_uuid_v7(id).map_err(|_| LocalUserCaError::InvalidContext)?;
        }
        if context.serial == 0 {
            return Err(LocalUserCaError::InvalidContext);
        }
        let valid_after =
            context.now_seconds.checked_sub(60).ok_or(LocalUserCaError::InvalidContext)?;
        let ttl = request.ttl_seconds.min(DEFAULT_USER_CERTIFICATE_TTL_SECONDS);
        let valid_before = context
            .now_seconds
            .checked_add(u64::from(ttl))
            .ok_or(LocalUserCaError::InvalidContext)?;
        let public = PublicKey::from_openssh(&request.public_key)
            .map_err(|_| LocalUserCaError::InvalidContext)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| LocalUserCaError::Entropy)?;
        let mut builder =
            Builder::new(nonce.to_vec(), public.key_data().clone(), valid_after, valid_before)
                .map_err(|_| LocalUserCaError::Certificate)?;
        builder.serial(context.serial).map_err(|_| LocalUserCaError::Certificate)?;
        builder
            .key_id(format!(
                "spl:{}:{}:{}:{}",
                context.organization, context.account, context.device, context.certificate
            ))
            .map_err(|_| LocalUserCaError::Certificate)?;
        let (kind, ids) = match &request.targets {
            CertificateTargets::Hosts(ids) => ("h", ids),
            CertificateTargets::HostGroups(ids) => ("g", ids),
        };
        for id in ids {
            builder
                .valid_principal(format!(
                    "spl:{}:{kind}:{id}:{}",
                    context.organization, request.remote_user
                ))
                .map_err(|_| LocalUserCaError::Certificate)?;
        }
        builder.extension("permit-pty", "").map_err(|_| LocalUserCaError::Certificate)?;
        builder
            .extension("org@scoplen.com", context.organization.to_string())
            .map_err(|_| LocalUserCaError::Certificate)?;
        builder
            .sign(&PrivateKey::from(Ed25519Keypair::from_seed(&self.0)))
            .and_then(|certificate| certificate.to_openssh())
            .map_err(|_| LocalUserCaError::Certificate)
    }
}
