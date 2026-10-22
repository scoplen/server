// SPDX-License-Identifier: AGPL-3.0-only
//! First-device identity verification, before invitation redemption or authentication.

#![forbid(unsafe_code)]

use std::fmt;

use scoplen_api::{
    personal_enrollment::{PersonalEnrollmentCodecError, PersonalEnrollmentRequest},
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext, ed25519_verify, validate_server_origin,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub mod operator_passkeys;

/// The identity contract implemented by this crate.
pub const COMPONENT: &str = "identity";

/// A structurally valid enrollment that has passed all three first-device signatures.
///
/// Only [`verify_personal_enrollment`] can construct this value. It does not establish
/// invitation validity, account uniqueness, or an authenticated session.
pub struct VerifiedPersonalEnrollment {
    invitation_token_digest: [u8; 32],
    trusted_origin: String,
    account_id: Uuid,
    device_id: Uuid,
    personal_vault_id: Uuid,
    account_signing_public_key: [u8; 32],
    account_kem_public_key: [u8; 32],
    key_bundle_update: SyncAccountKeyBundleUpdate,
    key_bundle_update_cbor: Vec<u8>,
    device_certificate_cbor: Vec<u8>,
    wrapped_personal_vault_key: Vec<u8>,
}

impl VerifiedPersonalEnrollment {
    /// Canonical deployment origin bound by the verified possession signature.
    #[must_use]
    pub fn trusted_origin(&self) -> &str {
        &self.trusted_origin
    }

    /// SHA-256 of the decoded one-use token; the bearer token is not retained.
    #[must_use]
    pub const fn invitation_token_digest(&self) -> &[u8; 32] {
        &self.invitation_token_digest
    }

    #[must_use]
    pub const fn account_id(&self) -> Uuid {
        self.account_id
    }

    #[must_use]
    pub const fn device_id(&self) -> Uuid {
        self.device_id
    }

    #[must_use]
    pub const fn personal_vault_id(&self) -> Uuid {
        self.personal_vault_id
    }

    #[must_use]
    pub const fn account_signing_public_key(&self) -> &[u8; 32] {
        &self.account_signing_public_key
    }

    #[must_use]
    pub const fn account_kem_public_key(&self) -> &[u8; 32] {
        &self.account_kem_public_key
    }

    #[must_use]
    pub const fn key_bundle_update(&self) -> &SyncAccountKeyBundleUpdate {
        &self.key_bundle_update
    }

    /// Exact canonical K-4 bytes covered by the device possession proof.
    #[must_use]
    pub fn key_bundle_update_cbor(&self) -> &[u8] {
        &self.key_bundle_update_cbor
    }

    /// Exact canonical K-2 certificate bytes covered by the device possession proof.
    #[must_use]
    pub fn device_certificate_cbor(&self) -> &[u8] {
        &self.device_certificate_cbor
    }

    #[must_use]
    pub fn wrapped_personal_vault_key(&self) -> &[u8] {
        &self.wrapped_personal_vault_key
    }
}

impl fmt::Debug for VerifiedPersonalEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPersonalEnrollment([REDACTED])")
    }
}

/// Verification failures contain no submitted identity, token, or artifact bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PersonalEnrollmentVerificationError {
    /// The server did not supply its configured canonical HTTPS origin.
    #[error("trusted enrollment origin is invalid")]
    InvalidTrustedOrigin,
    /// A caller constructed a request outside the validated K-3/K-5 syntax boundary.
    #[error("Personal enrollment request is invalid")]
    InvalidRequest,
    /// Identity binding or any first-device signature failed.
    #[error("Personal enrollment denied")]
    Denied,
}

/// Verify a decoded D-101 enrollment against the configured deployment origin.
///
/// Callers must use the bounded K-3/K-5 JSON codec at the HTTP boundary. A successful result
/// still requires an unexpired invitation and one atomic identity transaction before the first
/// device is enrolled. This function never authenticates a caller to another route.
///
/// # Errors
///
/// Returns `InvalidRequest` for malformed artifacts, `InvalidTrustedOrigin` for server
/// configuration, or one undifferentiated `Denied` for identity or signature failures.
pub fn verify_personal_enrollment(
    trusted_origin: &str,
    request: &PersonalEnrollmentRequest,
) -> Result<VerifiedPersonalEnrollment, PersonalEnrollmentVerificationError> {
    request.validate().map_err(|error| match error {
        PersonalEnrollmentCodecError::IdentityMismatch => {
            PersonalEnrollmentVerificationError::Denied
        }
        _ => PersonalEnrollmentVerificationError::InvalidRequest,
    })?;
    validate_server_origin(trusted_origin)
        .map_err(|_| PersonalEnrollmentVerificationError::InvalidTrustedOrigin)?;

    let key_bundle_update_cbor = request
        .key_bundle_update
        .to_cbor()
        .map_err(|_| PersonalEnrollmentVerificationError::InvalidRequest)?;
    let device_certificate_cbor = request
        .device_certificate
        .encode()
        .map_err(|_| PersonalEnrollmentVerificationError::InvalidRequest)?;

    let key_signature_input = request
        .key_bundle_update
        .signature_input()
        .map_err(|_| PersonalEnrollmentVerificationError::InvalidRequest)?;
    ed25519_verify(
        &request.account_signing_public_key,
        &key_signature_input,
        &request.key_bundle_update.signature,
    )
    .map_err(|_| PersonalEnrollmentVerificationError::Denied)?;
    request
        .device_certificate
        .verify(&request.account_signing_public_key)
        .map_err(|_| PersonalEnrollmentVerificationError::Denied)?;

    let context = PersonalEnrollmentContext::new(
        trusted_origin,
        &request.invitation_token,
        request.account_id,
        request.personal_vault_id,
        PersonalEnrollmentArtifacts {
            account_signing_public_key: &request.account_signing_public_key,
            account_kem_public_key: &request.account_kem_public_key,
            key_bundle_update: &key_bundle_update_cbor,
            device_certificate: &device_certificate_cbor,
            wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
        },
    )
    .map_err(|_| PersonalEnrollmentVerificationError::InvalidRequest)?;
    context
        .verify(&request.device_certificate.signing_public_key, &request.device_signature)
        .map_err(|_| PersonalEnrollmentVerificationError::Denied)?;

    Ok(VerifiedPersonalEnrollment {
        invitation_token_digest: Sha256::digest(request.invitation_token).into(),
        trusted_origin: trusted_origin.to_owned(),
        account_id: request.account_id,
        device_id: request.device_certificate.device_id,
        personal_vault_id: request.personal_vault_id,
        account_signing_public_key: request.account_signing_public_key,
        account_kem_public_key: request.account_kem_public_key,
        key_bundle_update: request.key_bundle_update.clone(),
        key_bundle_update_cbor,
        device_certificate_cbor,
        wrapped_personal_vault_key: request.wrapped_personal_vault_key.clone(),
    })
}
