// SPDX-License-Identifier: AGPL-3.0-only
//! Versioned authenticated envelopes for confidential Organization identity material.

use std::ops::RangeInclusive;

use scoplen_crypto::{
    SecretVec, SymmetricKey, XChaChaNonce, random_key, random_nonce, xchacha20poly1305_open,
    xchacha20poly1305_seal,
};
use zeroize::Zeroizing;

use super::OrganizationStoreError as Error;
use crate::kms::KeyManagementService;

const WRAPPED_KEY_END: usize = 73;
const MATERIAL_NONCE_END: usize = WRAPPED_KEY_END + 24;
const OVERHEAD: usize = MATERIAL_NONCE_END + 16;

fn kek(kms: &dyn KeyManagementService) -> Result<SymmetricKey, Error> {
    let key = kms.key_encryption_key();
    if key == &[0; 32] {
        return Err(Error::StorageUnavailable);
    }
    Ok(SymmetricKey::new(*key))
}

pub(super) fn seal(
    plaintext: &[u8],
    aad: impl Fn(u8) -> Vec<u8>,
    kms: &dyn KeyManagementService,
) -> Result<Vec<u8>, Error> {
    let key = random_key().map_err(|_| Error::StorageUnavailable)?;
    let wrap_nonce = random_nonce().map_err(|_| Error::StorageUnavailable)?;
    let material_nonce = random_nonce().map_err(|_| Error::StorageUnavailable)?;
    let wrapped = xchacha20poly1305_seal(&kek(kms)?, &wrap_nonce, key.as_bytes(), &aad(1))
        .map_err(|_| Error::StorageUnavailable)?;
    let ciphertext = xchacha20poly1305_seal(&key, &material_nonce, plaintext, &aad(2))
        .map_err(|_| Error::StorageUnavailable)?;
    let mut envelope = Vec::with_capacity(OVERHEAD + plaintext.len());
    envelope.push(1);
    envelope.extend_from_slice(wrap_nonce.as_ref());
    envelope.extend_from_slice(&wrapped);
    envelope.extend_from_slice(material_nonce.as_ref());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub(super) fn open(
    envelope: &[u8],
    plaintext_size: RangeInclusive<usize>,
    aad: impl Fn(u8) -> Vec<u8>,
    kms: &dyn KeyManagementService,
) -> Result<SecretVec, Error> {
    let invalid = || Error::StorageUnavailable;
    let size = envelope.len().checked_sub(OVERHEAD).ok_or_else(invalid)?;
    if !plaintext_size.contains(&size) || envelope[0] != 1 {
        return Err(invalid());
    }
    let wrap_nonce = XChaChaNonce::from_slice(&envelope[1..25]).ok_or_else(invalid)?;
    let key = Zeroizing::new(
        xchacha20poly1305_open(&kek(kms)?, &wrap_nonce, &envelope[25..WRAPPED_KEY_END], &aad(1))
            .map_err(|_| invalid())?,
    );
    let key = SymmetricKey::from_slice(&key).ok_or_else(invalid)?;
    let material_nonce = XChaChaNonce::from_slice(&envelope[WRAPPED_KEY_END..MATERIAL_NONCE_END])
        .ok_or_else(invalid)?;
    xchacha20poly1305_open(&key, &material_nonce, &envelope[MATERIAL_NONCE_END..], &aad(2))
        .map(SecretVec::new)
        .map_err(|_| invalid())
}
