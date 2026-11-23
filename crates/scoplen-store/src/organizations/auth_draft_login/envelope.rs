// SPDX-License-Identifier: AGPL-3.0-only
//! Short-lived per-attempt data keys wrapped by the deployment KEK.

use scoplen_api::auth_connection_draft::test_login::DraftLoginCredentials;
use scoplen_crypto::{
    SecretBytes, SymmetricKey, XChaChaNonce, random_key, random_nonce, xchacha20poly1305_open,
    xchacha20poly1305_seal,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{DraftLoginMaterial, Error, KeyManagementService};

const WRAPPED_KEY_END: usize = 73;
const MATERIAL_NONCE_END: usize = WRAPPED_KEY_END + 24;
const OVERHEAD: usize = MATERIAL_NONCE_END + 16 + 32;

fn aad(attempt: Uuid, generation: Uuid, usage: u8) -> Vec<u8> {
    let mut aad = b"spl-organization-auth-draft-test\0v1\0".to_vec();
    aad.push(usage);
    aad.extend_from_slice(attempt.as_bytes());
    aad.extend_from_slice(generation.as_bytes());
    aad
}

fn kek(kms: &dyn KeyManagementService) -> Result<SymmetricKey, Error> {
    let bytes = kms.key_encryption_key();
    if bytes == &[0; 32] {
        return Err(Error::StorageUnavailable);
    }
    Ok(SymmetricKey::new(*bytes))
}

pub(super) fn seal(
    attempt: Uuid,
    generation: Uuid,
    material: &DraftLoginMaterial,
    kms: &dyn KeyManagementService,
) -> Result<Vec<u8>, Error> {
    let credentials = material.credentials.to_json().map_err(|_| Error::InvalidRequest)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(32 + credentials.len()));
    plaintext.extend_from_slice(material.verifier.as_bytes());
    plaintext.extend_from_slice(credentials.as_bytes());
    let key = random_key().map_err(|_| Error::StorageUnavailable)?;
    let wrap_nonce = random_nonce().map_err(|_| Error::StorageUnavailable)?;
    let material_nonce = random_nonce().map_err(|_| Error::StorageUnavailable)?;
    let wrapped = xchacha20poly1305_seal(
        &kek(kms)?,
        &wrap_nonce,
        key.as_bytes(),
        &aad(attempt, generation, 1),
    )
    .map_err(|_| Error::StorageUnavailable)?;
    let ciphertext =
        xchacha20poly1305_seal(&key, &material_nonce, &plaintext, &aad(attempt, generation, 2))
            .map_err(|_| Error::StorageUnavailable)?;
    let mut envelope = Vec::with_capacity(OVERHEAD + credentials.len());
    envelope.push(1);
    envelope.extend_from_slice(wrap_nonce.as_ref());
    envelope.extend_from_slice(&wrapped);
    envelope.extend_from_slice(material_nonce.as_ref());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub(super) fn open(
    attempt: Uuid,
    generation: Uuid,
    envelope: &[u8],
    kms: &dyn KeyManagementService,
) -> Result<DraftLoginMaterial, Error> {
    let invalid = || Error::StorageUnavailable;
    if !(OVERHEAD + 1..=OVERHEAD + 4096).contains(&envelope.len()) || envelope[0] != 1 {
        return Err(invalid());
    }
    let wrap_nonce = XChaChaNonce::from_slice(&envelope[1..25]).ok_or_else(invalid)?;
    let opened_key = Zeroizing::new(
        xchacha20poly1305_open(
            &kek(kms)?,
            &wrap_nonce,
            &envelope[25..WRAPPED_KEY_END],
            &aad(attempt, generation, 1),
        )
        .map_err(|_| invalid())?,
    );
    let key = SymmetricKey::from_slice(&opened_key).ok_or_else(invalid)?;
    let material_nonce = XChaChaNonce::from_slice(&envelope[WRAPPED_KEY_END..MATERIAL_NONCE_END])
        .ok_or_else(invalid)?;
    let plaintext = Zeroizing::new(
        xchacha20poly1305_open(
            &key,
            &material_nonce,
            &envelope[MATERIAL_NONCE_END..],
            &aad(attempt, generation, 2),
        )
        .map_err(|_| invalid())?,
    );
    let (verifier, credentials) = plaintext.split_at_checked(32).ok_or_else(invalid)?;
    Ok(DraftLoginMaterial {
        credentials: DraftLoginCredentials::from_json(credentials).map_err(|_| invalid())?,
        verifier: SecretBytes::from_slice(verifier).ok_or_else(invalid)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestKms([u8; 32]);

    impl KeyManagementService for TestKms {
        fn key_encryption_key(&self) -> &[u8; 32] {
            &self.0
        }

        fn backend_name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn envelope_authenticates_attempt_generation_and_both_ciphertexts() {
        let attempt = Uuid::now_v7();
        let generation = Uuid::now_v7();
        let kms = TestKms([1; 32]);
        let material = DraftLoginMaterial {
            credentials: DraftLoginCredentials::from_json(
                br#"{"client_id":"fixture-client","client_secret":"fixture-secret"}"#,
            )
            .unwrap(),
            verifier: SecretBytes::new([2; 32]),
        };
        let sealed = seal(attempt, generation, &material, &kms).unwrap();
        assert_eq!(open(attempt, generation, &sealed, &kms).unwrap(), material);
        for (id, draft, key) in [
            (Uuid::now_v7(), generation, TestKms([1; 32])),
            (attempt, Uuid::now_v7(), TestKms([1; 32])),
            (attempt, generation, TestKms([3; 32])),
        ] {
            assert_eq!(open(id, draft, &sealed, &key), Err(Error::StorageUnavailable));
        }
        for byte in [0, WRAPPED_KEY_END - 1, MATERIAL_NONCE_END] {
            let mut tampered = sealed.clone();
            tampered[byte] ^= 1;
            assert_eq!(open(attempt, generation, &tampered, &kms), Err(Error::StorageUnavailable));
        }
    }
}
