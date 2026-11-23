// SPDX-License-Identifier: AGPL-3.0-only
//! Short-lived per-attempt data keys wrapped by the deployment KEK.

use scoplen_api::auth_connection_draft::test_login::DraftLoginCredentials;
use scoplen_crypto::SecretBytes;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{DraftLoginMaterial, Error, KeyManagementService};
use crate::organizations::auth_envelope;

fn aad(attempt: Uuid, generation: Uuid, usage: u8) -> Vec<u8> {
    let mut aad = b"spl-organization-auth-draft-test\0v1\0".to_vec();
    aad.push(usage);
    aad.extend_from_slice(attempt.as_bytes());
    aad.extend_from_slice(generation.as_bytes());
    aad
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
    auth_envelope::seal(&plaintext, |usage| aad(attempt, generation, usage), kms)
}

pub(super) fn open(
    attempt: Uuid,
    generation: Uuid,
    envelope: &[u8],
    kms: &dyn KeyManagementService,
) -> Result<DraftLoginMaterial, Error> {
    let invalid = || Error::StorageUnavailable;
    let plaintext =
        auth_envelope::open(envelope, 33..=4128, |usage| aad(attempt, generation, usage), kms)?;
    let (verifier, credentials) = plaintext.as_bytes().split_at_checked(32).ok_or_else(invalid)?;
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
        for byte in [0, 25, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[byte] ^= 1;
            assert_eq!(open(attempt, generation, &tampered, &kms), Err(Error::StorageUnavailable));
        }
    }
}
