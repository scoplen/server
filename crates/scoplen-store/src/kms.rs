// SPDX-License-Identifier: AGPL-3.0-only
//! Key-management boundary and the local deployment-key backend.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;
use zeroize::Zeroizing;

/// Width of the deployment key-encryption key in bytes.
pub const KEY_ENCRYPTION_KEY_BYTES: usize = 32;

/// Key-management failures that can be shown without exposing key material.
#[derive(Debug, Error)]
pub enum KmsError {
    /// The configured path is empty.
    #[error("KMS key file path must not be empty")]
    EmptyPath,
    /// The key file could not be read.
    #[error("could not read KMS key file: {0}")]
    Read(#[source] std::io::Error),
    /// The key file is not exactly one 32-byte lowercase or uppercase hex key.
    #[error("KMS key file must contain exactly 64 hexadecimal characters")]
    InvalidEncoding,
    /// An all-zero key is never a valid deployment key.
    #[error("KMS key file must not contain an all-zero key")]
    ZeroKey,
}

/// Common interface implemented by local and external KMS backends.
pub trait KeyManagementService: Send + Sync {
    /// Return the deployment key-encryption key for application-level wrapping.
    fn key_encryption_key(&self) -> &[u8; KEY_ENCRYPTION_KEY_BYTES];

    /// Return a stable backend label for readiness and diagnostics.
    fn backend_name(&self) -> &'static str;
}

/// Signing boundary used for deployment audit checkpoints.
pub trait AuditCheckpointSigner: Send + Sync {
    /// Sign the domain-separated checkpoint payload.
    fn sign_checkpoint(&self, payload: &[u8]) -> [u8; 64];

    /// Return the public key used to verify exported checkpoints.
    fn verification_key(&self) -> [u8; 32];
}

/// A deployment key loaded from the local key file generated during bootstrap.
pub struct LocalKeyFile {
    path: PathBuf,
    key: Zeroizing<[u8; KEY_ENCRYPTION_KEY_BYTES]>,
}

impl LocalKeyFile {
    /// Load and validate a local deployment key file.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError`] when the path is empty, the file cannot be read, or the file does not
    /// contain one non-zero 32-byte hexadecimal key.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, KmsError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(KmsError::EmptyPath);
        }
        let contents = fs::read_to_string(path).map_err(KmsError::Read)?;
        let key = decode_key(contents.trim())?;
        Ok(Self { path: path.to_path_buf(), key: Zeroizing::new(key) })
    }

    /// Return the configured key-file path without exposing key material.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// An Ed25519 audit signing seed loaded from a local private file.
#[derive(Clone)]
pub struct LocalAuditSigner {
    path: PathBuf,
    seed: Zeroizing<[u8; 32]>,
}

impl LocalAuditSigner {
    /// Load and validate an Ed25519 seed encoded as exactly 64 hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError`] when the path cannot be read or the seed is malformed or all zero.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, KmsError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(KmsError::EmptyPath);
        }
        let contents = fs::read_to_string(path).map_err(KmsError::Read)?;
        let seed = decode_key(contents.trim())?;
        Ok(Self { path: path.to_path_buf(), seed: Zeroizing::new(seed) })
    }

    /// Return the configured signing-key path without exposing the seed.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditCheckpointSigner for LocalAuditSigner {
    fn sign_checkpoint(&self, payload: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(payload).to_bytes()
    }

    fn verification_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed).verifying_key().to_bytes()
    }
}

impl fmt::Debug for LocalAuditSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalAuditSigner")
            .field("path", &self.path)
            .field("seed", &"<redacted>")
            .finish()
    }
}

fn decode_key(encoded: &str) -> Result<[u8; KEY_ENCRYPTION_KEY_BYTES], KmsError> {
    if encoded.len() != KEY_ENCRYPTION_KEY_BYTES * 2
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(KmsError::InvalidEncoding);
    }
    let mut key = [0_u8; KEY_ENCRYPTION_KEY_BYTES];
    for (index, slot) in key.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = (hex_value(encoded.as_bytes()[offset])? << 4)
            | hex_value(encoded.as_bytes()[offset + 1])?;
    }
    if key == [0; KEY_ENCRYPTION_KEY_BYTES] {
        return Err(KmsError::ZeroKey);
    }
    Ok(key)
}

impl KeyManagementService for LocalKeyFile {
    fn key_encryption_key(&self) -> &[u8; KEY_ENCRYPTION_KEY_BYTES] {
        &self.key
    }

    fn backend_name(&self) -> &'static str {
        "local-key-file"
    }
}

impl fmt::Debug for LocalKeyFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalKeyFile")
            .field("path", &self.path)
            .field("key", &"<redacted>")
            .finish()
    }
}

fn hex_value(byte: u8) -> Result<u8, KmsError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(KmsError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!("scoplen-kms-{}.key", uuid::Uuid::new_v4()))
    }

    #[test]
    fn parallel_key_file_loads_use_distinct_paths() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(32));
        let handles = (1..=32_u8)
            .map(|marker| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let path = path();
                    fs::write(&path, format!("{marker:02x}").repeat(KEY_ENCRYPTION_KEY_BYTES))
                        .expect("write parallel key");
                    barrier.wait();
                    let key = LocalKeyFile::load(&path).expect("load parallel key");
                    fs::remove_file(path).expect("remove parallel key");
                    assert_eq!(key.key_encryption_key(), &[marker; KEY_ENCRYPTION_KEY_BYTES]);
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("parallel key load");
        }
    }

    #[test]
    fn local_key_file_loads_and_redacts_secret() {
        let path = path();
        fs::write(&path, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n")
            .expect("write key");
        let key = LocalKeyFile::load(&path).expect("load key");
        assert_eq!(key.backend_name(), "local-key-file");
        assert_eq!(key.key_encryption_key()[0], 0);
        assert_eq!(key.path(), path.as_path());
        assert!(!format!("{key:?}").contains("001122"));
        fs::remove_file(path).expect("remove key");
    }

    #[test]
    fn malformed_and_zero_keys_fail_closed() {
        let path = path();
        for contents in [String::new(), "00".to_owned(), "zz".repeat(32), "00".repeat(32)] {
            fs::write(&path, contents).expect("write malformed key");
            let error = LocalKeyFile::load(&path).expect_err("reject malformed key");
            assert!(matches!(error, KmsError::InvalidEncoding | KmsError::ZeroKey));
        }
        assert!(matches!(LocalKeyFile::load(""), Err(KmsError::EmptyPath)));
        fs::remove_file(path).expect("remove key");
    }

    #[test]
    fn local_audit_signer_signs_without_redacting_material() {
        let path = path();
        fs::write(&path, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n")
            .expect("write key");
        let signer = LocalAuditSigner::load(&path).expect("load signer");
        let signature = signer.sign_checkpoint(b"checkpoint");
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&signer.verification_key())
            .expect("verification key");
        verifying
            .verify_strict(b"checkpoint", &ed25519_dalek::Signature::from_bytes(&signature))
            .expect("signature verifies");
        assert!(!format!("{signer:?}").contains("001122"));
        fs::remove_file(path).expect("remove key");
    }
}
