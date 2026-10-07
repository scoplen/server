// SPDX-License-Identifier: AGPL-3.0-only
//! Audit-chain integrity primitives shared by server storage and control-plane roles.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Audit contract marker.
pub const COMPONENT: &str = "audit";
/// Audit hash width in bytes.
pub const HASH_BYTES: usize = 32;
/// Ed25519 checkpoint signature width in bytes.
pub const CHECKPOINT_SIGNATURE_BYTES: usize = 64;
/// Maximum canonical event size accepted by the storage boundary.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
const CHECKPOINT_DOMAIN: &[u8] = b"spl-audit-checkpoint-v1";

/// Audit primitive validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuditError {
    /// The canonical event bytes were empty or exceeded the bounded storage size.
    #[error("canonical audit event must contain between 1 and {MAX_EVENT_BYTES} bytes")]
    InvalidEvent,
    /// A sequence number or timestamp was not positive.
    #[error("audit sequence and timestamp must be positive")]
    InvalidPosition,
}

/// Validate canonical event bytes before hashing or persisting them.
///
/// # Errors
///
/// Returns [`AuditError::InvalidEvent`] for empty or oversized bytes.
pub fn validate_event(event: &[u8]) -> Result<(), AuditError> {
    if event.is_empty() || event.len() > MAX_EVENT_BYTES {
        return Err(AuditError::InvalidEvent);
    }
    Ok(())
}

/// Compute the next per-organization chain hash.
///
/// The hash is `SHA-256(previous_hash || canonical_event_bytes)`. The all-zero hash is the
/// genesis value for the first event in an organization chain.
///
/// # Errors
///
/// Returns [`AuditError::InvalidEvent`] when the event is empty or oversized.
pub fn event_hash(
    previous_hash: &[u8; HASH_BYTES],
    event: &[u8],
) -> Result<[u8; HASH_BYTES], AuditError> {
    validate_event(event)?;
    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(event);
    Ok(hasher.finalize().into())
}

/// Build the exact bytes signed for a checkpoint.
///
/// # Errors
///
/// Returns [`AuditError::InvalidPosition`] when the sequence or timestamp is zero.
pub fn checkpoint_payload(
    organization_id: &[u8; 16],
    sequence: u64,
    head_hash: &[u8; HASH_BYTES],
    signed_at_ms: u64,
) -> Result<Vec<u8>, AuditError> {
    if sequence == 0 || signed_at_ms == 0 {
        return Err(AuditError::InvalidPosition);
    }
    let mut payload = Vec::with_capacity(
        CHECKPOINT_DOMAIN.len() + organization_id.len() + 8 + head_hash.len() + 8,
    );
    payload.extend_from_slice(CHECKPOINT_DOMAIN);
    payload.extend_from_slice(organization_id);
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(head_hash);
    payload.extend_from_slice(&signed_at_ms.to_be_bytes());
    Ok(payload)
}

/// Verify a sequence of events and return its final hash.
///
/// # Errors
///
/// Returns [`AuditError::InvalidPosition`] when the sequence is not gap-free, or
/// [`AuditError::InvalidEvent`] when an event is empty or oversized.
pub fn verify_chain<'a, I>(events: I) -> Result<[u8; HASH_BYTES], AuditError>
where
    I: IntoIterator<Item = (u64, &'a [u8])>,
{
    let mut expected_sequence = 1;
    let mut previous = [0; HASH_BYTES];
    for (sequence, event) in events {
        if sequence != expected_sequence {
            return Err(AuditError::InvalidPosition);
        }
        previous = event_hash(&previous, event)?;
        expected_sequence = expected_sequence.checked_add(1).ok_or(AuditError::InvalidPosition)?;
    }
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_hash_is_deterministic_and_chained() {
        let first = event_hash(&[0; HASH_BYTES], b"first").expect("first hash");
        let second = event_hash(&first, b"second").expect("second hash");
        assert_ne!(first, second);
        assert_eq!(first, event_hash(&[0; HASH_BYTES], b"first").expect("repeat hash"));
        assert_eq!(
            verify_chain([(1, &b"first"[..]), (2, &b"second"[..])]).expect("verify"),
            second
        );
    }

    #[test]
    fn bounds_and_positions_fail_closed() {
        assert_eq!(validate_event(&[]), Err(AuditError::InvalidEvent));
        assert_eq!(validate_event(&vec![0; MAX_EVENT_BYTES + 1]), Err(AuditError::InvalidEvent));
        assert_eq!(verify_chain([(2, &b"event"[..])]), Err(AuditError::InvalidPosition));
        assert_eq!(
            checkpoint_payload(&[1; 16], 0, &[2; HASH_BYTES], 1),
            Err(AuditError::InvalidPosition)
        );
        assert_eq!(
            checkpoint_payload(&[1; 16], 1, &[2; HASH_BYTES], 0),
            Err(AuditError::InvalidPosition)
        );
    }

    #[test]
    fn checkpoint_payload_binds_all_fields() {
        let payload = checkpoint_payload(&[1; 16], 3, &[2; HASH_BYTES], 4).expect("payload");
        assert!(payload.starts_with(CHECKPOINT_DOMAIN));
        assert_eq!(payload.len(), CHECKPOINT_DOMAIN.len() + 16 + 8 + HASH_BYTES + 8);
        assert_ne!(payload, checkpoint_payload(&[1; 16], 4, &[2; HASH_BYTES], 4).expect("other"));
    }
}
