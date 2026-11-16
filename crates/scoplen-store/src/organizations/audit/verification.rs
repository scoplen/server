// SPDX-License-Identifier: AGPL-3.0-only
//! Original-byte verification, independent of optional historical JSON projection.

use ed25519_dalek::{Signature, VerifyingKey};
use scoplen_api::audit::{AuditCheckpoint, AuditRange, AuditVerification, format_audit_timestamp};
use scoplen_audit::event_hash;
use sqlx::Row;
use uuid::Uuid;

pub(super) struct Event {
    organization: Vec<u8>,
    sequence: i64,
    previous_hash: Vec<u8>,
    hash: Vec<u8>,
    bytes: Option<Vec<u8>>,
}

impl Event {
    pub(super) fn verify(
        self,
        organization: Uuid,
        sequence: u64,
        expected_previous: Option<[u8; 32]>,
    ) -> Option<[u8; 32]> {
        let previous: [u8; 32] = self.previous_hash.try_into().ok()?;
        let stored: [u8; 32] = self.hash.try_into().ok()?;
        if self.organization.as_slice() != organization.as_bytes()
            || u64::try_from(self.sequence).ok()? != sequence
            || (sequence == 1 && previous != [0; 32])
            || expected_previous.is_some_and(|expected| expected != previous)
            || event_hash(&previous, &self.bytes?).ok()? != stored
        {
            return None;
        }
        Some(stored)
    }
}

pub(super) fn event_from_row<R: Row>(row: &R) -> Option<Event>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Some(Event {
        organization: row.try_get("organization_id").ok()?,
        sequence: row.try_get("sequence").ok()?,
        previous_hash: row.try_get("previous_hash").ok()?,
        hash: row.try_get("event_hash").ok()?,
        bytes: row.try_get("event_bytes").ok()?,
    })
}

pub(super) fn checkpoint_from_row<R: Row>(row: &R, organization: Uuid) -> Option<AuditCheckpoint>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    if row.try_get::<Vec<u8>, _>("organization_id").ok()?.as_slice() != organization.as_bytes() {
        return None;
    }
    let result = AuditCheckpoint {
        sequence: u64::try_from(row.try_get::<i64, _>("sequence").ok()?).ok()?,
        head_hash: row.try_get::<Vec<u8>, _>("head_hash").ok()?.try_into().ok()?,
        signed_at: format_audit_timestamp(row.try_get("signed_at_ms").ok()?).ok()?,
        signature: row.try_get::<Vec<u8>, _>("signature").ok()?.try_into().ok()?,
    };
    result.validate().ok()?;
    Some(result)
}

pub(super) fn verify_checkpoint(
    checkpoint: &AuditCheckpoint,
    organization: Uuid,
    hash: [u8; 32],
    trusted_key: &[u8; 32],
) -> bool {
    if checkpoint.head_hash != hash {
        return false;
    }
    checkpoint.signed_payload(organization).is_ok_and(|payload| {
        VerifyingKey::from_bytes(trusted_key).is_ok_and(|key| {
            key.verify_strict(&payload, &Signature::from_bytes(&checkpoint.signature)).is_ok()
        })
    })
}

pub(super) fn failure(
    organization_id: Uuid,
    range: AuditRange,
    sequence: u64,
) -> AuditVerification {
    AuditVerification {
        organization_id,
        from_sequence: range.from_sequence,
        to_sequence: range.to_sequence,
        checked_events: sequence - range.from_sequence,
        valid: false,
        failure_sequence: Some(sequence),
        previous_hash: None,
        head_hash: None,
        checkpoint: None,
        uncheckpointed_from_sequence: None,
    }
}

pub(super) fn success(
    organization_id: Uuid,
    range: AuditRange,
    previous_hash: [u8; 32],
    head_hash: [u8; 32],
    checkpoint: Option<AuditCheckpoint>,
) -> AuditVerification {
    let uncheckpointed_from_sequence = match &checkpoint {
        Some(checkpoint) if checkpoint.sequence == range.to_sequence => None,
        Some(checkpoint) => Some(checkpoint.sequence + 1),
        None => Some(range.from_sequence),
    };
    AuditVerification {
        organization_id,
        from_sequence: range.from_sequence,
        to_sequence: range.to_sequence,
        checked_events: range.to_sequence - range.from_sequence + 1,
        valid: true,
        failure_sequence: None,
        previous_hash: Some(previous_hash),
        head_hash: Some(head_hash),
        checkpoint,
        uncheckpointed_from_sequence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_original_bounds_and_genesis_are_integrity_failures() {
        let organization = Uuid::now_v7();
        for bytes in [None, Some(Vec::new()), Some(vec![0; scoplen_audit::MAX_EVENT_BYTES + 1])] {
            let event = Event {
                organization: organization.as_bytes().to_vec(),
                sequence: 1,
                previous_hash: vec![0; 32],
                hash: vec![0; 32],
                bytes,
            };
            assert!(event.verify(organization, 1, Some([0; 32])).is_none());
        }
        let previous = [9; 32];
        let hash = event_hash(&previous, b"original").unwrap();
        let event = Event {
            organization: organization.as_bytes().to_vec(),
            sequence: 1,
            previous_hash: previous.to_vec(),
            hash: hash.to_vec(),
            bytes: Some(b"original".to_vec()),
        };
        assert!(
            event.verify(organization, 1, None).is_none(),
            "a self-consistent hash cannot replace the zero genesis predecessor"
        );
    }
}
