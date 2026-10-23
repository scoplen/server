-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE pairing_sessions (
    pairing_id BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(pairing_id) = 16),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    responder_device_id BYTEA NOT NULL CHECK (octet_length(responder_device_id) = 16),
    capability_digest BYTEA NOT NULL CHECK (octet_length(capability_digest) = 32),
    account_id BYTEA CHECK (account_id IS NULL OR octet_length(account_id) = 16),
    initiator_device_id BYTEA CHECK (initiator_device_id IS NULL OR octet_length(initiator_device_id) = 16),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms - created_at_ms = 300000),
    retain_until_ms BIGINT NOT NULL CHECK (retain_until_ms >= expires_at_ms),
    state TEXT NOT NULL CHECK (state IN ('waiting','exchanging','ready','completed','cancelled','expired')),
    slot_count BIGINT NOT NULL CHECK (slot_count BETWEEN 0 AND 7),
    payload_bytes BIGINT NOT NULL CHECK (payload_bytes BETWEEN 0 AND 268435456),
    approval_fingerprint BYTEA CHECK (approval_fingerprint IS NULL OR octet_length(approval_fingerprint) = 32),
    completed_revision BIGINT CHECK (completed_revision IS NULL OR completed_revision > 0),
    CHECK ((account_id IS NULL) = (initiator_device_id IS NULL)),
    CHECK ((approval_fingerprint IS NULL) = (completed_revision IS NULL)),
    CHECK ((state = 'completed') = (approval_fingerprint IS NOT NULL)),
    CHECK (state NOT IN ('exchanging','ready','completed') OR account_id IS NOT NULL),
    CHECK (state NOT IN ('completed','cancelled','expired') OR payload_bytes = 0)
);
CREATE INDEX pairing_sessions_by_retention ON pairing_sessions (retain_until_ms);
CREATE INDEX pairing_sessions_by_expiry ON pairing_sessions (state, expires_at_ms);

CREATE TABLE pairing_slots (
    pairing_id BYTEA NOT NULL CHECK (octet_length(pairing_id) = 16),
    slot_index BIGINT NOT NULL CHECK (slot_index BETWEEN 0 AND 6),
    payload BYTEA CHECK (payload IS NULL OR octet_length(payload) BETWEEN 1 AND 4456448),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    PRIMARY KEY (pairing_id, slot_index),
    FOREIGN KEY (pairing_id) REFERENCES pairing_sessions (pairing_id) ON DELETE CASCADE
);
