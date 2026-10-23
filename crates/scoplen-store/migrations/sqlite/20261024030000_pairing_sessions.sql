-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE pairing_sessions (
    pairing_id BLOB NOT NULL PRIMARY KEY CHECK (length(pairing_id) = 16),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    responder_device_id BLOB NOT NULL CHECK (length(responder_device_id) = 16),
    capability_digest BLOB NOT NULL CHECK (length(capability_digest) = 32),
    account_id BLOB CHECK (account_id IS NULL OR length(account_id) = 16),
    initiator_device_id BLOB CHECK (initiator_device_id IS NULL OR length(initiator_device_id) = 16),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms - created_at_ms = 300000),
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms >= expires_at_ms),
    state TEXT NOT NULL CHECK (state IN ('waiting','exchanging','ready','completed','cancelled','expired')),
    slot_count INTEGER NOT NULL CHECK (slot_count BETWEEN 0 AND 7),
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes BETWEEN 0 AND 268435456),
    approval_fingerprint BLOB CHECK (approval_fingerprint IS NULL OR length(approval_fingerprint) = 32),
    completed_revision INTEGER CHECK (completed_revision IS NULL OR completed_revision > 0),
    CHECK ((account_id IS NULL) = (initiator_device_id IS NULL)),
    CHECK ((approval_fingerprint IS NULL) = (completed_revision IS NULL)),
    CHECK ((state = 'completed') = (approval_fingerprint IS NOT NULL)),
    CHECK (state NOT IN ('exchanging','ready','completed') OR account_id IS NOT NULL),
    CHECK (state NOT IN ('completed','cancelled','expired') OR payload_bytes = 0)
);
CREATE INDEX pairing_sessions_by_retention ON pairing_sessions (retain_until_ms);
CREATE INDEX pairing_sessions_by_expiry ON pairing_sessions (state, expires_at_ms);

CREATE TABLE pairing_slots (
    pairing_id BLOB NOT NULL CHECK (length(pairing_id) = 16),
    slot_index INTEGER NOT NULL CHECK (slot_index BETWEEN 0 AND 6),
    payload BLOB CHECK (payload IS NULL OR length(payload) BETWEEN 1 AND 4456448),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    PRIMARY KEY (pairing_id, slot_index),
    FOREIGN KEY (pairing_id) REFERENCES pairing_sessions (pairing_id) ON DELETE CASCADE
);
