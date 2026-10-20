-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE deployment_audit_events (
    sequence INTEGER NOT NULL PRIMARY KEY CHECK (sequence > 0),
    previous_hash BLOB NOT NULL CHECK (length(previous_hash) = 32),
    event_bytes BLOB NOT NULL CHECK (length(event_bytes) BETWEEN 1 AND 1048576),
    event_hash BLOB NOT NULL CHECK (length(event_hash) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0)
);

CREATE TABLE deployment_audit_checkpoints (
    sequence INTEGER NOT NULL PRIMARY KEY CHECK (sequence > 0),
    head_hash BLOB NOT NULL CHECK (length(head_hash) = 32),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    signed_at_ms INTEGER NOT NULL CHECK (signed_at_ms > 0)
);
