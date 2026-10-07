-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE audit_events (
    organization_id BYTEA NOT NULL CHECK (octet_length(organization_id) = 16),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    event_bytes BYTEA NOT NULL CHECK (octet_length(event_bytes) BETWEEN 1 AND 1048576),
    event_hash BYTEA NOT NULL CHECK (octet_length(event_hash) = 32),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
    PRIMARY KEY (organization_id, sequence),
    FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE
);

CREATE INDEX audit_events_by_hash
    ON audit_events (organization_id, event_hash);

CREATE TABLE audit_checkpoints (
    organization_id BYTEA NOT NULL CHECK (octet_length(organization_id) = 16),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    head_hash BYTEA NOT NULL CHECK (octet_length(head_hash) = 32),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    signed_at_ms BIGINT NOT NULL CHECK (signed_at_ms > 0),
    PRIMARY KEY (organization_id, sequence),
    FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE
);
