-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE sync_vaults (
    vault_id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(vault_id) = 16),
    kind TEXT NOT NULL CHECK (kind IN ('personal', 'shared', 'organization')),
    current_seq BIGINT NOT NULL DEFAULT 0 CHECK (current_seq >= 0),
    purge_horizon BIGINT NOT NULL DEFAULT 0 CHECK (purge_horizon >= 0),
    CHECK (purge_horizon <= current_seq)
);

CREATE TABLE sync_vault_members (
    vault_id BYTEA NOT NULL CHECK (octet_length(vault_id) = 16),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    key_epoch BIGINT NOT NULL CHECK (key_epoch > 0),
    wrapped_vault_key BYTEA NOT NULL CHECK (octet_length(wrapped_vault_key) > 0 AND octet_length(wrapped_vault_key) <= 65536),
    PRIMARY KEY (vault_id, account_id),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE TABLE sync_objects (
    vault_id BYTEA NOT NULL,
    object_id BYTEA NOT NULL CHECK (octet_length(object_id) = 16),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    envelope BYTEA NOT NULL CHECK (octet_length(envelope) > 0 AND octet_length(envelope) <= 266240),
    tombstone BOOLEAN NOT NULL CHECK (tombstone IN (TRUE, FALSE)),
    signer_device_id BYTEA CHECK (signer_device_id IS NULL OR octet_length(signer_device_id) = 16),
    written_at_ms BIGINT NOT NULL CHECK (written_at_ms >= 0),
    PRIMARY KEY (vault_id, object_id),
    UNIQUE (vault_id, sequence),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE TABLE sync_object_versions (
    vault_id BYTEA NOT NULL,
    object_id BYTEA NOT NULL CHECK (octet_length(object_id) = 16),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    envelope BYTEA NOT NULL CHECK (octet_length(envelope) > 0 AND octet_length(envelope) <= 266240),
    tombstone BOOLEAN NOT NULL CHECK (tombstone IN (TRUE, FALSE)),
    signer_device_id BYTEA CHECK (signer_device_id IS NULL OR octet_length(signer_device_id) = 16),
    written_at_ms BIGINT NOT NULL CHECK (written_at_ms >= 0),
    PRIMARY KEY (vault_id, object_id, sequence),
    UNIQUE (vault_id, sequence),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE TABLE sync_acks (
    vault_id BYTEA NOT NULL,
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    cursor BIGINT NOT NULL CHECK (cursor >= 0),
    acknowledged_at_ms BIGINT NOT NULL CHECK (acknowledged_at_ms >= 0),
    PRIMARY KEY (vault_id, device_id),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE INDEX sync_objects_by_vault_sequence ON sync_objects (vault_id, sequence);
CREATE INDEX sync_versions_by_vault_sequence ON sync_object_versions (vault_id, sequence);
CREATE INDEX sync_vault_members_by_account ON sync_vault_members (account_id, vault_id);
