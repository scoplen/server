-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE sync_vaults (
    vault_id BLOB PRIMARY KEY NOT NULL CHECK (length(vault_id) = 16),
    kind TEXT NOT NULL CHECK (kind IN ('personal', 'shared', 'organization')),
    current_seq INTEGER NOT NULL DEFAULT 0 CHECK (current_seq >= 0),
    purge_horizon INTEGER NOT NULL DEFAULT 0 CHECK (purge_horizon >= 0),
    CHECK (purge_horizon <= current_seq)
);

CREATE TABLE sync_vault_members (
    vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    wrapped_vault_key BLOB NOT NULL CHECK (length(wrapped_vault_key) > 0 AND length(wrapped_vault_key) <= 65536),
    PRIMARY KEY (vault_id, account_id),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE TABLE sync_vault_member_keys (
    vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    wrapped_vault_key BLOB NOT NULL CHECK (length(wrapped_vault_key) > 0 AND length(wrapped_vault_key) <= 65536),
    PRIMARY KEY (vault_id, account_id, epoch),
    FOREIGN KEY (vault_id, account_id) REFERENCES sync_vault_members (vault_id, account_id) ON DELETE CASCADE
);

CREATE TABLE sync_objects (
    vault_id BLOB NOT NULL,
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    envelope BLOB NOT NULL CHECK (length(envelope) > 0 AND length(envelope) <= 266240),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    signer_device_id BLOB CHECK (signer_device_id IS NULL OR length(signer_device_id) = 16),
    written_at_ms INTEGER NOT NULL CHECK (written_at_ms >= 0),
    PRIMARY KEY (vault_id, object_id),
    UNIQUE (vault_id, sequence),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE TABLE sync_object_versions (
    vault_id BLOB NOT NULL,
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    envelope BLOB NOT NULL CHECK (length(envelope) > 0 AND length(envelope) <= 266240),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    signer_device_id BLOB CHECK (signer_device_id IS NULL OR length(signer_device_id) = 16),
    written_at_ms INTEGER NOT NULL CHECK (written_at_ms >= 0),
    PRIMARY KEY (vault_id, object_id, sequence),
    UNIQUE (vault_id, sequence),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE TABLE sync_acks (
    vault_id BLOB NOT NULL,
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    cursor INTEGER NOT NULL CHECK (cursor >= 0),
    acknowledged_at_ms INTEGER NOT NULL CHECK (acknowledged_at_ms >= 0),
    PRIMARY KEY (vault_id, device_id),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE INDEX sync_objects_by_vault_sequence ON sync_objects (vault_id, sequence);
CREATE INDEX sync_versions_by_vault_sequence ON sync_object_versions (vault_id, sequence);
CREATE INDEX sync_vault_members_by_account ON sync_vault_members (account_id, vault_id);
CREATE INDEX sync_vault_member_keys_by_vault_epoch ON sync_vault_member_keys (vault_id, epoch, account_id);
