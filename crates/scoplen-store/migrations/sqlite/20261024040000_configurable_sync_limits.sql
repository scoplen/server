-- SPDX-License-Identifier: AGPL-3.0-only
-- Rebuild both leaf tables transactionally; deployment-selected envelope admission is enforced
-- by the store. The nonempty envelope check and every identity, epoch and relational check remain.

CREATE TABLE sync_objects_configurable (
    vault_id BLOB NOT NULL,
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    envelope BLOB NOT NULL CHECK (length(envelope) > 0),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    signer_device_id BLOB CHECK (signer_device_id IS NULL OR length(signer_device_id) = 16),
    written_at_ms INTEGER NOT NULL CHECK (written_at_ms >= 0),
    key_epoch INTEGER NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
    PRIMARY KEY (vault_id, object_id),
    UNIQUE (vault_id, sequence),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

INSERT INTO sync_objects_configurable
    (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch)
SELECT vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch
FROM sync_objects;
DROP TABLE sync_objects;
ALTER TABLE sync_objects_configurable RENAME TO sync_objects;
CREATE INDEX sync_objects_by_vault_sequence ON sync_objects (vault_id, sequence);

CREATE TABLE sync_object_versions_configurable (
    vault_id BLOB NOT NULL,
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    envelope BLOB NOT NULL CHECK (length(envelope) > 0),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    signer_device_id BLOB CHECK (signer_device_id IS NULL OR length(signer_device_id) = 16),
    written_at_ms INTEGER NOT NULL CHECK (written_at_ms >= 0),
    key_epoch INTEGER NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
    PRIMARY KEY (vault_id, object_id, sequence),
    UNIQUE (vault_id, sequence),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

INSERT INTO sync_object_versions_configurable
    (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch)
SELECT vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch
FROM sync_object_versions;
DROP TABLE sync_object_versions;
ALTER TABLE sync_object_versions_configurable RENAME TO sync_object_versions;
CREATE INDEX sync_versions_by_vault_sequence ON sync_object_versions (vault_id, sequence);
