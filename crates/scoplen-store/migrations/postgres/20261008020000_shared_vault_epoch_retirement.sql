-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE sync_objects ADD COLUMN key_epoch BIGINT NOT NULL DEFAULT 1 CHECK (key_epoch > 0);
ALTER TABLE sync_object_versions ADD COLUMN key_epoch BIGINT NOT NULL DEFAULT 1 CHECK (key_epoch > 0);

CREATE TABLE sync_vault_retired_epochs (
    vault_id BYTEA NOT NULL CHECK (octet_length(vault_id) = 16),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    PRIMARY KEY (vault_id, epoch),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);

CREATE INDEX sync_vault_retired_epochs_by_vault
    ON sync_vault_retired_epochs (vault_id, epoch);
