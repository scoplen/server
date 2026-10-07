-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE sync_personal_vaults (
    account_id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(account_id) = 16),
    vault_id BYTEA NOT NULL UNIQUE CHECK (octet_length(vault_id) = 16),
    key_epoch BIGINT NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
    wrapped_vault_key BYTEA NOT NULL CHECK (octet_length(wrapped_vault_key) > 0 AND octet_length(wrapped_vault_key) <= 65536),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);
