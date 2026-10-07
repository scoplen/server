-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE sync_personal_vaults (
    account_id BLOB PRIMARY KEY NOT NULL CHECK (length(account_id) = 16),
    vault_id BLOB NOT NULL UNIQUE CHECK (length(vault_id) = 16),
    key_epoch INTEGER NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
    wrapped_vault_key BLOB NOT NULL CHECK (length(wrapped_vault_key) > 0 AND length(wrapped_vault_key) <= 65536),
    FOREIGN KEY (vault_id) REFERENCES sync_vaults (vault_id) ON DELETE CASCADE
);
