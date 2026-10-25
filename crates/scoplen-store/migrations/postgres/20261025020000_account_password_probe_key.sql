-- SPDX-License-Identifier: AGPL-3.0-only

-- The migration reserves the singleton. Runtime initialization may fill it once;
-- a missing singleton is corruption, not permission to replace the deployment key.
CREATE TABLE account_password_probe_key (
    singleton BIGINT PRIMARY KEY NOT NULL CHECK (singleton = 1),
    encrypted_key BYTEA,
    created_at_ms BIGINT,
    CHECK (
        (encrypted_key IS NULL AND created_at_ms IS NULL)
        OR (encrypted_key IS NOT NULL AND octet_length(encrypted_key) = 73
            AND created_at_ms IS NOT NULL AND created_at_ms > 0)
    )
);

INSERT INTO account_password_probe_key (singleton) VALUES (1);
