-- SPDX-License-Identifier: AGPL-3.0-only

-- The migration reserves the singleton. Runtime initialization may fill it once;
-- a missing singleton is corruption, not permission to replace the deployment key.
CREATE TABLE account_password_probe_key (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    encrypted_key BLOB,
    created_at_ms INTEGER,
    CHECK (
        (encrypted_key IS NULL AND created_at_ms IS NULL)
        OR (encrypted_key IS NOT NULL AND length(encrypted_key) = 73
            AND created_at_ms IS NOT NULL AND created_at_ms > 0)
    )
);

INSERT INTO account_password_probe_key (singleton) VALUES (1);

CREATE TRIGGER account_password_probe_key_no_reset
BEFORE UPDATE ON account_password_probe_key
WHEN OLD.encrypted_key IS NOT NULL
    AND (NEW.encrypted_key IS NULL OR NEW.created_at_ms IS NOT OLD.created_at_ms)
BEGIN SELECT RAISE(ABORT, 'initialized Account probe key cannot be reset'); END;
CREATE TRIGGER account_password_probe_key_no_delete
BEFORE DELETE ON account_password_probe_key
WHEN OLD.encrypted_key IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'initialized Account probe key cannot be removed'); END;
CREATE TRIGGER account_password_probe_key_no_replace
BEFORE INSERT ON account_password_probe_key
WHEN EXISTS (SELECT 1 FROM account_password_probe_key WHERE encrypted_key IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'initialized Account probe key cannot be replaced'); END;
