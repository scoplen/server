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

CREATE FUNCTION protect_account_password_probe_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'Account probe key singleton cannot be truncated';
    END IF;
    IF OLD.encrypted_key IS NOT NULL THEN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'initialized Account probe key cannot be removed';
        END IF;
        IF NEW.encrypted_key IS NULL OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
            RAISE EXCEPTION 'initialized Account probe key cannot be reset';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER account_password_probe_key_no_reset
BEFORE UPDATE OR DELETE ON account_password_probe_key
FOR EACH ROW EXECUTE FUNCTION protect_account_password_probe_key();
CREATE TRIGGER account_password_probe_key_no_truncate
BEFORE TRUNCATE ON account_password_probe_key
FOR EACH STATEMENT EXECUTE FUNCTION protect_account_password_probe_key();
