-- SPDX-License-Identifier: AGPL-3.0-only

-- Historical confirmation facts only; these rows confer no current authority.
-- Fixed application payload: 275 bytes, below the 512-byte contract bound.
CREATE TABLE account_operation_receipts (
    operation_id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(operation_id) = 16),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    personal_vault_id BYTEA NOT NULL CHECK (octet_length(personal_vault_id) = 16),
    device_id BYTEA NOT NULL UNIQUE CHECK (octet_length(device_id) = 16),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    kind BIGINT NOT NULL CHECK (kind IN (1, 2)),
    device_signing_public_key BYTEA NOT NULL CHECK (octet_length(device_signing_public_key) = 65),
    device_kem_public_key BYTEA NOT NULL CHECK (octet_length(device_kem_public_key) = 65),
    account_signing_public_key BYTEA NOT NULL CHECK (octet_length(account_signing_public_key) = 32),
    admitted_key_revision BIGINT NOT NULL CHECK (admitted_key_revision > 0),
    committed_at_ms BIGINT NOT NULL CHECK (committed_at_ms > 0),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id) ON DELETE CASCADE
);

CREATE INDEX account_operation_receipts_account ON account_operation_receipts (account_id);
CREATE INDEX account_operation_receipts_signing ON account_operation_receipts (device_signing_public_key);
CREATE INDEX account_operation_receipts_kem ON account_operation_receipts (device_kem_public_key);

CREATE FUNCTION guard_account_operation_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_exists BOOLEAN;
    retained_count BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Serialize the Account lifetime bound even for direct concurrent insertions.
        EXECUTE format('SELECT TRUE FROM %I.identity_accounts WHERE account_id = $1 FOR UPDATE', TG_TABLE_SCHEMA)
            INTO parent_exists USING NEW.account_id;
        EXECUTE format('SELECT COUNT(*) FROM %I.account_operation_receipts WHERE account_id = $1', TG_TABLE_SCHEMA)
            INTO retained_count USING NEW.account_id;
        IF parent_exists IS DISTINCT FROM TRUE OR retained_count >= 65536 THEN
            RAISE EXCEPTION 'Account receipt ownership or capacity is invalid';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.identity_accounts WHERE account_id = $1)', TG_TABLE_SCHEMA)
            INTO parent_exists USING OLD.account_id;
        IF parent_exists THEN
            RAISE EXCEPTION 'Account receipt requires Account deletion';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Account receipt is immutable';
END;
$$;

CREATE TRIGGER account_operation_receipts_guard
BEFORE INSERT OR UPDATE OR DELETE ON account_operation_receipts
FOR EACH ROW EXECUTE FUNCTION guard_account_operation_receipt();

CREATE FUNCTION guard_account_operation_receipts_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_exists BOOLEAN;
BEGIN
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.account_operation_receipts r JOIN %I.identity_accounts a ON a.account_id = r.account_id)', TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
        INTO parent_exists;
    IF parent_exists THEN
        RAISE EXCEPTION 'Account receipt requires Account deletion';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER account_operation_receipts_truncate
BEFORE TRUNCATE ON account_operation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION guard_account_operation_receipts_truncate();
