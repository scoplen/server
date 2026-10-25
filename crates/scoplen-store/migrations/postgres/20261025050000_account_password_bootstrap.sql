-- SPDX-License-Identifier: AGPL-3.0-only

-- Existing Accounts remain without password state. Initial creation is transaction-local;
-- credential/root/ARK transitions require a separately authorized lifecycle.
ALTER TABLE identity_accounts ADD COLUMN password_owned BOOLEAN NOT NULL DEFAULT FALSE;

CREATE FUNCTION guard_account_password_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.password_owned IS DISTINCT FROM OLD.password_owned THEN
        RAISE EXCEPTION 'Account password ownership is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_accounts_password_owned_immutable
BEFORE UPDATE OF password_owned ON identity_accounts
FOR EACH ROW EXECUTE FUNCTION guard_account_password_ownership();

CREATE TABLE account_password_bootstrap (
    account_id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(account_id) = 16),
    origin TEXT NOT NULL CHECK (octet_length(origin) BETWEEN 1 AND 2048),
    username TEXT NOT NULL UNIQUE CHECK (octet_length(username) BETWEEN 3 AND 64),
    credential_generation BIGINT NOT NULL CHECK (credential_generation = 1),
    password_profile BIGINT NOT NULL CHECK (password_profile = 1),
    password_salt BYTEA NOT NULL CHECK (octet_length(password_salt) = 16),
    verifier BYTEA NOT NULL CHECK (octet_length(verifier) = 32),
    password_ark BYTEA NOT NULL CHECK (octet_length(password_ark) = 73),
    personal_vault_id BYTEA NOT NULL CHECK (octet_length(personal_vault_id) = 16),
    account_signing_public_key BYTEA NOT NULL CHECK (octet_length(account_signing_public_key) = 32),
    account_kem_public_key BYTEA NOT NULL CHECK (octet_length(account_kem_public_key) = 32),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id) ON DELETE CASCADE
);

CREATE FUNCTION guard_account_password_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_password_owned BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        EXECUTE format('SELECT password_owned FROM %I.identity_accounts WHERE account_id = $1', TG_TABLE_SCHEMA)
            INTO parent_password_owned USING NEW.account_id;
        IF parent_password_owned IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'Account password bootstrap cannot be attached';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'Account password bootstrap is immutable';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        EXECUTE format('SELECT password_owned FROM %I.identity_accounts WHERE account_id = $1', TG_TABLE_SCHEMA)
            INTO parent_password_owned USING OLD.account_id;
        IF parent_password_owned IS NOT NULL THEN
            RAISE EXCEPTION 'Account password bootstrap requires Account deletion';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Account password bootstrap operation is unsupported';
END;
$$;

CREATE TRIGGER account_password_bootstrap_guard
BEFORE INSERT OR UPDATE OR DELETE ON account_password_bootstrap
FOR EACH ROW EXECUTE FUNCTION guard_account_password_bootstrap();

CREATE FUNCTION guard_account_password_bootstrap_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_exists BOOLEAN;
BEGIN
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.account_password_bootstrap b JOIN %I.identity_accounts a ON a.account_id = b.account_id)', TG_TABLE_SCHEMA, TG_TABLE_SCHEMA)
        INTO parent_exists;
    IF parent_exists THEN
        RAISE EXCEPTION 'Account password bootstrap requires Account deletion';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER account_password_bootstrap_truncate
BEFORE TRUNCATE ON account_password_bootstrap
FOR EACH STATEMENT EXECUTE FUNCTION guard_account_password_bootstrap_truncate();
