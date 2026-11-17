-- SPDX-License-Identifier: AGPL-3.0-only

-- Preserve all existing credential, capability and browser-family bindings as unsigned bytes.
ALTER TABLE account_password_bootstrap DROP CONSTRAINT account_password_bootstrap_credential_generation_check;
ALTER TABLE account_password_bootstrap ALTER COLUMN credential_generation TYPE BYTEA USING int8send(credential_generation);
ALTER TABLE account_password_bootstrap ADD CONSTRAINT account_password_bootstrap_credential_generation_check CHECK (octet_length(credential_generation)=8 AND credential_generation>decode('0000000000000000','hex'));
ALTER TABLE account_admission_capabilities DROP CONSTRAINT account_admission_capabilities_credential_generation_check;
ALTER TABLE account_admission_capabilities ALTER COLUMN credential_generation TYPE BYTEA USING int8send(credential_generation);
ALTER TABLE account_admission_capabilities ADD CONSTRAINT account_admission_capabilities_credential_generation_check CHECK (octet_length(credential_generation)=8 AND credential_generation>decode('0000000000000000','hex'));
ALTER TABLE account_browser_families DROP CONSTRAINT account_browser_families_credential_generation_check;
ALTER TABLE account_browser_families ALTER COLUMN credential_generation TYPE BYTEA USING int8send(credential_generation);
ALTER TABLE account_browser_families ADD CONSTRAINT account_browser_families_credential_generation_check CHECK (octet_length(credential_generation)=8 AND credential_generation>decode('0000000000000000','hex'));

CREATE OR REPLACE FUNCTION guard_account_password_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_password_owned BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        EXECUTE format('SELECT password_owned FROM %I.identity_accounts WHERE account_id = $1', TG_TABLE_SCHEMA)
            INTO parent_password_owned USING NEW.account_id;
        IF parent_password_owned IS DISTINCT FROM TRUE OR NEW.credential_generation<>decode('0000000000000001','hex') THEN
            RAISE EXCEPTION 'Account password bootstrap cannot be attached';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF (NEW.account_id,NEW.origin,NEW.username,NEW.password_profile,NEW.personal_vault_id,NEW.account_signing_public_key,NEW.account_kem_public_key)
            IS DISTINCT FROM (OLD.account_id,OLD.origin,OLD.username,OLD.password_profile,OLD.personal_vault_id,OLD.account_signing_public_key,OLD.account_kem_public_key)
            OR (NEW IS DISTINCT FROM OLD AND NEW.credential_generation<=OLD.credential_generation) THEN
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

ALTER TABLE account_request_challenges DROP CONSTRAINT account_request_challenges_kind_check;
ALTER TABLE account_request_challenges ADD CONSTRAINT account_request_challenges_kind_check CHECK (kind IN (1,2,3));
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 50);
ALTER TABLE account_operation_receipts DROP CONSTRAINT account_operation_receipts_device_id_key;
ALTER TABLE account_operation_receipts DROP CONSTRAINT account_operation_receipts_kind_check;
ALTER TABLE account_operation_receipts ADD CONSTRAINT account_operation_receipts_kind_check CHECK (kind IN (1,2,3));
ALTER TABLE account_operation_receipts ALTER COLUMN admitted_key_revision DROP NOT NULL;
ALTER TABLE account_operation_receipts ADD COLUMN credential_generation BYTEA CHECK (octet_length(credential_generation)=8 AND credential_generation>decode('0000000000000000','hex'));
ALTER TABLE account_operation_receipts ADD CONSTRAINT account_operation_receipts_result_check CHECK ((kind IN (1,2) AND admitted_key_revision IS NOT NULL AND credential_generation IS NULL) OR (kind=3 AND admitted_key_revision IS NULL AND credential_generation IS NOT NULL));
CREATE UNIQUE INDEX account_operation_receipts_enrolled_device ON account_operation_receipts (device_id) WHERE kind IN (1,2);
