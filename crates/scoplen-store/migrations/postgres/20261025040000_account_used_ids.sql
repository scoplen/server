-- SPDX-License-Identifier: AGPL-3.0-only

-- Admission is initialized explicitly before enabling Account registration. No existing
-- Account is removed or relabeled, and these digests have no Account foreign key.
CREATE TABLE account_used_ids (
    digest BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(digest) = 32)
);

CREATE TABLE account_id_retention_guard (
    singleton BIGINT PRIMARY KEY NOT NULL CHECK (singleton = 1),
    row_ceiling BIGINT CHECK (row_ceiling > 0 AND row_ceiling <= 576460752303423487),
    maintenance BOOLEAN NOT NULL DEFAULT TRUE
);
INSERT INTO account_id_retention_guard (singleton) VALUES (1);

CREATE FUNCTION protect_account_used_ids() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'used Account digests are immutable and retained';
END;
$$;
CREATE TRIGGER account_used_ids_no_change BEFORE UPDATE OR DELETE ON account_used_ids
FOR EACH ROW EXECUTE FUNCTION protect_account_used_ids();
CREATE TRIGGER account_used_ids_no_truncate BEFORE TRUNCATE ON account_used_ids
FOR EACH STATEMENT EXECUTE FUNCTION protect_account_used_ids();

CREATE FUNCTION protect_account_id_retention_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('TRUNCATE', 'DELETE') THEN
        RAISE EXCEPTION 'Account retention guard is retained';
    END IF;
    IF OLD.row_ceiling IS NOT NULL
        AND (NEW.row_ceiling IS NULL OR NEW.row_ceiling < OLD.row_ceiling) THEN
        RAISE EXCEPTION 'Account retention ceiling cannot be reset';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER account_id_retention_guard_no_reset BEFORE UPDATE OR DELETE ON account_id_retention_guard
FOR EACH ROW EXECUTE FUNCTION protect_account_id_retention_guard();
CREATE TRIGGER account_id_retention_guard_no_truncate BEFORE TRUNCATE ON account_id_retention_guard
FOR EACH STATEMENT EXECUTE FUNCTION protect_account_id_retention_guard();
