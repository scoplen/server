-- SPDX-License-Identifier: AGPL-3.0-only

-- Admission is initialized explicitly before enabling Account registration. No existing
-- Account is removed or relabeled, and these digests have no Account foreign key.
CREATE TABLE account_used_ids (
    digest BLOB PRIMARY KEY NOT NULL CHECK (typeof(digest) = 'blob' AND length(digest) = 32)
);

CREATE TABLE account_id_retention_guard (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    row_ceiling INTEGER CHECK (row_ceiling > 0 AND row_ceiling <= 576460752303423487),
    maintenance INTEGER NOT NULL DEFAULT 1 CHECK (maintenance IN (0, 1))
);
INSERT INTO account_id_retention_guard (singleton) VALUES (1);

CREATE TRIGGER account_used_ids_no_update BEFORE UPDATE ON account_used_ids
BEGIN SELECT RAISE(ABORT, 'used Account digests are immutable'); END;
CREATE TRIGGER account_used_ids_no_delete BEFORE DELETE ON account_used_ids
BEGIN SELECT RAISE(ABORT, 'used Account digests are retained'); END;
CREATE TRIGGER account_id_retention_guard_no_delete BEFORE DELETE ON account_id_retention_guard
BEGIN SELECT RAISE(ABORT, 'Account retention guard is retained'); END;
CREATE TRIGGER account_id_retention_guard_no_replace BEFORE INSERT ON account_id_retention_guard
WHEN EXISTS (SELECT 1 FROM account_id_retention_guard)
BEGIN SELECT RAISE(ABORT, 'Account retention guard cannot be replaced'); END;
CREATE TRIGGER account_id_retention_guard_no_reset BEFORE UPDATE ON account_id_retention_guard
WHEN OLD.row_ceiling IS NOT NULL
    AND (NEW.row_ceiling IS NULL OR NEW.row_ceiling < OLD.row_ceiling)
BEGIN SELECT RAISE(ABORT, 'Account retention ceiling cannot be reset'); END;
