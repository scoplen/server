-- SPDX-License-Identifier: AGPL-3.0-only

-- Historical confirmation facts only; these rows confer no current authority.
-- Fixed application payload: 275 bytes, below the 512-byte contract bound.
CREATE TABLE account_operation_receipts (
    operation_id BLOB PRIMARY KEY NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    account_id BLOB NOT NULL CHECK (typeof(account_id) = 'blob' AND length(account_id) = 16),
    personal_vault_id BLOB NOT NULL CHECK (typeof(personal_vault_id) = 'blob' AND length(personal_vault_id) = 16),
    device_id BLOB NOT NULL UNIQUE CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
    request_digest BLOB NOT NULL CHECK (typeof(request_digest) = 'blob' AND length(request_digest) = 32),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    device_signing_public_key BLOB NOT NULL CHECK (typeof(device_signing_public_key) = 'blob' AND length(device_signing_public_key) = 65),
    device_kem_public_key BLOB NOT NULL CHECK (typeof(device_kem_public_key) = 'blob' AND length(device_kem_public_key) = 65),
    account_signing_public_key BLOB NOT NULL CHECK (typeof(account_signing_public_key) = 'blob' AND length(account_signing_public_key) = 32),
    admitted_key_revision INTEGER NOT NULL CHECK (admitted_key_revision > 0),
    committed_at_ms INTEGER NOT NULL CHECK (committed_at_ms > 0),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id) ON DELETE CASCADE
);

CREATE INDEX account_operation_receipts_account ON account_operation_receipts (account_id);
CREATE INDEX account_operation_receipts_signing ON account_operation_receipts (device_signing_public_key);
CREATE INDEX account_operation_receipts_kem ON account_operation_receipts (device_kem_public_key);

CREATE TRIGGER account_operation_receipts_insert
BEFORE INSERT ON account_operation_receipts
WHEN EXISTS (SELECT 1 FROM account_operation_receipts WHERE operation_id = NEW.operation_id OR device_id = NEW.device_id)
    OR (SELECT COUNT(*) FROM account_operation_receipts WHERE account_id = NEW.account_id) >= 65536
BEGIN
    SELECT RAISE(ABORT, 'Account receipt cannot be replaced or exceed its bound');
END;

CREATE TRIGGER account_operation_receipts_immutable
BEFORE UPDATE ON account_operation_receipts
BEGIN
    SELECT RAISE(ABORT, 'Account receipt is immutable');
END;

CREATE TRIGGER account_operation_receipts_delete
BEFORE DELETE ON account_operation_receipts
WHEN EXISTS (SELECT 1 FROM identity_accounts WHERE account_id = OLD.account_id)
BEGIN
    SELECT RAISE(ABORT, 'Account receipt requires Account deletion');
END;
