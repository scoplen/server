-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE identity_accounts (
    account_id BLOB NOT NULL PRIMARY KEY CHECK (length(account_id) = 16),
    email TEXT,
    account_signing_public_key BLOB NOT NULL CHECK (length(account_signing_public_key) = 32),
    account_kem_public_key BLOB NOT NULL CHECK (length(account_kem_public_key) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0)
);

CREATE TABLE identity_devices (
    device_id BLOB NOT NULL PRIMARY KEY CHECK (length(device_id) = 16),
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    certificate BLOB NOT NULL CHECK (length(certificate) BETWEEN 1 AND 65536),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id)
);

CREATE INDEX identity_devices_by_account ON identity_devices (account_id, device_id);
CREATE INDEX sync_account_key_device_wraps_by_device ON sync_account_key_device_wraps (device_id);

CREATE TABLE personal_invitations (
    invitation_id BLOB NOT NULL PRIMARY KEY CHECK (length(invitation_id) = 16),
    token_digest BLOB NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    issuer_operator_id BLOB NOT NULL CHECK (length(issuer_operator_id) = 16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms - issued_at_ms = 86400000),
    consumed_at_ms INTEGER,
    consumed_account_id BLOB CHECK (consumed_account_id IS NULL OR length(consumed_account_id) = 16),
    CHECK (
        (consumed_at_ms IS NULL AND consumed_account_id IS NULL) OR
        (consumed_at_ms IS NOT NULL AND consumed_at_ms >= issued_at_ms AND consumed_at_ms < expires_at_ms AND consumed_account_id IS NOT NULL)
    ),
    FOREIGN KEY (consumed_account_id) REFERENCES identity_accounts (account_id)
);

CREATE INDEX personal_invitations_by_expiry ON personal_invitations (expires_at_ms);
