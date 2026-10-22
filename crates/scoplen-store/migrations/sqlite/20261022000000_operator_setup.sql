-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE deployment_operators (
    operator_id BLOB NOT NULL PRIMARY KEY CHECK (length(operator_id) = 16),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at_s INTEGER NOT NULL CHECK (created_at_s > 0)
);

CREATE TABLE operator_credentials (
    credential_id BLOB NOT NULL PRIMARY KEY CHECK (length(credential_id) BETWEEN 1 AND 1023),
    operator_id BLOB NOT NULL UNIQUE CHECK (length(operator_id) = 16),
    user_handle BLOB NOT NULL UNIQUE CHECK (length(user_handle) = 16 AND user_handle = operator_id),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    rp_id TEXT NOT NULL CHECK (length(rp_id) BETWEEN 1 AND 253),
    credential_version INTEGER NOT NULL CHECK (credential_version = 1),
    credential_state BLOB NOT NULL CHECK (length(credential_state) BETWEEN 1 AND 32768),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at_s INTEGER NOT NULL CHECK (created_at_s > 0),
    FOREIGN KEY (operator_id) REFERENCES deployment_operators (operator_id)
);

CREATE TABLE operator_setup (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    token_digest BLOB NOT NULL CHECK (length(token_digest) = 32),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    issued_at_s INTEGER NOT NULL CHECK (issued_at_s > 0),
    expires_at_s INTEGER NOT NULL CHECK (expires_at_s - issued_at_s = 3600),
    completed_at_s INTEGER CHECK (completed_at_s IS NULL OR completed_at_s >= issued_at_s)
);

CREATE TABLE operator_ceremonies (
    ceremony_id BLOB NOT NULL PRIMARY KEY CHECK (length(ceremony_id) = 16),
    purpose INTEGER NOT NULL CHECK (purpose IN (1, 2)),
    operator_id BLOB CHECK (operator_id IS NULL OR length(operator_id) = 16),
    setup_digest BLOB CHECK (setup_digest IS NULL OR length(setup_digest) = 32),
    browser_jkt TEXT NOT NULL CHECK (length(browser_jkt) = 43),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    rp_id TEXT NOT NULL CHECK (length(rp_id) BETWEEN 1 AND 253),
    issued_at_s INTEGER NOT NULL CHECK (issued_at_s > 0),
    expires_at_s INTEGER NOT NULL CHECK (expires_at_s > issued_at_s AND expires_at_s - issued_at_s <= 300),
    state_version INTEGER NOT NULL CHECK (state_version = 1),
    library_state BLOB NOT NULL CHECK (length(library_state) BETWEEN 1 AND 32768),
    consumed_at_s INTEGER CHECK (consumed_at_s IS NULL OR consumed_at_s >= issued_at_s),
    CHECK ((purpose = 1 AND operator_id IS NOT NULL AND setup_digest IS NOT NULL)
        OR (purpose = 2 AND operator_id IS NULL AND setup_digest IS NULL))
);
CREATE INDEX operator_ceremonies_by_expiry ON operator_ceremonies (expires_at_s);
