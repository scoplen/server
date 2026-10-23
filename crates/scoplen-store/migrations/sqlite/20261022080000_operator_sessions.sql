-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE operator_refresh_families (
    family_id BLOB NOT NULL PRIMARY KEY CHECK (length(family_id) = 16),
    principal_kind TEXT NOT NULL CHECK (principal_kind = 'operator'),
    operator_id BLOB NOT NULL CHECK (length(operator_id) = 16),
    credential_id BLOB NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1023),
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) = 43),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    audience TEXT NOT NULL CHECK (audience = 'spl-admin/1'),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms - created_at_ms = 2592000000),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms),
    FOREIGN KEY (operator_id) REFERENCES deployment_operators (operator_id),
    FOREIGN KEY (credential_id) REFERENCES operator_credentials (credential_id)
);
CREATE INDEX operator_refresh_families_by_expiry ON operator_refresh_families (expires_at_ms);
CREATE INDEX operator_refresh_families_by_operator ON operator_refresh_families (operator_id, expires_at_ms);

CREATE TABLE operator_refresh_tokens (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK (length(token_digest) = 32),
    family_id BLOB NOT NULL CHECK (length(family_id) = 16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
    spent_at_ms INTEGER CHECK (spent_at_ms IS NULL OR spent_at_ms >= issued_at_ms),
    FOREIGN KEY (family_id) REFERENCES operator_refresh_families (family_id) ON DELETE CASCADE
);
CREATE INDEX operator_refresh_tokens_by_family ON operator_refresh_tokens (family_id);
