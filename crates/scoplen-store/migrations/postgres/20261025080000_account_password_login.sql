-- SPDX-License-Identifier: AGPL-3.0-only

-- Attempts retain canonical public bindings, never the raw attempt or an AuthSecret derivative.
-- Admission capabilities retain digests only and follow their Account's ordinary lifecycle.
CREATE TABLE account_password_attempts (
    attempt_digest BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(attempt_digest)=32),
    origin_digest BYTEA NOT NULL CHECK (octet_length(origin_digest)=32),
    username TEXT NOT NULL CHECK (octet_length(username) BETWEEN 3 AND 64),
    password_profile BIGINT NOT NULL CHECK (password_profile=1),
    password_salt BYTEA NOT NULL CHECK (octet_length(password_salt)=16),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms BETWEEN 1 AND 9223372036854655807),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=issued_at_ms+120000)
);
CREATE INDEX account_password_attempts_expiry ON account_password_attempts (expires_at_ms);

CREATE TABLE account_admission_capabilities (
    token_digest BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(token_digest)=32),
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    credential_generation BIGINT NOT NULL CHECK (credential_generation>0),
    snapshot_digest BYTEA NOT NULL CHECK (octet_length(snapshot_digest)=32),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms BETWEEN 1 AND 9223372036854475807),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=issued_at_ms+300000)
);
CREATE INDEX account_admission_capabilities_expiry ON account_admission_capabilities (expires_at_ms);
CREATE INDEX account_admission_capabilities_account ON account_admission_capabilities (account_id);
