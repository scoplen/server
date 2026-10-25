-- SPDX-License-Identifier: AGPL-3.0-only

-- Attempts retain canonical public bindings, never the raw attempt or an AuthSecret derivative.
-- Admission capabilities retain digests only and follow their Account's ordinary lifecycle.
CREATE TABLE account_password_attempts (
    attempt_digest BLOB PRIMARY KEY NOT NULL CHECK (typeof(attempt_digest)='blob' AND length(attempt_digest)=32),
    origin_digest BLOB NOT NULL CHECK (typeof(origin_digest)='blob' AND length(origin_digest)=32),
    username TEXT NOT NULL CHECK (length(CAST(username AS BLOB)) BETWEEN 3 AND 64),
    password_profile INTEGER NOT NULL CHECK (password_profile=1),
    password_salt BLOB NOT NULL CHECK (typeof(password_salt)='blob' AND length(password_salt)=16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 1 AND 9223372036854655807),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=issued_at_ms+120000)
);
CREATE INDEX account_password_attempts_expiry ON account_password_attempts (expires_at_ms);

CREATE TABLE account_admission_capabilities (
    token_digest BLOB PRIMARY KEY NOT NULL CHECK (typeof(token_digest)='blob' AND length(token_digest)=32),
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(account_id)='blob' AND length(account_id)=16),
    credential_generation INTEGER NOT NULL CHECK (credential_generation>0),
    snapshot_digest BLOB NOT NULL CHECK (typeof(snapshot_digest)='blob' AND length(snapshot_digest)=32),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 1 AND 9223372036854475807),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=issued_at_ms+300000)
);
CREATE INDEX account_admission_capabilities_expiry ON account_admission_capabilities (expires_at_ms);
CREATE INDEX account_admission_capabilities_account ON account_admission_capabilities (account_id);
