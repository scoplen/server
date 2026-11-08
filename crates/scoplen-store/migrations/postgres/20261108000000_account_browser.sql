-- SPDX-License-Identifier: AGPL-3.0-only

-- Browser attempts share native password admission, while retaining a distinct proof binding.
ALTER TABLE account_password_attempts ADD COLUMN purpose BIGINT NOT NULL DEFAULT 0 CHECK (purpose IN (0,1));
ALTER TABLE account_password_attempts ADD COLUMN browser_jkt TEXT CHECK ((purpose=0 AND browser_jkt IS NULL) OR (purpose=1 AND browser_jkt IS NOT NULL AND length(browser_jkt)=43));

CREATE TABLE account_browser_families (
    family_id BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(family_id)=16),
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    credential_generation BIGINT NOT NULL CHECK (credential_generation>0),
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt)=43),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms-created_at_ms=2592000000),
    revoked_at_ms BIGINT CHECK (revoked_at_ms IS NULL OR revoked_at_ms>=created_at_ms)
);
CREATE INDEX account_browser_families_expiry ON account_browser_families (expires_at_ms);
CREATE INDEX account_browser_families_account ON account_browser_families (account_id,expires_at_ms);

CREATE TABLE account_browser_access_tokens (
    token_digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(token_digest)=32),
    family_id BYTEA NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (octet_length(family_id)=16),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms>0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms-issued_at_ms=600000)
);
CREATE INDEX account_browser_access_expiry ON account_browser_access_tokens (expires_at_ms);
CREATE INDEX account_browser_access_family ON account_browser_access_tokens (family_id);

CREATE TABLE account_browser_refresh_tokens (
    token_digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(token_digest)=32),
    family_id BYTEA NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (octet_length(family_id)=16),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms>0),
    spent_at_ms BIGINT CHECK (spent_at_ms IS NULL OR spent_at_ms>=issued_at_ms)
);
CREATE INDEX account_browser_refresh_family ON account_browser_refresh_tokens (family_id);

-- Rotation and sign-out have independent admission without resetting password budgets.
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 42);
