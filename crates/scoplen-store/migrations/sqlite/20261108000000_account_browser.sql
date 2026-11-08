-- SPDX-License-Identifier: AGPL-3.0-only

-- Browser attempts share native password admission, while retaining a distinct proof binding.
ALTER TABLE account_password_attempts ADD COLUMN purpose INTEGER NOT NULL DEFAULT 0 CHECK (purpose IN (0,1));
ALTER TABLE account_password_attempts ADD COLUMN browser_jkt TEXT CHECK ((purpose=0 AND browser_jkt IS NULL) OR (purpose=1 AND browser_jkt IS NOT NULL AND length(browser_jkt)=43));

CREATE TABLE account_browser_families (
    family_id BLOB NOT NULL PRIMARY KEY CHECK (length(family_id)=16),
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (length(account_id)=16),
    credential_generation INTEGER NOT NULL CHECK (credential_generation>0),
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt)=43),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms-created_at_ms=2592000000),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms>=created_at_ms)
);
CREATE INDEX account_browser_families_expiry ON account_browser_families (expires_at_ms);
CREATE INDEX account_browser_families_account ON account_browser_families (account_id,expires_at_ms);

CREATE TABLE account_browser_access_tokens (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK (length(token_digest)=32),
    family_id BLOB NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (length(family_id)=16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms>0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms-issued_at_ms=600000)
);
CREATE INDEX account_browser_access_expiry ON account_browser_access_tokens (expires_at_ms);
CREATE INDEX account_browser_access_family ON account_browser_access_tokens (family_id);

CREATE TABLE account_browser_refresh_tokens (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK (length(token_digest)=32),
    family_id BLOB NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (length(family_id)=16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms>0),
    spent_at_ms INTEGER CHECK (spent_at_ms IS NULL OR spent_at_ms>=issued_at_ms)
);
CREATE INDEX account_browser_refresh_family ON account_browser_refresh_tokens (family_id);

-- Rotation and sign-out have independent admission without resetting password budgets.
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 42),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
    bucket_key BLOB NOT NULL CHECK (typeof(bucket_key)='blob'),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms BETWEEN 0 AND 9223372036854715807),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 30),
    failure_streak INTEGER NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms INTEGER,
    cooldown_until_ms INTEGER,
    last_admitted_ms INTEGER NOT NULL CHECK (last_admitted_ms BETWEEN 1 AND 9223372036854175807),
    retire_at_ms INTEGER NOT NULL CHECK (retire_at_ms>0),
    PRIMARY KEY (endpoint,kind,bucket_key),
    CHECK (last_admitted_ms<=retire_at_ms-600000),
    CHECK (window_start_ms<=retire_at_ms-60000),
    CHECK (cooldown_until_ms IS NULL OR cooldown_until_ms<=retire_at_ms),
    CHECK ((kind=1 AND length(bucket_key) IN (4,16)) OR (kind=2 AND length(bucket_key)=32) OR (kind IN (3,4) AND length(bucket_key)=16)),
    CHECK ((failure_streak=0 AND last_failure_ms IS NULL AND cooldown_until_ms IS NULL)
        OR (failure_streak>0 AND last_failure_ms IS NOT NULL AND last_failure_ms>0
            AND cooldown_until_ms IS NOT NULL AND cooldown_until_ms>=last_failure_ms))
);
INSERT INTO account_entry_admission_next SELECT * FROM account_entry_admission;
DROP TABLE account_entry_admission;
ALTER TABLE account_entry_admission_next RENAME TO account_entry_admission;
CREATE INDEX account_entry_admission_retire ON account_entry_admission (retire_at_ms);
