-- SPDX-License-Identifier: AGPL-3.0-only

-- Credential-only changes retain identity/key ownership and every existing public artifact.
-- Fixed-width big-endian generations preserve the complete positive uint64 contract.
CREATE TABLE account_password_bootstrap_next (
    account_id BLOB PRIMARY KEY NOT NULL CHECK (typeof(account_id) = 'blob' AND length(account_id) = 16),
    origin TEXT NOT NULL CHECK (length(CAST(origin AS BLOB)) BETWEEN 1 AND 2048),
    username TEXT NOT NULL UNIQUE CHECK (length(CAST(username AS BLOB)) BETWEEN 3 AND 64),
    credential_generation BLOB NOT NULL CHECK (typeof(credential_generation)='blob' AND length(credential_generation)=8 AND credential_generation>X'0000000000000000'),
    password_profile INTEGER NOT NULL CHECK (password_profile = 1),
    password_salt BLOB NOT NULL CHECK (typeof(password_salt) = 'blob' AND length(password_salt) = 16),
    verifier BLOB NOT NULL CHECK (typeof(verifier) = 'blob' AND length(verifier) = 32),
    password_ark BLOB NOT NULL CHECK (typeof(password_ark) = 'blob' AND length(password_ark) = 73),
    personal_vault_id BLOB NOT NULL CHECK (typeof(personal_vault_id) = 'blob' AND length(personal_vault_id) = 16),
    account_signing_public_key BLOB NOT NULL CHECK (typeof(account_signing_public_key) = 'blob' AND length(account_signing_public_key) = 32),
    account_kem_public_key BLOB NOT NULL CHECK (typeof(account_kem_public_key) = 'blob' AND length(account_kem_public_key) = 32),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id) ON DELETE CASCADE
);
INSERT INTO account_password_bootstrap_next (account_id,origin,username,credential_generation,password_profile,password_salt,verifier,password_ark,personal_vault_id,account_signing_public_key,account_kem_public_key) SELECT account_id,origin,username,unhex(printf('%016x',credential_generation)),password_profile,password_salt,verifier,password_ark,personal_vault_id,account_signing_public_key,account_kem_public_key FROM account_password_bootstrap;
DROP TRIGGER account_password_bootstrap_delete;
DROP TABLE account_password_bootstrap;
ALTER TABLE account_password_bootstrap_next RENAME TO account_password_bootstrap;
CREATE TRIGGER account_password_bootstrap_owner
BEFORE INSERT ON account_password_bootstrap
WHEN NEW.credential_generation IS NOT X'0000000000000001' OR NOT EXISTS (
    SELECT 1 FROM identity_accounts WHERE account_id = NEW.account_id AND password_owned = 1
) OR EXISTS (SELECT 1 FROM account_password_bootstrap WHERE account_id = NEW.account_id)
BEGIN
    SELECT RAISE(ABORT, 'Account password bootstrap cannot be attached or replaced');
END;

CREATE TRIGGER account_password_bootstrap_immutable
BEFORE UPDATE ON account_password_bootstrap
WHEN NEW.account_id IS NOT OLD.account_id OR NEW.origin IS NOT OLD.origin
    OR NEW.username IS NOT OLD.username OR NEW.password_profile IS NOT OLD.password_profile
    OR NEW.personal_vault_id IS NOT OLD.personal_vault_id
    OR NEW.account_signing_public_key IS NOT OLD.account_signing_public_key
    OR NEW.account_kem_public_key IS NOT OLD.account_kem_public_key
    OR ((NEW.password_salt IS NOT OLD.password_salt OR NEW.verifier IS NOT OLD.verifier
        OR NEW.password_ark IS NOT OLD.password_ark OR NEW.credential_generation IS NOT OLD.credential_generation)
        AND NEW.credential_generation<=OLD.credential_generation)
BEGIN
    SELECT RAISE(ABORT, 'Account password transition is invalid');
END;

CREATE TRIGGER account_password_bootstrap_delete
BEFORE DELETE ON account_password_bootstrap
WHEN EXISTS (SELECT 1 FROM identity_accounts WHERE account_id = OLD.account_id)
BEGIN
    SELECT RAISE(ABORT, 'Account password bootstrap requires Account deletion');
END;

CREATE TABLE account_admission_capabilities_next (
    token_digest BLOB PRIMARY KEY NOT NULL CHECK (typeof(token_digest)='blob' AND length(token_digest)=32),
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(account_id)='blob' AND length(account_id)=16),
    credential_generation BLOB NOT NULL CHECK (typeof(credential_generation)='blob' AND length(credential_generation)=8 AND credential_generation>X'0000000000000000'),
    snapshot_digest BLOB NOT NULL CHECK (typeof(snapshot_digest)='blob' AND length(snapshot_digest)=32),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 1 AND 9223372036854475807),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=issued_at_ms+300000)
);
INSERT INTO account_admission_capabilities_next SELECT token_digest,account_id,unhex(printf('%016x',credential_generation)),snapshot_digest,issued_at_ms,expires_at_ms FROM account_admission_capabilities;
DROP TABLE account_admission_capabilities;
ALTER TABLE account_admission_capabilities_next RENAME TO account_admission_capabilities;
CREATE INDEX account_admission_capabilities_expiry ON account_admission_capabilities (expires_at_ms);
CREATE INDEX account_admission_capabilities_account ON account_admission_capabilities (account_id);

-- Preserve token children before rebuilding their generation-bearing parent.
CREATE TABLE account_browser_access_tokens_retained AS SELECT * FROM account_browser_access_tokens;
DROP TABLE account_browser_access_tokens;
CREATE TABLE account_browser_refresh_tokens_retained AS SELECT * FROM account_browser_refresh_tokens;
DROP TABLE account_browser_refresh_tokens;
CREATE TABLE account_browser_families_next (
    family_id BLOB NOT NULL PRIMARY KEY CHECK (length(family_id)=16),
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (length(account_id)=16),
    credential_generation BLOB NOT NULL CHECK (typeof(credential_generation)='blob' AND length(credential_generation)=8 AND credential_generation>X'0000000000000000'),
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt)=43),
    trusted_origin TEXT NOT NULL CHECK (length(trusted_origin) BETWEEN 1 AND 2048),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms-created_at_ms=2592000000),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms>=created_at_ms)
);
INSERT INTO account_browser_families_next SELECT family_id,account_id,unhex(printf('%016x',credential_generation)),dpop_jkt,trusted_origin,scope,created_at_ms,expires_at_ms,revoked_at_ms FROM account_browser_families;
DROP TABLE account_browser_families;
ALTER TABLE account_browser_families_next RENAME TO account_browser_families;
CREATE INDEX account_browser_families_expiry ON account_browser_families (expires_at_ms);
CREATE INDEX account_browser_families_account ON account_browser_families (account_id,expires_at_ms);
CREATE TABLE account_browser_access_tokens (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK (length(token_digest)=32),
    family_id BLOB NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (length(family_id)=16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms>0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms-issued_at_ms=600000)
);

INSERT INTO account_browser_access_tokens SELECT * FROM account_browser_access_tokens_retained;
DROP TABLE account_browser_access_tokens_retained;
CREATE TABLE account_browser_refresh_tokens (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK (length(token_digest)=32),
    family_id BLOB NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (length(family_id)=16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms>0),
    spent_at_ms INTEGER CHECK (spent_at_ms IS NULL OR spent_at_ms>=issued_at_ms)
);

INSERT INTO account_browser_refresh_tokens SELECT * FROM account_browser_refresh_tokens_retained;
DROP TABLE account_browser_refresh_tokens_retained;
CREATE TABLE account_request_challenges_next (
    attempt_digest BLOB PRIMARY KEY NOT NULL CHECK (typeof(attempt_digest) = 'blob' AND length(attempt_digest) = 32),
    nonce_digest BLOB NOT NULL CHECK (typeof(nonce_digest) = 'blob' AND length(nonce_digest) = 32),
    origin_digest BLOB NOT NULL CHECK (typeof(origin_digest) = 'blob' AND length(origin_digest) = 32),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    intent INTEGER NOT NULL CHECK (intent IN (1, 2)),
    operation_id BLOB NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms = issued_at_ms + 120000)
);
INSERT INTO account_request_challenges_next SELECT * FROM account_request_challenges;
DROP TABLE account_request_challenges;
ALTER TABLE account_request_challenges_next RENAME TO account_request_challenges;
CREATE INDEX account_request_challenges_expiry ON account_request_challenges (expires_at_ms);
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 50),
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
CREATE TABLE account_operation_receipts_next (
    operation_id BLOB PRIMARY KEY NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    account_id BLOB NOT NULL CHECK (typeof(account_id) = 'blob' AND length(account_id) = 16),
    personal_vault_id BLOB NOT NULL CHECK (typeof(personal_vault_id) = 'blob' AND length(personal_vault_id) = 16),
    device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
    request_digest BLOB NOT NULL CHECK (typeof(request_digest) = 'blob' AND length(request_digest) = 32),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    device_signing_public_key BLOB NOT NULL CHECK (typeof(device_signing_public_key) = 'blob' AND length(device_signing_public_key) = 65),
    device_kem_public_key BLOB NOT NULL CHECK (typeof(device_kem_public_key) = 'blob' AND length(device_kem_public_key) = 65),
    account_signing_public_key BLOB NOT NULL CHECK (typeof(account_signing_public_key) = 'blob' AND length(account_signing_public_key) = 32),
    admitted_key_revision INTEGER CHECK (admitted_key_revision > 0),
    credential_generation BLOB CHECK (credential_generation IS NULL OR (typeof(credential_generation)='blob' AND length(credential_generation)=8 AND credential_generation>X'0000000000000000')),
    committed_at_ms INTEGER NOT NULL CHECK (committed_at_ms > 0),
    CHECK ((kind IN (1,2) AND admitted_key_revision IS NOT NULL AND credential_generation IS NULL) OR (kind=3 AND admitted_key_revision IS NULL AND credential_generation IS NOT NULL)),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id) ON DELETE CASCADE
);
INSERT INTO account_operation_receipts_next (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) SELECT * FROM account_operation_receipts;
DROP TRIGGER account_operation_receipts_delete;
DROP TABLE account_operation_receipts;
ALTER TABLE account_operation_receipts_next RENAME TO account_operation_receipts;
CREATE INDEX account_operation_receipts_account ON account_operation_receipts (account_id);
CREATE INDEX account_operation_receipts_signing ON account_operation_receipts (device_signing_public_key);
CREATE INDEX account_operation_receipts_kem ON account_operation_receipts (device_kem_public_key);
CREATE UNIQUE INDEX account_operation_receipts_enrolled_device ON account_operation_receipts (device_id) WHERE kind IN (1,2);
CREATE TRIGGER account_operation_receipts_insert
BEFORE INSERT ON account_operation_receipts
WHEN EXISTS (SELECT 1 FROM account_operation_receipts WHERE operation_id = NEW.operation_id OR (NEW.kind IN (1,2) AND device_id = NEW.device_id))
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
