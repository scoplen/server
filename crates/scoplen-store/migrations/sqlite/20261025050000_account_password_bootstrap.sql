-- SPDX-License-Identifier: AGPL-3.0-only

-- Existing Accounts remain without password state. Initial creation is transaction-local;
-- credential/root/ARK transitions require a separately authorized lifecycle.
ALTER TABLE identity_accounts ADD COLUMN password_owned INTEGER NOT NULL DEFAULT 0
    CHECK (password_owned IN (0, 1));

CREATE TRIGGER identity_accounts_password_owned_immutable
BEFORE UPDATE OF password_owned ON identity_accounts
WHEN NEW.password_owned IS NOT OLD.password_owned
BEGIN
    SELECT RAISE(ABORT, 'Account password ownership is immutable');
END;

CREATE TRIGGER identity_accounts_password_owned_replacement
BEFORE INSERT ON identity_accounts
WHEN EXISTS (
    SELECT 1 FROM identity_accounts
    WHERE account_id = NEW.account_id
        AND (password_owned = 1 OR password_owned IS NOT NEW.password_owned)
)
BEGIN
    SELECT RAISE(ABORT, 'Account password ownership is immutable');
END;

CREATE TABLE account_password_bootstrap (
    account_id BLOB PRIMARY KEY NOT NULL CHECK (typeof(account_id) = 'blob' AND length(account_id) = 16),
    origin TEXT NOT NULL CHECK (length(CAST(origin AS BLOB)) BETWEEN 1 AND 2048),
    username TEXT NOT NULL UNIQUE CHECK (length(CAST(username AS BLOB)) BETWEEN 3 AND 64),
    credential_generation INTEGER NOT NULL CHECK (credential_generation = 1),
    password_profile INTEGER NOT NULL CHECK (password_profile = 1),
    password_salt BLOB NOT NULL CHECK (typeof(password_salt) = 'blob' AND length(password_salt) = 16),
    verifier BLOB NOT NULL CHECK (typeof(verifier) = 'blob' AND length(verifier) = 32),
    password_ark BLOB NOT NULL CHECK (typeof(password_ark) = 'blob' AND length(password_ark) = 73),
    personal_vault_id BLOB NOT NULL CHECK (typeof(personal_vault_id) = 'blob' AND length(personal_vault_id) = 16),
    account_signing_public_key BLOB NOT NULL CHECK (typeof(account_signing_public_key) = 'blob' AND length(account_signing_public_key) = 32),
    account_kem_public_key BLOB NOT NULL CHECK (typeof(account_kem_public_key) = 'blob' AND length(account_kem_public_key) = 32),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id) ON DELETE CASCADE
);

CREATE TRIGGER account_password_bootstrap_owner
BEFORE INSERT ON account_password_bootstrap
WHEN NOT EXISTS (
    SELECT 1 FROM identity_accounts WHERE account_id = NEW.account_id AND password_owned = 1
) OR EXISTS (SELECT 1 FROM account_password_bootstrap WHERE account_id = NEW.account_id)
BEGIN
    SELECT RAISE(ABORT, 'Account password bootstrap cannot be attached or replaced');
END;

CREATE TRIGGER account_password_bootstrap_immutable
BEFORE UPDATE ON account_password_bootstrap
WHEN NEW.account_id IS NOT OLD.account_id OR NEW.origin IS NOT OLD.origin
    OR NEW.username IS NOT OLD.username OR NEW.credential_generation IS NOT OLD.credential_generation
    OR NEW.password_profile IS NOT OLD.password_profile OR NEW.password_salt IS NOT OLD.password_salt
    OR NEW.verifier IS NOT OLD.verifier OR NEW.password_ark IS NOT OLD.password_ark
    OR NEW.personal_vault_id IS NOT OLD.personal_vault_id
    OR NEW.account_signing_public_key IS NOT OLD.account_signing_public_key
    OR NEW.account_kem_public_key IS NOT OLD.account_kem_public_key
BEGIN
    SELECT RAISE(ABORT, 'Account password bootstrap is immutable');
END;

CREATE TRIGGER account_password_bootstrap_delete
BEFORE DELETE ON account_password_bootstrap
WHEN EXISTS (SELECT 1 FROM identity_accounts WHERE account_id = OLD.account_id)
BEGIN
    SELECT RAISE(ABORT, 'Account password bootstrap requires Account deletion');
END;
