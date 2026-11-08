-- SPDX-License-Identifier: AGPL-3.0-only

-- Initial active local user CA; the encrypted seed is bound to this immutable tenant and id.
CREATE TABLE organization_user_cas (
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (length(organization_id)=16),
    id BLOB NOT NULL CHECK (length(id)=16),
    encrypted_seed BLOB NOT NULL CHECK (length(encrypted_seed)=73),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 16384),
    last_serial BLOB NOT NULL CHECK (length(last_serial)=8),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id)
);

CREATE TABLE organization_user_certificates (
    organization_id BLOB NOT NULL,
    id BLOB NOT NULL CHECK (length(id)=16),
    authority_id BLOB NOT NULL,
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (length(account_id)=16),
    device_id BLOB NOT NULL REFERENCES identity_devices(device_id) ON DELETE CASCADE CHECK (length(device_id)=16),
    serial BLOB NOT NULL CHECK (length(serial)=8 AND serial<>X'0000000000000000'),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 131072),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,authority_id,serial),
    FOREIGN KEY (organization_id,authority_id) REFERENCES organization_user_cas(organization_id,id)
);

-- Admit CA creation and issuance independently without resetting existing source/Account debt.
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 40),
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
