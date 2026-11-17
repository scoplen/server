-- SPDX-License-Identifier: AGPL-3.0-only

-- Retain used Grant identifiers and original fields after private withdrawal.
-- Composite references prevent cross-Organization Membership or Host ownership.
CREATE TABLE organization_grants (
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (length(organization_id)=16),
    id BLOB NOT NULL CHECK (length(id)=16),
    membership_id BLOB NOT NULL CHECK (length(membership_id)=16),
    host_id BLOB NOT NULL CHECK (length(host_id)=16),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=created_at_ms),
    withdrawn_at_ms INTEGER CHECK (withdrawn_at_ms>0),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,membership_id) REFERENCES organization_memberships(organization_id,id),
    FOREIGN KEY (organization_id,host_id) REFERENCES organization_inventory_objects(organization_id,object_id)
);
CREATE UNIQUE INDEX organization_grants_id ON organization_grants (id);
CREATE INDEX organization_grants_directory ON organization_grants (organization_id,withdrawn_at_ms,id);
CREATE INDEX organization_grants_membership_host ON organization_grants (organization_id,membership_id,host_id,withdrawn_at_ms);
CREATE INDEX organization_grants_host ON organization_grants (organization_id,host_id,withdrawn_at_ms);

-- Grant authoring has separate endpoint budgets without resetting existing admission debt.
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 45),
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
