-- SPDX-License-Identifier: AGPL-3.0-only

-- Organization inventory has an immutable tenant owner and no client-held vault key.
CREATE TABLE organization_inventory_vaults (
    organization_id BLOB PRIMARY KEY NOT NULL REFERENCES organizations(id) CHECK (length(organization_id)=16),
    vault_id BLOB UNIQUE NOT NULL REFERENCES sync_vaults(vault_id) CHECK (length(vault_id)=16),
    UNIQUE (organization_id,vault_id)
);

-- Existing teams had no inventory. Their server-generated Organization identifier is also
-- the initial vault identifier; the mapping remains explicit and immutable.
INSERT INTO sync_vaults (vault_id,kind) SELECT id,'organization' FROM organizations;
INSERT INTO organization_inventory_vaults (organization_id,vault_id) SELECT id,id FROM organizations;

CREATE TABLE organization_inventory_objects (
    organization_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    object_id BLOB NOT NULL CHECK (length(object_id)=16),
    object_type INTEGER NOT NULL CHECK (object_type IN (1,2,4,5,6,7,11)),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 2097152),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=created_at_ms),
    PRIMARY KEY (organization_id,object_id),
    FOREIGN KEY (organization_id,vault_id) REFERENCES organization_inventory_vaults(organization_id,vault_id)
);
CREATE INDEX organization_inventory_directory ON organization_inventory_objects (organization_id,object_type,object_id);

CREATE TABLE organization_inventory_references (
    organization_id BLOB NOT NULL,
    source_id BLOB NOT NULL,
    target_id BLOB NOT NULL,
    PRIMARY KEY (organization_id,source_id,target_id),
    FOREIGN KEY (organization_id,source_id) REFERENCES organization_inventory_objects(organization_id,object_id),
    FOREIGN KEY (organization_id,target_id) REFERENCES organization_inventory_objects(organization_id,object_id)
);
CREATE INDEX organization_inventory_incoming ON organization_inventory_references (organization_id,target_id);

CREATE TABLE organization_inventory_receipts (
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (length(account_id)=16),
    idempotency_key BLOB NOT NULL CHECK (length(idempotency_key)=16),
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (length(organization_id)=16),
    request_digest BLOB NOT NULL CHECK (length(request_digest)=32),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 2097152),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (account_id,idempotency_key)
);
CREATE INDEX organization_inventory_receipts_expiry ON organization_inventory_receipts (expires_at_ms);

CREATE TABLE organization_inventory_acks (
    vault_id BLOB NOT NULL REFERENCES organization_inventory_vaults(vault_id),
    device_id BLOB NOT NULL REFERENCES identity_devices(device_id) ON DELETE CASCADE CHECK (length(device_id)=16),
    view_revision BLOB NOT NULL CHECK (length(view_revision)=8 AND view_revision<>X'0000000000000000'),
    cursor INTEGER NOT NULL CHECK (cursor>=0),
    acknowledged_at_ms INTEGER NOT NULL CHECK (acknowledged_at_ms>0),
    PRIMARY KEY (vault_id,device_id)
);

CREATE UNIQUE INDEX organization_memberships_owner_id ON organization_memberships (organization_id,id);
CREATE TABLE organization_groups (
    organization_id BLOB NOT NULL REFERENCES organizations(id),
    id BLOB NOT NULL CHECK (length(id)=16),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 128),
    source TEXT NOT NULL CHECK (source IN ('local','IdP')),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 262144),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=created_at_ms),
    deleted_at_ms INTEGER,
    PRIMARY KEY (organization_id,id)
);
CREATE TABLE organization_group_members (
    organization_id BLOB NOT NULL,
    group_id BLOB NOT NULL,
    membership_id BLOB NOT NULL,
    PRIMARY KEY (organization_id,group_id,membership_id),
    FOREIGN KEY (organization_id,group_id) REFERENCES organization_groups(organization_id,id),
    FOREIGN KEY (organization_id,membership_id) REFERENCES organization_memberships(organization_id,id)
);
CREATE INDEX organization_group_members_membership ON organization_group_members (organization_id,membership_id);
CREATE TABLE organization_policies (
    organization_id BLOB NOT NULL REFERENCES organizations(id),
    id BLOB NOT NULL CHECK (length(id)=16),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 128),
    source TEXT NOT NULL CHECK (length(CAST(source AS BLOB)) BETWEEN 1 AND 65536),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    response_json BLOB NOT NULL CHECK (length(response_json) BETWEEN 1 AND 262144),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=created_at_ms),
    deleted_at_ms INTEGER,
    PRIMARY KEY (organization_id,id)
);

-- Preserve every existing admission row and the singleton's capacity/debt accounting.
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 38),
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
