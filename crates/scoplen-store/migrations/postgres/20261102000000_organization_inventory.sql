-- SPDX-License-Identifier: AGPL-3.0-only

-- Organization inventory has an immutable tenant owner and no client-held vault key.
CREATE TABLE organization_inventory_vaults (
    organization_id BYTEA PRIMARY KEY NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    vault_id BYTEA UNIQUE NOT NULL REFERENCES sync_vaults(vault_id) CHECK (octet_length(vault_id)=16),
    UNIQUE (organization_id,vault_id)
);

-- Existing teams had no inventory. Their server-generated Organization identifier is also
-- the initial vault identifier; the mapping remains explicit and immutable.
INSERT INTO sync_vaults (vault_id,kind) SELECT id,'organization' FROM organizations;
INSERT INTO organization_inventory_vaults (organization_id,vault_id) SELECT id,id FROM organizations;

CREATE TABLE organization_inventory_objects (
    organization_id BYTEA NOT NULL,
    vault_id BYTEA NOT NULL,
    object_id BYTEA NOT NULL CHECK (octet_length(object_id)=16),
    object_type BIGINT NOT NULL CHECK (object_type IN (1,2,4,5,6,7,11)),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 2097152),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms),
    PRIMARY KEY (organization_id,object_id),
    FOREIGN KEY (organization_id,vault_id) REFERENCES organization_inventory_vaults(organization_id,vault_id)
);
CREATE INDEX organization_inventory_directory ON organization_inventory_objects (organization_id,object_type,object_id);

CREATE TABLE organization_inventory_references (
    organization_id BYTEA NOT NULL,
    source_id BYTEA NOT NULL,
    target_id BYTEA NOT NULL,
    PRIMARY KEY (organization_id,source_id,target_id),
    FOREIGN KEY (organization_id,source_id) REFERENCES organization_inventory_objects(organization_id,object_id),
    FOREIGN KEY (organization_id,target_id) REFERENCES organization_inventory_objects(organization_id,object_id)
);
CREATE INDEX organization_inventory_incoming ON organization_inventory_references (organization_id,target_id);

CREATE TABLE organization_inventory_receipts (
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key)=16),
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 2097152),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (account_id,idempotency_key)
);
CREATE INDEX organization_inventory_receipts_expiry ON organization_inventory_receipts (expires_at_ms);

CREATE TABLE organization_inventory_acks (
    vault_id BYTEA NOT NULL REFERENCES organization_inventory_vaults(vault_id),
    device_id BYTEA NOT NULL REFERENCES identity_devices(device_id) ON DELETE CASCADE CHECK (octet_length(device_id)=16),
    view_revision BYTEA NOT NULL CHECK (octet_length(view_revision)=8 AND view_revision<>decode('0000000000000000','hex')),
    cursor BIGINT NOT NULL CHECK (cursor>=0),
    acknowledged_at_ms BIGINT NOT NULL CHECK (acknowledged_at_ms>0),
    PRIMARY KEY (vault_id,device_id)
);

CREATE UNIQUE INDEX organization_memberships_owner_id ON organization_memberships (organization_id,id);
CREATE TABLE organization_groups (
    organization_id BYTEA NOT NULL REFERENCES organizations(id),
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    source TEXT NOT NULL CHECK (source IN ('local','IdP')),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 262144),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms),
    deleted_at_ms BIGINT,
    PRIMARY KEY (organization_id,id)
);
CREATE TABLE organization_group_members (
    organization_id BYTEA NOT NULL,
    group_id BYTEA NOT NULL,
    membership_id BYTEA NOT NULL,
    PRIMARY KEY (organization_id,group_id,membership_id),
    FOREIGN KEY (organization_id,group_id) REFERENCES organization_groups(organization_id,id),
    FOREIGN KEY (organization_id,membership_id) REFERENCES organization_memberships(organization_id,id)
);
CREATE INDEX organization_group_members_membership ON organization_group_members (organization_id,membership_id);
CREATE TABLE organization_policies (
    organization_id BYTEA NOT NULL REFERENCES organizations(id),
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    source TEXT NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 65536),
    enabled BIGINT NOT NULL CHECK (enabled IN (0,1)),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 262144),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms),
    deleted_at_ms BIGINT,
    PRIMARY KEY (organization_id,id)
);

-- Extend authoring admission without resetting any existing debt.
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 38);
