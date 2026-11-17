-- SPDX-License-Identifier: AGPL-3.0-only

-- Retain used Grant identifiers and original fields after private withdrawal.
-- Composite references prevent cross-Organization Membership or Host ownership.
CREATE TABLE organization_grants (
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    membership_id BYTEA NOT NULL CHECK (octet_length(membership_id)=16),
    host_id BYTEA NOT NULL CHECK (octet_length(host_id)=16),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 4096),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms),
    withdrawn_at_ms BIGINT CHECK (withdrawn_at_ms>0),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,membership_id) REFERENCES organization_memberships(organization_id,id),
    FOREIGN KEY (organization_id,host_id) REFERENCES organization_inventory_objects(organization_id,object_id)
);
CREATE UNIQUE INDEX organization_grants_id ON organization_grants (id);
CREATE INDEX organization_grants_directory ON organization_grants (organization_id,withdrawn_at_ms,id);
CREATE INDEX organization_grants_membership_host ON organization_grants (organization_id,membership_id,host_id,withdrawn_at_ms);
CREATE INDEX organization_grants_host ON organization_grants (organization_id,host_id,withdrawn_at_ms);

-- Grant authoring has separate endpoint budgets without resetting existing admission debt.
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 45);
