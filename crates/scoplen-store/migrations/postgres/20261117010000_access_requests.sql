-- SPDX-License-Identifier: AGPL-3.0-only

-- Immutable original request attribution and persisted terminal history.
-- A Host tombstone retains its inventory row; only pending requests block deletion.
CREATE TABLE organization_access_requests (
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    requester_account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(requester_account_id)=16),
    requester_membership_id BYTEA NOT NULL CHECK (octet_length(requester_membership_id)=16),
    host_id BYTEA NOT NULL CHECK (octet_length(host_id)=16),
    status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','cancelled')),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 8192),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402214399999),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms AND updated_at_ms<=253402300799999),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (organization_id,id),
    FOREIGN KEY (organization_id,requester_membership_id) REFERENCES organization_memberships(organization_id,id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id,host_id) REFERENCES organization_inventory_objects(organization_id,object_id)
);
CREATE UNIQUE INDEX organization_access_requests_id ON organization_access_requests (id);
CREATE INDEX organization_access_requests_mine ON organization_access_requests (organization_id,requester_account_id,id);
CREATE INDEX organization_access_requests_approvals ON organization_access_requests (organization_id,status,expires_at_ms,id);
CREATE INDEX organization_access_requests_expiry ON organization_access_requests (status,expires_at_ms,organization_id,id);
CREATE INDEX organization_access_requests_host ON organization_access_requests (organization_id,host_id,status);

-- Request check and mutations have separate budgets, preserving all existing admission debt.
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 49);
