-- SPDX-License-Identifier: AGPL-3.0-only

-- Team identity remains independent of the Account's Personal vault and enrolled Devices.
CREATE TABLE organization_memberships (
    id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(id)=16),
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    status TEXT NOT NULL CHECK (status IN ('active','suspended','deprovisioned')),
    roles_json TEXT NOT NULL CHECK (octet_length(roles_json) BETWEEN 1 AND 4096),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms),
    UNIQUE (organization_id, account_id)
);
CREATE INDEX organization_memberships_account ON organization_memberships (account_id, organization_id);

-- This narrow receipt is for POST /api/v1/orgs only and expires after 24 hours.
CREATE TABLE organization_creation_receipts (
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key)=16),
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (account_id, idempotency_key)
);
CREATE INDEX organization_creation_receipts_expiry ON organization_creation_receipts (expires_at_ms);
