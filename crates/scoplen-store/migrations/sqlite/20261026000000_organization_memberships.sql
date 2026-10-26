-- SPDX-License-Identifier: AGPL-3.0-only

-- Team identity remains independent of the Account's Personal vault and enrolled Devices.
CREATE TABLE organization_memberships (
    id BLOB PRIMARY KEY NOT NULL CHECK (typeof(id)='blob' AND length(id)=16),
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (typeof(organization_id)='blob' AND length(organization_id)=16),
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(account_id)='blob' AND length(account_id)=16),
    status TEXT NOT NULL CHECK (status IN ('active','suspended','deprovisioned')),
    roles_json TEXT NOT NULL CHECK (length(CAST(roles_json AS BLOB)) BETWEEN 1 AND 4096),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms>0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=created_at_ms),
    UNIQUE (organization_id, account_id)
);
CREATE INDEX organization_memberships_account ON organization_memberships (account_id, organization_id);

-- This narrow receipt is for POST /api/v1/orgs only and expires after 24 hours.
CREATE TABLE organization_creation_receipts (
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(account_id)='blob' AND length(account_id)=16),
    idempotency_key BLOB NOT NULL CHECK (typeof(idempotency_key)='blob' AND length(idempotency_key)=16),
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (typeof(organization_id)='blob' AND length(organization_id)=16),
    request_digest BLOB NOT NULL CHECK (typeof(request_digest)='blob' AND length(request_digest)=32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (account_id, idempotency_key)
);
CREATE INDEX organization_creation_receipts_expiry ON organization_creation_receipts (expires_at_ms);
