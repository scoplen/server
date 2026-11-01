-- SPDX-License-Identifier: AGPL-3.0-only

-- Team changes share one complete unsigned revision; dissolved teams retain their audit.
ALTER TABLE organizations ADD COLUMN dissolved_at_ms BIGINT CHECK (dissolved_at_ms > 0);
ALTER TABLE organizations ADD COLUMN view_revision BYTEA NOT NULL DEFAULT decode('0000000000000001','hex') CHECK (octet_length(view_revision)=8 AND view_revision<>decode('0000000000000000','hex'));

CREATE TABLE organization_invitations (
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    recipient_account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(recipient_account_id)=16),
    recipient_username TEXT NOT NULL CHECK (octet_length(recipient_username) BETWEEN 3 AND 64),
    issuer_account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(issuer_account_id)=16),
    roles_json TEXT NOT NULL CHECK (octet_length(roles_json) BETWEEN 1 AND 4096),
    password_verifier BYTEA NOT NULL CHECK (octet_length(password_verifier)=32),
    status TEXT NOT NULL CHECK (status IN ('pending','accepted','revoked','locked')),
    wrong_passwords BIGINT NOT NULL DEFAULT 0 CHECK (wrong_passwords BETWEEN 0 AND 5),
    membership_id BYTEA REFERENCES organization_memberships(id) CHECK (membership_id IS NULL OR (octet_length(membership_id)=16)),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms>=created_at_ms),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (organization_id,id),
    CHECK ((status='accepted' AND membership_id IS NOT NULL) OR (status<>'accepted' AND membership_id IS NULL)),
    CHECK (status<>'locked' OR wrong_passwords=5)
);

-- Historical confirmation is Account-bound and never supplies current membership authority.
CREATE TABLE organization_operation_receipts (
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key)=16),
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    operation BIGINT NOT NULL CHECK (operation BETWEEN 1 AND 3),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    invitation_id BYTEA CHECK (invitation_id IS NULL OR (octet_length(invitation_id)=16)),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json)<=1024),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (account_id,idempotency_key),
    CHECK ((operation=1 AND invitation_id IS NOT NULL AND octet_length(response_json)=0) OR (operation IN (2,3) AND octet_length(response_json)>0))
);
CREATE INDEX organization_operation_receipts_expiry ON organization_operation_receipts (expires_at_ms);

-- Extend the namespace without touching retained debt or capacity accounting.
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 11);
