-- SPDX-License-Identifier: AGPL-3.0-only

-- Team changes share one complete unsigned revision; dissolved teams retain their audit.
ALTER TABLE organizations ADD COLUMN dissolved_at_ms INTEGER CHECK (dissolved_at_ms > 0);
ALTER TABLE organizations ADD COLUMN view_revision BLOB NOT NULL DEFAULT X'0000000000000001' CHECK (typeof(view_revision)='blob' AND length(view_revision)=8 AND view_revision<>X'0000000000000000');

CREATE TABLE organization_invitations (
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (typeof(organization_id)='blob' AND length(organization_id)=16),
    id BLOB NOT NULL CHECK (typeof(id)='blob' AND length(id)=16),
    recipient_account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(recipient_account_id)='blob' AND length(recipient_account_id)=16),
    recipient_username TEXT NOT NULL CHECK (length(CAST(recipient_username AS BLOB)) BETWEEN 3 AND 64),
    issuer_account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(issuer_account_id)='blob' AND length(issuer_account_id)=16),
    roles_json TEXT NOT NULL CHECK (length(CAST(roles_json AS BLOB)) BETWEEN 1 AND 4096),
    password_verifier BLOB NOT NULL CHECK (typeof(password_verifier)='blob' AND length(password_verifier)=32),
    status TEXT NOT NULL CHECK (status IN ('pending','accepted','revoked','locked')),
    wrong_passwords INTEGER NOT NULL DEFAULT 0 CHECK (wrong_passwords BETWEEN 0 AND 5),
    membership_id BLOB REFERENCES organization_memberships(id) CHECK (membership_id IS NULL OR (typeof(membership_id)='blob' AND length(membership_id)=16)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms>=created_at_ms),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (organization_id,id),
    CHECK ((status='accepted' AND membership_id IS NOT NULL) OR (status<>'accepted' AND membership_id IS NULL)),
    CHECK (status<>'locked' OR wrong_passwords=5)
);

-- Historical confirmation is Account-bound and never supplies current membership authority.
CREATE TABLE organization_operation_receipts (
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(account_id)='blob' AND length(account_id)=16),
    idempotency_key BLOB NOT NULL CHECK (typeof(idempotency_key)='blob' AND length(idempotency_key)=16),
    organization_id BLOB NOT NULL REFERENCES organizations(id) CHECK (typeof(organization_id)='blob' AND length(organization_id)=16),
    operation INTEGER NOT NULL CHECK (operation BETWEEN 1 AND 3),
    request_digest BLOB NOT NULL CHECK (typeof(request_digest)='blob' AND length(request_digest)=32),
    invitation_id BLOB CHECK (invitation_id IS NULL OR (typeof(invitation_id)='blob' AND length(invitation_id)=16)),
    response_json BLOB NOT NULL CHECK (typeof(response_json)='blob' AND length(response_json)<=1024),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms BETWEEN 1 AND 9223372036768375807),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=created_at_ms+86400000),
    PRIMARY KEY (account_id,idempotency_key),
    CHECK ((operation=1 AND invitation_id IS NOT NULL AND length(response_json)=0) OR (operation IN (2,3) AND length(response_json)>0))
);
CREATE INDEX organization_operation_receipts_expiry ON organization_operation_receipts (expires_at_ms);

-- Preserve every existing admission row and the singleton's capacity/debt accounting.
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 11),
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
