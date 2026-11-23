-- SPDX-License-Identifier: AGPL-3.0-only

CREATE UNIQUE INDEX sync_vaults_id_kind ON sync_vaults(vault_id, kind);

CREATE TABLE organization_shared_vaults (
    vault_id BYTEA PRIMARY KEY NOT NULL,
    organization_id BYTEA NOT NULL REFERENCES organizations(id),
    kind TEXT NOT NULL DEFAULT 'shared' CHECK (kind = 'shared'),
    UNIQUE (organization_id, vault_id),
    FOREIGN KEY (vault_id, kind) REFERENCES sync_vaults(vault_id, kind) ON DELETE CASCADE
);

CREATE TABLE organization_shared_vault_recipients (
    vault_id BYTEA NOT NULL,
    organization_id BYTEA NOT NULL,
    membership_id BYTEA NOT NULL,
    account_id BYTEA NOT NULL,
    PRIMARY KEY (vault_id, account_id),
    FOREIGN KEY (organization_id, vault_id)
        REFERENCES organization_shared_vaults(organization_id, vault_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, membership_id, account_id)
        REFERENCES organization_memberships(organization_id, id, account_id),
    FOREIGN KEY (vault_id, account_id)
        REFERENCES sync_vault_members(vault_id, account_id) ON DELETE CASCADE
);

CREATE INDEX organization_shared_vault_recipients_membership
    ON organization_shared_vault_recipients(organization_id, membership_id);
