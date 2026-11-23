-- SPDX-License-Identifier: AGPL-3.0-only

-- Installed credentials belong to the active revision. A suspended head retains only public metadata.
CREATE TABLE organization_auth_connections (
    organization_id BYTEA NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    revision BYTEA NOT NULL CHECK (octet_length(revision)=16 AND get_byte(revision,6) >> 4 = 7 AND (get_byte(revision,8) & 192) = 128),
    status TEXT NOT NULL CHECK (status IN ('active','suspended')),
    issuer TEXT NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    client_id TEXT NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 512),
    space_id TEXT NOT NULL CHECK (space_id COLLATE "C" ~ '^spc_[A-Za-z0-9_-]{1,92}$'),
    provider TEXT,
    trust_fingerprint BYTEA,
    credential BYTEA,
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300799999),
    CHECK ((status='active' AND provider IS NOT NULL AND octet_length(provider) BETWEEN 1 AND 65536
            AND trust_fingerprint IS NOT NULL AND octet_length(trust_fingerprint)=32
            AND credential IS NOT NULL AND octet_length(credential) BETWEEN 80 AND 8192)
        OR (status='suspended' AND provider IS NULL AND trust_fingerprint IS NULL AND credential IS NULL))
);
CREATE UNIQUE INDEX organization_auth_connections_revision ON organization_auth_connections (revision);

-- Each candidate captures the draft's owner, while expected_revision may outlive a superseded head.
CREATE UNIQUE INDEX organization_auth_drafts_owner_generation ON organization_auth_drafts (organization_id,generation);
CREATE TABLE organization_auth_connection_activations (
    id BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(id)=16 AND get_byte(id,6) >> 4 = 7 AND (get_byte(id,8) & 192) = 128),
    organization_id BYTEA NOT NULL,
    draft_generation BYTEA NOT NULL,
    expected_revision BYTEA CHECK (expected_revision IS NULL OR (octet_length(expected_revision)=16 AND get_byte(expected_revision,6) >> 4 = 7 AND (get_byte(expected_revision,8) & 192) = 128)),
    family_id BYTEA NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE,
    state_digest BYTEA NOT NULL CHECK (octet_length(state_digest)=32),
    browser_digest BYTEA NOT NULL CHECK (octet_length(browser_digest)=32),
    nonce_digest BYTEA NOT NULL CHECK (octet_length(nonce_digest)=32),
    trust_fingerprint BYTEA NOT NULL CHECK (octet_length(trust_fingerprint)=32),
    issuer TEXT NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    client_id TEXT NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 512),
    space_id TEXT NOT NULL CHECK (space_id COLLATE "C" ~ '^spc_[A-Za-z0-9_-]{1,92}$'),
    provider TEXT NOT NULL CHECK (octet_length(provider) BETWEEN 1 AND 65536),
    phase TEXT NOT NULL CHECK (phase IN ('pending','claimed','verified','failed')),
    credential BYTEA CHECK (credential IS NULL OR (octet_length(credential) BETWEEN 80 AND 8192)),
    verifier BYTEA CHECK (verifier IS NULL OR (octet_length(verifier) BETWEEN 80 AND 8192)),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300799999),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 1 AND 253402300799999 AND expires_at_ms>created_at_ms AND expires_at_ms<=created_at_ms+300000),
    FOREIGN KEY (organization_id,draft_generation) REFERENCES organization_auth_drafts(organization_id,generation) ON DELETE CASCADE,
    CHECK ((phase='pending' AND credential IS NOT NULL AND verifier IS NOT NULL)
        OR (phase IN ('claimed','verified') AND credential IS NOT NULL AND verifier IS NULL)
        OR (phase='failed' AND credential IS NULL AND verifier IS NULL))
);
CREATE UNIQUE INDEX organization_auth_connection_activations_state ON organization_auth_connection_activations (state_digest);
CREATE UNIQUE INDEX organization_auth_connection_activations_family ON organization_auth_connection_activations (family_id);
CREATE INDEX organization_auth_connection_activations_expiry ON organization_auth_connection_activations (expires_at_ms,id);
CREATE INDEX organization_auth_connection_activations_draft ON organization_auth_connection_activations (organization_id,draft_generation);

-- Expired receipts shed their public result while preventing reuse of the spent key.
CREATE TABLE organization_auth_connection_receipts (
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE,
    origin_digest BYTEA NOT NULL CHECK (octet_length(origin_digest)=32),
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key)=16 AND get_byte(idempotency_key,6) >> 4 = 7 AND (get_byte(idempotency_key,8) & 192) = 128),
    request_digest BYTEA,
    response_json BYTEA,
    created_at_ms BIGINT,
    expires_at_ms BIGINT,
    PRIMARY KEY (account_id,origin_digest,idempotency_key),
    CHECK ((request_digest IS NULL AND response_json IS NULL AND created_at_ms IS NULL AND expires_at_ms IS NULL)
        OR (request_digest IS NOT NULL AND octet_length(request_digest)=32
            AND response_json IS NOT NULL AND octet_length(response_json) BETWEEN 1 AND 8192
            AND created_at_ms IS NOT NULL AND created_at_ms BETWEEN 1 AND 253402214399999
            AND expires_at_ms IS NOT NULL AND expires_at_ms=created_at_ms+86400000))
);
CREATE INDEX organization_auth_connection_receipts_expiry ON organization_auth_connection_receipts (expires_at_ms) WHERE expires_at_ms IS NOT NULL;

-- Preserve all existing admission buckets while admitting the four independent mutation endpoints.
ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 57);
