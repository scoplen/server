-- SPDX-License-Identifier: AGPL-3.0-only

-- The Organization row serializes the slot even before the first draft exists.
CREATE TABLE organization_auth_drafts (
    organization_id BYTEA NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE CHECK (octet_length(organization_id)=16),
    generation BYTEA NOT NULL CHECK (octet_length(generation)=16 AND get_byte(generation,6) >> 4 = 7 AND (get_byte(generation,8) & 192) = 128),
    issuer TEXT NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300799999)
);
CREATE UNIQUE INDEX organization_auth_drafts_generation ON organization_auth_drafts (generation);

-- Expiry discards the result, retaining only the spent key in its original namespace.
-- A late original request must never create or cancel a subsequent generation.
CREATE TABLE organization_auth_draft_receipts (
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    origin_digest BYTEA NOT NULL CHECK (octet_length(origin_digest)=32),
    idempotency_key BYTEA NOT NULL CHECK (octet_length(idempotency_key)=16 AND get_byte(idempotency_key,6) >> 4 = 7 AND (get_byte(idempotency_key,8) & 192) = 128),
    request_digest BYTEA,
    generation BYTEA,
    created_at_ms BIGINT,
    expires_at_ms BIGINT,
    PRIMARY KEY (account_id,origin_digest,idempotency_key),
    CHECK ((request_digest IS NULL AND generation IS NULL AND created_at_ms IS NULL AND expires_at_ms IS NULL)
        OR (request_digest IS NOT NULL AND octet_length(request_digest)=32
            AND generation IS NOT NULL AND octet_length(generation)=16 AND get_byte(generation,6) >> 4 = 7 AND (get_byte(generation,8) & 192) = 128
            AND created_at_ms IS NOT NULL AND created_at_ms BETWEEN 1 AND 253402214399999
            AND expires_at_ms IS NOT NULL AND expires_at_ms=created_at_ms+86400000))
);
CREATE INDEX organization_auth_draft_receipts_expiry ON organization_auth_draft_receipts (expires_at_ms) WHERE expires_at_ms IS NOT NULL;

ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 52);
