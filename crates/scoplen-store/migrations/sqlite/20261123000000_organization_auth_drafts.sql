-- SPDX-License-Identifier: AGPL-3.0-only

-- The Organization row serializes the slot even before the first draft exists.
CREATE TABLE organization_auth_drafts (
    organization_id BLOB NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE CHECK (typeof(organization_id)='blob' AND length(organization_id)=16),
    generation BLOB NOT NULL CHECK (typeof(generation)='blob' AND length(generation)=16 AND substr(hex(generation),13,1)='7' AND substr(hex(generation),17,1) IN ('8','9','A','B')),
    issuer TEXT NOT NULL CHECK (typeof(issuer)='text' AND length(CAST(issuer AS BLOB)) BETWEEN 1 AND 2048),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300799999)
);
CREATE UNIQUE INDEX organization_auth_drafts_generation ON organization_auth_drafts (generation);

-- Expiry discards the result, retaining only the spent key in its original namespace.
-- A late original request must never create or cancel a subsequent generation.
CREATE TABLE organization_auth_draft_receipts (
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (typeof(account_id)='blob' AND length(account_id)=16),
    origin_digest BLOB NOT NULL CHECK (typeof(origin_digest)='blob' AND length(origin_digest)=32),
    idempotency_key BLOB NOT NULL CHECK (typeof(idempotency_key)='blob' AND length(idempotency_key)=16 AND substr(hex(idempotency_key),13,1)='7' AND substr(hex(idempotency_key),17,1) IN ('8','9','A','B')),
    request_digest BLOB,
    generation BLOB,
    created_at_ms INTEGER,
    expires_at_ms INTEGER,
    PRIMARY KEY (account_id,origin_digest,idempotency_key),
    CHECK ((request_digest IS NULL AND generation IS NULL AND created_at_ms IS NULL AND expires_at_ms IS NULL)
        OR (request_digest IS NOT NULL AND typeof(request_digest)='blob' AND length(request_digest)=32
            AND generation IS NOT NULL AND typeof(generation)='blob' AND length(generation)=16 AND substr(hex(generation),13,1)='7' AND substr(hex(generation),17,1) IN ('8','9','A','B')
            AND created_at_ms IS NOT NULL AND created_at_ms BETWEEN 1 AND 253402214399999
            AND expires_at_ms IS NOT NULL AND expires_at_ms=created_at_ms+86400000))
);
CREATE INDEX organization_auth_draft_receipts_expiry ON organization_auth_draft_receipts (expires_at_ms) WHERE expires_at_ms IS NOT NULL;

CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 52),
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
