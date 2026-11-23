-- SPDX-License-Identifier: AGPL-3.0-only

-- Installed credentials belong to the active revision. A suspended head retains only public metadata.
CREATE TABLE organization_auth_connections (
    organization_id BLOB NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    revision BLOB NOT NULL CHECK (typeof(revision)='blob' AND length(revision)=16 AND substr(hex(revision),13,1)='7' AND substr(hex(revision),17,1) IN ('8','9','A','B')),
    status TEXT NOT NULL CHECK (status IN ('active','suspended')),
    issuer TEXT NOT NULL CHECK (typeof(issuer)='text' AND length(CAST(issuer AS BLOB)) BETWEEN 1 AND 2048),
    client_id TEXT NOT NULL CHECK (typeof(client_id)='text' AND length(CAST(client_id AS BLOB)) BETWEEN 1 AND 512),
    space_id TEXT NOT NULL CHECK (typeof(space_id)='text' AND length(space_id) BETWEEN 5 AND 96 AND length(CAST(space_id AS BLOB))=length(space_id) AND substr(space_id,1,4)='spc_' AND substr(space_id,5) NOT GLOB '*[^A-Za-z0-9_-]*'),
    provider TEXT,
    trust_fingerprint BLOB,
    credential BLOB,
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms)='integer' AND created_at_ms BETWEEN 1 AND 253402300799999),
    CHECK ((status='active' AND provider IS NOT NULL AND typeof(provider)='text' AND length(CAST(provider AS BLOB)) BETWEEN 1 AND 65536
            AND trust_fingerprint IS NOT NULL AND typeof(trust_fingerprint)='blob' AND length(trust_fingerprint)=32
            AND credential IS NOT NULL AND typeof(credential)='blob' AND length(credential) BETWEEN 80 AND 8192)
        OR (status='suspended' AND provider IS NULL AND trust_fingerprint IS NULL AND credential IS NULL))
);
CREATE UNIQUE INDEX organization_auth_connections_revision ON organization_auth_connections (revision);

-- Each candidate captures the draft's owner, while expected_revision may outlive a superseded head.
CREATE UNIQUE INDEX organization_auth_drafts_owner_generation ON organization_auth_drafts (organization_id,generation);
CREATE TABLE organization_auth_connection_activations (
    id BLOB NOT NULL PRIMARY KEY CHECK (typeof(id)='blob' AND length(id)=16 AND substr(hex(id),13,1)='7' AND substr(hex(id),17,1) IN ('8','9','A','B')),
    organization_id BLOB NOT NULL,
    draft_generation BLOB NOT NULL,
    expected_revision BLOB CHECK (expected_revision IS NULL OR (typeof(expected_revision)='blob' AND length(expected_revision)=16 AND substr(hex(expected_revision),13,1)='7' AND substr(hex(expected_revision),17,1) IN ('8','9','A','B'))),
    family_id BLOB NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE,
    state_digest BLOB NOT NULL CHECK (typeof(state_digest)='blob' AND length(state_digest)=32),
    browser_digest BLOB NOT NULL CHECK (typeof(browser_digest)='blob' AND length(browser_digest)=32),
    nonce_digest BLOB NOT NULL CHECK (typeof(nonce_digest)='blob' AND length(nonce_digest)=32),
    trust_fingerprint BLOB NOT NULL CHECK (typeof(trust_fingerprint)='blob' AND length(trust_fingerprint)=32),
    issuer TEXT NOT NULL CHECK (typeof(issuer)='text' AND length(CAST(issuer AS BLOB)) BETWEEN 1 AND 2048),
    client_id TEXT NOT NULL CHECK (typeof(client_id)='text' AND length(CAST(client_id AS BLOB)) BETWEEN 1 AND 512),
    space_id TEXT NOT NULL CHECK (typeof(space_id)='text' AND length(space_id) BETWEEN 5 AND 96 AND length(CAST(space_id AS BLOB))=length(space_id) AND substr(space_id,1,4)='spc_' AND substr(space_id,5) NOT GLOB '*[^A-Za-z0-9_-]*'),
    provider TEXT NOT NULL CHECK (typeof(provider)='text' AND length(CAST(provider AS BLOB)) BETWEEN 1 AND 65536),
    phase TEXT NOT NULL CHECK (phase IN ('pending','claimed','verified','failed')),
    credential BLOB CHECK (credential IS NULL OR (typeof(credential)='blob' AND length(credential) BETWEEN 80 AND 8192)),
    verifier BLOB CHECK (verifier IS NULL OR (typeof(verifier)='blob' AND length(verifier) BETWEEN 80 AND 8192)),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms)='integer' AND created_at_ms BETWEEN 1 AND 253402300799999),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms)='integer' AND expires_at_ms BETWEEN 1 AND 253402300799999 AND expires_at_ms>created_at_ms AND expires_at_ms<=created_at_ms+300000),
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
    account_id BLOB NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE,
    origin_digest BLOB NOT NULL CHECK (typeof(origin_digest)='blob' AND length(origin_digest)=32),
    idempotency_key BLOB NOT NULL CHECK (typeof(idempotency_key)='blob' AND length(idempotency_key)=16 AND substr(hex(idempotency_key),13,1)='7' AND substr(hex(idempotency_key),17,1) IN ('8','9','A','B')),
    request_digest BLOB,
    response_json BLOB,
    created_at_ms INTEGER,
    expires_at_ms INTEGER,
    PRIMARY KEY (account_id,origin_digest,idempotency_key),
    CHECK ((request_digest IS NULL AND response_json IS NULL AND created_at_ms IS NULL AND expires_at_ms IS NULL)
        OR (request_digest IS NOT NULL AND typeof(request_digest)='blob' AND length(request_digest)=32
            AND response_json IS NOT NULL AND typeof(response_json)='blob' AND length(response_json) BETWEEN 1 AND 8192
            AND created_at_ms IS NOT NULL AND typeof(created_at_ms)='integer' AND created_at_ms BETWEEN 1 AND 253402214399999
            AND expires_at_ms IS NOT NULL AND typeof(expires_at_ms)='integer' AND expires_at_ms=created_at_ms+86400000))
);
CREATE INDEX organization_auth_connection_receipts_expiry ON organization_auth_connection_receipts (expires_at_ms) WHERE expires_at_ms IS NOT NULL;

-- Preserve all existing admission buckets while admitting the four independent mutation endpoints.
CREATE TABLE account_entry_admission_next (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 57),
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
