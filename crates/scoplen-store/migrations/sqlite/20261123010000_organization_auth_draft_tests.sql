-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE organization_auth_draft_tests (
    id BLOB NOT NULL PRIMARY KEY CHECK (typeof(id)='blob' AND length(id)=16 AND substr(hex(id),13,1)='7' AND substr(hex(id),17,1) IN ('8','9','A','B')),
    generation BLOB NOT NULL REFERENCES organization_auth_drafts(generation) ON DELETE CASCADE,
    family_id BLOB NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE,
    state_digest BLOB NOT NULL CHECK (typeof(state_digest)='blob' AND length(state_digest)=32),
    browser_digest BLOB NOT NULL CHECK (typeof(browser_digest)='blob' AND length(browser_digest)=32),
    nonce_digest BLOB NOT NULL CHECK (typeof(nonce_digest)='blob' AND length(nonce_digest)=32),
    trust_fingerprint BLOB NOT NULL CHECK (typeof(trust_fingerprint)='blob' AND length(trust_fingerprint)=32),
    provider TEXT NOT NULL CHECK (typeof(provider)='text' AND length(CAST(provider AS BLOB)) BETWEEN 1 AND 65536),
    phase TEXT NOT NULL CHECK (phase IN ('pending','claimed','verified','failed')),
    credentials BLOB,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300499999),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms=created_at_ms+300000),
    CHECK ((phase='pending' AND typeof(credentials)='blob' AND length(credentials) BETWEEN 146 AND 4241)
        OR (phase<>'pending' AND credentials IS NULL))
);
CREATE UNIQUE INDEX organization_auth_draft_tests_state ON organization_auth_draft_tests (state_digest);
CREATE UNIQUE INDEX organization_auth_draft_tests_live_family ON organization_auth_draft_tests (family_id) WHERE phase IN ('pending','claimed');
CREATE INDEX organization_auth_draft_tests_family ON organization_auth_draft_tests (family_id);
CREATE INDEX organization_auth_draft_tests_generation ON organization_auth_draft_tests (generation);
CREATE INDEX organization_auth_draft_tests_expiry ON organization_auth_draft_tests (expires_at_ms,id);
