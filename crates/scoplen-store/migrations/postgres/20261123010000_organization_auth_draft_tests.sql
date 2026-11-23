-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE organization_auth_draft_tests (
    id BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(id)=16 AND get_byte(id,6) >> 4 = 7 AND (get_byte(id,8) & 192) = 128),
    generation BYTEA NOT NULL REFERENCES organization_auth_drafts(generation) ON DELETE CASCADE,
    family_id BYTEA NOT NULL REFERENCES account_browser_families(family_id) ON DELETE CASCADE,
    state_digest BYTEA NOT NULL CHECK (octet_length(state_digest)=32),
    browser_digest BYTEA NOT NULL CHECK (octet_length(browser_digest)=32),
    nonce_digest BYTEA NOT NULL CHECK (octet_length(nonce_digest)=32),
    trust_fingerprint BYTEA NOT NULL CHECK (octet_length(trust_fingerprint)=32),
    provider TEXT NOT NULL CHECK (octet_length(provider) BETWEEN 1 AND 65536),
    phase TEXT NOT NULL CHECK (phase IN ('pending','claimed','verified','failed')),
    credentials BYTEA,
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300499999),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms=created_at_ms+300000),
    CHECK ((phase='pending' AND credentials IS NOT NULL AND octet_length(credentials) BETWEEN 146 AND 4241)
        OR (phase<>'pending' AND credentials IS NULL))
);
CREATE UNIQUE INDEX organization_auth_draft_tests_state ON organization_auth_draft_tests (state_digest);
CREATE UNIQUE INDEX organization_auth_draft_tests_live_family ON organization_auth_draft_tests (family_id) WHERE phase IN ('pending','claimed');
CREATE INDEX organization_auth_draft_tests_family ON organization_auth_draft_tests (family_id);
CREATE INDEX organization_auth_draft_tests_generation ON organization_auth_draft_tests (generation);
CREATE INDEX organization_auth_draft_tests_expiry ON organization_auth_draft_tests (expires_at_ms,id);
