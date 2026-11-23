-- SPDX-License-Identifier: AGPL-3.0-only

-- A link or its withdrawal advances the Membership generation without changing native roles.
ALTER TABLE organization_memberships ADD COLUMN auth_link_generation BIGINT NOT NULL DEFAULT 0 CHECK (auth_link_generation>=0);
CREATE UNIQUE INDEX organization_memberships_link_writer ON organization_memberships (organization_id,id,account_id);
CREATE UNIQUE INDEX account_browser_families_link_writer ON account_browser_families (family_id,account_id);

-- Subject comparisons are keyed and already include Organization, issuer, client and Space.
CREATE TABLE organization_auth_links (
    id BYTEA NOT NULL PRIMARY KEY CHECK (CASE WHEN octet_length(id)=16 THEN get_byte(id,6) >> 4 = 7 AND (get_byte(id,8) & 192) = 128 ELSE FALSE END),
    organization_id BYTEA NOT NULL,
    membership_id BYTEA NOT NULL,
    subject_comparison BYTEA NOT NULL CHECK (octet_length(subject_comparison)=32),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300799999),
    FOREIGN KEY (organization_id,membership_id) REFERENCES organization_memberships(organization_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX organization_auth_links_membership ON organization_auth_links (organization_id,membership_id);
CREATE UNIQUE INDEX organization_auth_links_subject ON organization_auth_links (organization_id,subject_comparison);

-- Bind the attempt to the writer's current Membership and original browser family.
-- A claimed, verified or failed attempt never retains its PKCE verifier.
CREATE TABLE organization_auth_link_attempts (
    id BYTEA NOT NULL PRIMARY KEY CHECK (CASE WHEN octet_length(id)=16 THEN get_byte(id,6) >> 4 = 7 AND (get_byte(id,8) & 192) = 128 ELSE FALSE END),
    organization_id BYTEA NOT NULL,
    membership_id BYTEA NOT NULL,
    account_id BYTEA NOT NULL,
    family_id BYTEA NOT NULL,
    connection_revision BYTEA NOT NULL CHECK (CASE WHEN octet_length(connection_revision)=16 THEN get_byte(connection_revision,6) >> 4 = 7 AND (get_byte(connection_revision,8) & 192) = 128 ELSE FALSE END),
    link_generation BIGINT NOT NULL CHECK (link_generation>=0),
    state_digest BYTEA NOT NULL CHECK (octet_length(state_digest)=32),
    browser_digest BYTEA NOT NULL CHECK (octet_length(browser_digest)=32),
    nonce_digest BYTEA NOT NULL CHECK (octet_length(nonce_digest)=32),
    phase TEXT NOT NULL CHECK (phase IN ('pending','claimed','verified','failed')),
    verifier BYTEA CHECK (verifier IS NULL OR (octet_length(verifier) BETWEEN 80 AND 8192)),
    subject_comparison BYTEA CHECK (subject_comparison IS NULL OR (octet_length(subject_comparison)=32)),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms BETWEEN 1 AND 253402300799999),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 1 AND 253402300799999 AND expires_at_ms>created_at_ms AND expires_at_ms<=created_at_ms+300000),
    FOREIGN KEY (organization_id,membership_id,account_id) REFERENCES organization_memberships(organization_id,id,account_id) ON DELETE CASCADE,
    FOREIGN KEY (family_id,account_id) REFERENCES account_browser_families(family_id,account_id) ON DELETE CASCADE,
    CHECK ((phase='pending' AND verifier IS NOT NULL AND subject_comparison IS NULL)
        OR (phase IN ('claimed','failed') AND verifier IS NULL AND subject_comparison IS NULL)
        OR (phase='verified' AND verifier IS NULL AND subject_comparison IS NOT NULL))
);
CREATE UNIQUE INDEX organization_auth_link_attempts_state ON organization_auth_link_attempts (state_digest);
CREATE UNIQUE INDEX organization_auth_link_attempts_family ON organization_auth_link_attempts (family_id);
CREATE INDEX organization_auth_link_attempts_expiry ON organization_auth_link_attempts (expires_at_ms,id);
CREATE INDEX organization_auth_link_attempts_membership ON organization_auth_link_attempts (organization_id,membership_id);
