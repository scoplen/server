-- SPDX-License-Identifier: AGPL-3.0-only

-- A link or its withdrawal advances the Membership generation without changing native roles.
ALTER TABLE organization_memberships ADD COLUMN auth_link_generation INTEGER NOT NULL DEFAULT 0 CHECK (typeof(auth_link_generation)='integer' AND auth_link_generation>=0);
CREATE UNIQUE INDEX organization_memberships_link_writer ON organization_memberships (organization_id,id,account_id);
CREATE UNIQUE INDEX account_browser_families_link_writer ON account_browser_families (family_id,account_id);

-- Subject comparisons are keyed and already include Organization, issuer, client and Space.
CREATE TABLE organization_auth_links (
    id BLOB NOT NULL PRIMARY KEY CHECK (typeof(id)='blob' AND length(id)=16 AND substr(hex(id),13,1)='7' AND substr(hex(id),17,1) IN ('8','9','A','B')),
    organization_id BLOB NOT NULL,
    membership_id BLOB NOT NULL,
    subject_comparison BLOB NOT NULL CHECK (typeof(subject_comparison)='blob' AND length(subject_comparison)=32),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms)='integer' AND created_at_ms BETWEEN 1 AND 253402300799999),
    FOREIGN KEY (organization_id,membership_id) REFERENCES organization_memberships(organization_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX organization_auth_links_membership ON organization_auth_links (organization_id,membership_id);
CREATE UNIQUE INDEX organization_auth_links_subject ON organization_auth_links (organization_id,subject_comparison);

-- Bind the attempt to the writer's current Membership and original browser family.
-- A claimed, verified or failed attempt never retains its PKCE verifier.
CREATE TABLE organization_auth_link_attempts (
    id BLOB NOT NULL PRIMARY KEY CHECK (typeof(id)='blob' AND length(id)=16 AND substr(hex(id),13,1)='7' AND substr(hex(id),17,1) IN ('8','9','A','B')),
    organization_id BLOB NOT NULL,
    membership_id BLOB NOT NULL,
    account_id BLOB NOT NULL,
    family_id BLOB NOT NULL,
    connection_revision BLOB NOT NULL CHECK (typeof(connection_revision)='blob' AND length(connection_revision)=16 AND substr(hex(connection_revision),13,1)='7' AND substr(hex(connection_revision),17,1) IN ('8','9','A','B')),
    link_generation INTEGER NOT NULL CHECK (typeof(link_generation)='integer' AND link_generation>=0),
    state_digest BLOB NOT NULL CHECK (typeof(state_digest)='blob' AND length(state_digest)=32),
    browser_digest BLOB NOT NULL CHECK (typeof(browser_digest)='blob' AND length(browser_digest)=32),
    nonce_digest BLOB NOT NULL CHECK (typeof(nonce_digest)='blob' AND length(nonce_digest)=32),
    phase TEXT NOT NULL CHECK (phase IN ('pending','claimed','verified','failed')),
    verifier BLOB CHECK (verifier IS NULL OR (typeof(verifier)='blob' AND length(verifier) BETWEEN 80 AND 8192)),
    subject_comparison BLOB CHECK (subject_comparison IS NULL OR (typeof(subject_comparison)='blob' AND length(subject_comparison)=32)),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms)='integer' AND created_at_ms BETWEEN 1 AND 253402300799999),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms)='integer' AND expires_at_ms BETWEEN 1 AND 253402300799999 AND expires_at_ms>created_at_ms AND expires_at_ms<=created_at_ms+300000),
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
