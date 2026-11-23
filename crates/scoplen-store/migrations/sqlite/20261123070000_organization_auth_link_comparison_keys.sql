-- SPDX-License-Identifier: AGPL-3.0-only

-- Stable subject comparisons survive rewrapping independently of each connection credential.
CREATE TABLE organization_auth_link_comparison_keys (
    organization_id BLOB NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    encrypted_key BLOB NOT NULL CHECK (typeof(encrypted_key)='blob' AND length(encrypted_key)=145)
);
