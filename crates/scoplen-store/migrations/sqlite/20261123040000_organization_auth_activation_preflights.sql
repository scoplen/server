-- SPDX-License-Identifier: AGPL-3.0-only

-- One expiring discovery reservation per original browser family across Organizations.
CREATE TABLE organization_auth_activation_preflights (
    family_id BLOB NOT NULL PRIMARY KEY REFERENCES account_browser_families(family_id) ON DELETE CASCADE CHECK (typeof(family_id)='blob' AND length(family_id)=16),
    reservation_id BLOB NOT NULL CHECK (typeof(reservation_id)='blob' AND length(reservation_id)=16 AND substr(hex(reservation_id),13,1)='7' AND substr(hex(reservation_id),17,1) IN ('8','9','A','B')),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms)='integer' AND expires_at_ms BETWEEN 1 AND 253402300799999)
);
CREATE INDEX organization_auth_activation_preflights_expiry ON organization_auth_activation_preflights (expires_at_ms,family_id);
