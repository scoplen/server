-- SPDX-License-Identifier: AGPL-3.0-only

-- One expiring discovery reservation per original browser family across Organizations.
CREATE TABLE organization_auth_activation_preflights (
    family_id BYTEA NOT NULL PRIMARY KEY REFERENCES account_browser_families(family_id) ON DELETE CASCADE,
    reservation_id BYTEA NOT NULL CHECK (CASE WHEN octet_length(reservation_id)=16 THEN get_byte(reservation_id,6) >> 4 = 7 AND (get_byte(reservation_id,8) & 192) = 128 ELSE FALSE END),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms BETWEEN 1 AND 253402300799999)
);
CREATE INDEX organization_auth_activation_preflights_expiry ON organization_auth_activation_preflights (expires_at_ms,family_id);
