-- SPDX-License-Identifier: AGPL-3.0-only

-- Existing rows remain unverified until the atomic D-141 activation reads their signed expiry.
ALTER TABLE organization_user_certificates ADD COLUMN valid_before BYTEA
    CHECK (valid_before IS NULL OR octet_length(valid_before)=8);
CREATE INDEX organization_user_certificates_expiry
    ON organization_user_certificates (organization_id,authority_id,valid_before);

-- These CA-owned serials survive Account/Device cascading deletion and snapshot expiry pruning.
CREATE TABLE organization_user_ca_revocations (
    organization_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    serial BYTEA NOT NULL CHECK (octet_length(serial)=8 AND serial<>decode('0000000000000000','hex')),
    valid_before BYTEA NOT NULL CHECK (octet_length(valid_before)=8),
    PRIMARY KEY (organization_id,authority_id,serial),
    FOREIGN KEY (organization_id,authority_id) REFERENCES organization_user_cas(organization_id,id)
);
CREATE INDEX organization_user_ca_revocations_expiry
    ON organization_user_ca_revocations (organization_id,authority_id,valid_before);

CREATE TABLE organization_user_ca_krls (
    organization_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    version BYTEA NOT NULL CHECK (octet_length(version)=8 AND version<>decode('0000000000000000','hex')),
    generated_at BYTEA NOT NULL CHECK (octet_length(generated_at)=8),
    snapshot BYTEA NOT NULL CHECK (octet_length(snapshot) BETWEEN 44 AND 4194304),
    PRIMARY KEY (organization_id,authority_id),
    FOREIGN KEY (organization_id,authority_id) REFERENCES organization_user_cas(organization_id,id)
);

-- A missing snapshot after activation is corruption, never permission to recreate an empty KRL.
CREATE TABLE organization_user_ca_krl_activation (
    singleton BIGINT NOT NULL PRIMARY KEY CHECK (singleton=1),
    activated BIGINT NOT NULL CHECK (activated IN (0,1))
);
INSERT INTO organization_user_ca_krl_activation VALUES (1,0);
