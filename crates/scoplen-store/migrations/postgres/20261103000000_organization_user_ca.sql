-- SPDX-License-Identifier: AGPL-3.0-only

-- Initial active local user CA; the encrypted seed is bound to this immutable tenant and id.
CREATE TABLE organization_user_cas (
    organization_id BYTEA NOT NULL REFERENCES organizations(id) CHECK (octet_length(organization_id)=16),
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    encrypted_seed BYTEA NOT NULL CHECK (octet_length(encrypted_seed)=73),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 16384),
    last_serial BYTEA NOT NULL CHECK (octet_length(last_serial)=8),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id)
);

CREATE TABLE organization_user_certificates (
    organization_id BYTEA NOT NULL,
    id BYTEA NOT NULL CHECK (octet_length(id)=16),
    authority_id BYTEA NOT NULL,
    account_id BYTEA NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE CHECK (octet_length(account_id)=16),
    device_id BYTEA NOT NULL REFERENCES identity_devices(device_id) ON DELETE CASCADE CHECK (octet_length(device_id)=16),
    serial BYTEA NOT NULL CHECK (octet_length(serial)=8 AND serial<>decode('0000000000000000','hex')),
    response_json BYTEA NOT NULL CHECK (octet_length(response_json) BETWEEN 1 AND 131072),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms>0),
    PRIMARY KEY (organization_id,id),
    UNIQUE (organization_id,authority_id,serial),
    FOREIGN KEY (organization_id,authority_id) REFERENCES organization_user_cas(organization_id,id)
);

ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 40);
