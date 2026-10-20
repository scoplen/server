-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE device_access_token_keys (
    kid TEXT NOT NULL PRIMARY KEY CHECK (length(kid) = 32 AND kid ~ '^[0-9a-f]{32}$'),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    encrypted_seed BYTEA NOT NULL CHECK (octet_length(encrypted_seed) = 73),
    activated_at_ms BIGINT NOT NULL CHECK (activated_at_ms > 0),
    retired_at_ms BIGINT,
    verify_until_ms BIGINT,
    active_slot BIGINT,
    CHECK (
        (active_slot = 1 AND retired_at_ms IS NULL AND verify_until_ms IS NULL)
        OR (active_slot IS NULL AND retired_at_ms IS NOT NULL
            AND retired_at_ms > activated_at_ms
            AND verify_until_ms = retired_at_ms + 604800000)
    )
);

CREATE UNIQUE INDEX device_access_token_keys_one_active
    ON device_access_token_keys(active_slot);
