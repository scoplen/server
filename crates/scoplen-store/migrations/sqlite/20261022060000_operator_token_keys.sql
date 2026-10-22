-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE operator_access_token_keys (
    kid TEXT NOT NULL PRIMARY KEY CHECK (length(kid) = 41 AND substr(kid, 1, 9) = 'operator-' AND substr(kid, 10) NOT GLOB '*[^0-9a-f]*'),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    encrypted_seed BLOB NOT NULL CHECK (length(encrypted_seed) = 73),
    activated_at_ms INTEGER NOT NULL CHECK (activated_at_ms > 0),
    retired_at_ms INTEGER,
    verify_until_ms INTEGER,
    active_slot INTEGER,
    CHECK (
        (active_slot IS NOT NULL AND active_slot = 1
            AND retired_at_ms IS NULL AND verify_until_ms IS NULL)
        OR (active_slot IS NULL AND retired_at_ms IS NOT NULL
            AND retired_at_ms > activated_at_ms
            AND verify_until_ms IS NOT NULL
            AND verify_until_ms = retired_at_ms + 604800000)
    )
);

CREATE UNIQUE INDEX operator_access_token_keys_one_active
    ON operator_access_token_keys(active_slot);
