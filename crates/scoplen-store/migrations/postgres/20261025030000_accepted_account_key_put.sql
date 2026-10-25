-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE sync_account_key_bundles ADD COLUMN accepted_put_cbor BYTEA
    CHECK (accepted_put_cbor IS NULL OR octet_length(accepted_put_cbor) BETWEEN 1 AND 4194304);
