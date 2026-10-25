-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE sync_account_key_bundles ADD COLUMN accepted_put_cbor BLOB
    CHECK (accepted_put_cbor IS NULL OR length(accepted_put_cbor) BETWEEN 1 AND 4194304);
