-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE sync_vaults ADD COLUMN rotation_pending BOOLEAN NOT NULL DEFAULT FALSE CHECK (rotation_pending IN (TRUE, FALSE));
