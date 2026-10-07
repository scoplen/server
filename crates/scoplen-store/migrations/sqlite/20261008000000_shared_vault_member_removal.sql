-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE sync_vaults ADD COLUMN rotation_pending INTEGER NOT NULL DEFAULT 0 CHECK (rotation_pending IN (0, 1));
