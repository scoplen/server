-- SPDX-License-Identifier: AGPL-3.0-only

-- Preserve the original creation time when introducing name settings.
ALTER TABLE organizations ADD COLUMN updated_at_ms BIGINT NOT NULL DEFAULT 0
    CHECK (updated_at_ms >= 0);
UPDATE organizations SET updated_at_ms = created_at_ms;
