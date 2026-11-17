-- SPDX-License-Identifier: AGPL-3.0-only

-- Restore token lookup and retirement indexes after the credential-generation table rebuild.
CREATE INDEX account_browser_access_expiry ON account_browser_access_tokens (expires_at_ms);
CREATE INDEX account_browser_access_family ON account_browser_access_tokens (family_id);
CREATE INDEX account_browser_refresh_family ON account_browser_refresh_tokens (family_id);
