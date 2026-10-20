-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE device_auth_challenges (
    nonce_digest BLOB NOT NULL PRIMARY KEY CHECK (length(nonce_digest) = 32),
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms - issued_at_ms = 120000),
    consumed_at_ms INTEGER CHECK (consumed_at_ms IS NULL OR consumed_at_ms >= issued_at_ms)
);
CREATE INDEX device_auth_challenges_by_expiry ON device_auth_challenges (expires_at_ms);

CREATE TABLE device_refresh_families (
    family_id BLOB NOT NULL PRIMARY KEY CHECK (length(family_id) = 16),
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) = 43),
    audience TEXT NOT NULL CHECK (audience = 'spl-api/1'),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms - created_at_ms = 2592000000),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id),
    FOREIGN KEY (device_id) REFERENCES identity_devices (device_id)
);
CREATE INDEX device_refresh_families_by_expiry ON device_refresh_families (expires_at_ms);
CREATE INDEX device_refresh_families_by_device ON device_refresh_families (device_id, expires_at_ms);

CREATE TABLE device_refresh_tokens (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK (length(token_digest) = 32),
    family_id BLOB NOT NULL CHECK (length(family_id) = 16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
    spent_at_ms INTEGER CHECK (spent_at_ms IS NULL OR spent_at_ms >= issued_at_ms),
    FOREIGN KEY (family_id) REFERENCES device_refresh_families (family_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX device_refresh_tokens_one_live ON device_refresh_tokens (family_id) WHERE spent_at_ms IS NULL;
CREATE INDEX device_refresh_tokens_by_family ON device_refresh_tokens (family_id, issued_at_ms);

CREATE TABLE device_dpop_replays (
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) = 43),
    jti_digest BLOB NOT NULL CHECK (length(jti_digest) = 32),
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (dpop_jkt, jti_digest)
);
CREATE INDEX device_dpop_replays_by_retention ON device_dpop_replays (retain_until_ms);

CREATE TABLE device_auth_admission (
    endpoint INTEGER NOT NULL CHECK (endpoint IN (1, 2, 3)),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    bucket_key BLOB NOT NULL CHECK (
        (kind = 1 AND length(bucket_key) IN (4, 16)) OR
        (kind IN (2, 3) AND length(bucket_key) = 16)
    ),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    failure_streak INTEGER NOT NULL CHECK (failure_streak >= 0),
    last_failure_ms INTEGER,
    cooldown_until_ms INTEGER,
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key)
);
CREATE INDEX device_auth_admission_by_retention ON device_auth_admission (retain_until_ms);
