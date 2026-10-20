-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE device_auth_challenges (
    nonce_digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(nonce_digest) = 32),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms > 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms - issued_at_ms = 120000),
    consumed_at_ms BIGINT CHECK (consumed_at_ms IS NULL OR consumed_at_ms >= issued_at_ms)
);
CREATE INDEX device_auth_challenges_by_expiry ON device_auth_challenges (expires_at_ms);

CREATE TABLE device_refresh_families (
    family_id BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(family_id) = 16),
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) = 43),
    audience TEXT NOT NULL CHECK (audience = 'spl-api/1'),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms > 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms - created_at_ms = 2592000000),
    revoked_at_ms BIGINT CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms),
    FOREIGN KEY (account_id) REFERENCES identity_accounts (account_id),
    FOREIGN KEY (device_id) REFERENCES identity_devices (device_id)
);
CREATE INDEX device_refresh_families_by_expiry ON device_refresh_families (expires_at_ms);
CREATE INDEX device_refresh_families_by_device ON device_refresh_families (device_id, expires_at_ms);

CREATE TABLE device_refresh_tokens (
    token_digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    family_id BYTEA NOT NULL CHECK (octet_length(family_id) = 16),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms > 0),
    spent_at_ms BIGINT CHECK (spent_at_ms IS NULL OR spent_at_ms >= issued_at_ms),
    FOREIGN KEY (family_id) REFERENCES device_refresh_families (family_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX device_refresh_tokens_one_live ON device_refresh_tokens (family_id) WHERE spent_at_ms IS NULL;
CREATE INDEX device_refresh_tokens_by_family ON device_refresh_tokens (family_id, issued_at_ms);

CREATE TABLE device_dpop_replays (
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) = 43),
    jti_digest BYTEA NOT NULL CHECK (octet_length(jti_digest) = 32),
    retain_until_ms BIGINT NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (dpop_jkt, jti_digest)
);
CREATE INDEX device_dpop_replays_by_retention ON device_dpop_replays (retain_until_ms);

CREATE TABLE device_auth_admission (
    endpoint BIGINT NOT NULL CHECK (endpoint IN (1, 2, 3)),
    kind BIGINT NOT NULL CHECK (kind IN (1, 2, 3)),
    bucket_key BYTEA NOT NULL CHECK (
        (kind = 1 AND octet_length(bucket_key) IN (4, 16)) OR
        (kind IN (2, 3) AND octet_length(bucket_key) = 16)
    ),
    window_start_ms BIGINT NOT NULL CHECK (window_start_ms >= 0),
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    failure_streak BIGINT NOT NULL CHECK (failure_streak >= 0),
    last_failure_ms BIGINT,
    cooldown_until_ms BIGINT,
    retain_until_ms BIGINT NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key)
);
CREATE INDEX device_auth_admission_by_retention ON device_auth_admission (retain_until_ms);
