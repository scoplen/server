-- SPDX-License-Identifier: AGPL-3.0-only

-- Independent Account-entry debt and one-use request challenges have no identity FK.
-- The singleton serializes capacity admission and advances database time monotonically.
CREATE TABLE account_entry_state (
    singleton BIGINT PRIMARY KEY NOT NULL CHECK (singleton = 1),
    time_high_water_ms BIGINT NOT NULL CHECK (time_high_water_ms >= 0),
    rate_rows BIGINT NOT NULL CHECK (rate_rows BETWEEN 0 AND 131072),
    challenge_rows BIGINT NOT NULL CHECK (challenge_rows BETWEEN 0 AND 16384),
    last_cleanup_ms BIGINT NOT NULL CHECK (last_cleanup_ms >= 0)
);
INSERT INTO account_entry_state VALUES (1, 0, 0, 0, 0);

CREATE TABLE account_entry_admission (
    endpoint BIGINT NOT NULL CHECK (endpoint BETWEEN 1 AND 5),
    kind BIGINT NOT NULL CHECK (kind BETWEEN 1 AND 4),
    bucket_key BYTEA NOT NULL,
    window_start_ms BIGINT NOT NULL CHECK (window_start_ms BETWEEN 0 AND 9223372036854715807),
    attempts BIGINT NOT NULL CHECK (attempts BETWEEN 0 AND 30),
    failure_streak BIGINT NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms BIGINT,
    cooldown_until_ms BIGINT,
    last_admitted_ms BIGINT NOT NULL CHECK (last_admitted_ms BETWEEN 1 AND 9223372036854175807),
    retire_at_ms BIGINT NOT NULL CHECK (retire_at_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key),
    CHECK (last_admitted_ms <= retire_at_ms - 600000),
    CHECK (window_start_ms <= retire_at_ms - 60000),
    CHECK (cooldown_until_ms IS NULL OR cooldown_until_ms <= retire_at_ms),
    CHECK ((kind = 1 AND octet_length(bucket_key) IN (4, 16))
        OR (kind = 2 AND octet_length(bucket_key) = 32)
        OR (kind IN (3, 4) AND octet_length(bucket_key) = 16)),
    CHECK ((failure_streak = 0 AND last_failure_ms IS NULL AND cooldown_until_ms IS NULL)
        OR (failure_streak > 0 AND last_failure_ms IS NOT NULL AND last_failure_ms > 0
            AND cooldown_until_ms IS NOT NULL AND cooldown_until_ms >= last_failure_ms))
);
CREATE INDEX account_entry_admission_retire ON account_entry_admission (retire_at_ms);

CREATE TABLE account_request_challenges (
    attempt_digest BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(attempt_digest) = 32),
    nonce_digest BYTEA NOT NULL CHECK (octet_length(nonce_digest) = 32),
    origin_digest BYTEA NOT NULL CHECK (octet_length(origin_digest) = 32),
    kind BIGINT NOT NULL CHECK (kind IN (1, 2)),
    intent BIGINT NOT NULL CHECK (intent IN (1, 2)),
    operation_id BYTEA NOT NULL CHECK (octet_length(operation_id) = 16),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms > 0),
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms = issued_at_ms + 120000)
);
CREATE INDEX account_request_challenges_expiry ON account_request_challenges (expires_at_ms);
