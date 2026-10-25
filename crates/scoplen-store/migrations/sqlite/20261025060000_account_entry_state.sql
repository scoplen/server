-- SPDX-License-Identifier: AGPL-3.0-only

-- Independent Account-entry debt and one-use request challenges have no identity FK.
-- The singleton serializes capacity admission and advances database time monotonically.
CREATE TABLE account_entry_state (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    time_high_water_ms INTEGER NOT NULL CHECK (time_high_water_ms >= 0),
    rate_rows INTEGER NOT NULL CHECK (rate_rows BETWEEN 0 AND 131072),
    challenge_rows INTEGER NOT NULL CHECK (challenge_rows BETWEEN 0 AND 16384),
    last_cleanup_ms INTEGER NOT NULL CHECK (last_cleanup_ms >= 0)
);
INSERT INTO account_entry_state VALUES (1, 0, 0, 0, 0);

CREATE TABLE account_entry_admission (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 5),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
    bucket_key BLOB NOT NULL CHECK (typeof(bucket_key) = 'blob'),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms BETWEEN 0 AND 9223372036854715807),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 30),
    failure_streak INTEGER NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms INTEGER,
    cooldown_until_ms INTEGER,
    last_admitted_ms INTEGER NOT NULL CHECK (last_admitted_ms BETWEEN 1 AND 9223372036854175807),
    retire_at_ms INTEGER NOT NULL CHECK (retire_at_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key),
    CHECK (last_admitted_ms <= retire_at_ms - 600000),
    CHECK (window_start_ms <= retire_at_ms - 60000),
    CHECK (cooldown_until_ms IS NULL OR cooldown_until_ms <= retire_at_ms),
    CHECK ((kind = 1 AND length(bucket_key) IN (4, 16))
        OR (kind = 2 AND length(bucket_key) = 32)
        OR (kind IN (3, 4) AND length(bucket_key) = 16)),
    CHECK ((failure_streak = 0 AND last_failure_ms IS NULL AND cooldown_until_ms IS NULL)
        OR (failure_streak > 0 AND last_failure_ms IS NOT NULL AND last_failure_ms > 0
            AND cooldown_until_ms IS NOT NULL AND cooldown_until_ms >= last_failure_ms))
);
CREATE INDEX account_entry_admission_retire ON account_entry_admission (retire_at_ms);

CREATE TABLE account_request_challenges (
    attempt_digest BLOB PRIMARY KEY NOT NULL CHECK (typeof(attempt_digest) = 'blob' AND length(attempt_digest) = 32),
    nonce_digest BLOB NOT NULL CHECK (typeof(nonce_digest) = 'blob' AND length(nonce_digest) = 32),
    origin_digest BLOB NOT NULL CHECK (typeof(origin_digest) = 'blob' AND length(origin_digest) = 32),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    intent INTEGER NOT NULL CHECK (intent IN (1, 2)),
    operation_id BLOB NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms = issued_at_ms + 120000)
);
CREATE INDEX account_request_challenges_expiry ON account_request_challenges (expires_at_ms);
