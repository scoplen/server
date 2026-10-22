-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE operator_auth_admission (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 5),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
    bucket_key BLOB NOT NULL CHECK (
        (kind = 1 AND length(bucket_key) IN (4, 16)) OR
        (kind = 2 AND length(bucket_key) = 32 AND endpoint IN (1, 2)) OR
        (kind = 3 AND length(bucket_key) = 16 AND endpoint = 4) OR
        (kind = 4 AND length(bucket_key) = 16 AND endpoint IN (4, 5))
    ),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    failure_streak INTEGER NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms INTEGER,
    cooldown_until_ms INTEGER,
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key)
);
CREATE INDEX operator_auth_admission_by_retention ON operator_auth_admission (retain_until_ms);

CREATE TABLE operator_dpop_replays (
    dpop_jkt TEXT NOT NULL CHECK (length(dpop_jkt) = 43),
    jti_digest BLOB NOT NULL CHECK (length(jti_digest) = 32),
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (dpop_jkt, jti_digest)
);
CREATE INDEX operator_dpop_replays_by_retention ON operator_dpop_replays (retain_until_ms);
