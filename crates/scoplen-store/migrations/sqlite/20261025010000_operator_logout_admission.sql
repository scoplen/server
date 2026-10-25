-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE operator_auth_admission_logout (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 6),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
    bucket_key BLOB NOT NULL CHECK (
        (kind = 1 AND length(bucket_key) IN (4, 16)) OR
        (kind = 2 AND length(bucket_key) = 32 AND endpoint IN (1, 2)) OR
        (kind = 3 AND length(bucket_key) = 16 AND endpoint = 4) OR
        (kind = 4 AND length(bucket_key) = 16 AND endpoint IN (4, 5, 6))
    ),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    failure_streak INTEGER NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms INTEGER,
    cooldown_until_ms INTEGER,
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key)
);
INSERT INTO operator_auth_admission_logout
    (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak,
     last_failure_ms, cooldown_until_ms, retain_until_ms)
SELECT endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak,
       last_failure_ms, cooldown_until_ms, retain_until_ms
FROM operator_auth_admission;
DROP TABLE operator_auth_admission;
ALTER TABLE operator_auth_admission_logout RENAME TO operator_auth_admission;
CREATE INDEX operator_auth_admission_by_retention ON operator_auth_admission (retain_until_ms);
