-- Independent durable admission for each pairing method and route.
CREATE TABLE pairing_admission (
    endpoint INTEGER NOT NULL CHECK (endpoint BETWEEN 1 AND 6),
    kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 3),
    bucket_key BLOB NOT NULL CHECK ((kind = 1 AND length(bucket_key) IN (4, 16)) OR (kind = 2 AND length(bucket_key) = 32) OR (kind = 3 AND length(bucket_key) = 16)),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    failure_streak INTEGER NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms INTEGER CHECK (last_failure_ms >= 0),
    cooldown_until_ms INTEGER CHECK (cooldown_until_ms >= 0),
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key)
);

CREATE INDEX pairing_admission_by_retention ON pairing_admission (retain_until_ms);
