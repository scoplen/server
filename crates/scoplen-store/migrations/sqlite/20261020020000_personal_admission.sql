-- Durable Personal enrollment admission and cooldowns shared by API workers.
CREATE TABLE personal_admission (
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    bucket_key BLOB NOT NULL CHECK ((kind = 1 AND length(bucket_key) IN (4, 16)) OR (kind = 2 AND length(bucket_key) = 32)),
    window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    failure_streak INTEGER NOT NULL CHECK (failure_streak >= 0),
    last_failure_ms INTEGER,
    cooldown_until_ms INTEGER,
    retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (kind, bucket_key)
);

CREATE INDEX personal_admission_by_retention ON personal_admission (retain_until_ms);
