-- Durable Personal enrollment admission and cooldowns shared by API workers.
CREATE TABLE personal_admission (
    kind BIGINT NOT NULL CHECK (kind IN (1, 2)),
    bucket_key BYTEA NOT NULL CHECK ((kind = 1 AND octet_length(bucket_key) IN (4, 16)) OR (kind = 2 AND octet_length(bucket_key) = 32)),
    window_start_ms BIGINT NOT NULL CHECK (window_start_ms >= 0),
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    failure_streak BIGINT NOT NULL CHECK (failure_streak >= 0),
    last_failure_ms BIGINT,
    cooldown_until_ms BIGINT,
    retain_until_ms BIGINT NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (kind, bucket_key)
);

CREATE INDEX personal_admission_by_retention ON personal_admission (retain_until_ms);
