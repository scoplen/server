-- Independent durable admission for each pairing method and route.
CREATE TABLE pairing_admission (
    endpoint BIGINT NOT NULL CHECK (endpoint BETWEEN 1 AND 6),
    kind BIGINT NOT NULL CHECK (kind BETWEEN 1 AND 3),
    bucket_key BYTEA NOT NULL CHECK ((kind = 1 AND octet_length(bucket_key) IN (4, 16)) OR (kind = 2 AND octet_length(bucket_key) = 32) OR (kind = 3 AND octet_length(bucket_key) = 16)),
    window_start_ms BIGINT NOT NULL CHECK (window_start_ms >= 0),
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    failure_streak BIGINT NOT NULL CHECK (failure_streak BETWEEN 0 AND 10),
    last_failure_ms BIGINT CHECK (last_failure_ms >= 0),
    cooldown_until_ms BIGINT CHECK (cooldown_until_ms >= 0),
    retain_until_ms BIGINT NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (endpoint, kind, bucket_key)
);

CREATE INDEX pairing_admission_by_retention ON pairing_admission (retain_until_ms);
