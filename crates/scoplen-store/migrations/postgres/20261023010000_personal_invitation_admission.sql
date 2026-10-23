-- Independent issuance quotas; Operator identity is selected only after authentication.
CREATE TABLE personal_invitation_admission (
    kind BIGINT NOT NULL CHECK (kind IN (1, 2)),
    bucket_key BYTEA NOT NULL CHECK ((kind = 1 AND octet_length(bucket_key) IN (4, 16)) OR (kind = 2 AND octet_length(bucket_key) = 16)),
    window_start_ms BIGINT NOT NULL CHECK (window_start_ms >= 0),
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    retain_until_ms BIGINT NOT NULL CHECK (retain_until_ms > 0),
    PRIMARY KEY (kind, bucket_key)
);
CREATE INDEX personal_invitation_admission_by_retention ON personal_invitation_admission (retain_until_ms);
