-- SPDX-License-Identifier: AGPL-3.0-only

-- Durable fractional-token admission; byte ordering preserves the complete unsigned range.
CREATE TABLE sync_write_admission (
    device_id BLOB NOT NULL PRIMARY KEY CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
    requests_per_second BLOB NOT NULL CHECK (typeof(requests_per_second) = 'blob' AND length(requests_per_second) = 8 AND requests_per_second > X'0000000000000000'),
    burst BLOB NOT NULL CHECK (typeof(burst) = 'blob' AND length(burst) = 8 AND burst > X'0000000000000000'),
    tokens BLOB NOT NULL CHECK (typeof(tokens) = 'blob' AND length(tokens) = 16),
    refill_origin_ns BLOB NOT NULL CHECK (typeof(refill_origin_ns) = 'blob' AND length(refill_origin_ns) = 16),
    retire_at_ns BLOB NOT NULL CHECK (typeof(retire_at_ns) = 'blob' AND length(retire_at_ns) = 16)
);
CREATE INDEX sync_write_admission_by_retirement ON sync_write_admission (retire_at_ns, device_id);

-- Preserve retired clock history without a deployment-wide lock on ordinary admission.
CREATE TABLE sync_write_admission_clock (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    retired_through_ns BLOB NOT NULL CHECK (typeof(retired_through_ns) = 'blob' AND length(retired_through_ns) = 16)
);
INSERT INTO sync_write_admission_clock (singleton, retired_through_ns)
VALUES (1, X'00000000000000000000000000000000');
