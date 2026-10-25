-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE operator_auth_admission
    DROP CONSTRAINT operator_auth_admission_endpoint_check,
    DROP CONSTRAINT operator_auth_admission_check;
ALTER TABLE operator_auth_admission
    ADD CONSTRAINT operator_auth_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 6),
    ADD CONSTRAINT operator_auth_admission_bucket_key_check CHECK (
        (kind = 1 AND octet_length(bucket_key) IN (4, 16)) OR
        (kind = 2 AND octet_length(bucket_key) = 32 AND endpoint IN (1, 2)) OR
        (kind = 3 AND octet_length(bucket_key) = 16 AND endpoint = 4) OR
        (kind = 4 AND octet_length(bucket_key) = 16 AND endpoint IN (4, 5, 6))
    );
