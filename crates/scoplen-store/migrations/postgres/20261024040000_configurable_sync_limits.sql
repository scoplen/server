-- SPDX-License-Identifier: AGPL-3.0-only
-- Keep nonempty envelopes; the store enforces the deployment-selected upper bound.

ALTER TABLE sync_objects DROP CONSTRAINT sync_objects_envelope_check;
ALTER TABLE sync_objects ADD CONSTRAINT sync_objects_envelope_check CHECK (octet_length(envelope) > 0);
ALTER TABLE sync_object_versions DROP CONSTRAINT sync_object_versions_envelope_check;
ALTER TABLE sync_object_versions ADD CONSTRAINT sync_object_versions_envelope_check CHECK (octet_length(envelope) > 0);
