-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE account_entry_admission DROP CONSTRAINT account_entry_admission_endpoint_check;
ALTER TABLE account_entry_admission ADD CONSTRAINT account_entry_admission_endpoint_check CHECK (endpoint BETWEEN 1 AND 53);
