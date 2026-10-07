# Changelog

Changes are recorded here for released or reviewable repository outcomes.

## Unreleased

- Added the injected-authenticator `POST /sync/v1/session` handshake with account-scoped shared-vault
  descriptors, device binding, compatibility checks, and the persisted rotation-pending state.
  Personal and organization vault ownership, production identity, and full quota enforcement remain
  open; the baseline listener does not mount this router.
- Added authenticated-injection `DELETE /sync/v1/vaults/{vault}/members/{account}` with
  last-admin protection, atomic member and wrap removal, and a durable rotation-pending marker.
  Successful next-epoch publication clears the marker. The identity service remains responsible
  for immediately denying removed devices' vault operations.
- Added authenticated-injection `POST /sync/v1/vaults/{vault}/members` with bounded sorted epoch
  wraps, exact current-epoch coverage, duplicate-member conflict mapping, and atomic membership
  plus historical-wrap persistence. Route and storage tests cover missing epochs and rollback.
- Added authenticated-injection `POST /sync/v1/vaults/{vault}/epochs` with admin-gated next-epoch
  validation, exact current-member wrap matching, atomic historical/current key persistence, and
  conflict and malformed-request problem mapping. SQLite/PostgreSQL schema parity and route/store
  failure-path tests cover the all-or-nothing rotation boundary.
- Added authenticated-injection `GET /sync/v1/vaults/{vault}/keys` with bounded ascending epoch
  wraps, account-scoped durable lookup, not-found mapping, and route failure-path coverage. The
  initial creation flow returns the epoch-1 opaque wrap; rotation remains a later endpoint.
- Added authenticated-injection `POST /sync/v1/vaults` shared-vault creation with deterministic
  CBOR decoding, UUIDv7 and bounded-wrap validation, duplicate conflict mapping, and a response
  descriptor fixed to epoch one. SQLite persists the creator's admin/member row and opaque key wrap
  atomically; migration parity and storage rollback tests cover the durable boundary.
- Added an authenticated-injection `/sync/v1/notify` WebSocket adapter with bounded first-message
  credentials, fail-closed device authorization, per-device local fan-out, deterministic CBOR event
  delivery, lag handling, and route-level success and rejection tests. Multi-instance delivery and
  event publication from the identity and vault services remain open.
- Added authenticated-injection K-4 `/sync/v1/keys` GET/PUT routes with deterministic CBOR,
  per-device bundle reads, signed-update validation hooks, exact replay responses, conflict and
  storage problem mapping, and route-level tests. The baseline listener still does not mount the
  router.
- Added an opaque SQLite account key-bundle store for D-50 with per-device wrapped-ARK reads,
  bounded artifacts and device wraps, atomic revision compare-and-swap updates, and exact replay
  handling. Authentication, membership, and account-signature verification remain service-layer
  responsibilities.
- Added the K-4 HTTP/CBOR adapter for changes, snapshots, retained versions, object writes, and
  acknowledgements. The adapter requires an injected DPoP-bound authenticator and a write-envelope
  validator, maps storage failures to problem-details codes, and remains unmounted by the baseline
  listener until identity and policy services are implemented.
- Added an atomic SQLite sync retention pass that bounds history to the current version plus 20
  retained versions, purges acknowledged or 180-day-old tombstones, and advances the purge horizon
  without making membership or policy decisions in the storage layer.
- Added the SQLite sync storage foundation: per-vault gap-free sequences, atomic compare-and-swap
  batches, current change and snapshot paging, acknowledgement cursors, and bounded version reads.
- Added the server workspace baseline, role/configuration boundary, first-run material, public
  listener, ALPN declaration, health endpoints, structured logging, and TypeScript console checks.
