# Changelog

Changes are recorded here for released or reviewable repository outcomes.

## Unreleased

- API and edge roles can start with PostgreSQL; their public listener checks the selected database
  and object store through `/readyz`. The authenticated sync router remains SQLite-only and unmounted.
- Fixed account-key PUT retries after signing-key rotation. An authenticated, authorized exact
  replay skips current-key signature verification, while altered replays conflict and new
  revisions still require valid signatures. SQLite and PostgreSQL classify one read snapshot;
  the final mutation transaction rechecks revision and exact bytes against concurrent rotations.
- Enforced the fixed 4 MiB account-key GET response limit during bundle updates and statement
  replacement for every device wrap. Oversized projections roll back atomically and PUT returns
  `413 sync.quota_exceeded`; exact 4 MiB responses remain readable.
- Fixed PostgreSQL schema verification for composite foreign keys by pairing referenced columns
  with their source columns in constraint order, and synchronized its migration-count and job-time
  assertions with current migrations and queue behavior.
- Made KMS test key files unique across parallel tests so one test cannot overwrite another's
  fixture on platforms with coarse clock resolution.
- Require rustls 0.23.46 and update the server lockfile for the same TLS advisories
  addressed in the shared protocol workspace (RUSTSEC-2026-0346 through RUSTSEC-2026-0349).
- Added a strict local deployment-key-file backend behind `KeyManagementService`, with bounded
  hexadecimal parsing, zero-key rejection, secret zeroization, redacted debug output, and failure
  coverage. Database-backed role preparation now loads this backend before startup. Cloud
  KMS/PKCS#11 adapters and application-level column encryption remain open. TOML and
  `SPL_STORAGE_KMS_*` overrides select the local key-file path.
- Added an independent local Ed25519 audit signer generated as `audit-signing.key`; the worker
  signs advanced organization chain heads at most hourly and stores idempotent checkpoints.
  External signer backends, public-key distribution, control-plane event producers, and audit
  retention/export remain open.
- Added bounded audit-chain primitives and SQLite persistence: canonical event SHA-256 chaining,
  same-transaction append helpers, checkpoint payload construction, idempotent signed-checkpoint
  storage, and chain verification with failure-path tests. Control-plane event producers and
  retention/export integration remain open.
- Added shared-vault epoch retirement with durable markers, per-object key-epoch tracking, an
  authenticated idempotent route, newest/in-use checks, and rejection of writes using retired
  epochs. Personal and organization vaults remain outside this operation.
- Connected the worker role to bounded sync-retention scheduling: vault ids are deduplicated in the
  durable queue, claimed by kind, purged atomically with the existing retention primitive, and
  retried after malformed or failed jobs. The worker passes no acknowledgement floor until device
  membership and identity are available.
- Enforced default sync cardinality limits atomically for object insertion, shared-vault creation,
  and member addition. The session advertises the store limits, and quota rejection returns
  `413 sync.quota_exceeded` with no mutation. Deployment-configurable limits remain open.
- Added process-local per-device token-bucket admission for authenticated object writes at the
  advertised 50 requests-per-second and burst-200 defaults. Exhausted buckets return
  `429 sync.rate_limited` with `Retry-After`, without reading or mutating the request body.
  Deployment-configurable and multi-instance admission remain open.
- Added atomic one-per-account personal-vault provisioning with an ARK-wrapped epoch-one key,
  account-scoped key lookup, and personal-vault descriptors in the authenticated session response.
  SQLite and PostgreSQL migrations enforce ownership uniqueness. First-enrollment wiring and a
  personal-vault key wire route still require a shared contract and production identity service.
- Added the injected-authenticator `POST /sync/v1/session` handshake with account-scoped shared-vault
  descriptors, device binding, compatibility checks, and the persisted rotation-pending state.
  Organization vault ownership, production identity, and full quota enforcement remain
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
  wraps, account-scoped durable lookup for shared members and personal owners, not-found mapping,
  and route failure-path coverage. Shared-vault creation and personal provisioning return the
  epoch-1 opaque wrap; rotation remains a later endpoint.
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
