# Changelog

Changes are recorded here for released or reviewable repository outcomes.

## Unreleased

- Mounted `GET /api/v1/accounts/me` for enrolled devices with exact `account:read` scope,
  JWT/DPoP/replay checks and transaction-local current account/device/proof-key/certificate
  authorization on SQLite and PostgreSQL. The bounded shared Resource codec preserves null or
  exact stored email, stable strong ETags and persisted timestamps; no-store/Pragma responses
  and disclosure-free errors cover revoked, missing, corrupt and unavailable state. Added real
  HTTP authorization/failure regressions, profile reads to the complete public Personal flow,
  the production route manifest and PostgreSQL CI. Profile mutation remains separate work.

- Added the real React Personal console for first-passkey setup, fresh discoverable Operator
  login, serialized cookie-only refresh and explicit Personal invitation creation. The setup
  fragment is scrubbed immediately and the non-extractable browser proof key and access token
  remain in memory. Unknown outcomes never trigger automatic business replay. Public generated
  API types are pinned and checked, and actual WebCrypto proofs interoperate with the shared
  Rust verifier. API-role static assets use a bounded SHA-256 whitelist, strict CSP and Trusted
  Types; missing builds return an actionable console-only 503. Added asset configuration,
  production build, bundled fonts/licenses, failure-path tests and CI checks. Physical passkey
  and release-package verification remain open.

- SQLite Operator session audit-rollback tests install one stable trigger and toggle a
  fixture row, avoiding stale pooled schema state when replacing triggers repeatedly.
  Login, refresh and reuse-revocation rollback checks retain their real audit failures.

- PostgreSQL device authentication and Operator JWKS HTTP tests use disposable schemas so
  deliberate key corruption cannot contaminate later runs or neighboring tests. CI now runs
  both public HTTP fixtures together, including the Operator JWKS failure boundary.

- Added full public Personal bootstrap and sync regressions for SQLite and PostgreSQL: real
  passkey setup and fresh login, protected invitation issuance, first-device enrollment,
  challenge/token exchange, Personal session and keys, signed encrypted host write, downloaded
  envelope verification/decryption and durable ACK. The tests use the complete production API
  router and verify its deployment audit chain, without seeding account/device/vault rows.
  This is server HTTP evidence; native desktop and two-device flows remain separate gates.

- PostgreSQL Operator keyring tests use a disposable schema per test, isolating deliberate
  key tampering from preceding device-key tests and later authentication checks in CI.

- Mounted Operator-authenticated Personal invitation issuance on SQLite and PostgreSQL using
  the published strict JSON contract and real Cedar schema/policies. Dedicated durable source
  and Operator quotas, exact scope, protected DPoP replay claims and current-session checks
  precede issuance. The mutation holds authorization locks through its mandatory audit and
  commit; one-time URLs are disclosed only after confirmed commit. Live HTTP regressions cover
  ordinary-device and reduced-scope denials, revocation during body delivery, concurrent quota
  contention, audit rollback, SQLite deferred commit failure and PostgreSQL lost commit ACK.
  Added the admission migration, schema parity, production route manifest and PostgreSQL CI.

- PostgreSQL HTTP lost-commit fixtures wait for the exact held business advisory lock before
  withholding its acknowledgement. Parallel admission/keyring waits cannot redirect the fault
  into a preceding transaction.

- Updated `ctutils` to 0.4.4 for RUSTSEC-2026-0385, fixing non-constant-time mask
  generation and integer comparison in the shared cryptographic dependency graph.

- Included the mounted Operator JWKS endpoint in the control-plane route manifest so the
  three-platform contract checks validate both independent public key discovery routes.

- Mounted discoverable Operator passkey login and cookie-only browser refresh on the API listener.
  Strict shared codecs, exact Origin, durable admission and DPoP replay checks precede login;
  refresh verifies proof binding, rotates and audits inside one transaction. Responses disclose
  only four browser token fields and the scoped secure cookie after confirmed commit. Real
  SQLite/PostgreSQL HTTP tests cover signed login, Operator JWKS, current state, native/device
  separation, wrong keys, replay, matching-token reuse, quotas, races, mandatory audit rollback,
  deferred failures and real PostgreSQL lost commit acknowledgements. Console remains open.

- Mounted first-Operator setup options and finish on the API listener with shared strict wire
  codecs, exact Origin, presented-key DPoP verification, durable replay claims and source/private
  admission on SQLite and PostgreSQL. Registration returns only an Operator id. Real software
  passkey HTTP tests cover wrong keys, replay, malformed outer and embedded artifacts, expiry,
  quotas, concurrent completion, mandatory audit rollback, deferred commit failure and a real
  PostgreSQL lost commit acknowledgement. Unknown outcomes disclose no success or cookie.
  Updated all proto pins to `e2dd140` and the route manifest.

- PostgreSQL administration transaction guards hold shared row locks on the current Operator,
  credential and refresh family through commit or rollback. Direct concurrent revocations cannot
  interleave between authorization and the protected mutation; expiry is rechecked after locks.

- Added durable discoverable Operator passkey login and independent browser sessions on SQLite
  and PostgreSQL. Login compares against the current credential, then atomically updates its
  counter/backup state, consumes the ceremony, creates a 30-day refresh family and appends the
  mandatory audit. Refresh verifies and claims the original proof in its transaction, rotates
  single-use digest-only credentials, and revokes a family on authenticated matching-token reuse.
  Administration mutations can recheck current family, Operator and credential state under the
  session lock. Complete browser JSON and scoped secure cookies are validated before commit;
  uncertain commits disclose neither.

- Added an independent SQLite/PostgreSQL Operator access-token keyring and public
  `GET /.well-known/operator-jwks.json`. Dedicated seeds, `operator-` key identifiers, and
  purpose-bound encrypted envelopes prevent device-key reuse. Creation and 30-day rotation
  commit with deployment audit events; retired keys remain public for seven days. KMS,
  integrity, storage, or required audit failures return a non-cacheable 503 without partial
  keys. Device JWKS stays independent. Updated all proto pins to `0c06293` and UUID to 1.28.0
  in the lockfile for the shared Operator profile.

- Added independent durable Operator authentication admission and DPoP replay claims on both
  stores. Per-endpoint source, setup-digest, ceremony and authenticated-Operator windows enforce
  quotas and bounded exponential cooldowns across replicas. Setup completion clears failures
  without refunding quotas; failed embedded registration commits ceremony consumption, cooldown
  and denial audit together.

- Added durable first-operator setup and real ES256 WebAuthn verification on SQLite and
  PostgreSQL. API initialization discloses a digest-only one-hour setup entitlement once after
  confirmed commit; restarts and background roles never reproduce or extend it. The local
  `splctl bootstrap --reissue-pending` action replaces only an uncompleted entitlement.
  Registration, permanent setup completion, ceremony consumption and deployment audit commit
  together. Removed setup-link file creation. The maintained verifier requires vendored
  OpenSSL build prerequisites. Console integration remains incomplete.

- Updated `rustls-webpki` to 0.103.16 and both `webpki-roots` and `webpki-root-certs` to 1.0.10,
  fixing RUSTSEC-2026-0382, RUSTSEC-2026-0381, and RUSTSEC-2026-0383 for TLS certificate trust.
- Mounted the enrolled-device Personal sync routes on the API listener for SQLite and PostgreSQL.
  Requests verify signed device tokens, method/path/access-token-bound DPoP proofs, durable replay
  claims, current certificates, route scopes, and vault ownership. Object writes verify device
  signatures; writes and acknowledgements recheck authorization inside the mutation transaction.
  Configured body and write-rate limits apply across connections, including TLS listeners.
  Object and business-state ACK commits with an unconfirmed result return 503 with `changed: true`
  and `retryable: false`; precommit failures and no-op ACK failures preserve no-change retry semantics.
  SQLite deferred-commit and PostgreSQL lost-acknowledgement regressions exercise these distinctions.
  Notification fan-out preserves each authenticated account/device identity. Shared mutations,
  account-key updates, and production notifications
  remain unmounted.
- Centralized SQLite integration-fixture cleanup with a ten-second deadline for Windows
  sharing and lock violations after connection-pool shutdown. Other cleanup errors still fail
  immediately. A real exclusive Windows file handle held beyond the former one-second budget
  now exercises release and cleanup, alongside the unchanged storage assertions.
- Added durable D-101 Personal invitations and atomic first-device enrollment to SQLite and
  PostgreSQL. Redemption accepts only the identity verifier's signed result, rejects existing
  identity/K-4/vault identifiers with one denial, checks expiry after obtaining the invitation
  lock, and rolls back account, device, keys, vault, invitation, and audit together on failure.
  PostgreSQL 17 and SQLite tests cover concurrent redemption, legacy collisions, mutable K-4
  certificate replacement, expiry, and late rollback. Operator authentication and production
  HTTP routes are still pending.
- Added a deployment-wide audit chain separate from organization chains in SQLite and PostgreSQL,
  with transactional append, bounded-memory prefix verification, and an hourly signed checkpoint.
  Concurrent checkpoint writers serialize in the database; event producers and export remain open.
- The authenticated K-4 HTTP/CBOR router now accepts either SQLite or PostgreSQL as one selected
  durable backend for all sync, shared-vault, and account-key routes. PostgreSQL 17 integration
  tests cover successful and rejected requests, account isolation, conflicts, quotas, and local
  notifications. The baseline listener still does not mount the router; production identity and
  multi-instance notification fan-out remain open.
- Pinned migration SQL checkouts to LF so Windows and Unix builds embed identical migration
  bytes and SQLx checksums. Existing databases created with noncanonical bytes still require
  their matching build; recorded migration checksums are not rewritten.
- Added PostgreSQL parity for shared-vault epoch publication, member addition/removal, and safe
  epoch retirement. Per-vault serialization and a shared account quota lock protect concurrent
  mutations; key-response bounds and late-failure rollback are covered against PostgreSQL 17.
  The sync HTTP adapter remains SQLite-only and unmounted by the baseline listener.
- Added PostgreSQL shared-vault creation with an atomic admin membership and epoch-one wrap,
  account-scoped stable listings, and non-retired member-key reads. Disposable PostgreSQL tests
  cover isolation, concurrent quota and duplicate races, and rollback after a key-row failure.
- Added a `scoplen-identity` verifier for D-101 first-device enrollment. It checks the K-4 account
  signature, K-2 certificate, and origin-bound device possession proof, returning only a redacted
  verified value for later atomic redemption. Synchronized all server proto pins to `e288515`.
  Invitation state, persistence, operator authorization, production routes, and device-token
  authentication remain incomplete.
- Validated the configured public HTTPS origin against the shared K-3 rules, with an external
  `server.public_port` separate from the listener port. Setup links now use this trusted origin;
  invalid hosts and ports fail startup and configuration checks. Operator setup and production
  authentication remain incomplete.
- Create new first-run key, certificate, and setup files with owner-only Unix permissions and
  exclusive creation. Existing files and symlink destinations cannot be overwritten; incomplete
  CA material fails closed instead of replacing an existing certificate or key.
- Added PostgreSQL Personal sync snapshot paging and bounded retained-version reads. Snapshots
  recover from the purge horizon; both reads use one read-only repeatable-read transaction, and
  PostgreSQL integration tests cover vault isolation, paging, retention, missing-state errors, and
  concurrent writes. Corrected the PostgreSQL retention DELETE syntax exposed by the recovery
  test. The sync HTTP adapter remains SQLite-only and unmounted.
- Added PostgreSQL Personal sync storage for atomic compare-and-swap batches, gap-free sequences,
  current change pages, and monotone device acknowledgements. The runtime passes configured
  current-object limits to PostgreSQL, and real database tests cover concurrency, rollback,
  conflicts, cursor bounds, and quota rejection. The sync router remains unmounted and SQLite-only.
- Added PostgreSQL parity for atomic, one-per-account personal-vault provisioning, owner-scoped
  wrapped-key reads, and account-scoped personal/shared vault listings. Duplicate and concurrent
  creation attempts leave no orphan vault row. The sync router and remaining sync queries still
  use SQLite.
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
