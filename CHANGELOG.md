# Changelog

Changes are recorded here for released or reviewable repository outcomes.

## Unreleased

- Verify real password Account registration/login, independent Device admission, native refresh
  and bidirectional encrypted Host synchronization in the Personal production-container check.
  The public-API consumer uses random disposable keys without identity seeding and writes a
  separate content-free acceptance receipt, preserving existing integration descriptors.

- Advance the SQLite upgrade and offline-recovery probe to the team membership migration
  while preserving its pinned historical image boundary.

- Validate mounted control-plane routes against the same pinned public API contract used by
  the server, with a regression check for CI checkout drift. Run team membership migrations
  and HTTP failure paths in separate PostgreSQL test databases.

- Mount Account-owned team creation and current-membership list/read on SQLite and PostgreSQL.
  Creation defaults to disabled and atomically persists one initial owner, organization audit
  and 24-hour idempotency receipt. Exact confirmation returns current team state without
  duplicate effects; uncertain commits retain original-key recovery. Bounded worker cleanup
  retires expired receipts without removing team state. Device authentication and refresh now
  sign complete current active memberships while preserving existing refresh scope ceilings.
  Invitations, asset authorization, Shared vaults and dissolution remain separate work.

- Return `404 sync.object_not_found` for absent and foreign Personal vault ids after enrolled
  Device authentication and route-scope checks. SQLite/PostgreSQL HTTP regressions exercise
  vault keys, changes, snapshots, versions, object writes and ACKs with real tokens and DPoP.

- Mount native independent Device admission on SQLite and PostgreSQL with strict source/metadata
  admission, bounded zeroizing input and the shared nonwaiting proof limit. Confirmed admission
  returns 201; exact historical confirmation returns 200 without current authority. Preparation
  deadlines preserve the store-owned COMMIT boundary and published failure flags. Actual HTTP
  coverage connects registration, password login, admission, ordinary Device authentication and
  same-Account K-4/session access, including lost-COMMIT recovery. Inactive Account state and full
  V3/I1 acceptance remain separate work.

- Add atomic SQLite/PostgreSQL independent Device admission using real password-login
  capabilities, complete current-snapshot CAS, fresh Account/Device proofs and shared immutable
  receipts. Success adds one Device/certificate/wrap while preserving old encrypted material.
  Stale state spends the capability without selecting an Account quota; invalid proof, rate and
  checked capacity denials preserve their distinct claim/debt rules. Exact historical
  confirmation survives later root/Device changes and grants no current authority. Response
  bounds and final expiry precede the non-cancellable COMMIT; lost business acknowledgement
  remains unknown. Inactive Account state and full V3 acceptance remain independent gaps.

- Mount native password options/login on SQLite and PostgreSQL using the durable coordinators.
  Source admission precedes body collection; proof/bootstrap validation shares the registration
  concurrency bound. Native metadata, bounded secret buffers, strict errors and audited failures
  reject alternative credentials. Only confirmed transactions disclose attempts or encrypted
  bootstrap/capabilities. Password authentication alone creates no Device or ordinary session.
  Decoded field overages retain their 413 classification even inside a small encoded body.

- Mount native Account registration and exact historical confirmation on both relational
  backends, with strict metadata, zeroizing bounded body collection and immediate 16-job
  proof-work admission. Precommit deadlines preserve unknown business COMMIT outcomes.
  Add registration policy and retained identity-capacity configuration, API-only probe/id
  initialization, fail-closed startup checks and aggregate capacity warnings. Closing new
  registration preserves receipt confirmation; new Device admission remains a separate outcome.

- Mount the native Account request-challenge route with independent durable pre-body source
  admission, strict shared metadata/JSON validation, private Device quotas and audited failures.
  Challenge secrets are returned only after confirmed commit; browser credentials and CORS
  alternatives are rejected. Worker maintenance retires expired challenges and idle debt in
  indexed bounded batches. This endpoint grants no Account, Device or sync authority; separate
  registration and password handlers own their audited protocol transactions.

- Add atomic SQLite/PostgreSQL Account registration and explicit immutable-receipt confirmation.
  Fresh proofs, complete aggregate, D-129 reservation, receipts, challenge consumption and audit
  commit together. Historical confirmation remains available after revocation or registration
  closure, grants no current authority and cannot recreate deleted Accounts. Device freshness
  includes all retained Accounts and canonical cross-role public keys. Unacknowledged business
  commits remain unknown; complete V3 acceptance remains separate work.

- Add durable password options/login and digest-only admission capabilities on SQLite/PostgreSQL.
  Strict shared DTOs, retained Kprobe, synthetic unknown-user probes, fixed-size verifier checks,
  complete signed bootstrap validation, quota admission and mandatory audit share confirmed
  transaction outcomes. A rate rejection retains the attempt and admitted debt. Preparation
  timeout acknowledges rollback; uncertain commits disclose no token or bootstrap. Capability
  capacity is bounded globally and per Account; Account deletion preserves permanent used-id
  digests. Indexed retirement shares the existing once-per-second worker gate. Cross-surface
  inactive Account enforcement remains separate work.

- Advance the SQLite container recovery probe to the Account-id retention migration while
  preserving its pinned historical source and pre-upgrade recovery boundary.

- Add transaction-local initial password Account persistence and bounded complete bootstrap
  validation on SQLite/PostgreSQL. Immutable creation ownership prevents missing credentials
  from becoming legacy state. Password Account K-4 writers preserve encrypted roots, recovery
  material and existing wraps; unsupported transitions return nonretryable conflicts, with
  legitimate exact replay classified first. Caller-owned protocol proofs, admission, receipts,
  consumption and audit must commit atomically. Registration/login routes and Device admission
  remain incomplete; no capability or session is issued by these storage helpers.

- Add independent bounded Account-entry rate/cooldown and digest-only request-challenge
  storage on SQLite and PostgreSQL. Shared capacity and monotonic database time prevent
  replica races, replay and backward-clock debt reset. Transaction-local claim/finish
  helpers compose challenge consumption with mandatory audit and registration state.
  These storage helpers alone do not enable Account registration or password sign-in.

- Removed retired Personal invitation/enrollment and pairing production modules, routes,
  privileges and worker maintenance. Historical migrations, tables and business data remain
  intact. Existing Device authentication and Personal sync continue. Operator setup/login/logout
  remain in the console, which no longer offers invitations. Rust, CI and generated console
  contracts use published `proto@a604b726`. Retained tests seed valid signed legacy artifacts in
  owned databases; the container check covers Operator lifecycle, retired-route absence and
  TLS/SQLite recovery. New Account password registration/bootstrap and Device admission remain
  incomplete.

- Refresh retention-job claim and transition clocks after scheduling while retaining the fixed
  purge cutoff. A long scheduling sweep can no longer backdate a newly claimed lease before its
  job was created. Keep each sweep's availability cutoff separate from its advancing lease
  clock, so failed jobs remain deferred until a later sweep. Deterministic SQLite/PostgreSQL
  regressions cover completion, retry clocks and eligibility after the retry time has elapsed.

- Add Account-id digest retention on SQLite and PostgreSQL, with bounded upgrade reservation,
  a durable admitted ceiling, explicit audited maintenance and a transaction-local registration
  helper. Independent instances serialize new digests; rollback preserves capacity and audit.
  Forward schema guards prevent ordinary digest removal or ceiling reset. Registration HTTP,
  operator maintenance authorization and warning delivery remain separate work.

- Keep probe-key fault-injection trigger creation and removal on one owned connection, so
  SQLite pool schema caches cannot reject a repeated failure fixture as already existing.

- Retain the complete accepted signed K-4 PUT atomically with verified enrollment, publication
  and pairing on SQLite and PostgreSQL. A bounded consistent storage reader rejects damaged or
  mismatched projections, including missing or extra wraps. Existing rows keep no historical
  acceptance claim; lower-level new revisions invalidate evidence and exact replay never
  backfills it. Account registration/login and Device admission remain separate work.

- Added durable current-family Operator logout on SQLite and PostgreSQL. Revocation and its
  deployment audit commit atomically; eligible fresh-proof retries confirm an already revoked
  family without another revocation event. Other families and all retained refresh digests stay
  intact. Current identity, credential, binding and expiry checks also apply after lock waits;
  corrupt stored passkey keys fail closed through the maintained verifier's public-key checks.
  Forward migrations preserve existing authentication admission debt and add independent logout
  quotas. The HTTP adapter and console adoption are separate outcomes.

- Added the SQLite/PostgreSQL storage boundary for an independent Account password probe key.
  Database-serialized initialization and same-value KMS rewrapping commit with deployment audit;
  wrong keys, damaged ciphertext and missing singleton state fail without silent replacement.
  Initialized singleton guards reject reset, removal and replacement through ordinary SQL writes.
  Unconfirmed commits return no key. Account password routes and credentials remain separate work.

- Updated protocol dependencies and generated console types to `proto@439b956`, including
  the current Operator-family logout wire and explicit authenticated operation requirements.
  Existing protected invitation handling requires the business-scope variant explicitly;
  an intrinsic requirement cannot grant invitation authority. Mounting logout is separate.

- Added current Operator-family sign out through the strict DPoP-protected logout HTTP route
  and Personal console. It ignores refresh cookies, revokes and audits only the current family,
  and confirms eligible already-revoked state with a fresh proof. Uncertain outcomes retain the
  original browser credentials for explicit retry before expiry; local tab locking remains a
  separate action. The console serializes session actions and rejects late responses after lock.
  Route-contract CI checks the same published proto revision as the server dependency.

- Added atomic worker retirement of expired device and Operator refresh credentials on SQLite
  and PostgreSQL. Each heartbeat examines at most 16 expired families per kind, removes at most
  256 digests and deletes only empty families. Unexpired and revoked-unexpired reuse evidence
  remains intact. Independent pools, late deletion failure, uncertain commit acknowledgement
  and blocked shutdown are covered; login no longer performs unbounded cascade cleanup.

- Added bounded worker maintenance for pairing sessions on SQLite and PostgreSQL, independently
  of later pairing requests. Each heartbeat expires at most 256 sessions and removes at most
  256 retention-expired sessions, with atomic payload erasure and deployment audit. Unexpired
  sessions and retained receipts are preserved, and shutdown cancels an active pass.

- Fixed disposable Personal fixture preparation on Windows to write ordinary canonical
  local-drive paths accepted by production admission. Bootstrap and restart checks use the
  same normalization and retain exact owned-path checks; Windows ACL and alias restrictions
  remain enforced by the existing server admission.

- Updated Rust protocol dependencies and the generated console API source to `proto@b1748dd`,
  including D-123's secretless interactive Credential descriptor. Older readers reject this
  pre-Stable K-1 registry extension; HTTP/API and K-2 artifacts are unchanged. Sync preserves
  encrypted envelopes without inspecting Credential fields.

- Made per-device object-write admission durable across API instances and restarts on SQLite
  and PostgreSQL. Admission commits before body collection; malformed and oversized attempts
  retain their charge. Exact unsigned fixed-point balances, database time, stored-policy
  transitions and bounded retirement with a persistent clock watermark preserve debt. Storage
  failures, including an unconfirmed admission-only commit, dispatch no business mutation and
  return retryable `sync.storage_unavailable`. Existing wire shapes and defaults are unchanged.

- Connected worker retention to transaction-current Personal device acknowledgements on SQLite
  and PostgreSQL. Complete signed certificate/revocation verification, current admission checks,
  ACK reads and tombstone/history deletion share one transaction. Missing ACKs count as zero;
  inactive or missing unrevoked identities, empty sets and unsupported membership retain the
  180-day policy. Corrupt statements or ACKs fail without partial deletion. Account-before-vault
  locking serializes with pairing, account-key publication and authenticated ACKs. Shared and
  organization device membership remains separate work.

- Added a private, stable deployment lease for server and local `splctl` state access. Running
  processes hold shared admission; offline operations require exclusive admission. Shutdown first
  fences notification streams and drains role tasks and pools for up to 10 seconds. A timed-out
  drain cancels remaining tasks with bounded cleanup, reports a fatal error and retains the lease
  until the host process exits. Real process, incomplete-request, TLS, notification, SQLite
  transaction and Windows permission regressions cover the admission boundary. Encrypted archive
  creation and restoration remain separate roadmap work.

- Added verified, standalone SQLite snapshots before upgrading existing schemas, including
  committed WAL pages. Empty/current databases skip snapshots; snapshot failures stop migration.
  Private snapshots retain the three newest completed recovery points, including after a failed
  migration. A cross-process startup lock prevents duplicate upgrades and remains held when a
  caller cancels initialization. Windows checks existing snapshot and lock ACLs before storage
  startup. Complete encrypted deployment backup, scheduled backup and CLI restore remain planned.

- Added Windows data-directory admission before database/object-storage initialization and
  standalone bootstrap. New directories receive a private inheritable DACL at creation;
  existing directories, custom key parents and private key files with unsafe or unsupported
  access controls are refused without permission repair. A fixed, hidden Windows PowerShell
  5.1/.NET check has a 15-second deadline, handles paths only as data and emits no raw diagnostics.
  Drive admission rejects mapped network drives and roots that cannot be confirmed ready and local.
  Windows-native boundaries and public bootstrap/startup regressions cover creation,
  inherited file protection, broad/NULL ACLs, reparse points and unavailable checking support.
  Operators still control parent-directory safety and existing-material recovery.

- Added a source-built Personal container entry with bundled console assets, direct HTTPS from
  operator-provisioned certificate files, a non-root distroless runtime and persistent private
  SQLite/key storage. Compose requires the public DNS name and certificate directory explicitly.
  The guide covers first-Operator Passkey setup/login, one-use invitation creation, local pending
  setup recovery, verified readiness and restart behavior. A repeatable container check and CI
  job exercise trusted HTTPS, bundled assets, public software-passkey bootstrap and persistent
  restart state, with strictly owned cleanup and private failure evidence. Complete release
  artifacts and backup/restore remain roadmap work.

- Prevented an acknowledged SQLite custom-BEGIN cancellation from returning an open transaction
  to the pool. Connections with remaining tracked transactions are rolled back before reuse;
  failed cleanup discards them. Deterministic worker/acknowledgement barriers cover the exact
  cancellation window, same-connection reuse, failed-cleanup replacement, queued rollback ordering
  and subsequent authentication source admission. This distinct defect does not identify the
  cause of the historical native post-reopen refresh failure.

- Upgraded every Rust protocol dependency and the generated console contract source to
  `proto@e2b8817`, containing D-116 asynchronous agent signing. The server's API, crypto and
  model consumers and the public API artifact retain their existing behavior; server SSH
  execution and host-agent integration remain separate work.

- Added content-free authentication storage diagnostics with request-id correlation, static
  phases/error categories and elapsed time. SQLite busy/locked failures and connection-pool
  failures remain distinguishable without retaining database text. Real HTTP writer-timeout
  and cancelled-admission tests preserve credentials, audit state, pool availability and
  existing recovery flags. The historical native post-reopen refresh failure remains unresolved.

- Moved D-93 read admission into SQLite/PostgreSQL metadata queries before envelope loading.
  The production changes, snapshot and history paths validate full source metadata, select exact
  encoded budgets and load only approved payloads in the same snapshot. First-entry and complete
  history budget failures issue no payload query; short pages load only their selected entries.

- Aligned PostgreSQL sync test vault ids with the UUIDv7 notification contract, restoring
  shared-vault and Personal mutation coverage after transactional notification publication.
  The PostgreSQL CI job now runs the complete 38-test sync storage suite instead of three
  name-filtered subsets.

- Adopted deployment-selected D-91 write limits across request decoding, SQLite/PostgreSQL
  storage admission, ordered assignments and complete request-bound conflicts. Exact CBOR
  request bytes include field/header overhead; higher limits can exceed the former defaults.
  Conflicts keep their independent 128 MiB cap and fail without partial results. Separate
  D-93 read payload/body budgets preserve access to retained data when write limits decrease.
  Changes and snapshots return budgeted prefixes with progress-preserving cursors; an unencodable
  first entry or complete unpaged history fails without partial results.
  New forward migrations retain objects, history, epochs, signers, timestamps and relational
  constraints while removing the fixed envelope ceiling. Added populated-migration,
  501-object, raised-envelope, reopen and certified-signature HTTP regressions on both stores.

- Upgraded the shared protocol pin to `cb4f248`, including the D-75 GET/CONNECT notification
  scope lookup, and regenerated the console's public API types from the same published revision.

- Mounted Personal K-4 notifications on the production TLS listener for classic GET and HTTP/2
  extended CONNECT. The D-75 context/authentication/ready sequence enforces a complete reassembled
  16 KiB message limit and a ten-second deadline including credential verification. Enrolled-device
  JWT, exact method/target/ath DPoP, durable replay, current identity and `sync:read` checks precede
  subscription. Connections close on token expiry, revocation, stalled state checks or backpressure;
  fixed safe close codes distinguish policy, wire and temporary failures. Real SQLite/PostgreSQL
  TLS listener tests cover authentication, isolation, committed-write delivery, H2, denial, replay,
  expiry and revocation. Fragmentation, verification deadlines and stalled I/O have targeted
  regressions. Notification delivery remains single-instance; PostgreSQL fan-out is separate work.

- Mounted all six second-device pairing HTTP operations and the static `/pair` link landing.
  Strict shared JSON codecs, source-before-parse admission, verified capability/account quotas,
  current enrolled-device DPoP and `keys:write` checks enforce the native role boundary.
  Responses prevent caching/referrer disclosure and accept no cookies, mixed credentials or
  credentialed CORS. Failure-audit errors fail closed; unknown business commits preserve
  `changed: true`/`retryable: false` and disclose no capability. Added real SQLite/PostgreSQL
  public bootstrap, seven-slot completion, new-device authentication/key reads, denial and
  quota regressions, lost-create-COMMIT acknowledgement coverage, route manifest and CI.

- Added a durable seven-slot second-device pairing relay and atomic completion on SQLite and
  PostgreSQL. Digest-only capabilities, fixed expiry, original terminal retention, aggregate
  deployment budgets, role/order checks, exact replay and payload erasure share one state
  machine. Completion verifies current identity, signed certificate/history, complete next
  K-4 membership, unchanged account ciphertexts and new-device possession; response overflow
  or audit failure rolls back the full candidate. Retained receipt replay never reverses
  later revocation, and a lost commit acknowledgement discloses no success body. Added real
  signed SQLite/PostgreSQL concurrency, rollback, quota, expiry and lost-commit regressions.

- Added independent durable pairing admission on SQLite and PostgreSQL, with per-route source,
  verified capability and account quotas; denial cooldowns; bounded cleanup; safe failure audit;
  and transaction-local authenticated-success clearing. Counts and cooldowns serialize across
  replicas, and audit failure rolls back denial state.

- Added a registered `personal_live_bootstrap` development example and reproducible disposable
  HTTPS fixture procedure. New private directories hold localhost certificates/configuration;
  public Operator setup, discoverable software-passkey login and authorized invitation issuance
  produce the bounded four-field integration descriptor. SQLite and private loopback PostgreSQL
  profiles use the production binary without identity SQL seeds. The caller manages the server
  process and disposable database; failures publish no descriptor and prohibit automatic replay.

- Mounted `GET /api/v1/accounts/me/devices` with exact enrolled-device `account:read`
  authorization, durable DPoP replay protection and transaction-local caller rechecks on SQLite
  and PostgreSQL. Complete bounded snapshots include every stored signed certificate and
  revocation, including inactive peers, and verify signatures, account bindings and unique
  device ids before disclosure. Corrupt, missing or oversized state fails as a whole. Added
  real public HTTP denial/boundary regressions, concurrent statement and key-bundle coverage,
  the complete Personal flow read, production route manifest and PostgreSQL CI.

- Raised the Tokio minimum and lock to 1.53.3 for RUSTSEC-2026-0386, addressing
  Unix `AsyncFd` I/O safety.

- PostgreSQL runtime readiness and audit-worker tests use private disposable schemas, keeping
  concurrent setup audit events and earlier runs from changing checkpoint assertions. All
  existing assertions remain intact; CI runs both PostgreSQL runtime fixtures together.

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
