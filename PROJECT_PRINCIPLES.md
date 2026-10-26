# Scoplen server principles

Scoplen is a Plystra project. This record applies the shared adoption record in
[`../scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md) to the
self-hosted server, host agent, administration CLI, and web console.

## Current boundary

- The server owns durable service behavior, role supervision, operator configuration, and the
  web console. It does not own client source or shared wire contracts.
- The vendor does not receive deployment data. Operators control the server's data directory,
  keys, logs, backups, and retention.
- `splctl doctor` validates configuration and checks trusted public HTTPS health/readiness
  without opening storage or changing deployment state. Full diagnostics and console parity
  remain open roadmap work.
- Windows bootstrap and storage startup create private missing data directories and reject
  unsafe existing directory/key ACLs through bounded OS PowerShell 5.1/.NET admission, without
  rewriting existing permissions. Operators retain parent-directory and recovery responsibility;
  see [the Windows procedure](docs/windows-data-directory.md).
- Before upgrading an existing SQLite schema, startup preserves a verified standalone recovery
  snapshot including committed WAL pages and retains three private completed recovery points.
  Snapshot failure stops upgrade; explicit offline recovery still requires the matching server
  version, deployment keys and local objects. Complete encrypted backup and CLI restoration
  remain separate roadmap gaps.
- The repository is Exploration maturity until the roadmap evidence is complete. The baseline
  listener is useful for local development and reverse-proxy integration; it is not a complete
  production server.

## Open gaps

- ACME TLS-ALPN-01 issuance and renewal are integrated; live CA issuance and renewal have not been
  verified against an external authority.
- SQLite migrations, transactions, sync storage, atomic Personal retention, and a durable
  leased job queue with worker lease cleanup exist. The API listener mounts the Personal K-4
  subset on SQLite or PostgreSQL with enrolled-device tokens, durable DPoP replay protection,
  current certificates, scopes, vault ownership, signed envelopes, and transaction-local write
  authorization. D-122 configured per-device rate limits persist across API instances and
  restarts in both databases. Short pre-body admission, full unsigned fixed-point balances,
  stored-policy transitions and bounded clock-safe retirement preserve token debt. Admission
  failure never dispatches an object mutation. Deployment-selected D-91 write
  exchange limits apply consistently in HTTP and both stores, with exact encoded request
  admission, complete ordered responses and a fixed conflict cap. Independent
  D-93 read budgets can retain larger history after writes are lowered. Metadata admission
  precedes payload loading in the production reader, with bounded SQL projection and consistent
  snapshots; the complete source metadata is validated before selecting a shorter page.
  Forward migrations preserve current/history rows and relational constraints while removing the
  fixed default envelope ceiling.
  Personal notifications now use D-75 GET/H2 CONNECT context/authentication/ready, durable JWT/DPoP admission, bounded
  transport and current-state checks, expiry/revocation closure and the committed-write local hub.
  PostgreSQL now publishes transactional content-free hints through schema-scoped LISTEN/NOTIFY,
  with bounded local dispatch, current recipient authorization, supervised recovery and generation
  fences closing sockets on gaps or overflow. Personal account-key publication rechecks the
  original identity and token lifetime under the account transaction, verifies complete signed
  recipients, and commits revision, response bounds and audit atomically. Exact replay and
  uncertain commits retain distinct recovery semantics. Shared-vault mutations, public-root
  replacement, ARK rotation and device revocation workflows remain open.
  Durable first-operator
  setup and maintained WebAuthn verification exist on both stores, including discoverable login,
  audit-atomic browser-session creation, cookie rotation, matching-token reuse revocation and
  transaction-local current-session authorization. Strict setup/login HTTP routes and cookie-only
  Operator refresh enforce exact Origin, durable DPoP/admission and non-disclosure after unknown
  commits. Current-family Operator logout is implemented at the storage boundary on both
  databases, with current credential/key validation, post-wait expiry checks, atomic revocation
  audit and fresh-proof terminal confirmation. It preserves other families and unexpired
  digests. The public HTTP route and console use the same current-family boundary.
  Current-family Operator logout uses the independent access token and a fresh token-bound
  proof, ignores refresh cookies and serializes revocation with its audit. Confirmed terminal
  retry cannot authorize other operations. Uncertain logout outcomes preserve the original
  browser credentials for explicit retry before expiry; local Lock makes no server-revocation
  claim. Same-tab session actions are serialized and late responses are fenced after Lock.
  The Account password probe-key storage boundary separately persists one random Kprobe under
  KMS protection. Database-serialized initialization and same-value rewrapping are audit-atomic;
  unknown commits return no key, and damaged/missing state never triggers silent replacement.
  A separate transaction-local boundary creates only new password Account aggregates and reads
  their complete verified public/encrypted bootstrap. Creation-only ownership prevents missing
  credentials from becoming legacy state. Existing key writers reject unsupported password
  transitions and preserve legitimate exact replay. Caller-owned challenge/proof verification,
  admission, receipts, protocol consumption and audit remain required in the same transaction;
  these helpers never commit or issue authority. Protocol coordinators own their enclosing
  audited transactions; complete Account-entry acceptance remains open.
  Independent bounded Account-entry admission and digest-only request challenges use durable
  database time and shared replica capacity. Transaction-local consumption requires mandatory
  audit with its owning mutation, while receipt-only confirmation adds no duplicate success
  audit. Complete Account-entry acceptance remains open.
  The separate registration coordinator verifies fresh possession and owns one complete business
  transaction, mandatory audit and immutable bounded receipts. Explicit historical confirmation
  survives later revocation or registration closure, but supplies no current authority or negative
  receipt. New-business commit uncertainty remains explicit; global Device freshness includes
  legacy and retained receipt state, without an unbounded side cache.
  Native registration HTTP enforces source admission before body collection, strict transport,
  bounded zeroizing input and 16 nonwaiting proof jobs. Known creation and historical confirmation
  have separate responses; unacknowledged business COMMIT retains exact-confirmation recovery.
  API-only startup initializes retained probe/id state and rejects KMS or ceiling drift before
  listener admission. Closing registration preserves historical confirmation and existing access.

  Password options/login now compose strict shared DTO decoding, retained-key synthetic probes,
  fixed-size verifier comparison, complete bootstrap validation, transient capability insertion
  and mandatory audit in durable transactions. Rate rejection retains both attempts and admitted
  debt. Preparation cancellation explicitly rolls back before bounded fixed failure audit;
  COMMIT is never cancelled and an unknown commit returns no capability. Digest-only capability
  consumption stays transaction-local and Account deletion leaves permanent used-id retention.
  Native password HTTP composes these coordinators with strict metadata, zeroizing bounded bodies,
  source admission and the same nonwaiting proof semaphore as registration. Unconfirmed options
  or login transactions disclose no attempt, token or bootstrap. Cross-surface inactive Account
  enforcement and complete V3 acceptance remain open.
  Independent Device admission now revalidates a real password capability against the complete
  transaction-current bootstrap before Account/Device proof and established Account admission.
  Stale CAS invalidates the capability without claiming old-root proof verification or charging
  Account quota. Success commits only one new Device/certificate/wrap, its signed next PUT,
  immutable receipt and challenge/capability consumption with mandatory audit. Invalid proof,
  rate and unchanged capacity denials preserve their explicit claim/debt semantics. Historical
  confirmation uses only exact receipt facts and the original root/Device keys; it neither
  restores authority nor repeats success audit. Full response bounds and both final expiries
  precede an uncancelled COMMIT. Shared receipt/freshness helpers preserve the registration
  boundary. Native admission HTTP now composes the coordinator with actual-peer source checks,
  strict native metadata, zeroizing bounded input, the shared 16-job proof bound and 15-second
  preparation budget. Store-owned COMMIT remains uncancelled. Confirmed admission and historical
  confirmation return 201 and 200; uncertain business outcomes retain explicit recovery.
  Actual HTTP lifecycle coverage reaches ordinary Device authentication and same-Account
  K-4/session reads on both databases. The schema has no Account active/suspended state; that
  enforcement and complete identity acceptance remain independent gaps.
  Worker refresh retirement is atomic across device and Operator state: each heartbeat examines
  at most 16 expired families per kind, removes at most 256 digests and deletes only empty
  expired families. Family locks precede token deletion and expiry is rechecked after locking;
  every unexpired family and spent digest, including revoked families, remains intact. Ordinary
  shutdown can cancel blocked maintenance. Logs contain only confirmed counts and fixed errors.
  Enrolled devices can read their complete signed certificate/revocation snapshot with current
  admission checked in the same account transaction. Every statement is verified before
  disclosure; inactive peer rows do not silently filter the signed set, and invalid or
  oversized collections fail without partial results. Signed device claims are not hardware
  attestations or server observation timestamps. Retired Personal invitation/enrollment and
  pairing production modules, routes, privileges and worker cleanup are removed. Their historical
  migrations and tables remain untouched and unused by runtime. Existing Device authentication
  and Personal sync continue. Complete password-account acceptance remains incomplete.
  Account-owned team creation and current-membership discovery use the same enrolled Device
  boundary, independently of asset authorization. Explicit creation policy defaults to closed;
  one transaction persists the team, sole initial owner, organization audit and 24-hour receipt.
  Exact confirmation requires current membership and preserves the original mutation. Bounded
  worker maintenance retires only expired receipts. Authentication and refresh include every
  current active membership while retaining the original refresh-family scope ceiling.
  Name-only settings use transaction-current Account/Device and tenant Membership verification,
  canonical Cedar `manage_organization`, exact `orgs:write` and strong Resource preconditions.
  Name, durable update time and organization audit commit atomically; matching unchanged names
  do not write. Unconfirmed updates require an explicit read and reviewed edit, independently of
  original-key creation confirmation. Custom-policy/group storage and broader Cedar graph
  integration remain open.
  Team invitations, asset permissions, Shared vaults and dissolution remain open.
  The Operator React console connects setup, fresh passkey sign-in and
  explicit server sign out through the generated public API contract. Its proof key
  and access token stay in memory; reloads require a new login. Manifest-validated static assets fail independently of
  API readiness. Physical passkey/browser interoperability, remaining console administration,
  complete identity and policy workflows, Shared/organization membership-aware purging,
  certificate, gateway, audit, agent, CLI, and console behavior remain on the roadmap. The worker
  can use the PostgreSQL query backend; API and edge can start with PostgreSQL and check readiness.
  Personal worker retention verifies complete signed statements and current identities before
  reading every device's ACK and deleting tombstones in one transaction. Missing ACKs count as
  zero; incomplete/empty admission state keeps the 180-day policy. Corrupt identity or ACK state
  fails without partial deletion. SQLite takes the writer lock before reading membership;
  PostgreSQL takes the shared account-key and identity locks before locking the vault, so
  key publication, ACKs and retention keep a consistent order.
- A source-built Personal Compose entry bundles the console, uses externally provisioned HTTPS
  certificates, and retains SQLite and keys in a private volume under a non-root distroless
  runtime. Its public-API container check covers setup, fresh software-passkey login/logout,
  retired-route absence and persisted restart state. Its independent Account check uses real
  public password registration/login, fresh Device admission, native authentication/refresh
  and signed encrypted Host synchronization in both directions, without SQL identity seeds.
  Complete deployment, backup/restore, upgrade, physical Passkey
  interoperability and release artifacts still require their own validated gates.

## Review

Review this record with the project record before a new public surface or a maturity change.
