# Scoplen server principles

Scoplen is a Plystra project. This record applies the shared adoption record in
[`../scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md) to the
self-hosted server, host agent, administration CLI, and web console.

## Current boundary

- The server owns durable service behavior, role supervision, operator configuration, and the
  web console. It does not own client source or shared wire contracts.
- The vendor does not receive deployment data. Operators control the server's data directory,
  keys, logs, backups, and retention.
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
- SQLite migrations, transactions, sync storage, an atomic retention primitive, and a durable
  leased job queue with worker lease cleanup exist. The API listener mounts the Personal K-4
  subset on SQLite or PostgreSQL with enrolled-device tokens, durable DPoP replay protection,
  current certificates, scopes, vault ownership, signed envelopes, and transaction-local write
  authorization. Configured rate limits apply across connections. Deployment-selected D-91 write
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
  commits. Operator invitation HTTP issuance enforces exact scope and published Cedar policies,
  independent database quotas, and transaction-local session authorization; one-time URLs are
  disclosed only after an audited confirmed commit.
  Enrolled devices can read their complete signed certificate/revocation snapshot with current
  admission checked in the same account transaction. Every statement is verified before
  disclosure; inactive peer rows do not silently filter the signed set, and invalid or
  oversized collections fail without partial results. Signed device claims are not hardware
  attestations or server observation timestamps. Durable pairing storage now serializes bounded
  relay retention, current-device authorization and atomic second-device membership publication
  with its deployment audit on both databases. Exact completion recovery retains its receipt
  without reversing later revocation; uncertain commits disclose no success body. All six native
  pairing HTTP operations now enforce current-device DPoP, exact scope, verified role admission,
  bounded shared codecs and noncacheable responses. The public link landing requests no password
  and runs no script. Remaining device lifecycle mutations remain open.
  The Personal React console connects setup, fresh passkey sign-in and invitation
  requests through the generated public API contract. Its proof key and access token stay in
  memory; reloads require a new login. Manifest-validated static assets fail independently of
  API readiness. Physical passkey/browser interoperability, remaining console administration,
  complete identity and policy workflows, membership-aware purge scheduling,
  certificate, gateway, audit, agent, CLI, and console behavior remain on the roadmap. The worker
  can use the PostgreSQL query backend; API and edge can start with PostgreSQL and check readiness.
- A source-built Personal Compose entry bundles the console, uses externally provisioned HTTPS
  certificates, and retains SQLite and keys in a private volume under a non-root distroless
  runtime. Its public-API container check covers setup, fresh software-passkey login, invitation
  issuance and restart state. Complete deployment, backup/restore, upgrade, physical Passkey
  interoperability and release artifacts still require their own validated gates.

## Review

Review this record with the project record before a new public surface or a maturity change.
