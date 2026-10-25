# Server architecture

`spl-server` is a single process with role selection. The role names are `api`, `worker`, `ca`,
`edge`, and `gateway`; `all` expands to those roles in a stable order. The process loads one TOML
configuration, applies non-empty `SPL_` environment overrides, and validates local invariants.
It creates first-run material when a database-backed role is selected, then starts the selected
roles. Standalone `ca` and `gateway` roles do not open a database or create Personal setup material.

The public listener is one TCP port. In `plain` mode it is intended to sit behind a trusted TLS
terminator. In `files` mode it terminates TLS itself and advertises `h2`, `http/1.1`, and
`spl-gw/1` through ALPN. In `acme` mode it obtains and renews a certificate through Let's Encrypt
TLS-ALPN-01, persists the ACME account and certificate cache below the data directory, and uses
the same ALPN set for application connections. The gateway protocol is reserved for the managed
data-path gate and is not accepted by the baseline listener yet.
The file-certificate listener explicitly selects Rustls's AWS-LC provider and supported default
TLS versions, so dependencies enabling a second provider cannot make startup panic or change its
provider through process-global state.

The trusted public HTTPS origin comes from canonical `server.public_host` and external
`server.public_port`, independently of the local `server.listen_port`. The shared K-3 origin
validator rejects ambiguous hosts before startup. Bootstrap uses this origin for setup links;
incoming Host and forwarding headers do not determine it.
For every database-backed role, startup reads the retained Operator setup origin before creating
object storage or local key and CA material. A mismatch with the effective public host and port
stops startup without replacing the entitlement or disclosing the retained origin. The API role
also rechecks the origin inside its setup initialization transaction. Explicit local reissue can
replace only a pending entitlement; completed setup requires an identity-preserving migration
procedure before its origin can change.

The Rust protocol consumers and generated console API types use the published
`proto@a604b726` revision. This workspace consumes only `scoplen-api`, `scoplen-crypto` and
`scoplen-model`. This revision includes the Account password and Device admission contracts
and removes retired Personal invitation/enrollment and pairing formats. Consuming these
contracts does not mount the new Account entry endpoints.
The server stores encrypted object envelopes
without inspecting Credential fields. D-121 interactive SSH authentication belongs to
`scoplen-ssh`, which this workspace does not consume. Server SSH execution and host-agent
integration remain separate roadmap work.

The baseline exposes `/healthz`, `/readyz`, and `/metrics`. Logs are JSON tracing events; secret
material is written only under the configured data directory and is never included in request
responses or logs.

Device-refresh storage warnings carry only the request id, the fixed endpoint, an operation
phase (`source_admission`, `keyring`, or `refresh_transaction`), a static error category and
elapsed milliseconds. Admission receipt is a debug event with the same request id. Storage
classification discards the original database error and distinguishes SQLite busy/locked,
pool timeout and pool closure from other database failures. No SQL text, URL, proof, token or
submitted content is logged. These events locate future failures without changing HTTP
responses or automatically replaying refresh credentials after an uncertain commit.
SQLite uses a five-second busy timeout; WAL permits readers while an unrelated writer holds
its reservation, but another writer can still fail before source admission is committed.
Controlled HTTP contention and admission-cancellation tests cover those boundaries. They do
not identify the cause of the observed native post-reopen refresh failure.
The SQLite pool also rolls back a remaining tracked transaction before returning a connection to
the idle queue, discarding it if cleanup fails or it remains in a transaction. SQLx 0.8.6 acknowledges
a custom `BEGIN IMMEDIATE` before asynchronously validating its handle; cancellation in that
window can leave an open transaction without a constructed `Transaction` guard. A controlled
worker/acknowledgement regression reproduces that separate defect and checks same-connection
reuse, failed-cleanup replacement, queued-rollback ordering and subsequent real source admission.
No business operation is retried or detached, and unknown refresh commit recovery is unchanged.
For a private diagnostic run, `RUST_LOG=info,scoplen_server::device_auth=debug` includes
admission receipt; storage warnings are already visible at the default info level.

The API role loads the React Operator console from `console.assets_dir`, defaulting to
`web/console/dist` relative to the working directory, with `SPL_CONSOLE_ASSETS_DIR` as an override.
The production build records explicit paths, byte lengths and SHA-256 hashes. Startup reads only
bounded manifest files inside the canonical directory, validates all bytes, and holds them in
memory. Fixed entry paths `/` and `/setup` and listed `/assets/*` files have a strict same-origin
CSP, Trusted Types, no-store, no-referrer and nosniff headers. There is no arbitrary filesystem
fallback. A missing or invalid build disables only the console with an actionable 503; the
API and readiness checks continue independently. Edge-only listeners have no console routes.

The entry flow uses public generated OpenAPI types for setup, fresh passkey login, browser
refresh before initial sign out and current-family logout. It scrubs the setup fragment before making requests,
keeps its non-extractable proof key and access token in memory, and never resumes an old cookie
after reload with a newly generated key. Web Locks serialize refresh. Unknown business outcomes
require explicit recovery without automatic replay; locking a tab clears local session material.
The UI uses local Inter, Lora and JetBrains Mono fonts without third-party requests.

`scoplen-identity` exposes the maintained Operator passkey verifier. Retired Personal
invitation/enrollment and pairing modules, routes, privileges and worker cleanup are absent.
Historical schema and data remain intact and unused by runtime. Existing Devices continue to
use public authentication and Personal sync. Account password registration/sign-in, bootstrap
and new Device admission remain incomplete; consuming their published contracts does not mount
those endpoints. Tests directly seed real signed artifacts only into owned fixture databases.

First-run material is created exclusively and flushed before success. On Unix, new files have
owner read/write permissions from creation, before any secret is written. Existing files,
including symlink destinations, are never overwritten. An incomplete CA pair requires operator
recovery; bootstrap does not replace its surviving file. Windows permission admission runs
before database/object-storage initialization and at the public bootstrap entry. New data
directories receive a protected DACL at creation; existing directories, custom key parents and
private key files are inspected without repair. Only ordinary server-account/System/Administrators
allow entries and matching trusted ownership are accepted, with inheritable server full control
for directories. Reparse points, NULL DACLs and unsupported ACLs fail closed. A fixed hidden,
noninteractive OS Windows PowerShell 5.1 process uses .NET access-control APIs and a 15-second
deadline; paths are data and child output is discarded. See
[Windows data-directory permissions](windows-data-directory.md). Parent-directory write and
replacement safety remains the operator's responsibility.

The relational storage boundary supports SQLite or PostgreSQL for `api`, `worker`, and `edge`.
SQLite roles open `server.data_dir/scoplen.sqlite`, enable WAL and foreign keys on pooled
connections, and apply embedded forward migrations before generating first-run material.
PostgreSQL roles use `storage.database_url` and apply the parallel migrations before generating
first-run material. The migrations establish the organization table plus the sync storage
foundation: vault counters,
current opaque object envelopes, retained version rows, per-device acknowledgement cursors, the
account key-bundle tables, and per-organization audit events and signed checkpoints. Account key
artifacts remain opaque at this boundary; the store
scopes wrapped-ARK reads to the authenticated device and applies atomic revision replay rules.
Personal account-key publication retains the original certificate and DPoP binding while receiving
the body. Its required authenticator commit hook reauthorizes inside the account transaction,
verifies the current root signature and complete certified-unrevoked recipients, and atomically
applies the revision, all wraps, response bounds and business audit. SQLite uses BEGIN IMMEDIATE;
PostgreSQL shares the exclusive account lock with statement replacement, and locks
the identity rows against account/device changes. Exact replay reauthorizes and compares all
signed bytes, without a new signature check or audit. New-update COMMIT uncertainty has
`changed: true`, `retryable: false`; confirmed rollback and replay-close failures have no business
mutation. There is no public-root replacement, ARK rotation or revocation workflow in this route.
Both new publication and replay retain trusted token expiry and check its validity after lock
acquisition/current identity loading and immediately before COMMIT.
The SQLite sync store allocates a contiguous sequence range inside a write transaction, checks
every compare-and-swap base before changing state, and exposes current change and
full-reconciliation snapshot pages without interpreting envelope bytes. Both relational stores
validate deployment-selected envelope/count/complete CBOR request-byte limits before mutation;
the HTTP adapter uses the same D-91 limits for requests, ordered assignments and complete
request-bound conflicts. The conflict cap stays at 128 MiB; encoding failure returns 503 without
truncation. D-93 read payload/body budgets are configured independently, preserving access to
retained larger data after write limits decrease. Changes and snapshots select the longest
encodable prefix from at most 1,001 metadata rows, including lookahead. Shared structural
validation covers the full requested source page before prefix selection; exact CBOR size checks
precede the sequence- and length-guarded payload query. Metadata and selected payloads share one
SQLite read transaction or PostgreSQL read-only repeatable-read snapshot, and loaded rows must
match admitted metadata. Complete history is admitted from at most 21 metadata rows before any
payload query. An unencodable first entry or complete history returns 503; history is never
truncated. HTTP exclusively calls the bounded store interfaces and validates the encoded response
through the shared codecs. The raw internal store interfaces retain storage-only semantics.
History counts and key and notification resource bounds remain fixed and independent. An additive
forward migration replaces the old envelope ceiling with a nonempty check, preserving all data
and relational constraints; SQLite rebuilds both leaf tables transactionally and PostgreSQL
replaces the checks.
Both relational stores
atomically provision one personal vault and its opaque wrapped key per account, scope key reads to
the owner, and list the account's personal vault and current shared memberships. Both stores
atomically create a shared vault with its admin membership and epoch-one wrap, enforce the
per-account shared-vault quota, and read only a member's non-retired wraps. PostgreSQL also
serializes CAS batches on the vault row, enforces its configured object limit, assigns gap-free
sequences, serves current changes and full-reconciliation snapshots from read-only repeatable-read
transactions, reads up to 21 retained object versions, and stores monotone device ACKs.
Both stores serialize epoch publication, member addition/removal, and epoch retirement with vault
writes. PostgreSQL member addition also takes the account quota lock used by vault creation before
locking the vault, so concurrent joins across vaults cannot exceed the account limit. Historical
wraps cascade when a member is removed, and retired epochs stay unavailable to new writes.
A migration error
prevents startup. `/readyz` queries the database and returns 503 when the query fails. The API
listener mounts existing Device authentication, Operator setup/login/refresh/logout and
the authenticated Personal sync subset. The injected sync router selects one SQLite or PostgreSQL
backend for its account-key, object-sync, and shared-vault operations.
Object POST admission uses a separate short transaction before body collection. The store owns
the validated rate settings and fixed-point arithmetic; the HTTP layer reexports those settings
and advertises them in the session. SQLite reserves the writer before sampling database time. PostgreSQL
upserts the device bucket to serialize first insertion and existing debt before sampling
`clock_timestamp()`. Admission does not hold account/vault locks or keep the bucket lock through
body validation and business mutation. A failed or unconfirmed admission transaction dispatches
no business write and has `changed: false`, `retryable: true`.
Retirement uses an indexed, fixed set of at most 16 fully refilled idle candidates. PostgreSQL
skips locked rows inside that set without finding replacement candidates. Candidate locks precede
the singleton retirement-clock update, which commits atomically with deletion. Ordinary
admission only reads that clock through a non-locking query. Preserved clock history prevents a
deleted bucket from gaining early refill after database time rolls backward. Fixed-width
big-endian bytes preserve positive `u64` settings and exact `u128` balances/horizons in both
backends; no floating-point or signed count narrowing participates in rate admission.
It delegates authentication, signature verification, membership, and policy decisions to the
service. Notification events are encoded by `scoplen-api` and delivered only to authenticated
device subscriptions through a process-local broadcast hub. SQLite publishes after a committed
write. PostgreSQL queues content-free hints inside the mutation transaction and uses schema-scoped
`LISTEN`/`NOTIFY` for both local and cross-instance delivery. An owned listener and bounded
64-hint dispatcher recheck current recipient authorization with five-second deadlines. Startup
awaits LISTEN; readiness fails while it is unavailable. Observed gaps, queue overflow,
authorization outages, and worker shutdown fence current sockets with 1011; sockets opened
during an outage also fail with 1011. Fresh LISTEN restores admission after bounded reconnect
attempts. Hints remain best effort and clients reconcile or poll after interruption. A parallel
PostgreSQL migration set is checked against the SQLite logical schema in tests.
`scoplen-store` also exposes a backend-neutral object
storage boundary for local filesystem and S3-compatible stores, with validated keys and streaming
or multipart access. Database-backed roles initialize the configured object backend at startup and
`/readyz` checks its reachability alongside the relational database. The durable job queue stores
bounded opaque payloads, claims jobs with owner-checked leases, records retries, and requeues
expired leases; the `worker` role runs this cleanup from a 30-second heartbeat.
Worker retention scheduling visits every vault through strictly increasing id pages of at most 1,000
entries on SQLite and PostgreSQL. Each sweep captures its greatest id before paging, defers
later appended ids, and restarts from the beginning on the next heartbeat to discover ids
inserted behind its cursor.
Shutdown can interrupt an active retention sweep; unfinished durable jobs keep their existing
deduplication, lease and retry behavior. Retention jobs use the same SQLite/PostgreSQL transaction
for Personal ownership, complete bounded signed certificates/revocations, current admission
identities, ACKs, tombstone/history deletion and the purge horizon. The signed set is validated
once and at most 1,000 unrevoked identities are streamed and checked in device-id order; each
identity's current certificate/root/account binding and P-256
proof-key thumbprint use the same verifier as device authentication. Missing ACKs count as zero.
Inactive or missing unrevoked identities cannot shrink the signed set: they disable early
purging, as do empty sets, unsupported vault kinds and absent enrollment state. Those vaults
retain the 180-day policy. Invalid signed state, mismatched current identities and ACKs ahead of
the vault fail atomically and retain the job for retry. SQLite begins
with its writer lock. PostgreSQL discovers the candidate owner, takes the shared seed-0 account-key
lock, locks current identity and ownership rows, then locks the vault and rechecks ownership before
reading ACKs. This serializes with exclusive account-key publication and follows the
account-before-vault order used by authenticated ACKs and object writes. The raw caller-supplied
floor primitive and the worker entry share their backend's transaction-local purge SQL.
Shared/organization membership-aware purging and policy filtering remain open. API/edge PostgreSQL
startup and listener readiness are available; remaining shared-sync router mounting,
application-level column encryption, control-plane audit event producers, and other worker jobs
remain roadmap work.
The storage boundary defines a redacted local deployment-key-file backend behind a KMS trait;
cloud adapters, column encryption, and external KMS readiness remain open. Database-backed role
preparation loads and validates the local backend before startup. Bootstrap creates an independent
Ed25519 `audit-signing.key`; the worker writes hourly idempotent checkpoints for advanced audit
heads. `storage.kms.backend`,
`storage.kms.key_file`, and `storage.kms.audit_key_file` are also available through the documented
TOML and environment configuration. Audit retention/export integration remains open.

Account-id retention is independent of Account rows and normal device authorization. A forward
migration creates a digest-only table and an uninitialized deployment guard. Before registration
can use the storage helper, explicit initialization reserves every current Account id in pages
of at most 256 rows, under a database writer/guard lock, and admits one durable ceiling with its
audit. PostgreSQL also locks the legacy Account table during that initial reservation. A failure
rolls back the entire reservation; unsupported legacy ids require recovery rather than omission.
Repeated initialization requires the same ceiling and preserves an explicit maintenance state.
Guard writes serialize final-slot admission and reject stale PostgreSQL repeatable-read snapshots
before a retained-count decision. SQLite checks byte storage explicitly and scans the first
legacy-id page without a type-dependent lower sentinel.
The helper must be called before Account/vault locks in the same transaction as verified
registration, its receipt and audit. It uses the published shared digest, adds no permanent
Device, vault or operation-id collection, and never commits independently. Ordinary Account
deletion cannot cascade into the retained set. Maintenance quiesces new registration writers;
audited ceiling increases preserve every digest. These storage methods grant no operator
authorization and expose no new HTTP route. Mounted registration, configuration/admission wiring,
operator warning delivery and complete backup/restore acceptance remain separate roadmap work.
