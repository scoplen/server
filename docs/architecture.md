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

The baseline exposes `/healthz`, `/readyz`, and `/metrics`. Logs are JSON tracing events; secret
material is written only under the configured data directory and is never included in request
responses or logs.

The API role loads the React Personal console from `console.assets_dir`, defaulting to
`web/console/dist` relative to the working directory, with `SPL_CONSOLE_ASSETS_DIR` as an override.
The production build records explicit paths, byte lengths and SHA-256 hashes. Startup reads only
bounded manifest files inside the canonical directory, validates all bytes, and holds them in
memory. Fixed entry paths `/` and `/setup` and listed `/assets/*` files have a strict same-origin
CSP, Trusted Types, no-store, no-referrer and nosniff headers. There is no arbitrary filesystem
fallback. A missing or invalid build disables only the console with an actionable 503; the
API and readiness checks continue independently. Edge-only listeners have no console routes.

The entry flow uses public generated OpenAPI types for setup, fresh passkey login, browser
refresh and Personal invitation requests. It scrubs the setup fragment before making requests,
keeps its non-extractable proof key and access token in memory, and never resumes an old cookie
after reload with a newly generated key. Web Locks serialize refresh. Unknown business outcomes
require explicit recovery without automatic replay; locking a tab clears local session material.
The UI uses local Inter, Lora and JetBrains Mono fonts without third-party requests.

`scoplen-identity` consumes the bounded D-101 Personal enrollment request from `scoplen-api`.
It validates the trusted canonical origin and three existing signatures, then exposes the token
digest, bound origin and ids, and exact canonical K-4/K-2 artifacts through a read-only verified
value. Structurally invalid input remains separate from identity or signature denial; neither
error contains submitted material. This in-memory verification does not check invitation state,
persist an account or device, grant a token, or mount an enrollment route. Those operations still
require operator authentication and one durable identity transaction.

First-run material is created exclusively and flushed before success. On Unix, new files have
owner read/write permissions from creation, before any secret is written. Existing files,
including symlink destinations, are never overwritten. An incomplete CA pair requires operator
recovery; bootstrap does not replace its surviving file. Windows uses the data directory's
inherited access controls; protect the directory before first startup. Windows ACL restriction
and validation are not implemented. Existing deployment file permissions are not changed.

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
The SQLite sync store allocates a contiguous sequence range inside a write transaction, checks
every compare-and-swap base before changing state, and exposes current change and
full-reconciliation snapshot pages without interpreting envelope bytes. Both relational stores
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
listener mounts Personal enrollment, device authentication, Operator setup/login/refresh and
the authenticated Personal sync subset. The injected sync router selects one SQLite or PostgreSQL
backend for its account-key, object-sync, and shared-vault operations.
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
expired leases; the `worker` role runs this cleanup from a 30-second heartbeat. Policy filtering,
retention job scheduling and membership-aware tombstone purge orchestration run through the same
bounded worker paths on SQLite and PostgreSQL. API/edge PostgreSQL startup and listener readiness
are available; remaining shared-sync router mounting, application-level
column encryption, control-plane audit event producers, and other worker jobs remain roadmap work.
The storage boundary defines a redacted local deployment-key-file backend behind a KMS trait;
cloud adapters, column encryption, and external KMS readiness remain open. Database-backed role
preparation loads and validates the local backend before startup. Bootstrap creates an independent
Ed25519 `audit-signing.key`; the worker writes hourly idempotent checkpoints for advanced audit
heads. `storage.kms.backend`,
`storage.kms.key_file`, and `storage.kms.audit_key_file` are also available through the documented
TOML and environment configuration. Audit retention/export integration remains open.
