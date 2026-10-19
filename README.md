# Scoplen server

The self-hosted Scoplen server, host agent, administration CLI, and web-console workspace.
Scoplen is a Plystra project. This repository is licensed under AGPL-3.0-only.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline (roadmap V1) is complete. The
current binary provides role selection, validated TOML and `SPL_` environment configuration,
first-run deployment material, a single public listener, health/readiness/metrics endpoints, and
plain, file-based, or ACME TLS. The `api`, `worker`, and `edge` roles open the selected SQLite or
PostgreSQL database and apply forward migrations; readiness checks that database. The SQLite
storage layer has the first sync foundation: per-vault gap-free sequence allocation, atomic
compare-and-swap batches, current change and snapshot paging, acknowledgement cursors, and
bounded version reads. It also exposes an atomic retention pass for the worker: historical rows are
version plus 20 retained versions, and acknowledged or expired tombstones advance the purge
horizon while deleting their retained history. The `scoplen-store` queue now persists opaque jobs
with bounded payloads, atomic claims, owner-checked leases, retry/failure state, and expired-lease
requeue; the `worker` role runs a 30-second heartbeat that requeues abandoned leases.
Standalone `ca` and `gateway` roles do not open a database or generate Personal setup material.
New bootstrap material uses exclusive file creation and, on Unix, owner read/write permissions
(`0600`). Existing files are preserved; an incomplete CA pair requires recovery from the
operator's backup. Windows inherits the data directory's access controls: the operator must
protect that directory before first startup. Bootstrap does not restrict or validate its Windows
ACL, so a directory that grants other users access also exposes generated secrets to them.
Existing deployments retain their current file permissions, which the operator must restrict
separately if needed.
The `scoplen-sync` crate now exposes a K-4 HTTP/CBOR router for a session handshake that lists
account-owned personal vaults and current shared-vault memberships with their rotation state,
shared-vault creation, key retrieval, epoch publication, and member addition and removal, plus
account key bundles, changes,
snapshots, version reads, object writes, acknowledgements, and the authenticated
`/sync/v1/notify` WebSocket. The notification adapter accepts an opaque first credential message,
applies an injected device policy, and fans out deterministic CBOR events through a caller-owned
local hub. Committed object writes publish a vault-advancement hint to connected devices that
still pass notification and vault-read authorization; notification delivery cannot roll back a
write, and clients can fall back to polling. This fan-out remains process-local. The router
requires an injected authenticator that binds DPoP proofs to the request method and
URI, authorizes vault, account-key, and notification operations, records the creator's initial
shared-vault membership and opaque epoch-1 key wrap, adds and removes members with historical
opaque wraps, validates account-key signatures and active-device wraps, and validates encrypted
envelopes before storage. The caller selects a SQLite or PostgreSQL store for the entire
authenticated router. The PostgreSQL path has been exercised through HTTP/CBOR against PostgreSQL
17; the baseline listener does not mount either backend without production identity. The
`scoplen-identity` crate verifies a decoded D-101 first-device
enrollment's K-4 account signature, K-2 device certificate, and origin-bound P-256 possession
proof. It returns a redacted, read-only verified value with the invitation-token digest and exact
canonical artifacts for a future atomic redemption transaction. It neither checks invitation
state nor enrolls a device; operator authorization, durable identity, challenge/device token
exchange, and the production enrollment route remain incomplete. All server proto dependencies
are pinned to `scoplen-proto@e288515` for this shared contract.

The `scoplen-store` crate now provides a backend-neutral object
storage boundary with local filesystem and S3-compatible implementations, including bounded key
validation and streaming/multipart operations; database-backed roles initialize the configured
backend and include it in `/readyz`. Production identity
and authentication, policy filtering, membership-aware purge orchestration, multi-instance
notification fan-out, organization vault ownership in session listings, higher wire ceilings and
other route body limits, control, gateway, and console behavior are still
roadmap work. The audit crate and SQLite store now provide bounded canonical-event SHA-256 chain
hashing, same-transaction append helpers, checkpoint payload construction, durable checkpoints,
and chain verification. The worker signs an advanced chain head at most hourly with an independent
Ed25519 seed and writes idempotent checkpoints; control-plane event producers and retention export
wiring remain open. The storage crate also validates and redacts a local 32-byte deployment
key-file backend behind the `KeyManagementService` trait; cloud KMS, PKCS#11, column encryption,
and external KMS runtime wiring remain open. Database-backed role preparation now loads and
validates the local backend before startup. Bootstrap also creates the independent
`audit-signing.key`; `storage.kms.backend = "local"`, `storage.kms.key_file`, and
`storage.kms.audit_key_file` are configurable in TOML or via `SPL_STORAGE_KMS_*` environment overrides.
For a stale object-write batch, the sync adapter returns every conflicting object in request order
with its current change or an explicit absent value. If a stored change cannot be encoded within
the K-4 bounds, it returns `503 sync.storage_unavailable` instead of an incomplete conflict body.
Authenticated change, snapshot, object-version, account-key, and vault-key reads also return
`503 sync.storage_unavailable` when persisted data cannot form a valid complete response; malformed
caller input retains its request error and no partial success body is sent.
The SQLite and PostgreSQL sync stores enforce configured current-object, shared-vault-per-account,
and member-per-vault cardinality limits in mutation transactions. Defaults are 100,000 current
objects per vault (including tombstones), 1,000
shared vault memberships per account, and 1,000 accounts per shared vault. The K-4
session advertises these limits. Quota rejection returns `413 sync.quota_exceeded` without changing
state. Member limits cannot exceed 1,000 because epoch publication requires one key wrap per member
and the current wire codec accepts at most 1,000 wraps. The authenticated K-4 router enforces configured
per-device write rates in a process-local token bucket and advertises those same values in the
session (defaults: 50 requests per second, burst 200). An exhausted bucket returns
`429 sync.rate_limited` and `Retry-After`. The router also enforces configured envelope bytes,
batch object count, and encoded batch bytes, advertises those bounds in the session, and returns
`413 sync.invalid_request` for an oversized write before changing state. These three bounds may be
lowered from their defaults; the current K-4 codec and SQLite store prevent raising them.
Account-key updates, shared-vault epoch publication, and member addition each enforce their fixed
4 MiB K-4 request bound before collecting the body and return `413 sync.invalid_request` when
oversized. Shared-vault creation enforces its fixed 64 KiB wrap plus 256-byte encoded-body bound
the same way. The session handshake enforces its fixed 4 KiB request limit before collecting the
body and returns `413 sync.invalid_request` for an oversized request. Member removal and epoch
retirement reject any non-empty request body with a CBOR `400 sync.invalid_request` problem before
changing state. Acknowledgements collect at most 17 bytes, the maximum canonical `{cursor: uint}`
encoding, and reject larger bodies with a CBOR `400 sync.invalid_request` problem after authorization.
Change-feed and snapshot reads accept at most 37 query bytes for canonical `after` and `limit`
parameters, rejecting longer queries with a CBOR `400 sync.invalid_request` problem after
authorization. A read cursor below the purge horizon or ahead of the vault sequence returns a
CBOR `410 sync.cursor_expired` problem so the client can restart full reconciliation; an ACK cursor
ahead of the sequence remains `400 sync.cursor_ahead`. These limits are not session-advertised write
settings. Other route body limits and multi-instance rate admission remain roadmap work.
The SQLite and PostgreSQL stores atomically provision one personal vault per account with an opaque
ARK-wrapped initial key. Both scope personal-key reads to the owner and list the account's personal
vault and current shared memberships. The authenticated K-4 vault-key route delivers that key only
to its owner using the shared `{keys}` response shape on either backend. Enrollment wiring,
production identity, and personal-key rotation remain open.
Both stores also atomically create a shared vault with its admin membership and epoch-one wrap,
list current shared memberships in vault-id order, and return only a member's non-retired wraps.
Both stores publish the next epoch for exactly the current member set, add members with every
served wrap, remove members and their wraps while marking rotation pending, and retire older
epochs only after current objects no longer reference them. Mutations enforce the fixed key
response count and size bounds before commit.
The storage crate also carries a parallel PostgreSQL migration set and a logical schema check
against the SQLite set. The API, edge, and worker roles can select PostgreSQL with
`storage.backend = "postgres"` and `storage.database_url`; the listener's `/readyz` checks the
selected database and object store. Worker queue, sync-retention, account-key, audit, account-scoped
vault-list, and personal-vault key queries use PostgreSQL. PostgreSQL also supports atomic CAS
batches with gap-free vault sequences, current change and full-reconciliation snapshot pages from
one read transaction, bounded retained-version reads, and monotone device acknowledgements. The
runtime passes the configured object limit to that writer. The injected sync HTTP adapter selects
SQLite or PostgreSQL consistently for all K-4 routes; the baseline listener does not mount it.

Shared-vault key epochs have a bounded retirement path: the authenticated sync adapter accepts
`POST /sync/v1/vaults/{vault}/epochs/{epoch}/retire`, and the SQLite store records retirement
markers, keeps validated key epochs on object history, removes retired wraps atomically, and
rejects writes that reference a retired epoch. Retirement is idempotent and refuses the newest
served epoch or any epoch still referenced by a current object.
Epoch publication and member addition also check that every affected member's complete key
response remains within the fixed 64 non-retired epoch and 4 MiB encoded-response bounds. A
mutation that would exceed either bound returns `413 sync.quota_exceeded` without changing state;
retiring an older epoch after re-encryption or using smaller wraps can free capacity.
Account-key bundle updates and certificate/revocation replacement also check every resulting
device-specific `GET /sync/v1/keys` response against the fixed 4 MiB CBOR limit inside the same
account transaction. An update that would exceed it returns `413 sync.quota_exceeded` without
changing the bundle or statements. Statements may precede the first bundle; that bundle must pass
the same check before it becomes visible.
PostgreSQL account-key GET reads the bundle, device wrap, certificates, and revocations from one
read-only repeatable-read snapshot, so concurrent rotations cannot splice separate versions into
a response.
Authenticated account-key PUTs classify an exact persisted replay before validating a new update
with the current signing key. A rotation therefore does not reject a retry signed by the previous
key. Changed bytes at the current revision return `409 sync.conflict`; the final write transaction
rechecks revision and exact bytes, so a concurrent rotation cannot turn a replay into a mutation.

## Repository shape

The Cargo workspace contains the server supervisor and one crate boundary for each server role.
`web/console` is a strict TypeScript package for the future web console. `deploy/` and `docs/`
hold deployment and operational material as those roadmap gates become implementable.

## Development

SQL migrations use LF line endings on every platform. SQLx embeds and hashes the exact SQL
bytes, so keep the repository's migration attributes when creating a checkout. A database made
by an earlier build with different migration bytes can fail with a checksum mismatch; retain
the matching build and back up its data before rebuilding the database. Do not edit historical
SQL or recorded migration checksums to bypass the failure.

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm --dir web/console install --frozen-lockfile
pnpm --dir web/console lint
pnpm --dir web/console typecheck
```

For a local configuration check:

```text
cargo run -p scoplen-server -- --validate-config
```

Run `cargo run -p scoplen-server -- --help` for role selection and configuration options. The
Personal defaults bind to `127.0.0.1:8443` and use a local data directory. A reverse proxy may
terminate TLS and select `tls.mode = "plain"`; direct TLS uses `tls.mode = "files"` with a PEM
certificate and key. `tls.mode = "acme"` obtains and renews a Let's Encrypt TLS-ALPN-01
certificate for `server.public_host`, using the contact in `tls.acme_email`. ACME account keys and
certificates are cached below `server.data_dir/acme-cache`; keep the data directory in protected
operator storage. The `tls.acme_production` setting defaults to `true`; set it to `false` only when
testing against the Let's Encrypt staging directory.

TLS-ALPN-01 requires external port 443, even when the local listener uses another port.
Set `server.public_host` to a canonical lowercase DNS name, canonical IPv4 address, or
unbracketed canonical IPv6 address. `server.public_port` (or `SPL_SERVER_PUBLIC_PORT`) is the
externally reachable HTTPS port, defaulting to 443; it is independent of the local
`server.listen_port`. The server validates the resulting canonical HTTPS origin at startup and
uses it for generated setup links. Port 443 is omitted from those links; a different external
port is included. Invalid or ambiguous public hosts fail `--validate-config` and startup.
The emitted setup link is reserved for the future operator setup flow; it cannot be redeemed
while the setup and authentication routes remain unmounted.

The SQLite database is `scoplen.sqlite` in `server.data_dir`; migrations run before SQLite-backed
roles start, and a migration failure stops startup. API, edge, and worker roles may instead use
PostgreSQL by setting `storage.backend = "postgres"` and `storage.database_url` (or
`SPL_STORAGE_DATABASE_URL`). Object storage is initialized alongside the database for
database-backed roles. The default `storage.object.backend = "filesystem"` stores below
`server.data_dir/objects`; an S3-compatible backend can be selected with the nested S3 settings
in `spl-server.example.toml` or their `SPL_STORAGE_OBJECT_*` environment overrides. `/readyz`
checks both the database and the configured object-storage backend.
Set the three `[sync]` cardinality values in `spl-server.example.toml` or override them with
`SPL_SYNC_MAX_OBJECTS_PER_VAULT`, `SPL_SYNC_MAX_SHARED_VAULTS_PER_ACCOUNT`, and
`SPL_SYNC_MAX_MEMBERS_PER_SHARED_VAULT`. Values must be positive; object and account limits must fit
SQLite's signed count range, and the member limit must be at most 1,000. The baseline listener does
not mount the K-4 router until production identity is available.
Set `sync.write_requests_per_second` and `sync.write_burst` in the same file, or use
`SPL_SYNC_WRITE_REQUESTS_PER_SECOND` and `SPL_SYNC_WRITE_BURST`. Both values must be positive. The
authenticated K-4 router takes the validated write-rate settings when it is mounted; limits are
enforced per process until shared admission is implemented.
Set `sync.max_envelope_bytes`, `sync.max_batch_objects`, and `sync.max_batch_bytes` in the same file,
or use `SPL_SYNC_MAX_ENVELOPE_BYTES`, `SPL_SYNC_MAX_BATCH_OBJECTS`, and
`SPL_SYNC_MAX_BATCH_BYTES`. Each must be positive and no greater than its default: 266,240 bytes,
500 objects, and 4,194,304 encoded bytes respectively. The authenticated K-4 router takes these
validated write bounds when mounted.

## Security

See [SECURITY.md](SECURITY.md). The SQLite database, generated deployment keys, CA keys, and setup
links are private deployment material; keep the data directory out of source control and unprotected
backups. Copying only `scoplen.sqlite` while the server is running is not a consistent backup in WAL
mode. Built-in backup and restore are still roadmap work.
