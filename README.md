# scoplen-server

The self-hosted Scoplen server, host agent, administration CLI, and web-console workspace.
Scoplen is a Plystra project. This repository is licensed under AGPL-3.0-only.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline (roadmap V1) is complete. The
current binary provides role selection, validated TOML and `SPL_` environment configuration,
first-run deployment material, a single public listener, health/readiness/metrics endpoints, and
plain, file-based, or ACME TLS. It now opens a durable SQLite database in WAL mode and applies
forward migrations for `api`, `worker`, and `edge` roles; readiness checks that database. The
storage layer also has the first sync foundation: per-vault gap-free sequence allocation, atomic
compare-and-swap batches, current change and snapshot paging, acknowledgement cursors, and
bounded version reads. It also exposes an atomic retention pass for the worker: historical rows are
version plus 20 retained versions, and acknowledged or expired tombstones advance the purge
horizon while deleting their retained history. The `scoplen-store` queue now persists opaque jobs
with bounded payloads, atomic claims, owner-checked leases, retry/failure state, and expired-lease
requeue; the `worker` role runs a 30-second heartbeat that requeues abandoned leases.
Standalone `ca` and `gateway` roles do not open SQLite or generate Personal setup material.
The `scoplen-sync` crate now exposes a K-4 HTTP/CBOR router for a session handshake that lists
account-owned personal vaults and current shared-vault memberships with their rotation state,
shared-vault creation, key retrieval, epoch publication, and member addition and removal, plus
account key bundles, changes,
snapshots, version reads, object writes, acknowledgements, and the authenticated
`/sync/v1/notify` WebSocket. The notification adapter accepts an opaque first credential message,
applies an injected device policy, and fans out deterministic CBOR events through a caller-owned
local hub. It requires an injected authenticator that binds DPoP proofs to the request method and
URI, authorizes vault, account-key, and notification operations, records the creator's initial
shared-vault membership and opaque epoch-1 key wrap, adds and removes members with historical
opaque wraps, validates account-key signatures and active-device wraps, and validates encrypted
envelopes before storage; the baseline listener
does not mount this router. The `scoplen-store` crate now provides a backend-neutral object
storage boundary with local filesystem and S3-compatible implementations, including bounded key
validation and streaming/multipart operations; database-backed roles initialize the configured
backend and include it in `/readyz`. PostgreSQL, production identity/authentication, policy
filtering, membership-aware purge orchestration, multi-instance
notification fan-out, organization vault ownership in session listings, write-rate and
deployment-configurable quota enforcement, control, gateway, and console behavior are still
roadmap work. The audit crate and SQLite store now provide bounded canonical-event SHA-256 chain
hashing, same-transaction append helpers, checkpoint payload construction, durable checkpoints,
and chain verification; control-plane event producers, deployment-key signing, and retention
export wiring remain open. The storage crate also validates and redacts a local 32-byte deployment
key-file backend behind the `KeyManagementService` trait; cloud KMS, PKCS#11, column encryption,
and external KMS runtime wiring remain open. Database-backed role preparation now loads and
validates the local backend before startup. `storage.kms.backend = "local"` and
`storage.kms.key_file` are configurable in TOML or via `SPL_STORAGE_KMS_*` environment overrides.
The SQLite sync store enforces the default 100,000 current objects per vault (including
tombstones), 1,000 shared vault memberships per account, and 1,000 accounts per shared vault in
the mutation transaction. The session advertises those same limits, and the HTTP adapter returns
`413 sync.quota_exceeded` without changing state. Deployment-configurable quotas and per-device
write-rate enforcement remains process-local at the advertised default of 50 requests per second
with a burst of 200; an exhausted authenticated device bucket returns `429 sync.rate_limited` and
`Retry-After`. Deployment-configurable limits and multi-instance rate admission remain roadmap
work.
The store provides an atomic, one-per-account personal-vault provisioning method with an opaque
ARK-wrapped initial key, and the authenticated K-4 vault-key route delivers that key only to its
owner using the shared `{keys}` response shape. Enrollment wiring, production identity, and
personal-key rotation remain open. A session lists a personal vault only after provisioning
succeeds.
The storage crate also carries a parallel PostgreSQL migration set and a logical schema check
against the SQLite set. The server roles remain SQLite-only until their storage queries and
readiness wiring are implemented for PostgreSQL.

Shared-vault key epochs have a bounded retirement path: the authenticated sync adapter accepts
`POST /sync/v1/vaults/{vault}/epochs/{epoch}/retire`, and the SQLite store records retirement
markers, keeps validated key epochs on object history, removes retired wraps atomically, and
rejects writes that reference a retired epoch. Retirement is idempotent and refuses the newest
served epoch or any epoch still referenced by a current object.

## Repository shape

The Cargo workspace contains the server supervisor and one crate boundary for each server role.
`web/console` is a strict TypeScript package for the future web console. `deploy/` and `docs/`
hold deployment and operational material as those roadmap gates become implementable.

## Development

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
The SQLite database is `scoplen.sqlite` in `server.data_dir`; migrations run before database-backed
roles start, and a migration failure stops startup. These roles currently require
`storage.backend = "sqlite"`. Object storage is initialized alongside the database for those
roles. The default `storage.object.backend = "filesystem"` stores below
`server.data_dir/objects`; an S3-compatible backend can be selected with the nested S3 settings
in `spl-server.example.toml` or their `SPL_STORAGE_OBJECT_*` environment overrides. `/readyz`
checks both the database and the configured object-storage backend.

## Security

See [SECURITY.md](SECURITY.md). The SQLite database, generated deployment keys, CA keys, and setup
links are private deployment material; keep the data directory out of source control and unprotected
backups. Copying only `scoplen.sqlite` while the server is running is not a consistent backup in WAL
mode. Built-in backup and restore are still roadmap work.
