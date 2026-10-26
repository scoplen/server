# Personal container deployment

This source-built entry runs the existing single-node `all` profile with SQLite, local object
storage, and the Personal console in one container. The console is built in the image and its
bounded asset manifest is checked by the production server on startup. The runtime is
distroless and runs as UID/GID `65532:65532`, with a read-only root filesystem and a writable
private data volume. No image is published by these commands.

Maturity remains Exploration. Complete deployment/release gates, signed images, SBOM/provenance,
Helm and PostgreSQL/MinIO examples, backup/restore, and physical Passkey interoperability remain
separate roadmap work. `all` retains the existing role semantics; the CA and gateway roles do
not yet provide the complete managed-access workflow.

## Prerequisites

- Docker with Linux containers, BuildKit and Docker Compose v2 or later.
- A DNS name resolving to this host, and a browser-trusted certificate for that exact name.
- An existing private certificate directory outside this checkout containing `fullchain.pem`
  and `private-key.pem`. The directory and both files must be readable by container UID 65532.
  On Linux, a dedicated directory owned by `65532:65532` with mode `0500` and files with mode
  `0400` meets this requirement. Provision a restricted copy rather than loosening permissions
  on the certificate authority's original private key. Do not use a world-readable key.

The server's generated internal CA does not provide browser trust for its public HTTPS listener.
The DNS name and externally reachable port must match the configured origin. This example
terminates TLS directly on container port 8443; no reverse proxy is required.

## Configure and start

Run from the server repository root. Copy `deploy/.env.example` to `deploy/.env`, then set:

| Variable | Value |
| --- | --- |
| `SCOPLEN_SERVER_HOST` | Certificate DNS name, without a scheme, port, or path. Required. |
| `SCOPLEN_TLS_DIRECTORY` | Absolute path of the existing private certificate directory. Required. |
| `SCOPLEN_HTTPS_PORT` | Public HTTPS port mapped to container port 8443. Default: `8443`. |
| `SCOPLEN_BIND_ADDRESS` | Host interface for the published port. Default: `0.0.0.0`. |
| `SPL_ORGANIZATIONS_ALLOW_CREATION` | Allow authenticated Accounts to create teams: `true` or `false`. Default: `false`. |

The default Compose project name is `scoplen-personal`. For another independent deployment,
supply the same explicit `--project-name` in every command so its data volume stays separate.
Missing required variables stop Compose before creating a service. A missing certificate
directory is rejected rather than created. Keep the environment file and all keys out of Git.

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml build
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml up --detach --no-build
```

The pinned Node/Rust stages build from the lockfiles; pnpm's version comes from the console
manifest. BuildKit reuses one Rust target cache per Linux architecture and separate Cargo
registry, Cargo Git and pnpm store caches. Cache mounts are shared with locking across builds;
compiled targets do not become image layers. Copied workspace inputs receive fresh container
timestamps before Cargo uses a retained target, so source changes cannot hide behind older
copied timestamps. Incremental compilation is disabled and Cargo uses one job. pnpm dependency
requests retain supply-chain checks and use bounded retries and a two-minute request timeout.
The final image contains `spl-server`,
`splctl`, built console assets/fonts/licenses,
and the configuration in `deploy/personal.toml`. A new Docker-managed data volume inherits the
image directory's UID/GID 65532 and mode `0700`. It retains the database, deployment encryption
key, audit signer, internal CA, and local objects. An existing volume keeps its existing
ownership and contents; do not replace a deployment's keys or database to work around an error.

Check the real HTTPS listener from a host with its DNS and certificate trust configured:

```text
curl --fail --show-error https://sync.example.com:8443/healthz
curl --fail --show-error https://sync.example.com:8443/readyz
```

Use the configured host/port. For a private certificate authority, supply its trusted PEM with
`--cacert`; certificate hostname verification must remain enabled. Readiness checks the actual
database and object store. The distroless image has no shell or curl; configuration validation
is not a replacement for these readiness requests. The console at `/` and `/setup` must also
load successfully. Missing/invalid console assets return 503 independently of `/readyz`.

The image also carries the read-only diagnostic command:

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml exec -T server /app/splctl doctor
```

This runs inside the container and uses its effective configuration to check the configured
public HTTPS host and port. That address must be reachable from the container; the check does
not substitute the internal listener port. For a private CA, provision its trusted public PEM
as `ca.pem` in the existing TLS directory and add
`--ca-certificate /run/scoplen/tls/ca.pem` to the command. System trust remains enabled.
The findings report configuration, health and readiness, with exit 0 for success and exit 1
for failure. Other diagnostics are explicitly `NOT CHECKED`; this command does not start or
repair a deployment, open storage or generate keys.

To check from another machine, including while the container is stopped, use a native
`splctl doctor --config <operator-config.toml>` with the same public host and port, and
`--ca-certificate <trusted-ca.pem>` when needed. Normal `SPL_` overrides apply; `splctl` does
not load Compose's `deploy/.env`. The source-build invocation is documented in the README.
Reachability is established only from the machine running the command.

## First Operator session

Read local bootstrap output with:

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml logs server
```

The first API initializer prints the complete one-hour setup link exactly once. This bootstrap
output contains a one-time credential: keep Docker access and captured logs private, and do
not attach them to an issue or paste them into a shared terminal.

1. Open the complete HTTPS setup link in a current browser supporting Passkeys, WebCrypto,
   and Web Locks. Use its exact DNS name and port.
2. Choose **Create passkey** and complete your authenticator's verification and save action.
3. Choose **Sign in with passkey** and verify again. Setup itself creates no browser session.
4. Use **Sign out** when finished. Confirmed server sign out revokes this browser session;
   **Lock this tab** only discards local credentials.

Account registration and new Device admission are not available through this console. Existing
Device credentials continue to authenticate and sync.

Cancellation can start a fresh ceremony. An uncertain registration result requires attempting
fresh login with the saved Passkey; do not automatically register again. An uncertain sign-out
response retains credentials for an explicit retry before expiry; local locking leaves server
sign out unconfirmed.
Reloading the console requires a fresh Passkey login.

If a pending setup link is lost or expires, run the existing server-local recovery command:

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml exec server /app/splctl bootstrap --reissue-pending
```

It uses the same local database/KMS, invalidates old setup ceremonies, and prints a replacement
only after confirmed commit. Completed setup cannot reopen. This operation never resets accounts.

## Stop, restart, and data

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml stop
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml up --detach --no-build
```

The image uses SIGINT so the existing supervisor closes its owned tasks gracefully. Restarting
retains the original setup state, accounts, keys and objects. After replacing TLS
files, restart the container to load them. After changing source/assets, rebuild the image and
recreate the service. `down` removes the service while retaining its named volume; `down --volumes`
deletes the database and keys and must not be used for a deployment you intend to keep.
Shutdown fences notification connections and allows up to 10 seconds for requests, role tasks and
database pools to drain. If it times out, the server cancels remaining tasks and reports an error;
its deployment lease remains held until the container process exits. Wait for the container to stop
before any offline copy. Do not delete `deployment.lease` from the data volume to bypass an
occupied lock.

To opt in to Account-owned team creation, set `SPL_ORGANIZATIONS_ALLOW_CREATION=true` in
`deploy/.env` and run the same `up --detach --no-build` command to recreate the service with
the new environment. Changing this policy does not require an image rebuild or a new data
volume. Only the exact lowercase values `true` and `false` are valid; another value stops
server configuration validation before startup. Returning to `false` blocks new creation
while preserving current membership discovery and exact creation confirmation. Team creation
adds the Account as its initial owner without moving its Personal data or granting Operator
access. Invitations, team assets, Shared vaults, dissolution and team administration remain
separate work; the Operator console has no team-creation form.

Before upgrading an existing SQLite schema, the server creates and verifies a standalone
`pre-migration-<UUIDv7>.sqlite` snapshot in `/var/lib/spl/scoplen.sqlite.migration-snapshots/`.
Committed WAL pages are included. The three newest completed snapshots are retained; fresh empty
databases and restarts without pending migrations do not create snapshots. Snapshot or retention
failure prevents migrations. The private `scoplen.sqlite.migration.lock` file remains in the data
volume and serializes startup. Do not remove it while a server or recovery process may be active.
A second startup waits up to five seconds, then stops if the lock is still held; let the active
startup finish before retrying.

A failed migration stops startup and retains its pre-upgrade snapshot. Each migration is atomic,
but earlier migrations in the same upgrade may already have committed. Recovery is an explicit
offline operation with the matching old image and original keys/objects; never mix a recovered
database with the newer database's WAL/SHM files. Interrupted `.partial` files and unrecognized
entries are not retention candidates and remain for inspection. Snapshot files contain private
database material and are not an encrypted, complete deployment archive.

Single-archive encrypted backup, scheduled backups, `splctl backup` restoration, and reversible
upgrades remain unimplemented. Keep this an explicit trial environment until those gates are
complete; retain a consistent offline copy of the entire data volume and the matching image
before an upgrade. SQLite-only snapshots omit the deployment, CA and audit keys and object files.
Custom object/KMS paths and the external TLS directory also need their own complete backup.

## Repeatable container check

The `Personal container (Linux amd64)` CI job runs the same repository check that can be run
locally with Node 24 and a local Linux-container Docker daemon. Build the registered native
`personal_live_bootstrap` example and `splctl`, then pass their executable paths:

```text
cargo build --locked -p scoplen-server --example personal_live_bootstrap
cargo build --locked -p scoplen-ctl --bin splctl
node scripts/check-personal-container.mjs --bootstrap-driver <cargo-target-directory>/debug/examples/personal_live_bootstrap --doctor-cli <cargo-target-directory>/debug/splctl
```

On Windows both native executables have an `.exe` extension. Use the actual target directory selected
by Cargo. Unset `SPL_*` overrides and use a private temporary directory outside Git checkouts.
The check uses a fresh disposable CA trusted only by its HTTPS clients; it does not change
the operating system or browser trust store.

Before building images, the check admits its SQLite probe as UID/GID 65532 using a separate
read-only context containing only the public check identity. The private temporary directory,
TLS material and command diagnostics keep their original permissions and are not exposed to
that probe. The probe also verifies the schema checkpoint against a temporary SQLite database
whose schema starts in WAL, using the same checkpoint function as the old-schema seeder.
A seeding process that exits before readiness fails immediately with a fixed
reason. Its summary includes bounded exit/OOM status and, when present, a fixed probe phase,
an allowlisted error code and a bounded numeric SQLite code. The final log is read after
process exit so a fast failure does not hide its summary. Detailed output remains private;
these observations do not establish the underlying cause.

The check builds the production image, starts its own uniquely named Compose project, and
checks image/data-volume permissions, non-root writes, TLS trust and hostname rejection,
`/healthz`, `/readyz`, every manifest-listed console asset and bundled licenses. It performs
native `splctl doctor` checks from the host against that same public HTTPS origin with the
explicit fixture CA. Exact fixed configuration/health/readiness findings and exit 0 must pass
before and after the existing restart; while stopped, the same command must return exit 1
with fixed health/readiness connection failures. Each invocation preserves its input files
and fixture entries and leaves its configured local data directory absent. This verifies the
native CLI against the production server; it does not execute the image's bundled CLI.
It performs
one public setup, fresh resident software-passkey login and current-session logout with the
registered driver, confirms an eligible terminal logout retry, and checks that all eight retired
Personal invitation/enrollment/pairing API routes and old `/pair` landing return 404. Its separate
`verify-account --with-team --across-restart` invocation registers two randomly generated password
Accounts. For each, the first enrolled Device writes a signed, encrypted Host. A fresh independent
Device derives that Account's password credential, verifies and decrypts the complete signed
bootstrap, completes admission, authenticates and refreshes its session. With the check's
explicit creation opt-in, that Device confirms empty membership discovery, creates a team with its Account as the sole owner,
reads and lists the same team, and explicitly confirms the original idempotency key without
creating another team. One conditional PATCH renames the team. A second request with the original
ETag must return the exact unchanged/nonretryable stale-precondition problem; an unchanged-name
PATCH with the new ETag must preserve the complete Resource. Direct read, discovery and exact
confirmation with the original creation key/body must return that renamed Resource.
It refreshes its session again, then opens its own ARK and Personal vault-key wraps.
It verifies and decrypts the retained Host, edits and uploads it with its own Device signature;
the original Device refreshes and verifies the returned edit. Each Account's discovery must
contain only its own team. Both Accounts attempt GET and PATCH against the other team and a
fresh absent id. Each response must be `404 organization.not_found`, with `changed: false` and
`retryable: false`; the complete problem bodies must match after removing only the request
instance, and failure headers must not disclose an ETag. Both owners then read and confirm
their unchanged complete Resources, including ETags, and decrypt their unchanged Personal Hosts.
Only these public HTTPS operations can produce the separate content-free
`account-acceptance.json` receipt. Completing both Accounts' team operations and subsequent
Personal sync also produces `team-acceptance.json`, requiring the creation, name-settings and
`team_account_isolation_verified` success fields; the Account receipt and descriptor are unchanged.
With `--across-restart`, the native process retains both Devices' keys, original unused refresh
credentials, renamed team Resources and expected Hosts in memory while the controller performs the same
graceful stop/start and readiness checks. Only fixed ready/resume markers cross the process
boundary. Its first authentication requests after restart refresh those original credentials,
then repeat both Accounts' own-team discovery, foreign-versus-absent refusals, exact creation
confirmation and complete Resource comparisons, including ETags, update times and sole owner
memberships. Both retained signed Hosts must still decrypt to the same content. These completed
operations produce `team-restart-acceptance.json`, requiring membership, name-settings and
`team_account_isolation_restart_verified` success fields. No Account or Device is seeded
again, no credential is written to a fixture file, and failed operations are not retried.
The coordinator bounds its wait and aborts/reaps its driver if readiness or the controller fails.
Before startup, Compose rendering checks the default `false`, explicit `true` and unchanged
invalid input; the server's configuration tests verify invalid booleans are rejected.
No SQL identity seed or internal server coordinator is used. Repeated bootstrap and Account checks are rejected without
changing their completed artifacts. The controller verifies unchanged public
keyrings and completed setup state during that same service restart. Every HTTPS exchange has a whole-request deadline and
operations are not retried automatically.

The Account check exercises an independent protocol consumer against the production image;
native desktop interaction, reopen/restart behavior and independent client acceptance retain
their separate tests. Other server tests may use signed legacy identity fixtures; those seeds
do not participate in this password Account or encrypted Host acceptance flow. Physical
authenticators and native GUI/macOS acceptance remain separate.

The check also archives the pinned server revision
`37af5126585254612e734f542cfd4e36670915d9` from local Git history and builds its original
server binaries into a disposable image with the current check's runtime files. That revision
precedes the `20261024040000` configurable-limit and `20261025000000` durable write-admission
SQLite migrations. The recovery anchor remains `20261024030000`; the current-image check follows
the latest migration and verifies both new admission tables and the initial clock watermark.
The old image starts a real Personal volume;
the check seeds committed organization and sync-object rows and an object file, then starts the
current image against that volume while the seeding SQLite connection keeps its committed WAL
open. Before seeding, a successful truncating checkpoint establishes the old schema in the main
database, so the bare-file comparison can check the seeded rows rather than fail on a missing
schema. It checks that the WAL holds data absent from the main database file alone, then verifies
the migrated rows, the independently readable old schema snapshot, and both SQLite integrity and
foreign-key integrity. After stopping the current
server, the check copies only the completed snapshot, original keys, and object files into a
separate empty recovery volume. The matching old server must reach `/readyz` and preserve those
rows and files; newer WAL/SHM files are excluded from the copy. CI fetches the repository's full
history so this fixed old revision is available. This is one Linux amd64 upgrade and offline
recovery acceptance case, not a complete encrypted deployment backup or general restore tool.
It does not seed identity tables. Independent
desktop Account registration/device admission/SSH, physical authenticators, arm64 and full deployment/release gates need
their own evidence.

Only resources bearing this check's unique ownership labels and matching IDs are stopped or
removed. Successful runs remove their own containers, network, volume, image and private
temporary files. Failed runs stop their own service and retain their private diagnostics and
test state at the printed local path; do not upload that material to CI artifacts or issues.
The check never prunes Docker caches or touches earlier failed fixtures.

Image-build failures report a fixed failure category, the last observed build stage, and bounded
exit metadata; detailed command output remains in the private check directory. The CI job retains
the native bootstrap executable separately and removes its intermediate Cargo outputs before
building the independent production image. After building, separate static stages identify image
metadata, directory validation, probe-image retrieval and TLS fixture preparation. Failures expose
only fixed categories/reasons and bounded I/O or exit metadata; private diagnostic-write failures
report that stage before attempting to retain further output. Unknown messages, paths, command
arguments and captured output never enter these summaries.
Only a fixed `directory-mode` failure can add `actualMode` and `expectedMode`, both integer image
permission bits bounded to `0..0o7777`.

Use the fixed summary to select the next investigation. A missing image-build failure summary
alone does not prove that building succeeded: retaining its private output can fail first.
Summaries identify observed failure points; an unobserved underlying cause remains unknown.
Detailed private output must remain local; an ephemeral CI runner does not retain it as an artifact.
