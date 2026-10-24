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

| Variable                | Value                                                                  |
| ----------------------- | ---------------------------------------------------------------------- |
| `SCOPLEN_SERVER_HOST`   | Certificate DNS name, without a scheme, port, or path. Required.       |
| `SCOPLEN_TLS_DIRECTORY` | Absolute path of the existing private certificate directory. Required. |
| `SCOPLEN_HTTPS_PORT`    | Public HTTPS port mapped to container port 8443. Default: `8443`.      |
| `SCOPLEN_BIND_ADDRESS`  | Host interface for the published port. Default: `0.0.0.0`.             |

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

## First Operator and Personal invitation

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
4. Choose **Create Personal invitation**. Copy the one-use link before closing the tab.
5. Open Scoplen's desktop app and use that invitation to create the separate Personal account
   and enroll its first device. The browser Operator is the deployment administrator.

Cancellation can start a fresh ceremony. An uncertain registration result requires attempting
fresh login with the saved Passkey; do not automatically register again. An uncertain invitation
response cannot recover the earlier link; issuing another invitation is an explicit new action.
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
retains the original setup state, accounts, keys, invitations and objects. After replacing TLS
files, restart the container to load them. After changing source/assets, rebuild the image and
recreate the service. `down` removes the service while retaining its named volume; `down --volumes`
deletes the database and keys and must not be used for a deployment you intend to keep.

Automatic backups, restoration, and reversible upgrades are not implemented yet. Keep this an
explicit trial environment until those gates are complete; retain a consistent offline copy of
the entire data volume and the matching image before an upgrade. Exporting only SQLite loses
the keys required to use its encrypted records.

## Repeatable container check

The `Personal container (Linux amd64)` CI job runs the same repository check that can be run
locally with Node 24 and a local Linux-container Docker daemon. Build the registered native
`personal_live_bootstrap` example, then pass its executable path:

```text
cargo build --locked -p scoplen-server --example personal_live_bootstrap
node scripts/check-personal-container.mjs --bootstrap-driver <cargo-target-directory>/debug/examples/personal_live_bootstrap
```

On Windows the native driver has an `.exe` extension. Use the actual target directory selected
by Cargo. Unset `SPL_*` overrides and use a private temporary directory outside Git checkouts.
The check uses a fresh disposable CA trusted only by its HTTPS clients; it does not change
the operating system or browser trust store.

The check builds the production image, starts its own uniquely named Compose project, and
checks image/data-volume permissions, non-root writes, TLS trust and hostname rejection,
`/healthz`, `/readyz`, every manifest-listed console asset and bundled licenses. It performs
one public setup, fresh resident software-passkey login and invitation issuance with the
registered driver, rejects repeated bootstrap, then restarts the service and verifies the
same public keyrings and completed setup state. It does not seed identity tables. Independent
desktop enrollment/SSH, physical authenticators, arm64 and full deployment/release gates need
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
