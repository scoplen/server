# PostgreSQL container deployment

This source-built single-node entry layers PostgreSQL over the existing
[Personal Compose deployment](personal-container.md). It uses the same non-root server image,
bundled Operator console, direct HTTPS listener, local key management and filesystem objects.
PostgreSQL has its own persistent volume and no published host port. The server starts after
the database healthcheck succeeds and applies its normal PostgreSQL migrations.

Maturity remains Exploration. This entry does not provide high availability, MinIO, encrypted
backup/restore, a SQLite-to-PostgreSQL migration, signed release images or the complete V12 gate.

## Configure a new deployment

Use the Docker and external-certificate prerequisites in the
[Personal procedure](personal-container.md#prerequisites). Run all commands from the server
repository root. Copy `deploy/.env.example` to `deploy/.env` and configure its public DNS name,
public port, bind address, team-creation policy and private TLS directory as documented there.

Set the additional required `SCOPLEN_POSTGRES_PASSWORD` in `deploy/.env` to a newly generated
private random password of at least 32 bytes, encoded as hexadecimal. For example,
`openssl rand -hex 32` generates an appropriate value; put its output only in the private
environment file. This override interpolates the password into a PostgreSQL URL, so arbitrary
punctuation must not be used. There is no default password. The database and initial role are
both named `scoplen`; the official PostgreSQL image initializes that role as its administrator.
This database is dedicated to this deployment.

Keep the environment file, Docker access and command output private. Rendered Compose
configuration and container inspection include the database credential. Use `config --quiet`
when checking configuration rather than printing or uploading the rendered document.

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml build server
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml up --detach --no-build
```

The override pins the official PostgreSQL 17.11 Alpine image by digest. Its default project
name is `scoplen-postgres`, distinct from the SQLite entry. Use both Compose files in the
same order for every operation. For another independent deployment, pass the same explicit
`--project-name` in every command so both named volumes remain separate. Missing public host,
TLS directory or database password stops Compose before startup; the existing TLS directory
must contain `fullchain.pem` and `private-key.pem`, readable by server UID 65532.

Start with a new project and empty volumes. Changing the storage backend does not copy an
existing SQLite deployment. Do not attach a different database to a retained server-key volume
or attach an existing database to new deployment keys.

## Verify and sign in

Check the configured public HTTPS origin with normal certificate and hostname verification:

```text
curl --fail --show-error https://sync.example.com:8443/healthz
curl --fail --show-error https://sync.example.com:8443/readyz
```

For a private CA, add `--cacert <trusted-ca.pem>`. `/readyz` checks the actual database and
object store; the PostgreSQL startup healthcheck alone does not establish API readiness.
The console at `/` and `/setup` must also load. Use the same first Operator setup, fresh
Passkey sign-in and explicit sign-out procedure as the Personal entry. To read the private
one-time setup link:

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml logs server
```

The console has no Account registration or new Device admission form. Native clients use the
same password Account and encrypted Personal synchronization APIs on either database. Team
creation defaults to disabled; set `SPL_ORGANIZATIONS_ALLOW_CREATION=true` and recreate the
server to opt in. Invitations, team assets and Shared vaults remain separate roadmap work.

Read-only diagnosis and pending Operator setup recovery use the existing bundled CLI with
both Compose files:

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml exec -T server /app/splctl doctor
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml exec server /app/splctl bootstrap --reissue-pending
```

The configured public origin must be reachable from the container for `doctor`. Provision
`ca.pem` in the TLS directory and pass `--ca-certificate /run/scoplen/tls/ca.pem` when using
a private CA. The reissue command is only for incomplete setup; it does not reset Accounts
or reopen completed setup.

## Restart, retained state and upgrades

```text
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml stop
docker compose --env-file deploy/.env -f deploy/compose.personal.yaml -f deploy/compose.postgres.yaml up --detach --no-build
```

The `postgres-data` volume retains the relational database. The inherited `data` volume retains
the deployment encryption key, audit signer, internal CA and filesystem objects. Both are
required to retain the same deployment. `down` retains both volumes; adding `--volumes`
permanently deletes them. Keep the external TLS directory and private environment file as well.

The PostgreSQL image applies `POSTGRES_PASSWORD` only when initializing an empty database.
Changing `SCOPLEN_POSTGRES_PASSWORD` alone does not rotate an existing role password and will
break server authentication. Keep the value unchanged across restart. A planned password
rotation must update the database role and the server configuration together.

Readiness becomes unavailable while PostgreSQL is stopped or unreachable. Restore the same
database and credentials, then check `/readyz` again before using the service. Do not reset
keys, delete volumes or initialize a replacement database to resolve a readiness failure.

Before an upgrade, retain the matching server image and a consistent offline copy of both
volumes, the environment file and external TLS material. Stop both services cleanly before
copying their volumes. PostgreSQL storage is version-specific; a PostgreSQL major upgrade
requires its own supported database migration procedure. The server's SQLite pre-migration
snapshots do not apply to PostgreSQL. Automated backup, encrypted archives and restoration
remain unimplemented, so keep this a trial deployment until those gates are complete.
