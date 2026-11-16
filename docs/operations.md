# Server backup and restore

## Current scope

`splctl backup` creates a password-encrypted offline archive for a SQLite deployment with
filesystem object storage and local key files. It includes a standalone database snapshot,
the required deployment, KMS, audit and internal-CA keys, and every local object. Committed
SQLite WAL pages are included in the snapshot; WAL and SHM files, deployment leases,
migration snapshots and unrelated files are excluded.

The archive is binary age v1. Keep its passphrase separately from the archive. Protect both
because the archive contains the server's complete retained data and private keys. Losing
the passphrase makes the archive unusable. Scheduled backups, PostgreSQL archives, S3 archives
and automatic recovery are not supported by this first profile.

This archive profile has these fixed bounds:

| Resource                                                                                         | Maximum |
| ------------------------------------------------------------------------------------------------ | ------- |
| Payload entries, including the database and required keys                                         | 65,536  |
| Total plaintext payload                                                                          | 64 GiB  |
| Encrypted archive                                                                                | 65 GiB  |
| JSON manifest                                                                                    | 16 MiB  |
| Each deployment, KMS or audit key file, internal-CA certificate/key, or included TLS certificate/key | 64 KiB  |

The key-material bound applies to the encoded key or PEM file. ACME cache blobs are not subject
to that key-parser bound; they remain subject to the payload and archive bounds.

## Create and verify

Stop every server role and other process using the deployment first. Do not remove the
deployment lease file to bypass an occupied-deployment error. Use an existing private
passphrase file containing 1 to 4,096 UTF-8 bytes; the commands read its exact bytes, including
any newline, so preserve the same file contents for verification and recovery. Do not put a
passphrase in command-line arguments or configuration.

Create the archive with the build currently operating the stopped deployment. Use that exact
archive-producing build for verification and restoration:

```sh
splctl backup create --config server.toml --output backup.age --passphrase-file backup-passphrase.txt
splctl backup verify --archive backup.age --passphrase-file backup-passphrase.txt
```

The archive output must not already exist. Creation validates the source recovery material and
completes the encrypted write before reporting `Backup created.`. Run the explicit verification
command to read back and validate the completed archive; success reports `Backup verified.`.
Runtime failures exit with status 1; invalid command usage exits with
status 2. Failed commands do not publish a success result or print the passphrase.

The executable must have a known full source revision. Source and container builds use
`SCOPLEN_BUILD_REVISION`; the container build argument has the same name. Verification and
restoration require the exact archived build revision and migration history. Keep that build
or its source and locked build inputs with the recovery procedure. A newer executable is not
a substitute for restoring with the matching version first.

Verification checks authenticated decryption, the strict manifest and payload digests, SQLite
integrity and foreign keys, available audit-chain proof, and required key material. Verification
does not start a service or apply migrations. External TLS material and other external
requirements are recorded for recovery; supply them separately when restarting.

## Restore to a new directory

The destination must be an absent child of an existing private parent. Restoration does not
overwrite an existing directory, restore into a mounted volume's root, or start the server.

```sh
splctl backup restore --archive backup.age --data-dir recovery/restored --passphrase-file backup-passphrase.txt
```

On success the first output line is `Backup restored.`. Apply the reported configuration
mapping before starting the matching server build:

```toml
[server]
data_dir = "recovery/restored"

[storage.kms]
key_file = "recovery/restored/kms.key"
audit_key_file = "recovery/restored/audit-signing.key"

[storage.object]
directory = "recovery/restored/objects"
```

Preserve the original `server.public_host` and `server.public_port`. They identify the trusted
public origin used by existing Accounts, Devices and signatures. For `tls.mode = "files"`,
reconfigure the certificate and private-key file paths separately, using a valid certificate
for that same public origin. Restore first with the matching executable, verify normal login
and synchronization, then follow the ordinary upgrade procedure if needed.

The database and all required keys form one recovery unit. Do not replace a missing key with
a newly generated key or copy selected identity tables into another deployment. A failed
decryption or validation leaves the requested destination absent; review the failure and
recover a known-good archive rather than using partial staging files.

## Personal Compose recovery

Stop the existing Compose service. Retain its data volume unchanged until the recovered service
has been checked. Use the exact image revision recorded in the archive for the offline CLI
commands and for the first recovered startup.

Create a fresh named volume, prepare its root as a private directory owned by the image's
`65532:65532` runtime account, and mount that volume as a parent directory. Mount the archive
and its private passphrase file separately. Run the image's `/app/splctl` entry point with
`backup restore --archive /backup/backup.age --data-dir /recovery/restored
--passphrase-file /backup/passphrase.txt`. The `/recovery` volume mount already exists;
`/recovery/restored` must not exist before the command.

Mount the archive and passphrase inputs read-only and make both readable by UID 65532. For the
passphrase, provision a dedicated copy owned by `65532:65532` with mode `0400` in a private
directory accessible to that account. Keep the original secret file's permissions restricted.

Update the Compose configuration to mount the new volume at `/var/lib/spl` and set:

```yaml
environment:
  SPL_SERVER_DATA_DIR: /var/lib/spl/restored
  SPL_STORAGE_KMS_KEY_FILE: /var/lib/spl/restored/kms.key
  SPL_STORAGE_KMS_AUDIT_KEY_FILE: /var/lib/spl/restored/audit-signing.key
  SPL_STORAGE_OBJECT_DIRECTORY: /var/lib/spl/restored/objects
```

Keep the original public origin and provision its TLS files through the existing read-only
certificate mount. After startup, use `splctl doctor` with the deployment CA where required,
sign in with an existing Account and verify its synchronized inventory. Restart the recovered
service once more and repeat those checks before retiring the original volume.

The repository's `scripts/check-personal-container.mjs` exercises this workflow with disposable
volumes, the public CLI, trusted HTTPS, existing in-memory Device credentials, encrypted Personal
Hosts and team state. It also retains the separate ordinary restart and matching old-version
migration-snapshot recovery checks.
