# Server backup and restore

## Current scope

`splctl backup` creates a password-encrypted archive for a SQLite deployment with
filesystem object storage and local key files. It includes a standalone database snapshot,
the required deployment, KMS, audit and internal-CA keys, and every local object. Committed
SQLite WAL pages are included in the snapshot; WAL and SHM files, deployment leases,
migration snapshots and unrelated files are excluded.

The archive is binary age v1. Keep its passphrase separately from the archive. Protect both
because the archive contains the server's complete retained data and private keys. Losing
the passphrase makes the archive unusable. Worker can schedule daily local archives for the
online SQLite profile below. PostgreSQL archives, S3 archive delivery, archive rotation and
automatic recovery remain separate work.

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

## Create while the server runs

For SQLite with filesystem objects, local KMS and `tls.mode = "plain"` or `"files"`, add
`--online` to capture a live standalone database snapshot while ordinary requests continue:

```sh
splctl backup create --online --config server.toml --output backup.age --passphrase-file backup-passphrase.txt
splctl backup verify --archive backup.age --passphrase-file backup-passphrase.txt
```

Use the same build and effective TOML/environment settings as the running deployment. All
required state must already exist. Prevent external processes from changing captured key,
object or managed static-TLS files during the operation. Current server business writes keep
these files stable; Account, token-key and team-CA changes are captured in SQL. Online creation
rejects ACME mode and any `acme-cache` path, including an empty directory, file or link, or a
path whose absence cannot be established safely. It never omits that state or falls back to
offline creation. External KMS, S3 and PostgreSQL are unsupported.

Online creation holds a shared deployment lease for its entire lifetime and is refused while
an exclusive local operation is running. The default command still requires every deployment
process to stop and obtains exclusive admission. Neither command initializes or migrates the
source. A snapshot is a consistent point during capture, so writes completed later need not
appear in the archive. Copying, validation and encryption consume I/O and CPU; a live read
snapshot can retain WAL pages. There is no fixed latency or storage guarantee.

For Personal Compose, run the matching image's `/app/splctl` as UID 65532 with the same data
volume, configuration, TLS mount and environment overrides as the service. Mount a separate
private backup directory and passphrase file; the archive output and passphrase must remain
outside the source data and object roots. Override the image entry point explicitly and keep
the existing service running. Provision access for UID 65532 without widening source or secret
permissions. Verification and the explicit fresh-volume restore below use the unchanged age
archive and matching build; stop the original service before starting the restored service.

## Schedule daily local archives

Enable the built-in schedule in the same effective deployment configuration used by Worker:

```toml
[backup]
enabled = true
daily_utc = "03:00"
directory = "/var/backups/scoplen"
passphrase_file = "/run/secrets/scoplen-backup-passphrase"
```

Use exact UTC `HH:MM` from `00:00` to `23:59`. The corresponding overrides are
`SPL_BACKUP_ENABLED`, `SPL_BACKUP_DAILY_UTC`, `SPL_BACKUP_DIRECTORY` and
`SPL_BACKUP_PASSPHRASE_FILE`. Configuration changes require restart. Create the dedicated
private output directory and passphrase file before enabling the schedule. Both must be
outside source data/object roots and readable/writable as appropriate by the runtime user.
Keep the passphrase file's exact 1-4,096 UTF-8 bytes; it is reread on each attempt without
trimming. Its contents are never configuration values or log fields.

Only the actual Worker role runs scheduling: worker-only, combined API/Worker and `all`
are supported. API-only processes may share this configuration but warn that Worker must
run. Enabled scheduling rejects PostgreSQL, external KMS, S3 objects, ACME and any managed
`acme-cache` path. Existing online-capture exclusions of external file writers still apply.
For a container, mount the dedicated output directory writable and the passphrase file
read-only into each participating Worker with permissions for the existing runtime user.

The first enabled start with no prior daily job immediately creates today's backup. On later
starts, Worker resumes today's unfinished job according to its persisted eligibility. A
missing current-day job waits until the configured UTC time. It never replays missed days;
a successful daily job prevents a duplicate that day, including after restart. Each UTC
date has at most three claims, with five minutes between failed attempts. Restarts preserve
that count and delay. After exhaustion, the next current day follows its normal due time.
Multiple Workers use one atomic database claim and renew it during capture.

Archives are named `scoplen-YYYY-MM-DD.age`. Existing files are never replaced, and no old
archives are automatically deleted. A successful event requires both complete synchronized
archive publication and confirmed job completion. If a crash or database error leaves an
existing archive without confirmed completion, Worker reports `unconfirmed`/`output_exists`
and preserves the file. Inspect it with the ordinary matching-build `backup verify` command;
the scheduler does not automatically adopt, rename or remove it. Manage retention separately.

Structured events use target `backup.daily` and event values `enabled`, `disabled`, `started`,
`retry_scheduled`, `succeeded`, `exhausted` and `unconfirmed`. Status fields contain only the
UTC slot, attempt, fixed archive basename, retry/completion timestamp and fixed reason class.
Ordinary capture failure leaves login, sync and the API running. Disable and restart to stop
new scheduling and retries while preserving job history and existing archives.

Backup work does not block Worker maintenance or the async request runtime. Shutdown stops
new scheduling and gives an active capture the existing common ten-second drain. The CLI
exits with failure if that drain times out; interrupted work is not recorded as successful.
An embedding host receiving `ShutdownTimedOut` must exit, as with other local operations.
Verification and fresh-directory restoration use the unchanged matching-build procedure.

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
migration-snapshot recovery checks. Its separate online workflow continuously submits encrypted
public Device writes during capture, checks pre-capture and post-completion markers, restores
onto a fresh volume and verifies original Devices, decryption and team isolation across another
actual restart. Online restoration is not compared for full equality with a newer source.
