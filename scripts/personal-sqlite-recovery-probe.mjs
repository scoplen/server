// SPDX-License-Identifier: AGPL-3.0-only
// Runs only in the pinned Node check image against disposable Docker volumes.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import {
  chownSync,
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

let failurePhase = "context";
const invoked =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
const [operation, run] = invoked ? process.argv.slice(2) : [];
if (invoked) {
  process.on("uncaughtExceptionMonitor", (error) => {
    const code = [
      "ERR_ASSERTION",
      "ERR_SQLITE_ERROR",
      "EACCES",
      "EPERM",
      "ENOSPC",
      "EDQUOT",
      "ENOENT",
      "EEXIST",
      "EISDIR",
    ].includes(error?.code)
      ? error.code
      : null;
    const sqliteCode =
      Number.isInteger(error?.errcode) &&
      error.errcode >= 0 &&
      error.errcode <= 65535
        ? error.errcode
        : null;
    console.error(
      `Scoplen SQLite probe failure: ${JSON.stringify({ phase: failurePhase, code, sqliteCode })}`,
    );
  });
  assert(
    /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(run),
    "invalid check identity",
  );
  assert.equal(readFileSync("/check/.container-check-owner", "utf8"), run);
}

const oldMigration = 20261024030000;
const newMigration = 20261123070000;
const vaultId = Buffer.alloc(16, 0x11);
const objectId = Buffer.alloc(16, 0x22);
const organizationId = Buffer.alloc(16, 0x33);
const envelope = Buffer.from(
  "disposable pre-upgrade encrypted-envelope fixture",
);
const objectMarker = Buffer.from(
  Array.from({ length: 256 }, (_, index) => index),
);
const keyNames = [
  "deployment.key",
  "audit-signing.key",
  "internal-ca.pem",
  "internal-ca-key.pem",
];

function ordinary(path, directory = false) {
  const metadata = lstatSync(path);
  assert(!metadata.isSymbolicLink(), "redirected recovery path");
  assert(
    directory ? metadata.isDirectory() : metadata.isFile(),
    "unexpected recovery entry type",
  );
  return metadata;
}

function checkpointSeedSchema(database) {
  failurePhase = "checkpoint-seed-schema";
  const checkpoint = database.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
  assert.equal(checkpoint.busy, 0);
  assert.equal(checkpoint.log, 0);
  assert.equal(checkpoint.checkpointed, 0);
}

function checkSchemaBaseline() {
  const path = "/tmp/checkpoint-schema.sqlite";
  const bare = "/tmp/checkpoint-schema-bare.sqlite";
  const database = new DatabaseSync(path);
  function bareSchema() {
    copyFileSync(path, bare, constants.COPYFILE_EXCL);
    const copy = new DatabaseSync(bare, { readOnly: true });
    try {
      return copy
        .prepare(
          "SELECT name FROM sqlite_schema WHERE name = 'checkpoint_probe'",
        )
        .get();
    } finally {
      copy.close();
      unlinkSync(bare);
    }
  }
  try {
    database.exec(
      "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE checkpoint_probe (id INTEGER PRIMARY KEY)",
    );
    failurePhase = "verify-schema-baseline";
    assert.equal(
      bareSchema(),
      undefined,
      "regression schema must start in WAL",
    );
    checkpointSeedSchema(database);
    failurePhase = "verify-schema-baseline";
    assert.equal(bareSchema()?.name, "checkpoint_probe");
  } finally {
    database.close();
    for (const file of [
      path,
      `${path}-wal`,
      `${path}-shm`,
      bare,
      `${bare}-wal`,
      `${bare}-shm`,
    ]) {
      if (existsSync(file)) unlinkSync(file);
    }
  }
}

function snapshot(root) {
  const directory = join(root, "scoplen.sqlite.migration-snapshots");
  const folder = ordinary(directory, true);
  assert.equal(folder.uid, 65532);
  assert.equal(folder.gid, 65532);
  assert.equal(folder.mode & 0o7777, 0o700);
  const lock = ordinary(join(root, "scoplen.sqlite.migration.lock"));
  assert.equal(lock.uid, 65532);
  assert.equal(lock.gid, 65532);
  assert.equal(lock.mode & 0o7777, 0o600);
  const names = readdirSync(directory);
  assert.equal(
    names.length,
    1,
    "expected one completed pre-migration snapshot",
  );
  assert(
    /^pre-migration-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\.sqlite$/.test(
      names[0],
    ),
  );
  const path = join(directory, names[0]);
  const metadata = ordinary(path);
  assert.equal(metadata.uid, 65532);
  assert.equal(metadata.gid, 65532);
  assert.equal(metadata.mode & 0o7777, 0o600);
  assert(!existsSync(`${path}-wal`) && !existsSync(`${path}-shm`));
  return path;
}

export function inspectDatabase(path, current) {
  ordinary(path);
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    assert.equal(
      database.prepare("PRAGMA integrity_check").get().integrity_check,
      "ok",
    );
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
    const versions = database
      .prepare(
        "SELECT version FROM _sqlx_migrations WHERE success = 1 ORDER BY version",
      )
      .all()
      .map((row) => row.version);
    assert(versions.includes(oldMigration));
    assert.equal(versions.includes(newMigration), current);
    assert.equal(versions.at(-1), current ? newMigration : oldMigration);
    const admissionTables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN ('sync_write_admission', 'sync_write_admission_clock') ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    assert.deepEqual(
      admissionTables,
      current ? ["sync_write_admission", "sync_write_admission_clock"] : [],
    );
    if (current) {
      const clock = database
        .prepare(
          "SELECT retired_through_ns FROM sync_write_admission_clock WHERE singleton = 1",
        )
        .get();
      assert.deepEqual(Buffer.from(clock.retired_through_ns), Buffer.alloc(16));
      assert.equal(
        database
          .prepare("SELECT COUNT(*) AS count FROM sync_write_admission")
          .get().count,
        0,
      );
    }
    const organization = database
      .prepare("SELECT name FROM organizations WHERE id = ?")
      .get(organizationId);
    assert.equal(organization?.name, "Disposable recovery organization");
    const inventoryTables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN ('organization_inventory_vaults', 'organization_inventory_objects', 'organization_inventory_references', 'organization_inventory_receipts', 'organization_inventory_acks', 'organization_groups', 'organization_group_members', 'organization_policies') ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    assert.deepEqual(
      inventoryTables,
      current
        ? [
            "organization_group_members",
            "organization_groups",
            "organization_inventory_acks",
            "organization_inventory_objects",
            "organization_inventory_receipts",
            "organization_inventory_references",
            "organization_inventory_vaults",
            "organization_policies",
          ]
        : [],
    );
    const accessTables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN ('organization_access_requests', 'organization_auth_activation_preflights', 'organization_auth_connection_activations', 'organization_auth_connection_receipts', 'organization_auth_connections', 'organization_auth_draft_receipts', 'organization_auth_draft_tests', 'organization_auth_drafts', 'organization_auth_link_attempts', 'organization_auth_link_comparison_keys', 'organization_auth_links', 'organization_grants') ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    assert.deepEqual(
      accessTables,
      current
        ? [
            "organization_access_requests",
            "organization_auth_activation_preflights",
            "organization_auth_connection_activations",
            "organization_auth_connection_receipts",
            "organization_auth_connections",
            "organization_auth_draft_receipts",
            "organization_auth_draft_tests",
            "organization_auth_drafts",
            "organization_auth_link_attempts",
            "organization_auth_link_comparison_keys",
            "organization_auth_links",
            "organization_grants",
          ]
        : [],
    );
    if (current) {
      for (const table of accessTables) {
        assert.equal(
          database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get()
            .count,
          0,
          "upgrade must preserve an empty Grant, access request and Organization identity history",
        );
      }
    }
    const userCaTables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN ('organization_user_ca_krl_activation', 'organization_user_ca_krls', 'organization_user_ca_revocations', 'organization_user_cas', 'organization_user_certificates') ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    assert.deepEqual(
      userCaTables,
      current
        ? [
            "organization_user_ca_krl_activation",
            "organization_user_ca_krls",
            "organization_user_ca_revocations",
            "organization_user_cas",
            "organization_user_certificates",
          ]
        : [],
    );
    const browserTables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN ('account_browser_access_tokens', 'account_browser_families', 'account_browser_refresh_tokens') ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    assert.deepEqual(
      browserTables,
      current
        ? [
            "account_browser_access_tokens",
            "account_browser_families",
            "account_browser_refresh_tokens",
          ]
        : [],
    );
    if (current) {
      const inventory = database
        .prepare(
          "SELECT v.vault_id, s.kind, s.current_seq FROM organization_inventory_vaults v JOIN sync_vaults s ON s.vault_id = v.vault_id WHERE v.organization_id = ?",
        )
        .get(organizationId);
      assert.deepEqual(Buffer.from(inventory.vault_id), organizationId);
      assert.equal(inventory.kind, "organization");
      assert.equal(inventory.current_seq, 0);
    }
    for (const table of ["sync_objects", "sync_object_versions"]) {
      const row = database
        .prepare(
          `SELECT sequence, envelope, key_epoch FROM ${table} WHERE vault_id = ? AND object_id = ?`,
        )
        .get(vaultId, objectId);
      assert.equal(row?.sequence, 1);
      assert.deepEqual(Buffer.from(row.envelope), envelope);
      assert.equal(row.key_epoch, 1);
      const schema = database
        .prepare(
          "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
        )
        .get(table).sql;
      assert.equal(/length\(envelope\)\s*<=\s*266240/.test(schema), !current);
    }
  } finally {
    database.close();
  }
}

function inspectStandaloneSnapshot(root) {
  const temporary = "/tmp/standalone-snapshot.sqlite";
  copyFileSync(snapshot(root), temporary, constants.COPYFILE_EXCL);
  try {
    inspectDatabase(temporary, false);
  } finally {
    unlinkSync(temporary);
  }
}

function assertLiveCommittedWal(root) {
  failurePhase = "verify-live-wal";
  const wal = ordinary(join(root, "scoplen.sqlite-wal"));
  assert(wal.size > 0, "committed WAL must still be live");
  failurePhase = "verify-wal-readback";
  inspectDatabase(join(root, "scoplen.sqlite"), false);
  failurePhase = "verify-base-only";
  const bare = "/tmp/base-without-wal.sqlite";
  copyFileSync(join(root, "scoplen.sqlite"), bare, constants.COPYFILE_EXCL);
  const database = new DatabaseSync(bare);
  try {
    assert.equal(
      database
        .prepare("SELECT name FROM organizations WHERE id = ?")
        .get(organizationId),
      undefined,
      "seeded row was already checkpointed into the main database",
    );
  } finally {
    database.close();
    unlinkSync(bare);
  }
}

function assertMaterial(root) {
  for (const name of keyNames) assert(ordinary(join(root, name)).size > 0);
  ordinary(join(root, "objects"), true);
  ordinary(join(root, "objects", "ci-recovery-marker"));
  assert.deepEqual(
    readFileSync(join(root, "objects", "ci-recovery-marker")),
    objectMarker,
  );
}

function copyOrdinary(source, destination) {
  ordinary(source);
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
  chownSync(destination, 65532, 65532);
  chmodSync(destination, 0o600);
}

function copyObjects(source, destination) {
  ordinary(source, true);
  mkdirSync(destination, { mode: 0o700 });
  chownSync(destination, 65532, 65532);
  chmodSync(destination, 0o700);
  for (const name of readdirSync(source)) {
    const from = join(source, name);
    const to = join(destination, name);
    const metadata = lstatSync(from);
    assert(!metadata.isSymbolicLink(), "redirected object path");
    if (metadata.isDirectory()) copyObjects(from, to);
    else copyOrdinary(from, to);
  }
}

function databaseState(path) {
  ordinary(path);
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    assert.equal(
      database.prepare("PRAGMA integrity_check").get().integrity_check,
      "ok",
    );
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
    const tables = database
      .prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
      )
      .all()
      .map((row) => row.name);
    return JSON.stringify(
      tables.map((table) => {
        assert(/^[A-Za-z0-9_]+$/.test(table), "unsupported fixture table name");
        const query = database.prepare(`SELECT * FROM "${table}"`);
        query.setReadBigInts(true);
        const rows = query
          .all()
          .map((row) =>
            JSON.stringify(row, (_key, value) => {
              if (typeof value === "bigint")
                return { integer: value.toString() };
              if (value instanceof Uint8Array)
                return { bytes: Buffer.from(value).toString("hex") };
              return value;
            }),
          )
          .sort();
        return [table, rows];
      }),
    );
  } finally {
    database.close();
  }
}

function compareObjects(source, restored) {
  ordinary(source, true);
  ordinary(restored, true);
  const names = readdirSync(source).sort();
  assert.deepEqual(
    readdirSync(restored).sort(),
    names,
    "restored object names changed",
  );
  for (const name of names) {
    const from = join(source, name);
    const to = join(restored, name);
    const metadata = lstatSync(from);
    assert(!metadata.isSymbolicLink(), "redirected source object");
    if (metadata.isDirectory()) compareObjects(from, to);
    else {
      ordinary(from);
      ordinary(to);
      assert(
        readFileSync(from).equals(readFileSync(to)),
        "restored object bytes changed",
      );
    }
  }
}

export function inspectDailyJobs(path) {
  ordinary(path);
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    return database
      .prepare(
        "SELECT id, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error FROM jobs WHERE kind = 'backup.daily' ORDER BY created_at_ms, id",
      )
      .all()
      .map((row) => {
        const slot = Buffer.from(row.payload).toString("utf8");
        assert(/^\d{4}-\d{2}-\d{2}$/.test(slot), "invalid daily slot payload");
        const day = Date.parse(`${slot}T00:00:00Z`) / 86_400_000;
        assert(Number.isSafeInteger(day), "invalid daily slot day");
        assert.equal(
          new Date(day * 86_400_000).toISOString().slice(0, 10),
          slot,
        );
        const encoded = Buffer.alloc(8);
        encoded.writeBigInt64BE(BigInt(day));
        const id = createHash("sha256")
          .update("scoplen.backup.daily.v1\0")
          .update(encoded)
          .digest()
          .subarray(0, 16);
        assert(Buffer.from(row.id).equals(id), "invalid daily slot identity");
        return {
          slot,
          attempts: row.attempts,
          owner: row.lease_owner,
          leaseUntil: row.lease_until_ms,
          availableAt: row.available_at_ms,
          createdAt: row.created_at_ms,
          finishedAt: row.finished_at_ms,
          lastError: row.last_error,
        };
      });
  } finally {
    database.close();
  }
}

if (operation === "check-context") {
  assert.equal(process.getuid(), 65532);
  assert.equal(process.getgid(), 65532);
  assert.deepEqual(readdirSync("/check"), [".container-check-owner"]);
  checkSchemaBaseline();
  console.log("context-ready");
} else if (operation === "seed-and-hold") {
  failurePhase = "open-seed-database";
  const root = "/var/lib/spl";
  ordinary(root, true);
  const database = new DatabaseSync(join(root, "scoplen.sqlite"));
  try {
    failurePhase = "verify-seed-schema";
    assert.equal(
      database
        .prepare("SELECT MAX(version) AS version FROM _sqlx_migrations")
        .get().version,
      oldMigration,
    );
    // A fresh server may leave schema pages in WAL; seed only after that baseline is durable.
    checkpointSeedSchema(database);
    failurePhase = "seed-rows";
    database.exec(
      "PRAGMA foreign_keys = ON; PRAGMA wal_autocheckpoint = 0; BEGIN IMMEDIATE",
    );
    try {
      database
        .prepare(
          "INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, 123)",
        )
        .run(organizationId, "Disposable recovery organization");
      database
        .prepare(
          "INSERT INTO sync_vaults (vault_id, kind, current_seq, purge_horizon) VALUES (?, 'organization', 1, 0)",
        )
        .run(vaultId);
      for (const table of ["sync_objects", "sync_object_versions"]) {
        database
          .prepare(
            `INSERT INTO ${table} (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch) VALUES (?, ?, 1, ?, 0, NULL, 123, 1)`,
          )
          .run(vaultId, objectId, envelope);
      }
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
  } catch (error) {
    database.close();
    throw error;
  }
  failurePhase = "write-object-marker";
  ordinary(join(root, "objects"), true);
  writeFileSync(join(root, "objects", "ci-recovery-marker"), objectMarker, {
    flag: "wx",
    mode: 0o600,
  });
  failurePhase = "verify-material";
  assertMaterial(root);
  assertLiveCommittedWal(root);
  // Pin the checkpoint boundary before subsequent public Account writes.
  database.exec("BEGIN");
  database.prepare("SELECT COUNT(*) FROM organizations").get();
  failurePhase = "hold-seed";
  process.on("SIGTERM", () => {
    database.close();
    process.exit(0);
  });
  setTimeout(() => {
    database.close();
    process.exit(1);
  }, 600_000);
  console.log("ready");
  setInterval(() => {}, 60_000);
} else if (operation === "check-live-wal") {
  assertLiveCommittedWal("/var/lib/spl");
} else if (operation === "check-upgrade") {
  const root = "/var/lib/spl";
  inspectStandaloneSnapshot(root);
  inspectDatabase(join(root, "scoplen.sqlite"), true);
  assertMaterial(root);
} else if (operation === "check-archive-source") {
  failurePhase = "archive-source";
  const root = "/source";
  assertMaterial(root);
  assert(
    ordinary(join(root, "scoplen.sqlite-wal")).size > 0,
    "archive fixture must retain committed WAL pages",
  );
  const source = new DatabaseSync(join(root, "scoplen.sqlite"), {
    readOnly: true,
  });
  const barePath = "/tmp/archive-source-without-wal.sqlite";
  copyFileSync(join(root, "scoplen.sqlite"), barePath, constants.COPYFILE_EXCL);
  const bare = new DatabaseSync(barePath, { readOnly: true });
  try {
    const count = (database, table) =>
      database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count;
    const accounts = count(source, "identity_accounts");
    assert(accounts >= 2, "archive source must include both public Accounts");
    assert(
      count(bare, "identity_accounts") < accounts,
      "at least one public Account must still be committed only in WAL",
    );
    assert(
      count(source, "deployment_audit_events") > 0,
      "archive source must include deployment audit",
    );
    assert(
      count(source, "audit_events") > 0,
      "archive source must include team audit",
    );
    assert(
      count(source, "sync_objects") >= 3,
      "archive source must include both encrypted Personal Hosts",
    );
  } finally {
    bare.close();
    source.close();
    unlinkSync(barePath);
  }
} else if (
  operation === "prepare-archive-parent" ||
  operation === "prepare-daily-parent" ||
  operation === "prepare-daily-collision"
) {
  failurePhase = "archive-parent";
  const root = "/recovery";
  ordinary(root, true);
  assert.deepEqual(
    readdirSync(root),
    [],
    "archive parent volume must be fresh",
  );
  chownSync(root, 65532, 65532);
  chmodSync(root, 0o700);
  const passphrase = join(root, "passphrase.txt");
  writeFileSync(passphrase, randomBytes(32).toString("base64url"), {
    flag: "wx",
    mode: 0o600,
  });
  chownSync(passphrase, 65532, 65532);
  chmodSync(passphrase, 0o600);
  assert(!existsSync(join(root, "restored")), "restore target must be absent");
  if (operation !== "prepare-archive-parent") {
    const archives = join(root, "archives");
    mkdirSync(archives, { mode: 0o700 });
    chownSync(archives, 65532, 65532);
    if (operation === "prepare-daily-collision") {
      const slot = new Date().toISOString().slice(0, 10);
      const collision = join(archives, `scoplen-${slot}.age`);
      writeFileSync(
        collision,
        "Owned daily collision; preserve these bytes.\n",
        {
          flag: "wx",
          mode: 0o600,
        },
      );
      chownSync(collision, 65532, 65532);
    }
  }
} else if (operation === "prepare-daily-source") {
  failurePhase = "daily-source";
  const root = "/source-parent/restored";
  assert.deepEqual(inspectDailyJobs(join(root, "scoplen.sqlite")), []);
  const objects = join(root, "objects");
  ordinary(objects, true);
  const descriptor = openSync(
    join(objects, "ci-daily-capture-buffer"),
    "wx",
    0o600,
  );
  try {
    const chunk = randomBytes(1024 * 1024);
    for (let index = 0; index < 64; index++) {
      let offset = 0;
      while (offset < chunk.length)
        offset += writeSync(descriptor, chunk, offset);
    }
  } finally {
    closeSync(descriptor);
  }
} else if (operation === "daily-state") {
  failurePhase = "daily-state";
  const archives = "/recovery/archives";
  ordinary(archives, true);
  const entries = readdirSync(archives).sort();
  const files = entries.filter((name) =>
    /^scoplen-\d{4}-\d{2}-\d{2}\.age$/.test(name),
  );
  console.log(
    JSON.stringify({
      observedAt: Date.now(),
      jobs: inspectDailyJobs("/source-parent/restored/scoplen.sqlite"),
      archives: files.map((name) => ({
        name,
        size: ordinary(join(archives, name)).size,
        sha256: createHash("sha256")
          .update(readFileSync(join(archives, name)))
          .digest("hex"),
      })),
      staging: entries.filter((name) => !files.includes(name)).length,
    }),
  );
} else if (operation === "deny-daily-completion") {
  failurePhase = "daily-completion-denial";
  const path = "/source-parent/restored/scoplen.sqlite";
  const jobs = inspectDailyJobs(path);
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].attempts, 1);
  assert.equal(jobs[0].finishedAt, null);
  const database = new DatabaseSync(path);
  try {
    database.exec(
      "CREATE TRIGGER ci_deny_daily_completion BEFORE UPDATE OF finished_at_ms ON jobs WHEN NEW.kind = 'backup.daily' AND OLD.finished_at_ms IS NULL AND NEW.finished_at_ms IS NOT NULL BEGIN SELECT RAISE(ABORT, 'owned completion denial'); END",
    );
  } finally {
    database.close();
  }
  assert.deepEqual(
    inspectDailyJobs(path),
    jobs,
    "completion denial changed job rows",
  );
} else if (operation === "empty-daily-passphrase") {
  failurePhase = "daily-empty-passphrase";
  const path = "/recovery/passphrase.txt";
  const metadata = ordinary(path);
  assert.equal(metadata.uid, 65532);
  assert.equal(metadata.mode & 0o7777, 0o600);
  assert(metadata.size > 0);
  writeFileSync(path, Buffer.alloc(0));
} else if (operation === "check-daily-collision") {
  const slot = new Date().toISOString().slice(0, 10);
  const archives = "/recovery/archives";
  assert.deepEqual(readdirSync(archives), [`scoplen-${slot}.age`]);
  assert.equal(
    readFileSync(join(archives, `scoplen-${slot}.age`), "utf8"),
    "Owned daily collision; preserve these bytes.\n",
  );
} else if (
  operation === "check-archive-restore" ||
  operation === "check-online-archive-restore"
) {
  failurePhase = "archive-restore";
  const online = operation === "check-online-archive-restore";
  const source = online ? "/source-parent/restored" : "/source";
  const restored = "/recovery/restored";
  const metadata = ordinary(restored, true);
  assert.equal(metadata.uid, 65532);
  assert.equal(metadata.gid, 65532);
  assert.equal(metadata.mode & 0o7777, 0o700);
  for (const name of keyNames) {
    ordinary(join(source, name));
    ordinary(join(restored, name));
    assert(
      readFileSync(join(source, name)).equals(
        readFileSync(join(restored, name)),
      ),
      "archive changed required key bytes",
    );
  }
  assert(
    readFileSync(join(restored, "kms.key")).equals(
      readFileSync(join(source, online ? "kms.key" : "deployment.key")),
    ),
    "archive changed the configured KMS key",
  );
  if (online) {
    const database = new DatabaseSync(join(restored, "scoplen.sqlite"), {
      readOnly: true,
    });
    try {
      assert.equal(
        database.prepare("PRAGMA integrity_check").get().integrity_check,
        "ok",
      );
      assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
      assert.equal(
        database
          .prepare(
            "SELECT MAX(version) AS version FROM _sqlx_migrations WHERE success = 1",
          )
          .get().version,
        newMigration,
      );
    } finally {
      database.close();
    }
  } else {
    const sourceDatabase = join(source, "scoplen.sqlite");
    ordinary(sourceDatabase);
    assert(
      !existsSync(`${sourceDatabase}-wal`),
      "source WAL must be checkpointed before state comparison",
    );
    // A WAL-mode header still needs writable sidecar storage when read-only.
    const temporary = "/tmp/archive-source-checkpointed.sqlite";
    copyFileSync(sourceDatabase, temporary, constants.COPYFILE_EXCL);
    try {
      assert(
        databaseState(temporary) ===
          databaseState(join(restored, "scoplen.sqlite")),
        "archive changed retained database, audit or Account state",
      );
    } finally {
      unlinkSync(temporary);
    }
  }
  compareObjects(join(source, "objects"), join(restored, "objects"));
  for (const name of [
    "deployment.lease",
    "scoplen.sqlite-wal",
    "scoplen.sqlite-shm",
    "scoplen.sqlite.migration-snapshots",
  ])
    assert(
      !existsSync(join(restored, name)),
      "archive copied excluded operational state",
    );
} else if (operation === "restore-offline") {
  const source = "/source";
  const recovery = "/recovery";
  ordinary(source, true);
  ordinary(recovery, true);
  assert.deepEqual(readdirSync(recovery), [], "recovery volume must be empty");
  inspectStandaloneSnapshot(source);
  assertMaterial(source);
  chownSync(recovery, 65532, 65532);
  chmodSync(recovery, 0o700);
  copyOrdinary(snapshot(source), join(recovery, "scoplen.sqlite"));
  for (const name of keyNames)
    copyOrdinary(join(source, name), join(recovery, name));
  copyObjects(join(source, "objects"), join(recovery, "objects"));
  assert(
    !existsSync(join(recovery, "scoplen.sqlite-wal")) &&
      !existsSync(join(recovery, "scoplen.sqlite-shm")),
  );
  inspectDatabase(join(recovery, "scoplen.sqlite"), false);
  assertMaterial(recovery);
} else if (operation === "check-recovery") {
  const source = "/source";
  const recovery = "/recovery";
  inspectStandaloneSnapshot(source);
  inspectDatabase(join(recovery, "scoplen.sqlite"), false);
  assertMaterial(recovery);
  for (const name of keyNames)
    assert.deepEqual(
      readFileSync(join(recovery, name)),
      readFileSync(join(source, name)),
    );
  assert.deepEqual(
    readFileSync(join(recovery, "objects", "ci-recovery-marker")),
    readFileSync(join(source, "objects", "ci-recovery-marker")),
  );
} else if (invoked) {
  assert.fail("unknown recovery probe");
}
