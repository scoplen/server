// SPDX-License-Identifier: AGPL-3.0-only
// Runs only in the pinned Node check image against disposable Docker volumes.
import assert from "node:assert/strict";
import {
  chownSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";

let failurePhase = "context";
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

const [operation, run] = process.argv.slice(2);
assert(
  /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(run),
  "invalid check identity",
);
assert.equal(readFileSync("/check/.container-check-owner", "utf8"), run);

const oldMigration = 20261024030000;
const newMigration = 20261025020000;
const vaultId = Buffer.alloc(16, 0x11);
const objectId = Buffer.alloc(16, 0x22);
const organizationId = Buffer.alloc(16, 0x33);
const envelope = Buffer.from(
  "disposable pre-upgrade encrypted-envelope fixture",
);
const objectMarker = Buffer.from("disposable object-file recovery fixture\n");
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

function inspectDatabase(path, current) {
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
        database.prepare("SELECT COUNT(*) AS count FROM sync_write_admission").get()
          .count,
        0,
      );
    }
    const organization = database
      .prepare("SELECT name FROM organizations WHERE id = ?")
      .get(organizationId);
    assert.equal(organization?.name, "Disposable recovery organization");
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
  failurePhase = "hold-seed";
  process.on("SIGTERM", () => {
    database.close();
    process.exit(0);
  });
  setTimeout(() => {
    database.close();
    process.exit(1);
  }, 300_000);
  console.log("ready");
  setInterval(() => {}, 60_000);
} else if (operation === "check-live-wal") {
  assertLiveCommittedWal("/var/lib/spl");
} else if (operation === "check-upgrade") {
  const root = "/var/lib/spl";
  inspectStandaloneSnapshot(root);
  inspectDatabase(join(root, "scoplen.sqlite"), true);
  assertMaterial(root);
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
} else {
  assert.fail("unknown recovery probe");
}
