// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertAccountAcceptance,
  assertOwnedFixture,
  assertOwnedResource,
  assertPrivateDirectoryArchive,
  describeCheckFailure,
  describeImageBuildFailure,
  describeWalHolderFailure,
  prepareRecoveryProbeContext,
} from "./check-personal-container.mjs";

test("Account acceptance requires the explicit completed password and sync receipt", () => {
  assert.doesNotThrow(() =>
    assertAccountAcceptance({ account_password_sync_verified: true }),
  );
  for (const receipt of [
    undefined,
    null,
    {},
    { account_password_sync_verified: false },
    { account_password_sync_verified: "true" },
    { disposable: true, operator_lifecycle_verified: true },
  ]) {
    assert.throws(() => assertAccountAcceptance(receipt));
  }
});

test("recovery probe follows the latest SQLite migration and preserves its old-image anchor", async () => {
  const migrations = await readdir(
    new URL("../crates/scoplen-store/migrations/sqlite/", import.meta.url),
  );
  const versions = migrations
    .filter((name) => /^\d{14}_.+\.sql$/.test(name))
    .map((name) => Number(name.slice(0, 14)));
  const source = await readFile(
    new URL("./personal-sqlite-recovery-probe.mjs", import.meta.url),
    "utf8",
  );
  const old = Number(source.match(/const oldMigration = (\d+);/)[1]);
  const current = Number(source.match(/const newMigration = (\d+);/)[1]);
  assert.equal(old, 20261024030000, "matching historical image stays pinned");
  assert(versions.includes(old));
  assert.equal(
    current,
    Math.max(...versions),
    "new migrations must update the recovery consumer",
  );
});

test("actual recovery probe reports a bounded failure before opening an invalid context", async () => {
  const { error, stdout, stderr } = await new Promise((accept) => {
    execFile(
      process.execPath,
      [
        fileURLToPath(
          new URL("./personal-sqlite-recovery-probe.mjs", import.meta.url),
        ),
        "seed-and-hold",
        "invalid",
      ],
      { timeout: 10_000, windowsHide: true },
      (error, stdout, stderr) => accept({ error, stdout, stderr }),
    );
  });
  assert.equal(error?.code, 1);
  assert.equal(stdout, "");
  assert.deepEqual(describeWalHolderFailure({ ExitCode: error.code }, stderr), {
    exitCode: 1,
    oomKilled: false,
    probe: { phase: "context", code: "ERR_ASSERTION", sqliteCode: null },
  });
});

test("WAL holder failures expose only fixed probe phases and bounded status", () => {
  const secret = "synthetic-private-value";
  for (const phase of [
    "verify-base-only",
    "checkpoint-seed-schema",
    "verify-schema-baseline",
  ]) {
    const stderr = `Scoplen SQLite probe failure: ${JSON.stringify({
      phase,
      code: "ERR_SQLITE_ERROR",
      sqliteCode: 14,
      message: secret,
    })}\n${secret}`;
    assert.deepEqual(
      describeWalHolderFailure(
        { ExitCode: 1, OOMKilled: false, Error: secret },
        stderr,
      ),
      {
        exitCode: 1,
        oomKilled: false,
        probe: {
          phase,
          code: "ERR_SQLITE_ERROR",
          sqliteCode: 14,
        },
      },
    );
  }
  for (const value of [
    secret,
    "{",
    JSON.stringify({ phase: secret }),
    "null",
  ]) {
    const result = describeWalHolderFailure(
      { ExitCode: secret, OOMKilled: secret },
      `Scoplen SQLite probe failure: ${value}`,
    );
    assert.deepEqual(result, { exitCode: null, oomKilled: false, probe: null });
    assert(!JSON.stringify(result).includes(secret));
  }
  const result = describeWalHolderFailure(
    { ExitCode: 137, OOMKilled: true },
    `Scoplen SQLite probe failure: ${JSON.stringify({
      phase: "seed-rows",
      code: secret,
      sqliteCode: 65536,
    })}`,
  );
  assert.deepEqual(result, {
    exitCode: 137,
    oomKilled: true,
    probe: { phase: "seed-rows", code: null, sqliteCode: null },
  });
});

test("build failures expose only fixed categories, stage names and bounded exit metadata", () => {
  const secret = "synthetic-private-value";
  const describe = (stderr, error = { code: 1 }) =>
    describeImageBuildFailure({ error, stdout: secret, stderr });
  assert.deepEqual(
    describe(`#17 [server-build 8/8] RUN ${secret}\nno space left on device`),
    {
      category: "storage-exhausted",
      lastObservedStage: "server-build",
      exitCode: 1,
      signal: null,
    },
  );
  for (const [message, expected] of [
    ["cannot allocate memory", "memory-or-kill"],
    ["process exited with exit code: 137", "memory-or-kill"],
    ["could not resolve host", "network"],
    ["error[E0308]: could not compile", "compiler"],
    [secret, "unknown"],
  ]) {
    const result = describe(
      `#2 [console-build 1/2]\n#3 [runtime 1/7]\n${secret}\n${message}`,
    );
    assert.equal(result.category, expected);
    assert.equal(result.lastObservedStage, "runtime");
    assert(!JSON.stringify(result).includes(secret));
  }
  assert.equal(
    describe("", { killed: true, signal: "SIGTERM" }).category,
    "deadline-or-kill",
  );
  assert.equal(
    describe("", { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }).category,
    "output-limit",
  );
  assert.equal(
    describe("#4 [historical-build 8/8] error[E0308]: could not compile")
      .lastObservedStage,
    "historical-build",
  );
  assert.deepEqual(
    describe(secret, { code: secret, signal: secret, message: secret }),
    {
      category: "unknown",
      lastObservedStage: "unknown",
      exitCode: null,
      signal: null,
    },
  );
});

test("post-build failures expose fixed phases, reasons and bounded metadata only", () => {
  const secret = "synthetic-private-value";
  const error = new Error(secret, {
    cause: { code: 7, signal: secret, message: secret, stdout: secret },
  });
  for (const phase of [
    "production image metadata",
    "image data-directory validation",
    "probe image pull",
    "non-root recovery probe admission",
    "TLS fixture preparation",
    "historical source extraction",
    "matching old image build",
    "old schema seed",
    "SQLite migration snapshot",
    "offline snapshot restore",
    "matching old image recovery",
  ]) {
    const description = describeCheckFailure({ phase, error });
    assert.equal(description.phase, phase);
    assert.equal(description.category, "command");
    assert.equal(description.exitCode, 7);
    assert.equal(description.signal, null);
    assert(!JSON.stringify(description).includes(secret));
  }
  assert.deepEqual(
    describeCheckFailure({ phase: secret, error: { code: secret } }),
    {
      phase: "unknown",
      category: "operation",
      reason: null,
      ioCode: null,
      exitCode: null,
      signal: null,
    },
  );
  for (const code of ["ENOSPC", "EDQUOT", "EACCES", "EPERM"]) {
    const description = describeCheckFailure({
      phase: "production image build",
      error: { code, message: secret },
      diagnosticWrite: true,
    });
    assert.equal(description.category, "private-diagnostic-write");
    assert.equal(description.ioCode, code);
    assert(!JSON.stringify(description).includes(secret));
  }
  for (const [message, reason] of [
    ["committed WAL fixture exited before readiness", "wal-holder-exit"],
    ["committed WAL fixture timed out", "wal-holder-timeout"],
  ]) {
    assert.equal(
      describeCheckFailure({
        phase: "old schema seed",
        error: { code: "ERR_ASSERTION", message: `${message}: ${secret}` },
      }).reason,
      reason,
    );
  }
});

test("non-root recovery context exposes only the public owner marker without widening private files", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "scoplen-probe-context-test-"),
  );
  try {
    const run = randomUUID();
    const privateFile = join(directory, "private.txt");
    await writeFile(privateFile, "synthetic-private-value", { mode: 0o600 });
    const parentMode = (await lstat(directory)).mode;
    const privateMode = (await lstat(privateFile)).mode;
    const context = await prepareRecoveryProbeContext(directory, run);
    assert.deepEqual(await readdir(context), [".container-check-owner"]);
    assert.equal(
      await readFile(join(context, ".container-check-owner"), "utf8"),
      run,
    );
    assert.equal((await lstat(directory)).mode, parentMode);
    assert.equal((await lstat(privateFile)).mode, privateMode);
    if (process.platform !== "win32") {
      assert.equal((await lstat(context)).mode & 0o7777, 0o755);
      assert.equal(
        (await lstat(join(context, ".container-check-owner"))).mode & 0o7777,
        0o444,
      );
    }
    await assert.rejects(prepareRecoveryProbeContext(directory, run));
    await assert.rejects(prepareRecoveryProbeContext(directory, "invalid"));
    assert.equal(
      await readFile(privateFile, "utf8"),
      "synthetic-private-value",
    );
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("directory-mode diagnostics expose only bounded image permission bits", () => {
  const secret = "synthetic-private-value";
  const describe = (
    actual,
    expected,
    message = "image data directory is not private",
  ) =>
    describeCheckFailure({
      phase: "image data-directory validation",
      error: { code: "ERR_ASSERTION", message, actual, expected },
    });
  const unchanged = {
    phase: "image data-directory validation",
    category: "validation",
    reason: "directory-mode",
    ioCode: null,
    exitCode: null,
    signal: null,
  };
  assert.deepEqual(describe(0o755, 0o700), {
    ...unchanged,
    actualMode: 0o755,
    expectedMode: 0o700,
  });
  assert.deepEqual(describe(0, 0o7777), {
    ...unchanged,
    actualMode: 0,
    expectedMode: 0o7777,
  });
  assert(
    !JSON.stringify(
      describe(0o755, 0o700, `image data directory is not private: ${secret}`),
    ).includes(secret),
  );
  for (const [actual, expected] of [
    [secret, 0o700],
    [0o755, secret],
    [-1, 0o700],
    [0o755, -1],
    [0o10000, 0o700],
    [0o755, 0o10000],
    [0.5, 0o700],
    [0o755, null],
    [Number.NaN, 0o700],
    [0o755, Number.POSITIVE_INFINITY],
    [{ secret }, 0o700],
    [[0o755], 0o700],
  ]) {
    const description = describe(actual, expected);
    assert.equal(JSON.stringify(description), JSON.stringify(unchanged));
    assert(!JSON.stringify(description).includes(secret));
  }
  assert.equal(
    JSON.stringify(
      describe(0o755, 0o700, "image data directory has the wrong owner"),
    ),
    JSON.stringify({ ...unchanged, reason: "directory-owner" }),
  );
});

test("a real private diagnostic write failure reports its phase without path or output disclosure", async () => {
  const parent = await realpath(tmpdir());
  const run = randomUUID();
  const directory = await realpath(
    await mkdtemp(join(parent, `scoplen-personal-container-${run}-`)),
  );
  try {
    await writeFile(join(directory, ".container-check-owner"), run, {
      flag: "wx",
      mode: 0o600,
    });
    const secret = "synthetic-private-value";
    const result = await new Promise((accept) => {
      execFile(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `
        const { writePrivateDiagnostic } = await import(process.env.SCOPLEN_TEST_MODULE);
        try {
          await writePrivateDiagnostic(process.env.SCOPLEN_TEST_PATH, process.env.SCOPLEN_TEST_SECRET, "production image build");
        } catch { process.exitCode = 1; }
      `,
        ],
        {
          env: {
            ...process.env,
            SCOPLEN_TEST_MODULE: new URL(
              "./check-personal-container.mjs",
              import.meta.url,
            ).href,
            SCOPLEN_TEST_PATH: join(directory, "absent", secret),
            SCOPLEN_TEST_SECRET: secret,
          },
        },
        (error, stdout, stderr) => accept({ error, stdout, stderr }),
      );
    });
    assert.equal(result.error?.code, 1);
    assert.equal(result.stdout, "");
    assert(!result.stderr.includes(secret));
    assert(!result.stderr.includes(directory));
    const description = JSON.parse(
      result.stderr.trim().replace(/^Personal container check failure: /, ""),
    );
    assert.equal(description.phase, "production image build");
    assert.equal(description.category, "private-diagnostic-write");
    assert.equal(description.ioCode, "ENOENT");
  } finally {
    await assertOwnedFixture(directory, parent, run);
    await rm(directory, { recursive: true });
  }
});

test("cleanup refuses foreign Docker ownership even inside the expected Compose project", () => {
  const labels = {
    "com.scoplen.personal-container-check": "current",
    "com.docker.compose.project": "expected",
  };
  assertOwnedResource(labels, "current", "expected");
  assert.throws(() => assertOwnedResource(labels, "another", "expected"));
  assert.throws(() => assertOwnedResource(labels, "current", "another"));
  assert.throws(() => assertOwnedResource(undefined, "current"));
});

test("actual image-directory metadata must prove private non-root ownership", () => {
  const archive = Buffer.alloc(1536);
  archive.write("spl/", 0);
  archive.write("0000700", 100);
  archive.write("0177774", 108);
  archive.write("0177774", 116);
  archive.write("00000000000", 124);
  archive.write("5", 156);
  assertPrivateDirectoryArchive(archive);
  const publicMode = Buffer.from(archive);
  publicMode.write("0000755", 100);
  assert.throws(
    () => assertPrivateDirectoryArchive(publicMode),
    (error) => {
      const description = describeCheckFailure({
        phase: "image data-directory validation",
        error,
      });
      assert.equal(description.category, "validation");
      assert.equal(description.reason, "directory-mode");
      assert.equal(description.actualMode, 0o755);
      assert.equal(description.expectedMode, 0o700);
      return true;
    },
  );
  const rootOwned = Buffer.from(archive);
  rootOwned.write("0000000", 108);
  assert.throws(
    () => assertPrivateDirectoryArchive(rootOwned),
    (error) => {
      assert.equal(
        describeCheckFailure({
          phase: "image data-directory validation",
          error,
        }).reason,
        "directory-owner",
      );
      return true;
    },
  );
  const specialBits = Buffer.from(archive);
  specialBits.write("0001700", 100);
  assert.throws(() => assertPrivateDirectoryArchive(specialBits));
  assert.throws(() => assertPrivateDirectoryArchive(Buffer.alloc(512)));
});

test("cleanup rejects replaced ownership, alternate parents and junction or symlink entries", async () => {
  const parent = await realpath(tmpdir());
  const run = randomUUID();
  const directory = await realpath(
    await mkdtemp(join(parent, `scoplen-personal-container-${run}-`)),
  );
  const outside = await realpath(
    await mkdtemp(join(parent, "scoplen-container-boundary-test-")),
  );
  try {
    const marker = join(directory, ".container-check-owner");
    const sentinel = join(outside, "retained.txt");
    await writeFile(marker, run, { flag: "wx", mode: 0o600 });
    await writeFile(sentinel, "retain", { flag: "wx", mode: 0o600 });
    await assertOwnedFixture(directory, parent, run);
    await assert.rejects(assertOwnedFixture(directory, outside, run));
    await writeFile(marker, "another check");
    await assert.rejects(assertOwnedFixture(directory, parent, run));
    await writeFile(marker, run);
    await symlink(
      outside,
      join(directory, "redirected"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await assert.rejects(assertOwnedFixture(directory, parent, run));
    assert.equal(await readFile(sentinel, "utf8"), "retain");
  } finally {
    await rm(directory, { recursive: true });
    await rm(outside, { recursive: true });
  }
});
