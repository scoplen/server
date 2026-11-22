// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../", import.meta.url));
const ownerLabel = "com.scoplen.personal-container-check";
const fixturePrefix = "scoplen-personal-container-";
const preMigrationRevision = "37af5126585254612e734f542cfd4e36670915d9";
const failurePhases = new Set([
  "preflight",
  "production image build",
  "production image metadata",
  "image data-directory validation",
  "probe image pull",
  "non-root recovery probe admission",
  "TLS fixture preparation",
  "historical source extraction",
  "matching old image build",
  "old schema seed",
  "SQLite migration snapshot",
  "native doctor on production HTTPS",
  "native doctor while stopped",
  "native doctor after restart",
  "non-root Compose startup and trusted HTTPS",
  "bundled console assets",
  "public Operator setup, Passkey login/logout and retired entry absence",
  "public Account password entry and encrypted sync",
  "team membership and Personal Host after restart",
  "restart and persistent setup/key verification",
  "offline archive source and fresh volume",
  "public encrypted archive creation",
  "public encrypted archive verification",
  "public encrypted archive restoration",
  "restored archive data verification",
  "restored Compose startup and persistent restart",
  "online archive capture and restored Device restart",
  "daily archive volume preparation",
  "daily source preparation",
  "daily API-only restart",
  "daily API-only scheduling check",
  "daily Device write preparation",
  "daily Worker ownership and renewal",
  "daily Worker events and maintenance",
  "daily Worker same-day restart",
  "daily archive verification and restoration",
  "daily Worker failures and shutdown",
  "offline snapshot restore",
  "matching old image recovery",
  "owned-resource cleanup",
  "failed-check cleanup",
]);

export function assertAccountAcceptance(receipt) {
  assert.deepEqual(receipt, {
    account_password_sync_verified: true,
    account_credential_sync_verified: true,
    account_credential_isolation_verified: true,
  });
}

export function assertTeamAcceptance(receipt) {
  assert.deepEqual(receipt, {
    team_creation_personal_sync_verified: true,
    team_settings_personal_sync_verified: true,
    team_account_isolation_verified: true,
  });
}

export function assertTeamRestartAcceptance(receipt) {
  assert.deepEqual(receipt, {
    team_membership_restart_verified: true,
    team_settings_restart_verified: true,
    team_account_isolation_restart_verified: true,
  });
}

export function assertBackupAcceptance(result, operation) {
  const messages = {
    create: "Backup created.",
    verify: "Backup verified.",
    restore: "Backup restored.",
  };
  assert(Object.hasOwn(messages, operation), "unknown backup operation");
  assert.equal(
    result.error ? result.error.code : 0,
    0,
    "backup command failed",
  );
  assert.equal(
    result.stderr,
    "",
    "successful backup command has no diagnostic",
  );
  assert.equal(
    result.stdout.replaceAll("\r\n", "\n").split("\n")[0],
    messages[operation],
    "backup command did not confirm its operation",
  );
}

export function consoleProbeImage(dockerfile) {
  const image = dockerfile.match(
    /^FROM (node:[^\s]+@sha256:[a-f0-9]{64}) AS console-dependencies\r?$/m,
  )?.[1];
  assert(image, "pinned console Node dependency stage missing");
  return image;
}

export function consoleAssetContentType(path) {
  assert(
    /^(index\.html|assets\/[A-Za-z0-9_.-]+\.(js|css|woff2|wasm))$/.test(path),
  );
  return {
    html: "text/html; charset=utf-8",
    js: "text/javascript; charset=utf-8",
    css: "text/css; charset=utf-8",
    woff2: "font/woff2",
    wasm: "application/wasm",
  }[path.split(".").at(-1)];
}

export function assertDoctorAcceptance(result, healthy) {
  assert.equal(
    result.error ? result.error.code : 0,
    healthy ? 0 : 1,
    "unexpected doctor exit code",
  );
  assert.equal(result.stderr, "", "doctor findings must use stdout only");
  const connectionFailure =
    "could not establish trusted HTTPS; check DNS, the public port, certificate chain and hostname, or explicitly supply the deployment CA.";
  const expected = [
    "PASS configuration: configuration and selected roles are valid.",
    ...["health", "readiness"].map((check) =>
      healthy
        ? `PASS ${check}: trusted public HTTPS returned the expected response.`
        : `FAIL ${check}: ${connectionFailure}`,
    ),
    "NOT CHECKED remaining diagnostics: external reachability; ACME management; clock offset; local storage permissions and capacity; direct database/object/KMS probes; backup recency; schema and gateway/host-agent compatibility; console parity.",
    "",
  ].join("\n");
  assert.equal(
    result.stdout.replaceAll("\r\n", "\n"),
    expected,
    "unexpected doctor findings",
  );
}

export function describeCheckFailure({
  phase,
  error,
  diagnosticWrite = false,
}) {
  const cause = error?.cause ?? error;
  const { exitCode, signal } = describeImageBuildFailure({ error: cause });
  const assertion = error?.code === "ERR_ASSERTION";
  const reasons = [
    ["resource belongs to another check", "resource-owner"],
    ["resource belongs to another project", "resource-project"],
    ["runtime must be non-root", "runtime-user"],
    ["runtime must use the supervisor's shutdown signal", "runtime-signal"],
    ["invalid directory archive", "directory-archive"],
    ["unexpected image directory entry", "directory-entry"],
    ["image data directory is not private", "directory-mode"],
    ["image data directory has the wrong owner", "directory-owner"],
    ["image data directory has the wrong group", "directory-group"],
    ["image data directory missing", "directory-missing"],
    ["committed WAL fixture exited before readiness", "wal-holder-exit"],
    ["committed WAL fixture timed out", "wal-holder-timeout"],
    [
      "daily capture needs persisted ownership observations",
      "daily-observations",
    ],
    ["daily Worker created duplicate slots", "daily-duplicate-slot"],
    ["daily slot was claimed more than once", "daily-duplicate-claim"],
    [
      "daily capture completed before ownership observation",
      "daily-active-interval",
    ],
    ["daily claim changed owners", "daily-owner-change"],
    ["daily claim expired during capture", "daily-lease-expired"],
    ["daily capture did not renew its lease", "daily-lease-renewal"],
    ["object hold exited early", "daily-object-hold-exit"],
    ["object hold signal timed out", "daily-object-hold-timeout"],
    ["object hold release failed", "daily-object-hold-release"],
    [
      "daily capture ended outside the held object read",
      "daily-object-hold-interval",
    ],
    [
      "daily capture did not cross a renewal interval",
      "daily-renewal-interval",
    ],
    ["daily completion was not confirmed", "daily-completion"],
    ["daily Worker capture timed out", "daily-capture-timeout"],
    ["Worker maintenance did not progress during capture", "daily-maintenance"],
  ];
  const reason =
    (assertion && typeof error.message === "string"
      ? reasons.find(([message]) => error.message.startsWith(message))?.[1]
      : null) ?? null;
  const modeMetadata =
    reason === "directory-mode" &&
    [error.actual, error.expected].every(
      (value) => Number.isInteger(value) && value >= 0 && value <= 0o7777,
    )
      ? { actualMode: error.actual, expectedMode: error.expected }
      : {};
  return {
    phase: failurePhases.has(phase) ? phase : "unknown",
    category: diagnosticWrite
      ? "private-diagnostic-write"
      : assertion
        ? "validation"
        : exitCode !== null || signal !== null
          ? "command"
          : "operation",
    reason,
    ioCode: [
      "ENOSPC",
      "EDQUOT",
      "EACCES",
      "EPERM",
      "ENOENT",
      "EEXIST",
      "EISDIR",
    ].includes(cause?.code)
      ? cause.code
      : null,
    exitCode,
    signal,
    ...modeMetadata,
  };
}

export function describeWalHolderFailure(state, stderr) {
  let probe = null;
  const prefix = "Scoplen SQLite probe failure: ";
  const line =
    typeof stderr === "string"
      ? stderr.split(/\r?\n/).find((value) => value.startsWith(prefix))
      : undefined;
  if (line) {
    try {
      const value = JSON.parse(line.slice(prefix.length));
      if (
        [
          "context",
          "open-seed-database",
          "verify-seed-schema",
          "checkpoint-seed-schema",
          "verify-schema-baseline",
          "seed-rows",
          "write-object-marker",
          "verify-material",
          "verify-live-wal",
          "verify-wal-readback",
          "verify-base-only",
          "hold-seed",
        ].includes(value?.phase)
      ) {
        probe = {
          phase: value.phase,
          code: [
            "ERR_ASSERTION",
            "ERR_SQLITE_ERROR",
            "EACCES",
            "EPERM",
            "ENOSPC",
            "EDQUOT",
            "ENOENT",
            "EEXIST",
            "EISDIR",
          ].includes(value.code)
            ? value.code
            : null,
          sqliteCode:
            Number.isInteger(value.sqliteCode) &&
            value.sqliteCode >= 0 &&
            value.sqliteCode <= 65535
              ? value.sqliteCode
              : null,
        };
      }
    } catch {
      // Raw probe output remains in the private diagnostic files.
    }
  }
  return {
    exitCode:
      Number.isInteger(state?.ExitCode) &&
      state.ExitCode >= 0 &&
      state.ExitCode <= 255
        ? state.ExitCode
        : null,
    oomKilled: state?.OOMKilled === true,
    probe,
  };
}

export async function writePrivateDiagnostic(path, value, phase) {
  try {
    await writeFile(path, value, { flag: "wx", mode: 0o600 });
  } catch (error) {
    console.error(
      `Personal container check failure: ${JSON.stringify(describeCheckFailure({ phase, error, diagnosticWrite: true }))}`,
    );
    throw new Error("private diagnostic write failed", { cause: error });
  }
}

export async function prepareRecoveryProbeContext(directory, run) {
  assert(/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(run));
  const context = join(directory, "recovery-probe-context");
  await mkdir(context, { mode: 0o755 });
  const marker = join(context, ".container-check-owner");
  await writeFile(marker, run, { flag: "wx", mode: 0o444 });
  // Only the public check identity is shared with a different container UID.
  await chmod(marker, 0o444);
  await chmod(context, 0o755);
  return context;
}

export function describeImageBuildFailure({ error, stdout, stderr }) {
  const output = `${stdout ?? ""}\n${stderr ?? ""}`;
  let category = "unknown";
  if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER")
    category = "output-limit";
  else if (
    /no space left on device|disk quota exceeded|\bENOSPC\b/i.test(output)
  )
    category = "storage-exhausted";
  else if (
    /cannot allocate memory|out of memory|signal: (?:9|killed)|exit code: 137\b/i.test(
      output,
    )
  )
    category = "memory-or-kill";
  else if (error?.killed) category = "deadline-or-kill";
  else if (
    /could not resolve host|failed to resolve|connection (?:timed out|reset|refused)|TLS handshake timeout|network is unreachable/i.test(
      output,
    )
  )
    category = "network";
  else if (
    /error\[E\d{4}\]|could not compile|linking with .+ failed|compilation terminated/i.test(
      output,
    )
  )
    category = "compiler";
  let lastObservedStage = "unknown";
  for (const stage of output.matchAll(
    /#\d+\s+\[(console-build|server-build|historical-build|runtime)(?:\s[^\]]*)?\]/g,
  ))
    lastObservedStage = stage[1];
  return {
    category,
    lastObservedStage,
    exitCode:
      Number.isInteger(error?.code) && error.code >= 0 && error.code <= 255
        ? error.code
        : null,
    signal: ["SIGTERM", "SIGKILL", "SIGABRT"].includes(error?.signal)
      ? error.signal
      : null,
  };
}

export function assertOwnedResource(labels, run, project) {
  assert.equal(labels?.[ownerLabel], run, "resource belongs to another check");
  if (project !== undefined)
    assert.equal(
      labels?.["com.docker.compose.project"],
      project,
      "resource belongs to another project",
    );
}

export function assertPrivateDirectoryArchive(archive) {
  let found = false;
  for (let offset = 0; offset + 512 <= archive.length;) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const text = (start, length) =>
      header
        .subarray(start, start + length)
        .toString("utf8")
        .replace(/\0.*$/s, "");
    const number = (start, length) =>
      Number.parseInt(text(start, length).trim() || "0", 8);
    const size = number(124, 12);
    assert(
      Number.isSafeInteger(size) &&
        size >= 0 &&
        offset + 512 + size <= archive.length,
      "invalid directory archive",
    );
    const type = text(156, 1);
    if (type !== "x" && type !== "g") {
      assert(
        !found && type === "5" && /^spl\/?$/.test(text(0, 100)),
        "unexpected image directory entry",
      );
      assert.equal(
        number(100, 8) & 0o7777,
        0o700,
        "image data directory is not private",
      );
      assert.equal(
        number(108, 8),
        65532,
        "image data directory has the wrong owner",
      );
      assert.equal(
        number(116, 8),
        65532,
        "image data directory has the wrong group",
      );
      found = true;
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  assert(found, "image data directory missing");
}

export async function assertOwnedFixture(directory, parent, run) {
  assert.equal(
    dirname(directory),
    parent,
    "fixture is outside its private parent",
  );
  assert(
    basename(directory).startsWith(`${fixturePrefix}${run}-`),
    "unexpected fixture name",
  );
  assert.equal(
    await realpath(directory),
    directory,
    "fixture root is redirected",
  );
  assert.equal(
    await readFile(join(directory, ".container-check-owner"), "utf8"),
    run,
    "fixture belongs to another check",
  );
  async function check(path) {
    const metadata = await lstat(path);
    assert(
      !metadata.isSymbolicLink(),
      "refuse to remove redirected fixture entries",
    );
    if (metadata.isDirectory())
      for (const name of await readdir(path)) await check(join(path, name));
  }
  await check(directory);
}

export async function request(
  origin,
  path,
  ca,
  servername = "localhost",
  maxBytes = 2 * 1024 * 1024,
) {
  return await new Promise((accept, reject) => {
    const outgoing = https.get(
      new URL(path, origin),
      {
        ca,
        servername,
        rejectUnauthorized: true,
        family: 4,
        timeout: 5000,
        signal: AbortSignal.timeout(5000),
      },
      (incoming) => {
        const chunks = [];
        let size = 0;
        incoming.on("data", (chunk) => {
          size += chunk.length;
          if (size > maxBytes)
            outgoing.destroy(new Error("HTTPS response exceeds check budget"));
          else chunks.push(chunk);
        });
        incoming.on("end", () =>
          accept({
            status: incoming.statusCode,
            headers: incoming.headers,
            body: Buffer.concat(chunks),
          }),
        );
        incoming.on("error", reject);
      },
    );
    outgoing.on("timeout", () =>
      outgoing.destroy(new Error("HTTPS request timed out")),
    );
    outgoing.on("error", reject);
  });
}

export async function runTeamRestart({
  fixture,
  run,
  restart,
  timeout = 120_000,
}) {
  for (const name of ["team-restart.ready", "team-restart.resume"]) {
    try {
      await lstat(join(fixture, name));
      assert.fail("team restart signal already exists");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const controller = new AbortController();
  let settled = false;
  const completed = run(controller.signal).finally(() => {
    settled = true;
  });
  // Readiness polling also observes a driver that fails before publishing its marker.
  completed.catch(() => {});
  try {
    const deadline = Date.now() + timeout;
    for (;;) {
      if (settled) {
        await completed;
        assert.fail("team restart driver exited before restart");
      }
      try {
        assert.equal(
          await readFile(join(fixture, "team-restart.ready"), "utf8"),
          "ready\n",
        );
        break;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      assert(Date.now() < deadline, "team restart driver readiness timed out");
      await new Promise((accept) => setTimeout(accept, 50));
    }
    await restart();
    assert(!settled, "team restart driver exited before restart");
    await writeFile(join(fixture, "team-restart.resume"), "resume\n", {
      flag: "wx",
      mode: 0o600,
    });
    await completed;
  } finally {
    controller.abort();
    await completed.catch(() => {});
  }
}

export async function runOnlineBackup({
  fixture,
  run,
  capture,
  restore,
  restart,
  timeout = 120_000,
  daily = false,
}) {
  const prefix = daily ? "daily-backup" : "online-backup";
  const kind = daily ? "daily" : "online";
  const names = [
    "ready",
    "start",
    "complete",
    "post",
    "resume",
    "restored",
    "restart",
  ];
  for (const name of names) {
    try {
      await lstat(join(fixture, `${prefix}.${name}`));
      assert.fail("online backup signal already exists");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const controller = new AbortController();
  let settled = false;
  const completed = run(controller.signal).finally(() => {
    settled = true;
  });
  completed.catch(() => {});
  const wait = async (name) => {
    const deadline = Date.now() + timeout;
    for (;;) {
      if (settled) {
        await completed;
        assert.fail("online backup driver exited before completion");
      }
      try {
        const contents = await readFile(
          join(fixture, `${prefix}.${name}`),
          "utf8",
        );
        assert(
          "ready\n".startsWith(contents),
          "invalid online backup driver signal",
        );
        if (contents === "ready\n") return;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      assert(Date.now() < deadline, "online backup driver signal timed out");
      await new Promise((accept) => setTimeout(accept, 50));
    }
  };
  const signal = (name) =>
    writeFile(join(fixture, `${prefix}.${name}`), "continue\n", {
      flag: "wx",
      mode: 0o600,
    });
  let capturing;
  try {
    await wait("ready");
    const started = Date.now();
    capturing = capture();
    capturing.catch(() => {});
    await signal("start");
    const interval = await capturing;
    const finished = Date.now();
    const captureStarted = daily ? interval?.started : started;
    const captureFinished = daily ? interval?.finished : finished;
    assert(
      Number.isSafeInteger(captureStarted) &&
        Number.isSafeInteger(captureFinished) &&
        captureStarted >= started &&
        captureFinished <= finished &&
        captureStarted < captureFinished,
      "invalid active capture interval",
    );
    await signal("complete");
    await wait("post");
    const writes = JSON.parse(
      await readFile(join(fixture, `${prefix}-writes.json`), "utf8"),
    );
    assert(
      Array.isArray(writes) && writes.every(Number.isSafeInteger),
      "invalid online write receipts",
    );
    const confirmed = writes.filter(
      (time) => time >= captureStarted && time <= captureFinished,
    ).length;
    assert(confirmed > 0, "no confirmed public write during active capture");
    await restore();
    await signal("resume");
    await wait("restored");
    await restart();
    assert(!settled, "online backup driver exited before restored restart");
    await signal("restart");
    await completed;
    assert.deepEqual(
      JSON.parse(
        await readFile(join(fixture, `${prefix}-acceptance.json`), "utf8"),
      ),
      {
        [`${kind}_public_writes_verified`]: true,
        [`${kind}_restored_device_team_verified`]: true,
        [`${kind}_restored_restart_verified`]: true,
      },
    );
    return confirmed;
  } finally {
    controller.abort();
    await completed.catch(() => {});
    await capturing?.catch(() => {});
  }
}

export function assertDailyCapture(samples, slot) {
  assert(
    samples.length >= 3,
    "daily capture needs persisted ownership observations",
  );
  for (const sample of samples) {
    assert.equal(sample.jobs.length, 1, "daily Worker created duplicate slots");
    assert.equal(sample.jobs[0].slot, slot);
    assert.equal(
      sample.jobs[0].attempts,
      1,
      "daily slot was claimed more than once",
    );
  }
  const claimed = samples.filter(
    (sample) => sample.jobs[0].finishedAt === null,
  );
  const active = claimed.filter(
    (sample) => sample.staging > 0 && sample.archives.length === 0,
  );
  assert(
    active.length >= 2,
    "daily capture completed before ownership observation",
  );
  const first = active[0];
  const last = active.at(-1);
  assert.equal(typeof first.jobs[0].owner, "string");
  assert(first.jobs[0].owner.length > 0);
  for (const sample of claimed) {
    assert.equal(
      sample.jobs[0].owner,
      first.jobs[0].owner,
      "daily claim changed owners",
    );
    assert(
      sample.jobs[0].leaseUntil > sample.observedAt,
      "daily claim expired during capture",
    );
  }
  assert(
    last.jobs[0].leaseUntil > first.jobs[0].leaseUntil,
    "daily capture did not renew its lease",
  );
  assert(
    last.observedAt - first.observedAt >= 20_000,
    "daily capture did not cross a renewal interval",
  );
  const completed = samples.at(-1);
  const job = completed.jobs[0];
  assert(
    Number.isSafeInteger(job.finishedAt),
    "daily completion was not confirmed",
  );
  assert.equal(job.owner, null);
  assert.equal(job.leaseUntil, null);
  assert.equal(job.lastError, null);
  assert.equal(completed.archives.length, 1);
  assert.equal(completed.archives[0].name, `scoplen-${slot}.age`);
  assert(completed.archives[0].size > 0);
  assert.equal(completed.staging, 0);
  return { started: first.observedAt, finished: last.observedAt };
}

export function assertDailyEvents(records) {
  const events = records.filter((record) => record.target === "backup.daily");
  assert(events.length > 0, "daily Worker emitted no status events");
  for (const { fields } of events) {
    assert.equal(
      fields.message,
      fields.reason === "worker_required"
        ? "scheduled backups require a Worker process"
        : "scheduled backup status",
    );
    assert(
      [
        "enabled",
        "disabled",
        "started",
        "retry_scheduled",
        "succeeded",
        "exhausted",
        "unconfirmed",
      ].includes(fields.event),
    );
    for (const name of Object.keys(fields))
      assert(
        [
          "message",
          "event",
          "slot",
          "attempt",
          "archive",
          "reason",
          "retry_at_ms",
          "completed_at_ms",
        ].includes(name),
        "unsafe daily event field",
      );
    if (fields.slot !== undefined)
      assert(/^\d{4}-\d{2}-\d{2}$/.test(fields.slot));
    if (fields.archive !== undefined)
      assert.equal(fields.archive, `scoplen-${fields.slot}.age`);
    if (fields.reason !== undefined)
      assert(
        [
          "worker_required",
          "clock_unavailable",
          "job_update_unconfirmed",
          "lease_update_unconfirmed",
          "output_exists",
          "capture_failed",
          "completion_unconfirmed",
          "attempt_limit",
          "schedule_unavailable",
        ].includes(fields.reason),
      );
    for (const name of ["attempt", "retry_at_ms", "completed_at_ms"])
      if (fields[name] !== undefined)
        assert(Number.isSafeInteger(fields[name]) && fields[name] >= 0);
  }
  return events;
}

export async function checkPersonalContainer(driverPath, doctorPath) {
  assert(
    !Object.keys(process.env).some((name) =>
      name.toUpperCase().startsWith("SPL_"),
    ),
    "unset SPL_* overrides before this disposable check",
  );
  const driver = await realpath(resolve(driverPath));
  assert(
    (await lstat(driver)).isFile(),
    "bootstrap driver must be a native executable",
  );
  const doctorCli = await realpath(resolve(doctorPath));
  assert(
    (await lstat(doctorCli)).isFile(),
    "doctor CLI must be a native executable",
  );
  const parent = await realpath(tmpdir());
  const run = randomUUID();
  const directory = await realpath(
    await mkdtemp(join(parent, `${fixturePrefix}${run}-`)),
  );
  const fixture = join(directory, "fixture");
  const serverLog = join(fixture, "server.log");
  const project = `scoplen-personal-${run}`;
  const image = `scoplen-server:personal-check-${run}`;
  const historicalImage = `scoplen-server:pre-migration-check-${run}`;
  const inspector = `${project}-image`;
  const walHolder = `${project}-wal-holder`;
  const recoveryContainer = `${project}-recovery`;
  const recoveryVolume = `${project}_recovery`;
  const archiveVolume = `${project}_archive`;
  const onlineArchiveVolume = `${project}_online_archive`;
  const dailyArchiveVolume = `${project}_daily_archive`;
  const dailyFailureVolume = `${project}_daily_failure`;
  const dailyPublicationVolume = `${project}_daily_publication`;
  const dailyInterruptedVolume = `${project}_daily_interrupted`;
  const dailyUnconfirmedVolume = `${project}_daily_unconfirmed`;
  const dailyPassphraseVolume = `${project}_daily_passphrase`;
  const dailyWorkers = [1, 2].map(
    (index) => `${project}-daily-worker-${index}`,
  );
  const dailyFailureWorker = `${project}-daily-failure-worker`;
  const dailyPublicationWorker = `${project}-daily-publication-worker`;
  const publicationHold = `${project}-daily-publication-hold`;
  const dailyAllWorker = `${project}-daily-all-worker`;
  const dailyDisabledWorker = `${project}-daily-disabled-worker`;
  const dailyInterruptedWorker = `${project}-daily-interrupted-worker`;
  const captureHold = `${project}-daily-object-hold`;
  const interruptedHold = `${project}-interrupted-object-hold`;
  const dailyUnconfirmedWorker = `${project}-daily-unconfirmed-worker`;
  const dailyPassphraseWorker = `${project}-daily-passphrase-worker`;
  let sequence = 0;
  let phase = "preflight";
  let succeeded = false;
  let imageId;
  let historicalImageId;
  let probeImage;
  let probeImageId;
  let recoveryProbeContext;
  let container;
  let certificatePrepared = false;
  await writeFile(join(directory, ".container-check-owner"), run, {
    flag: "wx",
    mode: 0o600,
  });
  console.log(`Private container-check workspace: ${directory}`);

  async function command(
    program,
    args,
    {
      environment = process.env,
      timeout = 120_000,
      allowFailure = false,
      binary = false,
      signal,
    } = {},
  ) {
    const log = join(
      directory,
      `${String(++sequence).padStart(3, "0")}-${basename(program).replace(/[^A-Za-z0-9.-]/g, "_")}`,
    );
    let closed;
    const result = await new Promise((accept) => {
      const child = execFile(
        program,
        args,
        {
          cwd: repository,
          env: environment,
          timeout,
          signal,
          windowsHide: true,
          encoding: binary ? "buffer" : "utf8",
          maxBuffer: 32 * 1024 * 1024,
        },
        (error, stdout, stderr) => accept({ error, stdout, stderr }),
      );
      if (signal)
        closed = new Promise((acceptClose) => child.once("close", acceptClose));
    });
    if (closed) await closed;
    await writePrivateDiagnostic(`${log}.stdout`, result.stdout, phase);
    await writePrivateDiagnostic(`${log}.stderr`, result.stderr, phase);
    if (result.error && !allowFailure)
      throw new Error(`${basename(program)} failed during ${phase}`, {
        cause: result.error,
      });
    return result;
  }
  const docker = async (args, options) =>
    await command("docker", args, options);
  const inspect = async (kind, name) =>
    JSON.parse((await docker([kind, "inspect", name])).stdout)[0];
  async function nodeProbe(operation, mounts = [], user = "0:0") {
    return await docker([
      "run",
      "--rm",
      "--pull",
      "never",
      "--network",
      "none",
      "--read-only",
      "--user",
      user,
      "--label",
      `${ownerLabel}=${run}`,
      "--mount",
      `type=bind,source=${join(repository, "scripts/personal-container-probe.mjs")},target=/container-probe.mjs,readonly`,
      ...mounts,
      probeImage,
      "node",
      "/container-probe.mjs",
      operation,
      run,
    ]);
  }
  async function sqliteProbe(operation, mounts, user = "65532:65532") {
    return await docker([
      "run",
      "--rm",
      "--pull",
      "never",
      "--network",
      "none",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
      "--user",
      user,
      "--label",
      `${ownerLabel}=${run}`,
      "--mount",
      `type=bind,source=${join(repository, "scripts/personal-sqlite-recovery-probe.mjs")},target=/sqlite-probe.mjs,readonly`,
      "--mount",
      `type=bind,source=${recoveryProbeContext},target=/check,readonly`,
      ...mounts,
      probeImage,
      "node",
      "/sqlite-probe.mjs",
      operation,
      run,
    ]);
  }
  function progress(next) {
    phase = next;
    console.log(`Personal container check: ${phase}`);
  }

  try {
    recoveryProbeContext = await prepareRecoveryProbeContext(directory, run);
    assert.equal(
      (await docker(["info", "--format", "{{.OSType}}"])).stdout.trim(),
      "linux",
      "Linux containers are required",
    );
    await docker(["compose", "version"]);
    const dockerfile = await readFile(join(repository, "Dockerfile"), "utf8");
    probeImage = consoleProbeImage(dockerfile);
    const socket = net.createServer();
    const port = await new Promise((accept, reject) => {
      socket.once("error", reject);
      socket.listen(0, "127.0.0.1", () => {
        const value = socket.address().port;
        socket.close((error) => (error ? reject(error) : accept(value)));
      });
    });
    await command(driver, ["prepare", fixture, "--port", String(port)]);
    const doctorConfig = join(fixture, "server.toml");
    const doctorCa = join(fixture, "ca.pem");
    const doctor = async (healthy) => {
      const before = (await readdir(fixture)).sort();
      const configBefore = await readFile(doctorConfig);
      const caBefore = await readFile(doctorCa);
      await assert.rejects(lstat(join(fixture, "data")), { code: "ENOENT" });
      const result = await command(
        doctorCli,
        ["doctor", "--config", doctorConfig, "--ca-certificate", doctorCa],
        { allowFailure: true, timeout: 30_000 },
      );
      assertDoctorAcceptance(result, healthy);
      assert.deepEqual(
        (await readdir(fixture)).sort(),
        before,
        "doctor changed fixture entries",
      );
      assert.deepEqual(
        await readFile(doctorConfig),
        configBefore,
        "doctor changed configuration",
      );
      assert.deepEqual(
        await readFile(doctorCa),
        caBefore,
        "doctor changed CA input",
      );
      await assert.rejects(lstat(join(fixture, "data")), { code: "ENOENT" });
    };
    const ca = await readFile(join(fixture, "ca.pem"));
    const origin = `https://localhost:${port}`;
    const environment = {
      ...process.env,
      SCOPLEN_SERVER_HOST: "localhost",
      SCOPLEN_HTTPS_PORT: String(port),
      SCOPLEN_BIND_ADDRESS: "127.0.0.1",
      SCOPLEN_TLS_DIRECTORY: join(fixture, "tls").replaceAll("\\", "/"),
      SPL_ORGANIZATIONS_ALLOW_CREATION: "true",
    };
    const emptyEnv = join(directory, "compose.env");
    const override = join(directory, "compose.override.json");
    await writeFile(emptyEnv, "", { flag: "wx", mode: 0o600 });
    const overrideContent = (
      selectedImage,
      restored = false,
      restoredVolume = archiveVolume,
      daily = false,
      dailyOutput = dailyArchiveVolume,
    ) =>
      JSON.stringify({
        services: {
          server: {
            image: selectedImage,
            labels: { [ownerLabel]: run },
            ...(daily
              ? {
                  command: [
                    "--config",
                    "/etc/scoplen/personal.toml",
                    "--role",
                    "api",
                  ],
                }
              : {}),
            ...(restored
              ? {
                  environment: {
                    SPL_SERVER_DATA_DIR: "/var/lib/spl/restored",
                    SPL_STORAGE_KMS_KEY_FILE: "/var/lib/spl/restored/kms.key",
                    SPL_STORAGE_KMS_AUDIT_KEY_FILE:
                      "/var/lib/spl/restored/audit-signing.key",
                    SPL_STORAGE_OBJECT_DIRECTORY:
                      "/var/lib/spl/restored/objects",
                    ...(daily
                      ? {
                          SPL_BACKUP_ENABLED: "true",
                          SPL_BACKUP_DAILY_UTC: "23:59",
                          SPL_BACKUP_DIRECTORY: "/recovery/archives",
                          SPL_BACKUP_PASSPHRASE_FILE:
                            "/recovery/passphrase.txt",
                        }
                      : {}),
                  },
                  volumes: [
                    {
                      type: "volume",
                      source: "archive",
                      target: "/var/lib/spl",
                    },
                    ...(daily
                      ? [
                          {
                            type: "volume",
                            source: "daily",
                            target: "/recovery",
                          },
                        ]
                      : []),
                  ],
                }
              : {}),
          },
        },
        volumes: {
          data: { labels: { [ownerLabel]: run } },
          ...(restored
            ? { archive: { external: true, name: restoredVolume } }
            : {}),
          ...(daily ? { daily: { external: true, name: dailyOutput } } : {}),
        },
        networks: { default: { labels: { [ownerLabel]: run } } },
      });
    await writeFile(override, overrideContent(image), {
      flag: "wx",
      mode: 0o600,
    });
    const composeArgs = [
      "compose",
      "--project-name",
      project,
      "--env-file",
      emptyEnv,
      "-f",
      join(repository, "deploy/compose.personal.yaml"),
      "-f",
      override,
    ];
    const compose = async (args, options = {}) =>
      await docker([...composeArgs, ...args], { ...options, environment });
    await compose(["config", "--quiet"]);
    for (const value of [undefined, "true", "invalid"]) {
      const rendering = { ...environment };
      if (value === undefined)
        delete rendering.SPL_ORGANIZATIONS_ALLOW_CREATION;
      else rendering.SPL_ORGANIZATIONS_ALLOW_CREATION = value;
      const result = await docker(
        [...composeArgs, "config", "--format", "json"],
        {
          environment: rendering,
        },
      );
      assert.equal(
        JSON.parse(result.stdout).services.server.environment
          .SPL_ORGANIZATIONS_ALLOW_CREATION,
        value ?? "false",
        "Compose must preserve the explicit creation policy for server validation",
      );
    }
    for (const name of ["SCOPLEN_SERVER_HOST", "SCOPLEN_TLS_DIRECTORY"]) {
      const missing = { ...environment };
      delete missing[name];
      assert(
        (
          await docker([...composeArgs, "config", "--quiet"], {
            environment: missing,
            allowFailure: true,
          })
        ).error,
        `Compose must require ${name}`,
      );
    }

    progress("probe image pull");
    await docker(["pull", probeImage], { timeout: 300_000 });
    probeImageId = (await inspect("image", probeImage)).Id;
    progress("non-root recovery probe admission");
    assert.equal(
      (await sqliteProbe("check-context", [])).stdout.trim(),
      "context-ready",
    );

    progress("production image build");
    const revision = (
      await command("git", ["rev-parse", "HEAD"])
    ).stdout.trim();
    assert(/^[a-f0-9]{40}$/.test(revision), "full build revision unavailable");
    const build = await docker(
      [
        "build",
        "--label",
        `${ownerLabel}=${run}`,
        "--tag",
        image,
        "--build-arg",
        `SCOPLEN_BUILD_REVISION=${revision}`,
        "--progress",
        "plain",
        ".",
      ],
      { timeout: 3_600_000, allowFailure: true },
    );
    if (build.error) {
      console.error(
        `Personal image build failure: ${JSON.stringify(describeImageBuildFailure(build))}`,
      );
      throw new Error(
        "production image build failed; inspect private build output",
      );
    }
    progress("production image metadata");
    const built = await inspect("image", image);
    assertOwnedResource(built.Config.Labels, run);
    imageId = built.Id;
    assert.equal(built.Config.User, "65532:65532", "runtime must be non-root");
    assert.equal(
      built.Config.StopSignal,
      "SIGINT",
      "runtime must use the supervisor's shutdown signal",
    );
    progress("image data-directory validation");
    await docker([
      "create",
      "--name",
      inspector,
      "--network",
      "none",
      "--label",
      `${ownerLabel}=${run}`,
      image,
    ]);
    assertPrivateDirectoryArchive(
      (await docker(["cp", `${inspector}:/var/lib/spl`, "-"], { binary: true }))
        .stdout,
    );
    const fixtureMount = [
      "--mount",
      `type=bind,source=${directory},target=/check`,
    ];
    progress("TLS fixture preparation");
    await nodeProbe("prepare-tls", fixtureMount);
    certificatePrepared = true;

    progress("historical source extraction");
    const historicalSource = join(directory, "historical-source");
    const historicalArchive = join(directory, "historical-source.tar");
    await mkdir(historicalSource, { mode: 0o700 });
    assert.equal(
      (
        await command("git", [
          "rev-parse",
          "--verify",
          `${preMigrationRevision}^{commit}`,
        ])
      ).stdout.trim(),
      preMigrationRevision,
      "pinned pre-migration source is unavailable",
    );
    await command("git", [
      "archive",
      "--format=tar",
      `--output=${historicalArchive}`,
      preMigrationRevision,
      "Cargo.toml",
      "Cargo.lock",
      "rust-toolchain.toml",
      "crates",
    ]);
    await command("tar", ["-xf", historicalArchive, "-C", historicalSource]);

    progress("matching old image build");
    const oldBuild = await docker(
      [
        "build",
        "--label",
        `${ownerLabel}=${run}`,
        "--tag",
        historicalImage,
        "--file",
        join(repository, "scripts/Dockerfile.personal-recovery-old"),
        "--build-arg",
        `CHECK_RUNTIME_IMAGE=${image}`,
        "--progress",
        "plain",
        historicalSource,
      ],
      { timeout: 3_600_000, allowFailure: true },
    );
    if (oldBuild.error) {
      console.error(
        `Personal image build failure: ${JSON.stringify(describeImageBuildFailure(oldBuild))}`,
      );
      throw new Error(
        "matching old image build failed; inspect private build output",
      );
    }
    const oldBuilt = await inspect("image", historicalImage);
    assertOwnedResource(oldBuilt.Config.Labels, run);
    historicalImageId = oldBuilt.Id;
    assert.equal(oldBuilt.Config.User, "65532:65532");
    await writeFile(override, overrideContent(historicalImage));

    progress("old schema seed");
    await compose(["up", "--detach", "--no-build"]);
    const oldContainer = (
      await compose(["ps", "--quiet", "server"])
    ).stdout.trim();
    assert(
      /^[a-f0-9]{12,64}$/.test(oldContainer),
      "expected one owned old server container",
    );
    const oldService = await inspect("container", oldContainer);
    assertOwnedResource(oldService.Config.Labels, run, project);
    assert.equal(oldService.Image, historicalImageId);
    const oldDeadline = Date.now() + 60_000;
    for (;;) {
      try {
        if ((await request(origin, "/readyz", ca)).status === 200) break;
      } catch {}
      assert(
        Date.now() < oldDeadline,
        "old production HTTPS readiness timed out",
      );
      await new Promise((accept) => setTimeout(accept, 500));
    }
    const oldLogs = await docker(["logs", oldContainer]);
    await writePrivateDiagnostic(serverLog, oldLogs.stdout, phase);
    await compose(["stop", "server"]);
    assert.equal((await inspect("container", oldContainer)).State.ExitCode, 0);
    const walHolderId = (
      await docker([
        "run",
        "--detach",
        "--name",
        walHolder,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--stop-signal",
        "SIGTERM",
        "--user",
        "65532:65532",
        "--label",
        `${ownerLabel}=${run}`,
        "--mount",
        `type=bind,source=${join(repository, "scripts/personal-sqlite-recovery-probe.mjs")},target=/sqlite-probe.mjs,readonly`,
        "--mount",
        `type=bind,source=${recoveryProbeContext},target=/check,readonly`,
        "--mount",
        `type=volume,source=${project}_data,target=/var/lib/spl`,
        probeImage,
        "node",
        "/sqlite-probe.mjs",
        "seed-and-hold",
        run,
      ])
    ).stdout.trim();
    assert(/^[a-f0-9]{12,64}$/.test(walHolderId));
    const holderService = await inspect("container", walHolderId);
    assertOwnedResource(holderService.Config.Labels, run);
    assert.equal(holderService.Image, probeImageId);
    const walDeadline = Date.now() + 30_000;
    for (;;) {
      const holderLogs = await docker(["logs", walHolderId]);
      if (holderLogs.stdout.trim() === "ready") break;
      const holderState = (await inspect("container", walHolderId)).State;
      if (!holderState.Running) {
        const finalLogs = await docker(["logs", walHolderId]);
        console.error(
          `Committed WAL fixture failure: ${JSON.stringify(describeWalHolderFailure(holderState, finalLogs.stderr))}`,
        );
      }
      assert(
        holderState.Running,
        "committed WAL fixture exited before readiness",
      );
      assert(Date.now() < walDeadline, "committed WAL fixture timed out");
      await new Promise((accept) => setTimeout(accept, 250));
    }
    await sqliteProbe("check-live-wal", [
      "--mount",
      `type=volume,source=${project}_data,target=/var/lib/spl,readonly`,
    ]);
    await writeFile(override, overrideContent(image));

    progress("non-root Compose startup and trusted HTTPS");
    await compose(["up", "--detach", "--no-build", "--force-recreate"]);
    container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
    assert(
      /^[a-f0-9]{12,64}$/.test(container),
      "expected one owned server container",
    );
    const service = await inspect("container", container);
    assertOwnedResource(service.Config.Labels, run, project);
    assert.equal(service.Image, imageId);
    assert.equal(service.HostConfig.ReadonlyRootfs, true);
    assert(service.HostConfig.CapDrop.includes("ALL"));
    assert(service.HostConfig.SecurityOpt.includes("no-new-privileges:true"));
    assert(
      service.Mounts.some(
        (mount) =>
          mount.Destination === "/run/scoplen/tls" && mount.RW === false,
      ),
    );
    const deadline = Date.now() + 60_000;
    for (;;) {
      try {
        if ((await request(origin, "/readyz", ca)).status === 200) break;
      } catch {}
      assert(Date.now() < deadline, "production HTTPS readiness timed out");
      await new Promise((accept) => setTimeout(accept, 500));
    }
    assert.equal((await request(origin, "/healthz", ca)).status, 200);
    await assert.rejects(request(origin, "/healthz"), (error) =>
      [
        "SELF_SIGNED_CERT_IN_CHAIN",
        "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
      ].includes(error.code),
    );
    await assert.rejects(
      request(origin, "/healthz", ca, "wrong-name.invalid"),
      { code: "ERR_TLS_CERT_ALTNAME_INVALID" },
    );
    await nodeProbe("check-data", ["--volumes-from", container], "65532:65532");
    progress("SQLite migration snapshot");
    await sqliteProbe("check-upgrade", ["--volumes-from", `${container}:ro`]);

    progress("native doctor on production HTTPS");
    await doctor(true);

    progress("bundled console assets");
    await docker([
      "cp",
      `${container}:/app/console/manifest.json`,
      join(directory, "manifest.json"),
    ]);
    const manifest = JSON.parse(
      await readFile(join(directory, "manifest.json"), "utf8"),
    );
    assert.equal(manifest.version, 1);
    assert(manifest.assets.length > 0 && manifest.assets.length <= 256);
    for (const asset of manifest.assets) {
      const contentType = consoleAssetContentType(asset.path);
      const response = await request(
        origin,
        asset.path === "index.html" ? "/" : `/${asset.path}`,
        ca,
        undefined,
        contentType === "application/wasm" ? 8 * 1024 * 1024 : undefined,
      );
      assert.equal(response.status, 200);
      assert.equal(response.body.length, asset.bytes);
      assert.equal(response.headers["content-type"], contentType);
      assert.equal(
        createHash("sha256").update(response.body).digest("hex"),
        asset.sha256,
      );
      assert.equal(response.headers["cache-control"], "no-store");
    }
    assert.equal((await request(origin, "/setup", ca)).status, 200);
    await docker([
      "cp",
      `${container}:/app/console/licenses`,
      join(directory, "licenses"),
    ]);
    for (const name of [
      "react",
      "react-dom",
      "@fontsource-variable-inter",
      "@fontsource-variable-lora",
      "@fontsource-variable-jetbrains-mono",
      "scoplen-browser",
    ])
      assert(
        (await readFile(join(directory, "licenses", `${name}.txt`))).length > 0,
      );

    progress(
      "public Operator setup, Passkey login/logout and retired entry absence",
    );
    const logs = await docker(["logs", container]);
    await writePrivateDiagnostic(
      join(fixture, "current-server.log"),
      logs.stdout,
      phase,
    );
    await command(driver, ["bootstrap", fixture, "--server-log", serverLog]);
    const descriptorPath = join(fixture, "descriptor.json");
    const descriptorBytes = await readFile(descriptorPath);
    const descriptor = JSON.parse(descriptorBytes);
    assert.equal(descriptor.disposable, true);
    assert.equal(descriptor.origin, origin);
    assert.equal(descriptor.operator_lifecycle_verified, true);
    const repeat = await command(
      driver,
      ["bootstrap", fixture, "--server-log", serverLog],
      { allowFailure: true },
    );
    assert(repeat.error, "bootstrap must not repeat");
    assert.deepEqual(await readFile(descriptorPath), descriptorBytes);

    const paths = ["/.well-known/jwks.json", "/.well-known/operator-jwks.json"];
    const keys = [];
    for (const path of paths) {
      const response = await request(origin, path, ca);
      assert.equal(response.status, 200);
      const value = JSON.parse(response.body);
      assert(
        value.keys.length > 0 && value.keys.every((key) => key.d === undefined),
      );
      keys.push(response.body);
    }

    const archiveCommand = async (
      operation,
      args,
      source = false,
      destination = archiveVolume,
      sourceVolume = `${project}_data`,
      restoredSource = false,
    ) => {
      const result = await docker([
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--user",
        "65532:65532",
        "--label",
        `${ownerLabel}=${run}`,
        "--env",
        "SPL_SERVER_PUBLIC_HOST=localhost",
        "--env",
        `SPL_SERVER_PUBLIC_PORT=${port}`,
        ...(restoredSource
          ? [
              "--env",
              "SPL_SERVER_DATA_DIR=/var/lib/spl/restored",
              "--env",
              "SPL_STORAGE_KMS_KEY_FILE=/var/lib/spl/restored/kms.key",
              "--env",
              "SPL_STORAGE_KMS_AUDIT_KEY_FILE=/var/lib/spl/restored/audit-signing.key",
              "--env",
              "SPL_STORAGE_OBJECT_DIRECTORY=/var/lib/spl/restored/objects",
            ]
          : []),
        "--mount",
        `type=volume,source=${destination},target=/recovery`,
        ...(source
          ? [
              "--mount",
              `type=volume,source=${sourceVolume},target=/var/lib/spl`,
              "--mount",
              `type=bind,source=${join(fixture, "tls")},target=/run/scoplen/tls,readonly`,
            ]
          : []),
        "--entrypoint",
        "/app/splctl",
        image,
        "backup",
        operation,
        ...args,
        "--passphrase-file",
        "/recovery/passphrase.txt",
      ]);
      assertBackupAcceptance(result, operation);
    };

    progress("public Account password entry and encrypted sync");
    const accountArguments = [
      "verify-account",
      fixture,
      "--with-team",
      "--across-restart",
    ];
    await runTeamRestart({
      fixture,
      run: (signal) =>
        command(driver, accountArguments, { signal, timeout: 300_000 }),
      restart: async () => {
        progress("restart and persistent setup/key verification");
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        progress("native doctor while stopped");
        await doctor(false);
        progress("restart and persistent setup/key verification");
        await compose(["up", "--detach", "--no-build"]);
        const restartDeadline = Date.now() + 60_000;
        for (;;) {
          try {
            if ((await request(origin, "/readyz", ca)).status === 200) break;
          } catch {}
          assert(
            Date.now() < restartDeadline,
            "restarted production HTTPS readiness timed out",
          );
          await new Promise((accept) => setTimeout(accept, 500));
        }
        progress("native doctor after restart");
        await doctor(true);
        progress("restart and persistent setup/key verification");
        for (const [index, path] of paths.entries()) {
          const response = await request(origin, path, ca);
          assert.equal(response.status, 200);
          assert.deepEqual(
            response.body,
            keys[index],
            "restart changed a persisted token keyring",
          );
        }
        const recovery = await compose(
          [
            "exec",
            "-T",
            "server",
            "/app/splctl",
            "bootstrap",
            "--reissue-pending",
          ],
          { allowFailure: true },
        );
        assert(
          recovery.error &&
            recovery.stderr.trim() ===
              "splctl: operator setup error: operator setup authentication denied",
          "completed Operator setup must survive restart",
        );
        assert.equal(
          recovery.stdout,
          "",
          "completed setup disclosed a replacement link",
        );
        assert.equal(
          (await inspect("container", container)).RestartCount,
          0,
          "service restarted unexpectedly",
        );

        progress("offline archive source and fresh volume");
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        await sqliteProbe("check-archive-source", [
          "--mount",
          `type=volume,source=${project}_data,target=/source,readonly`,
        ]);
        await docker([
          "volume",
          "create",
          "--label",
          `${ownerLabel}=${run}`,
          archiveVolume,
        ]);
        assertOwnedResource(
          (await inspect("volume", archiveVolume)).Labels,
          run,
        );
        await sqliteProbe(
          "prepare-archive-parent",
          ["--mount", `type=volume,source=${archiveVolume},target=/recovery`],
          "0:0",
        );
        progress("public encrypted archive creation");
        await archiveCommand(
          "create",
          [
            "--config",
            "/etc/scoplen/personal.toml",
            "--output",
            "/recovery/backup.age",
          ],
          true,
        );
        await docker(["stop", "--time", "30", walHolderId]);
        assert.equal(
          (await inspect("container", walHolderId)).State.ExitCode,
          0,
        );
        progress("public encrypted archive verification");
        await archiveCommand("verify", ["--archive", "/recovery/backup.age"]);
        progress("public encrypted archive restoration");
        await archiveCommand("restore", [
          "--archive",
          "/recovery/backup.age",
          "--data-dir",
          "/recovery/restored",
        ]);
        progress("restored archive data verification");
        await sqliteProbe("check-archive-restore", [
          "--mount",
          `type=volume,source=${project}_data,target=/source,readonly`,
          "--mount",
          `type=volume,source=${archiveVolume},target=/recovery,readonly`,
        ]);

        progress("restored Compose startup and persistent restart");
        await writeFile(override, overrideContent(image, true));
        await compose(["config", "--quiet"]);
        await compose(["up", "--detach", "--no-build", "--force-recreate"]);
        container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
        assert(/^[a-f0-9]{12,64}$/.test(container));
        const restoredService = await inspect("container", container);
        assertOwnedResource(restoredService.Config.Labels, run, project);
        assert.equal(restoredService.Image, imageId);
        assert(
          restoredService.Mounts.some(
            (mount) =>
              mount.Destination === "/var/lib/spl" &&
              mount.Name === archiveVolume,
          ),
          "restored Compose service must mount the fresh parent volume",
        );
        const checkRestored = async () => {
          const restoredDeadline = Date.now() + 60_000;
          for (;;) {
            try {
              if ((await request(origin, "/readyz", ca)).status === 200) break;
            } catch {}
            assert(
              Date.now() < restoredDeadline,
              "restored production HTTPS readiness timed out",
            );
            await new Promise((accept) => setTimeout(accept, 500));
          }
          await doctor(true);
          for (const [index, path] of paths.entries()) {
            const response = await request(origin, path, ca);
            assert.equal(response.status, 200);
            assert.deepEqual(
              response.body,
              keys[index],
              "restore changed a persisted token keyring",
            );
          }
          assert.equal((await inspect("container", container)).RestartCount, 0);
        };
        await checkRestored();
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        await compose(["up", "--detach", "--no-build"]);
        await checkRestored();
        progress("team membership and Personal Host after restart");
      },
    });
    const acceptancePaths = [
      ["account-acceptance.json", assertAccountAcceptance],
      ["team-acceptance.json", assertTeamAcceptance],
      ["team-restart-acceptance.json", assertTeamRestartAcceptance],
    ];
    const acceptanceBytes = [];
    for (const [name, validate] of acceptancePaths) {
      const bytes = await readFile(join(fixture, name));
      validate(JSON.parse(bytes));
      acceptanceBytes.push(bytes);
    }
    assert.deepEqual(await readFile(descriptorPath), descriptorBytes);
    const accountRepeat = await command(driver, accountArguments, {
      allowFailure: true,
    });
    assert(accountRepeat.error, "Account acceptance must not repeat");
    for (const [index, [name]] of acceptancePaths.entries())
      assert.deepEqual(
        await readFile(join(fixture, name)),
        acceptanceBytes[index],
      );

    progress("online archive capture and restored Device restart");
    await docker([
      "volume",
      "create",
      "--label",
      `${ownerLabel}=${run}`,
      onlineArchiveVolume,
    ]);
    assertOwnedResource(
      (await inspect("volume", onlineArchiveVolume)).Labels,
      run,
    );
    await sqliteProbe(
      "prepare-archive-parent",
      ["--mount", `type=volume,source=${onlineArchiveVolume},target=/recovery`],
      "0:0",
    );
    const checkOnlineService = async () => {
      const deadline = Date.now() + 60_000;
      for (;;) {
        try {
          if ((await request(origin, "/readyz", ca)).status === 200) break;
        } catch {}
        assert(
          Date.now() < deadline,
          "online restored production HTTPS readiness timed out",
        );
        await new Promise((accept) => setTimeout(accept, 500));
      }
      await doctor(true);
      assert.equal((await inspect("container", container)).RestartCount, 0);
    };
    const confirmedOnlineWrites = await runOnlineBackup({
      fixture,
      run: (signal) =>
        command(driver, ["verify-online-backup", fixture], {
          signal,
          timeout: 360_000,
        }),
      capture: () =>
        archiveCommand(
          "create",
          [
            "--online",
            "--config",
            "/etc/scoplen/personal.toml",
            "--output",
            "/recovery/online.age",
          ],
          true,
          onlineArchiveVolume,
          archiveVolume,
          true,
        ),
      restore: async () => {
        await archiveCommand(
          "verify",
          ["--archive", "/recovery/online.age"],
          false,
          onlineArchiveVolume,
        );
        await archiveCommand(
          "restore",
          [
            "--archive",
            "/recovery/online.age",
            "--data-dir",
            "/recovery/restored",
          ],
          false,
          onlineArchiveVolume,
        );
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        await sqliteProbe("check-online-archive-restore", [
          "--mount",
          `type=volume,source=${archiveVolume},target=/source-parent,readonly`,
          "--mount",
          `type=volume,source=${onlineArchiveVolume},target=/recovery,readonly`,
        ]);
        await writeFile(
          override,
          overrideContent(image, true, onlineArchiveVolume),
        );
        await compose(["config", "--quiet"]);
        await compose(["up", "--detach", "--no-build", "--force-recreate"]);
        container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
        const restored = await inspect("container", container);
        assertOwnedResource(restored.Config.Labels, run, project);
        assert.equal(restored.Image, imageId);
        assert(
          restored.Mounts.some(
            (mount) =>
              mount.Destination === "/var/lib/spl" &&
              mount.Name === onlineArchiveVolume,
          ),
        );
        await checkOnlineService();
      },
      restart: async () => {
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        await compose(["up", "--detach", "--no-build"]);
        await checkOnlineService();
      },
    });

    console.log(
      `Online capture confirmed ${confirmedOnlineWrites} public writes and restored original Devices across restart.`,
    );

    progress("daily archive volume preparation");
    const slot = new Date().toISOString().slice(0, 10);
    const dailyArchive = `scoplen-${slot}.age`;
    const prepareDailyVolume = async (name, collision = false) => {
      await docker([
        "volume",
        "create",
        "--label",
        `${ownerLabel}=${run}`,
        name,
      ]);
      assertOwnedResource((await inspect("volume", name)).Labels, run);
      await sqliteProbe(
        collision ? "prepare-daily-collision" : "prepare-daily-parent",
        ["--mount", `type=volume,source=${name},target=/recovery`],
        "0:0",
      );
    };
    await prepareDailyVolume(dailyArchiveVolume);
    progress("daily source preparation");
    await sqliteProbe("prepare-daily-source", [
      "--mount",
      `type=volume,source=${onlineArchiveVolume},target=/source-parent`,
    ]);
    progress("daily API-only restart");
    await compose(["stop", "server"]);
    assert.equal((await inspect("container", container)).State.ExitCode, 0);
    await writeFile(
      override,
      overrideContent(image, true, onlineArchiveVolume, true),
    );
    await compose(["up", "--detach", "--no-build", "--force-recreate"]);
    container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
    await checkOnlineService();
    const dailyState = async (
      source = onlineArchiveVolume,
      output = dailyArchiveVolume,
    ) =>
      JSON.parse(
        (
          await sqliteProbe("daily-state", [
            "--mount",
            `type=volume,source=${source},target=/source-parent`,
            "--mount",
            `type=volume,source=${output},target=/recovery,readonly`,
          ])
        ).stdout,
      );
    const records = async (name) => {
      const result = await docker(["logs", name]);
      return `${result.stdout}\n${result.stderr}`
        .split(/\r?\n/)
        .filter((line) => line.startsWith("{"))
        .map((line) => JSON.parse(line));
    };
    const waitForHold = async (name, expected) => {
      const deadline = Date.now() + 60_000;
      for (;;) {
        const { stdout } = await docker(["logs", name]);
        if (stdout === expected) return;
        assert(
          (await inspect("container", name)).State.Running,
          "object hold exited early",
        );
        assert(Date.now() < deadline, "object hold signal timed out");
        await new Promise((accept) => setTimeout(accept, 200));
      }
    };
    const startHold = async (name, source) => {
      await docker([
        "run",
        "--detach",
        "--name",
        name,
        "--pull",
        "never",
        "--network",
        "none",
        "--user",
        "65532:65532",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--label",
        `${ownerLabel}=${run}`,
        "--label",
        `com.docker.compose.project=${project}`,
        "--mount",
        `type=volume,source=${source},target=/source,readonly`,
        "--mount",
        `type=bind,source=${join(repository, "scripts/hold-daily-backup-object.pl")},target=/hold.pl,readonly`,
        probeImage,
        "perl",
        "/hold.pl",
        "/source/restored/objects/ci-daily-capture-buffer",
      ]);
      const item = await inspect("container", name);
      assertOwnedResource(item.Config.Labels, run, project);
      assert.equal(item.Image, probeImageId);
      await waitForHold(name, "ready\n");
    };
    const releaseHold = async (name) => {
      await docker(["kill", "--signal", "USR1", name]);
      assert.equal(
        (await docker(["wait", name])).stdout.trim(),
        "0",
        "object hold release failed",
      );
      assert.equal(
        (await docker(["logs", name])).stdout,
        "ready\nblocked\nreleased\n",
        "object hold release failed",
      );
    };
    const startDailyWorker = async (
      name,
      source = onlineArchiveVolume,
      output = dailyArchiveVolume,
      cpus = "0.025",
      enabled = true,
      roles = ["worker"],
    ) => {
      await docker([
        "run",
        "--detach",
        "--name",
        name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cpus",
        cpus,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--label",
        `${ownerLabel}=${run}`,
        "--label",
        `com.docker.compose.project=${project}`,
        "--env",
        "SPL_SERVER_PUBLIC_HOST=localhost",
        "--env",
        `SPL_SERVER_PUBLIC_PORT=${port}`,
        "--env",
        "SPL_SERVER_DATA_DIR=/var/lib/spl/restored",
        "--env",
        "SPL_STORAGE_KMS_KEY_FILE=/var/lib/spl/restored/kms.key",
        "--env",
        "SPL_STORAGE_KMS_AUDIT_KEY_FILE=/var/lib/spl/restored/audit-signing.key",
        "--env",
        "SPL_STORAGE_OBJECT_DIRECTORY=/var/lib/spl/restored/objects",
        "--env",
        `SPL_BACKUP_ENABLED=${enabled}`,
        "--env",
        "SPL_BACKUP_DAILY_UTC=23:59",
        "--env",
        "SPL_BACKUP_DIRECTORY=/recovery/archives",
        "--env",
        "SPL_BACKUP_PASSPHRASE_FILE=/recovery/passphrase.txt",
        "--mount",
        `type=volume,source=${source},target=/var/lib/spl`,
        "--mount",
        `type=volume,source=${output},target=/recovery`,
        "--mount",
        `type=bind,source=${join(fixture, "tls")},target=/run/scoplen/tls,readonly`,
        image,
        "--config",
        "/etc/scoplen/personal.toml",
        ...roles.flatMap((role) => ["--role", role]),
      ]);
      const worker = await inspect("container", name);
      assertOwnedResource(worker.Config.Labels, run, project);
      assert.equal(worker.Image, imageId);
    };
    const stopDailyWorker = async (name, expected = 0) => {
      await docker(["stop", "--time", "16", name]);
      assert.equal((await inspect("container", name)).State.ExitCode, expected);
    };
    const dailyCli = async (
      operation,
      destination = dailyArchiveVolume,
      allowFailure = false,
      archiveSource = dailyArchiveVolume,
    ) => {
      const creating = operation === "create";
      const result = await docker(
        [
          "run",
          "--rm",
          "--pull",
          "never",
          "--network",
          "none",
          "--read-only",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges:true",
          "--tmpfs",
          "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
          "--label",
          `${ownerLabel}=${run}`,
          "--env",
          "SPL_SERVER_PUBLIC_HOST=localhost",
          "--env",
          `SPL_SERVER_PUBLIC_PORT=${port}`,
          "--env",
          "SPL_SERVER_DATA_DIR=/var/lib/spl/restored",
          "--env",
          "SPL_STORAGE_KMS_KEY_FILE=/var/lib/spl/restored/kms.key",
          "--env",
          "SPL_STORAGE_KMS_AUDIT_KEY_FILE=/var/lib/spl/restored/audit-signing.key",
          "--env",
          "SPL_STORAGE_OBJECT_DIRECTORY=/var/lib/spl/restored/objects",
          "--mount",
          `type=volume,source=${archiveSource},target=/archive,readonly`,
          "--mount",
          `type=volume,source=${destination},target=/recovery`,
          ...(creating
            ? [
                "--mount",
                `type=volume,source=${destination},target=/var/lib/spl`,
                "--mount",
                `type=bind,source=${join(fixture, "tls")},target=/run/scoplen/tls,readonly`,
              ]
            : []),
          "--entrypoint",
          "/app/splctl",
          image,
          "backup",
          operation,
          ...(creating
            ? [
                "--config",
                "/etc/scoplen/personal.toml",
                "--output",
                "/recovery/after-stop.age",
              ]
            : ["--archive", `/archive/archives/${dailyArchive}`]),
          ...(operation === "restore"
            ? ["--data-dir", "/recovery/restored"]
            : []),
          "--passphrase-file",
          creating ? "/recovery/passphrase.txt" : "/archive/passphrase.txt",
        ],
        { allowFailure, timeout: 180_000 },
      );
      if (!allowFailure) assertBackupAcceptance(result, operation);
      return result;
    };
    const waitDailyFailure = async (volume, reason) => {
      const deadline = Date.now() + 100_000;
      for (;;) {
        const state = await dailyState(volume, volume);
        assert.equal(state.jobs.length, 1);
        const job = state.jobs[0];
        assert.equal(job.slot, slot);
        assert(job.attempts <= 2);
        if (job.attempts === 2 && job.owner === null) {
          assert.equal(job.finishedAt, null);
          assert.equal(job.lastError, reason);
          assert(job.availableAt - state.observedAt > 290_000);
          return state;
        }
        assert(Date.now() < deadline, "daily failed attempt timed out");
        await new Promise((accept) => setTimeout(accept, 1000));
      }
    };
    progress("daily API-only scheduling check");
    assert.deepEqual(
      (await dailyState()).jobs,
      [],
      "API-only process scheduled a daily slot",
    );
    const apiEvents = assertDailyEvents(await records(container));
    assert(apiEvents.some(({ fields }) => fields.reason === "worker_required"));
    let completedDaily;
    progress("daily Device write preparation");
    const dailyWrites = await runOnlineBackup({
      fixture,
      daily: true,
      timeout: 180_000,
      run: (signal) =>
        command(driver, ["verify-daily-backup", fixture], {
          signal,
          timeout: 660_000,
        }),
      capture: async () => {
        assert.deepEqual((await dailyState()).jobs, []);
        progress("daily Worker ownership and renewal");
        await startHold(captureHold, onlineArchiveVolume);
        await startDailyWorker(dailyWorkers[0]);
        await startDailyWorker(
          dailyWorkers[1],
          onlineArchiveVolume,
          dailyArchiveVolume,
          "0.025",
          true,
          ["api", "worker"],
        );
        await waitForHold(captureHold, "ready\nblocked\n");
        const samples = [];
        let firstHeld;
        let heldInterval;
        const deadline = Date.now() + 180_000;
        for (;;) {
          const sample = await dailyState();
          assert(
            sample.jobs.length <= 1,
            "daily Worker created duplicate slots",
          );
          if (sample.jobs[0]?.attempts > 0) samples.push(sample);
          if (!heldInterval && sample.staging > 0 && sample.jobs[0]?.owner) {
            firstHeld ??= sample;
            if (sample.observedAt - firstHeld.observedAt >= 31_000) {
              assert(
                sample.jobs[0].leaseUntil > firstHeld.jobs[0].leaseUntil,
                "daily capture did not renew its lease",
              );
              heldInterval = {
                started: firstHeld.observedAt,
                finished: sample.observedAt,
              };
              await releaseHold(captureHold);
            }
          }
          assert.equal((await request(origin, "/readyz", ca)).status, 200);
          for (const name of dailyWorkers)
            assert((await inspect("container", name)).State.Running);
          if (
            sample.jobs[0]?.finishedAt !== null &&
            sample.jobs[0]?.finishedAt !== undefined
          )
            break;
          assert(Date.now() < deadline, "daily Worker capture timed out");
          await new Promise((accept) => setTimeout(accept, 1000));
        }
        await writePrivateDiagnostic(
          join(directory, "daily-capture-observations.json"),
          `${JSON.stringify(samples)}\n`,
          phase,
        );
        const interval = assertDailyCapture(samples, slot);
        assert(
          heldInterval &&
            heldInterval.started >= interval.started &&
            heldInterval.finished <= interval.finished,
          "daily capture ended outside the held object read",
        );
        completedDaily = samples.at(-1);
        progress("daily Worker events and maintenance");
        const logs = (await Promise.all(dailyWorkers.map(records))).flat();
        const events = assertDailyEvents(logs);
        assert.equal(
          events.filter(({ fields }) => fields.event === "started").length,
          1,
        );
        assert.equal(
          events.filter(({ fields }) => fields.event === "succeeded").length,
          1,
        );
        assert(
          logs.some(
            (record) =>
              record.fields?.message === "worker heartbeat" &&
              Date.parse(record.timestamp) > heldInterval.started &&
              Date.parse(record.timestamp) < heldInterval.finished,
          ),
          "Worker maintenance did not progress during capture",
        );
        progress("daily Worker same-day restart");
        for (const name of dailyWorkers) await stopDailyWorker(name);
        for (const name of dailyWorkers) await docker(["start", name]);
        await new Promise((accept) => setTimeout(accept, 32_000));
        const restarted = await dailyState();
        assert.deepEqual(
          restarted.jobs,
          completedDaily.jobs,
          "same-day restart changed confirmed job",
        );
        assert.deepEqual(
          restarted.archives,
          completedDaily.archives,
          "same-day restart changed archive",
        );
        for (const name of dailyWorkers) await stopDailyWorker(name);
        await startDailyWorker(
          dailyAllWorker,
          onlineArchiveVolume,
          dailyArchiveVolume,
          "1",
          true,
          ["all"],
        );
        await new Promise((accept) => setTimeout(accept, 32_000));
        const allRoles = await dailyState();
        assert.deepEqual(
          allRoles.jobs,
          completedDaily.jobs,
          "all-role startup repeated the same-day claim",
        );
        assert.deepEqual(allRoles.archives, completedDaily.archives);
        assert(
          assertDailyEvents(await records(dailyAllWorker)).some(
            ({ fields }) => fields.event === "enabled",
          ),
        );
        await stopDailyWorker(dailyAllWorker);
        return heldInterval;
      },
      restore: async () => {
        progress("daily archive verification and restoration");
        await dailyCli("verify");
        await dailyCli("restore");
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        await sqliteProbe("check-online-archive-restore", [
          "--mount",
          `type=volume,source=${onlineArchiveVolume},target=/source-parent,readonly`,
          "--mount",
          `type=volume,source=${dailyArchiveVolume},target=/recovery,readonly`,
        ]);
        await writeFile(
          override,
          overrideContent(image, true, dailyArchiveVolume),
        );
        await compose(["up", "--detach", "--no-build", "--force-recreate"]);
        container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
        await checkOnlineService();
      },
      restart: async () => {
        await compose(["stop", "server"]);
        assert.equal((await inspect("container", container)).State.ExitCode, 0);
        await compose(["up", "--detach", "--no-build"]);
        await checkOnlineService();
      },
    });
    console.log(
      `Daily Worker capture confirmed ${dailyWrites} public writes, renewed one two-Worker claim, suppressed same-day restart duplicates and restored original Devices.`,
    );

    progress("daily Worker failures and shutdown");
    await prepareDailyVolume(dailyPublicationVolume);
    await dailyCli("restore", dailyPublicationVolume);
    await startHold(publicationHold, dailyPublicationVolume);
    await startDailyWorker(
      dailyPublicationWorker,
      dailyPublicationVolume,
      dailyPublicationVolume,
      "1",
    );
    await waitForHold(publicationHold, "ready\nblocked\n");
    const publicationState = () =>
      dailyState(dailyPublicationVolume, dailyPublicationVolume);
    const admitted = await publicationState();
    assert.equal(admitted.jobs.length, 1);
    assert.equal(admitted.jobs[0].slot, slot);
    assert.equal(admitted.jobs[0].attempts, 2);
    assert(admitted.jobs[0].owner && admitted.jobs[0].finishedAt === null);
    assert.equal(admitted.staging, 1);
    assert.deepEqual(admitted.archives, []);
    const marker = async (operation) => {
      assertOwnedResource(
        (await inspect("volume", dailyPublicationVolume)).Labels,
        run,
      );
      await docker([
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--label",
        `${ownerLabel}=${run}`,
        "--mount",
        `type=volume,source=${dailyPublicationVolume},target=/recovery`,
        "--mount",
        `type=bind,source=${join(repository, "scripts/check-personal-container-publication.mjs")},target=/publication.mjs,readonly`,
        probeImage,
        "node",
        "/publication.mjs",
        slot,
        operation,
      ]);
    };
    // The Worker is blocked on its source object after accepting an absent destination.
    await marker("publish");
    await releaseHold(publicationHold);
    const publicationFailure = await waitDailyFailure(
      dailyPublicationVolume,
      "output_exists",
    );
    assert.equal(publicationFailure.staging, 1);
    assert.deepEqual(
      publicationFailure.archives.map(({ name }) => name),
      [dailyArchive],
    );
    const publicationEvents = assertDailyEvents(
      await records(dailyPublicationWorker),
    );
    assert(
      publicationEvents.some(
        ({ fields }) =>
          fields.event === "unconfirmed" && fields.reason === "output_exists",
      ),
    );
    assert(
      publicationEvents.some(
        ({ fields }) =>
          fields.event === "retry_scheduled" && fields.attempt === 2,
      ),
    );
    assert(
      !publicationEvents.some(({ fields }) => fields.event === "succeeded"),
    );
    // Withdraw only the simulated publisher's own link. Its staging and bytes remain observable.
    await marker("withdraw");

    await prepareDailyVolume(dailyFailureVolume, true);
    await dailyCli("restore", dailyFailureVolume);
    await compose(["stop", "server"]);
    assert.equal((await inspect("container", container)).State.ExitCode, 0);
    await writeFile(
      override,
      overrideContent(
        image,
        true,
        dailyFailureVolume,
        true,
        dailyFailureVolume,
      ),
    );
    await compose(["up", "--detach", "--no-build", "--force-recreate"]);
    container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
    await checkOnlineService();
    await startDailyWorker(
      dailyFailureWorker,
      dailyFailureVolume,
      dailyFailureVolume,
      "1",
    );
    const failedDaily = await waitDailyFailure(
      dailyFailureVolume,
      "output_exists",
    );
    assert.equal((await request(origin, "/readyz", ca)).status, 200);
    await command(driver, ["verify-daily-backup-available", fixture]);
    assert.deepEqual(
      JSON.parse(
        await readFile(join(fixture, "daily-failure-acceptance.json"), "utf8"),
      ),
      {
        daily_failure_public_sync_verified: true,
      },
    );
    assert.equal((await inspect("container", container)).RestartCount, 0);
    const failedEvents = assertDailyEvents(await records(dailyFailureWorker));
    assert(
      failedEvents.some(({ fields }) => fields.event === "retry_scheduled"),
    );
    assert(!failedEvents.some(({ fields }) => fields.event === "succeeded"));
    await stopDailyWorker(dailyFailureWorker);
    await docker(["start", dailyFailureWorker]);
    await new Promise((accept) => setTimeout(accept, 32_000));
    assert.deepEqual(
      (await dailyState(dailyFailureVolume, dailyFailureVolume)).jobs,
      failedDaily.jobs,
      "restart reset the persisted retry delay",
    );
    await stopDailyWorker(dailyFailureWorker);
    await sqliteProbe("check-daily-collision", [
      "--mount",
      `type=volume,source=${dailyFailureVolume},target=/recovery,readonly`,
    ]);
    await startDailyWorker(
      dailyDisabledWorker,
      dailyFailureVolume,
      dailyFailureVolume,
      "1",
      false,
    );
    await new Promise((accept) => setTimeout(accept, 32_000));
    const disabled = await dailyState(dailyFailureVolume, dailyFailureVolume);
    assert.deepEqual(
      disabled.jobs,
      failedDaily.jobs,
      "disabled Worker changed persisted retry state",
    );
    assert.deepEqual(
      disabled.archives,
      failedDaily.archives,
      "disabled Worker changed retained output",
    );
    const disabledEvents = assertDailyEvents(
      await records(dailyDisabledWorker),
    );
    assert(disabledEvents.some(({ fields }) => fields.event === "disabled"));
    assert(!disabledEvents.some(({ fields }) => fields.event === "started"));
    await stopDailyWorker(dailyDisabledWorker);

    await prepareDailyVolume(dailyUnconfirmedVolume);
    await dailyCli("restore", dailyUnconfirmedVolume);
    await sqliteProbe("deny-daily-completion", [
      "--mount",
      `type=volume,source=${dailyUnconfirmedVolume},target=/source-parent`,
    ]);
    await startDailyWorker(
      dailyUnconfirmedWorker,
      dailyUnconfirmedVolume,
      dailyUnconfirmedVolume,
      "1",
    );
    const unconfirmed = await waitDailyFailure(
      dailyUnconfirmedVolume,
      "completion_unconfirmed",
    );
    assert.equal(unconfirmed.archives.length, 1);
    assert.equal(unconfirmed.archives[0].name, dailyArchive);
    assert(unconfirmed.archives[0].size > 0);
    assert.equal(unconfirmed.staging, 0);
    const unconfirmedEvents = assertDailyEvents(
      await records(dailyUnconfirmedWorker),
    );
    assert(
      unconfirmedEvents.some(
        ({ fields }) =>
          fields.event === "unconfirmed" &&
          fields.reason === "completion_unconfirmed",
      ),
    );
    assert(
      unconfirmedEvents.some(
        ({ fields }) => fields.event === "retry_scheduled",
      ),
    );
    assert(
      !unconfirmedEvents.some(({ fields }) => fields.event === "succeeded"),
    );
    await dailyCli(
      "verify",
      dailyUnconfirmedVolume,
      false,
      dailyUnconfirmedVolume,
    );
    await stopDailyWorker(dailyUnconfirmedWorker);
    await docker(["start", dailyUnconfirmedWorker]);
    await new Promise((accept) => setTimeout(accept, 32_000));
    const unconfirmedRestart = await dailyState(
      dailyUnconfirmedVolume,
      dailyUnconfirmedVolume,
    );
    assert.deepEqual(
      unconfirmedRestart.jobs,
      unconfirmed.jobs,
      "restart inferred success from an unconfirmed archive",
    );
    assert.deepEqual(
      unconfirmedRestart.archives,
      unconfirmed.archives,
      "unconfirmed archive changed across restart",
    );
    await stopDailyWorker(dailyUnconfirmedWorker);

    await prepareDailyVolume(dailyPassphraseVolume);
    await dailyCli("restore", dailyPassphraseVolume);
    await sqliteProbe("empty-daily-passphrase", [
      "--mount",
      `type=volume,source=${dailyPassphraseVolume},target=/recovery`,
    ]);
    await compose(["stop", "server"]);
    assert.equal((await inspect("container", container)).State.ExitCode, 0);
    await writeFile(
      override,
      overrideContent(
        image,
        true,
        dailyPassphraseVolume,
        true,
        dailyPassphraseVolume,
      ),
    );
    await compose(["up", "--detach", "--no-build", "--force-recreate"]);
    container = (await compose(["ps", "--quiet", "server"])).stdout.trim();
    await checkOnlineService();
    await startDailyWorker(
      dailyPassphraseWorker,
      dailyPassphraseVolume,
      dailyPassphraseVolume,
      "1",
    );
    const passphraseFailure = await waitDailyFailure(
      dailyPassphraseVolume,
      "capture_failed",
    );
    assert.deepEqual(passphraseFailure.archives, []);
    assert.equal(passphraseFailure.staging, 0);
    const passphraseEvents = assertDailyEvents(
      await records(dailyPassphraseWorker),
    );
    assert(
      passphraseEvents.some(
        ({ fields }) =>
          fields.event === "retry_scheduled" &&
          fields.reason === "capture_failed",
      ),
    );
    assert(
      !passphraseEvents.some(({ fields }) => fields.event === "succeeded"),
    );
    await command(driver, [
      "verify-daily-backup-available",
      fixture,
      "--passphrase-failure",
    ]);
    assert.deepEqual(
      JSON.parse(
        await readFile(
          join(fixture, "daily-passphrase-failure-acceptance.json"),
          "utf8",
        ),
      ),
      {
        daily_failure_public_sync_verified: true,
      },
    );
    assert.equal((await inspect("container", container)).RestartCount, 0);
    await stopDailyWorker(dailyPassphraseWorker);

    await prepareDailyVolume(dailyInterruptedVolume);
    await dailyCli("restore", dailyInterruptedVolume);
    await startHold(interruptedHold, dailyInterruptedVolume);
    await startDailyWorker(
      dailyInterruptedWorker,
      dailyInterruptedVolume,
      dailyInterruptedVolume,
      "0.01",
    );
    await waitForHold(interruptedHold, "ready\nblocked\n");
    const interruptedDeadline = Date.now() + 100_000;
    let interrupted;
    for (;;) {
      const state = await dailyState(
        dailyInterruptedVolume,
        dailyInterruptedVolume,
      );
      if (
        state.jobs[0]?.attempts === 2 &&
        state.jobs[0].owner !== null &&
        state.staging > 0 &&
        state.archives.length === 0
      ) {
        interrupted = state.jobs[0];
        assert(interrupted.owner !== null && interrupted.finishedAt === null);
        break;
      }
      assert(
        Date.now() < interruptedDeadline,
        "daily interrupted attempt timed out",
      );
      await new Promise((accept) => setTimeout(accept, 500));
    }
    const shutdownStarted = Date.now();
    await docker(["kill", "--signal", "SIGINT", dailyInterruptedWorker]);
    await new Promise((accept) => setTimeout(accept, 1000));
    const duringShutdown = await dailyCli(
      "create",
      dailyInterruptedVolume,
      true,
    );
    assert(duringShutdown.error, "offline admission escaped a draining Worker");
    await new Promise((accept) =>
      setTimeout(accept, Math.max(0, shutdownStarted + 7500 - Date.now())),
    );
    assert((await inspect("container", dailyInterruptedWorker)).State.Running);
    assert(
      (await dailyCli("create", dailyInterruptedVolume, true)).error,
      "offline admission escaped before the timed-out process exited",
    );
    for (;;) {
      const state = await inspect("container", dailyInterruptedWorker);
      if (!state.State.Running) {
        assert.equal(state.State.ExitCode, 1);
        break;
      }
      assert(
        Date.now() - shutdownStarted < 16_000,
        "daily capture extended the common shutdown deadline",
      );
      await new Promise((accept) => setTimeout(accept, 250));
    }
    const shutdownElapsed = Date.now() - shutdownStarted;
    assert(shutdownElapsed >= 9000 && shutdownElapsed < 16_000);
    await releaseHold(interruptedHold);
    const interruptedState = await dailyState(
      dailyInterruptedVolume,
      dailyInterruptedVolume,
    );
    assert.equal(interruptedState.jobs[0].attempts, interrupted.attempts);
    assert.equal(interruptedState.jobs[0].owner, interrupted.owner);
    assert.equal(interruptedState.jobs[0].finishedAt, null);
    assert.deepEqual(interruptedState.archives, []);
    const interruptedLogs = await docker(["logs", dailyInterruptedWorker]);
    assert(
      interruptedLogs.stderr.includes(
        "spl-server: server shutdown exceeded 10 seconds; the deployment lease remains held until this process exits. Exit this process before an offline backup or restore",
      ),
    );
    assert(
      !assertDailyEvents(await records(dailyInterruptedWorker)).some(
        ({ fields }) => fields.event === "succeeded",
      ),
    );
    await dailyCli("create", dailyInterruptedVolume);
    const retryAt = publicationFailure.jobs[0].availableAt;
    for (;;) {
      const state = await publicationState();
      assert.equal(state.jobs.length, 1);
      const [job] = state.jobs;
      assert.equal(job.slot, slot);
      if (job.finishedAt !== null) {
        assert.equal(job.attempts, 3);
        assert.equal(job.owner, null);
        assert(job.finishedAt >= retryAt);
        assert.equal(state.staging, 1);
        assert.deepEqual(
          state.archives.map(({ name }) => name),
          [dailyArchive],
        );
        break;
      }
      assert(
        Date.now() < retryAt + 120_000,
        "daily publication retry timed out",
      );
      await new Promise((accept) => setTimeout(accept, 5000));
    }
    const retryEvents = assertDailyEvents(
      await records(dailyPublicationWorker),
    );
    const starts = retryEvents.filter(
      ({ fields }) => fields.event === "started" && fields.attempt === 3,
    );
    assert.equal(starts.length, 1);
    assert(Date.parse(starts[0].timestamp) >= retryAt);
    assert.equal(
      retryEvents.filter(
        ({ fields }) => fields.event === "succeeded" && fields.attempt === 3,
      ).length,
      1,
    );
    await marker("check-recovered");
    await dailyCli(
      "verify",
      dailyPublicationVolume,
      false,
      dailyPublicationVolume,
    );
    await stopDailyWorker(dailyPublicationWorker);
    console.log(
      "Daily archive publication preserved a competing output and unrelated staging, then the persisted retry published a verified archive.",
    );
    console.log(
      "Daily Worker failures preserved collision and unconfirmed output with retry state, empty passphrase failure left public login/sync available, and interrupted capture kept offline admission until the bounded fatal process exit.",
    );

    progress("offline snapshot restore");
    await compose(["stop", "server"]);
    assert.equal((await inspect("container", container)).State.ExitCode, 0);
    await docker([
      "volume",
      "create",
      "--label",
      `${ownerLabel}=${run}`,
      recoveryVolume,
    ]);
    assertOwnedResource((await inspect("volume", recoveryVolume)).Labels, run);
    await sqliteProbe(
      "restore-offline",
      [
        "--mount",
        `type=volume,source=${project}_data,target=/source,readonly`,
        "--mount",
        `type=volume,source=${recoveryVolume},target=/recovery`,
      ],
      "0:0",
    );

    progress("matching old image recovery");
    const recoveredContainerId = (
      await docker([
        "run",
        "--detach",
        "--name",
        recoveryContainer,
        "--pull",
        "never",
        "--label",
        `${ownerLabel}=${run}`,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--publish",
        `127.0.0.1:${port}:8443`,
        "--env",
        "SPL_SERVER_PUBLIC_HOST=localhost",
        "--env",
        `SPL_SERVER_PUBLIC_PORT=${port}`,
        "--mount",
        `type=volume,source=${recoveryVolume},target=/var/lib/spl`,
        "--mount",
        `type=bind,source=${join(fixture, "tls")},target=/run/scoplen/tls,readonly`,
        historicalImage,
      ])
    ).stdout.trim();
    assert(/^[a-f0-9]{12,64}$/.test(recoveredContainerId));
    const recoveredService = await inspect("container", recoveredContainerId);
    assertOwnedResource(recoveredService.Config.Labels, run);
    assert.equal(recoveredService.Image, historicalImageId);
    assert.equal(recoveredService.HostConfig.ReadonlyRootfs, true);
    const recoveryDeadline = Date.now() + 60_000;
    for (;;) {
      try {
        if ((await request(origin, "/readyz", ca)).status === 200) break;
      } catch {}
      assert(
        Date.now() < recoveryDeadline,
        "matching old image recovery timed out",
      );
      await new Promise((accept) => setTimeout(accept, 500));
    }
    assert.equal((await request(origin, "/healthz", ca)).status, 200);
    await sqliteProbe("check-recovery", [
      "--mount",
      `type=volume,source=${project}_data,target=/source,readonly`,
      "--mount",
      `type=volume,source=${recoveryVolume},target=/recovery,readonly`,
    ]);
    succeeded = true;
  } catch (error) {
    console.error(
      `Personal container check failure: ${JSON.stringify(describeCheckFailure({ phase, error }))}`,
    );
    await writePrivateDiagnostic(
      join(directory, "failure.txt"),
      `${phase}\n${error.stack}\n`,
      phase,
    );
    throw error;
  } finally {
    progress(succeeded ? "owned-resource cleanup" : "failed-check cleanup");
    try {
      const containers = (
        await docker([
          "container",
          "ls",
          "--all",
          "--filter",
          `label=${ownerLabel}=${run}`,
          "--format",
          "{{.ID}}",
        ])
      ).stdout
        .trim()
        .split(/\s+/)
        .filter(Boolean);
      for (const id of containers) {
        const item = await inspect("container", id);
        assertOwnedResource(
          item.Config.Labels,
          run,
          [`/${inspector}`, `/${walHolder}`, `/${recoveryContainer}`].includes(
            item.Name,
          )
            ? undefined
            : project,
        );
        assert(
          [
            `/${inspector}`,
            `/${project}-server-1`,
            `/${walHolder}`,
            `/${recoveryContainer}`,
            ...[
              ...dailyWorkers,
              dailyAllWorker,
              dailyFailureWorker,
              dailyPublicationWorker,
              publicationHold,
              dailyDisabledWorker,
              dailyInterruptedWorker,
              captureHold,
              interruptedHold,
              dailyUnconfirmedWorker,
              dailyPassphraseWorker,
            ].map((name) => `/${name}`),
          ].includes(item.Name),
          "unexpected owned container",
        );
        assert(
          [imageId, historicalImageId, probeImageId].includes(item.Image),
          "owned container changed images",
        );
        if (item.State.Running) await docker(["stop", "--time", "30", id]);
        if (succeeded) await docker(["container", "rm", "--volumes", id]);
      }
      if (succeeded) {
        for (const [kind, name] of [
          ["volume", `${project}_data`],
          ["network", `${project}_default`],
        ]) {
          const item = await inspect(kind, name);
          assertOwnedResource(item.Labels, run, project);
          await docker([kind, "rm", name]);
        }
        assertOwnedResource(
          (await inspect("volume", recoveryVolume)).Labels,
          run,
        );
        await docker(["volume", "rm", recoveryVolume]);
        assertOwnedResource(
          (await inspect("volume", archiveVolume)).Labels,
          run,
        );
        await docker(["volume", "rm", archiveVolume]);
        assertOwnedResource(
          (await inspect("volume", onlineArchiveVolume)).Labels,
          run,
        );
        await docker(["volume", "rm", onlineArchiveVolume]);
        for (const name of [
          dailyArchiveVolume,
          dailyFailureVolume,
          dailyPublicationVolume,
          dailyInterruptedVolume,
          dailyUnconfirmedVolume,
          dailyPassphraseVolume,
        ]) {
          assertOwnedResource((await inspect("volume", name)).Labels, run);
          await docker(["volume", "rm", name]);
        }
        for (const [tag, expectedId] of [
          [image, imageId],
          [historicalImage, historicalImageId],
        ]) {
          const item = await inspect("image", tag);
          assertOwnedResource(item.Config.Labels, run);
          assert.equal(item.Id, expectedId);
          await docker(["image", "rm", tag]);
        }
        if (certificatePrepared) {
          await nodeProbe("release-tls", [
            "--mount",
            `type=bind,source=${directory},target=/check`,
          ]);
        }
        await assertOwnedFixture(directory, parent, run);
        await rm(directory, { recursive: true });
      } else {
        console.error(
          `Private diagnostics and stopped test resources retained: ${directory}`,
        );
      }
    } catch (error) {
      console.error(
        `Personal container check failure: ${JSON.stringify(describeCheckFailure({ phase, error }))}`,
      );
      await writePrivateDiagnostic(
        join(directory, "cleanup-failure.txt"),
        `${error.stack}\n`,
        phase,
      );
      console.error(
        `Cleanup stopped; private diagnostics and remaining test resources retained: ${directory}`,
      );
      throw error;
    }
  }
  console.log(
    "Personal container check passed: production build, trusted HTTPS, native doctor success/stopped failure/restart recovery, console, public Operator setup/login/logout, independent password Accounts and Devices, team creation/conditional name settings/discovery/confirmation, foreign-versus-absent team GET/PATCH isolation and encrypted Personal Host sync for both Accounts, bidirectional shared-password Credential sync and foreign-Account snapshot/version refusal, native refresh and complete team/Personal isolation across restart and public encrypted-archive restoration into a fresh Compose parent volume with a further persistent restart, Worker-triggered daily capture during public writes, two-Worker ownership/renewal, worker-only/combined/all selection, same-day restart suppression, collision/retry/disable preservation and bounded shutdown admission, retained database/audit/key/object state and committed WAL Accounts, retired entry absence, persistent restart state, SQLite upgrade and matching old image recovery.",
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const arguments_ = process.argv.slice(2);
  if (
    arguments_.length !== 4 ||
    arguments_[0] !== "--bootstrap-driver" ||
    arguments_[2] !== "--doctor-cli"
  ) {
    console.error(
      "usage: node scripts/check-personal-container.mjs --bootstrap-driver <native-personal_live_bootstrap> --doctor-cli <native-splctl>",
    );
    process.exitCode = 1;
  } else {
    try {
      await checkPersonalContainer(arguments_[1], arguments_[3]);
    } catch {
      console.error(
        "Personal container check failed; private command output was not printed.",
      );
      process.exitCode = 1;
    }
  }
}
