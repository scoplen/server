// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  link,
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
import { DatabaseSync } from "node:sqlite";
import { once } from "node:events";
import { createInterface } from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { publicationMarker } from "./check-personal-container-publication.mjs";
import {
  assertAccountAcceptance,
  assertBackupAcceptance,
  assertDoctorAcceptance,
  assertDailyCapture,
  assertDailyEvents,
  assertTeamAcceptance,
  assertTeamRestartAcceptance,
  assertOwnedFixture,
  assertOwnedResource,
  assertPrivateDirectoryArchive,
  consoleAssetContentType,
  consoleProbeImage,
  describeCheckFailure,
  describeImageBuildFailure,
  describeWalHolderFailure,
  prepareRecoveryProbeContext,
  runTeamRestart,
  runOnlineBackup,
} from "./check-personal-container.mjs";
import {
  inspectDailyJobs,
  inspectDatabase,
} from "./personal-sqlite-recovery-probe.mjs";

async function onlineTestDriver(
  fixture,
  signal,
  outsideInterval = false,
  daily = false,
) {
  const prefix = daily ? "daily-backup" : "online-backup";
  const kind = daily ? "daily" : "online";
  const wait = async (name) => {
    for (;;) {
      if (signal.aborted) throw new Error("online test driver aborted");
      try {
        const contents = await readFile(
          join(fixture, `${prefix}.${name}`),
          "utf8",
        );
        assert("continue\n".startsWith(contents));
        if (contents === "continue\n") return;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      await new Promise((accept) => setTimeout(accept, 5));
    }
  };
  const ready = async (name) => {
    const path = join(fixture, `${prefix}.${name}`);
    await writeFile(path, "rea", { flag: "wx" });
    await new Promise((accept) => setTimeout(accept, 60));
    await writeFile(path, "dy\n", { flag: "a" });
  };
  await ready("ready");
  await wait("start");
  const written = outsideInterval ? 0 : Date.now();
  await wait("complete");
  await writeFile(
    join(fixture, `${prefix}-writes.json`),
    JSON.stringify([written]),
  );
  await ready("post");
  await wait("resume");
  await ready("restored");
  await wait("restart");
  await writeFile(
    join(fixture, `${prefix}-acceptance.json`),
    JSON.stringify({
      [`${kind}_public_writes_verified`]: true,
      [`${kind}_restored_device_team_verified`]: true,
      [`${kind}_restored_restart_verified`]: true,
    }),
  );
}

test("online archive controller requires writes before restoring and retains the driver across restart", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-online-archive-test-"));
  const phases = [];
  try {
    await runOnlineBackup({
      fixture,
      run: (signal) => onlineTestDriver(fixture, signal),
      capture: async () => {
        phases.push("capture");
        await new Promise((accept) => setTimeout(accept, 100));
      },
      restore: async () => {
        phases.push("restore");
        await assert.rejects(readFile(join(fixture, "online-backup.resume")), {
          code: "ENOENT",
        });
      },
      restart: async () => {
        phases.push("restart");
        await assert.rejects(readFile(join(fixture, "online-backup.restart")), {
          code: "ENOENT",
        });
      },
    });
    assert.deepEqual(phases, ["capture", "restore", "restart"]);
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("online archive controller refuses write receipts outside capture without restoring", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-online-archive-test-"));
  let restored = false;
  try {
    await assert.rejects(
      runOnlineBackup({
        fixture,
        run: (signal) => onlineTestDriver(fixture, signal, true),
        capture: async () => {
          await new Promise((accept) => setTimeout(accept, 100));
        },
        restore: async () => {
          restored = true;
        },
        restart: async () => {},
      }),
      /no confirmed public write/,
    );
    assert.equal(restored, false);
    await assert.rejects(readFile(join(fixture, "online-backup.resume")), {
      code: "ENOENT",
    });
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("failed online capture aborts its driver without restoration or a completion signal", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-online-archive-test-"));
  let restored = false;
  try {
    await assert.rejects(
      runOnlineBackup({
        fixture,
        run: (signal) => onlineTestDriver(fixture, signal),
        capture: async () => {
          throw new Error("capture failed");
        },
        restore: async () => {
          restored = true;
        },
        restart: async () => {},
      }),
      /capture failed/,
    );
    assert.equal(restored, false);
    await assert.rejects(readFile(join(fixture, "online-backup.complete")), {
      code: "ENOENT",
    });
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("daily journey uses separate one-use signals and the observed active Worker interval", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-daily-archive-test-"));
  try {
    const confirmed = await runOnlineBackup({
      fixture,
      daily: true,
      run: (signal) => onlineTestDriver(fixture, signal, false, true),
      capture: async () => {
        const started = Date.now();
        await new Promise((accept) => setTimeout(accept, 100));
        const finished = Date.now();
        await new Promise((accept) => setTimeout(accept, 25));
        return { started, finished };
      },
      restore: async () => {},
      restart: async () => {},
    });
    assert.equal(confirmed, 1);
    await assert.rejects(readFile(join(fixture, "online-backup.ready")), {
      code: "ENOENT",
    });
    await assert.rejects(
      runOnlineBackup({ fixture, daily: true }),
      /signal already exists/,
    );
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("daily journey refuses a missing active interval before restoring", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-daily-archive-test-"));
  let restored = false;
  try {
    await assert.rejects(
      runOnlineBackup({
        fixture,
        daily: true,
        run: (signal) => onlineTestDriver(fixture, signal, false, true),
        capture: async () => {},
        restore: async () => {
          restored = true;
        },
        restart: async () => {},
      }),
      /invalid active capture interval/,
    );
    assert.equal(restored, false);
    await assert.rejects(readFile(join(fixture, "daily-backup.complete")), {
      code: "ENOENT",
    });
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("daily journey rejects writes outside the observed active capture interval", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-daily-archive-test-"));
  let restored = false;
  try {
    await assert.rejects(
      runOnlineBackup({
        fixture,
        daily: true,
        run: (signal) => onlineTestDriver(fixture, signal, false, true),
        capture: async () => {
          await new Promise((accept) => setTimeout(accept, 75));
          const started = Date.now();
          await new Promise((accept) => setTimeout(accept, 50));
          return { started, finished: Date.now() };
        },
        restore: async () => {
          restored = true;
        },
        restart: async () => {},
      }),
      /no confirmed public write/,
    );
    assert.equal(restored, false);
  } finally {
    await rm(fixture, { recursive: true });
  }
});

function dailySamples() {
  const now = 1_700_000_000_000;
  const job = {
    slot: "2026-11-18",
    attempts: 1,
    owner: "worker-one",
    leaseUntil: now + 60_000,
    availableAt: now,
    createdAt: now,
    finishedAt: null,
    lastError: null,
  };
  return [
    { observedAt: now, jobs: [{ ...job }], archives: [], staging: 1 },
    {
      observedAt: now + 21_000,
      jobs: [{ ...job, leaseUntil: now + 80_000 }],
      archives: [],
      staging: 1,
    },
    {
      observedAt: now + 22_000,
      jobs: [
        { ...job, owner: null, leaseUntil: null, finishedAt: now + 21_500 },
      ],
      archives: [{ name: "scoplen-2026-11-18.age", size: 100 }],
      staging: 0,
    },
  ];
}

test(
  "Linux fixture lease blocks a real archive object read until release",
  {
    skip: process.platform !== "linux",
    timeout: 15_000,
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "scoplen-object-lease-"));
    const object = join(directory, "ci-daily-capture-buffer");
    const probe = fileURLToPath(
      new URL("./hold-daily-backup-object.pl", import.meta.url),
    );
    await writeFile(object, "owned object", { mode: 0o600 });
    const holder = spawn("perl", [probe, object], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    const exited = once(holder, "exit");
    const lines = createInterface({ input: holder.stdout })[
      Symbol.asyncIterator
    ]();
    let reading;
    let completed = false;
    try {
      assert.equal((await lines.next()).value, "ready");
      reading = readFile(object, "utf8").then((contents) => {
        completed = true;
        return contents;
      });
      assert.equal((await lines.next()).value, "blocked");
      await writeFile(join(directory, "unrelated"), "independent write", {
        flag: "wx",
      });
      assert.equal(completed, false);
      assert(holder.kill("SIGUSR1"));
      assert.equal((await lines.next()).value, "released");
      assert.equal(await reading, "owned object");
      assert.equal((await exited)[0], 0);
    } finally {
      holder.kill("SIGKILL");
      await exited;
      await reading;
      await rm(directory, { recursive: true });
    }
  },
);

test("post-admission publication collides on a real hard link and preserves competing staging across retry", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-publication-test-"));
  const slot = "2026-01-02";
  const output = join(root, `scoplen-${slot}.age`);
  const staged = join(root, "encrypted-fixture");
  try {
    await writeFile(staged, "simulated completed archive", { flag: "wx" });
    await publicationMarker(root, slot, "publish");
    await assert.rejects(link(staged, output), { code: "EEXIST" });
    await publicationMarker(root, slot, "withdraw");
    await link(staged, output);
    await publicationMarker(root, slot, "check-recovered");
    await assert.rejects(
      publicationMarker(root, slot, "withdraw"),
      /unrelated file/,
    );
    assert.equal(await readFile(output, "utf8"), "simulated completed archive");
  } finally {
    await rm(root, { recursive: true });
  }
});

test("daily runtime evidence requires renewal, one owner and confirmed completion", () => {
  const samples = dailySamples();
  assert.deepEqual(assertDailyCapture(samples, "2026-11-18"), {
    started: samples[0].observedAt,
    finished: samples[1].observedAt,
  });
  for (const mutate of [
    (value) => {
      value[1].jobs[0].owner = "worker-two";
    },
    (value) => {
      value[1].jobs[0].attempts = 2;
    },
    (value) => {
      value[1].jobs.push({ ...value[1].jobs[0] });
    },
    (value) => {
      value[1].jobs[0].leaseUntil = value[0].jobs[0].leaseUntil;
    },
    (value) => {
      value[1].observedAt = value[0].observedAt + 100;
    },
    (value) => {
      value[2].jobs[0].finishedAt = null;
    },
    (value) => {
      value[2].archives = [];
    },
    (value) => {
      value[2].staging = 1;
    },
    (value) => {
      value[0].staging = 0;
      value[1].staging = 0;
    },
  ]) {
    const invalid = dailySamples();
    mutate(invalid);
    assert.throws(() => assertDailyCapture(invalid, "2026-11-18"));
  }
});

test("daily capture failures report fixed reasons without observed state", () => {
  for (const [message, reason] of [
    ["object hold exited early", "daily-object-hold-exit"],
    ["object hold signal timed out", "daily-object-hold-timeout"],
    ["object hold release failed", "daily-object-hold-release"],
    [
      "daily capture ended outside the held object read",
      "daily-object-hold-interval",
    ],
  ]) {
    assert.equal(
      describeCheckFailure({
        phase: "daily Worker ownership and renewal",
        error: { code: "ERR_ASSERTION", message },
      }).reason,
      reason,
    );
  }
  for (const [mutate, reason] of [
    [(samples) => samples.splice(1), "daily-observations"],
    [
      (samples) => {
        samples[0].staging = 0;
        samples[1].staging = 0;
      },
      "daily-active-interval",
    ],
    [
      (samples) => {
        samples[1].jobs[0].owner = "synthetic-private-owner";
      },
      "daily-owner-change",
    ],
    [
      (samples) => {
        samples[1].jobs[0].leaseUntil = samples[0].jobs[0].leaseUntil;
      },
      "daily-lease-renewal",
    ],
    [
      (samples) => {
        samples[1].observedAt = samples[0].observedAt + 100;
      },
      "daily-renewal-interval",
    ],
  ]) {
    const samples = dailySamples();
    mutate(samples);
    assert.throws(
      () => assertDailyCapture(samples, "2026-11-18"),
      (error) => {
        const description = describeCheckFailure({
          phase: "daily Worker ownership and renewal",
          error,
        });
        assert.deepEqual(description, {
          phase: "daily Worker ownership and renewal",
          category: "validation",
          reason,
          ioCode: null,
          exitCode: null,
          signal: null,
        });
        assert(
          !JSON.stringify(description).includes("synthetic-private-owner"),
        );
        return true;
      },
    );
  }
});

test("daily events accept only fixed content-free status fields", () => {
  const event = {
    target: "backup.daily",
    fields: {
      message: "scheduled backup status",
      event: "started",
      slot: "2026-11-18",
      attempt: 1,
      archive: "scoplen-2026-11-18.age",
    },
  };
  assertDailyEvents([event]);
  assertDailyEvents([
    {
      target: "backup.daily",
      fields: {
        message: "scheduled backups require a Worker process",
        event: "enabled",
        reason: "worker_required",
      },
    },
  ]);
  for (const fields of [
    { ...event.fields, path: "/private/archive" },
    { ...event.fields, reason: "private_error_text" },
    { ...event.fields, archive: "/private/scoplen-2026-11-18.age" },
    { ...event.fields, message: "underlying private failure" },
  ])
    assert.throws(() => assertDailyEvents([{ ...event, fields }]));
});

test("daily persisted probe validates the public slot payload and deterministic identity", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-daily-job-probe-"));
  const path = join(fixture, "jobs.sqlite");
  const database = new DatabaseSync(path);
  try {
    database.exec(
      "CREATE TABLE jobs (id BLOB, kind TEXT, payload BLOB, available_at_ms INTEGER, attempts INTEGER, lease_owner TEXT, lease_until_ms INTEGER, created_at_ms INTEGER, finished_at_ms INTEGER, last_error TEXT)",
    );
    const day = Buffer.alloc(8);
    day.writeBigInt64BE(
      BigInt(Date.parse("2026-11-18T00:00:00Z") / 86_400_000),
    );
    const id = createHash("sha256")
      .update("scoplen.backup.daily.v1\0")
      .update(day)
      .digest()
      .subarray(0, 16);
    database
      .prepare(
        "INSERT INTO jobs VALUES (?, 'backup.daily', ?, 1, 1, 'worker-one', 60001, 1, NULL, NULL)",
      )
      .run(id, Buffer.from("2026-11-18"));
    assert.deepEqual(inspectDailyJobs(path), [
      {
        slot: "2026-11-18",
        attempts: 1,
        owner: "worker-one",
        leaseUntil: 60001,
        availableAt: 1,
        createdAt: 1,
        finishedAt: null,
        lastError: null,
      },
    ]);
    database
      .prepare("UPDATE jobs SET payload = ?")
      .run(Buffer.from("2026-02-30"));
    assert.throws(() => inspectDailyJobs(path));
    database
      .prepare("UPDATE jobs SET payload = ?, id = ?")
      .run(Buffer.from("2026-11-18"), Buffer.alloc(16));
    assert.throws(() => inspectDailyJobs(path));
  } finally {
    database.close();
    await rm(fixture, { recursive: true });
  }
});

test("archive acceptance requires command success and the matching confirmation before optional mappings", () => {
  for (const [operation, first] of [
    ["create", "Backup created."],
    ["verify", "Backup verified."],
    ["restore", "Backup restored."],
  ]) {
    const success = { stdout: `${first}\n`, stderr: "" };
    assertBackupAcceptance(success, operation);
    assertBackupAcceptance(
      { ...success, stdout: `${first}\r\nConfiguration mapping follows.\r\n` },
      operation,
    );
    for (const result of [
      { ...success, error: { code: 1 } },
      { ...success, error: { signal: "SIGTERM" } },
      { ...success, error: { code: "ENOENT" } },
      { ...success, stderr: "unexpected diagnostic" },
      { ...success, stdout: "" },
      { ...success, stdout: "Backup failed.\n" },
    ])
      assert.throws(() => assertBackupAcceptance(result, operation));
  }
  assert.throws(() =>
    assertBackupAcceptance({ stdout: "", stderr: "" }, "unknown"),
  );
  assert.throws(() =>
    assertBackupAcceptance(
      { stdout: "Backup verified.\n", stderr: "" },
      "restore",
    ),
  );
});

test("container probes use the current digest-pinned console dependency image", async () => {
  const dockerfile = await readFile(
    new URL("../Dockerfile", import.meta.url),
    "utf8",
  );
  assert.match(
    consoleProbeImage(dockerfile),
    /^node:[^\s]+@sha256:[a-f0-9]{64}$/,
  );
  assert.throws(() =>
    consoleProbeImage(
      dockerfile.replace("AS console-dependencies", "AS other"),
    ),
  );
  assert.throws(() =>
    consoleProbeImage(dockerfile.replace(/@sha256:[a-f0-9]{64}/, "")),
  );
});

test("bundled asset verification admits WebAssembly with its required response type", () => {
  for (const [path, expected] of [
    ["index.html", "text/html; charset=utf-8"],
    ["assets/index.js", "text/javascript; charset=utf-8"],
    ["assets/index.css", "text/css; charset=utf-8"],
    ["assets/inter.woff2", "font/woff2"],
    ["assets/scoplen_browser_bg.wasm", "application/wasm"],
  ])
    assert.equal(consoleAssetContentType(path), expected);
  for (const path of [
    "assets/../index.html",
    "assets/subdir/module.wasm",
    "module.wasm",
    "assets/module.wasm.map",
  ])
    assert.throws(() => consoleAssetContentType(path));
});

function teamTestDriver(fixture, source, signal, observe = () => {}) {
  return new Promise((accept, reject) => {
    let result;
    const child = execFile(
      process.execPath,
      ["--input-type=module", "-e", source, fixture],
      { signal, timeout: 5000, windowsHide: true },
      (error, stdout, stderr) => {
        result = { error, stdout, stderr };
      },
    );
    observe(child);
    child.once("close", () => {
      if (result.error)
        reject(
          new Error("synthetic team driver failed", { cause: result.error }),
        );
      else accept(result);
    });
  });
}

const teamReady = `
  import assert from "node:assert/strict";
  import { readFile, writeFile } from "node:fs/promises";
  import { join } from "node:path";
  const fixture = process.argv[1];
  const held = { proof: "synthetic-private-proof", refresh: "synthetic-private-refresh" };
  await writeFile(join(fixture, "team-restart.ready"), "ready\\n", { flag: "wx" });
  for (;;) {
    try {
      assert.equal(await readFile(join(fixture, "team-restart.resume"), "utf8"), "resume\\n");
      break;
    } catch (error) { if (error.code !== "ENOENT") throw error; }
    await new Promise((accept) => setTimeout(accept, 10));
  }
  assert.equal(held.refresh, "synthetic-private-refresh");
  assert.equal(held.proof, "synthetic-private-proof");
  process.stdout.write("team-test-complete\\n");
`;

test("team driver retains its process across the controller restart before resuming", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-team-restart-test-"));
  let restarts = 0;
  let result;
  try {
    await runTeamRestart({
      fixture,
      run: async (signal) => {
        result = await teamTestDriver(fixture, teamReady, signal);
      },
      restart: async () => {
        restarts++;
        await assert.rejects(readFile(join(fixture, "team-restart.resume")), {
          code: "ENOENT",
        });
      },
    });
    assert.equal(restarts, 1);
    assert.equal(result.stdout, "team-test-complete\n");
    assert.equal(result.stderr, "");
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("team driver failure before readiness never restarts the server or publishes resume", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-team-restart-test-"));
  let restarts = 0;
  try {
    await assert.rejects(
      runTeamRestart({
        fixture,
        run: (signal) => teamTestDriver(fixture, "process.exit(7)", signal),
        restart: async () => {
          restarts++;
        },
      }),
      /synthetic team driver failed/,
    );
    assert.equal(restarts, 0);
    await assert.rejects(readFile(join(fixture, "team-restart.resume")), {
      code: "ENOENT",
    });
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("team readiness deadline aborts and reaps only its own stalled driver", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-team-restart-test-"));
  let child;
  let restarts = 0;
  try {
    await assert.rejects(
      runTeamRestart({
        fixture,
        timeout: 50,
        run: (signal) =>
          teamTestDriver(
            fixture,
            "setInterval(() => {}, 1000)",
            signal,
            (value) => {
              child = value;
            },
          ),
        restart: async () => {
          restarts++;
        },
      }),
      /team restart driver readiness timed out/,
    );
    assert.equal(restarts, 0);
    assert(child.exitCode !== null || child.signalCode !== null);
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("controller restart failure aborts the retained team driver without publishing resume", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-team-restart-test-"));
  let child;
  try {
    await assert.rejects(
      runTeamRestart({
        fixture,
        run: (signal) =>
          teamTestDriver(fixture, teamReady, signal, (value) => {
            child = value;
          }),
        restart: async () => {
          throw new Error("synthetic restart failure");
        },
      }),
      /synthetic restart failure/,
    );
    assert(child.exitCode !== null || child.signalCode !== null);
    await assert.rejects(readFile(join(fixture, "team-restart.resume")), {
      code: "ENOENT",
    });
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("stale team restart signals are preserved and never start a driver or restart", async () => {
  for (const name of ["team-restart.ready", "team-restart.resume"]) {
    const fixture = await mkdtemp(join(tmpdir(), "scoplen-team-restart-test-"));
    let calls = 0;
    try {
      const path = join(fixture, name);
      await writeFile(path, "synthetic-private-value", { flag: "wx" });
      await assert.rejects(
        runTeamRestart({
          fixture,
          run: async () => {
            calls++;
          },
          restart: async () => {
            calls++;
          },
        }),
        /team restart signal already exists/,
      );
      assert.equal(calls, 0);
      assert.equal(await readFile(path, "utf8"), "synthetic-private-value");
    } finally {
      await rm(fixture, { recursive: true });
    }
  }
});

test("a successful child exit without team readiness is not restart acceptance", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "scoplen-team-restart-test-"));
  let restarts = 0;
  try {
    await assert.rejects(
      runTeamRestart({
        fixture,
        run: (signal) => teamTestDriver(fixture, "process.exit(0)", signal),
        restart: async () => {
          restarts++;
        },
      }),
      /team restart driver exited before restart/,
    );
    assert.equal(restarts, 0);
  } finally {
    await rm(fixture, { recursive: true });
  }
});

test("doctor acceptance binds exit status and complete fixed findings to the service state", () => {
  const output = (healthy) =>
    [
      "PASS configuration: configuration and selected roles are valid.",
      ...["health", "readiness"].map((check) =>
        healthy
          ? `PASS ${check}: trusted public HTTPS returned the expected response.`
          : `FAIL ${check}: could not establish trusted HTTPS; check DNS, the public port, certificate chain and hostname, or explicitly supply the deployment CA.`,
      ),
      "NOT CHECKED remaining diagnostics: external reachability; ACME management; clock offset; local storage permissions and capacity; direct database/object/KMS probes; backup recency; schema and gateway/host-agent compatibility; console parity.",
      "",
    ].join("\n");
  const success = { stdout: output(true), stderr: "" };
  const stopped = { stdout: output(false), stderr: "", error: { code: 1 } };
  assertDoctorAcceptance(success, true);
  assertDoctorAcceptance(stopped, false);
  assertDoctorAcceptance(
    { ...success, stdout: success.stdout.replaceAll("\n", "\r\n") },
    true,
  );
  for (const [result, healthy] of [
    [success, false],
    [stopped, true],
    [{ ...success, error: { code: 1 } }, true],
    [{ ...success, error: { code: null, killed: true } }, true],
    [{ ...success, error: { signal: "SIGTERM" } }, true],
    [{ ...success, stderr: "unexpected diagnostic" }, true],
    [{ ...success, stdout: "PASS configuration\n" }, true],
    [
      { ...success, stdout: `${success.stdout}unexpected response body\n` },
      true,
    ],
    [{ ...stopped, error: { code: 2 } }, false],
    [{ ...stopped, error: { code: "ENOENT" } }, false],
  ]) {
    assert.throws(() => assertDoctorAcceptance(result, healthy));
  }
});

test("container CLI requires both native consumers before preparing a fixture", async () => {
  const result = await new Promise((accept) => {
    execFile(
      process.execPath,
      [
        fileURLToPath(
          new URL("./check-personal-container.mjs", import.meta.url),
        ),
        "--bootstrap-driver",
        "unused",
      ],
      { timeout: 10_000, windowsHide: true },
      (error, stdout, stderr) => accept({ error, stdout, stderr }),
    );
  });
  assert.equal(result.error?.code, 1);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr.trim(),
    "usage: node scripts/check-personal-container.mjs --bootstrap-driver <native-personal_live_bootstrap> --doctor-cli <native-splctl>",
  );
});

test("Account acceptance requires password, Host and Credential sync and isolation", () => {
  const complete = {
    account_password_sync_verified: true,
    account_credential_sync_verified: true,
    account_credential_isolation_verified: true,
  };
  assert.doesNotThrow(() => assertAccountAcceptance(complete));
  for (const receipt of [
    undefined,
    null,
    {},
    { account_password_sync_verified: true },
    {
      account_password_sync_verified: true,
      account_credential_sync_verified: true,
    },
    { ...complete, account_password_sync_verified: false },
    { ...complete, account_password_sync_verified: "true" },
    { ...complete, account_credential_sync_verified: false },
    { ...complete, account_credential_sync_verified: "true" },
    { ...complete, account_credential_isolation_verified: false },
    { ...complete, account_credential_isolation_verified: "true" },
    { disposable: true, operator_lifecycle_verified: true },
  ]) {
    assert.throws(() => assertAccountAcceptance(receipt));
  }
});

test("team acceptance requires both Accounts' creation, settings, isolation and Personal sync", () => {
  assert.doesNotThrow(() =>
    assertTeamAcceptance({
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: true,
      team_account_isolation_verified: true,
    }),
  );
  for (const receipt of [
    undefined,
    null,
    {},
    { team_creation_personal_sync_verified: true },
    { team_settings_personal_sync_verified: true },
    {
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: true,
    },
    {
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: true,
      team_account_isolation_verified: false,
    },
    {
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: true,
      team_account_isolation_verified: "true",
    },
    {
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: false,
    },
    {
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: "true",
    },
    { team_creation_personal_sync_verified: false },
    { team_creation_personal_sync_verified: "true" },
    { account_password_sync_verified: true },
    { disposable: true, operator_lifecycle_verified: true },
    {
      team_creation_personal_sync_verified: true,
      team_settings_personal_sync_verified: true,
      team_account_isolation_verified: true,
      team_name: "unexpected",
    },
  ]) {
    assert.throws(() => assertTeamAcceptance(receipt));
  }
});

test("team restart acceptance requires retained membership, settings and Account isolation", () => {
  assert.doesNotThrow(() =>
    assertTeamRestartAcceptance({
      team_membership_restart_verified: true,
      team_settings_restart_verified: true,
      team_account_isolation_restart_verified: true,
    }),
  );
  for (const receipt of [
    undefined,
    null,
    {},
    { team_membership_restart_verified: true },
    { team_settings_restart_verified: true },
    {
      team_membership_restart_verified: true,
      team_settings_restart_verified: true,
    },
    {
      team_membership_restart_verified: true,
      team_settings_restart_verified: true,
      team_account_isolation_restart_verified: false,
    },
    {
      team_membership_restart_verified: true,
      team_settings_restart_verified: true,
      team_account_isolation_restart_verified: "true",
    },
    {
      team_membership_restart_verified: true,
      team_settings_restart_verified: false,
    },
    {
      team_membership_restart_verified: true,
      team_settings_restart_verified: "true",
    },
    { team_membership_restart_verified: false },
    { team_membership_restart_verified: "true" },
    { team_creation_personal_sync_verified: true },
    { account_password_sync_verified: true },
    {
      team_membership_restart_verified: true,
      team_settings_restart_verified: true,
      team_account_isolation_restart_verified: true,
      team_name: "unexpected",
    },
  ])
    assert.throws(() => assertTeamRestartAcceptance(receipt));
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

test("actual SQLite recovery inspection preserves old rows and requires current Grant, request, draft login, browser and KRL tables", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scoplen-recovery-schema-"));
  const path = join(directory, "scoplen.sqlite");
  const database = new DatabaseSync(path);
  try {
    database.exec(
      "PRAGMA foreign_keys = ON; CREATE TABLE _sqlx_migrations (version INTEGER PRIMARY KEY, success INTEGER NOT NULL)",
    );
    const migrations = new URL(
      "../crates/scoplen-store/migrations/sqlite/",
      import.meta.url,
    );
    const names = (await readdir(migrations))
      .filter((name) => /^\d{14}_.+\.sql$/.test(name))
      .sort();
    const old = 20261024030000;
    async function applyMigration(name) {
      database.exec(await readFile(new URL(name, migrations), "utf8"));
      database
        .prepare("INSERT INTO _sqlx_migrations VALUES (?, 1)")
        .run(Number(name.slice(0, 14)));
    }
    for (const name of names.filter((name) => Number(name.slice(0, 14)) <= old))
      await applyMigration(name);
    database
      .prepare(
        "INSERT INTO organizations (id, name, created_at_ms) VALUES (?, 'Disposable recovery organization', 123)",
      )
      .run(Buffer.alloc(16, 0x33));
    database
      .prepare(
        "INSERT INTO sync_vaults (vault_id, kind, current_seq, purge_horizon) VALUES (?, 'organization', 1, 0)",
      )
      .run(Buffer.alloc(16, 0x11));
    for (const table of ["sync_objects", "sync_object_versions"])
      database
        .prepare(
          `INSERT INTO ${table} (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms, key_epoch) VALUES (?, ?, 1, ?, 0, NULL, 123, 1)`,
        )
        .run(
          Buffer.alloc(16, 0x11),
          Buffer.alloc(16, 0x22),
          Buffer.from("disposable pre-upgrade encrypted-envelope fixture"),
        );
    inspectDatabase(path, false);
    for (const table of [
      "organization_grants",
      "organization_access_requests",
      "organization_auth_drafts",
      "organization_auth_draft_receipts",
      "organization_auth_draft_tests",
    ]) {
      database.exec(`CREATE TABLE ${table} (id BLOB PRIMARY KEY)`);
      assert.throws(() => inspectDatabase(path, false), {
        code: "ERR_ASSERTION",
      });
      database.exec(`DROP TABLE ${table}`);
    }
    for (const name of names.filter((name) => Number(name.slice(0, 14)) > old))
      await applyMigration(name);
    inspectDatabase(path, true);
    for (const table of [
      "organization_grants",
      "organization_access_requests",
      "organization_auth_drafts",
      "organization_auth_draft_receipts",
      "organization_auth_draft_tests",
      "account_browser_families",
      "organization_user_ca_krl_activation",
    ]) {
      database.exec(`ALTER TABLE ${table} RENAME TO missing_recovery_table`);
      assert.throws(() => inspectDatabase(path, true), {
        code: "ERR_ASSERTION",
      });
      database.exec(`ALTER TABLE missing_recovery_table RENAME TO ${table}`);
    }
    inspectDatabase(path, true);
  } finally {
    database.close();
    await rm(directory, { recursive: true, force: true });
  }
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
    "daily archive volume preparation",
    "daily source preparation",
    "daily API-only restart",
    "daily API-only scheduling check",
    "daily Device write preparation",
    "daily Worker ownership and renewal",
    "daily Worker events and maintenance",
    "daily Worker same-day restart",
    "daily archive verification and restoration",
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
