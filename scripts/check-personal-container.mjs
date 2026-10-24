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
  "non-root Compose startup and trusted HTTPS",
  "bundled console assets",
  "single public setup, fresh Passkey login and invitation",
  "restart and persistent setup/key verification",
  "offline snapshot restore",
  "matching old image recovery",
  "owned-resource cleanup",
  "failed-check cleanup",
]);

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

async function request(origin, path, ca, servername = "localhost") {
  return await new Promise((accept, reject) => {
    const outgoing = https.get(
      new URL(path, origin),
      { ca, servername, rejectUnauthorized: true, family: 4, timeout: 5000 },
      (incoming) => {
        const chunks = [];
        let size = 0;
        incoming.on("data", (chunk) => {
          size += chunk.length;
          if (size > 2 * 1024 * 1024)
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

export async function checkPersonalContainer(driverPath) {
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
    } = {},
  ) {
    const log = join(
      directory,
      `${String(++sequence).padStart(3, "0")}-${basename(program).replace(/[^A-Za-z0-9.-]/g, "_")}`,
    );
    const result = await new Promise((accept) => {
      execFile(
        program,
        args,
        {
          cwd: repository,
          env: environment,
          timeout,
          windowsHide: true,
          encoding: binary ? "buffer" : "utf8",
          maxBuffer: 32 * 1024 * 1024,
        },
        (error, stdout, stderr) => accept({ error, stdout, stderr }),
      );
    });
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
    probeImage = dockerfile.match(
      /^FROM (node:[^\s]+@sha256:[a-f0-9]{64}) AS console-build\r?$/m,
    )?.[1];
    assert(probeImage, "pinned console Node stage missing");
    const socket = net.createServer();
    const port = await new Promise((accept, reject) => {
      socket.once("error", reject);
      socket.listen(0, "127.0.0.1", () => {
        const value = socket.address().port;
        socket.close((error) => (error ? reject(error) : accept(value)));
      });
    });
    await command(driver, ["prepare", fixture, "--port", String(port)]);
    const ca = await readFile(join(fixture, "ca.pem"));
    const origin = `https://localhost:${port}`;
    const environment = {
      ...process.env,
      SCOPLEN_SERVER_HOST: "localhost",
      SCOPLEN_HTTPS_PORT: String(port),
      SCOPLEN_BIND_ADDRESS: "127.0.0.1",
      SCOPLEN_TLS_DIRECTORY: join(fixture, "tls").replaceAll("\\", "/"),
    };
    const emptyEnv = join(directory, "compose.env");
    const override = join(directory, "compose.override.json");
    await writeFile(emptyEnv, "", { flag: "wx", mode: 0o600 });
    const overrideContent = (selectedImage) =>
      JSON.stringify({
        services: {
          server: { image: selectedImage, labels: { [ownerLabel]: run } },
        },
        volumes: { data: { labels: { [ownerLabel]: run } } },
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
    const build = await docker(
      [
        "build",
        "--label",
        `${ownerLabel}=${run}`,
        "--tag",
        image,
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
      const holderLogs = (await docker(["logs", walHolderId])).stdout;
      if (holderLogs.trim() === "ready") break;
      assert(
        (await inspect("container", walHolderId)).State.Running,
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
    await docker(["stop", "--time", "30", walHolderId]);
    assert.equal((await inspect("container", walHolderId)).State.ExitCode, 0);

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
      assert(
        /^(index\.html|assets\/[A-Za-z0-9_.-]+\.(js|css|woff2))$/.test(
          asset.path,
        ),
      );
      const response = await request(
        origin,
        asset.path === "index.html" ? "/" : `/${asset.path}`,
        ca,
      );
      assert.equal(response.status, 200);
      assert.equal(response.body.length, asset.bytes);
      const contentTypes = {
        html: "text/html; charset=utf-8",
        js: "text/javascript; charset=utf-8",
        css: "text/css; charset=utf-8",
        woff2: "font/woff2",
      };
      assert.equal(
        response.headers["content-type"],
        contentTypes[asset.path.split(".").at(-1)],
      );
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
    ])
      assert(
        (await readFile(join(directory, "licenses", `${name}.txt`))).length > 0,
      );

    progress("single public setup, fresh Passkey login and invitation");
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
    assert(descriptor.invitation_url.startsWith(`${origin}/invite#token=`));
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

    progress("restart and persistent setup/key verification");
    await compose(["stop", "server"]);
    assert.equal((await inspect("container", container)).State.ExitCode, 0);
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
      ["exec", "-T", "server", "/app/splctl", "bootstrap", "--reissue-pending"],
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
          ].includes(item.Name),
          "unexpected owned container",
        );
        assert(
          [imageId, historicalImageId, probeImageId].includes(item.Image),
          "owned container changed images",
        );
        if (item.State.Running) await docker(["stop", "--time", "30", id]);
        if (succeeded) await docker(["container", "rm", id]);
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
    "Personal container check passed: production build, trusted HTTPS, console, public bootstrap, restart, SQLite upgrade and matching old image recovery.",
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const arguments_ = process.argv.slice(2);
  if (arguments_.length !== 2 || arguments_[0] !== "--bootstrap-driver") {
    console.error(
      "usage: node scripts/check-personal-container.mjs --bootstrap-driver <native-personal_live_bootstrap>",
    );
    process.exitCode = 1;
  } else {
    try {
      await checkPersonalContainer(arguments_[1]);
    } catch {
      console.error(
        "Personal container check failed; private command output was not printed.",
      );
      process.exitCode = 1;
    }
  }
}
