// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
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
  const project = `scoplen-personal-${run}`;
  const image = `scoplen-server:personal-check-${run}`;
  const inspector = `${project}-image`;
  let sequence = 0;
  let phase = "preflight";
  let succeeded = false;
  let imageId;
  let probeImage;
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
    await writeFile(`${log}.stdout`, result.stdout, {
      flag: "wx",
      mode: 0o600,
    });
    await writeFile(`${log}.stderr`, result.stderr, {
      flag: "wx",
      mode: 0o600,
    });
    if (result.error && !allowFailure)
      throw new Error(`${basename(program)} failed during ${phase}`);
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
  function progress(next) {
    phase = next;
    console.log(`Personal container check: ${phase}`);
  }

  try {
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
    await writeFile(
      override,
      JSON.stringify({
        services: { server: { image, labels: { [ownerLabel]: run } } },
        volumes: { data: { labels: { [ownerLabel]: run } } },
        networks: { default: { labels: { [ownerLabel]: run } } },
      }),
      { flag: "wx", mode: 0o600 },
    );
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

    progress("production image build");
    await docker(
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
      { timeout: 3_600_000 },
    );
    const built = await inspect("image", image);
    assertOwnedResource(built.Config.Labels, run);
    imageId = built.Id;
    assert.equal(built.Config.User, "65532:65532", "runtime must be non-root");
    assert.equal(
      built.Config.StopSignal,
      "SIGINT",
      "runtime must use the supervisor's shutdown signal",
    );
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
    await docker(["pull", probeImage], { timeout: 300_000 });
    const fixtureMount = [
      "--mount",
      `type=bind,source=${directory},target=/check`,
    ];
    await nodeProbe("prepare-tls", fixtureMount);
    certificatePrepared = true;

    progress("non-root Compose startup and trusted HTTPS");
    await compose(["up", "--detach", "--no-build"]);
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
    const serverLog = join(fixture, "server.log");
    await writeFile(serverLog, logs.stdout, { flag: "wx", mode: 0o600 });
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
    succeeded = true;
  } catch (error) {
    await writeFile(
      join(directory, "failure.txt"),
      `${phase}\n${error.stack}\n`,
      { flag: "wx", mode: 0o600 },
    );
    throw error;
  } finally {
    progress(
      succeeded
        ? "owned-resource cleanup"
        : `stopping failed check after ${phase}`,
    );
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
          item.Name === `/${inspector}` ? undefined : project,
        );
        assert(
          item.Name === `/${inspector}` || item.Name === `/${project}-server-1`,
          "unexpected owned container",
        );
        assert.equal(item.Image, imageId, "owned container changed images");
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
        const item = await inspect("image", image);
        assertOwnedResource(item.Config.Labels, run);
        assert.equal(item.Id, imageId);
        await docker(["image", "rm", image]);
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
      await writeFile(
        join(directory, "cleanup-failure.txt"),
        `${error.stack}\n`,
        { flag: "wx", mode: 0o600 },
      );
      console.error(
        `Cleanup stopped; private diagnostics and remaining test resources retained: ${directory}`,
      );
      throw error;
    }
  }
  console.log(
    "Personal container check passed: production build, trusted HTTPS, console, public bootstrap and persistent restart.",
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
