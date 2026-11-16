// SPDX-License-Identifier: AGPL-3.0-only
// Consumes only synthetic artifacts exported by the real verified-TLS Rust tests.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstat, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const [input, ...extra] = process.argv.slice(2);
assert(input && extra.length === 0, "usage: node scripts/check-user-ca-krl.mjs <exported-fixture-directory>");
const directory = await realpath(resolve(input));
assert(!directory.includes(","), "fixture directory cannot contain a comma");
const names = [
  "subject-key", "personal-key", "personal.pub", "trusted-ca.pub", "principals",
  "empty.krl", "revoked.krl", "old-cert.pub", "fresh-cert.pub",
  "other-member-cert.pub", "other-team-cert.pub",
];
assert.deepEqual((await readdir(directory)).sort(), names.toSorted());
for (const name of names) {
  const metadata = await lstat(join(directory, name));
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1);
  assert(metadata.size > 0 && metadata.size <= 4 * 1024 * 1024);
}
const identity = randomUUID();
const container = `scoplen-krl-acceptance-${identity}`;
const image = `scoplen-krl-acceptance:${identity}`;
const label = "com.scoplen.krl-acceptance";
const scripts = fileURLToPath(new URL("./", import.meta.url));
let imageOwned = false;
let containerOwned = false;
async function docker(args) {
  return execute("docker", args, { timeout: 300_000, maxBuffer: 1024 * 1024, windowsHide: true });
}
async function owned(kind, name) {
  const { stdout } = await docker([kind, "inspect", "--format", `{{index .Config.Labels "${label}"}}`, name]);
  assert.equal(stdout.trim(), identity, "refusing cleanup of an unowned Docker resource");
}
try {
  await docker(["build", "--label", `${label}=${identity}`, "--tag", image,
    "--file", join(scripts, "Dockerfile.krl-acceptance"), scripts]);
  imageOwned = true;
  await docker(["create", "--name", container, "--label", `${label}=${identity}`,
    "--network", "none", "--read-only", "--tmpfs", "/run:rw,nosuid,nodev,size=16m,mode=755",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
    "--mount", `type=bind,source=${directory},target=/fixture,readonly`, image]);
  containerOwned = true;
  const { stdout } = await docker(["start", "--attach", container]);
  const { stdout: state } = await docker(["inspect", "--format", "{{.State.ExitCode}}", container]);
  assert.equal(state.trim(), "0", "owned OpenSSH acceptance failed");
  process.stdout.write(stdout);
} catch {
  process.stderr.write("Owned KRL OpenSSH acceptance failed; no existing services were used.\n");
  process.exitCode = 1;
} finally {
  if (containerOwned) {
    await owned("container", container);
    await docker(["rm", "--force", container]);
  }
  if (imageOwned) {
    await owned("image", image);
    await docker(["image", "rm", image]);
  }
}
