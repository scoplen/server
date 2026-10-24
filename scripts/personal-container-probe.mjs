// SPDX-License-Identifier: AGPL-3.0-only
// Runs in the pinned build-stage Node image, never in the production runtime.
import assert from "node:assert/strict";
import {
  chownSync,
  chmodSync,
  constants,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";

const [operation, run] = process.argv.slice(2);
assert(
  /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(run),
  "invalid check identity",
);
const certificateNames = ["fullchain.pem", "private-key.pem"];

if (operation === "check-data") {
  const root = "/var/lib/spl";
  const metadata = statSync(root);
  assert.equal(metadata.uid, 65532);
  assert.equal(metadata.gid, 65532);
  assert.equal(metadata.mode & 0o7777, 0o700);
  const path = `${root}/.container-check-${run}`;
  writeFileSync(path, run, { flag: "wx", mode: 0o600 });
  assert.equal(readFileSync(path, "utf8"), run);
  unlinkSync(path);
} else {
  assert.equal(readFileSync("/check/.container-check-owner", "utf8"), run);
  assert.equal(realpathSync("/check/fixture"), "/check/fixture");
  const root = "/check/fixture/tls";
  if (operation === "prepare-tls") {
    mkdirSync(root, { mode: 0o700 });
    for (const [source, destination] of [
      ["localhost.pem", certificateNames[0]],
      ["localhost-key.pem", certificateNames[1]],
    ]) {
      const original = lstatSync(`/check/fixture/${source}`);
      assert(original.isFile() && original.nlink === 1);
      const path = `${root}/${destination}`;
      copyFileSync(`/check/fixture/${source}`, path, constants.COPYFILE_EXCL);
      chownSync(path, 65532, 65532);
      chmodSync(path, 0o400);
    }
    chownSync(root, 65532, 65532);
    chmodSync(root, 0o500);
  } else {
    assert.equal(operation, "release-tls", "unknown container probe");
    assert.equal(realpathSync(root), root);
    assert(lstatSync(root).isDirectory());
    assert.deepEqual(readdirSync(root).sort(), certificateNames.sort());
    const owner = statSync("/check");
    for (const name of certificateNames) {
      const path = `${root}/${name}`;
      const metadata = lstatSync(path);
      assert(metadata.isFile() && metadata.nlink === 1);
      chownSync(path, owner.uid, owner.gid);
      chmodSync(path, 0o600);
    }
    chownSync(root, owner.uid, owner.gid);
    chmodSync(root, 0o700);
  }
}
