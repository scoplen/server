// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  assertOwnedFixture,
  assertOwnedResource,
  assertPrivateDirectoryArchive,
} from "./check-personal-container.mjs";

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
  assert.throws(() => assertPrivateDirectoryArchive(publicMode));
  const rootOwned = Buffer.from(archive);
  rootOwned.write("0000000", 108);
  assert.throws(() => assertPrivateDirectoryArchive(rootOwned));
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
