// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import {
  link,
  lstat,
  mkdir,
  readFile,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const marker = "Owned concurrent publisher; preserve these bytes.\n";

export async function publicationMarker(directory, slot, operation) {
  assert(/^\d{4}-\d{2}-\d{2}$/.test(slot));
  assert((await lstat(directory)).isDirectory());
  const archive = join(directory, `scoplen-${slot}.age`);
  const otherStage = join(
    directory,
    ".scoplen-backup-00000000-0000-4000-8000-000000000001",
  );
  const retained = join(otherStage, "marker");
  if (operation === "publish") {
    await mkdir(otherStage, { mode: 0o700 });
    await writeFile(retained, marker, { flag: "wx", mode: 0o600 });
    await link(retained, archive);
    return;
  }
  assert((await lstat(otherStage)).isDirectory());
  const source = await lstat(retained, { bigint: true });
  assert(source.isFile());
  assert(
    (await readFile(retained, "utf8")) === marker,
    "retained marker changed",
  );
  const actual = await lstat(archive, { bigint: true });
  assert(actual.isFile());
  if (operation === "withdraw") {
    assert(
      source.dev === actual.dev && source.ino === actual.ino,
      "refusing to withdraw an unrelated file",
    );
    await unlink(archive);
  } else {
    assert.equal(operation, "check-recovered");
    assert(
      source.dev !== actual.dev || source.ino !== actual.ino,
      "retry did not publish a new file",
    );
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await publicationMarker(
    "/recovery/archives",
    process.argv[2],
    process.argv[3],
  );
}
