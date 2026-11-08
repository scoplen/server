// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import {
  stageCargoConfiguration,
  verifyBrowserPackage,
} from "./prepare-browser.mjs";
import { revision } from "../../../scripts/sync-console-contract.mjs";

async function fixture(action) {
  const path = await mkdtemp(join(tmpdir(), "scoplen-browser-package-"));
  try {
    await action(path);
  } finally {
    assert.equal(dirname(resolve(path)), resolve(tmpdir()));
    assert.ok(basename(path).startsWith("scoplen-browser-package-"));
    await rm(path, { recursive: true, force: true });
  }
}
async function packageFixture(path) {
  const assets = {};
  for (const name of [
    "package.json",
    "scoplen_browser.d.ts",
    "scoplen_browser.js",
    "scoplen_browser_bg.wasm",
    "scoplen_browser_bg.wasm.d.ts",
  ]) {
    const data = Buffer.from(
      name === "package.json"
        ? JSON.stringify({ name: "@scoplen/browser", private: true })
        : "boundary fixture",
    );
    await writeFile(join(path, name), data);
    assets[name] = {
      bytes: data.length,
      sha256: createHash("sha256").update(data).digest("hex"),
    };
  }
  const metadata = {
    rust: "1.99.0",
    target: "wasm32-unknown-unknown",
    wasmBindgen: "0.2.129",
    sourceKind: "archive",
    sourceRevision: revision,
    sourceDirty: null,
    assets,
  };
  await writeFile(join(path, "build.json"), JSON.stringify(metadata));
  return metadata;
}

test("consumer refuses wrong source/tool provenance, changed assets and unexpected package files", async () => {
  await fixture(async (path) => {
    const metadata = await packageFixture(path);
    await verifyBrowserPackage(path);
    for (const change of [
      { sourceRevision: "0".repeat(40) },
      { sourceKind: "git" },
      { sourceDirty: false },
      { wasmBindgen: "0.2.128" },
      { rust: "1.98.0" },
    ]) {
      await writeFile(
        join(path, "build.json"),
        JSON.stringify({ ...metadata, ...change }),
      );
      await assert.rejects(verifyBrowserPackage(path));
    }
    await writeFile(join(path, "build.json"), JSON.stringify(metadata));
    await writeFile(join(path, "scoplen_browser.js"), "changed bytes");
    await assert.rejects(verifyBrowserPackage(path), /integrity/);
    await packageFixture(path);
    await writeFile(join(path, "unexpected.js"), "extra file");
    await assert.rejects(verifyBrowserPackage(path), /unexpected assets/);
  });
});

test("optional custom Cargo configuration is copied exactly and never overwrites authored configuration", async () => {
  await fixture(async (path) => {
    const source = join(path, "source");
    await mkdir(source);
    await stageCargoConfiguration(source, undefined);
    await assert.rejects(readFile(join(source, ".cargo", "config.toml")), {
      code: "ENOENT",
    });
    const config = join(path, "custom.toml");
    const contents = "[build]\njobs = 1\n# fixture-owned wrapper settings\n";
    await writeFile(config, contents);
    await stageCargoConfiguration(source, config);
    assert.equal(
      await readFile(join(source, ".cargo", "config.toml"), "utf8"),
      contents,
    );
    await writeFile(config, "changed input");
    await assert.rejects(stageCargoConfiguration(source, config), {
      code: "EEXIST",
    });
    assert.equal(
      await readFile(join(source, ".cargo", "config.toml"), "utf8"),
      contents,
    );
  });
});
