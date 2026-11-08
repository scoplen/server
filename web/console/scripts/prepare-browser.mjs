// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import process from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { constants } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { revision } from "../../../scripts/sync-console-contract.mjs";

const execute = promisify(execFile);
const root = fileURLToPath(new URL("../.browser/", import.meta.url));
const destination = join(root, "pkg");
const files = [
  "package.json",
  "scoplen_browser.d.ts",
  "scoplen_browser.js",
  "scoplen_browser_bg.wasm",
  "scoplen_browser_bg.wasm.d.ts",
];
if (!/^[0-9a-f]{40}$/.test(revision))
  throw new Error("browser source must use an exact published revision");

export async function verifyBrowserPackage(directory) {
  const metadata = JSON.parse(
    await readFile(join(directory, "build.json"), "utf8"),
  );
  if (
    metadata.rust !== "1.99.0" ||
    metadata.target !== "wasm32-unknown-unknown" ||
    metadata.wasmBindgen !== "0.2.129" ||
    metadata.sourceKind !== "archive" ||
    metadata.sourceRevision !== revision ||
    metadata.sourceDirty !== null ||
    !metadata.assets ||
    Object.keys(metadata.assets).sort().join() !== [...files].sort().join()
  )
    throw new Error(
      "browser package provenance or tool pins differ from the published source pin",
    );
  if (
    (await readdir(directory)).sort().join() !==
    [...files, "build.json"].sort().join()
  )
    throw new Error("browser package contains unexpected assets");
  for (const filename of files) {
    const path = join(directory, filename);
    const stat = await lstat(path);
    const data = await readFile(path);
    const expected = metadata.assets[filename];
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      !Number.isSafeInteger(expected.bytes) ||
      expected.bytes < 1 ||
      expected.bytes !== data.length ||
      !/^[0-9a-f]{64}$/.test(expected.sha256) ||
      createHash("sha256").update(data).digest("hex") !== expected.sha256 ||
      data.length > (filename.endsWith(".wasm") ? 8 : 2) * 1024 * 1024
    )
      throw new Error(`browser package asset integrity failed: ${filename}`);
  }
  const manifest = JSON.parse(
    await readFile(join(directory, "package.json"), "utf8"),
  );
  if (manifest.name !== "@scoplen/browser" || manifest.private !== true)
    throw new Error("unexpected shared browser package identity");
}

export async function stageCargoConfiguration(source, config) {
  if (!config) return;
  await mkdir(join(source, ".cargo"), { recursive: true });
  await copyFile(
    resolve(config),
    join(source, ".cargo", "config.toml"),
    constants.COPYFILE_EXCL,
  );
}

async function prepareBrowser() {
  try {
    await verifyBrowserPackage(destination);
    console.log(`verified shared browser source ${revision}`);
  } catch (error) {
    if (process.argv.includes("--check"))
      throw new Error(
        "Shared browser artifacts are missing or invalid. Run pnpm --dir web/console prepare:browser using Rust 1.99.0, target wasm32-unknown-unknown and wasm-bindgen-cli 0.2.129.",
        { cause: error },
      );
    await mkdir(root, { recursive: true });
    const temporary = await mkdtemp(join(root, "source-"));
    const absolute = resolve(temporary);
    if (
      dirname(absolute) !== resolve(root) ||
      !basename(absolute).startsWith("source-") ||
      !absolute.startsWith(resolve(root) + sep)
    )
      throw new Error(
        "refusing cleanup outside the temporary browser-source directory",
      );
    try {
      const response = await globalThis.fetch(
        `https://codeload.github.com/scoplen/proto/tar.gz/${revision}`,
        { redirect: "error", signal: globalThis.AbortSignal.timeout(120_000) },
      );
      if (!response.ok || !response.body)
        throw new Error(
          "could not download the pinned published browser source archive",
        );
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 64 * 1024 * 1024)
          throw new Error(
            "published browser source archive exceeds its download limit",
          );
        chunks.push(chunk);
      }
      const archive = join(temporary, "source.tar.gz");
      await writeFile(archive, Buffer.concat(chunks));
      const { stdout } = await execute("tar", ["-tzf", archive], {
        maxBuffer: 8 * 1024 * 1024,
      });
      const prefix = `proto-${revision}/`;
      if (
        stdout
          .split(/\r?\n/)
          .filter(Boolean)
          .some(
            (path) =>
              !path.startsWith(prefix) ||
              path.includes("\\") ||
              path.split("/").includes(".."),
          )
      )
        throw new Error("invalid source archive paths");
      await execute("tar", ["-xzf", archive, "-C", temporary]);
      const source = join(temporary, `proto-${revision}`);
      await stageCargoConfiguration(
        source,
        process.env.SCOPLEN_BROWSER_CARGO_CONFIG,
      );
      const { stdout: built, stderr } = await execute(
        process.execPath,
        ["scripts/build-browser.mjs", "--source-revision", revision],
        { cwd: source, env: process.env, maxBuffer: 8 * 1024 * 1024 },
      );
      if (built) process.stdout.write(built);
      if (stderr) process.stderr.write(stderr);
      const pkg = join(source, "crates", "scoplen-browser", "pkg");
      await verifyBrowserPackage(pkg);
      await mkdir(destination, { recursive: true });
      for (const filename of [...files, "build.json"])
        await copyFile(join(pkg, filename), join(destination, filename));
      await copyFile(join(source, "LICENSE"), join(root, "LICENSE"));
      await verifyBrowserPackage(destination);
      console.log(`prepared shared browser source ${revision}`);
    } finally {
      await rm(absolute, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await prepareBrowser();
