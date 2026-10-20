// SPDX-License-Identifier: Apache-2.0
// Check every mounted /api/v1 route in the server source tree against the
// authored OpenAPI contract and the explicit control-plane route manifest.
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const defaultManifest = join(repositoryRoot, "scripts/control-plane-routes.json");
const defaultSourceRoot = join(repositoryRoot, "crates/scoplen-server/src");
const methods = /^(get|post|patch|delete|put)$/;

async function* rustSources(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* rustSources(path);
    else if (entry.isFile() && entry.name.endsWith(".rs")) yield path;
  }
}

export async function checkControlPlaneRoutes(contractPath, manifestPath = defaultManifest, sourceRoot = defaultSourceRoot) {
  const contract = JSON.parse(await readFile(resolve(contractPath), "utf8"));
  const manifest = JSON.parse(await readFile(resolve(manifestPath), "utf8"));
  if (contract.openapi !== "3.1.0") throw new Error("the control-plane contract is not OpenAPI 3.1");
  if (!Array.isArray(manifest)) throw new Error("the route manifest must be an array");

  const expected = new Set();
  for (const entry of manifest) {
    if (!entry || typeof entry.path !== "string" || typeof entry.method !== "string") {
      throw new Error("route manifest entries require string path and method");
    }
    const method = entry.method.toLowerCase();
    if (!methods.test(method)) throw new Error(`unsupported route method: ${entry.method}`);
    if (!contract.paths?.[entry.path]?.[method]) {
      throw new Error(`route is missing from OpenAPI: ${method.toUpperCase()} ${entry.path}`);
    }
    const key = `${method.toUpperCase()} ${entry.path}`;
    if (expected.has(key)) throw new Error(`duplicate control-plane manifest route: ${key}`);
    expected.add(key);
  }

  const mounted = new Set();
  for await (const sourcePath of rustSources(sourceRoot)) {
    const source = await readFile(sourcePath, "utf8");
    for (const match of source.matchAll(/\.route\(\s*["'](\/api\/v1\/[^"']+)["']\s*,\s*/g)) {
      const [, absolutePath] = match;
      const route = source.slice(match.index + match[0].length);
      const method = route.match(/^(?:(?:axum::)?routing::)?(get|post|patch|delete|put)\s*\(/)?.[1];
      if (!method) throw new Error(`could not determine method for mounted route ${absolutePath} in ${sourcePath}`);
      const key = `${method.toUpperCase()} ${absolutePath.slice("/api/v1".length)}`;
      if (!expected.has(key)) throw new Error(`mounted route is absent from control-plane manifest: ${key}`);
      mounted.add(key);
    }
  }
  for (const key of expected) {
    if (!mounted.has(key)) throw new Error(`control-plane manifest route is not mounted: ${key}`);
  }
  return mounted.size;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [contractPath, manifestPath] = process.argv.slice(2);
  if (!contractPath) throw new Error("usage: node check-control-plane-routes.mjs <openapi-json-yaml> [manifest]");
  const count = await checkControlPlaneRoutes(contractPath, manifestPath);
  console.log(`validated ${count} mounted control-plane routes against OpenAPI 3.1`);
}
