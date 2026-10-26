// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { checkControlPlaneRoutes } from "./check-control-plane-routes.mjs";

test("CI checks routes against the server's pinned API contract", async () => {
  const manifest = await readFile(new URL("../crates/scoplen-server/Cargo.toml", import.meta.url), "utf8");
  const workflow = await readFile(new URL("../.github/workflows/check.yml", import.meta.url), "utf8");
  const revision = manifest.match(/^scoplen-api = \{ git = "https:\/\/github\.com\/scoplen\/proto\.git", rev = "([a-f0-9]{40})" \}$/m)?.[1];
  const checkedRevision = workflow.match(/repository: scoplen\/proto\r?\n\s+ref: ([a-f0-9]{40})\r?\n\s+path: proto/)?.[1];
  assert.ok(revision, "the server must pin its public API dependency");
  assert.equal(checkedRevision, revision, "CI must validate the same API contract the server consumes");
});

test("nested server module routes require a manifest and OpenAPI entry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scoplen-route-check-"));
  try {
    const sourceRoot = join(directory, "src");
    const nestedRoot = join(sourceRoot, "auth");
    await mkdir(nestedRoot, { recursive: true });
    await writeFile(
      join(nestedRoot, "enrollment.rs"),
      'Router::new().route("/api/v1/auth/personal-enroll", post(enroll))',
    );
    const contractPath = join(directory, "contract.json");
    const manifestPath = join(directory, "manifest.json");
    await writeFile(contractPath, JSON.stringify({
      openapi: "3.1.0",
      paths: { "/auth/personal-enroll": { post: {} } },
    }));
    await writeFile(manifestPath, "[]");
    await assert.rejects(
      checkControlPlaneRoutes(contractPath, manifestPath, sourceRoot),
      /mounted route is absent from control-plane manifest: POST \/auth\/personal-enroll/,
    );
    await writeFile(manifestPath, JSON.stringify([{ method: "POST", path: "/auth/personal-enroll" }]));
    assert.equal(await checkControlPlaneRoutes(contractPath, manifestPath, sourceRoot), 1);
    await writeFile(contractPath, JSON.stringify({ openapi: "3.1.0", paths: {} }));
    await assert.rejects(
      checkControlPlaneRoutes(contractPath, manifestPath, sourceRoot),
      /route is missing from OpenAPI: POST \/auth\/personal-enroll/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("public key discovery is checked outside the API prefix", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scoplen-jwks-route-check-"));
  try {
    const sourceRoot = join(directory, "src");
    await mkdir(sourceRoot);
    await writeFile(join(sourceRoot, "auth.rs"), 'Router::new().route("/.well-known/jwks.json", get(jwks))');
    const contractPath = join(directory, "contract.json");
    const manifestPath = join(directory, "manifest.json");
    await writeFile(contractPath, JSON.stringify({
      openapi: "3.1.0",
      paths: { "/.well-known/jwks.json": { get: {} } },
    }));
    await writeFile(manifestPath, "[]");
    await assert.rejects(
      checkControlPlaneRoutes(contractPath, manifestPath, sourceRoot),
      /mounted route is absent from control-plane manifest: GET \/\.well-known\/jwks\.json/,
    );
    await writeFile(manifestPath, JSON.stringify([{ method: "GET", path: "/.well-known/jwks.json" }]));
    assert.equal(await checkControlPlaneRoutes(contractPath, manifestPath, sourceRoot), 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
