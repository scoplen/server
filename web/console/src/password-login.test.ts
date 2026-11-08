// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { afterEach, mock, test } from "node:test";
import { AccountFailure } from "./account-http.ts";
import { AccountProofKey } from "./account-proof.ts";
import { performPasswordLogin } from "./password-login.ts";
import { PasswordWorkerLogin } from "./password-worker-client.ts";
import { bytes, encoded } from "./wire.ts";

const origin = "https://console.example";
const username = "qa.owner";
const password = () => new TextEncoder().encode("password boundary fixture");
const session = {
  access_token: `ab1_${encoded(new Uint8Array(32))}`,
  token_type: "DPoP",
  expires_in: 600,
  refresh_expires_in: 2_592_000,
};
const options = () => ({
  profile: 1,
  salt: encoded(new Uint8Array(16)),
  attempt_id: encoded(new Uint8Array(32)),
  expires_at_ms: String(Date.now() + 120_000),
});
function response(value: unknown) {
  return new Response(JSON.stringify(value), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      "X-Request-ID": "fixture-request",
    },
  });
}
afterEach(() => mock.restoreAll());

test("Worker exchange sends only existing options/auth-secret wire and returns no password-derived fields", async () => {
  const requests: {
    path: string;
    body: Record<string, unknown>;
    credentials?: RequestCredentials;
    header: Record<string, unknown>;
  }[] = [];
  mock.method(
    globalThis,
    "fetch",
    async (url: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      const proof = new Headers(init?.headers).get("DPoP")!;
      const header = JSON.parse(
        new TextDecoder().decode(bytes(proof.split(".")[0], 1, 2048)),
      );
      const claims = JSON.parse(
        new TextDecoder().decode(bytes(proof.split(".")[1], 1, 2048)),
      );
      assert.equal(claims.ath, undefined);
      assert.equal(claims.htm, "POST");
      assert.equal(claims.htu, origin + path);
      requests.push({
        path,
        body: JSON.parse(String(init?.body)),
        credentials: init?.credentials,
        header,
      });
      return response(path.endsWith("options") ? options() : session);
    },
  );
  const owned = password();
  let auth: Uint8Array | undefined;
  // Deterministic derivation boundary fake: this test does not claim a Rust/WASM KAT.
  const result = await performPasswordLogin(
    origin,
    username,
    owned,
    async (o, u, profile, salt, input, output) => {
      assert.equal(o, origin);
      assert.equal(u, username);
      assert.equal(profile, 1);
      assert.equal(salt.length, 16);
      assert.deepEqual(input, password());
      auth = output;
      output.fill(7);
    },
  );
  assert.deepEqual(
    requests.map((request) => request.credentials),
    ["omit", "same-origin"],
  );
  assert.deepEqual(requests[0].body, { username });
  assert.deepEqual(requests[1].body, {
    attempt_id: encoded(new Uint8Array(32)),
    auth_secret: encoded(new Uint8Array(32).fill(7)),
  });
  assert.deepEqual(requests[0].header.jwk, requests[1].header.jwk);
  assert.deepEqual(Object.keys(result).sort(), [
    "keyPair",
    "publicJwk",
    "session",
    "startedAt",
  ]);
  assert.deepEqual(result.session, session);
  assert.equal(result.keyPair.privateKey.extractable, false);
  assert.ok(owned.every((value) => value === 0));
  assert.ok(auth?.every((value) => value === 0));
});

test("derivation failure erases owned input/output and never submits password login", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () => {
    calls++;
    return response(options());
  });
  const owned = password();
  let auth: Uint8Array | undefined;
  await assert.rejects(
    performPasswordLogin(
      origin,
      username,
      owned,
      async (_o, _u, _p, _s, _input, output) => {
        auth = output;
        output.fill(8);
        throw new Error("allocation failure");
      },
    ),
    (error: unknown) =>
      error instanceof AccountFailure &&
      error.code === "password_derivation_failed" &&
      !error.changed,
  );
  assert.equal(calls, 1);
  assert.ok(owned.every((value) => value === 0));
  assert.ok(auth?.every((value) => value === 0));
});

test("an expired options attempt is not submitted after a slow derivation", async () => {
  const now = Date.now();
  let current = now;
  mock.method(Date, "now", () => current);
  let calls = 0;
  mock.method(globalThis, "fetch", async () => {
    calls++;
    return response(options());
  });
  await assert.rejects(
    performPasswordLogin(origin, username, password(), async () => {
      current = now + 120_001;
    }),
    (error: unknown) =>
      error instanceof AccountFailure &&
      error.code === "password_attempt_expired" &&
      !error.changed,
  );
  assert.equal(calls, 1);
});

test("native-only login material is rejected after the login and does not escape the Worker exchange", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () =>
    response(
      ++calls === 1 ? options() : { ...session, snapshot: "native-bootstrap" },
    ),
  );
  await assert.rejects(
    performPasswordLogin(origin, username, password(), async () => {}),
    (error: unknown) =>
      error instanceof AccountFailure &&
      error.code === "invalid_response" &&
      error.changed,
  );
  assert.equal(calls, 2);
});

class WorkerBoundary {
  onmessage: Worker["onmessage"] = null;
  onerror: Worker["onerror"] = null;
  onmessageerror: Worker["onmessageerror"] = null;
  terminated = false;
  received?: { origin: string; username: string; password: Uint8Array };
  postMessage(value: unknown, transfer: Transferable[]) {
    this.received = structuredClone(value, { transfer }) as NonNullable<
      WorkerBoundary["received"]
    >;
  }
  terminate() {
    this.terminated = true;
  }
  reply(value: unknown) {
    this.onmessage?.call(
      this as unknown as Worker,
      { data: value } as MessageEvent,
    );
  }
}

test("one-use Worker bridge transfers a separate owned password and terminates after only a session/key result", async () => {
  const worker = new WorkerBoundary();
  const bridge = new PasswordWorkerLogin(() => worker as unknown as Worker);
  const owned = password();
  const result = bridge.run(
    origin,
    username,
    owned,
    new AbortController().signal,
  );
  assert.ok(owned.every((value) => value === 0));
  assert.deepEqual(worker.received?.password, password());
  const key = await AccountProofKey.create();
  worker.reply({
    ok: true,
    result: { ...key.transfer(), session, startedAt: Date.now() },
  });
  assert.equal((await result).keyPair.privateKey.extractable, false);
  assert.equal(worker.terminated, true);
});

test("Worker bridge rejects secret-bearing output and abort always terminates the Worker", async () => {
  const worker = new WorkerBoundary();
  const bridge = new PasswordWorkerLogin(() => worker as unknown as Worker);
  const first = bridge.run(
    origin,
    username,
    password(),
    new AbortController().signal,
  );
  worker.reply({
    ok: true,
    result: { session, startedAt: Date.now(), auth_secret: "must-not-return" },
  });
  await assert.rejects(
    first,
    (error: unknown) =>
      error instanceof AccountFailure && error.code === "invalid_response",
  );
  assert.equal(worker.terminated, true);
  const next = new WorkerBoundary(),
    controller = new AbortController();
  const pending = new PasswordWorkerLogin(() => next as unknown as Worker).run(
    origin,
    username,
    password(),
    controller.signal,
  );
  controller.abort();
  await assert.rejects(
    pending,
    (error: unknown) =>
      error instanceof AccountFailure && error.code === "session_changed",
  );
  assert.equal(next.terminated, true);
});
