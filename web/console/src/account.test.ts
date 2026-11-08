// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";
import { AccountClient, type PasswordLogin } from "./account.ts";
import { AccountProofKey } from "./account-proof.ts";
import { AccountFailure, accountFetch } from "./account-http.ts";
import { accountSession, passwordOptions } from "./account-wire.ts";
import { bytes, encoded } from "./wire.ts";

const origin = "https://console.example";
const org = "019a0000-0000-7000-8000-000000000001";
const access = (value: number) =>
  `ab1_${encoded(new Uint8Array(32).fill(value))}`;
const session = (value = 1, refresh = 2_592_000) => ({
  access_token: access(value),
  token_type: "DPoP",
  expires_in: 600,
  refresh_expires_in: refresh,
});
const requestId = "00000000-0000-4000-8000-000000000001";
function response(
  value: unknown,
  status = 200,
  headers: Record<string, string> = {},
) {
  return new Response(status === 204 ? null : JSON.stringify(value), {
    status,
    headers: {
      "Content-Type":
        status >= 400 ? "application/problem+json" : "application/json",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      "X-Request-ID": requestId,
      ...headers,
    },
  });
}
function rejected(code: string, changed: boolean) {
  return (error: unknown) =>
    error instanceof AccountFailure &&
    error.code === code &&
    error.changed === changed;
}
function problem(
  code: string,
  status: number,
  changed: boolean,
  retryable: boolean,
) {
  return response(
    {
      type: "about:blank",
      title: "Test failure",
      status,
      detail: "Boundary fixture",
      instance: requestId,
      code,
      changed,
      retryable,
    },
    status,
  );
}
const password = () =>
  new TextEncoder().encode("fifteen valid words and characters");
// This injected login boundary does not claim to execute the password Worker or Rust KDF.
function loginBoundary(key: AccountProofKey, value = 1): PasswordLogin {
  return {
    run: async () => ({
      ...key.transfer(),
      session: session(value),
      startedAt: Date.now(),
    }),
  };
}
beforeEach(() => {
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: {
      request: async (_name: string, action: () => Promise<void>) => action(),
    },
  });
});
afterEach(() => mock.restoreAll());

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

test("Account browser wire rejects native credentials, token aliases and incorrect fixed lifetimes", () => {
  assert.equal(accountSession(session(), true).access_token, access(1));
  assert.equal(accountSession(session(2, 1)).refresh_expires_in, 1);
  for (const name of ["refresh_token", "admission_token", "snapshot"])
    assert.throws(() => accountSession({ ...session(), [name]: "forbidden" }));
  for (const value of [
    "native",
    `ab1_${"A".repeat(42)}B`,
    `ar1_${"A".repeat(43)}`,
  ])
    assert.throws(() => accountSession({ ...session(), access_token: value }));
  for (const expires_in of [0, 599, 601, "600"])
    assert.throws(() => accountSession({ ...session(), expires_in }));
  for (const refresh_expires_in of [0, 2_592_001, 1.5, "2592000"])
    assert.throws(() => accountSession({ ...session(), refresh_expires_in }));
  assert.throws(() => accountSession(session(1, 1), true));
  const options = {
    profile: 1,
    attempt_id: encoded(new Uint8Array(32)),
    salt: encoded(new Uint8Array(16)),
    expires_at_ms: "18446744073709551615",
  };
  assert.equal(passwordOptions(options).expires_at_ms, options.expires_at_ms);
  for (const expires_at_ms of ["0", "01", "18446744073709551616", 1])
    assert.throws(() => passwordOptions({ ...options, expires_at_ms }));
  assert.throws(() => passwordOptions({ ...options, profile: 2 }));
});

test("transferred non-extractable P-256 keys sign actual methods, canonical query-free targets and token ath", async () => {
  const original = await AccountProofKey.create();
  const transferred = structuredClone(original.transfer());
  assert.equal(transferred.keyPair.privateKey.extractable, false);
  const key = await AccountProofKey.adopt(transferred);
  for (const method of ["GET", "PATCH", "DELETE"] as const) {
    const proof = await key.proof(
      origin,
      `/api/v1/orgs/${org}?limit=50`,
      method,
      access(1),
    );
    const [header, payload, signature] = proof.split(".");
    const head = JSON.parse(new TextDecoder().decode(bytes(header, 1, 2048)));
    const claims = JSON.parse(
      new TextDecoder().decode(bytes(payload, 1, 2048)),
    );
    assert.deepEqual(Object.keys(head.jwk).sort(), ["crv", "kty", "x", "y"]);
    assert.equal(claims.htm, method);
    assert.equal(claims.htu, `${origin}/api/v1/orgs/${org}`);
    assert.equal(
      claims.ath,
      encoded(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(access(1)),
        ),
      ),
    );
    assert.equal(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        transferred.keyPair.publicKey,
        bytes(signature, 64),
        new TextEncoder().encode(`${header}.${payload}`),
      ),
      true,
    );
  }
  const other = await AccountProofKey.create();
  await assert.rejects(
    AccountProofKey.adopt({
      ...transferred,
      publicJwk: other.transfer().publicJwk,
    }),
  );
  await assert.rejects(key.proof(`${origin}:443`, "/api/v1/orgs", "GET"));
  await assert.rejects(key.proof(origin, "//other.example/api/v1/orgs", "GET"));
  await assert.rejects(key.proof(origin, "/api/v1/orgs#fragment", "GET"));
});

test("HTTP boundary verifies all problem fields and cache metadata before accepting rollback semantics", async () => {
  const key = await AccountProofKey.create();
  let answer = problem("organization.precondition_failed", 412, false, false);
  mock.method(globalThis, "fetch", async () => answer);
  const run = () =>
    accountFetch({
      origin,
      key,
      method: "PATCH",
      path: `/api/v1/orgs/${org}`,
      operation: "request",
      token: access(1),
      options: { body: { data: { name: "new" } } },
    });
  await assert.rejects(
    run(),
    rejected("organization.precondition_failed", false),
  );
  answer = problem("organization.precondition_failed", 412, false, false);
  answer.headers.delete("Cache-Control");
  await assert.rejects(run(), rejected("invalid_response", true));
  answer = response(
    {
      status: 412,
      code: "organization.precondition_failed",
      changed: false,
      retryable: false,
    },
    412,
  );
  await assert.rejects(run(), rejected("invalid_response", true));
  answer = problem("organization.precondition_failed", 412, false, false);
  answer.headers.set("X-Request-ID", "untrusted request identifier");
  await assert.rejects(
    run(),
    (error: unknown) =>
      error instanceof AccountFailure &&
      error.changed &&
      error.requestId === "",
  );
  answer = response({ ok: true }, 200, { "Content-Encoding": "gzip" });
  await assert.rejects(run(), rejected("invalid_response", true));
});

test("Account public transport confines routes and omits cookies while signing each exact HTTP method", async () => {
  const key = await AccountProofKey.create();
  const client = new AccountClient(origin, loginBoundary(key));
  const owned = password();
  await client.signIn("qa.owner", owned);
  assert.ok(owned.every((value) => value === 0));
  let calls = 0;
  mock.method(
    globalThis,
    "fetch",
    async (url: RequestInfo | URL, init?: RequestInit) => {
      calls++;
      assert.equal(String(url), `${origin}/api/v1/orgs?limit=50`);
      assert.equal(init?.credentials, "omit");
      assert.equal(init?.method, "GET");
      assert.equal(init?.body, undefined);
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("Authorization"), `DPoP ${access(1)}`);
      const claims = JSON.parse(
        new TextDecoder().decode(
          bytes(headers.get("DPoP")!.split(".")[1], 1, 2048),
        ),
      );
      assert.equal(claims.htm, "GET");
      assert.equal(claims.htu, `${origin}/api/v1/orgs`);
      return response({ items: [], next_cursor: null });
    },
  );
  await client.request("GET", "/api/v1/orgs?limit=50");
  for (const path of [
    "/api/v1/accounts/me/devices",
    "/api/v1/auth/refresh",
    `/api/v1/orgs/${org}/certificate-authorities`,
    `/api/v1/orgs/${org}/credentials`,
  ])
    await assert.rejects(
      client.request("GET", path),
      rejected("route_not_available", false),
    );
  assert.equal(calls, 1);
});

test("same-tab actions serialize one cookie-only refresh through the Account Web Lock", async () => {
  const key = await AccountProofKey.create();
  const client = new AccountClient(origin, loginBoundary(key));
  await client.signIn("qa.owner", password());
  const now = Date.now();
  mock.method(Date, "now", () => now + 571_000);
  let locks = 0,
    refreshes = 0,
    reads = 0;
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: {
      request: async (name: string, action: () => Promise<void>) => {
        assert.equal(name, "scoplen-account-refresh");
        locks++;
        await action();
      },
    },
  });
  mock.method(
    globalThis,
    "fetch",
    async (url: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (String(url).endsWith("/browser/refresh")) {
        refreshes++;
        assert.equal(init?.credentials, "same-origin");
        assert.equal(init?.body, "{}");
        assert.equal(headers.get("Authorization"), null);
        const claims = JSON.parse(
          new TextDecoder().decode(
            bytes(headers.get("DPoP")!.split(".")[1], 1, 2048),
          ),
        );
        assert.equal(claims.ath, undefined);
        return response(session(2, 2_591_429));
      }
      reads++;
      assert.equal(init?.credentials, "omit");
      assert.equal(headers.get("Authorization"), `DPoP ${access(2)}`);
      return response({});
    },
  );
  await Promise.all([
    client.request("GET", "/api/v1/accounts/me"),
    client.request("GET", "/api/v1/accounts/me"),
  ]);
  assert.deepEqual(
    { locks, refreshes, reads },
    { locks: 1, refreshes: 1, reads: 2 },
  );
});

test("an unknown refresh drops the session and a new tab never refreshes a retained cookie", async () => {
  const key = await AccountProofKey.create();
  const client = new AccountClient(origin, loginBoundary(key));
  await client.signIn("qa.owner", password());
  const now = Date.now();
  mock.method(Date, "now", () => now + 571_000);
  let calls = 0;
  mock.method(globalThis, "fetch", async () => {
    calls++;
    throw new Error("lost");
  });
  await assert.rejects(
    client.request("GET", "/api/v1/accounts/me"),
    rejected("response_lost", true),
  );
  assert.equal(client.authenticated, false);
  assert.equal(client.reason, "refresh_sign_in_required");
  const fresh = new AccountClient(
    origin,
    loginBoundary(await AccountProofKey.create()),
  );
  await assert.rejects(
    fresh.request("GET", "/api/v1/accounts/me"),
    rejected("sign_in_required", false),
  );
  assert.equal(calls, 1);
});

test("unknown logout retains original credentials for explicit fresh-proof retry and blocks protected actions", async () => {
  const key = await AccountProofKey.create();
  const client = new AccountClient(origin, loginBoundary(key));
  await client.signIn("qa.owner", password());
  const proofs: string[] = [];
  let calls = 0;
  mock.method(
    globalThis,
    "fetch",
    async (url: RequestInfo | URL, init?: RequestInit) => {
      calls++;
      assert.equal(
        String(url),
        `${origin}/api/v1/auth/accounts/browser/logout`,
      );
      assert.equal(init?.credentials, "omit");
      assert.equal(init?.body, "{}");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("Authorization"), `DPoP ${access(1)}`);
      proofs.push(headers.get("DPoP")!);
      if (calls === 1) return response({ revoked: true, extra: true });
      if (calls === 2)
        return problem("auth.authentication_required", 401, false, false);
      return response({ revoked: true });
    },
  );
  await assert.rejects(client.signOut(), rejected("invalid_response", true));
  assert.equal(client.authenticated, true);
  assert.equal(client.blocked, true);
  assert.equal(client.logoutState, "uncertain");
  await assert.rejects(
    client.request("GET", "/api/v1/accounts/me"),
    rejected("sign_out_pending", false),
  );
  assert.equal(calls, 1);
  await assert.rejects(
    client.signOut(),
    rejected("auth.authentication_required", false),
  );
  assert.equal(client.logoutState, "failed");
  assert.equal(client.authenticated, true);
  await client.signOut();
  assert.equal(client.authenticated, false);
  assert.equal(client.reason, "signed_out");
  assert.equal(new Set(proofs).size, 3);
  const keys = proofs.map(
    (proof) =>
      JSON.parse(new TextDecoder().decode(bytes(proof.split(".")[0], 1, 2048)))
        .jwk,
  );
  assert.deepEqual(keys, [keys[0], keys[0], keys[0]]);
});

test("expiry prevents logout retries without refresh or cookie fallback", async () => {
  const client = new AccountClient(
    origin,
    loginBoundary(await AccountProofKey.create()),
  );
  await client.signIn("qa.owner", password());
  mock.method(globalThis, "fetch", async () => {
    throw new Error("lost");
  });
  await assert.rejects(client.signOut(), rejected("response_lost", true));
  const now = Date.now();
  mock.method(Date, "now", () => now + 600_001);
  assert.equal(client.logoutState, "expired");
  await assert.rejects(client.signOut(), rejected("logout_expired", false));
  assert.equal(client.authenticated, true);
  client.lock();
  assert.equal(client.authenticated, false);
});

test("local Lock fences a late login result and clears its owned password bytes", async () => {
  const key = await AccountProofKey.create();
  let resolve!: (value: Awaited<ReturnType<PasswordLogin["run"]>>) => void;
  let entered!: () => void;
  const ready = new Promise<void>((accept) => {
    entered = accept;
  });
  const client = new AccountClient(origin, {
    run: async () => {
      entered();
      return new Promise((accept) => {
        resolve = accept;
      });
    },
  });
  const owned = password();
  const pending = client.signIn("qa.owner", owned);
  await ready;
  client.lock();
  resolve({ ...key.transfer(), session: session(), startedAt: Date.now() });
  await assert.rejects(pending, rejected("session_changed", false));
  assert.equal(client.authenticated, false);
  assert.ok(owned.every((value) => value === 0));
});

test("a late protected response is canceled after Lock and cannot replace a newer session", async () => {
  const entered = deferred<void>(),
    late = deferred<Response>();
  const client = new AccountClient(
    origin,
    loginBoundary(await AccountProofKey.create()),
  );
  await client.signIn("qa.owner", password());
  let calls = 0;
  mock.method(globalThis, "fetch", async () => {
    calls++;
    entered.resolve();
    return late.promise;
  });
  const old = client.request("GET", "/api/v1/accounts/me");
  await entered.promise;
  client.lock();
  const later = client.signIn("qa.owner", password());
  let canceled = false;
  late.resolve(
    new Response(
      new ReadableStream({
        cancel() {
          canceled = true;
        },
      }),
    ),
  );
  await assert.rejects(old, rejected("session_changed", false));
  await later;
  assert.equal(canceled, true);
  assert.equal(client.authenticated, true);
  assert.equal(calls, 1);
});

test("sign out refreshes once and fences protected actions queued before its confirmation", async () => {
  const entered = deferred<void>(),
    refreshed = deferred<Response>();
  const client = new AccountClient(
    origin,
    loginBoundary(await AccountProofKey.create()),
  );
  await client.signIn("qa.owner", password());
  const now = Date.now();
  mock.method(Date, "now", () => now + 571_000);
  const paths: string[] = [];
  mock.method(
    globalThis,
    "fetch",
    async (url: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      paths.push(path);
      if (path.endsWith("/refresh")) {
        entered.resolve();
        return refreshed.promise;
      }
      assert.ok(path.endsWith("/logout"));
      assert.equal(init?.credentials, "omit");
      assert.equal(
        new Headers(init?.headers).get("Authorization"),
        `DPoP ${access(2)}`,
      );
      return response({ revoked: true });
    },
  );
  const logout = client.signOut();
  await entered.promise;
  const queued = client.request("GET", "/api/v1/accounts/me");
  refreshed.resolve(response(session(2, 2_591_429)));
  await logout;
  await assert.rejects(queued, rejected("session_changed", false));
  assert.deepEqual(paths, [
    "/api/v1/auth/accounts/browser/refresh",
    "/api/v1/auth/accounts/browser/logout",
  ]);
});

test("Lock during an old refresh preserves a later independent sign-in", async () => {
  const entered = deferred<void>(),
    refreshed = deferred<Response>();
  const client = new AccountClient(
    origin,
    loginBoundary(await AccountProofKey.create()),
  );
  await client.signIn("qa.owner", password());
  const now = Date.now();
  mock.method(Date, "now", () => now + 571_000);
  mock.method(globalThis, "fetch", async () => {
    entered.resolve();
    return refreshed.promise;
  });
  const old = client.request("GET", "/api/v1/accounts/me");
  await entered.promise;
  client.lock();
  const later = client.signIn("qa.owner", password());
  refreshed.resolve(response(session(2, 2_591_429)));
  await assert.rejects(old, rejected("session_changed", false));
  await later;
  assert.equal(client.authenticated, true);
  assert.equal(client.reason, "");
});
