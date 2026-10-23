// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";
import {
  BrowserProofKey,
  ConsoleFailure,
  OperatorClient,
  takeSetupFragment,
} from "./operator.ts";
import { bytes, encoded } from "./wire.ts";

const origin = "https://operator.example";
const id = "019a0000-0000-7000-8000-000000000001";
const expires = "2030-01-02T03:04:05Z";
const setupToken = encoded(new Uint8Array(32));
const token = {
  access_token: "signed-access",
  token_type: "DPoP",
  expires_in: 900,
  refresh_expires_in: 2592000,
};
const invitation = {
  invitation_url: `${origin}/invite#token=${setupToken}`,
  expires_at: expires,
};
const loginOptions = {
  ceremony_id: id,
  expires_at: expires,
  public_key: {
    challenge: setupToken,
    timeout: 300000,
    rpId: "operator.example",
    allowCredentials: [],
    userVerification: "required",
  },
};
const setupOptions = {
  ceremony_id: id,
  expires_at: expires,
  public_key: {
    challenge: setupToken,
    timeout: 300000,
    rp: { id: "operator.example", name: "Scoplen" },
    user: {
      id: encoded(Buffer.from(id.replaceAll("-", ""), "hex")),
      name: `operator:${id}`,
      displayName: "Deployment operator",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
    attestation: "none",
  },
};

// These boundary stubs exercise the controller, not authenticator verification.
class Attestation {
  clientDataJSON = new Uint8Array([1]).buffer;
  attestationObject = new Uint8Array([2]).buffer;
}
class Assertion {
  clientDataJSON = new Uint8Array([3]).buffer;
  authenticatorData = new Uint8Array(37).buffer;
  signature = new Uint8Array(8).buffer;
  userHandle = new Uint8Array(16).buffer;
}
class Credential {
  rawId = new Uint8Array([4]).buffer;
  response: Attestation | Assertion;
  constructor(response: Attestation | Assertion) {
    this.response = response;
  }
}
beforeEach(() => {
  Object.defineProperty(globalThis, "PublicKeyCredential", {
    configurable: true,
    value: Credential,
  });
  Object.defineProperty(globalThis, "AuthenticatorAttestationResponse", {
    configurable: true,
    value: Attestation,
  });
  Object.defineProperty(globalThis, "AuthenticatorAssertionResponse", {
    configurable: true,
    value: Assertion,
  });
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: {
      create: async () => new Credential(new Attestation()),
      get: async () => new Credential(new Assertion()),
    },
  });
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: {
      request: async (_name: string, callback: () => Promise<void>) =>
        callback(),
    },
  });
});
afterEach(() => mock.restoreAll());
function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type":
        status >= 400 ? "application/problem+json" : "application/json",
    },
  });
}
function failure(operation: string, uncertain: boolean) {
  return (error: unknown) =>
    error instanceof ConsoleFailure &&
    error.operation === operation &&
    error.uncertain === uncertain;
}

test("setup fragment is scrubbed before validation and never retained in the URL", () => {
  const replaced: string[] = [];
  assert.equal(
    takeSetupFragment(
      new URL(`${origin}/setup?old=x#token=${setupToken}`),
      (path) => replaced.push(path),
    ),
    setupToken,
  );
  assert.deepEqual(replaced, ["/setup"]);
  assert.throws(() =>
    takeSetupFragment(new URL(`${origin}/setup#token=invalid`), (path) =>
      replaced.push(path),
    ),
  );
  assert.deepEqual(replaced, ["/setup", "/setup"]);
  assert.equal(
    takeSetupFragment(new URL(`${origin}/#token=${setupToken}`), (path) =>
      replaced.push(path),
    ),
    undefined,
  );
});

test("actual non-extractable WebCrypto key signs public-only ES256 proofs with exact target and ath", async () => {
  const generate = crypto.subtle.generateKey.bind(crypto.subtle);
  let nonExtractable = false;
  mock.method(
    crypto.subtle,
    "generateKey",
    async (...args: Parameters<SubtleCrypto["generateKey"]>) => {
      nonExtractable = args[1] === false;
      return generate(...args);
    },
  );
  const key = await BrowserProofKey.create();
  const first = await key.proof(
    origin,
    "/api/v1/admin/personal-invitations",
    "access",
  );
  const second = await key.proof(
    origin,
    "/api/v1/admin/personal-invitations",
    "access",
  );
  const [header, payload, signature] = first.split(".");
  const h = JSON.parse(new TextDecoder().decode(bytes(header, 1, 1024)));
  const p = JSON.parse(new TextDecoder().decode(bytes(payload, 1, 1024)));
  assert.equal(nonExtractable, true);
  assert.equal(h.typ, "dpop+jwt");
  assert.equal(h.alg, "ES256");
  assert.deepEqual(Object.keys(h.jwk).sort(), ["crv", "kty", "x", "y"]);
  assert.equal(p.htu, `${origin}/api/v1/admin/personal-invitations`);
  assert.equal(p.htm, "POST");
  assert.equal(
    p.ath,
    encoded(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode("access")),
    ),
  );
  assert.notEqual(payload, second.split(".")[1]);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    h.jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  assert.equal(
    await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      bytes(signature, 64),
      new TextEncoder().encode(`${header}.${payload}`),
    ),
    true,
  );
});

test("setup, fresh sign-in, and invitation require separate explicit operations", async () => {
  const paths: string[] = [];
  mock.method(globalThis, "fetch", async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname;
    paths.push(path);
    assert.equal(init.credentials, "same-origin");
    assert.equal(init.redirect, "error");
    assert.equal(init.cache, "no-store");
    assert.equal(init.referrerPolicy, "no-referrer");
    assert.ok(new Headers(init.headers).get("DPoP"));
    assert.ok(!url.includes(setupToken));
    if (path.endsWith("setup/options")) {
      assert.equal(JSON.parse(String(init.body)).setup_token, setupToken);
      return response(setupOptions);
    }
    if (path.endsWith("setup/finish"))
      return response({ operator_id: id }, 201);
    if (path.endsWith("login/options")) return response(loginOptions);
    if (path.endsWith("login/finish")) return response(token);
    assert.equal(
      new Headers(init.headers).get("Authorization"),
      "DPoP signed-access",
    );
    assert.equal(init.body, "{}");
    return response(invitation, 201);
  });
  const client = new OperatorClient(origin, setupToken);
  await client.register();
  assert.equal(paths.length, 2);
  assert.equal(client.canSetup, false);
  await client.signIn();
  assert.equal(paths.length, 4);
  assert.deepEqual(await client.invite(), invitation);
  assert.equal(paths.length, 5);
  client.lock();
  await assert.rejects(client.invite(), failure("invitation", false));
  assert.equal(paths.length, 5);
});

test("uncertain setup does not replay registration or consume the pending setup token", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () => {
    calls++;
    if (calls === 1) return response(setupOptions);
    throw new TypeError("lost acknowledgement");
  });
  const client = new OperatorClient(origin, setupToken);
  await assert.rejects(client.register(), failure("setup", true));
  assert.equal(calls, 2);
  assert.equal(client.canSetup, true);
  assert.equal(client.canReturnToSetup, false);
  await assert.rejects(client.register(), failure("setup", false));
  assert.equal(calls, 2);
  mock.method(globalThis, "fetch", async () => response(loginOptions));
  mock.method(navigator.credentials, "get", async () => {
    throw new DOMException("cancelled", "NotAllowedError");
  });
  await assert.rejects(client.signIn(), { name: "NotAllowedError" });
  assert.equal(client.canReturnToSetup, true);
});

test("successful fresh login after uncertain setup clears the pending setup entitlement", async () => {
  mock.method(globalThis, "fetch", async (url: string) => {
    if (url.endsWith("setup/options")) return response(setupOptions);
    if (url.endsWith("setup/finish"))
      throw new TypeError("lost acknowledgement");
    if (url.endsWith("login/options")) return response(loginOptions);
    return response(token);
  });
  const client = new OperatorClient(origin, setupToken);
  await assert.rejects(client.register(), failure("setup", true));
  assert.equal(client.canReturnToSetup, false);
  await client.signIn();
  assert.equal(client.canSetup, false);
  assert.equal(client.canReturnToSetup, false);
});

test("malformed options and cancelled passkeys never submit a finish", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async () => {
    calls++;
    return response({
      ...loginOptions,
      public_key: { ...loginOptions.public_key, rpId: "other.example" },
    });
  });
  await assert.rejects(new OperatorClient(origin).signIn());
  assert.equal(calls, 1);
  mock.method(globalThis, "fetch", async () => {
    calls++;
    return response(loginOptions);
  });
  mock.method(navigator.credentials, "get", async () => {
    throw new DOMException("cancelled", "NotAllowedError");
  });
  await assert.rejects(new OperatorClient(origin).signIn(), {
    name: "NotAllowedError",
  });
  assert.equal(calls, 2);
});

test("browser refresh is serialized and uses cookie-only carriage before invitation", async () => {
  let refreshes = 0;
  mock.method(globalThis, "fetch", async (url: string, init: RequestInit) => {
    if (url.endsWith("login/options")) return response(loginOptions);
    if (url.endsWith("login/finish"))
      return response({ ...token, expires_in: 10 });
    if (url.endsWith("/refresh")) {
      refreshes++;
      assert.equal(init.body, "{}");
      assert.equal(new Headers(init.headers).get("Authorization"), null);
      return response({ ...token, access_token: "rotated-access" });
    }
    assert.equal(
      new Headers(init.headers).get("Authorization"),
      "DPoP rotated-access",
    );
    return response(invitation, 201);
  });
  const client = new OperatorClient(origin);
  await client.signIn();
  await Promise.all([client.invite(), client.invite()]);
  assert.equal(refreshes, 1);
});

test("uncertain refresh drops session and a reload cannot refresh an old cookie with a new key", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async (url: string) => {
    calls++;
    if (url.endsWith("login/options")) return response(loginOptions);
    if (url.endsWith("login/finish"))
      return response({ ...token, expires_in: 10 });
    return response({ ...token, refresh_token: "native-only" });
  });
  const client = new OperatorClient(origin);
  await client.signIn();
  await assert.rejects(client.invite(), failure("refresh", true));
  assert.equal(calls, 3);
  await assert.rejects(client.invite(), failure("invitation", false));
  await assert.rejects(
    new OperatorClient(origin).invite(),
    failure("invitation", false),
  );
  assert.equal(calls, 3);
});

test("invitation unknown outcome never retries and changed denials are not unknown success", async () => {
  let calls = 0;
  let code = "auth.commit_outcome_unknown";
  mock.method(globalThis, "fetch", async (url: string) => {
    calls++;
    if (url.endsWith("login/options")) return response(loginOptions);
    if (url.endsWith("login/finish")) return response(token);
    return response(
      { status: 503, code, changed: true, retryable: false },
      503,
    );
  });
  const client = new OperatorClient(origin);
  await client.signIn();
  await assert.rejects(client.invite(), failure("invitation", true));
  assert.equal(calls, 3);
  code = "policy.denied";
  await assert.rejects(client.invite(), failure("invitation", false));
  assert.equal(calls, 4);
});

test("authentication denial clears access and malformed problem details stay uncertain", async () => {
  let calls = 0;
  mock.method(globalThis, "fetch", async (url: string) => {
    calls++;
    if (url.endsWith("login/options")) return response(loginOptions);
    if (url.endsWith("login/finish")) return response(token);
    return response(
      {
        status: 401,
        code: "auth.authentication_required",
        changed: false,
        retryable: false,
      },
      401,
    );
  });
  const client = new OperatorClient(origin);
  await client.signIn();
  await assert.rejects(client.invite(), failure("invitation", false));
  await assert.rejects(client.invite(), failure("invitation", false));
  assert.equal(calls, 3);
  mock.method(globalThis, "fetch", async (url: string) => {
    if (url.endsWith("login/options")) return response(loginOptions);
    return response([], 503);
  });
  await assert.rejects(
    new OperatorClient(origin).signIn(),
    failure("login", true),
  );
});
