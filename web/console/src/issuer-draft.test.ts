// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mock, test } from "node:test";
import { AccountProofKey } from "./account-proof.ts";
import { accountFetch } from "./account-http.ts";
import {
  IssuerDraftActions,
  draftIssuer,
  draftRegistrationSettings,
} from "./issuer-draft.ts";
import {
  TeamApi,
  RequestFailure,
  type AccountTransport,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";

const origin = "https://console.example";
const org = "019a0000-0000-7000-8000-000000000001";
const account = "019a0000-0000-7000-8000-000000000002";
const id = "019a0000-0000-7000-8000-000000000003";
const other = "019a0000-0000-7000-8000-000000000004";
const issuer = "https://Issuer.example:443/Case%2fPath/";
const path = `/api/v1/orgs/${org}/auth-connection-draft`;
const item = (generation = id, proposed = issuer) => ({
  id: generation,
  etag: `"${generation}"`,
  created_at: "2030-01-01T00:00:00.123Z",
  updated_at: "2030-01-01T00:00:00.123Z",
  data: { organization_id: org, issuer: proposed },
});
const missing = () => new RequestFailure("organization.not_found", 404);
const testPath = `${path}/test-login`;
const credentials = { client_id: "client+id:", client_secret: " secret:+% " };
const authorizationUrl = "https://issuer.example/authorize?state=fixture";
const startedLogin = () => ({
  id: other,
  organization_id: org,
  draft_generation: id,
  status: "pending",
  expires_at: new Date(Date.now() + 240_000).toISOString(),
  authorization_url: authorizationUrl,
});

test("the offline registration worksheet binds the exact saved issuer to the public HTTPS origin", async () => {
  const publicOrigin = "https://console.example:9443";
  const generate = (value: string) => {
    const hash = createHash("sha256").update(value, "utf8").digest("hex");
    return {
      redirect_uri: `${publicOrigin}/api/v1/auth/enterprise/oidc/${hash}/callback`,
      response_type: "code",
      grant_type: "authorization_code",
      code_challenge_method: "S256",
      scope: "openid",
      token_endpoint_auth_method: "client_secret_basic",
    };
  };
  for (const value of [
    issuer,
    issuer.slice(0, -1),
    issuer.replace("%2f", "%2F"),
    "https://identity.example/租户/",
  ])
    assert.deepEqual(
      await draftRegistrationSettings(publicOrigin, value),
      generate(value),
    );
  await assert.rejects(
    draftRegistrationSettings("http://console.example", issuer),
  );
  await assert.rejects(
    draftRegistrationSettings(`${publicOrigin}/setup`, issuer),
  );
  await assert.rejects(
    draftRegistrationSettings(
      publicOrigin,
      "https://identity.example/?unexpected",
    ),
  );
});
function fixture() {
  const calls: { method: Method; path: string; options: RequestOptions }[] = [];
  const transport: AccountTransport & {
    sessionGeneration: number;
    next: () => Promise<ApiResponse>;
  } = {
    origin,
    sessionGeneration: 1,
    next: async () => {
      throw missing();
    },
    async request(method, path, options = {}) {
      calls.push({ method, path, options });
      return this.next();
    },
  };
  const api = new TeamApi(transport);
  api.accountId = account;
  return { calls, transport, api, actions: new IssuerDraftActions(api, org) };
}

test("draft test signs a single start with cookie delivery and reads the original attempt without cookies", async (t) => {
  const f = fixture(),
    key = await AccountProofKey.create();
  f.transport.next = async () => ({ value: item(), etag: item().etag });
  await f.actions.read();
  const { authorization_url, ...original } = startedLogin();
  const proofs = new Set<string>();
  let request = 0;
  t.mock.method(globalThis, "fetch", async (url: string, init: RequestInit) => {
    const starting = request++ === 0;
    const headers = new Headers(init.headers);
    assert.equal(url, origin + (starting ? testPath : `${testPath}/${other}`));
    assert.equal(init.method, starting ? "POST" : "GET");
    assert.equal(init.credentials, starting ? "same-origin" : "omit");
    assert.equal(init.redirect, "error");
    assert.equal(init.referrerPolicy, "no-referrer");
    assert.equal(headers.get("Idempotency-Key"), null);
    assert.equal(headers.get("If-Match"), starting ? item().etag : null);
    assert.equal(init.body, starting ? JSON.stringify(credentials) : undefined);
    const proof = headers.get("DPoP")!;
    proofs.add(proof);
    const claims = JSON.parse(
      Buffer.from(proof.split(".")[1], "base64url").toString(),
    );
    assert.equal(claims.htm, init.method);
    assert.equal(claims.htu, url);
    const value = starting
      ? { ...original, authorization_url }
      : { ...original, status: "verified" };
    return new Response(JSON.stringify(value), {
      status: starting ? 201 : 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        pragma: "no-cache",
        "x-request-id": "draft-test-fixture",
      },
    });
  });
  f.transport.request = (method, path, options) =>
    accountFetch({
      origin,
      key,
      method,
      path,
      options,
      operation: "request",
      token: "fixture-bound-token",
    });
  await f.actions.startLogin(credentials);
  assert.equal(
    f.actions.login?.kind === "attempt" && f.actions.login.url,
    authorizationUrl,
  );
  await assert.rejects(f.actions.startLogin(credentials));
  await f.actions.readLogin();
  assert.equal(
    f.actions.login?.kind === "attempt" && f.actions.login.attempt.status,
    "verified",
  );
  assert.equal(
    f.actions.login?.kind === "attempt" && f.actions.login.url,
    undefined,
  );
  await f.actions.readLogin();
  assert.equal(proofs.size, 2);
  assert.equal(request, 2);
});

test("draft test rejects foreign navigation and waits after an uncertain start without replay", async (t) => {
  const f = fixture();
  const kind = () => f.actions.login?.kind;
  f.transport.next = async () => ({ value: item(), etag: item().etag });
  await f.actions.read();
  for (const secret of ["", "invalid\nvalue", "é".repeat(257)])
    await assert.rejects(
      f.actions.startLogin({ ...credentials, client_secret: secret }),
      { code: "invalid_draft_client" },
    );
  assert.equal(f.calls.length, 1);
  f.transport.next = async () => ({
    value: {
      ...startedLogin(),
      authorization_url: "https://issuer.example:8443/authorize",
    },
    etag: null,
  });
  await assert.rejects(f.actions.startLogin(credentials), {
    code: "invalid_response",
    changed: true,
  });
  assert.equal(kind(), "wait");
  await assert.rejects(f.actions.startLogin(credentials), {
    code: "draft_test_not_ready",
  });
  assert.equal(f.calls.length, 2);
  t.mock.method(performance, "now", () => 1_000_000_000);
  assert.equal(kind(), "expired");
  f.transport.next = async () => {
    throw new RequestFailure("organization.conflict", 409);
  };
  await assert.rejects(f.actions.startLogin(credentials), { status: 409 });
  assert.equal(kind(), "wait");
  assert.equal(f.calls.length, 3);
});

test("draft test fences altered status, superseded drafts and pending results from a replaced session", async (t) => {
  const f = fixture();
  f.transport.next = async () => ({ value: item(), etag: item().etag });
  await f.actions.read();
  const original = startedLogin();
  f.transport.next = async () => ({ value: original, etag: null });
  await f.actions.startLogin(credentials);
  const { authorization_url, ...attempt } = original;
  for (const value of [
    { ...attempt, id },
    { ...attempt, organization_id: other },
    { ...attempt, draft_generation: other },
    { ...attempt, expires_at: `${attempt.expires_at.slice(0, -1)}0Z` },
    { ...attempt, authorization_url },
  ]) {
    f.transport.next = async () => ({
      value: { ...value, status: "verified" },
      etag: null,
    });
    await assert.rejects(f.actions.readLogin(), {
      code: "invalid_response",
      changed: false,
    });
    assert.equal(
      f.actions.login?.kind === "attempt" && f.actions.login.attempt.status,
      "pending",
    );
  }
  f.transport.next = async () => {
    throw missing();
  };
  await f.actions.readLogin();
  assert.equal(f.actions.login?.kind, "unavailable");
  await assert.rejects(f.actions.startLogin(credentials), {
    code: "draft_test_not_ready",
  });

  f.transport.next = async () => ({
    value: item(other),
    etag: item(other).etag,
  });
  await f.actions.read();
  assert.equal(f.actions.login, undefined);
  f.transport.next = async () => ({
    value: { ...original, draft_generation: other },
    etag: null,
  });
  await f.actions.startLogin(credentials);
  let deliver!: (reply: ApiResponse) => void;
  f.transport.next = () =>
    new Promise((resolve) => {
      deliver = resolve;
    });
  const status = f.actions.readLogin();
  f.transport.sessionGeneration++;
  deliver({
    value: { ...attempt, draft_generation: other, status: "verified" },
    etag: null,
  });
  await assert.rejects(status, { code: "session_changed" });
  assert.equal(f.actions.login, undefined);

  const expired = fixture();
  expired.transport.next = async () => ({ value: item(), etag: item().etag });
  await expired.actions.read();
  expired.transport.next = async () => ({ value: original, etag: null });
  await expired.actions.startLogin(credentials);
  t.mock.method(performance, "now", () => 1_000_000_000);
  await expired.actions.readLogin();
  assert.equal(expired.actions.login?.kind, "expired");
  assert.equal(expired.calls.length, 2);
});

test("issuer draft signs the actual HTTPS methods with exact conditional headers and omitted credentials", async () => {
  const f = fixture(),
    key = await AccountProofKey.create(),
    requests: RequestInit[] = [];
  const responses = [
    new Response(
      JSON.stringify({
        type: "about:blank",
        title: "Unavailable",
        detail: "Unavailable",
        instance: "request-1",
        code: "organization.not_found",
        status: 404,
        changed: false,
        retryable: false,
      }),
      {
        status: 404,
        headers: {
          "content-type": "application/problem+json",
          "cache-control": "no-store",
          pragma: "no-cache",
          "x-request-id": "request-1",
        },
      },
    ),
    ...[201, 200].map(
      (status) =>
        new Response(JSON.stringify(item()), {
          status,
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            pragma: "no-cache",
            "x-request-id": "request-2",
            etag: item().etag,
          },
        }),
    ),
    new Response(null, {
      status: 204,
      headers: {
        "cache-control": "no-store",
        pragma: "no-cache",
        "x-request-id": "request-4",
      },
    }),
  ];
  const fetch = mock.method(
    globalThis,
    "fetch",
    async (url: string, init: RequestInit) => {
      assert.equal(url, origin + path);
      requests.push(init);
      return responses.shift()!;
    },
  );
  try {
    f.transport.request = (method, path, options) =>
      accountFetch({
        origin,
        key,
        method,
        path,
        options,
        operation: "request",
        token: "fixture-bound-token",
      });
    assert.equal(await f.actions.read(), null);
    await f.actions.create(issuer);
    assert.equal(
      f.actions.current,
      undefined,
      "receipt is historical until GET",
    );
    assert.deepEqual(await f.actions.read(), item());
    await f.actions.cancel();
    assert.deepEqual(
      requests.map((req) => req.method),
      ["GET", "POST", "GET", "DELETE"],
    );
    const proofs = new Set<string>();
    requests.forEach((req, index) => {
      const headers = new Headers(req.headers);
      assert.equal(req.credentials, "omit");
      assert.equal(req.redirect, "error");
      const proof = headers.get("DPoP")!;
      proofs.add(proof);
      const claims = JSON.parse(
        Buffer.from(proof.split(".")[1], "base64url").toString(),
      );
      assert.equal(claims.htm, req.method);
      assert.equal(claims.htu, origin + path);
      assert.equal(headers.get("If-None-Match"), index === 1 ? "*" : null);
      assert.equal(headers.get("If-Match"), index === 3 ? item().etag : null);
      assert.equal(
        Boolean(headers.get("Idempotency-Key")),
        index === 1 || index === 3,
      );
      assert.equal(
        req.body,
        index === 1 ? JSON.stringify({ data: { issuer } }) : undefined,
      );
    });
    assert.equal(proofs.size, 4);
  } finally {
    fetch.mock.restore();
  }
});

test("issuer draft preserves only an explicit original confirmation and rereads after writer changes", async () => {
  const { actions, transport, calls, api } = fixture();
  await actions.read();
  transport.next = async () => {
    throw new RequestFailure(
      "organization.commit_outcome_unknown",
      503,
      true,
      true,
    );
  };
  await assert.rejects(actions.create(issuer));
  const initial = calls.at(-1);
  assert.equal(actions.pending?.method, "POST");
  await assert.rejects(actions.create(issuer));
  assert.equal(calls.at(-1), initial);
  transport.next = async () => ({ value: item(), etag: item().etag });
  await actions.confirm();
  assert.deepEqual(calls.at(-1), initial);
  await actions.read();
  transport.next = async () => {
    throw new RequestFailure("response_lost", 0, true);
  };
  await assert.rejects(actions.cancel());
  const cancellation = calls.at(-1);
  transport.next = async () => ({ value: undefined, etag: null });
  await actions.confirm();
  assert.deepEqual(calls.at(-1), cancellation);
  assert.equal(actions.current, undefined);
  transport.next = async () => {
    throw missing();
  };
  await actions.read();
  transport.next = async () => {
    throw new RequestFailure("response_lost", 0, true);
  };
  await assert.rejects(actions.create(issuer));
  transport.sessionGeneration++;
  const n = calls.length;
  await assert.rejects(actions.confirm());
  assert.equal(calls.length, n);
  assert.equal(actions.pending, undefined);
  const nextTeam = new IssuerDraftActions(api, other);
  await assert.rejects(nextTeam.confirm());
  assert.equal(calls.length, n);
});

test("issuer draft requires a fresh review after conflicts or discarding an expired original", async () => {
  const { actions, transport, calls } = fixture();
  await actions.read();
  transport.next = async () => {
    throw new RequestFailure("organization.precondition_failed", 412);
  };
  await assert.rejects(actions.create(issuer));
  assert.equal(actions.current, undefined);
  await assert.rejects(actions.create(issuer));
  assert.equal(calls.length, 2);
  transport.next = async () => ({ value: item(), etag: item().etag });
  await actions.read();
  transport.next = async () => {
    throw new RequestFailure("response_lost", 0, true);
  };
  await assert.rejects(actions.cancel());
  const clock = mock.method(Date, "now", () =>
    Date.parse("2100-01-01T00:00:00Z"),
  );
  try {
    await assert.rejects(actions.confirm());
    assert.equal(calls.length, 4);
  } finally {
    clock.mock.restore();
  }
  await assert.rejects(actions.confirm(), {
    code: "draft_confirmation_unavailable",
  });
  assert.equal(calls.length, 4);
  actions.discard();
  await assert.rejects(actions.cancel());
  transport.next = async () => {
    throw new RequestFailure("policy.denied", 403);
  };
  await assert.rejects(actions.read());
  assert.equal(actions.current, undefined);
});

test("issuer draft rejects inaccurate resource bindings, malformed issuers and late data from a previous team", async () => {
  const { actions, transport } = fixture();
  assert.equal(draftIssuer(issuer), issuer);
  assert.equal(
    draftIssuer("https://issuer.example/a\uFEFF/"),
    "https://issuer.example/a\uFEFF/",
  );
  for (const invalid of [
    "http://example.test",
    "https://@example.test",
    "https://example.test/a?",
    "https://example.test/#",
    "https://example.test/a\\b",
    "https://example.test/\u0000",
    "https://example.test/\ud800",
    "https://example.test/" + "界".repeat(700),
  ])
    assert.throws(() => draftIssuer(invalid));
  for (const value of [
    { ...item(), data: { organization_id: other, issuer } },
    { ...item(), etag: `"${other}"` },
    { ...item(), updated_at: "2030-01-01T00:00:01Z" },
  ]) {
    transport.next = async () => ({ value, etag: value.etag });
    await assert.rejects(actions.read());
    assert.equal(actions.current, undefined);
  }
  transport.next = async () => ({ value: item(), etag: null });
  await assert.rejects(actions.read());
  let deliver!: (value: ApiResponse) => void;
  transport.next = () =>
    new Promise((resolve) => {
      deliver = resolve;
    });
  const pending = actions.read();
  actions.dispose();
  deliver({ value: item(), etag: item().etag });
  await assert.rejects(pending);
  assert.equal(actions.current, undefined);
});

test("malformed receipts preserve the original and malformed reads never report an input or successful write", async () => {
  const { actions, transport, calls } = fixture();
  await actions.read();
  transport.next = async () => ({
    value: item(id, "https://replacement.example/"),
    etag: item().etag,
  });
  await assert.rejects(actions.create(issuer), {
    code: "invalid_response",
    changed: true,
  });
  const original = calls.at(-1);
  transport.next = async () => ({
    value: item(id, "http://invalid.example/"),
    etag: item().etag,
  });
  await assert.rejects(actions.read(), {
    code: "invalid_response",
    changed: false,
  });
  assert.ok(actions.pending);
  transport.next = async () => ({ value: item(), etag: item().etag });
  await actions.confirm();
  assert.deepEqual(calls.at(-1), original);
  await actions.read();
  transport.next = async () => ({ value: undefined, etag: item().etag });
  await assert.rejects(actions.cancel(), {
    code: "invalid_response",
    changed: true,
  });
  assert.equal(actions.pending?.method, "DELETE");
});

test("only a verified empty-slot response opens creation, and concurrent reads cannot replace a pending write", async () => {
  const { actions, transport, calls } = fixture();
  for (const error of [
    new RequestFailure("policy.denied", 403),
    new RequestFailure("unrelated.not_found", 404),
    new RequestFailure("organization.not_found", 404, true),
    new RequestFailure("organization.not_found", 404, false, true),
  ]) {
    transport.next = async () => {
      throw error;
    };
    await assert.rejects(actions.read());
    await assert.rejects(actions.create(issuer));
    assert.equal(actions.current, undefined);
  }
  transport.next = async () => {
    throw missing();
  };
  await actions.read();
  let deliver!: (value: ApiResponse) => void;
  transport.next = () =>
    new Promise((resolve) => {
      deliver = resolve;
    });
  const saving = actions.create(issuer),
    n = calls.length;
  await assert.rejects(actions.read());
  await assert.rejects(actions.confirm());
  assert.equal(calls.length, n);
  deliver({ value: item(), etag: item().etag });
  await saving;
});
