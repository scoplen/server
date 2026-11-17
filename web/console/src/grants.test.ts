// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  GrantActions,
  GrantApi,
  grantFields,
  grantStatus,
  grantTime,
  parseGrant,
  parseGrantPage,
} from "./grants.ts";
import {
  RequestFailure,
  type AccountTransport,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";
import type { GrantFields, GrantResource } from "./generated/api.ts";
import { accountBrowserOperations } from "./generated/api.ts";
import { AccountClient } from "./account.ts";
import { AccountProofKey } from "./account-proof.ts";
import { AccountFailure } from "./account-http.ts";
import { encoded } from "./wire.ts";

const org = "019a0000-0000-7000-8000-000000000001";
const membership = "019a0000-0000-7000-8000-000000000002";
const host = "019a0000-0000-7000-8000-000000000003";
const id = "019a0000-0000-7000-8000-000000000004";
const key = "019a0000-0000-7000-8000-000000000005";
const fields: GrantFields = {
  membership,
  host,
  remote_user: " Ops e\u0301 ",
  valid_from: "2030-01-01T00:00:00Z",
  valid_until: "2030-01-01T01:00:00Z",
};
const grant = (data = fields, grantId = id, etag = '"v1"'): GrantResource => ({
  id: grantId,
  etag,
  created_at: "2026-11-17T00:00:00Z",
  updated_at: "2026-11-17T00:00:00Z",
  data: { ...data },
});
class Transport implements AccountTransport {
  readonly origin = "https://console.example";
  calls: { method: Method; path: string; options: RequestOptions }[] = [];
  next: (method: Method, options: RequestOptions) => Promise<ApiResponse> =
    async (_method, options) => {
      const body = options.body as
        { id?: string; data?: GrantFields } | undefined;
      return {
        value: grant(body?.data ?? fields, body?.id ?? id),
        etag: '"v1"',
      };
    };
  async request(
    method: Method,
    path: string,
    options: RequestOptions = {},
  ): Promise<ApiResponse> {
    this.calls.push({ method, path, options });
    return this.next(method, options);
  }
}
const setup = () => {
  const transport = new Transport(),
    api = new GrantApi(transport, org);
  return { transport, api, actions: new GrantActions(api) };
};

test("Grant fields preserve exact remote users and accept explicit finite or nonexpiring intervals", () => {
  assert.deepEqual(grantFields(fields), fields);
  assert.equal(
    grantFields({ ...fields, remote_user: "界".repeat(85), valid_until: null })
      .remote_user.length,
    85,
  );
  for (const remote_user of [
    "",
    "界".repeat(86),
    "user\n",
    "user\u0085",
    "\ud800",
  ])
    assert.throws(() => grantFields({ ...fields, remote_user }));
  assert.equal(grantTime("1970-01-01T00:00:00Z"), "1970-01-01T00:00:00Z");
  assert.equal(grantTime("9999-12-31T23:59:59Z"), "9999-12-31T23:59:59Z");
  for (const valid_from of [
    "1969-12-31T23:59:59Z",
    "2030-02-30T00:00:00Z",
    "2030-01-01T00:00:00.0Z",
    "2030-01-01T00:00:00+00:00",
    "2030-01-01T00:00:60Z",
  ])
    assert.throws(() => grantFields({ ...fields, valid_from }));
  for (const valid_until of [
    undefined,
    fields.valid_from,
    "2029-01-01T00:00:00Z",
  ])
    assert.throws(() => grantFields({ ...fields, valid_until }));
  for (const field of Object.keys(fields)) {
    const missing: Record<string, unknown> = { ...fields };
    delete missing[field];
    assert.throws(() => grantFields(missing));
  }
});
test("Grant status derives exact interval boundaries without altering the resource", () => {
  const item = grant(),
    original = JSON.stringify(item);
  assert.equal(
    grantStatus(item.data, Date.parse(fields.valid_from) - 1),
    "future",
  );
  assert.equal(grantStatus(item.data, Date.parse(fields.valid_from)), "active");
  assert.equal(
    grantStatus(item.data, Date.parse(fields.valid_until!)),
    "expired",
  );
  assert.equal(
    grantStatus(
      { ...fields, valid_until: null },
      Date.parse("9999-12-31T23:59:59Z"),
    ),
    "active",
  );
  assert.equal(JSON.stringify(item), original);
});
test("Grant response parsing requires known fields, original byte bounds and unambiguous extensions", () => {
  assert.deepEqual(
    parseGrant(
      JSON.stringify({
        ...grant(),
        extra: { safe: true },
        data: { ...fields, extension: 1 },
      }),
      '"v1"',
    ),
    grant(),
  );
  assert.throws(() => parseGrant(JSON.stringify(grant()), '"v2"'));
  assert.throws(() =>
    parseGrant(
      JSON.stringify(grant()).replace(
        '"data":',
        '"extra":{"x":1,"x":2},"data":',
      ),
    ),
  );
  assert.throws(() =>
    parseGrant(
      JSON.stringify(grant()).replace(
        '"membership":',
        '"membership":"' + membership + '","membership":',
      ),
    ),
  );
  const raw = JSON.stringify(grant());
  assert.throws(() => parseGrant(raw + " ".repeat(4_097)));
  for (const field of ["id", "etag", "created_at", "updated_at", "data"]) {
    const missing = { ...grant() };
    delete (missing as Record<string, unknown>)[field];
    assert.throws(() => parseGrant(JSON.stringify(missing)));
  }
  const padded = raw.replace('"data":', '"data":' + " ".repeat(4_096));
  assert.throws(() =>
    parseGrantPage(`{"items":[${padded}],"next_cursor":null}`),
  );
});
test("Grant pages enforce captured cursor, limit and exact final continuation", () => {
  const page = JSON.stringify({ items: [grant()], next_cursor: id });
  assert.equal(parseGrantPage(page).next_cursor, id);
  assert.throws(() => parseGrantPage(page, id));
  assert.throws(() => parseGrantPage(page, undefined, 0));
  assert.throws(() =>
    parseGrantPage(
      JSON.stringify({ items: [grant(), grant()], next_cursor: null }),
    ),
  );
  assert.throws(() =>
    parseGrantPage(JSON.stringify({ items: [grant()], next_cursor: host })),
  );
  assert.throws(() =>
    parseGrantPage('{"items":[],"next_cursor":null,"extra":{"a":1,"a":2}}'),
  );
  assert.throws(() =>
    parseGrantPage(
      JSON.stringify({ items: [], next_cursor: null }) + " ".repeat(2_097_152),
    ),
  );
});
test("GrantApi uses all five published Account-browser operations with original conditional metadata", async () => {
  const { transport, api } = setup();
  const routes = accountBrowserOperations.filter((route) =>
    route.path.includes("/grants"),
  );
  assert.equal(routes.length, 5);
  transport.next = async () => ({
    value: { items: [grant()], next_cursor: null },
    etag: null,
  });
  await api.list(host);
  assert.equal(
    transport.calls[0].path,
    `/api/v1/orgs/${org}/grants?limit=50&cursor=${host}`,
  );
  assert.equal(transport.calls[0].options.maximum, 2_097_152);
  assert.throws(() =>
    transport.calls[0].options.decode!(
      '{"items":[],"next_cursor":null,"x":{"k":1,"k":2}}',
    ),
  );
  transport.next = async () => ({ value: grant(), etag: '"v1"' });
  await api.get(id);
  await api.create({ id, data: fields }, key);
  await api.replace(grant(), fields);
  transport.next = async () => ({ value: undefined, etag: null });
  await api.withdraw(grant());
  assert.deepEqual(
    transport.calls.map((call) => [
      call.method,
      call.options.key,
      call.options.etag,
      call.options.success,
    ]),
    [
      ["GET", undefined, undefined, undefined],
      ["GET", undefined, undefined, undefined],
      ["POST", key, undefined, 201],
      ["PUT", undefined, '"v1"', undefined],
      ["DELETE", undefined, '"v1"', 204],
    ],
  );
  assert.deepEqual(transport.calls[2].options.body, { id, data: fields });
  assert.deepEqual(transport.calls[3].options.body, { data: fields });
  assert.equal(transport.calls[4].options.body, undefined);
});
test("GrantApi rejects mismatched IDs, fields and HTTP ETags", async () => {
  const { transport, api } = setup();
  transport.next = async () => ({ value: grant(fields, host), etag: '"v1"' });
  await assert.rejects(api.get(id));
  await assert.rejects(api.create({ id, data: fields }, key));
  transport.next = async () => ({
    value: grant({ ...fields, remote_user: "root" }),
    etag: '"v1"',
  });
  await assert.rejects(api.replace(grant(), fields));
  transport.next = async () => ({ value: grant(), etag: null });
  await assert.rejects(api.get(id));
});
test("uncertain Grant creation retains the immutable original request and sends no automatic retry", async () => {
  const { transport, actions } = setup();
  transport.next = async () => {
    throw new RequestFailure("response_lost", 0, true);
  };
  const mutable = { ...fields };
  await assert.rejects(actions.create(mutable));
  const pending = actions.pending!;
  assert.ok(pending);
  mutable.remote_user = "root";
  assert.equal(pending.body.data.remote_user, fields.remote_user);
  assert.ok(Object.isFrozen(pending.body.data));
  await assert.rejects(actions.create(fields));
  assert.equal(transport.calls.length, 1);
  transport.next = async (_method, options) => ({
    value: grant((options.body as { data: GrantFields }).data, pending.body.id),
    etag: '"v1"',
  });
  await actions.confirm();
  assert.deepEqual(transport.calls[1], transport.calls[0]);
  assert.equal(actions.pending, undefined);
});
test("a denied confirmation does not settle a previously uncertain creation", async () => {
  const { transport, actions } = setup();
  transport.next = async () => {
    throw new RequestFailure("organization.storage_unavailable", 503, true);
  };
  await assert.rejects(actions.create(fields));
  const original = actions.pending;
  transport.next = async () => {
    throw new RequestFailure("policy.denied", 403, false);
  };
  await assert.rejects(actions.confirm());
  assert.equal(actions.pending, original);
  actions.discard();
  assert.equal(actions.pending, undefined);
  await assert.rejects(actions.create(fields));
  assert.equal(transport.calls.length, 2);
});
test("confirmed unchanged initial rejection releases creation while expiry cannot create a new confirmation key", async () => {
  const { transport, actions } = setup();
  transport.next = async () => {
    throw new RequestFailure("policy.denied", 403);
  };
  await assert.rejects(actions.create(fields));
  assert.equal(actions.pending, undefined);
  transport.next = async () => {
    throw new Error("lost");
  };
  await assert.rejects(actions.create(fields));
  const original = actions.pending!;
  const clock = mock.method(Date, "now", () => original.deadline);
  try {
    await assert.rejects(actions.confirm());
    assert.equal(transport.calls.length, 2);
    assert.equal(actions.pending, original);
  } finally {
    clock.mock.restore();
  }
});
test("stale and unknown edits require reviewed state and never substitute ETags or replay", async () => {
  for (const failure of [
    new RequestFailure("organization.precondition_failed", 412),
    new RequestFailure("response_lost", 0, true),
    new Error("invalid response"),
  ]) {
    const { transport, actions } = setup();
    transport.next = async () => {
      throw failure;
    };
    await assert.rejects(actions.replace(grant(), fields));
    assert.equal(actions.reviewRequired, true);
    await assert.rejects(actions.withdraw(grant(fields, id, '"v2"')));
    assert.equal(transport.calls.length, 1);
    assert.equal(transport.calls[0].options.etag, '"v1"');
    actions.reviewed();
    transport.next = async () => ({ value: undefined, etag: null });
    await actions.withdraw(grant(fields, id, '"v2"'));
    assert.equal(transport.calls[1].options.etag, '"v2"');
  }
});
test("team/session disposal clears intents and fences a late successful creation", async () => {
  const { transport, actions } = setup();
  let release!: (value: ApiResponse) => void;
  transport.next = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const result = actions.create(fields);
  const original = actions.pending!;
  actions.dispose();
  release({ value: grant(fields, original.body.id), etag: '"v1"' });
  await assert.rejects(
    result,
    (error) =>
      error instanceof RequestFailure && error.code === "session_changed",
  );
  assert.equal(actions.pending, undefined);
  await assert.rejects(actions.confirm());
  const other = new GrantActions(new GrantApi(transport, host));
  await assert.rejects(other.confirm());
  assert.equal(transport.calls.length, 1);
});

test("production Account transport admits all Grant operations with exact proofs and fences a late response", async () => {
  const proof = await AccountProofKey.create();
  const origin = "https://console.example";
  const client = new AccountClient(origin, {
    run: async () => ({
      ...proof.transfer(),
      session: {
        access_token: `ab1_${encoded(new Uint8Array(32))}`,
        token_type: "DPoP",
        expires_in: 600,
        refresh_expires_in: 2_592_000,
      },
      startedAt: Date.now(),
    }),
  });
  await client.signIn(
    "grant.owner",
    new TextEncoder().encode("a valid fixture password"),
  );
  const proofs = new Set<string>();
  let deferred = false,
    release: ((value: Response) => void) | undefined;
  const response = (value: unknown, status = 200) =>
    new Response(status === 204 ? null : JSON.stringify(value), {
      status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "X-Request-ID": "grant-fixture",
        ...((status === 200 && !("items" in (value as object))) ||
        status === 201
          ? { ETag: '"v1"' }
          : {}),
      },
    });
  const fetchMock = mock.method(
    globalThis,
    "fetch",
    async (url: string, options: RequestInit) => {
      assert.equal(options.credentials, "omit");
      assert.equal(options.redirect, "error");
      const headers = new Headers(options.headers);
      const claims = JSON.parse(
        Buffer.from(headers.get("DPoP")!.split(".")[1], "base64url").toString(
          "utf8",
        ),
      );
      assert.equal(claims.htm, options.method);
      assert.equal(claims.htu, origin + new URL(url).pathname);
      assert.ok(claims.ath);
      assert.ok(!proofs.has(claims.jti));
      proofs.add(claims.jti);
      if (deferred)
        return new Promise<Response>((resolve) => {
          release = resolve;
        });
      if (options.method === "DELETE") {
        assert.equal(options.body, undefined);
        assert.equal(headers.get("If-Match"), '"v1"');
        return response({}, 204);
      }
      if (options.method === "POST") {
        assert.equal(headers.get("Idempotency-Key"), key);
        assert.equal(headers.get("If-Match"), null);
        return response(grant(), 201);
      }
      if (options.method === "PUT")
        assert.equal(headers.get("If-Match"), '"v1"');
      return response(
        url.includes("?") ? { items: [grant()], next_cursor: null } : grant(),
      );
    },
  );
  try {
    const api = new GrantApi(client, org);
    await api.list();
    await api.get(id);
    await api.create({ id, data: fields }, key);
    await api.replace(grant(), fields);
    await api.withdraw(grant());
    assert.equal(proofs.size, 5);
    deferred = true;
    const late = api.get(id);
    while (!release)
      await new Promise<void>((resolve) => setImmediate(resolve));
    client.lock();
    release(response(grant()));
    await assert.rejects(
      late,
      (error) =>
        error instanceof AccountFailure && error.code === "session_changed",
    );
  } finally {
    fetchMock.mock.restore();
  }
});
