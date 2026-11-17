// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import type {
  InventorySnippetFields,
  InventorySnippetResource,
} from "./generated/api.ts";
import { accountBrowserOperations } from "./generated/api.ts";
import { snippetFields } from "./snippet-fields.ts";
import { AccountClient } from "./account.ts";
import { AccountProofKey } from "./account-proof.ts";
import { encoded } from "./wire.ts";
import { SnippetActions } from "./snippets.ts";
import {
  TeamApi,
  RequestFailure,
  parseCollection,
  type AccountTransport,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";

const account = "019a0000-0000-7000-8000-000000000001";
const org = "019a0000-0000-7000-8000-000000000002";
const id = "019a0000-0000-7000-8000-000000000003";
const fields: InventorySnippetFields = {
  name: "Deployment",
  template: "echo {{name}} {{count}} {{target}} {{token}}",
  variables: {
    name: { kind: 1, default: "" },
    count: { kind: 2, default: "-9223372036854775808" },
    target: { kind: 3, choices: ["a", "b"], default: "b" },
    token: { kind: 4 },
  },
  tags: { deploy: true, 标签: true },
  folder: "Operations",
};
function resource(
  data = fields,
  identity = id,
  etag = '"v1"',
): InventorySnippetResource {
  return {
    id: identity,
    etag,
    created_at: "2030-01-01T00:00:00Z",
    updated_at: "2030-01-01T00:00:00Z",
    data: { schema: 1, fields: data },
  };
}
class Transport implements AccountTransport {
  origin = "https://console.example";
  sessionGeneration = 1;
  calls: { method: Method; path: string; options: RequestOptions }[] = [];
  next: (method: Method, options: RequestOptions) => Promise<ApiResponse> =
    async (_method, options) => {
      const body = options.body as
        { id?: string; data?: { fields: InventorySnippetFields } } | undefined;
      return {
        value: resource(body?.data?.fields ?? fields, body?.id ?? id),
        etag: '"v1"',
      };
    };
  async request(method: Method, path: string, options: RequestOptions = {}) {
    this.calls.push({ method, path, options });
    return this.next(method, options);
  }
}
function setup() {
  const transport = new Transport(),
    api = new TeamApi(transport);
  api.accountId = account;
  return { transport, api, actions: new SnippetActions(api, org, account) };
}

test("Snippet fields roundtrip all four kinds, text tags, empty model text and signed-i64 string boundaries", () => {
  assert.deepEqual(snippetFields(fields), fields);
  assert.deepEqual(snippetFields({ name: "", template: "" }), {
    name: "",
    template: "",
  });
  for (const value of [
    "0",
    "-1",
    "9223372036854775807",
    "-9223372036854775808",
  ])
    assert.equal(
      snippetFields({
        ...fields,
        variables: { n: { kind: 2, default: value } },
      }).variables?.n.kind,
      2,
    );
  assert.deepEqual(
    snippetFields({ ...fields, variables: { __proto__: { kind: 1 } } })
      .variables,
    {},
  );
  const own = JSON.parse('{"__proto__":{"kind":1},"constructor":{"kind":4}}');
  assert.equal(
    Object.keys(snippetFields({ ...fields, variables: own }).variables!).length,
    2,
  );
});
test("Snippet replacement rejects unknown fields, invalid secrets, choices, integer strings and model budgets", () => {
  for (const variable of [
    { kind: 0 },
    { kind: 5 },
    { kind: "1" },
    { kind: 4, default: null },
    { kind: 4, default: "" },
    { kind: 4, default: "private-value" },
    { kind: 1, choices: [] },
    { kind: 1, unknown: true },
    { kind: 3 },
    { kind: 3, choices: [] },
    { kind: 3, choices: ["a", "a"] },
    { kind: 3, choices: ["a"], default: "b" },
    { kind: 3, choices: [null] },
    ...[
      "+1",
      "01",
      "-0",
      "-01",
      "1.0",
      "9223372036854775808",
      "-9223372036854775809",
    ].map((value) => ({ kind: 2, default: value })),
    { kind: 2, default: 1 },
    { kind: 1, default: null },
  ])
    assert.throws(() =>
      snippetFields({ ...fields, variables: { value: variable } }),
    );
  for (const invalid of [
    { ...fields, command: "unused" },
    { ...fields, template: undefined },
    { ...fields, tags: { tag: false } },
    { ...fields, name: "e\u0301" },
    { ...fields, template: "\ud800" },
    { ...fields, folder: "界".repeat(5462) },
    { ...fields, variables: { "e\u0301": { kind: 1 } } },
    {
      ...fields,
      variables: {
        value: {
          kind: 3,
          choices: Array.from({ length: 4097 }, (_, index) => String(index)),
        },
      },
    },
    {
      ...fields,
      tags: Object.fromEntries(
        Array.from({ length: 4097 }, (_, index) => [String(index), true]),
      ),
    },
  ])
    assert.throws(() => snippetFields(invalid));
  for (const unsupported of [
    { ...resource(), data: { schema: 2, fields } },
    resource({ ...fields, extra: "unsupported" } as InventorySnippetFields),
  ])
    assert.throws(() => parseCollection("snippets", unsupported));
});
test("Snippet mappings use exactly the existing read/write scopes and browser writer only for POST", () => {
  const operations = accountBrowserOperations.filter((entry) =>
    entry.path.includes("/snippets"),
  );
  assert.equal(operations.length, 5);
  for (const entry of operations) {
    assert.deepEqual(entry.scopes, [
      entry.method === "GET" ? "inventory:read" : "inventory:write",
    ]);
    assert.equal(entry.writerReceipt, entry.method === "POST");
  }
});
test("Snippet reads and writes use public typed routes, response budgets and original strong preconditions", async () => {
  const { transport, actions } = setup();
  await actions.read(id);
  assert.equal(transport.calls[0].path, `/api/v1/orgs/${org}/snippets/${id}`);
  assert.equal(transport.calls[0].options.maximum, 2_097_152);
  await actions.replace(resource(), { ...fields, name: "Updated" });
  assert.equal(transport.calls[1].method, "PUT");
  assert.equal(transport.calls[1].options.etag, '"v1"');
  assert.equal(transport.calls[1].options.key, undefined);
  await actions.remove(resource());
  assert.equal(transport.calls[2].method, "DELETE");
  assert.equal(transport.calls[2].options.etag, '"v1"');
  transport.next = async () => ({
    value: { items: [resource()], next_cursor: id },
    etag: null,
  });
  await actions.list();
  assert.equal(
    transport.calls[3].path,
    `/api/v1/orgs/${org}/snippets?limit=50`,
  );
  assert.equal(transport.calls[3].options.maximum, 8_388_608);
  transport.next = async () => ({
    value: { items: [], next_cursor: null },
    etag: null,
  });
  await actions.list(id);
  assert.match(transport.calls[4].path, new RegExp(`cursor=${id}$`));
});
test("unknown Snippet POST keeps immutable original fields, id, key and deadline across refresh and later denial", async () => {
  mock.timers.enable({
    apis: ["Date"],
    now: Date.parse("2030-01-01T00:00:00Z"),
  });
  try {
    const { transport, actions } = setup(),
      source = structuredClone(fields);
    transport.next = async () => {
      throw new RequestFailure("outcome_unknown", 503, true);
    };
    await assert.rejects(actions.create(source));
    const pending = actions.pending!,
      original = JSON.stringify(transport.calls[0].options);
    source.name = "changed";
    source.variables!.target = { kind: 4 };
    assert.ok(Object.isFrozen(pending.body.data.fields.variables!.target));
    assert.equal(pending.deadline, Date.now() + 86_400_000);
    assert.equal(pending.body.data.fields.name, fields.name);
    await assert.rejects(actions.create(fields));
    transport.next = async () => {
      throw new RequestFailure("policy.denied", 403);
    };
    await assert.rejects(actions.confirm());
    assert.equal(actions.pending, pending);
    assert.equal(JSON.stringify(transport.calls[1].options), original);
    transport.next = async (_method, options) => ({
      value: resource(
        (options.body as typeof pending.body).data.fields,
        pending.body.id,
      ),
      etag: '"v1"',
    });
    mock.timers.tick(1_000);
    await actions.confirm();
    assert.equal(JSON.stringify(transport.calls[2].options), original);
    assert.equal(actions.pending, undefined);
  } finally {
    mock.timers.reset();
  }
});
test("malformed successful POST remains uncertain; a known initial denial does not retain intent", async () => {
  for (const response of [
    { value: {}, etag: null },
    { value: resource(), etag: '"v2"' },
  ]) {
    const { actions, transport } = setup();
    transport.next = async () => response;
    await assert.rejects(
      actions.create(fields),
      (error) => error instanceof RequestFailure && error.changed,
    );
    assert.ok(actions.pending);
  }
  const { actions, transport } = setup();
  transport.next = async () => {
    throw new RequestFailure("policy.denied", 403);
  };
  await assert.rejects(actions.create(fields));
  assert.equal(actions.pending, undefined);
});
test("original POST confirmation stops exactly at its original 24-hour deadline", async () => {
  mock.timers.enable({
    apis: ["Date"],
    now: Date.parse("2030-01-01T00:00:00Z"),
  });
  try {
    const { actions, transport } = setup();
    transport.next = async () => {
      throw new RequestFailure("unknown", 503, true);
    };
    await assert.rejects(actions.create(fields));
    const pending = actions.pending!;
    mock.timers.tick(86_399_999);
    await assert.rejects(actions.confirm());
    assert.equal(transport.calls.length, 2);
    mock.timers.tick(1);
    await assert.rejects(actions.confirm(), /unavailable/);
    assert.equal(transport.calls.length, 2);
    assert.equal(actions.pending, pending);
  } finally {
    mock.timers.reset();
  }
});
test("same-id but different typed create/confirm/replace results stay uncertain", async () => {
  for (const change of ["create", "confirm", "replace"] as const) {
    const { actions, transport } = setup();
    let originalId = id;
    if (change === "confirm") {
      transport.next = async () => {
        throw new RequestFailure("unknown", 503, true);
      };
      await assert.rejects(actions.create(fields));
      originalId = actions.pending!.body.id;
    }
    transport.next = async (_method, options) => {
      const body = options.body as { id?: string };
      return {
        value: resource(
          { ...fields, template: "different" },
          body.id ?? originalId,
        ),
        etag: '"v1"',
      };
    };
    const result =
      change === "create"
        ? actions.create(fields)
        : change === "confirm"
          ? actions.confirm()
          : actions.replace(resource(), fields);
    await assert.rejects(
      result,
      (error) =>
        error instanceof RequestFailure &&
        error.changed &&
        error.code === "invalid_response",
    );
    if (change === "replace") assert.equal(actions.reviewRequired, true);
    else assert.ok(actions.pending);
  }
});
test("typed result equality accepts reordered maps and the existing empty-map projection", async () => {
  const { actions, transport } = setup();
  const desired = {
    name: "Snippet",
    template: "echo",
    tags: {},
    variables: {},
  };
  transport.next = async (_method, options) => ({
    value: resource(
      { name: "Snippet", template: "echo" },
      (options.body as { id: string }).id,
    ),
    etag: '"v1"',
  });
  await actions.create(desired);
  transport.next = async (_method, options) => ({
    value: resource(
      {
        ...fields,
        variables: Object.fromEntries(
          Object.entries(fields.variables!).reverse(),
        ),
        tags: Object.fromEntries(Object.entries(fields.tags!).reverse()),
      },
      (options.body as { id: string }).id,
    ),
    etag: '"v1"',
  });
  await actions.create(fields);
});
test("uncertain and stale PUT/DELETE require successful explicit refresh before new edits, without replay", async () => {
  for (const failure of [
    new RequestFailure("outcome_unknown", 503, true),
    new RequestFailure("organization.precondition_failed", 412),
    new Error("malformed success"),
  ]) {
    for (const mode of ["replace", "remove"] as const) {
      const { actions, transport } = setup();
      transport.next = async () => {
        throw failure;
      };
      await assert.rejects(
        mode === "replace"
          ? actions.replace(resource(), fields)
          : actions.remove(resource()),
      );
      assert.equal(actions.reviewRequired, true);
      assert.equal(actions.pending, undefined);
      await assert.rejects(actions.replace(resource(), fields));
      assert.equal(transport.calls.length, 1);
      await assert.rejects(actions.review());
      assert.equal(actions.reviewRequired, true);
      transport.next = async () => ({
        value: { items: [resource()], next_cursor: null },
        etag: null,
      });
      await actions.review();
      assert.equal(actions.reviewRequired, false);
      assert.deepEqual(
        transport.calls.map((call) => call.method),
        [mode === "replace" ? "PUT" : "DELETE", "GET", "GET"],
      );
    }
  }
});
test("Account, origin, fresh-family changes and disposal fence late replies and clear original intents", async () => {
  for (const change of ["account", "origin", "family", "dispose"] as const) {
    const { actions, api, transport } = setup();
    let resolve!: (value: ApiResponse) => void;
    transport.next = () =>
      new Promise((done) => {
        resolve = done;
      });
    const submitted = actions.create(fields),
      pending = actions.pending!;
    if (change === "account") api.accountId = id;
    if (change === "origin") transport.origin = "https://other.example";
    if (change === "family") transport.sessionGeneration++;
    if (change === "dispose") actions.dispose();
    resolve({ value: resource(fields, pending.body.id), etag: '"v1"' });
    await assert.rejects(
      submitted,
      (error) =>
        error instanceof RequestFailure && error.code === "session_changed",
    );
    assert.equal(actions.pending, undefined);
    await assert.rejects(actions.list());
    assert.equal(transport.calls.length, 1);
  }
});
test("production Account transport admits the five Snippet routes with fresh exact proofs and protected headers", async () => {
  const proof = await AccountProofKey.create(),
    origin = "https://console.example";
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
    "snippet.owner",
    new TextEncoder().encode("a valid fixture password"),
  );
  const key = "019a0000-0000-7000-8000-000000000004",
    proofs = new Set<string>();
  const response = (value: unknown, status = 200, page = false) =>
    new Response(status === 204 ? null : JSON.stringify(value), {
      status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "X-Request-ID": "snippet-fixture",
        ...(!page && status !== 204 ? { ETag: '"v1"' } : {}),
      },
    });
  const fetchMock = mock.method(
    globalThis,
    "fetch",
    async (url: string, options: RequestInit) => {
      assert.equal(options.credentials, "omit");
      assert.equal(options.redirect, "error");
      const headers = new Headers(options.headers),
        claims = JSON.parse(
          Buffer.from(headers.get("DPoP")!.split(".")[1], "base64url").toString(
            "utf8",
          ),
        );
      assert.equal(claims.htm, options.method);
      assert.equal(claims.htu, origin + new URL(url).pathname);
      assert.ok(claims.ath);
      assert.ok(!proofs.has(claims.jti));
      proofs.add(claims.jti);
      assert.equal(headers.has("Cookie"), false);
      if (options.method === "DELETE") {
        assert.equal(headers.get("If-Match"), '"v1"');
        assert.equal(options.body, undefined);
        return response({}, 204);
      }
      if (options.method === "POST") {
        assert.equal(headers.get("Idempotency-Key"), key);
        assert.equal(headers.get("If-Match"), null);
        assert.deepEqual(JSON.parse(String(options.body)), {
          id,
          data: { fields },
        });
        return response(resource(), 201);
      }
      if (options.method === "PUT")
        assert.equal(headers.get("If-Match"), '"v1"');
      return url.includes("?")
        ? response({ items: [resource()], next_cursor: null }, 200, true)
        : response(resource());
    },
  );
  try {
    const api = new TeamApi(client);
    api.accountId = account;
    const actions = new SnippetActions(api, org, account);
    await actions.list();
    await actions.read(id);
    await api.save(org, "snippets", fields, undefined, { id, key });
    await actions.replace(resource(), fields);
    await actions.remove(resource());
    assert.equal(proofs.size, 5);
  } finally {
    fetchMock.mock.restore();
    client.lock();
  }
});
