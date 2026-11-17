// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  InventoryCsvFailure,
  InventoryImportApi,
  InventoryImportWorkflow,
  csvFailure,
  parsedInventoryCsv,
  parseImportResult,
  type InventoryCsvParser,
} from "./inventory-import.ts";
import type {
  InventoryImportFields,
  InventoryImportRequest,
} from "./generated/api.ts";
import {
  RequestFailure,
  TeamApi,
  type AccountTransport,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";
import { AccountClient } from "./account.ts";
import { AccountProofKey } from "./account-proof.ts";
import { encoded } from "./wire.ts";

const organization = "019a0000-0000-7000-8000-000000000001";
const account = "019a0000-0000-7000-8000-000000000002";
const fields: InventoryImportFields[] = [
  {
    name: " Web <&> ",
    address: " example.test ",
    port: 22,
    username: " ops ",
    login_name: " Operations ",
  },
];
const file = (source = "private fixture source") =>
  new File([source], "inventory.csv");
const pairs = (body: InventoryImportRequest) => ({
  items: body.rows.map(({ host_id, access_profile_id }) => ({
    host_id,
    access_profile_id,
  })),
});
class Transport implements AccountTransport {
  readonly origin = "https://console.example";
  calls: { method: Method; path: string; options: RequestOptions }[] = [];
  next: (options: RequestOptions) => Promise<ApiResponse> = async (
    options,
  ) => ({ value: pairs(options.body as InventoryImportRequest), etag: null });
  async request(
    method: Method,
    path: string,
    options: RequestOptions = {},
  ): Promise<ApiResponse> {
    this.calls.push({ method, path, options });
    return this.next(options);
  }
}
const setup = (parser: InventoryCsvParser = { parse: async () => fields }) => {
  const transport = new Transport(),
    team = new TeamApi(transport);
  team.accountId = account;
  const api = new InventoryImportApi(team, organization, account);
  return {
    transport,
    team,
    api,
    workflow: new InventoryImportWorkflow(api, parser),
  };
};

test("preparation calls the shared parser once, preserves its fields and freezes all preview ids without sending", async () => {
  let calls = 0,
    owned: Uint8Array | undefined;
  const { workflow, transport } = setup({
    parse: async (input) => {
      calls++;
      owned = input;
      assert.equal(new TextDecoder().decode(input), "private fixture source");
      return [
        ...fields,
        { name: "Second", address: "second.test", port: 2200, username: "ops" },
      ];
    },
  });
  const parsing = workflow.prepare(file());
  assert.equal(workflow.state.phase, "parsing");
  await parsing;
  assert.equal(calls, 1);
  assert.ok(owned!.every((byte) => byte === 0));
  assert.equal(transport.calls.length, 0);
  const body = workflow.state.preview!;
  assert.equal(body.rows.length, 2);
  assert.deepEqual(
    {
      name: body.rows[0].name,
      address: body.rows[0].address,
      port: body.rows[0].port,
      username: body.rows[0].username,
      login_name: body.rows[0].login_name,
    },
    fields[0],
  );
  assert.equal("login_name" in body.rows[1], false);
  const ids = body.rows.flatMap((row) => [row.host_id, row.access_profile_id]);
  assert.equal(new Set(ids).size, 4);
  for (const id of ids)
    assert.match(
      id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  assert.ok(
    Object.isFrozen(body) &&
      Object.isFrozen(body.rows) &&
      body.rows.every(Object.isFrozen),
  );
  await workflow.submit();
  assert.equal(workflow.state.phase, "complete");
  assert.equal(workflow.state.imported, 2);
  assert.equal(workflow.state.preview, undefined);
  assert.equal(transport.calls.length, 1);
  assert.equal(transport.calls[0].options.body, body);
});

test("fixed parser metadata is safe, malformed errors never expose private source, and raw overflow is rejected before reading", async () => {
  const known = csvFailure(
    '{"kind":"invalid_cell","record":2,"field":"username","source":"private fixture source"}',
  );
  assert.equal(known.kind, "invalid_cell");
  assert.equal(known.record, 2);
  assert.equal(known.field, "username");
  assert.doesNotMatch(JSON.stringify(known), /private fixture source/);
  for (const error of [
    "private fixture source",
    '{"kind":"bad private text"}',
    '{"kind":"invalid_cell","record":0}',
    '{"kind":"invalid_cell","field":"private fixture source"}',
    '{"kind":"invalid_csv","record":102}',
    new Error("private fixture source"),
  ]) {
    assert.equal(csvFailure(error).kind, "unavailable");
    assert.doesNotMatch(
      JSON.stringify(csvFailure(error)),
      /private fixture source/,
    );
  }
  const { workflow, transport } = setup({
    parse: async () => {
      throw known;
    },
  });
  await workflow.prepare(file());
  assert.equal(workflow.state.failure, known);
  assert.equal(workflow.state.preview, undefined);
  await workflow.prepare({
    size: 1_048_577,
    arrayBuffer: async () => {
      throw new Error("must not read");
    },
  });
  assert.equal(
    (workflow.state.failure as InventoryCsvFailure).kind,
    "too_large",
  );
  assert.equal(transport.calls.length, 0);
});

test("unknown import keeps its exact body, key, ids and original context, with no automatic retry", async () => {
  const { workflow, transport, api } = setup();
  await workflow.prepare(file());
  transport.next = async () => {
    throw new RequestFailure("response_lost", 0, true);
  };
  const submission = workflow.submit();
  assert.equal(workflow.state.phase, "importing");
  await submission;
  assert.equal(workflow.state.phase, "uncertain");
  const original = workflow.state.pending!;
  assert.equal(original.context, api.context);
  assert.deepEqual(original.context, {
    origin: transport.origin,
    account,
    organization,
    sessionGeneration: undefined,
  });
  assert.ok(Object.isFrozen(original) && Object.isFrozen(original.context));
  await workflow.prepare(file("another source"));
  await workflow.submit();
  await Promise.resolve();
  assert.equal(transport.calls.length, 1);
  assert.equal(workflow.state.pending, original);
  transport.next = async (options) => ({
    value: pairs(options.body as InventoryImportRequest),
    etag: null,
  });
  const confirmation = workflow.confirmOriginal();
  assert.equal(workflow.state.phase, "confirming");
  await confirmation;
  assert.equal(workflow.state.phase, "complete");
  assert.equal(transport.calls.length, 2);
  for (const call of transport.calls) {
    assert.equal(call.options.body, original.body);
    assert.equal(call.options.key, original.key);
    assert.equal(call.path, `/api/v1/orgs/${organization}/inventory/imports`);
    assert.equal(call.options.maximum, 32_768);
    assert.equal(call.options.success, 201);
    assert.equal(call.options.etag, undefined);
  }
});

test("a denied confirmation and expiry never settle an earlier uncertain import", async () => {
  const { workflow, transport } = setup();
  await workflow.prepare(file());
  transport.next = async () => {
    throw new RequestFailure(
      "organization.commit_outcome_unknown",
      503,
      true,
      true,
    );
  };
  await workflow.submit();
  const original = workflow.state.pending!;
  transport.next = async () => {
    throw new RequestFailure("policy.denied", 403);
  };
  await workflow.confirmOriginal();
  assert.equal(workflow.state.phase, "uncertain");
  assert.equal(workflow.state.pending, original);
  const clock = mock.method(Date, "now", () => original.deadline);
  try {
    await workflow.confirmOriginal();
  } finally {
    clock.mock.restore();
  }
  assert.equal(transport.calls.length, 2);
  assert.equal(workflow.state.pending, original);
});

test("confirmed initial rejection preserves the reviewed preview and separates authority failure from uncertainty", async () => {
  const { workflow, transport } = setup();
  await workflow.prepare(file());
  const preview = workflow.state.preview;
  transport.next = async () => {
    throw new RequestFailure("policy.denied", 403);
  };
  await workflow.submit();
  assert.equal(workflow.state.phase, "preview");
  assert.equal(workflow.state.preview, preview);
  assert.equal(workflow.state.pending, undefined);
});

test("count, order, each identifier and duplicate JSON names are checked before success", async () => {
  const { workflow, transport } = setup({
    parse: async () => [...fields, ...fields],
  });
  await workflow.prepare(file());
  const body = workflow.state.preview!,
    result = pairs(body);
  assert.deepEqual(
    parseImportResult(JSON.stringify({ ...result, future: {} }), body),
    result,
  );
  const invalid = [
    { items: [] },
    { items: [...result.items].reverse() },
    { items: [result.items[0], result.items[0]] },
    { items: result.items.map((item) => ({ ...item, host_id: account })) },
    {
      items: [{ ...result.items[0], access_profile_id: null }, result.items[1]],
    },
  ];
  for (const value of invalid)
    assert.throws(() => parseImportResult(JSON.stringify(value), body));
  assert.throws(() =>
    parseImportResult(
      `{"items":[],"items":${JSON.stringify(result.items)}}`,
      body,
    ),
  );
  assert.throws(() =>
    parseImportResult(
      `{"items":${JSON.stringify(result.items)},"extension":{"x":1,"x":2}}`,
      body,
    ),
  );
  transport.next = async () => ({ value: invalid[1], etag: null });
  await workflow.submit();
  assert.equal(workflow.state.phase, "uncertain");
  assert.ok(workflow.state.pending);
  assert.equal(workflow.state.imported, 0);
});

test("team/session disposal clears previews and original intents and fences both late parser and successful response", async () => {
  let parse!: (value: InventoryImportFields[]) => void;
  const first = setup({
    parse: () =>
      new Promise((resolve) => {
        parse = resolve;
      }),
  });
  const parsing = first.workflow.prepare(file());
  while (!parse) await new Promise<void>((resolve) => setImmediate(resolve));
  first.workflow.dispose();
  parse(fields);
  await assert.rejects(
    parsing,
    (error) =>
      error instanceof RequestFailure && error.code === "session_changed",
  );
  assert.equal(first.workflow.state.preview, undefined);
  assert.equal(first.transport.calls.length, 0);
  const { workflow, transport } = setup();
  await workflow.prepare(file());
  let release!: (value: ApiResponse) => void;
  transport.next = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const sending = workflow.submit();
  const original = workflow.state.pending!;
  workflow.dispose();
  release({ value: pairs(original.body), etag: null });
  await assert.rejects(
    sending,
    (error) =>
      error instanceof RequestFailure && error.code === "session_changed",
  );
  assert.equal(workflow.state.pending, undefined);
  assert.equal(workflow.state.phase, "empty");
  await assert.rejects(workflow.confirmOriginal());
  assert.equal(transport.calls.length, 1);
});

test("the captured Account context cannot be changed for original confirmation", async () => {
  const { workflow, transport, team } = setup();
  await workflow.prepare(file());
  transport.next = async () => {
    throw new RequestFailure("response_lost", 0, true);
  };
  await workflow.submit();
  team.accountId = organization;
  await assert.rejects(workflow.confirmOriginal());
  assert.equal(transport.calls.length, 1);
  assert.equal(workflow.state.pending, undefined);
  assert.equal(workflow.state.preview, undefined);
});

test("the shared parser projection is decoded without trimming or changing omitted names", () => {
  assert.deepEqual(
    parsedInventoryCsv(JSON.stringify({ rows: fields })),
    fields,
  );
  const withoutName = {
    name: "Host",
    address: "host.test",
    port: 22,
    username: "root",
  };
  assert.deepEqual(
    parsedInventoryCsv(JSON.stringify({ rows: [withoutName] })),
    [withoutName],
  );
  for (const rows of [
    [],
    Array(101).fill(withoutName),
    [{ ...withoutName, port: "22" }],
    [{ ...withoutName, login_name: null }],
  ])
    assert.throws(() => parsedInventoryCsv(JSON.stringify({ rows })));
});

test("preparation refuses colliding ids and a JSON body over its complete encoded budget before dispatch", async () => {
  const { workflow, transport } = setup();
  const clock = mock.method(Date, "now", () => 1_900_000_000_000);
  const random = mock.method(crypto, "getRandomValues", (output: Uint8Array) =>
    output.fill(1),
  );
  try {
    await workflow.prepare(file());
    assert.equal(
      (workflow.state.failure as InventoryCsvFailure).kind,
      "unavailable",
    );
    assert.equal(workflow.state.preview, undefined);
    assert.equal(transport.calls.length, 0);
  } finally {
    clock.mock.restore();
    random.mock.restore();
  }
  const oversized = setup({
    parse: async () =>
      Array.from({ length: 100 }, () => ({
        ...fields[0],
        name: "\t".repeat(16_384),
      })),
  });
  await oversized.workflow.prepare(file());
  assert.equal(
    (oversized.workflow.state.failure as InventoryCsvFailure).kind,
    "request_too_large",
  );
  assert.equal(oversized.workflow.state.preview, undefined);
  assert.equal(oversized.transport.calls.length, 0);
});

test("operation-key preparation failure is local and never fabricates an uncertain import", async () => {
  const { workflow, transport } = setup();
  await workflow.prepare(file());
  const body = workflow.state.preview;
  const random = mock.method(crypto, "getRandomValues", () => {
    throw new Error("random unavailable");
  });
  try {
    await workflow.submit();
    assert.equal(workflow.state.phase, "preview");
    assert.equal(workflow.state.preview, body);
    assert.equal(workflow.state.pending, undefined);
    assert.equal(
      (workflow.state.failure as RequestFailure).code,
      "import_preparation_failed",
    );
    assert.equal(transport.calls.length, 0);
  } finally {
    random.mock.restore();
  }
});

test("production Account transport keeps original import identity across same-family refresh with fresh proofs and bounded replies", async () => {
  const proof = await AccountProofKey.create();
  const access = (byte: number) =>
    `ab1_${encoded(new Uint8Array(32).fill(byte))}`;
  const session = (byte: number, remaining = 2_592_000) => ({
    access_token: access(byte),
    token_type: "DPoP",
    expires_in: 600,
    refresh_expires_in: remaining,
  });
  const origin = "https://console.example",
    start = Date.now();
  const client = new AccountClient(origin, {
    run: async () => ({
      ...proof.transfer(),
      session: session(1),
      startedAt: start,
    }),
  });
  await client.signIn(
    "import.owner",
    new TextEncoder().encode("valid fixture password"),
  );
  const api = new TeamApi(client);
  api.accountId = account;
  const workflow = new InventoryImportWorkflow(
    new InventoryImportApi(api, organization, account),
    { parse: async () => fields },
  );
  await workflow.prepare(file());
  const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
  Object.defineProperty(navigator, "locks", {
    configurable: true,
    value: {
      request: async (_name: string, action: () => Promise<void>) => action(),
    },
  });
  let imports = 0,
    refreshes = 0;
  const sent: { body: string; key: string }[] = [],
    proofs = new Set<string>();
  const response = (source: string, status: number) =>
    new Response(source, {
      status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        Pragma: "no-cache",
        "X-Request-ID": "import-boundary",
      },
    });
  const fetchMock = mock.method(
    globalThis,
    "fetch",
    async (input: RequestInfo | URL, options?: RequestInit) => {
      const url = String(input),
        headers = new Headers(options?.headers);
      const claims = JSON.parse(
        Buffer.from(headers.get("DPoP")!.split(".")[1], "base64url").toString(
          "utf8",
        ),
      );
      assert.equal(claims.htm, "POST");
      assert.equal(claims.htu, url);
      assert.ok(!proofs.has(claims.jti));
      proofs.add(claims.jti);
      assert.equal(options?.cache, "no-store");
      assert.equal(options?.redirect, "error");
      if (url.endsWith("/browser/refresh")) {
        refreshes++;
        assert.equal(options?.credentials, "same-origin");
        assert.equal(headers.get("Authorization"), null);
        return response(JSON.stringify(session(2, 2_591_429)), 200);
      }
      imports++;
      assert.equal(
        url,
        `${origin}/api/v1/orgs/${organization}/inventory/imports`,
      );
      assert.equal(options?.credentials, "omit");
      assert.equal(headers.get("If-Match"), null);
      assert.equal(
        headers.get("Authorization"),
        `DPoP ${access(imports === 1 ? 1 : 2)}`,
      );
      assert.ok(claims.ath);
      sent.push({
        body: String(options?.body),
        key: headers.get("Idempotency-Key")!,
      });
      if (imports === 1) throw new Error("lost acknowledgement");
      const source = JSON.stringify(
        pairs(JSON.parse(sent[0].body) as InventoryImportRequest),
      );
      return response(
        source + " ".repeat((imports === 2 ? 32_769 : 32_768) - source.length),
        201,
      );
    },
  );
  let clock: ReturnType<typeof mock.method> | undefined;
  try {
    await workflow.submit();
    assert.equal(workflow.state.phase, "uncertain");
    const original = workflow.state.pending!;
    clock = mock.method(Date, "now", () => start + 571_000);
    await workflow.confirmOriginal();
    assert.equal(refreshes, 1);
    assert.equal(workflow.state.phase, "uncertain");
    assert.equal(workflow.state.pending, original);
    assert.equal(
      (workflow.state.failure as RequestFailure).code,
      "invalid_response",
    );
    await workflow.confirmOriginal();
    assert.equal(workflow.state.phase, "complete");
    assert.equal(refreshes, 1);
    assert.equal(imports, 3);
    assert.equal(proofs.size, 4);
    assert.deepEqual(sent, [sent[0], sent[0], sent[0]]);
    assert.equal(original.context, workflow.api.context);
    assert.equal(client.sessionGeneration, original.context.sessionGeneration);
    client.lock();
    assert.notEqual(
      client.sessionGeneration,
      original.context.sessionGeneration,
    );
  } finally {
    fetchMock.mock.restore();
    clock?.mock.restore();
    if (previousLocks) Object.defineProperty(navigator, "locks", previousLocks);
    else Reflect.deleteProperty(navigator, "locks");
  }
});

test("an old import intent cannot be submitted under a fresh login family for the same Account", async () => {
  const proof = await AccountProofKey.create();
  const client = new AccountClient("https://console.example", {
    run: async () => ({
      ...proof.transfer(),
      session: {
        access_token: `ab1_${encoded(new Uint8Array(32).fill(1))}`,
        token_type: "DPoP",
        expires_in: 600,
        refresh_expires_in: 2_592_000,
      },
      startedAt: Date.now(),
    }),
  });
  const login = () =>
    client.signIn(
      "import.owner",
      new TextEncoder().encode("valid fixture password"),
    );
  await login();
  const api = new TeamApi(client);
  api.accountId = account;
  const workflow = new InventoryImportWorkflow(
    new InventoryImportApi(api, organization, account),
    { parse: async () => fields },
  );
  await workflow.prepare(file());
  let posts = 0;
  const fetchMock = mock.method(globalThis, "fetch", async () => {
    posts++;
    throw new Error("lost acknowledgement");
  });
  try {
    await workflow.submit();
    const original = workflow.state.pending!;
    assert.equal(posts, 1);
    client.lock();
    await login();
    assert.equal(api.accountId, original.context.account);
    assert.notEqual(
      client.sessionGeneration,
      original.context.sessionGeneration,
    );
    await assert.rejects(workflow.confirmOriginal());
    assert.equal(posts, 1);
    assert.equal(workflow.state.pending, undefined);
    assert.equal(workflow.state.preview, undefined);
    assert.equal(workflow.state.phase, "empty");
  } finally {
    fetchMock.mock.restore();
  }
});
