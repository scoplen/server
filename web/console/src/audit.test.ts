// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { afterEach, mock, test } from "node:test";
import {
  AuditApi,
  AuditInputError,
  auditRange,
  auditSequence,
  auditTime,
  emptyAuditFilters,
  parseAuditPage,
  parseAuditVerification,
} from "./audit.ts";
import { AccountProofKey } from "./account-proof.ts";
import { AccountClient } from "./account.ts";
import { AccountFailure, accountFetch } from "./account-http.ts";
import type { AccountTransport, RequestOptions } from "./team.ts";
import { encoded } from "./wire.ts";

const origin = "https://console.example";
const org = "019a0000-0000-7000-8000-000000000001";
const actor = "019a0000-0000-7000-8000-000000000002";
const target = "019a0000-0000-7000-8000-000000000003";
const zero = "0".repeat(64);
const head = "a".repeat(64);
const signature = encoded(new Uint8Array(64));
const range = auditRange("1", "3");
const event = (sequence = "3") => ({
  organization_id: org,
  sequence,
  occurred_at: "2026-11-01T00:00:00.001Z",
  category: "scoplen",
  event_class: "organization.inventory_created",
  outcome: "success",
  actor_account_id: actor,
  actor_device_id: null,
  actor_browser_family_id: null,
  resource: { kind: "host", id: target },
  previous_hash: zero,
  event_hash: head,
});
const page = (
  items: unknown[] = [event()],
  next_cursor: string | null = null,
) => JSON.stringify({ items, next_cursor });
const result = () => ({
  organization_id: org,
  ...range,
  checked_events: "3",
  valid: true,
  failure_sequence: null,
  previous_hash: zero,
  head_hash: head,
  checkpoint: null,
  uncheckpointed_from_sequence: "1",
});
function parseResult(value: unknown, selected = range) {
  return parseAuditVerification(JSON.stringify(value), org, selected);
}
function response(source: string, status = 200, headers = {}) {
  return new Response(source, {
    status,
    headers: {
      "Content-Type":
        status === 200 ? "application/json" : "application/problem+json",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      "X-Request-ID": "audit-test",
      ...headers,
    },
  });
}
afterEach(() => mock.restoreAll());

test("audit sequences and inclusive ranges preserve the complete uint64 domain", () => {
  for (const value of ["1", "9007199254740993", "18446744073709551615"])
    assert.equal(auditSequence(value), value);
  assert.equal(auditSequence("0", true), "0");
  for (const value of [
    "0",
    "01",
    "-1",
    "1.0",
    "1e3",
    "18446744073709551616",
    3,
  ])
    assert.throws(() => auditSequence(value));
  assert.deepEqual(auditRange("9007199254740993", "9007199254745088"), {
    from_sequence: "9007199254740993",
    to_sequence: "9007199254745088",
  });
  for (const [from, to] of [
    ["1", "4097"],
    ["3", "2"],
    ["0", "1"],
    [" 1", "2"],
  ])
    assert.throws(() => auditRange(from, to), AuditInputError);
});

test("audit timestamps retain normalized reversible milliseconds", () => {
  for (const suffix of ["Z", ".001Z", ".01Z", ".1Z", ".999Z"])
    assert.equal(
      auditTime(`2026-11-01T00:00:00${suffix}`, true),
      `2026-11-01T00:00:00${suffix}`,
    );
  for (const value of [
    "2026-11-01T00:00:00.000Z",
    "2026-11-01T00:00:00.010Z",
    "2026-11-01T00:00:00.0001Z",
    "2026-02-30T00:00:00Z",
    "2026-11-01T00:00:00+00:00",
    "1970-01-01T00:00:00Z",
  ])
    assert.throws(() => auditTime(value, true));
});

test("audit pages bind tenant, exact descending sequence, cursor, count and continuation", () => {
  assert.equal(
    parseAuditPage(
      page([event("9007199254740994"), event("9007199254740993")]),
      org,
    ).items[1].sequence,
    "9007199254740993",
  );
  assert.deepEqual(parseAuditPage(page([]), org), {
    items: [],
    next_cursor: null,
  });
  for (const source of [
    page([{ ...event(), organization_id: actor }]),
    page([event("2"), event("3")]),
    page([event(), event()]),
    page([event()], "2"),
    page([], "3"),
    page([{ ...event(), sequence: 3 }]),
  ])
    assert.throws(() => parseAuditPage(source, org));
  assert.throws(() => parseAuditPage(page(), org, emptyAuditFilters(), "3"));
  assert.throws(() =>
    parseAuditPage(
      page([event("3"), event("2")]),
      org,
      emptyAuditFilters(),
      undefined,
      1,
    ),
  );
  assert.equal(
    parseAuditPage(page([event("2")], "2"), org, emptyAuditFilters(), "3")
      .next_cursor,
    "2",
  );
});

test("published Grant audit kinds remain distinct from unknown labels", () => {
  const input = {
    ...event(),
    category: "authorization",
    event_class: "organization.grants_created",
    resource: { kind: "grant", id: target },
  };
  assert.deepEqual(
    parseAuditPage(page([input]), org).items[0].resource,
    input.resource,
  );
  for (const kind of ["Grant", "grants", "grant-extra"])
    assert.throws(() =>
      parseAuditPage(page([{ ...input, resource: { kind, id: target } }]), org),
    );
});

test("draft audit filtering retains the exact generation and writer", () => {
  const created = {
    ...event(),
    event_class: "organization.auth_draft_created",
    actor_device_id: actor,
    resource: { kind: "auth_connection_draft", id: target },
  };
  const filters = { ...emptyAuditFilters(), resource: `auth_connection_draft:${target}` };
  assert.deepEqual(parseAuditPage(page([created]), org, filters).items, [created]);
  assert.throws(() =>
    parseAuditPage(page([{ ...created, resource: { ...created.resource, id: actor } }]), org, filters),
  );
});

test("access-request audit events survive timeline decoding and filtered Account HTTP paging", async () => {
  const items = ["created", "approved", "denied", "cancelled", "expired"].map(
    (action, index) => ({
      ...event(String(6 - index)),
      category: "authorization",
      event_class: `organization.access_request_${action}`,
      actor_account_id: action === "expired" ? null : actor,
      actor_browser_family_id: action === "expired" ? null : target,
      resource: { kind: "access_request", id: target },
    }),
  );
  assert.deepEqual(parseAuditPage(page([...items, event("1")]), org).items, [
    ...items,
    event("1"),
  ]);
  for (const kind of ["AccessRequest", "access_requests", "access-request"])
    assert.throws(() =>
      parseAuditPage(
        page([{ ...items[0], resource: { kind, id: target } }]),
        org,
      ),
    );
  const key = await AccountProofKey.create();
  let calls = 0;
  mock.method(
    globalThis,
    "fetch",
    async (url: string, options: RequestInit) => {
      calls++;
      const request = new URL(url);
      assert.equal(request.pathname, `/api/v1/orgs/${org}/audit-events`);
      assert.equal(options.method, "GET");
      assert.equal(options.credentials, "omit");
      assert.equal(
        request.searchParams.get("filter"),
        `resource eq "access_request:${target}"`,
      );
      assert.equal(
        request.searchParams.get("cursor"),
        calls === 1 ? null : "4",
      );
      return response(
        calls === 1 ? page(items.slice(0, 3), "4") : page(items.slice(3)),
      );
    },
  );
  const api = new AuditApi({
    origin,
    request: (method, path, options) =>
      accountFetch({
        origin,
        key,
        method,
        path,
        options,
        token: "token",
        operation: "request",
      }),
  });
  const filters = {
    ...emptyAuditFilters(),
    resource: `access_request:${target}`,
  };
  const first = await api.list(org, filters);
  assert.equal(first.next_cursor, "4");
  const earlier = await api.list(org, filters, first.next_cursor!);
  assert.equal(earlier.next_cursor, null);
  assert.deepEqual([...first.items, ...earlier.items], items);
  await assert.rejects(
    api.list(org, { ...filters, resource: `access_requests:${target}` }),
    AuditInputError,
  );
  assert.equal(calls, 2);
});

test("required nullable audit attribution stays explicit and unclassified events stay unknown", () => {
  const unknown = {
    ...event(),
    category: "unknown",
    event_class: null,
    outcome: "unknown",
    actor_account_id: null,
    resource: null,
  };
  assert.equal(
    parseAuditPage(page([unknown]), org).items[0].actor_account_id,
    null,
  );
  for (const field of Object.keys(event())) {
    const input: Record<string, unknown> = { ...event() };
    delete input[field];
    assert.throws(() => parseAuditPage(page([input]), org), field);
  }
  for (const patch of [
    { category: "invented" },
    { outcome: "ok" },
    { event_class: "<script>" },
    { actor_account_id: "unknown" },
    { previous_hash: "A".repeat(64) },
    { resource: { kind: "password", id: target } },
  ])
    assert.throws(() => parseAuditPage(page([{ ...event(), ...patch }]), org));
});

test("audit decoders reject recursive duplicates, BOMs and complete source byte overflow", () => {
  const valid = page();
  for (const source of [
    `\uFEFF${valid}`,
    valid.replace('"items":', '"extension":{"same":1,"s\\u0061me":2},"items":'),
    valid.replace('"sequence":"3"', '"sequence":"3","sequ\\u0065nce":"3"'),
    `${" ".repeat(1_048_576)}${valid}`,
  ])
    assert.throws(() => parseAuditPage(source, org));
  const object = JSON.stringify(event());
  const exact =
    object.slice(0, -1) + " ".repeat(2_048 - Buffer.byteLength(object)) + "}";
  assert.equal(
    parseAuditPage(`{"items":[${exact}],"next_cursor":null}`, org).items.length,
    1,
  );
  assert.throws(() =>
    parseAuditPage(
      `{"items":[${exact.slice(0, -1)} }],"next_cursor":null}`,
      org,
    ),
  );
  const unicode = JSON.stringify({ ...event(), extension: "界".repeat(600) });
  assert.ok(unicode.length < 2_048 && Buffer.byteLength(unicode) > 2_048);
  assert.throws(() =>
    parseAuditPage(`{"it\\u0065ms":[${unicode}],"next_cursor":null}`, org),
  );
});

test("all six audit filters encode as AND clauses and bind each returned row", async () => {
  const filters = {
    fromTime: "2026-11-01T00:00:00Z",
    beforeTime: "2026-11-02T00:00:00Z",
    actor,
    resource: `host:${target}`,
    eventClass: event().event_class,
    outcome: "success",
  };
  let calls = 0;
  let answer = event();
  const api = new AuditApi({
    origin,
    request: async (method, path, options) => {
      calls++;
      assert.equal(method, "GET");
      const url = new URL(path, origin);
      assert.equal(url.pathname, `/api/v1/orgs/${org}/audit-events`);
      assert.equal(
        url.searchParams.get("filter"),
        `occurred_at ge "${filters.fromTime}" and occurred_at lt "${filters.beforeTime}" and actor_account_id eq "${actor}" and event_class eq "${filters.eventClass}" and resource eq "host:${target}" and outcome eq "success"`,
      );
      assert.equal(options?.maximum, 1_048_576);
      return { value: options!.decode!(page([answer])), etag: null };
    },
  });
  assert.equal((await api.list(org, filters)).items.length, 1);
  for (const patch of [
    { occurred_at: "2026-11-02T00:00:00Z" },
    { actor_account_id: target },
    { event_class: "organization.created" },
    { outcome: "failure" },
    { resource: { kind: "host", id: actor } },
  ]) {
    answer = { ...event(), ...patch };
    await assert.rejects(api.list(org, filters));
  }
  assert.equal(calls, 6);
});

test("invalid filter/range input never dispatches a request and captured filters cannot change in flight", async () => {
  let calls = 0;
  let decode: RequestOptions["decode"];
  let complete!: (value: { value: unknown; etag: null }) => void;
  const api = new AuditApi({
    origin,
    request: async (_method, _path, options) => {
      calls++;
      decode = options?.decode;
      return new Promise((resolve) => {
        complete = resolve;
      });
    },
  });
  for (const patch of [
    { actor: "bad" },
    { resource: target },
    { eventClass: "bad class" },
    { outcome: "other" },
    { fromTime: "2026-02-30T00:00:00Z" },
    { fromTime: "1970-01-01T00:00:00Z" },
    { fromTime: "2026-11-02T00:00:00Z", beforeTime: "2026-11-01T00:00:00Z" },
  ])
    await assert.rejects(
      api.list(org, { ...emptyAuditFilters(), ...patch }),
      AuditInputError,
    );
  await assert.rejects(
    api.verify(org, { from_sequence: "1", to_sequence: "4097" }),
    AuditInputError,
  );
  assert.equal(calls, 0);
  const filters = { ...emptyAuditFilters(), actor };
  const pending = api.list(org, filters);
  filters.actor = target;
  assert.throws(() =>
    decode!(page([{ ...event(), actor_account_id: target }])),
  );
  complete({ value: decode!(page()), etag: null });
  assert.equal((await pending).items[0].actor_account_id, actor);
});

test("verification distinguishes unsigned intervals, included checkpoints and uncovered suffixes", () => {
  assert.equal(parseResult(result()).uncheckpointed_from_sequence, "1");
  const checkpoint = {
    sequence: "2",
    head_hash: zero,
    signed_at: "2026-11-01T00:00:00.01Z",
    signature,
  };
  assert.equal(
    parseResult({ ...result(), checkpoint, uncheckpointed_from_sequence: "3" })
      .checkpoint?.sequence,
    "2",
  );
  assert.equal(
    parseResult({
      ...result(),
      checkpoint: { ...checkpoint, sequence: "3", head_hash: head },
      uncheckpointed_from_sequence: null,
    }).uncheckpointed_from_sequence,
    null,
  );
  const high = auditRange("9007199254740993", "9007199254740994");
  assert.equal(
    parseResult(
      {
        ...result(),
        ...high,
        checked_events: "2",
        previous_hash: head,
        uncheckpointed_from_sequence: high.from_sequence,
      },
      high,
    ).to_sequence,
    high.to_sequence,
  );
});

test("verification binds requested range and rejects inconsistent failure and checkpoint evidence", () => {
  const failure = {
    ...result(),
    valid: false,
    checked_events: "1",
    failure_sequence: "2",
    previous_hash: null,
    head_hash: null,
    uncheckpointed_from_sequence: null,
  };
  assert.equal(parseResult(failure).valid, false);
  for (const patch of [
    { checked_events: "0" },
    { failure_sequence: "4" },
    { failure_sequence: null },
    { previous_hash: zero },
    { head_hash: head },
    { uncheckpointed_from_sequence: "1" },
    {
      checkpoint: {
        sequence: "2",
        head_hash: head,
        signed_at: event().occurred_at,
        signature,
      },
    },
  ])
    assert.throws(() => parseResult({ ...failure, ...patch }));
  for (const patch of [
    { organization_id: actor },
    { from_sequence: "2" },
    { to_sequence: "4" },
    { checked_events: "2" },
    { failure_sequence: "1" },
    { previous_hash: head },
    { head_hash: null },
    { uncheckpointed_from_sequence: null },
    {
      checkpoint: {
        sequence: "4",
        head_hash: head,
        signed_at: event().occurred_at,
        signature,
      },
    },
    {
      checkpoint: {
        sequence: "3",
        head_hash: zero,
        signed_at: event().occurred_at,
        signature,
      },
      uncheckpointed_from_sequence: null,
    },
    {
      checkpoint: {
        sequence: "2",
        head_hash: head,
        signed_at: event().occurred_at,
        signature: signature + "=",
      },
      uncheckpointed_from_sequence: "3",
    },
  ])
    assert.throws(() => parseResult({ ...result(), ...patch }));
  const missing: Record<string, unknown> = { ...result() };
  delete missing.checkpoint;
  assert.throws(() => parseResult(missing));
  const source = JSON.stringify(result());
  assert.throws(() =>
    parseAuditVerification(
      source.replace('"valid":true', '"valid":true,"v\\u0061lid":true'),
      org,
      range,
    ),
  );
  assert.throws(() =>
    parseAuditVerification(" ".repeat(4_096) + source, org, range),
  );
});

test("actual Account HTTP audit reads omit cookies, use fresh query-free token-bound proofs and source decoders", async () => {
  const key = await AccountProofKey.create();
  const proofs: string[] = [];
  mock.method(
    globalThis,
    "fetch",
    async (url: string, options: RequestInit) => {
      const request = new URL(url);
      assert.equal(options.method, "GET");
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.redirect, "error");
      const headers = new Headers(options.headers);
      assert.equal(headers.get("Authorization"), "DPoP token");
      const proof = headers.get("DPoP")!;
      const claims = JSON.parse(
        Buffer.from(proof.split(".")[1], "base64url").toString("utf8"),
      );
      assert.equal(claims.htm, "GET");
      assert.equal(claims.htu, origin + request.pathname);
      assert.equal(
        claims.ath,
        encoded(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode("token"),
          ),
        ),
      );
      proofs.push(claims.jti);
      return response(
        request.pathname.endsWith("/verify")
          ? JSON.stringify(result())
          : page(),
      );
    },
  );
  const transport: AccountTransport = {
    origin,
    request: (method, path, options) =>
      accountFetch({
        origin,
        key,
        method,
        path,
        options,
        token: "token",
        operation: "request",
      }),
  };
  const api = new AuditApi(transport);
  assert.equal((await api.list(org)).items.length, 1);
  assert.equal((await api.verify(org, range)).valid, true);
  assert.equal(new Set(proofs).size, 2);
});

test("public Account session admits both generated audit routes and fences a late read after Lock", async () => {
  const key = await AccountProofKey.create();
  const client = new AccountClient(origin, {
    run: async () => ({
      ...key.transfer(),
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
    "audit.owner",
    new TextEncoder().encode("a valid fixture password"),
  );
  let complete: ((value: Response) => void) | undefined;
  let defer = false;
  mock.method(globalThis, "fetch", async (url: string) => {
    if (defer)
      return new Promise<Response>((resolve) => {
        complete = resolve;
      });
    return response(
      url.includes("/verify?") ? JSON.stringify(result()) : page(),
    );
  });
  const api = new AuditApi(client);
  assert.equal((await api.list(org)).items.length, 1);
  assert.equal((await api.verify(org, range)).valid, true);
  defer = true;
  const late = api.list(org);
  while (!complete) await new Promise<void>((resolve) => setImmediate(resolve));
  client.lock();
  complete(response(page()));
  await assert.rejects(
    late,
    (error: unknown) =>
      error instanceof AccountFailure && error.code === "session_changed",
  );
  assert.equal(client.authenticated, false);
});

test("audit success decoders never interpret problems and invalid reads retain changed:false", async () => {
  const key = await AccountProofKey.create();
  let answer = response(
    JSON.stringify({
      type: "about:blank",
      title: "Denied",
      detail: "Denied",
      status: 403,
      instance: "audit-test",
      code: "policy.denied",
      changed: false,
      retryable: false,
    }),
    403,
  );
  mock.method(globalThis, "fetch", async () => answer);
  let decoded = false;
  const request = (decode?: RequestOptions["decode"]) =>
    accountFetch({
      origin,
      key,
      method: "GET",
      path: `/api/v1/orgs/${org}/audit-events`,
      operation: "request",
      token: "token",
      options: { decode },
    });
  await assert.rejects(
    request(() => {
      decoded = true;
      throw new Error("not a page");
    }),
    (error: unknown) =>
      error instanceof AccountFailure &&
      error.code === "policy.denied" &&
      !error.changed,
  );
  assert.equal(decoded, false);
  for (const invalid of [
    response(page(), 200, { "Cache-Control": "public" }),
    response("\uFEFF" + page()),
    response('{"items":[]}'),
    new Response(Uint8Array.from([0xff]), { headers: response("").headers }),
  ]) {
    answer = invalid;
    await assert.rejects(
      request((source) => parseAuditPage(source, org)),
      (error: unknown) =>
        error instanceof AccountFailure &&
        error.code === "invalid_response" &&
        !error.changed,
    );
  }
});
