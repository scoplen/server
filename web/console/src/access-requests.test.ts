// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  AccessRequestActions,
  AccessRequestApi,
  parseAccessRequest,
  parseAccessRequestPage,
  requestPending,
  type RequestDecision,
} from "./access-requests.ts";
import type { AccessRequestResource } from "./generated/api.ts";
import {
  RequestFailure,
  type AccountTransport,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";
import { AccountClient } from "./account.ts";
import { AccountProofKey } from "./account-proof.ts";
import { encoded } from "./wire.ts";

const org = "019a0000-0000-7000-8000-000000000001";
const requester = "019a0000-0000-7000-8000-000000000002";
const approver = "019a0000-0000-7000-8000-000000000003";
const host = "019a0000-0000-7000-8000-000000000004";
const id = "019a0000-0000-7000-8000-000000000005";
const key = "019a0000-0000-7000-8000-000000000006";
const at = "2030-01-01T00:00:00.123456789Z";
const expires = "2030-01-02T00:00:00.123456789Z";
const item = (): AccessRequestResource => ({
  id,
  etag: '"v1"',
  created_at: at,
  updated_at: at,
  data: {
    requester_account_id: requester,
    requester_membership_id: requester,
    host,
    remote_user: " Ops e\u0301 ",
    duration_seconds: 3600,
    reason: " Deploy\n\t approved change ",
    expires_at: expires,
    status: "pending",
    decision: null,
    grant: null,
  },
});
const result = (decision: RequestDecision): AccessRequestResource => {
  const value = item();
  value.etag = '"v2"';
  value.updated_at = at;
  value.data.status = {
    approve: "approved",
    deny: "denied",
    cancel: "cancelled",
  }[decision];
  if (decision !== "cancel")
    value.data.decision = {
      outcome: decision,
      actor_account_id: approver,
      decided_at: at,
    };
  if (decision === "approve")
    value.data.grant = {
      id: key,
      valid_from: "2030-01-01T00:00:00Z",
      valid_until: "2030-01-01T01:00:00Z",
    };
  return value;
};
class Transport implements AccountTransport {
  readonly origin = "https://console.example";
  calls: { method: Method; path: string; options: RequestOptions }[] = [];
  reply: (
    method: Method,
    path: string,
    options: RequestOptions,
  ) => Promise<ApiResponse> = async (_method, path, options) => {
    const decision = path.endsWith("/cancel")
      ? "cancel"
      : (options.body as { decision: RequestDecision }).decision;
    return { value: result(decision), etag: '"v2"' };
  };
  request(
    method: Method,
    path: string,
    options: RequestOptions = {},
  ): Promise<ApiResponse> {
    this.calls.push({ method, path, options });
    return this.reply(method, path, options);
  }
}
const setup = (account = approver) => {
  const transport = new Transport(),
    api = new AccessRequestApi(transport, org, account);
  return { transport, api, actions: new AccessRequestActions(api) };
};

test("request resources preserve original text and fractional metadata with exact deadline and Grant arithmetic", () => {
  for (const value of [
    item(),
    result("approve"),
    result("deny"),
    result("cancel"),
  ])
    assert.deepEqual(
      parseAccessRequest(JSON.stringify(value), value.etag),
      value,
    );
  const value = item();
  value.data.expires_at = "2030-01-02T00:00:00.1234567890Z";
  assert.equal(
    parseAccessRequest(JSON.stringify(value)).data.expires_at,
    value.data.expires_at,
  );
  for (const expires_at of [
    "2030-01-02T00:00:00Z",
    "2030-01-02T00:00:00.123456788Z",
    "2030-01-02T00:00:01.123456789Z",
    "2030-02-30T00:00:00Z",
  ])
    assert.throws(() =>
      parseAccessRequest(
        JSON.stringify({ ...value, data: { ...value.data, expires_at } }),
      ),
    );
  const approved = result("approve");
  approved.data.grant!.valid_from = "2030-01-01T00:00:01Z";
  approved.data.grant!.valid_until = "2030-01-01T01:00:01Z";
  assert.throws(() => parseAccessRequest(JSON.stringify(approved)));
});
test("request parsing rejects missing fields, ambiguous extensions, control characters and inconsistent transitions", () => {
  for (const field of Object.keys(item())) {
    const value: Record<string, unknown> = { ...item() };
    delete value[field];
    assert.throws(() => parseAccessRequest(JSON.stringify(value)));
  }
  for (const field of Object.keys(item().data)) {
    const value = item();
    delete value.data[field];
    assert.throws(() => parseAccessRequest(JSON.stringify(value)));
  }
  const source = JSON.stringify(item());
  assert.throws(() =>
    parseAccessRequest(
      source.replace('"data":', '"extension":{"a":1,"a":2},"data":'),
    ),
  );
  assert.throws(() => parseAccessRequest(source, '"other"'));
  for (const patch of [
    { remote_user: "" },
    { remote_user: "界".repeat(86) },
    { remote_user: "user\u0085" },
    { remote_user: "\ud800" },
    { reason: " \n\t " },
    { reason: "work\r" },
    { reason: "work\u0085" },
    { reason: "\ud800" },
    { reason: "界".repeat(683) },
    { duration_seconds: 0 },
    { duration_seconds: 86401 },
    { duration_seconds: 1.5 },
    { status: "Pending" },
    { status: "x".repeat(65) },
    { status: "denied" },
    { status: "approved" },
    { decision: result("deny").data.decision },
    { grant: result("approve").data.grant },
  ])
    assert.throws(() =>
      parseAccessRequest(
        JSON.stringify({ ...item(), data: { ...item().data, ...patch } }),
      ),
    );
  const unknown = item();
  unknown.data.status = "future_status";
  assert.equal(
    parseAccessRequest(JSON.stringify(unknown)).data.status,
    "future_status",
  );
  assert.equal(requestPending(unknown, 0), false);
  assert.equal(requestPending(item(), Date.parse(expires)), false);
  assert.equal(requestPending(item(), Date.parse(at)), true);
});
test("request pages bind view, requester, ascending cursor and original encoded item bytes", () => {
  const source = JSON.stringify({ items: [item()], next_cursor: id });
  assert.equal(
    parseAccessRequestPage(source, requester, "mine").next_cursor,
    id,
  );
  assert.equal(
    parseAccessRequestPage(source, approver, "approvals").items.length,
    1,
  );
  assert.throws(() => parseAccessRequestPage(source, approver, "mine"));
  assert.throws(() => parseAccessRequestPage(source, requester, "approvals"));
  assert.throws(() => parseAccessRequestPage(source, requester, "mine", id));
  assert.throws(() =>
    parseAccessRequestPage(
      JSON.stringify({ items: [item(), item()], next_cursor: null }),
      requester,
      "mine",
    ),
  );
  assert.throws(() =>
    parseAccessRequestPage(
      JSON.stringify({ items: [], next_cursor: id }),
      requester,
      "mine",
    ),
  );
  assert.throws(() =>
    parseAccessRequestPage(
      JSON.stringify({ items: [result("approve")], next_cursor: null }),
      approver,
      "approvals",
    ),
  );
  const padded = JSON.stringify(item()).replace(
    '"data":',
    `"data":${" ".repeat(8192)}`,
  );
  assert.throws(() => parseAccessRequest(padded));
  assert.throws(() =>
    parseAccessRequestPage(
      `{"items":[${padded}],"next_cursor":null}`,
      requester,
      "mine",
    ),
  );
  assert.throws(() =>
    parseAccessRequestPage(" ".repeat(4194305), requester, "mine"),
  );
});
test("review and decisions use exact route, original body/key/ETag and bind every response field", async () => {
  const { transport, api } = setup();
  transport.reply = async () => ({ value: item(), etag: '"v1"' });
  await api.get(id);
  assert.equal(
    transport.calls[0].path,
    `/api/v1/orgs/${org}/access-requests/${id}`,
  );
  assert.equal(transport.calls[0].options.key, undefined);
  for (const decision of ["approve", "deny"] as const) {
    transport.reply = async () => ({ value: result(decision), etag: '"v2"' });
    await api.decide(item(), decision, key);
    const call = transport.calls.at(-1)!;
    assert.equal(
      call.path,
      `/api/v1/orgs/${org}/access-requests/${id}/decisions`,
    );
    assert.deepEqual(call.options.body, { decision });
    assert.equal(call.options.key, key);
    assert.equal(call.options.etag, '"v1"');
  }
  for (const patch of [
    { host: org },
    { remote_user: "Ops" },
    { duration_seconds: 1 },
    { reason: "changed" },
    { requester_membership_id: org },
  ]) {
    transport.reply = async () => {
      const value = result("approve");
      Object.assign(value.data, patch);
      return { value, etag: '"v2"' };
    };
    await assert.rejects(api.decide(item(), "approve", key));
  }
  transport.reply = async () => {
    const value = result("approve");
    value.data.decision!.actor_account_id = requester;
    return { value, etag: '"v2"' };
  };
  await assert.rejects(api.decide(item(), "approve", key));
  const own = setup(requester);
  await own.api.decide(item(), "cancel", key);
  assert.equal(own.transport.calls[0].options.body, undefined);
  assert.ok(own.transport.calls[0].path.endsWith("/cancel"));
});
test("wrong actors and decisions fail before retaining an intent or sending a request", async () => {
  for (const [account, decision] of [
    [requester, "approve"],
    [requester, "deny"],
    [approver, "cancel"],
    [approver, "revoke"],
  ] as const) {
    const { actions, api, transport } = setup(account);
    await assert.rejects(actions.decide(item(), decision as RequestDecision));
    await assert.rejects(api.decide(item(), decision as RequestDecision, key));
    assert.equal(actions.pending, undefined);
    assert.equal(transport.calls.length, 0);
  }
});
test("uncertain decisions retain only the frozen original operation until explicit confirmation", async () => {
  const { actions, transport } = setup();
  transport.reply = async () => {
    throw new RequestFailure(
      "organization.commit_outcome_unknown",
      503,
      true,
      true,
    );
  };
  const original = item();
  await assert.rejects(actions.decide(original, "approve"));
  const pending = actions.pending!;
  original.etag = '"changed"';
  original.data.reason = "changed";
  assert.equal(pending.original.etag, '"v1"');
  assert.equal(pending.original.data.reason, item().data.reason);
  assert.equal(Object.isFrozen(pending.original.data), true);
  await assert.rejects(actions.decide(item(), "deny"));
  assert.equal(transport.calls.length, 1);
  transport.reply = async () => ({ value: result("approve"), etag: '"v2"' });
  await actions.confirm();
  assert.equal(actions.pending, undefined);
  assert.deepEqual(transport.calls[1], transport.calls[0]);
});
test("definite stale outcomes require review, while unknown or malformed replies retain confirmation", async () => {
  for (const error of [
    new RequestFailure("organization.precondition_failed", 412),
    new RequestFailure("organization.conflict", 409),
  ]) {
    const { actions, transport } = setup();
    transport.reply = async () => {
      throw error;
    };
    await assert.rejects(actions.decide(item(), "approve"));
    assert.equal(actions.pending, undefined);
    assert.equal(actions.reviewRequired, true);
    await assert.rejects(actions.decide(item(), "approve"));
    assert.equal(transport.calls.length, 1);
  }
  const { actions, transport } = setup();
  transport.reply = async () => ({ value: item(), etag: '"v1"' });
  await assert.rejects(actions.decide(item(), "approve"));
  assert.ok(actions.pending);
  actions.discard();
  assert.equal(actions.reviewRequired, true);
  await assert.rejects(actions.decide(item(), "deny"));
  actions.reviewed();
  transport.reply = async () => ({ value: result("deny"), etag: '"v2"' });
  await actions.decide(item(), "deny");
});
test("team/session disposal fences late mutation results and removes original confirmation", async () => {
  const { actions, transport } = setup();
  let release!: (value: ApiResponse) => void;
  transport.reply = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const response = actions.decide(item(), "approve");
  actions.dispose();
  release({ value: result("approve"), etag: '"v2"' });
  await assert.rejects(
    response,
    (error) =>
      error instanceof RequestFailure && error.code === "session_changed",
  );
  assert.equal(actions.pending, undefined);
  await assert.rejects(actions.confirm());
  assert.equal(transport.calls.length, 1);
});
test("expired original confirmation never sends a replacement operation", async () => {
  const { actions, transport } = setup();
  transport.reply = async () => {
    throw new Error("lost response");
  };
  await assert.rejects(actions.decide(item(), "approve"));
  const clock = mock.method(Date, "now", () => actions.pending!.deadline);
  try {
    await assert.rejects(actions.confirm());
    assert.equal(transport.calls.length, 1);
  } finally {
    clock.mock.restore();
  }
});
test("production Account transport mounts request reads and decisions with fresh DPoP and exact headers", async () => {
  const proof = await AccountProofKey.create(),
    origin = "https://console.example";
  const client = new AccountClient(origin, {
    run: async () => ({
      ...proof.transfer(),
      session: {
        access_token: `ab1_${encoded(new Uint8Array(32))}`,
        token_type: "DPoP",
        expires_in: 600,
        refresh_expires_in: 2592000,
      },
      startedAt: Date.now(),
    }),
  });
  await client.signIn(
    "request.approver",
    new TextEncoder().encode("a valid fixture password"),
  );
  const proofs = new Set<string>();
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
      const list = url.includes("?");
      if (options.method === "POST") {
        assert.equal(headers.get("Idempotency-Key"), key);
        assert.equal(headers.get("If-Match"), '"v1"');
        assert.equal(options.body, JSON.stringify({ decision: "approve" }));
      } else {
        assert.equal(headers.get("Idempotency-Key"), null);
        assert.equal(headers.get("If-Match"), null);
      }
      return new Response(
        JSON.stringify(
          list
            ? { items: [item()], next_cursor: null }
            : options.method === "POST"
              ? result("approve")
              : item(),
        ),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            Pragma: "no-cache",
            "X-Request-ID": "request-fixture",
            ...(!list
              ? { ETag: options.method === "POST" ? '"v2"' : '"v1"' }
              : {}),
          },
        },
      );
    },
  );
  try {
    const api = new AccessRequestApi(client, org, approver);
    await api.list("approvals");
    await api.get(id);
    await api.decide(item(), "approve", key);
    assert.equal(proofs.size, 3);
  } finally {
    fetchMock.mock.restore();
    client.lock();
  }
});
