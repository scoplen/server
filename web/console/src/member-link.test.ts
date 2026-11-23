// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { MemberLinkActions } from "./member-link.ts";
import {
  TeamApi,
  RequestFailure,
  operationId,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";

const org = operationId(),
  member = operationId(),
  account = operationId(),
  id = operationId(),
  revision = operationId(),
  association = operationId();
const context = { organization_id: org, membership_id: member };
const settings = {
  id: revision,
  etag: `"${revision}"`,
  issuer: "https://issuer.example/Team",
  client_id: "Case-Sensitive",
  space_id: "spc_Org",
};
const subjectLink = {
  ...context,
  id: association,
  etag: `"${association}"`,
  created_at: new Date().toISOString(),
};
const status = { ...context, connection: settings, link: null };
const self = `/api/v1/orgs/${org}/auth-link`;
const named = `/api/v1/orgs/${org}/members/${member}/auth-link`;
const attemptPath = self + "/attempts/" + id;
const reply = (value?: unknown, etag: string | null = null) => ({
  value,
  etag,
});
function proof() {
  const pending = {
    ...context,
    id,
    connection_revision: revision,
    status: "pending",
    expires_at: new Date(Date.now() + 120_000).toISOString(),
  };
  const url = settings.issuer + "/authorize?state=example";
  return {
    pending,
    start: { ...pending, authorization_url: url },
    verified: { ...pending, status: "verified" },
    url,
  };
}
function fixture(asOwner = false) {
  const calls: { method: Method; path: string; options?: RequestOptions }[] =
    [];
  const responses: (ApiResponse | Error | Promise<ApiResponse>)[] = [];
  const transport = {
    origin: "https://console.example",
    sessionGeneration: 0,
    async request(method: Method, path: string, options?: RequestOptions) {
      calls.push({ method, path, options });
      assert.ok(responses.length, "unexpected operation");
      const result = responses.shift()!;
      if (result instanceof Error) throw result;
      return result;
    },
  };
  const api = new TeamApi(transport);
  api.accountId = account;
  return {
    actions: new MemberLinkActions(api, org, member, asOwner),
    transport,
    calls,
    responses,
    api,
  };
}
const denied = { code: "link_review_required" };
const lost = () => new RequestFailure("response_lost", 0, true);
test("member reviews the exact team connection, signs in separately and confirms only verified ownership", async () => {
  const { actions, calls, responses } = fixture();
  const p = proof();
  responses.push(
    reply(status),
    reply(p.start),
    reply(p.verified),
    reply(subjectLink, subjectLink.etag),
  );
  await assert.rejects(actions.start(), denied);
  await actions.read();
  await actions.start();
  assert.equal(actions.candidate?.url, p.url);
  await assert.rejects(actions.confirm(), denied);
  await actions.checkAttempt();
  assert.equal(actions.candidate?.url, undefined);
  assert.equal(actions.receipt, undefined);
  await actions.confirm();
  assert.deepEqual(actions.receipt, subjectLink);
  assert.equal(actions.current, undefined);
  assert.deepEqual(
    calls.map((v) => [v.method, v.path]),
    [
      ["GET", self],
      ["POST", self + "/attempts"],
      ["GET", attemptPath],
      ["POST", attemptPath + "/confirm"],
    ],
  );
  assert.deepEqual(calls[1].options, { etag: settings.etag, success: 201 });
  assert.deepEqual(calls[3].options, {
    etag: settings.etag,
    key: calls[3].options?.key,
    success: 201,
  });
  assert.match(calls[3].options!.key!, /^[a-f0-9-]{14}7[a-f0-9-]{21}$/);
});
test("original confirmation recovers with the same immutable request after a lost response; status cannot confirm it", async () => {
  const { actions, calls, responses } = fixture();
  const p = proof();
  responses.push(
    reply(status),
    reply(p.start),
    reply(p.verified),
    lost(),
    reply({ ...status, link: subjectLink }),
    reply(subjectLink, subjectLink.etag),
  );
  await actions.read();
  await actions.start();
  await actions.checkAttempt();
  await assert.rejects(actions.confirm(), { code: "response_lost" });
  assert.ok(actions.pending);
  await actions.read();
  assert.equal(actions.receipt, undefined);
  assert.ok(actions.pending);
  await assert.rejects(actions.withdraw(association), denied);
  await actions.recover();
  assert.deepEqual(calls[3], calls[5]);
  assert.deepEqual(actions.receipt, subjectLink);
});
test("unknown or malformed start cannot navigate or start again, and checking rejects unbound or private evidence", async () => {
  for (const result of [
    lost(),
    reply({ ...proof().start, subject: "private" }),
    reply({
      ...proof().start,
      authorization_url: "https://different.example/authorize",
    }),
    reply({ ...proof().start, membership_id: operationId() }),
  ]) {
    const { actions, responses, calls } = fixture();
    responses.push(reply(status), result);
    await actions.read();
    await assert.rejects(actions.start());
    assert.equal(actions.candidate, undefined);
    assert.ok(actions.waitRemaining > 0);
    await assert.rejects(actions.start(), denied);
    assert.equal(calls.length, 2);
  }
  for (const changed of [
    { connection_revision: operationId() },
    { id: operationId() },
    { organization_id: operationId() },
    { authorization_url: "https://issuer.example" },
    { status: ["verified"] },
    { claims: {} },
  ]) {
    const { actions, responses } = fixture();
    const p = proof();
    responses.push(
      reply(status),
      reply(p.start),
      reply({ ...p.verified, ...changed }),
      reply(),
    );
    await actions.read();
    await actions.start();
    await assert.rejects(actions.checkAttempt(), { code: "invalid_response" });
    await assert.rejects(actions.confirm(), denied);
    assert.equal(actions.candidate?.url, undefined);
    await actions.abandon();
    assert.equal(actions.candidate, undefined);
  }
});
test("changed connection, replaced session, expired proof or withdrawn team cannot use previous verification", async () => {
  const p = proof();
  for (const change of ["revision", "session", "team", "expired"]) {
    const { actions, responses, transport, calls } = fixture();
    responses.push(reply(status), reply(p.start), reply(p.verified));
    await actions.read();
    await actions.start();
    await actions.checkAttempt();
    if (change === "revision") {
      const replacement = operationId();
      responses.push(
        reply({
          ...status,
          connection: {
            ...settings,
            id: replacement,
            etag: `"${replacement}"`,
          },
        }),
      );
      await actions.read();
    } else if (change === "session") transport.sessionGeneration++;
    else if (change === "team") actions.dispose();
    else {
      const original = Date.now;
      Date.now = () => Date.parse(p.pending.expires_at) + 1;
      try {
        await assert.rejects(actions.confirm(), denied);
      } finally {
        Date.now = original;
      }
      continue;
    }
    const count = calls.length;
    await assert.rejects(actions.confirm());
    assert.equal(calls.length, count);
    assert.equal(actions.candidate, undefined);
  }
});
test("session disposal suppresses a late navigation response or a late confirmation receipt", async () => {
  for (const operation of ["start", "confirm"]) {
    const { actions, responses, transport } = fixture();
    const p = proof();
    responses.push(reply(status));
    await actions.read();
    if (operation === "confirm") {
      responses.push(reply(p.start), reply(p.verified));
      await actions.start();
      await actions.checkAttempt();
    }
    let finish!: (value: ApiResponse) => void;
    responses.push(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    const waiting = operation === "start" ? actions.start() : actions.confirm();
    transport.sessionGeneration++;
    finish(
      operation === "start"
        ? reply(p.start)
        : reply(subjectLink, subjectLink.etag),
    );
    await assert.rejects(waiting, { code: "session_changed" });
    assert.equal(actions.candidate, undefined);
    assert.equal(actions.receipt, undefined);
    assert.ok(!actions.pending);
  }
});
test("self unlink and Owner withdrawal bind the reviewed link, reject stale retries and never create a member link on behalf of someone else", async () => {
  for (const owner of [true, false]) {
    const { actions, calls, responses } = fixture(owner);
    const view = owner
      ? { ...context, link: subjectLink }
      : { ...status, link: subjectLink };
    const path = owner ? named : self;
    responses.push(
      reply(view),
      new RequestFailure("organization.precondition_failed", 412),
      reply(view),
      reply(),
    );
    await actions.read();
    await assert.rejects(actions.start(), denied);
    await assert.rejects(actions.confirm(), denied);
    await assert.rejects(actions.withdraw(operationId()), denied);
    await assert.rejects(actions.withdraw(association), { status: 412 });
    await assert.rejects(actions.withdraw(association), denied);
    await actions.read();
    await actions.withdraw(association);
    assert.equal(actions.current, undefined);
    for (const index of [1, 3])
      assert.deepEqual(calls[index], {
        method: "DELETE",
        path,
        options: { etag: subjectLink.etag, success: 204 },
      });
    assert.deepEqual(calls[0], { method: "GET", path, options: undefined });
  }
  const { actions, responses } = fixture(true);
  responses.push(reply(status));
  await assert.rejects(actions.read(), { code: "invalid_response" });
});
test("another active revision permanently fences an unresolved original confirmation in this tab", async () => {
  const { actions, calls, responses } = fixture(),
    p = proof();
  const replacement = operationId();
  responses.push(
    reply(status),
    reply(p.start),
    reply(p.verified),
    lost(),
    reply({
      ...status,
      connection: { ...settings, id: replacement, etag: `"${replacement}"` },
    }),
    reply(status),
  );
  await actions.read();
  await actions.start();
  await actions.checkAttempt();
  await assert.rejects(actions.confirm(), { code: "response_lost" });
  await actions.read();
  await actions.read();
  await assert.rejects(actions.recover(), denied);
  assert.equal(calls.length, 6);
  assert.ok(actions.pending);
});

test("a malformed confirmation response is never accepted as a receipt and preserves only original recovery", async () => {
  const { actions, responses } = fixture();
  const p = proof();
  responses.push(
    reply(status),
    reply(p.start),
    reply(p.verified),
    reply(subjectLink, null),
    reply({ ...subjectLink, access_token: "private" }, subjectLink.etag),
  );
  await actions.read();
  await actions.start();
  await actions.checkAttempt();
  await assert.rejects(actions.confirm(), {
    code: "invalid_response",
    changed: true,
  });
  await assert.rejects(actions.recover(), { code: "invalid_response" });
  assert.equal(actions.receipt, undefined);
  actions.discardReceipt();
  await assert.rejects(actions.recover(), denied);
  await assert.rejects(actions.start(), denied);
});
