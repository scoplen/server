// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthConnectionActions } from "./auth-connection.ts";
import {
  RequestFailure,
  TeamApi,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";

const id = (last: string) => `019a0000-0000-7000-8000-00000000000${last}`;
const org = id("1"),
  account = id("2"),
  attempt = id("3"),
  generation = id("4");
const activated = id("5"),
  suspended = id("6"),
  replaced = id("7");
const issuer = "https://issuer.example/t/";
const settings = {
  issuer,
  client_id: "test +: app",
  space_id: "spc_Case-Sensitive",
};
const input = {
  client_id: settings.client_id,
  space_id: settings.space_id,
  client_secret: " disposable + secret ",
};
const base = `/api/v1/orgs/${org}/auth-connection`;
const candidatePath = `${base}/activations/${attempt}`;
const now = new Date().toISOString();
const draft = {
  id: generation,
  etag: `"${generation}"`,
  created_at: now,
  updated_at: now,
  data: { organization_id: org, issuer },
};

function fixture() {
  const calls: { method: Method; path: string; options?: RequestOptions }[] =
    [];
  const responses: (ApiResponse | Error | Promise<ApiResponse>)[] = [];
  const transport = {
    origin: "https://console.example",
    sessionGeneration: 1,
    async request(method: Method, path: string, options?: RequestOptions) {
      calls.push({ method, path, options });
      assert.ok(responses.length, "unexpected request");
      const reply = responses.shift()!;
      if (reply instanceof Error) throw reply;
      return reply;
    },
  };
  const api = new TeamApi(transport);
  api.accountId = account;
  return {
    actions: new AuthConnectionActions(api, org),
    transport,
    calls,
    responses,
  };
}

function candidate(revision: string | null = null) {
  const pending = {
    ...settings,
    id: attempt,
    organization_id: org,
    draft_generation: generation,
    expected_revision: revision,
    expires_at: new Date(Date.now() + 120_000).toISOString(),
    status: "pending",
  };
  return {
    pending,
    start: {
      value: { ...pending, authorization_url: `${issuer}login?state=test` },
      etag: null,
    },
    finish: { value: { ...pending, status: "verified" }, etag: null },
  };
}

function resource(id: string, status: string): ApiResponse {
  const etag = `"${id}"`;
  return {
    value: {
      id,
      etag,
      created_at: now,
      updated_at: now,
      data: { ...settings, organization_id: org, status },
    },
    etag,
  };
}
const missing = () => new RequestFailure("organization.not_found", 404);
const lost = () =>
  new RequestFailure("organization.commit_outcome_unknown", 503, true, true);

test("initial activation starts once, verifies the exact candidate and confirms with the original empty-slot condition", async () => {
  const { actions, calls, responses } = fixture();
  const proof = candidate();
  await assert.rejects(actions.start(draft, input), {
    code: "connection_review_required",
  });
  responses.push(
    missing(),
    proof.start,
    proof.finish,
    resource(activated, "active"),
    resource(activated, "active"),
  );
  await actions.readCurrent();
  await actions.start(draft, input);
  assert.equal(actions.candidate?.url, proof.start.value.authorization_url);
  assert.ok(!JSON.stringify(actions.candidate).includes(input.client_secret));
  await assert.rejects(actions.confirm(draft.id), {
    code: "connection_review_required",
  });
  await actions.checkCandidate();
  assert.equal(actions.candidate?.url, undefined);
  await assert.rejects(actions.confirm(id("8")), {
    code: "connection_review_required",
  });
  await actions.confirm(draft.id);
  assert.equal(actions.receipt?.id, activated);
  assert.equal(actions.current, undefined);
  await actions.readCurrent();
  assert.deepEqual(actions.current, resource(activated, "active").value);
  const [firstRead, start, status, confirm, secondRead] = calls;
  assert.deepEqual(firstRead, secondRead);
  assert.deepEqual(start, {
    method: "POST",
    path: `${base}/activations`,
    options: {
      body: { ...input, draft_generation: generation },
      ifNoneMatch: "*",
      success: 201,
    },
  });
  assert.deepEqual(status, {
    method: "GET",
    path: candidatePath,
    options: undefined,
  });
  assert.equal(confirm.path, `${candidatePath}/confirm`);
  assert.deepEqual(confirm.options, {
    key: confirm.options?.key,
    ifNoneMatch: "*",
  });
  assert.match(confirm.options!.key!, /^[0-9a-f-]{14}7[0-9a-f-]{21}$/);
});

test("replacement preserves the active head before confirmation and suspension uses the reviewed revision", async () => {
  const { actions, calls, responses } = fixture();
  const proof = candidate(activated);
  responses.push(
    resource(activated, "active"),
    proof.start,
    proof.finish,
    resource(replaced, "active"),
    resource(replaced, "active"),
    resource(suspended, "suspended"),
  );
  await actions.readCurrent();
  await actions.start(draft, input);
  await actions.checkCandidate();
  assert.equal(actions.current?.id, activated);
  await actions.confirm(generation);
  assert.equal(actions.receipt?.id, replaced);
  await actions.readCurrent();
  await assert.rejects(actions.suspend(activated), {
    code: "connection_review_required",
  });
  await actions.suspend(replaced);
  assert.equal(actions.receipt?.id, suspended);
  assert.equal(calls[1].options?.etag, `"${activated}"`);
  assert.equal(calls[3].options?.etag, `"${activated}"`);
  assert.deepEqual(calls[5], {
    method: "POST",
    path: `${base}/suspend`,
    options: { etag: `"${replaced}"`, key: calls[5].options?.key },
  });
});

test("an uncertain transition recovers only its exact request after the head changes", async () => {
  const { actions, calls, responses, transport } = fixture();
  const proof = candidate();
  responses.push(
    missing(),
    proof.start,
    proof.finish,
    lost(),
    resource(suspended, "suspended"),
    resource(activated, "active"),
  );
  await actions.readCurrent();
  await actions.start(draft, input);
  await actions.checkCandidate();
  await assert.rejects(actions.confirm(generation), { changed: true });
  assert.equal(actions.hasPendingReceipt, true);
  await actions.readCurrent();
  assert.equal(actions.current?.id, suspended);
  await assert.rejects(actions.start(draft, input), {
    code: "connection_review_required",
  });
  await actions.recover();
  assert.deepEqual(calls[3], calls[5]);
  assert.equal(actions.receipt?.id, activated);
  assert.equal(actions.current, undefined);

  responses.push(resource(activated, "active"), lost());
  await actions.readCurrent();
  await assert.rejects(actions.suspend(activated), { changed: true });
  transport.sessionGeneration += 1;
  await assert.rejects(actions.recover(), { code: "session_changed" });
  assert.equal(calls.length, 8);
  assert.equal(actions.hasPendingReceipt, false);
});

test("a lost start is not replayed and a malformed verification cannot authorize confirmation", async () => {
  const uncertain = fixture();
  uncertain.responses.push(missing(), lost());
  await uncertain.actions.readCurrent();
  await assert.rejects(uncertain.actions.start(draft, input), {
    changed: true,
  });
  assert.ok(uncertain.actions.waitRemaining > 0);
  await assert.rejects(uncertain.actions.start(draft, input), {
    code: "connection_review_required",
  });
  assert.equal(uncertain.calls.length, 2);

  const foreign = fixture();
  const proof = candidate();
  foreign.responses.push(missing(), {
    ...proof.start,
    value: {
      ...proof.start.value,
      authorization_url: "https://foreign.example/",
    },
  });
  await foreign.actions.readCurrent();
  await assert.rejects(foreign.actions.start(draft, input), {
    code: "invalid_response",
    changed: true,
  });
  assert.equal(foreign.actions.candidate, undefined);

  const { actions, calls, responses } = fixture();
  responses.push(
    missing(),
    proof.start,
    {
      ...proof.finish,
      value: { ...proof.finish.value, space_id: "spc_Wrong" },
    },
    { value: undefined, etag: null },
  );
  await actions.readCurrent();
  await actions.start(draft, input);
  await assert.rejects(actions.checkCandidate(), { code: "invalid_response" });
  assert.equal(actions.candidate?.url, undefined);
  await assert.rejects(actions.confirm(generation), {
    code: "connection_review_required",
  });
  await actions.abandon();
  assert.deepEqual(calls[3], {
    method: "DELETE",
    path: candidatePath,
    options: { success: 204 },
  });
  assert.equal(actions.candidate, undefined);
});

test("only a verified empty slot or matching current resource allows writes", async () => {
  const { actions, responses, calls } = fixture();
  const valid = resource(activated, "active");
  responses.push({
    ...valid,
    value: { ...(valid.value as object), client_secret: "unexpected" },
  });
  await assert.rejects(actions.readCurrent(), { code: "invalid_response" });
  assert.equal(actions.current, undefined);
  await assert.rejects(actions.start(draft, input), {
    code: "connection_review_required",
  });
  responses.push(missing());
  await actions.readCurrent();
  await assert.rejects(
    actions.start(draft, { ...input, space_id: "spc_contains space" }),
    { code: "invalid_connection_candidate" },
  );
  await assert.rejects(
    actions.start(draft, { ...input, client_secret: "a\n" }),
    { code: "invalid_connection_candidate" },
  );
  assert.equal(calls.length, 2);
});
