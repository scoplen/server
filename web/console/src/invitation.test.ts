// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  InvitationOperation,
  parseJoinLink,
  takeJoinFragment,
  type InvitationCrypto,
} from "./invitation.ts";
import {
  TeamApi,
  RequestFailure,
  type AccountTransport,
  type Method,
  type RequestOptions,
} from "./team.ts";

const origin = "https://console.example";
const account = "019a0000-0000-7000-8000-000000000001";
const org = "019a0000-0000-7000-8000-000000000002";
const invitation = "019a0000-0000-7000-8000-000000000003";
// A deterministic boundary fake tests operation ownership, not shared cryptography.
const shared: InvitationCrypto = {
  async generate(_origin, _org, _invitation, password, verifier) {
    password.set(new TextEncoder().encode("01234567"));
    verifier.fill(3);
  },
  async parse(password) {
    if (new TextDecoder().decode(password) !== "01234567")
      throw new Error("invalid");
  },
};

test("canonical invitation fragment is scrubbed before validation", () => {
  const link = `${origin}/join-team#organization=${org}&invitation=${invitation}`;
  let replaced = "";
  assert.deepEqual(
    takeJoinFragment(new URL(link), (path) => (replaced = path)),
    { organization: org, invitation },
  );
  assert.equal(replaced, "/join-team");
  for (const source of [
    link + "&password=secret",
    link.replace(origin, "https://other.example"),
    link.replace("/join-team", "/join-team/"),
  ])
    assert.throws(() => parseJoinLink(source, origin));
  assert.throws(() =>
    takeJoinFragment(
      new URL(origin + "/join-team#invalid"),
      (path) => (replaced = path),
    ),
  );
  assert.equal(replaced, "/join-team");
});

test("uncertain invitation creation preserves exact original payload/key and reveals only after confirmation", async () => {
  const calls: RequestOptions[] = [];
  let fail = true;
  const transport: AccountTransport = {
    origin,
    async request(_method: Method, _path: string, options?: RequestOptions) {
      calls.push(options!);
      if (fail)
        throw new RequestFailure(
          "organization.commit_outcome_unknown",
          503,
          true,
          true,
        );
      const payload = options!.body as {
        invitation_id: string;
        recipient_username: string;
        roles: string[];
      };
      return {
        etag: '"1"',
        value: {
          id: payload.invitation_id,
          etag: '"1"',
          created_at: "2026-11-08T00:00:00Z",
          updated_at: "2026-11-08T00:00:00Z",
          data: {
            organization_id: org,
            organization_name: "Team",
            recipient_account_id: account,
            recipient_username: payload.recipient_username,
            issuer_account_id: account,
            roles: payload.roles,
            expires_at: "2026-11-09T00:00:00Z",
            status: "pending",
            membership_id: null,
          },
        },
      };
    },
  };
  const api = new TeamApi(transport);
  api.accountId = account;
  const operation = await InvitationOperation.create(
    api,
    shared,
    org,
    "recipient",
    ["member"],
  );
  assert.throws(() => operation.revealPassword());
  await assert.rejects(operation.submit(api));
  assert.equal(operation.state, "uncertain");
  assert.throws(() => operation.revealPassword());
  assert.throws(() => JSON.stringify(operation));
  fail = false;
  await operation.submit(api);
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(operation.revealPassword(), "01234567");
  assert.equal(new URL(operation.link).hash.includes("01234567"), false);
  operation.dispose();
  assert.equal(operation.hasSecret, false);
  assert.throws(() => operation.revealPassword());
  await assert.rejects(operation.submit(api));
});

test("a different account cannot confirm a captured pending invitation", async () => {
  const api = new TeamApi({
    origin,
    async request() {
      throw new Error("must not send");
    },
  });
  api.accountId = account;
  const operation = await InvitationOperation.create(
    api,
    shared,
    org,
    "recipient",
    ["member"],
  );
  api.accountId = invitation;
  await assert.rejects(operation.submit(api));
  assert.equal(operation.state, "ready");
  operation.dispose();
});

test("local invitation preparation failures erase owned buffers and send no mutation", async () => {
  let calls = 0;
  const api = new TeamApi({
    origin,
    async request() {
      calls++;
      throw new Error("must not send");
    },
  });
  api.accountId = account;
  let ownedPassword: Uint8Array | undefined;
  let ownedVerifier: Uint8Array | undefined;
  const failing: InvitationCrypto = {
    async generate(_origin, _org, _invitation, password, verifier) {
      ownedPassword = password;
      ownedVerifier = verifier;
      password.fill(7);
      verifier.fill(8);
      throw new Error("randomness unavailable");
    },
    async parse(password) {
      ownedPassword = password;
      throw new Error("invalid password");
    },
  };
  await assert.rejects(
    InvitationOperation.create(api, failing, org, "recipient", ["member"]),
    (error: unknown) =>
      error instanceof RequestFailure &&
      error.code === "invitation_preparation_failed" &&
      !error.changed,
  );
  assert.ok(ownedPassword?.every((value) => value === 0));
  assert.ok(ownedVerifier?.every((value) => value === 0));
  await assert.rejects(
    InvitationOperation.accept(
      api,
      failing,
      { organization: org, invitation },
      "invalid",
    ),
    (error: unknown) =>
      error instanceof RequestFailure &&
      error.code === "invalid_invitation_password" &&
      !error.changed,
  );
  assert.ok(ownedPassword?.every((value) => value === 0));
  assert.equal(calls, 0);
});
