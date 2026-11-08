// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TeamApi,
  operationId,
  parseCollection,
  parseInvitation,
  parseOrganization,
  parsePage,
  type AccountTransport,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";

const account = "019a0000-0000-7000-8000-000000000001";
const org = "019a0000-0000-7000-8000-000000000002";
const member = "019a0000-0000-7000-8000-000000000003";
const host = "019a0000-0000-7000-8000-000000000004";
const profile = "019a0000-0000-7000-8000-000000000005";
const key = "019a0000-0000-7000-8000-000000000006";
const timestamp = "2026-11-08T00:00:00Z";
const meta = (id: string) => ({
  id,
  etag: '"v1"',
  created_at: timestamp,
  updated_at: timestamp,
});
const team = {
  ...meta(org),
  data: {
    name: "Operations",
    membership: { id: member, account_id: account, roles: ["owner"] },
  },
};

class Transport implements AccountTransport {
  readonly origin = "https://console.example";
  calls: { method: Method; path: string; options?: RequestOptions }[] = [];
  response: ApiResponse = { value: team, etag: '"v1"' };
  async request(
    method: Method,
    path: string,
    options?: RequestOptions,
  ): Promise<ApiResponse> {
    this.calls.push({ method, path, options });
    return this.response;
  }
}

test("Resource timestamps preserve valid fractional UTC precision from the public server", async () => {
  const transport = new Transport();
  transport.response = {
    value: {
      ...meta(account),
      created_at: "2026-11-08T12:34:56.123Z",
      updated_at: "2026-11-08T12:34:56.123456789Z",
      data: { email: null },
    },
    etag: '"v1"',
  };
  const api = new TeamApi(transport);
  const profile = await api.profile();
  assert.equal(profile.created_at, "2026-11-08T12:34:56.123Z");
  assert.equal(profile.updated_at, "2026-11-08T12:34:56.123456789Z");
  transport.response = {
    value: {
      organization_id: org,
      invitation_id: key,
      account_id: account,
      membership_id: member,
      accepted_at: "2026-11-08T12:34:56.123Z",
    },
    etag: null,
  };
  assert.equal(
    (await api.accept(org, key, "ABCDEFGH", key)).accepted_at,
    "2026-11-08T12:34:56.123Z",
  );
  transport.response = {
    value: { organization_id: org, dissolved_at: "2026-11-08T12:34:56.123Z" },
    etag: null,
  };
  assert.equal(
    (await api.dissolve(team, key)).dissolved_at,
    "2026-11-08T12:34:56.123Z",
  );
  for (const created_at of [
    "2030-02-30T00:00:00.123Z",
    "2030-01-01T00:00:00.Z",
    "2030-01-01T00:00:00.123+00:00",
  ])
    assert.throws(() =>
      parseOrganization({ ...team, created_at }, account),
    );
});

test("team discovery binds the current account and preserves unknown role display", () => {
  assert.equal(parseOrganization(team, account, '"v1"').id, org);
  assert.throws(() => parseOrganization(team, org));
  assert.throws(() => parseOrganization(team, account, '"other"'));
  assert.equal(
    parseOrganization(
      {
        ...team,
        data: {
          ...team.data,
          membership: { ...team.data.membership, roles: ["future_role"] },
        },
      },
      account,
    ).data.membership.roles[0],
    "future_role",
  );
});

test("live pages reject duplicates, descending IDs and forged continuation", () => {
  const parse = (value: unknown) => parseOrganization(value, account);
  assert.deepEqual(parsePage({ items: [], next_cursor: null }, parse), {
    items: [],
    next_cursor: null,
  });
  assert.throws(() =>
    parsePage({ items: [team, team], next_cursor: null }, parse),
  );
  assert.throws(() => parsePage({ items: [team], next_cursor: member }, parse));
  assert.throws(() =>
    parsePage({ items: [team], next_cursor: null }, parse, org),
  );
});

test("inventory decoding retains exact direct route zero and refuses unsupported replacement content", () => {
  const value = {
    ...meta(profile),
    data: { schema: 1, fields: { host, username: " deploy ", route: 0 } },
  };
  assert.equal(parseCollection("access-profiles", value).data.fields.route, 0);
  assert.equal(
    parseCollection("access-profiles", value).data.fields.username,
    " deploy ",
  );
  assert.throws(() =>
    parseCollection("access-profiles", {
      ...value,
      data: { ...value.data, fields: { ...value.data.fields, route: "0" } },
    }),
  );
  assert.throws(() =>
    parseCollection("access-profiles", {
      ...value,
      data: {
        ...value.data,
        fields: { ...value.data.fields, credential: host },
      },
    }),
  );
  assert.throws(() =>
    parseCollection("access-profiles", {
      ...value,
      data: { ...value.data, schema: 2 },
    }),
  );
});

test("typed route and host group validation rejects nulls and inconsistent route payloads", () => {
  assert.throws(() =>
    parseCollection("routes", {
      ...meta(host),
      data: {
        schema: 1,
        fields: { name: "Jump", kind: 1, proxy: "example.com:1080" },
      },
    }),
  );
  assert.throws(() =>
    parseCollection("host-groups", {
      ...meta(host),
      data: { schema: 1, fields: { name: "Production", parent: null } },
    }),
  );
  assert.throws(() =>
    parseCollection("hosts", {
      ...meta(host),
      data: {
        schema: 1,
        fields: {
          name: "API",
          address: "example.com",
          groups: { [org]: false },
        },
      },
    }),
  );
});

test("invitation resources are bound to the target team without accepting secret readback", () => {
  const invitation = {
    ...meta(key),
    data: {
      organization_id: org,
      organization_name: "Operations",
      recipient_account_id: account,
      recipient_username: "operator",
      roles: ["member"],
      issuer_account_id: account,
      expires_at: timestamp,
      status: "pending",
      membership_id: null,
    },
  };
  assert.equal(parseInvitation(invitation, org).data.status, "pending");
  assert.throws(() => parseInvitation(invitation, host));
  assert.throws(() =>
    parseInvitation(
      { ...invitation, data: { ...invitation.data, membership_id: member } },
      org,
    ),
  );
  assert.equal(
    "password" in
      parseInvitation(
        {
          ...invitation,
          data: { ...invitation.data, password: "response-extension" },
        },
        org,
      ).data,
    false,
  );
});

test("public facade sends original resource ETags and caller-owned create IDs/keys", async () => {
  const transport = new Transport(),
    api = new TeamApi(transport);
  api.accountId = account;
  await api.rename(parseOrganization(team, account), "Operations East");
  assert.deepEqual(transport.calls[0], {
    method: "PATCH",
    path: `/api/v1/orgs/${org}`,
    options: {
      body: { data: { name: "Operations East" } },
      etag: '"v1"',
      maximum: 4096,
    },
  });
  transport.response = {
    value: {
      ...meta(host),
      data: { schema: 1, fields: { name: "API", address: "example.com" } },
    },
    etag: '"v1"',
  };
  await api.save(
    org,
    "hosts",
    { name: "API", address: "example.com" },
    undefined,
    { id: host, key },
  );
  assert.deepEqual(transport.calls[1].options?.body, {
    id: host,
    data: { fields: { name: "API", address: "example.com" } },
  });
  assert.equal(transport.calls[1].options?.key, key);
  assert.equal(transport.calls[1].options?.etag, undefined);
});

test("acceptance receipt must echo captured invitation, team and account", async () => {
  const transport = new Transport(),
    api = new TeamApi(transport);
  api.accountId = account;
  transport.response = {
    value: {
      invitation_id: key,
      organization_id: org,
      account_id: account,
      membership_id: member,
      accepted_at: timestamp,
    },
    etag: null,
  };
  assert.equal(
    (await api.accept(org, key, "00000000", host)).membership_id,
    member,
  );
  transport.response.value = {
    invitation_id: key,
    organization_id: org,
    account_id: host,
    membership_id: member,
    accepted_at: timestamp,
  };
  await assert.rejects(api.accept(org, key, "00000000", host));
});

test("browser-generated operation IDs are fresh canonical UUIDv7 values", () => {
  const first = operationId(),
    second = operationId();
  assert.match(
    first,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.notEqual(first, second);
});
