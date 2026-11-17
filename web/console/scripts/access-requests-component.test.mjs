// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import * as React from "react";
import { renderToStaticMarkup as render } from "react-dom/server";

let server, views, rules;
before(async () => {
  server = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, watch: null, hmr: false },
    appType: "custom",
  });
  views = await server.ssrLoadModule("/src/access-requests-view.tsx");
  rules = await server.ssrLoadModule("/src/rule-editor.tsx");
});
after(async () => {
  await server?.close();
});

test("request review renders original identity, exact text, pending deadline and finite approval history safely", () => {
  const item = {
    id: "request",
    etag: '"v1"',
    created_at: "2030-01-01T00:00:00Z",
    updated_at: "2030-01-01T00:00:00Z",
    data: {
      requester_account_id: "requester-account",
      requester_membership_id: "requester-membership",
      host: "target-host",
      remote_user: " <ops&> ",
      duration_seconds: 3600,
      reason: " Inspect <script>\n\tbefore deployment ",
      status: "approved",
      expires_at: "2030-01-02T00:00:00.123456789Z",
      decision: {
        outcome: "approve",
        actor_account_id: "independent-approver",
        decided_at: "2030-01-01T00:00:00.123456789Z",
      },
      grant: {
        id: "grant",
        valid_from: "2030-01-01T00:00:00Z",
        valid_until: "2030-01-01T01:00:00Z",
      },
    },
  };
  const html = render(React.createElement(views.RequestPreview, { item }));
  for (const text of [
    "requester-account",
    "target-host",
    " &lt;ops&amp;&gt; ",
    " Inspect &lt;script&gt;\n\tbefore deployment ",
    "independent-approver",
    item.data.expires_at,
    item.data.grant.valid_from,
    item.data.grant.valid_until,
  ])
    assert.ok(html.includes(text), `missing reviewed field: ${text}`);
  assert.doesNotMatch(html, /<script>|<ops|<select/);
});
test("Requests first render exposes both bounded views and refresh without a creation or connection shortcut", () => {
  const html = render(
    React.createElement(views.AccessRequestPanel, {
      teamApi: { transport: {} },
      organization: "019a0000-0000-7000-8000-000000000001",
      account: "019a0000-0000-7000-8000-000000000002",
      disabled: false,
    }),
  );
  assert.match(html, /My requests/);
  assert.match(html, /Approvals/);
  assert.match(html, /Refreshes every 60 seconds/);
  assert.match(html, /aria-busy="true"/);
  assert.match(html, /current policy still decides new SSH connections/);
  assert.doesNotMatch(
    html,
    /<select|>Connect<|>Create request<|>Approve<|>Deny</,
  );
});
test("ordinary rule editor offers the independent request permission and a named custom subject selector", () => {
  const html = render(
    React.createElement(rules.SimpleRuleEditor, {
      organization: "019a0000-0000-7000-8000-000000000001",
      members: [
        { id: "member", data: { status: "active", username: "alice" } },
      ],
      groups: [],
      assets: [],
      shared: {
        generate() {
          throw new Error("preview must be explicit");
        },
      },
      disabled: false,
      saving: false,
      onSave() {},
      onCancel() {},
    }),
  );
  assert.match(html, /May view selected assets/);
  assert.match(html, /May connect to selected Hosts/);
  assert.match(html, /May request temporary access/);
  assert.match(html, /aria-haspopup="listbox"/);
  assert.match(html, /aria-labelledby=/);
  assert.doesNotMatch(html, /<select/);
});
