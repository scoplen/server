// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { File } from "node:buffer";
import { createServer } from "vite";
import * as React from "react";
import { renderToStaticMarkup as render } from "react-dom/server";

let server, views, model, team;
before(async () => {
  server = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, watch: null, hmr: false, ws: false },
    appType: "custom",
  });
  views = await server.ssrLoadModule("/src/inventory-import-view.tsx");
  model = await server.ssrLoadModule("/src/inventory-import.ts");
  team = await server.ssrLoadModule("/src/team.ts");
});
after(async () => {
  await server?.close();
});

const row = (index) => ({
  host_id: `host-${index}`,
  access_profile_id: `login-${index}`,
  name: ` Host <&> ${index} `,
  address: `host-${index}.example.test`,
  port: index === 1 ? 2200 : 22,
  username: ` ops-${index} `,
  ...(index % 2 ? { login_name: ` Login ${index} ` } : {}),
});
const now = Date.parse("2030-01-01T00:00:00Z");
function content(state, extra = {}) {
  return render(
    React.createElement(views.InventoryImportContent, {
      state,
      disabled: false,
      now,
      onFile() {
        throw new Error("file must be chosen explicitly");
      },
      onSubmit() {
        throw new Error("import must be explicit");
      },
      onConfirm() {
        throw new Error("confirmation must be explicit");
      },
      onClose() {},
      ...extra,
    }),
  );
}
test("CSV entry discloses new assets, exact header, limits and no connection or overwrite", () => {
  const html = content({ phase: "empty", imported: 0 });
  for (const text of [
    "new Direct Host and default Login",
    "including duplicate names or endpoints",
    "does not overwrite assets or connect",
    "name,address,port,username,login_name",
    "1 MiB and 100 Hosts",
    "NFC",
    'type="file"',
  ])
    assert.ok(html.includes(text), `missing entry detail: ${text}`);
  assert.doesNotMatch(
    html,
    />Import \d+ hosts<|Confirm original import|<select/,
  );
});
test("CSV picker owns a named secondary button and hidden input with matching disabled state", () => {
  for (const disabled of [false, true]) {
    const html = content({ phase: "empty", imported: 0 }, { disabled });
    const button = html.match(/<button\b([^>]*)>Choose CSV file<\/button>/);
    assert.ok(button, "missing named CSV picker button");
    assert.match(button[1], /type="button"/);
    assert.match(button[1], /class="secondary"/);
    const helpId = button[1].match(/aria-describedby="([^"]+)"/)?.[1];
    assert.ok(helpId, "missing CSV picker description");
    assert.ok(html.includes(`<span id="${helpId}" class="field-help">`));
    const input = html.match(/<input\b[^>]*type="file"[^>]*>/)?.[0];
    assert.ok(input, "missing CSV file input");
    assert.match(input, /accept="\.csv,text\/csv"/);
    assert.match(input, /aria-label="CSV file"/);
    assert.match(input, /hidden=""/);
    assert.equal(button[1].includes('disabled=""'), disabled);
    assert.equal(input.includes('disabled=""'), disabled);
  }
});

test("preview includes every actual row and all five fields with preserved whitespace and safe escaping", () => {
  const body = {
    rows: Array.from({ length: 100 }, (_, index) => row(index + 1)),
  };
  const html = content({ phase: "preview", preview: body, imported: 0 });
  assert.equal((html.match(/<li>/g) ?? []).length, 100);
  for (let index = 1; index <= 100; index++) {
    for (const text of [
      ` Host &lt;&amp;&gt; ${index} `,
      `host-${index}.example.test`,
      ` ops-${index} `,
    ])
      assert.ok(html.includes(text), `missing actual row ${index}`);
    if (index % 2) assert.ok(html.includes(` Login ${index} `));
  }
  assert.match(html, /2200/);
  assert.match(html, /Not set/);
  assert.match(html, />Import 100 hosts<\/button>/);
  assert.match(html, /aria-label="Hosts to import"/);
  assert.doesNotMatch(html, /<select|<script>|<&amp;/);
});
test("loading, fixed parse errors and authority failure remain distinct", () => {
  const parsing = content({ phase: "parsing", imported: 0 });
  assert.match(parsing, /aria-busy="true"/);
  assert.match(parsing, /Preparing CSV preview/);
  assert.doesNotMatch(parsing, /type="file"|Import outcome unknown/);
  const error = content({
    phase: "empty",
    failure: new model.InventoryCsvFailure("invalid_cell", 3, "username"),
    imported: 0,
  });
  assert.match(error, /Data record 3/);
  assert.match(error, /Field: Username/);
  assert.match(error, /No import request was sent/);
  const denied = content({
    phase: "preview",
    preview: { rows: [row(1)] },
    failure: new team.RequestFailure("policy.denied", 403),
    imported: 0,
  });
  assert.match(denied, /current permissions do not allow/);
  assert.doesNotMatch(denied, /Import outcome unknown|Confirm original import/);
});
test("uncertainty and expiry retain original preview, explicit confirmation and conservative denial feedback", () => {
  const body = { rows: [row(1), row(2)] };
  const pending = {
    body,
    key: "original-key",
    deadline: now + 86_400_000,
    context: {
      origin: "https://console.example",
      account: "account",
      organization: "team",
    },
  };
  const state = {
    phase: "uncertain",
    preview: body,
    pending,
    failure: new team.RequestFailure("policy.denied", 403),
    imported: 0,
  };
  const html = content(state);
  for (const text of [
    "Import outcome unknown",
    "No request is retried automatically",
    "Confirm original import",
    "earlier outcome is still unknown",
    "Discard and review inventory",
  ])
    assert.ok(html.includes(text), `missing uncertainty detail: ${text}`);
  assert.equal((html.match(/<li>/g) ?? []).length, 2);
  assert.doesNotMatch(html, /No business change|>Import 2 hosts<|type="file"/);
  const expired = content(state, { now: pending.deadline });
  assert.match(expired, /confirmation window has expired/);
  assert.match(expired, /disabled="">Confirm original import/);
  const sending = content({ ...state, phase: "importing", failure: undefined });
  assert.match(sending, /Importing the reviewed Hosts/);
  assert.doesNotMatch(
    sending,
    /Import outcome unknown|Confirm original import/,
  );
});
test("verified completion and failed refresh cannot suggest that another import is needed", () => {
  const html = content(
    { phase: "complete", imported: 100 },
    { refreshFailed: true },
  );
  assert.match(html, /Import confirmed for 100 hosts/);
  assert.match(html, /Current inventory could not be refreshed/);
  assert.doesNotMatch(
    html,
    />Import \d+ hosts<|Confirm original import|type="file"/,
  );
});

test("a fresh session clears the old import preview before the component can expose or confirm it", async () => {
  let generation = 0,
    posts = 0;
  const transport = {
    origin: "https://console.example",
    get sessionGeneration() {
      return generation;
    },
    async request() {
      posts++;
      throw new team.RequestFailure("response_lost", 0, true);
    },
  };
  const api = new team.TeamApi(transport);
  api.accountId = "019a0000-0000-7000-8000-000000000002";
  const workflow = new model.InventoryImportWorkflow(
    new model.InventoryImportApi(
      api,
      "019a0000-0000-7000-8000-000000000001",
      api.accountId,
    ),
    {
      parse: async () => [
        {
          name: "Previous private Host",
          address: "previous.example.test",
          port: 22,
          username: "ops",
        },
      ],
    },
  );
  await workflow.prepare(new File(["fixture"], "inventory.csv"));
  await workflow.submit();
  assert.match(content(workflow.state), /Previous private Host/);
  generation++;
  await assert.rejects(workflow.confirmOriginal());
  assert.equal(posts, 1);
  const html = content(workflow.state);
  assert.doesNotMatch(
    html,
    /Previous private Host|previous.example.test|Confirm original import/,
  );
  assert.equal(workflow.state.pending, undefined);
  assert.equal(workflow.state.preview, undefined);
});
