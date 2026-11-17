// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { File } from "node:buffer";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { TextEncoder } from "node:util";
import { createServer } from "vite";
import * as React from "react";
import { renderToStaticMarkup as render } from "react-dom/server";

let server, shared, model, team, views;
before(async () => {
  server = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, watch: null, hmr: false, ws: false },
    optimizeDeps: { noDiscovery: true },
    appType: "custom",
  });
  const browser = await server.ssrLoadModule(
    "/.browser/pkg/scoplen_browser.js",
  );
  await browser.default({
    module_or_path: await readFile(
      new URL("../.browser/pkg/scoplen_browser_bg.wasm", import.meta.url),
    ),
  });
  shared = (await server.ssrLoadModule("/src/browser-shared.ts")).sharedBrowser;
  model = await server.ssrLoadModule("/src/inventory-import.ts");
  team = await server.ssrLoadModule("/src/team.ts");
  views = await server.ssrLoadModule("/src/inventory-import-view.tsx");
});
after(async () => {
  await server?.close();
});

const header = "name,address,port,username,login_name";
const bytes = (source) => new TextEncoder().encode(source);
test("the production Console adapter invokes the published Rust WASM CSV parser with exact whitespace and default conversion", async () => {
  const rows = await shared.csv.parse(
    bytes(
      `\ufeff${header}\r\n" Web, ""edge"" ",example.test,,operator," Operations "\r\nSecond,second.test,2200,root,`,
    ),
  );
  assert.deepEqual(rows, [
    {
      name: ' Web, "edge" ',
      address: "example.test",
      port: 22,
      username: "operator",
      login_name: " Operations ",
    },
    { name: "Second", address: "second.test", port: 2200, username: "root" },
  ]);
  assert.equal("login_name" in rows[1], false);
});
test("the production adapter reports fixed Rust parser errors without source content", async () => {
  for (const [input, kind, field] of [
    [new Uint8Array([0xc3, 0x28]), "invalid_utf8"],
    [bytes(`${header}\n"private-fixture-source`), "invalid_csv"],
    [
      bytes(
        "private-fixture-source,address,port,username,login_name\nHost,example.test,,ops,",
      ),
      "invalid_header",
    ],
    [bytes(`${header}\nHost,example.test,022,ops,`), "invalid_cell", "port"],
    [bytes(`${header}\n,example.test,,ops,`), "invalid_cell", "name"],
    [bytes(""), "empty_input"],
    [
      bytes(
        `${header}\n${Array(101).fill("Host,example.test,,ops,").join("\n")}`,
      ),
      "too_many_records",
    ],
    [new Uint8Array(1_048_577), "too_large"],
  ]) {
    await assert.rejects(shared.csv.parse(input), (failure) => {
      assert.ok(failure instanceof model.InventoryCsvFailure);
      assert.equal(failure.kind, kind);
      if (field) {
        assert.equal(failure.record, 1);
        assert.equal(failure.field, field);
      }
      assert.doesNotMatch(JSON.stringify(failure), /private-fixture-source/);
      return true;
    });
  }
});
test("100 actual rows flow from published parser to complete preview and one explicit atomic request", async () => {
  let posts = 0;
  const transport = {
    origin: "https://console.example",
    async request(method, path, options) {
      posts++;
      assert.equal(method, "POST");
      assert.match(path, /\/inventory\/imports$/);
      return {
        value: {
          items: options.body.rows.map(({ host_id, access_profile_id }) => ({
            host_id,
            access_profile_id,
          })),
        },
        etag: null,
      };
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
    shared.csv,
  );
  const source = `${header}\n${Array.from({ length: 100 }, (_, index) => `Host ${index + 1},example.test,,ops,`).join("\n")}`;
  await workflow.prepare(new File([source], "inventory.csv"));
  assert.equal(workflow.state.phase, "preview");
  assert.equal(posts, 0);
  const html = render(
    React.createElement(views.InventoryImportPreview, {
      body: workflow.state.preview,
    }),
  );
  assert.equal((html.match(/<li>/g) ?? []).length, 100);
  assert.match(html, /Host 100/);
  await workflow.submit();
  assert.equal(posts, 1);
  assert.equal(workflow.state.phase, "complete");
  assert.equal(workflow.state.imported, 100);
});

test("the production published WASM OpenSSH adapter retains complete mixed outcomes before an explicit ordered subset import", async () => {
  const source =
    'Host Mixed\n HostName prefix-%h\n User "part"word\n Port=2203\nHost Blocked\n ProxyJump none\nHost Last\n User Ops';
  const candidates = await shared.openssh.parse(bytes(source));
  assert.deepEqual(candidates, [
    {
      status: "ready",
      candidate: 1,
      fields: {
        name: "Mixed",
        address: "prefix-mixed",
        port: 2203,
        username: "partword",
      },
    },
    {
      status: "blocked",
      diagnostic: { kind: "unsupported_option", line: 6, candidate: 2 },
    },
    {
      status: "ready",
      candidate: 3,
      fields: { name: "Last", address: "last", port: 22, username: "Ops" },
    },
  ]);
  const posts = [];
  const api = new team.TeamApi({
    origin: "https://console.example",
    async request(method, path, options) {
      posts.push({ method, path, options });
      return {
        value: {
          items: options.body.rows.map(({ host_id, access_profile_id }) => ({
            host_id,
            access_profile_id,
          })),
        },
        etag: null,
      };
    },
  });
  api.accountId = "019a0000-0000-7000-8000-000000000002";
  const workflow = new model.InventoryImportWorkflow(
    new model.InventoryImportApi(
      api,
      "019a0000-0000-7000-8000-000000000001",
      api.accountId,
    ),
    shared.csv,
    shared.openssh,
  );
  workflow.setSource("openssh");
  await workflow.prepare(new File([source], "synthetic-source-name"));
  assert.deepEqual(workflow.state.selected, []);
  const html = render(
    React.createElement(views.InventoryOpenSshPreview, {
      state: workflow.state,
      disabled: false,
      onSelect() {},
    }),
  );
  assert.equal((html.match(/<li>/g) ?? []).length, 3);
  assert.match(html, /prefix-mixed/);
  assert.match(html, /Blocked/);
  assert.doesNotMatch(html, /ProxyJump|synthetic-source-name/);
  await workflow.submit();
  assert.equal(posts.length, 0);
  workflow.select(3);
  workflow.select(1);
  await workflow.submit();
  assert.equal(posts.length, 1);
  assert.equal(posts[0].method, "POST");
  assert.match(posts[0].path, /\/inventory\/imports$/);
  assert.deepEqual(
    posts[0].options.body.rows.map((row) => row.name),
    ["Mixed", "Last"],
  );
  for (const row of posts[0].options.body.rows)
    assert.deepEqual(Object.keys(row).sort(), [
      "access_profile_id",
      "address",
      "host_id",
      "name",
      "port",
      "username",
    ]);
  assert.equal(workflow.state.phase, "complete");
});

test("actual WASM OpenSSH file failures remain fixed and do not expose source values", async () => {
  const openssh = await server.ssrLoadModule("/src/inventory-openssh.ts");
  for (const [input, kind, line] of [
    [
      bytes("Host synthetic-private-alias\nInclude /synthetic/private/path"),
      "unsupported_scope",
      2,
    ],
    [
      bytes('Host synthetic-private-alias\nUser "unclosed'),
      "invalid_syntax",
      2,
    ],
    [new Uint8Array([0xc3, 0x28]), "invalid_utf8"],
    [new Uint8Array(1_048_577), "raw_too_large"],
    [bytes("Host *\nUser ops"), "no_candidates"],
  ])
    await assert.rejects(shared.openssh.parse(input), (failure) => {
      assert.ok(failure instanceof openssh.InventoryOpenSshFailure);
      assert.equal(failure.kind, kind);
      assert.equal(failure.line, line);
      assert.doesNotMatch(
        JSON.stringify(failure),
        /synthetic-private|\/synthetic|unclosed/,
      );
      return true;
    });
  const rows = await shared.openssh.parse(
    bytes(
      `Host ${Array.from({ length: 100 }, (_, index) => `Host${index}`).join(" ")}\nUser ops`,
    ),
  );
  assert.equal(rows.length, 100);
  assert.equal(rows[99].candidate, 100);
});
