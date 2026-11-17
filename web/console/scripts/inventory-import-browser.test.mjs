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
