// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import { createServer } from "vite";
import * as React from "react";
import { renderToStaticMarkup as render } from "react-dom/server";

let server, views, locale, rules;
before(async () => {
  server = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, watch: null, hmr: false, ws: false },
    appType: "custom",
  });
  views = await server.ssrLoadModule("/src/snippets-view.tsx");
  locale = await server.ssrLoadModule("/src/locale.tsx");
  rules = await server.ssrLoadModule("/src/rule-editor.tsx");
});
after(async () => {
  await server?.close();
});
const fields = {
  name: " <Deployment&> ",
  template: 'echo "{{label}}" <&>',
  variables: {
    label: { kind: 1, default: " <ops&> " },
    count: { kind: 2, default: "9223372036854775807" },
    target: { kind: 3, choices: ["a", "b"], default: "b" },
    token: { kind: 4 },
  },
  tags: { deploy: true },
  folder: "Operations",
};
test("Snippet editor uses named custom selectors for all four variable definitions and no secret default", () => {
  const html = render(
    React.createElement(views.SnippetEditor, {
      initial: fields,
      disabled: false,
      onSave() {},
      onCancel() {},
    }),
  );
  assert.equal((html.match(/aria-haspopup="listbox"/g) ?? []).length, 4);
  assert.equal((html.match(/Set default/g) ?? []).length, 3);
  for (const detail of [
    "Text",
    "Integer",
    "Choice",
    "Secret",
    "Variable name",
    "9223372036854775807",
    "Saving never runs this template",
    "definitions, not values for a session",
    "Secret variables never have defaults",
    "Save Snippet",
    "Add choice",
    "Add variable",
    "Add tag",
  ])
    assert.ok(html.includes(detail), detail);
  assert.match(html, /&lt;Deployment&amp;&gt;/);
  assert.doesNotMatch(
    html,
    /<select|type="password"|type="number"|<script|<Deployment/,
  );
});
test("Snippet library detail preserves and safely displays template, choices, tags, folder and integer strings", () => {
  const html = render(
    React.createElement(views.SnippetDetail, {
      item: { id: "snippet", data: { fields } },
    }),
  );
  for (const value of [
    "&lt;Deployment&amp;&gt;",
    "{{label}}",
    "&lt;&amp;&gt;",
    "9223372036854775807",
    "Operations",
    "deploy",
    "Secret",
  ])
    assert.ok(html.includes(value), value);
  assert.match(html, /<pre class="snippet-template">/);
  assert.doesNotMatch(html, /<button|<input|<select|<script/);
});
test("Snippet panel initially exposes library loading and explicit authoring without an execution action", () => {
  const html = render(
    React.createElement(views.SnippetPanel, {
      teamApi: {},
      organization: "team",
      account: "account",
      disabled: false,
      handle: { current: null },
      onBusy() {},
    }),
  );
  assert.match(html, /aria-busy="true"/);
  assert.match(html, /Create Snippet/);
  assert.match(html, /Refresh and review/);
  assert.match(html, /Execution and session values stay in the desktop app/);
  assert.doesNotMatch(html, /<select|>Execute<|>Connect<|type="password"/);
});
test("Snippet editor and detail support both maintained locales", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    for (const language of ["en", "zh-CN"]) {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { language },
      });
      const html = render(
        React.createElement(
          locale.LocaleProvider,
          null,
          React.createElement(views.SnippetEditor, {
            initial: fields,
            disabled: true,
            onSave() {},
            onCancel() {},
          }),
        ),
      );
      assert.ok(html.includes(language === "en" ? "Save Snippet" : "保存片段"));
      assert.match(html, /<fieldset[^>]*disabled=""/);
      assert.doesNotMatch(html, /<select/);
    }
  } finally {
    if (original) Object.defineProperty(globalThis, "navigator", original);
    else delete globalThis.navigator;
  }
});
test("the ordinary View editor labels a loaded Snippet and the published WASM generates its existing type-7 permission", async () => {
  const organization = "019a0000-0000-7000-8000-000000000001",
    membership = "019a0000-0000-7000-8000-000000000002",
    id = "019a0000-0000-7000-8000-000000000003";
  const html = render(
    React.createElement(rules.SimpleRuleEditor, {
      organization,
      members: [],
      groups: [],
      assets: [
        {
          type: 7,
          id,
          label: "Deployment",
          kind: "snippets",
          resource: { id, data: { schema: 1, fields } },
        },
      ],
      shared: {
        generate() {
          throw new Error("explicit preview required");
        },
      },
      disabled: false,
      saving: false,
      onSave() {},
      onCancel() {},
    }),
  );
  assert.match(html, /Deployment/);
  assert.match(html, /Snippet ·/);
  assert.doesNotMatch(html, /<select/);
  const browser = await server.ssrLoadModule(
    "/.browser/pkg/scoplen_browser.js",
  );
  await browser.default({
    module_or_path: await readFile(
      new URL("../.browser/pkg/scoplen_browser_bg.wasm", import.meta.url),
    ),
  });
  const shared = (await server.ssrLoadModule("/src/browser-shared.ts"))
    .sharedBrowser;
  const source = await shared.rules.generate({
    organization,
    membership,
    view: [{ type: 7, id }],
  });
  assert.ok(source.includes(`Snippet::"${id}"`));
  assert.match(source, /view_inventory/);
  assert.doesNotMatch(source, /connect_host/);
});
