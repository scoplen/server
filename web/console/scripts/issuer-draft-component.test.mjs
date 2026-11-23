// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

let server, panel, detail;
before(async () => {
  server = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, watch: null, hmr: false, ws: false },
    appType: "custom",
  });
  ({ IssuerDraftPanel: panel, DraftDetail: detail } =
    await server.ssrLoadModule("/src/issuer-draft-view.tsx"));
});
after(async () => {
  await server?.close();
});

test("team issuer settings start closed to writes until the selected organization's draft is read", () => {
  const html = renderToStaticMarkup(
    createElement(panel, {
      api: {},
      organization: "team",
      teamName: "Team",
      handle: { current: null },
      disabled: false,
      onBusy() {},
    }),
  );
  assert.match(html, /Connect Plystra Auth/);
  assert.match(html, /aria-busy="true"/);
  assert.match(html, /Read current draft/);
  assert.doesNotMatch(
    html,
    /<input|<a |Save draft|Cancel this draft|type="password"/,
  );
});

test("current draft renders the exact issuer as inert text and names its generation for review", () => {
  const draft = {
    id: "019a0000-0000-7000-8000-000000000003",
    data: { issuer: "https://Issuer.example/Tenant<&>/" },
  };
  const html = renderToStaticMarkup(createElement(detail, { draft }));
  assert.match(html, /<h3>Issuer draft<\/h3>/);
  assert.match(html, /https:\/\/Issuer\.example\/Tenant&lt;&amp;&gt;\//);
  assert.ok(html.includes(draft.id));
  assert.doesNotMatch(html, /<a |href=|src=|<input/);
});
