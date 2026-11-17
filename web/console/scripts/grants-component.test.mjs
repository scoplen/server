// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import * as React from "react";
import { renderToStaticMarkup as render } from "react-dom/server";

let server, views, choices;
before(async () => {
  server = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    server: { middlewareMode: true, watch: null },
    appType: "custom",
  });
  views = await server.ssrLoadModule("/src/grants-view.tsx");
  choices = await server.ssrLoadModule("/src/grant-choice.tsx");
});
after(async () => {
  await server?.close();
});

test("Grant preview renders all exact fields, explicit nonexpiry and safely escapes values", () => {
  const fields = {
    membership: "member",
    host: "host",
    remote_user: " <ops&> ",
    valid_from: "2030-01-01T00:00:00Z",
    valid_until: null,
  };
  const html = render(
    React.createElement(views.GrantPreview, {
      fields,
      member: "alice",
      host: "Production",
    }),
  );
  assert.match(html, /alice/);
  assert.match(html, /Production/);
  assert.match(html, / &lt;ops&amp;&gt; /);
  assert.match(html, /2030-01-01T00:00:00Z/);
  assert.match(html, /No expiry/);
  assert.doesNotMatch(html, /<select|<script|<ops/);
});
test("Grant custom selector has a named keyboard trigger, current selection and no native selector", () => {
  const props = {
    label: "Member",
    placeholder: "Choose a member",
    options: [
      { id: "one", label: "alice" },
      { id: "two", label: "bob" },
    ],
    value: "two",
    disabled: false,
    onChange() {},
  };
  const html = render(React.createElement(choices.GrantChoice, props));
  assert.match(html, /aria-haspopup="listbox"/);
  assert.match(html, /aria-expanded="false"/);
  assert.match(html, /aria-labelledby=/);
  assert.match(html, />bob<\/span>/);
  assert.doesNotMatch(html, /<select/);
  const empty = render(
    React.createElement(choices.GrantChoice, {
      ...props,
      options: [],
      value: "",
    }),
  );
  assert.match(empty, /disabled=""/);
  assert.match(empty, /Choose a member/);
  assert.equal(choices.choiceIndex("ArrowDown", 1, 2), 0);
  assert.equal(choices.choiceIndex("ArrowUp", 0, 2), 1);
  assert.equal(choices.choiceIndex("Home", 1, 2), 0);
  assert.equal(choices.choiceIndex("End", 0, 2), 1);
  assert.equal(choices.choiceIndex("ArrowDown", 0, 0), -1);
});
test("Grant workspace first render exposes explicit actions and separates visibility from withdrawal", () => {
  const html = render(
    React.createElement(views.GrantPanel, {
      teamApi: { transport: {} },
      organization: "019a0000-0000-7000-8000-000000000001",
      disabled: false,
    }),
  );
  assert.match(html, /Host visibility is managed separately/);
  assert.match(
    html,
    /certificates already issued expire normally and existing SSH sessions continue/,
  );
  assert.match(html, /Create Grant/);
  assert.match(html, /aria-busy="true"/);
  assert.doesNotMatch(html, /<select/);
});
