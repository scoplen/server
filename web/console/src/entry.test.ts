// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { consoleEntry } from "./entry.ts";
import { encoded } from "./wire.ts";

const origin = "https://console.example";
const org = "019a0000-0000-7000-8000-000000000001";
const invitation = "019a0000-0000-7000-8000-000000000002";

test("ordinary Account entry preserves the existing Operator bootstrap URL and immediately scrubs fragments", () => {
  const replacements: string[] = [];
  const replace = (path: string) => {
    replacements.push(path);
  };
  const token = encoded(new Uint8Array(32));
  assert.deepEqual(
    consoleEntry(new URL(`${origin}/setup?unused=x#token=${token}`), replace),
    { kind: "operator", setupToken: token, invalidLink: false },
  );
  assert.deepEqual(replacements, ["/setup"]);
  assert.deepEqual(
    consoleEntry(new URL(`${origin}/setup#token=invalid`), replace),
    { kind: "operator", invalidLink: true },
  );
  assert.equal(replacements.at(-1), "/setup");
  assert.deepEqual(
    consoleEntry(new URL(`${origin}/operator#token=${token}`), replace),
    { kind: "operator", setupToken: undefined, invalidLink: false },
  );
  assert.deepEqual(consoleEntry(new URL(origin), replace), {
    kind: "account",
    target: undefined,
    invalidLink: false,
  });
  assert.deepEqual(
    consoleEntry(
      new URL(
        `${origin}/join-team#organization=${org}&invitation=${invitation}`,
      ),
      replace,
    ),
    {
      kind: "account",
      target: { organization: org, invitation },
      invalidLink: false,
    },
  );
  assert.equal(replacements.at(-1), "/join-team");
  assert.deepEqual(
    consoleEntry(new URL(`${origin}/join-team#organization=invalid`), replace),
    { kind: "account", invalidLink: true },
  );
  assert.equal(replacements.at(-1), "/join-team");
  const root = consoleEntry(new URL(`${origin}/#token=${token}`), replace);
  assert.equal(root.kind, "account");
  assert.equal("setupToken" in root, false);
  assert.equal(replacements.at(-1), "/");
});
