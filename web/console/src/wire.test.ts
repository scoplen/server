// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bytes,
  encoded,
  strictJson,
  jsonResponse,
  timestamp,
  sessionResponse,
  invitationResponse,
  logoutResponse,
} from "./wire.ts";

test("logout confirms only one true revoked member", () => {
  assert.deepEqual(logoutResponse({ revoked: true }), { revoked: true });
  for (const value of [
    null,
    [],
    {},
    { revoked: false },
    { revoked: 1 },
    { revoked: "true" },
    { revoked: true, sid: "other" },
  ])
    assert.throws(() => logoutResponse(value));
  assert.throws(() =>
    logoutResponse(strictJson('{"revoked":true,"rev\\u006fked":true}')),
  );
});

test("canonical bounded base64url rejects aliases and unused pad bits", () => {
  assert.deepEqual(bytes("AA", 1), new Uint8Array([0]));
  for (const value of ["AB", "AA==", "AA+", "", "A", "AAAA"])
    assert.throws(() => bytes(value, 1));
  assert.equal(
    encoded(new Uint8Array(32)),
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  );
});

test("response JSON rejects duplicate names recursively including escaped extensions", () => {
  for (const source of [
    '{"a":1,"a":2}',
    '{"a":1,"\\u0061":2}',
    '{"x":[{"a":0,"a":1}]}',
    '{"x": {"x":1,"x":2}}',
  ])
    assert.throws(() => strictJson(source));
  assert.deepEqual(
    strictJson('{"x":[{},true,null,"a\\"b",-1.2e3],"y":{"x":1}}'),
    { x: [{}, true, null, 'a"b', -1200], y: { x: 1 } },
  );
  for (const source of [
    "",
    "true false",
    "[1,]",
    "{x:1}",
    '"unterminated',
    "[[[",
    "0garbage",
    "{",
    `${"[".repeat(65)}0${"]".repeat(65)}`,
  ])
    assert.throws(() => strictJson(source));
});

test("streamed JSON enforces byte ceilings and strict UTF-8 across chunks", async () => {
  await assert.rejects(jsonResponse(new Response('{"a":true}'), 4));
  await assert.rejects(
    jsonResponse(new Response(new Uint8Array([0x22, 0xff, 0x22])), 100),
  );
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([0x22, 0xc3]));
      controller.enqueue(new Uint8Array([0xa9, 0x22]));
      controller.close();
    },
  });
  assert.equal(await jsonResponse(new Response(stream), 4), "é");
  await assert.rejects(jsonResponse(new Response(null), 100));
});

test("browser session rejects native refresh credentials and invalid lifetimes", () => {
  const session = {
    access_token: "signed-token",
    token_type: "DPoP",
    expires_in: 900,
    refresh_expires_in: 2592000,
  };
  assert.deepEqual(sessionResponse(session), session);
  for (const patch of [
    { refresh_token: "secret" },
    { expires_in: 0 },
    { expires_in: 0.5 },
    { expires_in: Number.MAX_SAFE_INTEGER + 1 },
    { access_token: "bad token" },
    { token_type: "Bearer" },
  ])
    assert.throws(() => sessionResponse({ ...session, ...patch }));
});

test("invitation stays on exact trusted origin and carries only canonical fragment token", () => {
  const input = {
    invitation_url: `https://operator.example/invite#token=${encoded(new Uint8Array(32))}`,
    expires_at: "2030-01-02T03:04:05Z",
  };
  assert.deepEqual(
    invitationResponse(input, "https://operator.example"),
    input,
  );
  for (const url of [
    input.invitation_url.replace("operator.example", "operator.example.evil"),
    input.invitation_url + "&extra=1",
    input.invitation_url.replace("/invite#", "/invite?#"),
  ])
    assert.throws(() =>
      invitationResponse(
        { ...input, invitation_url: url },
        "https://operator.example",
      ),
    );
  for (const date of [
    "2030-02-30T00:00:00Z",
    "2030-01-01T00:00:00.000Z",
    "2030-01-01T00:00:00+00:00",
  ])
    assert.throws(() => timestamp(date));
});
