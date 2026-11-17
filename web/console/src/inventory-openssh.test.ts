// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  InventoryOpenSshFailure,
  openSshFailure,
  parsedInventoryOpenSsh,
  type InventoryOpenSshCandidate,
  type InventoryOpenSshParser,
} from "./inventory-openssh.ts";
import {
  InventoryImportApi,
  InventoryImportWorkflow,
} from "./inventory-import.ts";
import type { InventoryImportRequest } from "./generated/api.ts";
import { RequestFailure, TeamApi, type RequestOptions } from "./team.ts";

const ready = (candidate: number): InventoryOpenSshCandidate => ({
  status: "ready",
  candidate,
  fields: {
    name: ` Host <&> ${candidate} `,
    address: `host-${candidate}.example`,
    port: 22,
    username: " Ops ",
  },
});
const candidates: InventoryOpenSshCandidate[] = [
  ready(1),
  {
    status: "blocked",
    diagnostic: { kind: "unsupported_option", candidate: 2, line: 4 },
  },
  ready(3),
  ready(4),
];
const file = () => new File(["synthetic configuration"], "config");
function setup(
  parser: InventoryOpenSshParser = { parse: async () => candidates },
) {
  const calls: RequestOptions[] = [];
  const transport = {
    origin: "https://console.example",
    sessionGeneration: 1,
    async request(
      _method: unknown,
      path: string,
      options: RequestOptions = {},
    ) {
      assert.match(path, /\/inventory\/imports$/);
      calls.push(options);
      const body = options.body as InventoryImportRequest;
      return {
        value: {
          items: body.rows.map(({ host_id, access_profile_id }) => ({
            host_id,
            access_profile_id,
          })),
        },
        etag: null,
      };
    },
  };
  const api = new TeamApi(transport);
  api.accountId = "019a0000-0000-7000-8000-000000000002";
  const workflow = new InventoryImportWorkflow(
    new InventoryImportApi(
      api,
      "019a0000-0000-7000-8000-000000000001",
      api.accountId,
    ),
    {
      parse: async () => {
        throw new Error("CSV parser must not interpret OpenSSH");
      },
    },
    parser,
  );
  workflow.setSource("openssh");
  return { workflow, transport, calls };
}

test("shared projection preserves all candidate outcomes and exact typed fields without ids", () => {
  const decoded = parsedInventoryOpenSsh(JSON.stringify({ candidates }));
  assert.deepEqual(decoded, candidates);
  assert.equal("host_id" in decoded[0], false);
  assert.equal("selected" in decoded[0], false);
  for (const candidate of decoded)
    if (candidate.status === "ready")
      assert.equal("login_name" in candidate.fields, false);
});

test("strict projection and fixed file metadata reject malformed shapes without retaining source", () => {
  const marker = "synthetic-source-must-not-escape";
  for (const value of [
    { candidates: [] },
    { candidates: [...candidates, ready(4)] },
    { candidates: [ready(2)] },
    { candidates: [{ ...ready(1), extra: marker }] },
    {
      candidates: [
        { status: "blocked", diagnostic: { candidate: 1, kind: marker } },
      ],
    },
    {
      candidates: [
        {
          status: "blocked",
          diagnostic: { candidate: 1, kind: "invalid_field", field: marker },
        },
      ],
    },
    {
      candidates: [
        {
          status: "blocked",
          diagnostic: { candidate: 1, kind: "invalid_field", line: 0 },
        },
      ],
    },
    {
      candidates: [
        {
          status: "blocked",
          diagnostic: { candidate: 1, kind: "invalid_field", source: marker },
        },
      ],
    },
    { candidates: Array.from({ length: 101 }, (_, i) => ready(i + 1)) },
  ])
    assert.throws(
      () => parsedInventoryOpenSsh(JSON.stringify(value)),
      (error) => {
        assert.ok(error instanceof InventoryOpenSshFailure);
        assert.equal(error.kind, "unavailable");
        assert.doesNotMatch(JSON.stringify(error), new RegExp(marker));
        return true;
      },
    );
  assert.throws(() =>
    parsedInventoryOpenSsh('{"candidates":[],"candidates":[]}'),
  );
  assert.deepEqual(
    openSshFailure('{"kind":"unsupported_scope","line":8}'),
    new InventoryOpenSshFailure("unsupported_scope", 8),
  );
  for (const value of [
    marker,
    new Error(marker),
    `{"kind":"${marker}"}`,
    '{"kind":"invalid_syntax","line":null}',
    `{"kind":"invalid_syntax","source":"${marker}"}`,
  ]) {
    const failure = openSshFailure(value);
    assert.equal(failure.kind, "unavailable");
    assert.doesNotMatch(JSON.stringify(failure), new RegExp(marker));
  }
});

test("preparation defaults to no selection and allocates ids only once for the explicitly selected ordered subset", async () => {
  const { workflow, calls } = setup();
  let allocations = 0;
  const random = mock.method(crypto, "getRandomValues", (output: Uint8Array) =>
    output.fill(++allocations),
  );
  try {
    await workflow.prepare(file());
    assert.equal(allocations, 0);
    assert.deepEqual(workflow.state.selected, []);
    assert.equal(workflow.state.preview, undefined);
    assert.equal(workflow.state.candidates?.length, 4);
    await workflow.submit();
    workflow.select(2);
    assert.deepEqual(workflow.state.selected, []);
    workflow.select(4);
    workflow.select(1);
    workflow.select(3);
    workflow.select(3);
    assert.deepEqual(workflow.state.selected, [1, 4]);
    assert.equal(allocations, 0);
    assert.equal(calls.length, 0);
    await workflow.submit();
    assert.equal(
      allocations,
      5,
      "two ids per selected row and one operation key",
    );
    assert.equal(calls.length, 1);
    const body = calls[0].body as InventoryImportRequest;
    assert.deepEqual(
      body.rows.map((row) => row.name),
      [" Host <&> 1 ", " Host <&> 4 "],
    );
    assert.equal(
      body.rows.some(
        (row) => "status" in row || "candidate" in row || "login_name" in row,
      ),
      false,
    );
    assert.ok(
      Object.isFrozen(body) &&
        Object.isFrozen(body.rows) &&
        body.rows.every(Object.isFrozen),
    );
    assert.equal(workflow.state.phase, "complete");
  } finally {
    random.mock.restore();
  }
});

test("an uncertain selected import retains exact ids and key and cannot change source or selection", async () => {
  const { workflow, transport, calls } = setup();
  await workflow.prepare(file());
  workflow.select(3);
  const original = transport.request.bind(transport);
  transport.request = async (...args) => {
    await original(...args);
    throw new RequestFailure("response_lost", 0, true);
  };
  await workflow.submit();
  const intent = workflow.state.pending!;
  assert.equal(workflow.state.phase, "uncertain");
  workflow.setSource("csv");
  workflow.select(1);
  await workflow.prepare(file());
  assert.equal(workflow.state.pending, intent);
  assert.equal(calls.length, 1);
  transport.request = original;
  await workflow.confirmOriginal();
  assert.equal(calls[1].body, intent.body);
  assert.equal(calls[1].key, intent.key);
  assert.equal(workflow.state.imported, 1);
});

test("source changes clear previews; file errors and fresh sessions expose no old candidate data", async () => {
  const { workflow, transport, calls } = setup();
  await workflow.prepare(file());
  workflow.select(1);
  workflow.setSource("csv");
  assert.equal(workflow.state.candidates, undefined);
  assert.equal(workflow.state.selected, undefined);
  workflow.setSource("openssh");
  await workflow.prepare(file());
  transport.sessionGeneration++;
  assert.throws(() => workflow.select(1), RequestFailure);
  assert.equal(workflow.state.candidates, undefined);
  assert.equal(workflow.state.preview, undefined);
  assert.equal(calls.length, 0);
  const invalid = setup({
    parse: async () => {
      throw new InventoryOpenSshFailure("invalid_syntax", 3);
    },
  });
  await invalid.workflow.prepare(file());
  assert.equal(invalid.workflow.state.phase, "empty");
  assert.equal(invalid.workflow.state.candidates, undefined);
  assert.equal(
    (invalid.workflow.state.failure as InventoryOpenSshFailure).line,
    3,
  );
  await invalid.workflow.submit();
  assert.equal(invalid.calls.length, 0);
});

test("disposing while shared preparation is pending fences the late result and clears the owned bytes", async () => {
  let finish: (value: InventoryOpenSshCandidate[]) => void = () => {};
  let input: Uint8Array | undefined;
  const { workflow, calls } = setup({
    parse: async (bytes) => {
      input = bytes;
      return new Promise((resolve) => {
        finish = resolve;
      });
    },
  });
  const preparation = workflow.prepare(file());
  await new Promise((resolve) => setTimeout(resolve, 0));
  workflow.dispose();
  finish(candidates);
  await assert.rejects(preparation, RequestFailure);
  assert.equal(workflow.state.candidates, undefined);
  assert.ok(input?.every((byte) => byte === 0));
  assert.equal(calls.length, 0);
});
