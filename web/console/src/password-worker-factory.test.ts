// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { passwordWorkerFactory } from "./password-worker-factory.ts";

const origin = "https://console.example";
const worker = "/assets/password-worker-hashed.js";
const originalWorker = Object.getOwnPropertyDescriptor(globalThis, "Worker");
const originalTrustedTypes = Object.getOwnPropertyDescriptor(
  globalThis,
  "trustedTypes",
);
afterEach(() => {
  for (const [name, descriptor] of [
    ["Worker", originalWorker],
    ["trustedTypes", originalTrustedTypes],
  ] as const)
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
});

test("password Worker policy trusts only its exact compiled same-origin URL and reuses one named policy", () => {
  const names: string[] = [];
  const launches: unknown[] = [];
  let accept!: (value: string) => string;
  Object.defineProperty(globalThis, "trustedTypes", {
    configurable: true,
    value: {
      createPolicy(
        name: string,
        rules: { createScriptURL(value: string): string },
      ) {
        names.push(name);
        accept = rules.createScriptURL;
        return {
          createScriptURL(value: string) {
            return { trustedScriptURL: rules.createScriptURL(value) };
          },
        };
      },
    },
  });
  Object.defineProperty(globalThis, "Worker", {
    configurable: true,
    value: class {
      constructor(url: unknown, options: WorkerOptions) {
        launches.push({ url, options });
      }
    },
  });
  const create = passwordWorkerFactory(worker, origin);
  create();
  create();
  assert.deepEqual(names, ["scoplen-browser-worker"]);
  assert.deepEqual(
    launches,
    Array.from({ length: 2 }, () => ({
      url: { trustedScriptURL: origin + worker },
      options: { type: "module", name: "scoplen-password-login" },
    })),
  );
  assert.equal(accept(origin + worker), origin + worker);
  for (const value of [
    "https://other.example" + worker,
    origin + "/assets/another-worker.js",
    origin + worker + "?replacement=1",
    origin + worker + "#fragment",
    "javascript:alert(1)",
    worker,
  ])
    assert.throws(() => accept(value));
  assert.throws(() =>
    passwordWorkerFactory("https://other.example" + worker, origin),
  );
});

test("browsers without Trusted Types still launch only the compiled same-origin module", () => {
  Reflect.deleteProperty(globalThis, "trustedTypes");
  const launches: unknown[] = [];
  Object.defineProperty(globalThis, "Worker", {
    configurable: true,
    value: class {
      constructor(url: unknown) {
        launches.push(url);
      }
    },
  });
  passwordWorkerFactory(worker, origin)();
  assert.deepEqual(launches, [origin + worker]);
});
