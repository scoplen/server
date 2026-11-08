// SPDX-License-Identifier: AGPL-3.0-only
import init, { derivePasswordAuth } from "@scoplen/browser";
import wasmUrl from "@scoplen/browser/scoplen_browser_bg.wasm?url";
import { AccountFailure } from "./account-http.ts";
import { performPasswordLogin } from "./password-login.ts";
import { object } from "./wire.ts";

const scope = self as unknown as {
  location: Location;
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  postMessage(value: unknown): void;
  close(): void;
};

async function login(value: unknown) {
  let password: Uint8Array | undefined;
  let completed = false;
  try {
    const input = object(value);
    if (input.password instanceof Uint8Array) password = input.password;
    if (
      Object.keys(input).sort().join() !== "origin,password,username" ||
      input.origin !== scope.location.origin ||
      typeof input.origin !== "string" ||
      typeof input.username !== "string" ||
      !(input.password instanceof Uint8Array) ||
      !(input.password.buffer instanceof ArrayBuffer) ||
      input.password.byteOffset !== 0 ||
      input.password.byteLength !== input.password.buffer.byteLength
    )
      throw new AccountFailure("login", "invalid_password_input");
    password = input.password;
    try {
      await init({ module_or_path: wasmUrl });
    } catch {
      throw new AccountFailure("login", "password_derivation_failed");
    }
    const result = await performPasswordLogin(
      input.origin,
      input.username,
      password,
      async (...arguments_) => derivePasswordAuth(...arguments_),
    );
    completed = true;
    scope.postMessage({ ok: true, result });
  } catch (error) {
    const failure =
      error instanceof AccountFailure
        ? error
        : new AccountFailure("login", "password_worker_failed", 0, completed);
    scope.postMessage({
      ok: false,
      failure: {
        operation: failure.operation,
        code: failure.code,
        status: failure.status,
        changed: failure.changed,
        retryable: failure.retryable,
        requestId: failure.requestId,
        retryAfter: failure.retryAfter,
      },
    });
  } finally {
    password?.fill(0);
    scope.close();
  }
}

scope.onmessage = (event) => {
  scope.onmessage = null;
  void login(event.data);
};
