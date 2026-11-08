// SPDX-License-Identifier: AGPL-3.0-only
import type { PasswordLogin, PasswordLoginResult } from "./account.ts";
import { AccountFailure, type AccountOperation } from "./account-http.ts";
import { object } from "./wire.ts";

export class PasswordWorkerLogin implements PasswordLogin {
  #create: () => Worker;
  constructor(create: () => Worker) {
    this.#create = create;
  }
  run(
    origin: string,
    username: string,
    password: Uint8Array,
    signal: AbortSignal,
  ): Promise<PasswordLoginResult> {
    return new Promise((resolve, reject) => {
      let worker: Worker;
      try {
        worker = this.#create();
      } catch {
        password.fill(0);
        reject(new AccountFailure("login", "password_worker_unavailable"));
        return;
      }
      let finished = false;
      const finish = (result?: PasswordLoginResult, failure?: unknown) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        worker.terminate();
        password.fill(0);
        if (failure) reject(failure);
        else resolve(result!);
      };
      const abort = () =>
        finish(undefined, new AccountFailure("login", "session_changed"));
      const timer = setTimeout(
        () =>
          finish(
            undefined,
            new AccountFailure("login", "password_worker_timed_out", 0, true),
          ),
        180_000,
      );
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) {
        abort();
        return;
      }
      worker.onerror = () =>
        finish(
          undefined,
          new AccountFailure("login", "password_worker_failed", 0, true),
        );
      worker.onmessageerror = () =>
        finish(
          undefined,
          new AccountFailure("login", "password_worker_failed", 0, true),
        );
      worker.onmessage = (event: MessageEvent<unknown>) => {
        try {
          const message = object(event.data);
          if (
            Object.keys(message).sort().join() !==
            (message.ok === true ? "ok,result" : "failure,ok")
          )
            throw new Error("Unexpected password Worker response fields.");
          if (message.ok === true) {
            const result = object(message.result);
            if (
              Object.keys(result).some(
                (name) =>
                  !["session", "startedAt", "keyPair", "publicJwk"].includes(
                    name,
                  ),
              )
            )
              throw new Error("Unexpected password Worker output.");
            finish(result as unknown as PasswordLoginResult);
          } else if (message.ok === false) {
            const input = object(message.failure);
            if (
              !["options", "login"].includes(String(input.operation)) ||
              typeof input.code !== "string" ||
              !/^[a-z][a-z0-9_.]{0,127}$/.test(input.code) ||
              typeof input.status !== "number" ||
              !Number.isInteger(input.status) ||
              input.status < 0 ||
              input.status > 599 ||
              typeof input.changed !== "boolean" ||
              typeof input.retryable !== "boolean" ||
              typeof input.requestId !== "string" ||
              !/^[A-Za-z0-9._:-]{0,128}$/.test(input.requestId) ||
              typeof input.retryAfter !== "number" ||
              !Number.isInteger(input.retryAfter) ||
              input.retryAfter < 0 ||
              input.retryAfter > 300
            )
              throw new Error("Invalid password Worker failure.");
            finish(
              undefined,
              new AccountFailure(
                input.operation as AccountOperation,
                input.code,
                input.status,
                input.changed,
                input.retryable,
                input.requestId,
                input.retryAfter,
              ),
            );
          } else throw new Error("Invalid password Worker response.");
        } catch {
          finish(
            undefined,
            new AccountFailure("login", "invalid_response", 0, true),
          );
        }
      };
      let owned: Uint8Array<ArrayBuffer> | undefined;
      try {
        owned = password.slice();
        password.fill(0);
        worker.postMessage({ origin, username, password: owned }, [
          owned.buffer,
        ]);
      } catch {
        if (owned?.byteLength) owned.fill(0);
        finish(
          undefined,
          new AccountFailure("login", "password_worker_failed"),
        );
      }
    });
  }
}
