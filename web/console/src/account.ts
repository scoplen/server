// SPDX-License-Identifier: AGPL-3.0-only
import { accountBrowserOperations } from "./generated/api.ts";
import {
  AccountProofKey,
  canonicalOrigin,
  targetUrl,
  type ProofTransfer,
} from "./account-proof.ts";
import {
  AccountFailure,
  accountFetch,
  type AccountOperation,
} from "./account-http.ts";
import { accountSession } from "./account-wire.ts";
import { logoutResponse } from "./wire.ts";
import type {
  AccountTransport,
  ApiResponse,
  Method,
  RequestOptions,
} from "./team.ts";

export interface PasswordLoginResult extends ProofTransfer {
  session: unknown;
  startedAt: number;
}
export interface PasswordLogin {
  run(
    origin: string,
    username: string,
    password: Uint8Array,
    signal: AbortSignal,
  ): Promise<PasswordLoginResult>;
}

export class AccountClient implements AccountTransport {
  readonly origin: string;
  #login: PasswordLogin;
  #key?: AccountProofKey;
  #token?: string;
  #expiresAt = 0;
  #familyExpiresAt = 0;
  #generation = 0;
  #pending: Promise<void> = Promise.resolve();
  #loginAbort?: AbortController;
  #logoutAttempted = false;
  #logoutState: "idle" | "pending" | "failed" | "uncertain" = "idle";
  #listeners = new Set<() => void>();
  #reason = "";
  constructor(origin: string, login: PasswordLogin) {
    this.origin = canonicalOrigin(origin);
    this.#login = login;
  }
  get authenticated() {
    return Boolean(this.#token && this.#key);
  }
  get blocked() {
    return this.#logoutAttempted;
  }
  get reason() {
    return this.#reason;
  }
  get logoutExpiresAt() {
    return this.#expiresAt;
  }
  get logoutState(): "idle" | "pending" | "failed" | "uncertain" | "expired" {
    return this.#logoutAttempted &&
      this.#logoutState !== "pending" &&
      Date.now() >= this.#expiresAt
      ? "expired"
      : this.#logoutState;
  }
  subscribe(listener: () => void) {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }
  #notify() {
    for (const listener of this.#listeners) listener();
  }
  lock(reason = "") {
    this.#generation++;
    this.#loginAbort?.abort();
    this.#loginAbort = undefined;
    this.#key = undefined;
    this.#token = undefined;
    this.#expiresAt = 0;
    this.#familyExpiresAt = 0;
    this.#logoutAttempted = false;
    this.#logoutState = "idle";
    this.#reason = reason;
    this.#notify();
  }
  #current(generation: number, operation: AccountOperation) {
    if (generation !== this.#generation)
      throw new AccountFailure(operation, "session_changed");
  }
  #serialize<T>(
    operation: AccountOperation,
    action: (generation: number) => Promise<T>,
  ): Promise<T> {
    const generation = this.#generation;
    const result = this.#pending.then(() => {
      this.#current(generation, operation);
      return action(generation);
    });
    this.#pending = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
  signIn(username: string, password: Uint8Array): Promise<void> {
    if (
      !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username) ||
      password.length > 2_048
    ) {
      password.fill(0);
      return Promise.reject(
        new AccountFailure("login", "invalid_password_input"),
      );
    }
    const result = this.#serialize("login", async (generation) => {
      if (this.authenticated)
        throw new AccountFailure("login", "session_already_open");
      const controller = new AbortController();
      this.#loginAbort = controller;
      try {
        const result = await this.#login.run(
          this.origin,
          username,
          password,
          controller.signal,
        );
        this.#current(generation, "login");
        const key = await AccountProofKey.adopt(result);
        this.#current(generation, "login");
        this.#accept(result.session, result.startedAt, true);
        this.#key = key;
        this.#reason = "";
        this.#notify();
      } catch (error) {
        this.#current(generation, "login");
        if (error instanceof AccountFailure) throw error;
        throw new AccountFailure("login", "invalid_response", 0, true);
      } finally {
        if (this.#loginAbort === controller) this.#loginAbort = undefined;
      }
    });
    return result.finally(() => password.fill(0));
  }
  #accept(value: unknown, startedAt: number, login = false) {
    const session = accountSession(value, login);
    if (
      !Number.isSafeInteger(startedAt) ||
      startedAt < 0 ||
      startedAt > Date.now() ||
      startedAt + 600_000 <= Date.now()
    )
      throw new AccountFailure(
        login ? "login" : "refresh",
        "invalid_response",
        0,
        true,
      );
    this.#token = session.access_token;
    this.#expiresAt = startedAt + 600_000;
    const family = startedAt + session.refresh_expires_in * 1_000;
    this.#familyExpiresAt = login
      ? family
      : Math.min(this.#familyExpiresAt, family);
  }
  async #accessToken(generation: number, operation: AccountOperation) {
    this.#current(generation, operation);
    if (!this.#token || !this.#key)
      throw new AccountFailure(operation, "sign_in_required");
    if (this.#expiresAt - Date.now() <= 30_000) {
      await navigator.locks
        .request("scoplen-account-refresh", async () => {
          this.#current(generation, operation);
          if (!this.#key || !this.#token || Date.now() >= this.#familyExpiresAt)
            throw new AccountFailure("refresh", "sign_in_required");
          const startedAt = Date.now();
          try {
            const result = await accountFetch({
              origin: this.origin,
              key: this.#key,
              method: "POST",
              path: "/api/v1/auth/accounts/browser/refresh",
              operation: "refresh",
              options: { body: {}, maximum: 8_192 },
              current: () => this.#current(generation, "refresh"),
            });
            this.#current(generation, "refresh");
            this.#accept(result.value, startedAt);
          } catch (error) {
            if (generation === this.#generation)
              this.lock("refresh_sign_in_required");
            throw error;
          }
        })
        .catch((error: unknown) => {
          if (generation === this.#generation)
            this.lock("refresh_sign_in_required");
          throw error;
        });
    }
    this.#current(generation, operation);
    if (!this.#token) throw new AccountFailure(operation, "sign_in_required");
    return this.#token;
  }
  request(
    method: Method,
    path: string,
    options?: RequestOptions,
  ): Promise<ApiResponse> {
    return this.#serialize("request", async (generation) => {
      if (this.#logoutAttempted)
        throw new AccountFailure("request", "sign_out_pending");
      const url = targetUrl(this.origin, path);
      const segments = url.pathname.split("/");
      const allowed = accountBrowserOperations.some(
        (route) =>
          route.method === method &&
          route.path
            .split("/")
            .every(
              (part, index, parts) =>
                parts.length === segments.length &&
                (part.startsWith("{")
                  ? /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
                      segments[index],
                    )
                  : part === segments[index]),
            ),
      );
      if (!allowed) throw new AccountFailure("request", "route_not_available");
      const token = await this.#accessToken(generation, "request");
      return accountFetch({
        origin: this.origin,
        key: this.#key!,
        method,
        path,
        operation: "request",
        options,
        token,
        current: () => this.#current(generation, "request"),
      });
    });
  }
  signOut(): Promise<void> {
    return this.#serialize("logout", async (generation) => {
      const token = this.#logoutAttempted
        ? this.#token
        : await this.#accessToken(generation, "logout");
      if (!token || !this.#key || Date.now() >= this.#expiresAt)
        throw new AccountFailure("logout", "logout_expired");
      this.#logoutAttempted = true;
      this.#logoutState = "pending";
      this.#notify();
      try {
        const result = await accountFetch({
          origin: this.origin,
          key: this.#key,
          method: "POST",
          path: "/api/v1/auth/accounts/browser/logout",
          operation: "logout",
          options: { body: {}, maximum: 256 },
          token,
          current: () => this.#current(generation, "logout"),
        });
        try {
          logoutResponse(result.value);
        } catch {
          throw new AccountFailure("logout", "invalid_response", 0, true);
        }
        this.#current(generation, "logout");
        this.lock("signed_out");
      } catch (error) {
        if (generation === this.#generation) {
          this.#logoutState =
            error instanceof AccountFailure && !error.changed
              ? "failed"
              : "uncertain";
          this.#notify();
        }
        throw error;
      }
    });
  }
}
