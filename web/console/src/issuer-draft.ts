// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AuthConnectionDraftResource,
  DraftLoginAttempt,
  DraftLoginCredentials,
} from "./generated/api.ts";
import { canonicalOrigin } from "./account-proof.ts";
import {
  operationId,
  RequestFailure,
  resource,
  resourceTimestamp,
  TeamApi,
  type ApiResponse,
} from "./team.ts";
import { object, text, uuid } from "./wire.ts";

export function draftIssuer(value: unknown): string {
  if (
    typeof value === "string" &&
    value.isWellFormed() &&
    new TextEncoder().encode(value).length <= 2048 &&
    !/[\p{White_Space}\p{Cc}\\?#]/u.test(value)
  ) {
    const authority = /^https:\/\/([^/]+)/iu.exec(value)?.[1];
    if (
      authority &&
      !authority.includes("@") &&
      URL.canParse(value) &&
      new URL(value).hostname
    )
      return value;
  }
  throw new RequestFailure("invalid_draft_issuer");
}

export async function draftRegistrationSettings(
  origin: string,
  issuer: string,
) {
  const trustedOrigin = canonicalOrigin(origin);
  const bytes = new TextEncoder().encode(draftIssuer(issuer));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const issuerHash = Array.from(hash, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return {
    redirect_uri: `${trustedOrigin}/api/v1/auth/enterprise/oidc/${issuerHash}/callback`,
    response_type: "code",
    grant_type: "authorization_code",
    code_challenge_method: "S256",
    scope: "openid",
    token_endpoint_auth_method: "client_secret_basic",
  };
}

function parseDraft(
  reply: ApiResponse,
  org: string,
  originalIssuer?: string,
): AuthConnectionDraftResource {
  try {
    const item = resource(reply.value, reply.etag),
      issuer = draftIssuer(item.data.issuer);
    if (
      item.etag !== reply.etag ||
      item.etag !== `"${item.id}"` ||
      item.created_at !== item.updated_at ||
      uuid(item.data.organization_id) !== org ||
      (originalIssuer !== undefined && issuer !== originalIssuer)
    )
      throw new Error("Mismatched issuer draft.");
    return { ...item, data: { organization_id: org, issuer } };
  } catch {
    throw new RequestFailure(
      "invalid_response",
      originalIssuer === undefined ? 200 : 201,
      originalIssuer !== undefined,
    );
  }
}

const windowMs = 86_400_000;
const testWindowMs = 300_000;
type LoginTest =
  | { kind: "attempt"; attempt: DraftLoginAttempt; until: number; url?: string }
  | { kind: "wait"; until: number }
  | { kind: "unavailable" | "expired" };

export function validCredential(value: string): boolean {
  return (
    Boolean(value) &&
    value.isWellFormed() &&
    !/\p{Cc}/u.test(value) &&
    new TextEncoder().encode(value).length <= 512
  );
}

function loginAttempt(
  fields: Record<string, unknown>,
  org: string,
  draft: string,
): DraftLoginAttempt {
  const id = uuid(fields.id);
  const expiry = resourceTimestamp(fields.expires_at);
  const status = fields.status;
  if (
    uuid(fields.organization_id) !== org ||
    uuid(fields.draft_generation) !== draft ||
    (status !== "pending" && status !== "verified" && status !== "failed")
  )
    throw new Error("Mismatched login test.");
  return {
    id,
    organization_id: org,
    draft_generation: draft,
    status,
    expires_at: expiry,
  };
}

export function providerNavigation(value: unknown, issuer: string): string {
  const location = text(value);
  const authority = /^https:\/\/([^/?]+)/i.exec(location)?.[1];
  if (
    !authority ||
    authority.includes("@") ||
    /[\p{White_Space}\p{Cc}\\#]/u.test(location) ||
    new URL(location).origin !== new URL(issuer).origin
  )
    throw new Error("Invalid provider navigation.");
  return location;
}

type Original = Readonly<
  {
    key: string;
    started: number;
    monotonicStart: number;
  } & ({ method: "POST"; issuer: string } | { method: "DELETE"; etag: string })
>;

export class IssuerDraftActions {
  readonly api: TeamApi;
  readonly org: string;
  readonly account: string;
  readonly origin: string;
  readonly generation: number | undefined;
  current: AuthConnectionDraftResource | null | undefined;
  pending: Original | undefined;
  #disposed = false;
  #busy = false;
  #expiredKey?: string;
  #login?: LoginTest;

  constructor(api: TeamApi, org: string) {
    this.api = api;
    this.org = uuid(org);
    this.account = uuid(api.accountId);
    this.origin = api.transport.origin;
    this.generation = api.transport.sessionGeneration;
  }
  get path() {
    return `/api/v1/orgs/${this.org}/auth-connection-draft`;
  }
  get login() {
    if (this.#login && "until" in this.#login && this.loginRemaining === 0)
      this.#login = { kind: "expired" };
    return this.#login;
  }
  get loginRemaining() {
    const login = this.#login;
    return login && "until" in login
      ? Math.max(0, login.until - performance.now())
      : 0;
  }
  get canConfirm() {
    if (!this.pending || this.pending.key === this.#expiredKey) return false;
    const age = Date.now() - this.pending.started;
    const elapsed = performance.now() - this.pending.monotonicStart;
    if (age >= 0 && age < windowMs && elapsed >= 0 && elapsed < windowMs)
      return true;
    this.#expiredKey = this.pending.key;
    return false;
  }
  discard() {
    this.current = undefined;
    this.pending = undefined;
    this.#expiredKey = undefined;
    this.#login = undefined;
  }
  dispose() {
    this.#disposed = true;
    this.discard();
  }
  #check() {
    if (
      this.#disposed ||
      this.api.accountId !== this.account ||
      this.api.transport.origin !== this.origin ||
      this.api.transport.sessionGeneration !== this.generation
    ) {
      this.dispose();
      throw new RequestFailure("session_changed");
    }
  }
  async #run<T>(operation: () => Promise<T>): Promise<T> {
    this.#check();
    if (this.#busy)
      throw new Error("An issuer draft operation is already in progress.");
    this.#busy = true;
    try {
      return await operation();
    } finally {
      this.#busy = false;
      this.#check();
    }
  }
  async read() {
    return this.#run(async () => {
      const previous = this.current?.id;
      this.current = undefined;
      let result: AuthConnectionDraftResource | null;
      try {
        const reply = await this.api.transport.request("GET", this.path, {
          maximum: 8192,
        });
        result = parseDraft(reply, this.org);
      } catch (error) {
        if (!(
          error instanceof RequestFailure &&
          error.status === 404 &&
          error.code === "organization.not_found" &&
          !error.changed &&
          !error.retryable
        )) {
          if (this.#login?.kind === "attempt")
            this.#login = { kind: "unavailable" };
          throw error;
        }
        result = null;
      }
      this.#check();
      if (
        this.#login?.kind === "unavailable" ||
        (result?.id !== previous && this.#login?.kind !== "wait")
      )
        this.#login = undefined;
      this.current = result;
      return result;
    });
  }
  async startLogin(credentials: DraftLoginCredentials) {
    return this.#run(async () => {
      const draft = this.current;
      const login = this.login;
      if (
        !draft ||
        this.pending ||
        login?.kind === "wait" ||
        login?.kind === "unavailable" ||
        (login?.kind === "attempt" && login.attempt.status === "pending")
      )
        throw new RequestFailure("draft_test_not_ready");
      if (
        !validCredential(credentials.client_id) ||
        !validCredential(credentials.client_secret)
      )
        throw new RequestFailure("invalid_draft_client");

      this.#login = undefined;
      try {
        const reply = await this.api.transport.request(
          "POST",
          `${this.path}/test-login`,
          {
            body: credentials,
            etag: draft.etag,
            success: 201,
            maximum: 8192,
          },
        );
        this.#check();
        try {
          const fields = object(reply.value);
          const attempt = loginAttempt(fields, this.org, draft.id);
          if (attempt.status !== "pending" || reply.etag !== null)
            throw new Error("Invalid login test start.");
          const url = providerNavigation(
            fields.authorization_url,
            draft.data.issuer,
          );
          const until =
            performance.now() +
            Math.min(testWindowMs, Date.parse(attempt.expires_at) - Date.now());
          this.#login = { kind: "attempt", attempt, until, url };
        } catch {
          throw new RequestFailure("invalid_response", 201, true);
        }
      } catch (error) {
        this.#check();
        if (
          !(error instanceof RequestFailure) ||
          error.changed ||
          (error.status === 409 && error.code === "organization.conflict")
        )
          this.#login = {
            kind: "wait",
            until: performance.now() + testWindowMs,
          };
        else if (
          error.status === 412 &&
          error.code === "organization.precondition_failed"
        )
          this.#login = { kind: "unavailable" };
        throw error;
      }
    });
  }
  async readLogin() {
    return this.#run(async () => {
      const login = this.login;
      if (login?.kind !== "attempt" || login.attempt.status !== "pending")
        return;
      const original = login.attempt;
      try {
        const reply = await this.api.transport.request(
          "GET",
          `${this.path}/test-login/${original.id}`,
          {
            maximum: 8192,
          },
        );
        this.#check();
        if (this.login !== login) return;
        try {
          const fields = object(reply.value);
          const attempt = loginAttempt(
            fields,
            this.org,
            original.draft_generation,
          );
          if (
            reply.etag !== null ||
            "authorization_url" in fields ||
            attempt.id !== original.id ||
            attempt.expires_at !== original.expires_at
          )
            throw new Error("Invalid login test status.");
          this.#login = {
            ...login,
            attempt,
            url: attempt.status === "pending" ? login.url : undefined,
          };
        } catch {
          throw new RequestFailure("invalid_response", 200);
        }
      } catch (error) {
        this.#check();
        if (
          error instanceof RequestFailure &&
          error.status === 404 &&
          error.code === "organization.not_found" &&
          !error.changed &&
          !error.retryable
        ) {
          this.#login = { kind: "unavailable" };
          return;
        }
        if (
          error instanceof RequestFailure &&
          (error.status === 401 || error.status === 403)
        )
          this.#login = { kind: "unavailable" };
        throw error;
      }
    });
  }
  async create(issuer: string) {
    return this.#run(async () => {
      if (this.pending || this.current !== null)
        throw new Error("Review the current draft before saving.");
      this.pending = Object.freeze({
        method: "POST",
        issuer: draftIssuer(issuer),
        key: operationId(),
        started: Date.now(),
        monotonicStart: performance.now(),
      });
      await this.#attempt();
    });
  }
  async cancel() {
    return this.#run(async () => {
      if (this.pending || !this.current)
        throw new Error("Read the current draft before cancellation.");
      this.pending = Object.freeze({
        method: "DELETE",
        etag: this.current.etag,
        key: operationId(),
        started: Date.now(),
        monotonicStart: performance.now(),
      });
      await this.#attempt();
    });
  }
  async confirm() {
    return this.#run(async () => {
      if (!this.canConfirm)
        throw new RequestFailure("draft_confirmation_unavailable");
      await this.#attempt(true);
    });
  }
  async #attempt(confirmation = false) {
    const original = this.pending!;
    this.current = undefined;
    if (this.#login?.kind !== "wait") this.#login = undefined;
    try {
      if (original.method === "POST") {
        const reply = await this.api.transport.request("POST", this.path, {
          body: { data: { issuer: original.issuer } },
          key: original.key,
          ifNoneMatch: "*",
          success: 201,
          maximum: 8192,
        });
        parseDraft(reply, this.org, original.issuer);
      } else {
        const reply = await this.api.transport.request("DELETE", this.path, {
          key: original.key,
          etag: original.etag,
          success: 204,
        });
        if (reply.value !== undefined || reply.etag !== null)
          throw new RequestFailure("invalid_response", 204, true);
      }
      this.#check();
      this.pending = undefined;
    } catch (error) {
      this.#check();
      if (
        !confirmation &&
        error instanceof RequestFailure &&
        !error.changed &&
        !error.retryable
      )
        this.pending = undefined;
      throw error;
    }
  }
}
