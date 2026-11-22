// SPDX-License-Identifier: AGPL-3.0-only
import type { AuthConnectionDraftResource } from "./generated/api.ts";
import {
  operationId,
  RequestFailure,
  resource,
  TeamApi,
  type ApiResponse,
} from "./team.ts";
import { uuid } from "./wire.ts";

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
        ))
          throw error;
        result = null;
      }
      this.#check();
      this.current = result;
      return result;
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
