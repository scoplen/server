// SPDX-License-Identifier: AGPL-3.0-only
import type {
  GrantCreateRequest,
  GrantFields,
  GrantPage,
  GrantResource,
} from "./generated/api.ts";
import {
  operationId,
  RequestFailure,
  strongEtag,
  type AccountTransport,
} from "./team.ts";
import { object, strictJson, text, timestamp, uuid } from "./wire.ts";

const encoder = new TextEncoder();
const resourceMaximum = 4_096;
const pageMaximum = 2_097_152;

export function grantTime(value: unknown): string {
  const result = timestamp(value);
  if (Date.parse(result) < 0) throw new Error("Invalid Grant time.");
  return result;
}
export function grantFields(value: unknown): GrantFields {
  const input = object(value),
    remote_user = text(input.remote_user);
  if (
    !remote_user.isWellFormed() ||
    /\p{Cc}/u.test(remote_user) ||
    encoder.encode(remote_user).length < 1 ||
    encoder.encode(remote_user).length > 255
  )
    throw new Error("Invalid remote user.");
  const valid_from = grantTime(input.valid_from);
  const valid_until =
    input.valid_until === null ? null : grantTime(input.valid_until);
  if (valid_until !== null && valid_until <= valid_from)
    throw new Error("Invalid Grant interval.");
  return {
    membership: uuid(input.membership),
    host: uuid(input.host),
    remote_user,
    valid_from,
    valid_until,
  };
}
export function grantStatus(
  fields: GrantFields,
  now = Date.now(),
): "future" | "active" | "expired" {
  if (now < Date.parse(fields.valid_from)) return "future";
  return fields.valid_until !== null && now >= Date.parse(fields.valid_until)
    ? "expired"
    : "active";
}
function resource(value: unknown, etag?: string | null): GrantResource {
  const input = object(value);
  const result = {
    id: uuid(input.id),
    etag: strongEtag(input.etag),
    created_at: resourceTime(input.created_at),
    updated_at: resourceTime(input.updated_at),
    data: { ...grantFields(input.data) },
  };
  if (etag !== undefined && etag !== result.etag)
    throw new Error("Mismatched Grant version.");
  return result;
}
function resourceTime(value: unknown): string {
  const result = text(value);
  timestamp(result.replace(/\.\d+Z$/, "Z"));
  return result;
}
function page(
  value: unknown,
  cursor: string | undefined,
  limit: number,
): GrantPage {
  const input = object(value);
  if (!Array.isArray(input.items) || input.items.length > limit)
    throw new Error("Invalid Grant page.");
  const items = input.items.map((item) => resource(item));
  let previous = cursor ?? "";
  for (const item of items) {
    if (item.id <= previous) throw new Error("Invalid Grant order.");
    previous = item.id;
  }
  const next_cursor =
    input.next_cursor === null ? null : uuid(input.next_cursor);
  if (next_cursor !== null && (items.length === 0 || next_cursor !== previous))
    throw new Error("Invalid Grant continuation.");
  return { items, next_cursor };
}
export function parseGrant(
  source: string,
  etag?: string | null,
): GrantResource {
  if (encoder.encode(source).length > resourceMaximum)
    throw new Error("Grant exceeds its limit.");
  return resource(strictJson(source), etag);
}
export function parseGrantPage(
  source: string,
  cursor?: string,
  limit = 50,
): GrantPage {
  if (cursor !== undefined) uuid(cursor);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500)
    throw new Error("Invalid Grant page size.");
  if (encoder.encode(source).length > pageMaximum)
    throw new Error("Grant page exceeds its limit.");
  const value = strictJson(source, (path, start, end) => {
    if (
      path.length === 2 &&
      path[0] === "items" &&
      typeof path[1] === "number" &&
      encoder.encode(source.slice(start, end)).length > resourceMaximum
    )
      throw new Error("Grant exceeds its limit.");
  });
  return page(value, cursor, limit);
}

export class GrantApi {
  readonly transport: AccountTransport;
  readonly organization: string;
  readonly path: string;
  constructor(transport: AccountTransport, organization: string) {
    this.transport = transport;
    this.organization = uuid(organization);
    this.path = `/api/v1/orgs/${this.organization}/grants`;
  }
  async list(cursor?: string): Promise<GrantPage> {
    if (cursor !== undefined) uuid(cursor);
    const path = `${this.path}?limit=50${cursor ? `&cursor=${uuid(cursor)}` : ""}`;
    const reply = await this.transport.request("GET", path, {
      maximum: pageMaximum,
      decode: (source) => parseGrantPage(source, cursor),
    });
    return page(reply.value, cursor, 50);
  }
  async get(id: string): Promise<GrantResource> {
    const reply = await this.transport.request(
      "GET",
      `${this.path}/${uuid(id)}`,
      {
        maximum: resourceMaximum,
        decode: parseGrant,
      },
    );
    const result = resource(reply.value, reply.etag);
    if (result.id !== id) throw new Error("Mismatched Grant.");
    return result;
  }
  async create(body: GrantCreateRequest, key: string): Promise<GrantResource> {
    const request: GrantCreateRequest = {
      id: uuid(body.id),
      data: grantFields(body.data),
    };
    if (encoder.encode(JSON.stringify(request)).length > resourceMaximum)
      throw new Error("Grant exceeds its limit.");
    const reply = await this.transport.request("POST", this.path, {
      body: request,
      key: uuid(key),
      success: 201,
      maximum: resourceMaximum,
      decode: parseGrant,
    });
    return this.result(reply, request.id, request.data);
  }
  async replace(
    original: GrantResource,
    fields: GrantFields,
  ): Promise<GrantResource> {
    const data = grantFields(fields);
    const reply = await this.transport.request(
      "PUT",
      `${this.path}/${uuid(original.id)}`,
      {
        body: { data },
        etag: strongEtag(original.etag),
        maximum: resourceMaximum,
        decode: parseGrant,
      },
    );
    return this.result(reply, original.id, data);
  }
  async withdraw(original: GrantResource): Promise<void> {
    await this.transport.request(
      "DELETE",
      `${this.path}/${uuid(original.id)}`,
      {
        etag: strongEtag(original.etag),
        success: 204,
      },
    );
  }
  private result(
    reply: { value: unknown; etag: string | null },
    id: string,
    fields: GrantFields,
  ): GrantResource {
    const result = resource(reply.value, reply.etag);
    if (
      result.id !== id ||
      JSON.stringify(result.data) !== JSON.stringify(fields)
    )
      throw new Error("Mismatched Grant result.");
    return result;
  }
}

export interface GrantIntent {
  readonly body: GrantCreateRequest;
  readonly key: string;
  readonly deadline: number;
}
/** Bound to one mounted Account-browser/team context; never persisted or transferred. */
export class GrantActions {
  readonly api: GrantApi;
  pending: GrantIntent | undefined;
  reviewRequired = false;
  #active = true;
  #running = false;
  constructor(api: GrantApi) {
    this.api = api;
  }
  dispose(): void {
    this.#active = false;
    this.pending = undefined;
  }
  discard(): void {
    this.pending = undefined;
    this.reviewRequired = true;
  }
  reviewed(): void {
    this.current();
    this.reviewRequired = false;
  }
  private current(): void {
    if (!this.#active) throw new RequestFailure("session_changed");
  }
  private async execute<T>(action: () => Promise<T>): Promise<T> {
    this.current();
    if (this.#running) throw new Error("Grant action already in progress.");
    this.#running = true;
    try {
      const result = await action();
      this.current();
      return result;
    } finally {
      this.#running = false;
    }
  }
  async create(fields: GrantFields): Promise<GrantResource> {
    this.current();
    if (this.pending || this.reviewRequired)
      throw new Error("Review the current Grant state first.");
    const data = Object.freeze(grantFields(fields));
    this.pending = Object.freeze({
      body: Object.freeze({ id: operationId(), data }),
      key: operationId(),
      deadline: Date.now() + 86_400_000,
    });
    return this.attempt(true);
  }
  async confirm(): Promise<GrantResource> {
    return this.attempt(false);
  }
  private async attempt(initial: boolean): Promise<GrantResource> {
    this.current();
    const intent = this.pending;
    if (!intent || Date.now() >= intent.deadline)
      throw new Error("Original Grant confirmation is unavailable.");
    return this.execute(async () => {
      try {
        const result = await this.api.create(intent.body, intent.key);
        this.current();
        this.pending = undefined;
        return result;
      } catch (error) {
        if (
          initial &&
          this.#active &&
          error instanceof RequestFailure &&
          !error.changed &&
          error.code !== "session_changed"
        )
          this.pending = undefined;
        throw error;
      }
    });
  }
  async replace(
    original: GrantResource,
    fields: GrantFields,
  ): Promise<GrantResource> {
    return this.edit(() => this.api.replace(original, fields));
  }
  async withdraw(original: GrantResource): Promise<void> {
    return this.edit(() => this.api.withdraw(original));
  }
  private async edit<T>(action: () => Promise<T>): Promise<T> {
    if (this.pending || this.reviewRequired)
      throw new Error("Review the current Grant state first.");
    return this.execute(async () => {
      try {
        return await action();
      } catch (error) {
        if (
          this.#active &&
          (!(error instanceof RequestFailure) ||
            error.changed ||
            error.status === 412)
        )
          this.reviewRequired = true;
        throw error;
      }
    });
  }
}
