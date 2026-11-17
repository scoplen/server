// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AccessRequestDecisionRequest,
  AccessRequestPage,
  AccessRequestResource,
  AccessRequestView,
} from "./generated/api.ts";
import { grantTime } from "./grants.ts";
import {
  operationId,
  RequestFailure,
  strongEtag,
  type AccountTransport,
} from "./team.ts";
import { object, strictJson, text, timestamp, uuid } from "./wire.ts";

const encoder = new TextEncoder();
const resourceMaximum = 8_192;
const pageMaximum = 4_194_304;

function metadata(value: unknown) {
  const source = text(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(source))
    throw new Error("Invalid request timestamp.");
  const whole = timestamp(source.replace(/\.\d+Z$/, "Z"));
  return {
    source,
    seconds: Date.parse(whole) / 1_000,
    fraction:
      source.length === 20 ? "" : source.slice(20, -1).replace(/0+$/, ""),
  };
}

function resource(value: unknown, etag?: string | null): AccessRequestResource {
  const input = object(value),
    data = object(input.data);
  const created = metadata(input.created_at),
    expires = metadata(data.expires_at);
  const remote_user = text(data.remote_user),
    reason = text(data.reason);
  const status = text(data.status),
    duration = data.duration_seconds;
  if (
    !remote_user.isWellFormed() ||
    /\p{Cc}/u.test(remote_user) ||
    encoder.encode(remote_user).length < 1 ||
    encoder.encode(remote_user).length > 255 ||
    !reason.isWellFormed() ||
    !/\S/u.test(reason) ||
    /\p{Cc}/u.test(reason.replace(/[\n\t]/g, "")) ||
    encoder.encode(reason).length > 2_048 ||
    typeof duration !== "number" ||
    !Number.isInteger(duration) ||
    duration < 1 ||
    duration > 86_400 ||
    !/^[a-z][a-z0-9_]{0,63}$/.test(status) ||
    expires.seconds !== created.seconds + 86_400 ||
    expires.fraction !== created.fraction
  )
    throw new Error("Invalid access request.");
  let decision: AccessRequestResource["data"]["decision"] = null;
  if (data.decision !== null) {
    const item = object(data.decision);
    if (item.outcome !== "approve" && item.outcome !== "deny")
      throw new Error("Invalid request decision.");
    decision = {
      outcome: item.outcome,
      actor_account_id: uuid(item.actor_account_id),
      decided_at: metadata(item.decided_at).source,
    };
  }
  let grant: AccessRequestResource["data"]["grant"] = null;
  if (data.grant !== null) {
    const item = object(data.grant);
    grant = {
      id: uuid(item.id),
      valid_from: grantTime(item.valid_from),
      valid_until: grantTime(item.valid_until),
    };
    if (grant.valid_until <= grant.valid_from)
      throw new Error("Invalid request Grant.");
  }
  if (
    (["pending", "expired", "cancelled"].includes(status) &&
      (decision !== null || grant !== null)) ||
    (status === "denied" && (decision?.outcome !== "deny" || grant !== null)) ||
    (status === "approved" &&
      (decision?.outcome !== "approve" ||
        grant === null ||
        Date.parse(grant.valid_from) / 1_000 !==
          metadata(decision.decided_at).seconds ||
        Date.parse(grant.valid_until) / 1_000 !==
          metadata(decision.decided_at).seconds + duration))
  )
    throw new Error("Inconsistent access request.");
  const result: AccessRequestResource = {
    id: uuid(input.id),
    etag: strongEtag(input.etag),
    created_at: created.source,
    updated_at: metadata(input.updated_at).source,
    data: {
      requester_account_id: uuid(data.requester_account_id),
      requester_membership_id: uuid(data.requester_membership_id),
      host: uuid(data.host),
      remote_user,
      duration_seconds: duration,
      reason,
      expires_at: expires.source,
      status,
      decision,
      grant,
    },
  };
  if (etag !== undefined && etag !== result.etag)
    throw new Error("Mismatched request version.");
  return result;
}

export function parseAccessRequest(
  source: string,
  etag?: string | null,
): AccessRequestResource {
  if (encoder.encode(source).length > resourceMaximum)
    throw new Error("Access request exceeds its limit.");
  return resource(strictJson(source), etag);
}

function page(
  value: unknown,
  account: string,
  view: AccessRequestView,
  cursor?: string,
): AccessRequestPage {
  const input = object(value);
  if (!Array.isArray(input.items) || input.items.length > 50)
    throw new Error("Invalid request page.");
  const items = input.items.map((item) => resource(item));
  let previous = cursor ?? "";
  for (const item of items) {
    if (
      item.id <= previous ||
      (view === "mine" && item.data.requester_account_id !== account) ||
      (view === "approvals" &&
        (item.data.status !== "pending" ||
          item.data.requester_account_id === account))
    )
      throw new Error("Mismatched request page.");
    previous = item.id;
  }
  const next_cursor =
    input.next_cursor === null ? null : uuid(input.next_cursor);
  if (next_cursor !== null && (items.length === 0 || next_cursor !== previous))
    throw new Error("Invalid request continuation.");
  return { items, next_cursor };
}

export function parseAccessRequestPage(
  source: string,
  account: string,
  view: AccessRequestView,
  cursor?: string,
): AccessRequestPage {
  uuid(account);
  if (view !== "mine" && view !== "approvals")
    throw new Error("Invalid request view.");
  if (cursor !== undefined) uuid(cursor);
  if (encoder.encode(source).length > pageMaximum)
    throw new Error("Request page exceeds its limit.");
  return page(
    strictJson(source, (path, start, end) => {
      if (
        path.length === 2 &&
        path[0] === "items" &&
        typeof path[1] === "number" &&
        encoder.encode(source.slice(start, end)).length > resourceMaximum
      )
        throw new Error("Access request exceeds its limit.");
    }),
    account,
    view,
    cursor,
  );
}

export function requestPending(
  item: AccessRequestResource,
  now = Date.now(),
): boolean {
  return (
    item.data.status === "pending" && now < Date.parse(item.data.expires_at)
  );
}

export type RequestDecision =
  AccessRequestDecisionRequest["decision"] | "cancel";

function decisionActor(
  item: AccessRequestResource,
  decision: RequestDecision,
  account: string,
): void {
  if (
    !["approve", "deny", "cancel"].includes(decision) ||
    (decision === "cancel") !== (item.data.requester_account_id === account)
  )
    throw new Error("Invalid request actor or decision.");
}

export class AccessRequestApi {
  readonly transport: AccountTransport;
  readonly organization: string;
  readonly account: string;
  readonly path: string;
  constructor(
    transport: AccountTransport,
    organization: string,
    account: string,
  ) {
    this.transport = transport;
    this.organization = uuid(organization);
    this.account = uuid(account);
    this.path = `/api/v1/orgs/${this.organization}/access-requests`;
  }
  async list(
    view: AccessRequestView,
    cursor?: string,
  ): Promise<AccessRequestPage> {
    if (view !== "mine" && view !== "approvals")
      throw new Error("Invalid request view.");
    if (cursor !== undefined) uuid(cursor);
    const reply = await this.transport.request(
      "GET",
      `${this.path}?view=${view}&limit=50${cursor ? `&cursor=${cursor}` : ""}`,
      {
        maximum: pageMaximum,
        decode: (source) =>
          parseAccessRequestPage(source, this.account, view, cursor),
      },
    );
    return page(reply.value, this.account, view, cursor);
  }
  async get(id: string): Promise<AccessRequestResource> {
    const reply = await this.transport.request(
      "GET",
      `${this.path}/${uuid(id)}`,
      {
        maximum: resourceMaximum,
        decode: parseAccessRequest,
      },
    );
    const result = resource(reply.value, reply.etag);
    if (result.id !== id) throw new Error("Mismatched request.");
    return result;
  }
  async decide(
    original: AccessRequestResource,
    decision: RequestDecision,
    key: string,
  ): Promise<AccessRequestResource> {
    const captured = resource(original);
    decisionActor(captured, decision, this.account);
    const reply = await this.transport.request(
      "POST",
      `${this.path}/${captured.id}/${decision === "cancel" ? "cancel" : "decisions"}`,
      {
        ...(decision === "cancel" ? {} : { body: { decision } }),
        key: uuid(key),
        etag: captured.etag,
        maximum: resourceMaximum,
        decode: parseAccessRequest,
      },
    );
    const result = resource(reply.value, reply.etag);
    if (
      result.id !== captured.id ||
      result.created_at !== captured.created_at ||
      [
        "requester_account_id",
        "requester_membership_id",
        "host",
        "remote_user",
        "duration_seconds",
        "reason",
        "expires_at",
      ].some((field) => result.data[field] !== captured.data[field]) ||
      result.data.status !==
        { approve: "approved", deny: "denied", cancel: "cancelled" }[
          decision
        ] ||
      (decision !== "cancel" &&
        (result.data.decision?.outcome !== decision ||
          result.data.decision.actor_account_id !== this.account))
    )
      throw new Error("Mismatched request outcome.");
    return result;
  }
}

export interface AccessRequestIntent {
  readonly original: AccessRequestResource;
  readonly decision: RequestDecision;
  readonly key: string;
  readonly deadline: number;
}

/** One mounted Account-browser/team owns this exact in-memory original operation. */
export class AccessRequestActions {
  readonly api: AccessRequestApi;
  pending: AccessRequestIntent | undefined;
  reviewRequired = false;
  #active = true;
  #running = false;
  constructor(api: AccessRequestApi) {
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
  async decide(
    original: AccessRequestResource,
    decision: RequestDecision,
  ): Promise<AccessRequestResource> {
    this.current();
    if (this.pending || this.reviewRequired || !requestPending(original))
      throw new Error("Review the current request first.");
    const captured = parseAccessRequest(JSON.stringify(original));
    decisionActor(captured, decision, this.api.account);
    Object.freeze(captured.data);
    Object.freeze(captured);
    this.pending = Object.freeze({
      original: captured,
      decision,
      key: operationId(),
      deadline: Date.now() + 86_400_000,
    });
    return this.attempt(true);
  }
  async confirm(): Promise<AccessRequestResource> {
    return this.attempt(false);
  }
  private async attempt(initial: boolean): Promise<AccessRequestResource> {
    this.current();
    const intent = this.pending;
    if (!intent || Date.now() >= intent.deadline)
      throw new Error("Original confirmation is unavailable.");
    if (this.#running)
      throw new Error("A request action is already in progress.");
    this.#running = true;
    try {
      const result = await this.api.decide(
        intent.original,
        intent.decision,
        intent.key,
      );
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
      ) {
        this.pending = undefined;
        if (error.status === 412 || error.status === 409)
          this.reviewRequired = true;
      }
      throw error;
    } finally {
      this.#running = false;
    }
  }
}
