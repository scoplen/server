// SPDX-License-Identifier: AGPL-3.0-only
import { connectionTarget } from "./auth-connection.ts";
import type {
  OrganizationLinkAttempt,
  OrganizationLinkConnection,
  OrganizationMemberLink,
  OrganizationSelfLinkStatus,
  OrganizationMemberLinkStatus,
} from "./generated/api.ts";
import { providerNavigation } from "./issuer-draft.ts";
import {
  operationId,
  RequestFailure,
  resourceTimestamp,
  type TeamApi,
} from "./team.ts";
import { object, uuid } from "./wire.ts";

const verificationWindow = 300_000;
type Context = { organization_id: string; membership_id: string };
type Attempt = {
  data: OrganizationLinkAttempt;
  connection: OrganizationLinkConnection;
  url?: string;
  until: number;
  recovery: Pick<Original, "until" | "wallDeadline">;
};
type Original = {
  path: string;
  etag: string;
  key: string;
  until: number;
  wallDeadline: number;
};

function publicFields(value: unknown, start = false) {
  const fields = object(value);
  if (
    [
      "sub",
      "subject",
      "subject_digest",
      "subject_comparison",
      "comparison_value",
      "claims",
      "client_secret",
      "access_token",
      "refresh_token",
      "id_token",
    ].some((field) => field in fields) ||
    (!start && "authorization_url" in fields)
  )
    throw new Error("Private field in member link.");
  return fields;
}
function version(fields: Record<string, unknown>) {
  const id = uuid(fields.id),
    etag = `"${id}"`;
  if (fields.etag !== etag) throw new Error("Invalid immutable link version.");
  return { id, etag };
}
function bound(fields: Record<string, unknown>, context: Context) {
  if (
    fields.organization_id !== context.organization_id ||
    fields.membership_id !== context.membership_id
  )
    throw new Error("Unexpected membership.");
}
function link(value: unknown, context: Context): OrganizationMemberLink {
  const fields = publicFields(value);
  bound(fields, context);
  return {
    ...version(fields),
    ...context,
    created_at: resourceTimestamp(fields.created_at),
  };
}
function attempt(
  value: unknown,
  context: Context,
  revision: string,
  start: boolean,
): OrganizationLinkAttempt {
  const fields = publicFields(value, start);
  bound(fields, context);
  const status = fields.status;
  if (
    fields.connection_revision !== revision ||
    (status !== "pending" && status !== "verified" && status !== "failed") ||
    (start && status !== "pending")
  )
    throw new Error("Invalid link verification.");
  return {
    ...context,
    id: uuid(fields.id),
    connection_revision: revision,
    status,
    expires_at: resourceTimestamp(fields.expires_at),
  };
}
function decoded<T>(status: number, changed: boolean, parse: () => T) {
  try {
    return parse();
  } catch {
    throw new RequestFailure("invalid_response", status, changed);
  }
}
function noTag(etag: string | null) {
  if (etag !== null) throw new Error("Unexpected link version.");
}
function reviewRequired(): never {
  throw new RequestFailure("link_review_required");
}

export class MemberLinkActions {
  readonly #api: TeamApi;
  readonly #account: string;
  readonly #generation: number | undefined;
  readonly #context: Context;
  readonly #named: boolean;
  readonly #path: string;
  #disposed = false;
  #busy = false;
  #candidate?: Attempt;
  #waitUntil = 0;
  #original?: Original;
  current?: OrganizationSelfLinkStatus | OrganizationMemberLinkStatus;
  receipt?: OrganizationMemberLink;

  constructor(
    api: TeamApi,
    organization: string,
    membership: string,
    named = false,
  ) {
    this.#api = api;
    this.#account = uuid(api.accountId);
    this.#generation = api.transport.sessionGeneration;
    this.#context = {
      organization_id: uuid(organization),
      membership_id: uuid(membership),
    };
    this.#named = named;
    this.#path = `/api/v1/orgs/${organization}${named ? `/members/${membership}` : ""}/auth-link`;
  }
  get remaining() {
    return this.#candidate
      ? Math.max(
          0,
          Math.min(
            this.#candidate.until - performance.now(),
            Date.parse(this.#candidate.data.expires_at) - Date.now(),
          ),
        )
      : 0;
  }
  get candidate() {
    return this.remaining > 0 ? this.#candidate : undefined;
  }
  get waitRemaining() {
    return Math.max(0, this.#waitUntil - performance.now());
  }
  get pending() {
    return this.#original !== undefined;
  }
  get recoveryRemaining() {
    return this.#original
      ? Math.max(
          0,
          Math.min(
            this.#original.until - performance.now(),
            this.#original.wallDeadline - Date.now(),
          ),
        )
      : 0;
  }
  get hasLocalWork() {
    return (
      this.#busy ||
      Boolean(this.candidate || this.pending || this.waitRemaining)
    );
  }
  dispose() {
    this.#disposed = true;
    this.#candidate = undefined;
    this.#original = undefined;
    this.current = undefined;
    this.receipt = undefined;
    this.#waitUntil = 0;
  }
  #check() {
    if (
      this.#disposed ||
      this.#api.accountId !== this.#account ||
      this.#api.transport.sessionGeneration !== this.#generation
    ) {
      this.dispose();
      throw new RequestFailure("session_changed");
    }
  }
  async #run(action: () => Promise<void>) {
    this.#check();
    if (this.#busy) throw new RequestFailure("link_busy");
    this.#busy = true;
    try {
      await action();
    } finally {
      this.#busy = false;
      this.#check();
    }
  }
  async read() {
    await this.#run(async () => {
      this.current = undefined;
      this.receipt = undefined;
      const reply = await this.#api.transport.request("GET", this.#path);
      this.#check();
      this.current = decoded(200, false, () => {
        noTag(reply.etag);
        const fields = publicFields(reply.value);
        bound(fields, this.#context);
        const status = {
          ...this.#context,
          link: fields.link === null ? null : link(fields.link, this.#context),
        };
        if (this.#named) {
          if ("connection" in fields) throw new Error("Unexpected connection.");
          return status;
        }
        const settings =
          fields.connection === null ? null : publicFields(fields.connection);
        return {
          ...status,
          connection: settings && {
            ...version(settings),
            ...connectionTarget(settings),
          },
        };
      });
      if (
        this.#candidate &&
        (this.current.connection?.id !== this.#candidate.connection.id ||
          this.current.connection.issuer !==
            this.#candidate.connection.issuer ||
          this.current.connection.client_id !==
            this.#candidate.connection.client_id ||
          this.current.connection.space_id !==
            this.#candidate.connection.space_id ||
          this.current.link)
      )
        this.#candidate = undefined;
      if (
        this.#original &&
        this.current.connection?.etag !== this.#original.etag
      )
        this.#original.until = 0;
    });
  }
  async start() {
    await this.#run(async () => {
      const connection = this.current?.connection;
      if (
        this.#named ||
        !connection ||
        this.current?.link ||
        this.candidate ||
        this.pending ||
        this.waitRemaining
      )
        reviewRequired();
      // Native password freshness starts no later than this first request.
      const recovery = {
        until: performance.now() + verificationWindow,
        wallDeadline: Date.now() + verificationWindow,
      };
      try {
        const reply = await this.#api.transport.request(
          "POST",
          this.#path + "/attempts",
          { etag: connection.etag, success: 201 },
        );
        this.#check();
        this.#candidate = decoded(201, true, () => {
          noTag(reply.etag);
          const data = attempt(reply.value, this.#context, connection.id, true);
          const duration = Date.parse(data.expires_at) - Date.now();
          if (!(duration > 0 && duration <= verificationWindow))
            throw new Error("Invalid link expiry.");
          return {
            data,
            connection,
            recovery,
            until: performance.now() + duration,
            url: providerNavigation(
              object(reply.value).authorization_url,
              connection.issuer,
            ),
          };
        });
      } catch (error) {
        this.#check();
        if (
          !(error instanceof RequestFailure) ||
          error.changed ||
          error.status === 409
        )
          this.#waitUntil = performance.now() + verificationWindow;
        if (
          error instanceof RequestFailure &&
          [401, 403, 404, 409, 412].includes(error.status)
        )
          this.current = undefined;
        throw error;
      }
    });
  }
  #attemptPath(item: Attempt) {
    return this.#path + "/attempts/" + item.data.id;
  }
  async checkAttempt() {
    await this.#run(async () => {
      const original = this.candidate;
      if (!original || this.pending) reviewRequired();
      this.#candidate = {
        ...original,
        data: { ...original.data, status: "pending" },
        url: undefined,
      };
      try {
        const reply = await this.#api.transport.request(
          "GET",
          this.#attemptPath(original),
        );
        this.#check();
        this.#candidate = decoded(200, false, () => {
          noTag(reply.etag);
          const data = attempt(
            reply.value,
            this.#context,
            original.connection.id,
            false,
          );
          if (
            data.id !== original.data.id ||
            data.expires_at !== original.data.expires_at
          )
            throw new Error("Different link attempt.");
          return {
            ...original,
            data,
            url: data.status === "pending" ? original.url : undefined,
          };
        });
      } catch (error) {
        if (
          error instanceof RequestFailure &&
          [401, 403, 404, 412].includes(error.status)
        ) {
          this.#candidate = undefined;
          this.current = undefined;
        }
        throw error;
      }
    });
  }
  async #remove(path: string, etag?: string) {
    const reply = await this.#api.transport.request("DELETE", path, {
      ...(etag ? { etag } : {}),
      success: 204,
    });
    this.#check();
    if (reply.etag !== null || reply.value !== undefined)
      throw new RequestFailure("invalid_response", 204, true);
  }
  async abandon() {
    await this.#run(async () => {
      const original = this.candidate;
      if (!original || this.pending) reviewRequired();
      this.#candidate = {
        ...original,
        data: { ...original.data, status: "pending" },
        url: undefined,
      };
      try {
        await this.#remove(this.#attemptPath(original));
        this.#candidate = undefined;
      } catch (error) {
        if (error instanceof RequestFailure && error.status === 404)
          this.#candidate = undefined;
        throw error;
      }
    });
  }
  async confirm() {
    await this.#run(async () => {
      const original = this.candidate;
      if (
        this.pending ||
        original?.data.status !== "verified" ||
        this.current?.connection?.id !== original.connection.id ||
        this.current.link
      )
        reviewRequired();
      this.#original = {
        path: this.#attemptPath(original) + "/confirm",
        etag: original.connection.etag,
        key: operationId(),
        ...original.recovery,
      };
      this.#candidate = undefined;
      await this.#submit(false);
    });
  }
  async recover() {
    await this.#run(async () => {
      if (
        !this.#original ||
        !this.recoveryRemaining ||
        (this.current && this.current.connection?.etag !== this.#original.etag)
      )
        reviewRequired();
      await this.#submit(true);
    });
  }
  async #submit(recovery: boolean) {
    const original = this.#original!;
    this.current = undefined;
    try {
      const reply = await this.#api.transport.request("POST", original.path, {
        etag: original.etag,
        key: original.key,
        success: 201,
      });
      this.#check();
      this.receipt = decoded(201, true, () => {
        const item = link(reply.value, this.#context);
        if (item.etag !== reply.etag)
          throw new Error("Unconfirmed link version.");
        return item;
      });
      this.#original = undefined;
    } catch (error) {
      this.#check();
      if (
        !recovery &&
        error instanceof RequestFailure &&
        !error.changed &&
        !error.retryable
      )
        this.#original = undefined;
      throw error;
    }
  }
  discardReceipt() {
    this.#check();
    if (this.#busy) throw new RequestFailure("link_busy");
    this.#original = undefined;
    this.current = undefined;
  }
  async withdraw(reviewedId: string) {
    await this.#run(async () => {
      const selected = this.current?.link;
      if (!selected || selected.id !== reviewedId || this.pending)
        reviewRequired();
      this.current = undefined;
      await this.#remove(this.#path, selected.etag);
    });
  }
}
