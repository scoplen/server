// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AuthConnectionActivation,
  AuthConnectionCandidate,
  AuthConnectionDraftResource,
  AuthConnectionResource,
} from "./generated/api.ts";
import {
  draftIssuer,
  providerNavigation,
  validCredential,
} from "./issuer-draft.ts";
import {
  operationId,
  RequestFailure,
  resource,
  resourceTimestamp,
  type ApiResponse,
  type TeamApi,
} from "./team.ts";
import { object, text, uuid } from "./wire.ts";

type CandidateInput = Omit<AuthConnectionCandidate, "draft_generation">;
type Condition = { etag: string } | { ifNoneMatch: "*" };
type Target = { issuer: string; client_id: string; space_id: string };
type Candidate = {
  attempt: AuthConnectionActivation;
  until: number;
  url?: string;
};
type Transition = {
  key: string;
  path: string;
  condition: Condition;
  status: AuthConnectionResource["data"]["status"];
  target: Target;
  previous: string | null;
  deadline: number;
  wallDeadline: number;
};
const verificationWindow = 300_000;
const receiptWindow = 86_400_000;

function spaceId(value: string) {
  return /^spc_[A-Za-z0-9_-]{1,92}$/.test(value);
}

function publicFields(fields: Record<string, unknown>) {
  for (const name of [
    "client_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "claims",
  ])
    if (name in fields) throw new Error("Confidential field in response.");
  return fields;
}

export function connectionTarget(fields: Record<string, unknown>): Target {
  const client_id = text(fields.client_id),
    space_id = text(fields.space_id);
  if (!validCredential(client_id) || !spaceId(space_id))
    throw new Error("Invalid connection target.");
  return { issuer: draftIssuer(fields.issuer), client_id, space_id };
}

function sameTarget(a: Target, b: Target) {
  return (
    a.issuer === b.issuer &&
    a.client_id === b.client_id &&
    a.space_id === b.space_id
  );
}

function connection(
  reply: ApiResponse,
  org: string,
  original?: Transition,
): AuthConnectionResource {
  try {
    const envelope = publicFields(object(reply.value));
    const item = resource(envelope, reply.etag);
    const fields = publicFields(item.data);
    const settings = connectionTarget(fields),
      status = fields.status;
    if (
      "authorization_url" in envelope ||
      "authorization_url" in fields ||
      item.etag !== `"${item.id}"` ||
      item.created_at !== item.updated_at ||
      uuid(fields.organization_id) !== org ||
      (status !== "active" && status !== "suspended") ||
      (original &&
        (status !== original.status ||
          item.id === original.previous ||
          !sameTarget(settings, original.target)))
    )
      throw new Error("Mismatched connection.");
    return {
      id: item.id,
      etag: item.etag,
      created_at: item.created_at,
      updated_at: item.updated_at,
      data: { ...settings, organization_id: org, status },
    };
  } catch {
    throw new RequestFailure("invalid_response", 200, Boolean(original));
  }
}

function activation(reply: ApiResponse, org: string): AuthConnectionActivation {
  const fields = publicFields(object(reply.value));
  const status = fields.status;
  if (
    reply.etag !== null ||
    uuid(fields.organization_id) !== org ||
    (status !== "pending" && status !== "verified" && status !== "failed")
  )
    throw new Error("Invalid activation.");
  return {
    ...connectionTarget(fields),
    id: uuid(fields.id),
    organization_id: org,
    draft_generation: uuid(fields.draft_generation),
    expected_revision:
      fields.expected_revision === null ? null : uuid(fields.expected_revision),
    status,
    expires_at: resourceTimestamp(fields.expires_at),
  };
}

function missing(error: unknown) {
  return (
    error instanceof RequestFailure &&
    error.status === 404 &&
    error.code === "organization.not_found" &&
    !error.changed &&
    !error.retryable
  );
}

export class AuthConnectionActions {
  readonly #api: TeamApi;
  readonly #account: string;
  readonly #generation: number | undefined;
  readonly #org: string;
  readonly #path: string;
  #disposed = false;
  #busy = false;
  #candidate?: Candidate;
  #waitUntil = 0;
  #pending?: Transition;
  current: AuthConnectionResource | null | undefined;
  receipt: AuthConnectionResource | undefined;

  constructor(api: TeamApi, org: string) {
    this.#api = api;
    this.#account = uuid(api.accountId);
    this.#generation = api.transport.sessionGeneration;
    this.#org = uuid(org);
    this.#path = `/api/v1/orgs/${this.#org}/auth-connection`;
  }
  get candidate() {
    return this.candidateRemaining > 0 ? this.#candidate : undefined;
  }
  get candidateRemaining() {
    return Math.max(0, (this.#candidate?.until ?? 0) - performance.now());
  }
  get waitRemaining() {
    return Math.max(0, this.#waitUntil - performance.now());
  }
  get hasPendingReceipt() {
    return this.#pending !== undefined;
  }
  get canRecover() {
    return (
      this.#pending !== undefined &&
      performance.now() < this.#pending.deadline &&
      Date.now() < this.#pending.wallDeadline
    );
  }
  get hasLocalWork() {
    return (
      this.#busy ||
      this.hasPendingReceipt ||
      this.waitRemaining > 0 ||
      Boolean(this.candidate)
    );
  }
  dispose() {
    this.#disposed = true;
    this.current = undefined;
    this.receipt = undefined;
    this.#candidate = undefined;
    this.#pending = undefined;
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
  async #run<T>(action: () => Promise<T>) {
    this.#check();
    if (this.#busy) throw new RequestFailure("connection_busy");
    this.#busy = true;
    try {
      return await action();
    } finally {
      this.#busy = false;
      this.#check();
    }
  }
  async readCurrent() {
    await this.#run(async () => {
      this.current = undefined;
      try {
        const reply = await this.#api.transport.request("GET", this.#path);
        this.#check();
        this.current = connection(reply, this.#org);
      } catch (error) {
        if (!missing(error)) throw error;
        this.#check();
        this.current = null;
      }
      this.receipt = undefined;
    });
  }
  #condition(): Condition {
    if (this.current === undefined)
      throw new RequestFailure("connection_review_required");
    return this.current === null
      ? { ifNoneMatch: "*" }
      : { etag: this.current.etag };
  }
  async start(draft: AuthConnectionDraftResource, input: CandidateInput) {
    await this.#run(async () => {
      if (
        this.#pending ||
        this.candidate ||
        this.waitRemaining > 0 ||
        draft.data.organization_id !== this.#org
      )
        throw new RequestFailure("connection_review_required");
      const draftID = uuid(draft.id),
        issuer = draftIssuer(draft.data.issuer);
      if (
        !validCredential(input.client_id) ||
        !validCredential(input.client_secret) ||
        !spaceId(input.space_id)
      )
        throw new RequestFailure("invalid_connection_candidate");
      const condition = this.#condition(),
        expected = this.current?.id ?? null;
      this.receipt = undefined;
      try {
        const reply = await this.#api.transport.request(
          "POST",
          `${this.#path}/activations`,
          {
            ...condition,
            success: 201,
            body: {
              draft_generation: draftID,
              client_id: input.client_id,
              client_secret: input.client_secret,
              space_id: input.space_id,
            },
          },
        );
        this.#check();
        try {
          const attempt = activation(reply, this.#org);
          if (
            attempt.status !== "pending" ||
            attempt.draft_generation !== draftID ||
            attempt.expected_revision !== expected ||
            !sameTarget(attempt, {
              issuer,
              client_id: input.client_id,
              space_id: input.space_id,
            })
          )
            throw new Error("Mismatched candidate.");
          const duration = Date.parse(attempt.expires_at) - Date.now();
          if (!(duration > 0 && duration <= verificationWindow))
            throw new Error("Invalid verification window.");
          this.#candidate = {
            attempt,
            until: performance.now() + duration,
            url: providerNavigation(
              object(reply.value).authorization_url,
              issuer,
            ),
          };
        } catch {
          throw new RequestFailure("invalid_response", 201, true);
        }
      } catch (error) {
        this.#check();
        if (
          !(error instanceof RequestFailure) ||
          error.changed ||
          error.status === 409
        )
          this.#waitUntil = performance.now() + verificationWindow;
        if (error instanceof RequestFailure && error.status === 412)
          this.current = undefined;
        throw error;
      }
    });
  }
  #attemptPath(attempt: AuthConnectionActivation) {
    return `${this.#path}/activations/${attempt.id}`;
  }
  async checkCandidate() {
    await this.#run(async () => {
      const previous = this.candidate;
      if (this.#pending || !previous)
        throw new RequestFailure("connection_review_required");
      const original = previous.attempt;
      // Fail closed if a status reply cannot be verified. The known ID can still be abandoned.
      this.#candidate = {
        ...previous,
        attempt: { ...original, status: "pending" },
        url: undefined,
      };
      try {
        const reply = await this.#api.transport.request(
          "GET",
          this.#attemptPath(original),
        );
        this.#check();
        try {
          const attempt = activation(reply, this.#org);
          if (
            "authorization_url" in object(reply.value) ||
            attempt.id !== original.id ||
            attempt.draft_generation !== original.draft_generation ||
            attempt.expected_revision !== original.expected_revision ||
            attempt.expires_at !== original.expires_at ||
            !sameTarget(attempt, original)
          )
            throw new Error("Mismatched verification result.");
          this.#candidate = {
            ...previous,
            attempt,
            url: attempt.status === "pending" ? previous.url : undefined,
          };
        } catch {
          throw new RequestFailure("invalid_response", 200);
        }
      } catch (error) {
        if (missing(error)) this.#candidate = undefined;
        throw error;
      }
    });
  }
  async abandon() {
    await this.#run(async () => {
      const candidate = this.candidate;
      if (this.#pending || !candidate)
        throw new RequestFailure("connection_review_required");
      this.#candidate = {
        ...candidate,
        attempt: { ...candidate.attempt, status: "pending" },
        url: undefined,
      };
      const reply = await this.#api.transport.request(
        "DELETE",
        this.#attemptPath(candidate.attempt),
        { success: 204 },
      );
      this.#check();
      if (reply.value !== undefined || reply.etag !== null)
        throw new RequestFailure("invalid_response", 204, true);
      this.#candidate = undefined;
    });
  }
  async confirm(draftId: string) {
    await this.#run(async () => {
      const attempt = this.candidate?.attempt;
      if (
        this.#pending ||
        attempt?.status !== "verified" ||
        draftId !== attempt.draft_generation ||
        this.current === undefined ||
        (this.current?.id ?? null) !== attempt.expected_revision
      )
        throw new RequestFailure("connection_review_required");
      await this.#beginTransition(
        `${this.#attemptPath(attempt)}/confirm`,
        "active",
        attempt,
      );
    });
  }
  async suspend(reviewed: string) {
    await this.#run(async () => {
      if (
        this.#pending ||
        this.current?.data.status !== "active" ||
        this.current.id !== reviewed
      )
        throw new RequestFailure("connection_review_required");
      await this.#beginTransition(
        `${this.#path}/suspend`,
        "suspended",
        this.current.data,
      );
    });
  }
  async #beginTransition(
    path: string,
    status: Transition["status"],
    settings: Target,
  ) {
    this.#pending = {
      key: operationId(),
      path,
      status,
      condition: this.#condition(),
      target: {
        issuer: settings.issuer,
        client_id: settings.client_id,
        space_id: settings.space_id,
      },
      previous: this.current?.id ?? null,
      deadline: performance.now() + receiptWindow,
      wallDeadline: Date.now() + receiptWindow,
    };
    await this.#submit(false);
  }
  async recover() {
    await this.#run(async () => {
      if (!this.canRecover)
        throw new RequestFailure("connection_review_required");
      await this.#submit(true);
    });
  }
  discardReceipt() {
    this.#check();
    if (this.#busy) throw new RequestFailure("connection_busy");
    this.#pending = undefined;
    this.current = undefined;
    this.#candidate = undefined;
  }
  async #submit(recovery: boolean) {
    const original = this.#pending!;
    this.current = undefined;
    this.receipt = undefined;
    try {
      const reply = await this.#api.transport.request("POST", original.path, {
        ...original.condition,
        key: original.key,
      });
      this.#check();
      this.receipt = connection(reply, this.#org, original);
      this.#candidate = undefined;
      this.#pending = undefined;
    } catch (error) {
      this.#check();
      if (
        !recovery &&
        error instanceof RequestFailure &&
        !error.changed &&
        !error.retryable
      )
        this.#pending = undefined;
      throw error;
    }
  }
}
