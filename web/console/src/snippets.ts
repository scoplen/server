// SPDX-License-Identifier: AGPL-3.0-only
import type {
  InventorySnippetCreateRequest,
  InventorySnippetFields,
  InventorySnippetResource,
} from "./generated/api.ts";
import { snippetFields } from "./snippet-fields.ts";
import {
  TeamApi,
  RequestFailure,
  operationId,
  parseCollection,
} from "./team.ts";
import { uuid } from "./wire.ts";

export interface SnippetIntent {
  readonly body: InventorySnippetCreateRequest;
  readonly key: string;
  readonly deadline: number;
}

/** In-memory authoring belongs to one Account, team and browser login family. */
export class SnippetActions {
  readonly teamApi: TeamApi;
  readonly context: Readonly<{
    origin: string;
    account: string;
    organization: string;
    sessionGeneration: number | undefined;
  }>;
  pending: SnippetIntent | undefined;
  reviewRequired = false;
  #active = true;
  #running = false;
  constructor(teamApi: TeamApi, organization: string, account: string) {
    this.teamApi = teamApi;
    this.context = Object.freeze({
      origin: teamApi.transport.origin,
      account: uuid(account),
      organization: uuid(organization),
      sessionGeneration: teamApi.transport.sessionGeneration,
    });
  }
  dispose(): void {
    this.#active = false;
    this.pending = undefined;
  }
  private current(): void {
    if (
      !this.#active ||
      this.teamApi.transport.origin !== this.context.origin ||
      this.teamApi.accountId !== this.context.account ||
      this.teamApi.transport.sessionGeneration !==
        this.context.sessionGeneration
    ) {
      this.dispose();
      throw new RequestFailure("session_changed");
    }
  }
  private async execute<T>(action: () => Promise<T>): Promise<T> {
    this.current();
    if (this.#running) throw new Error("Snippet action already in progress.");
    this.#running = true;
    try {
      const result = await action();
      this.current();
      return result;
    } finally {
      this.#running = false;
    }
  }
  async list(cursor?: string) {
    return this.execute(() =>
      this.teamApi.list(this.context.organization, "snippets", cursor),
    );
  }
  async review() {
    const page = await this.list();
    this.reviewRequired = false;
    return page;
  }
  async read(id: string): Promise<InventorySnippetResource> {
    return this.execute(async () => {
      const reply = await this.teamApi.transport.request(
        "GET",
        `/api/v1/orgs/${this.context.organization}/snippets/${uuid(id)}`,
        { maximum: 2_097_152 },
      );
      const result = parseCollection("snippets", reply.value, reply.etag);
      if (result.id !== id) throw new Error("Mismatched Snippet result.");
      return result;
    });
  }
  async create(
    fields: InventorySnippetFields,
  ): Promise<InventorySnippetResource> {
    this.current();
    if (this.pending || this.reviewRequired)
      throw new Error("Review current Snippets first.");
    const data = snippetFields(fields);
    for (const entry of Object.values(data.variables ?? {})) {
      if (entry.kind === 3) Object.freeze(entry.choices);
      Object.freeze(entry);
    }
    if (data.variables) Object.freeze(data.variables);
    if (data.tags) Object.freeze(data.tags);
    Object.freeze(data);
    this.pending = Object.freeze({
      body: Object.freeze({
        id: operationId(),
        data: Object.freeze({ fields: data }),
      }),
      key: operationId(),
      deadline: Date.now() + 86_400_000,
    });
    return this.attempt(true);
  }
  async confirm(): Promise<InventorySnippetResource> {
    return this.attempt(false);
  }
  private async attempt(initial: boolean): Promise<InventorySnippetResource> {
    this.current();
    const intent = this.pending;
    if (!intent || Date.now() >= intent.deadline)
      throw new Error("Original Snippet confirmation is unavailable.");
    return this.execute(async () => {
      try {
        const result = await this.save(intent.body.data.fields, undefined, {
          id: intent.body.id,
          key: intent.key,
        });
        this.current();
        this.pending = undefined;
        return result;
      } catch (error) {
        this.current();
        if (initial && error instanceof RequestFailure && !error.changed)
          this.pending = undefined;
        throw error;
      }
    });
  }
  discard(): void {
    this.current();
    this.pending = undefined;
    this.reviewRequired = true;
  }
  async replace(
    original: InventorySnippetResource,
    fields: InventorySnippetFields,
  ) {
    const desired = snippetFields(fields);
    return this.edit(() => this.save(desired, original));
  }
  async remove(original: InventorySnippetResource): Promise<void> {
    return this.edit(() =>
      this.teamApi.remove(this.context.organization, "snippets", original),
    );
  }
  private async save(
    fields: InventorySnippetFields,
    original?: InventorySnippetResource,
    creation?: { id: string; key: string },
  ) {
    try {
      const result = await this.teamApi.save(
        this.context.organization,
        "snippets",
        fields,
        original,
        creation,
      );
      const actual = snippetFields(result.data.fields),
        desired = snippetFields(fields);
      // Empty optional maps have no entries in the existing K-1 projection.
      for (const value of [actual, desired]) {
        if (value.variables && Object.keys(value.variables).length === 0)
          delete value.variables;
        if (value.tags && Object.keys(value.tags).length === 0)
          delete value.tags;
      }
      if (
        JSON.stringify(actual) !== JSON.stringify(desired) ||
        (original && result.created_at !== original.created_at)
      )
        throw new Error("Mismatched Snippet fields.");
      return result;
    } catch (error) {
      if (error instanceof RequestFailure) throw error;
      throw new RequestFailure("invalid_response", original ? 200 : 201, true);
    }
  }
  private async edit<T>(action: () => Promise<T>): Promise<T> {
    this.current();
    if (this.pending || this.reviewRequired)
      throw new Error("Review current Snippets first.");
    return this.execute(async () => {
      try {
        return await action();
      } catch (error) {
        this.current();
        if (
          !(error instanceof RequestFailure) ||
          error.changed ||
          error.status === 412
        )
          this.reviewRequired = true;
        throw error;
      }
    });
  }
}
