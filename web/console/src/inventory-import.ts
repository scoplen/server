// SPDX-License-Identifier: AGPL-3.0-only
import type {
  InventoryImportFields,
  InventoryImportRequest,
  InventoryImportResult,
} from "./generated/api.ts";
import { RequestFailure, TeamApi, operationId } from "./team.ts";
import { object, strictJson, uuid } from "./wire.ts";
import {
  InventoryOpenSshFailure,
  type InventoryOpenSshCandidate,
  type InventoryOpenSshParser,
} from "./inventory-openssh.ts";

export type InventoryImportSource = "csv" | "openssh";

export interface InventoryCsvParser {
  parse(input: Uint8Array): Promise<InventoryImportFields[]>;
}
export type CsvErrorKind =
  | "invalid_utf8"
  | "invalid_csv"
  | "invalid_header"
  | "invalid_cell"
  | "empty_input"
  | "too_many_records"
  | "too_large"
  | "request_too_large"
  | "unreadable"
  | "unavailable";
export type CsvField = "name" | "address" | "port" | "username" | "login_name";
export class InventoryCsvFailure extends Error {
  readonly kind: CsvErrorKind;
  readonly record?: number;
  readonly field?: CsvField;
  constructor(kind: CsvErrorKind, record?: number, field?: CsvField) {
    super(kind);
    this.kind = kind;
    this.record = record;
    this.field = field;
  }
}

/** Only fixed parser metadata may cross into feedback; never retain its thrown source. */
export function csvFailure(value: unknown): InventoryCsvFailure {
  try {
    if (typeof value !== "string" || value.length > 256) throw new Error();
    const input = object(strictJson(value));
    if (
      ![
        "invalid_utf8",
        "invalid_csv",
        "invalid_header",
        "invalid_cell",
        "empty_input",
        "too_many_records",
        "too_large",
      ].includes(String(input.kind))
    )
      throw new Error();
    const record = input.record;
    const field = input.field;
    if (
      (record !== undefined &&
        (typeof record !== "number" ||
          !Number.isInteger(record) ||
          record < 1 ||
          record > 101)) ||
      (field !== undefined &&
        !["name", "address", "port", "username", "login_name"].includes(
          String(field),
        ))
    )
      throw new Error();
    return new InventoryCsvFailure(
      input.kind as CsvErrorKind,
      record as number | undefined,
      field as CsvField | undefined,
    );
  } catch {
    return new InventoryCsvFailure("unavailable");
  }
}

/** Decode the Rust parser's JSON projection, without interpreting CSV or normalizing cells. */
export function parsedInventoryCsv(source: string): InventoryImportFields[] {
  const input = object(strictJson(source));
  if (
    !Array.isArray(input.rows) ||
    input.rows.length < 1 ||
    input.rows.length > 100
  )
    throw new InventoryCsvFailure("unavailable");
  return input.rows.map((value) => {
    const row = object(value);
    if (
      typeof row.name !== "string" ||
      typeof row.address !== "string" ||
      typeof row.username !== "string" ||
      !Number.isInteger(row.port) ||
      Number(row.port) < 1 ||
      Number(row.port) > 65535 ||
      (row.login_name !== undefined && typeof row.login_name !== "string")
    )
      throw new InventoryCsvFailure("unavailable");
    return {
      name: row.name,
      address: row.address,
      port: row.port as number,
      username: row.username,
      ...(row.login_name === undefined
        ? {}
        : { login_name: row.login_name as string }),
    };
  });
}

export function parseImportResult(
  source: string,
  request: InventoryImportRequest,
): InventoryImportResult {
  const input = object(strictJson(source));
  if (!Array.isArray(input.items) || input.items.length !== request.rows.length)
    throw new Error("Invalid import result count.");
  const items = input.items.map((item, index) => {
    const pair = object(item);
    const expected = request.rows[index];
    const host_id = uuid(pair.host_id),
      access_profile_id = uuid(pair.access_profile_id);
    if (
      host_id !== expected.host_id ||
      access_profile_id !== expected.access_profile_id
    )
      throw new Error("Mismatched import result identity.");
    return { host_id, access_profile_id };
  });
  return { items };
}

export class InventoryImportApi {
  readonly teamApi: TeamApi;
  readonly context: Readonly<{
    origin: string;
    account: string;
    organization: string;
    sessionGeneration: number | undefined;
  }>;
  constructor(teamApi: TeamApi, organization: string, account: string) {
    this.teamApi = teamApi;
    this.context = Object.freeze({
      origin: teamApi.transport.origin,
      account: uuid(account),
      organization: uuid(organization),
      sessionGeneration: teamApi.transport.sessionGeneration,
    });
  }
  async create(
    body: InventoryImportRequest,
    key: string,
  ): Promise<InventoryImportResult> {
    this.assertCurrent();
    if (new TextEncoder().encode(JSON.stringify(body)).length > 2_097_152)
      throw new RequestFailure("import_preparation_failed");
    const result = await this.teamApi.transport.request(
      "POST",
      `/api/v1/orgs/${this.context.organization}/inventory/imports`,
      {
        body,
        key: uuid(key),
        success: 201,
        maximum: 32_768,
        decode: (source) => parseImportResult(source, body),
      },
    );
    this.assertCurrent();
    try {
      // Recheck even when a transport already decoded the response.
      return parseImportResult(JSON.stringify(result.value), body);
    } catch {
      throw new RequestFailure("invalid_response", 201, true);
    }
  }
  assertCurrent(): void {
    if (
      this.teamApi.transport.origin !== this.context.origin ||
      this.teamApi.accountId !== this.context.account ||
      this.teamApi.transport.sessionGeneration !==
        this.context.sessionGeneration
    )
      throw new RequestFailure("session_changed");
  }
}

export interface InventoryImportIntent {
  readonly body: InventoryImportRequest;
  readonly key: string;
  readonly deadline: number;
  readonly context: InventoryImportApi["context"];
}
export type InventoryImportPhase =
  | "empty"
  | "parsing"
  | "preview"
  | "importing"
  | "uncertain"
  | "confirming"
  | "complete";
export interface InventoryImportState {
  phase: InventoryImportPhase;
  source?: InventoryImportSource;
  candidates?: readonly InventoryOpenSshCandidate[];
  selected?: readonly number[];
  preview?: InventoryImportRequest;
  pending?: InventoryImportIntent;
  failure?: unknown;
  imported: number;
}

/** One mounted TeamApi owns one login family; refresh preserves it, fresh login replaces it. */
export class InventoryImportWorkflow {
  readonly api: InventoryImportApi;
  readonly parser: InventoryCsvParser;
  readonly openssh?: InventoryOpenSshParser;
  state: InventoryImportState = { phase: "empty", imported: 0 };
  #active = true;
  #running = false;
  constructor(
    api: InventoryImportApi,
    parser: InventoryCsvParser,
    openssh?: InventoryOpenSshParser,
  ) {
    this.api = api;
    this.parser = parser;
    this.openssh = openssh;
  }
  dispose(): void {
    this.#active = false;
    this.state = { phase: "empty", imported: 0 };
  }
  private current(): void {
    if (!this.#active) throw new RequestFailure("session_changed");
    try {
      this.api.assertCurrent();
    } catch (error) {
      this.dispose();
      throw error;
    }
  }
  setSource(source: InventoryImportSource): void {
    this.current();
    if (
      this.#running ||
      this.state.pending ||
      source === (this.state.source ?? "csv")
    )
      return;
    this.state = { phase: "empty", source, imported: 0 };
  }
  select(candidate: number): void {
    this.current();
    if (
      this.#running ||
      this.state.pending ||
      this.state.preview ||
      this.state.phase !== "preview" ||
      !this.state.candidates?.some(
        (item) => item.status === "ready" && item.candidate === candidate,
      )
    )
      return;
    const selected = new Set(this.state.selected);
    if (selected.has(candidate)) selected.delete(candidate);
    else selected.add(candidate);
    this.state = {
      ...this.state,
      selected: Object.freeze([...selected].sort((a, b) => a - b)),
      failure: undefined,
    };
  }
  private prepareRows(
    fields: readonly InventoryImportFields[],
  ): InventoryImportRequest {
    const body: InventoryImportRequest = {
      rows: fields.map((row) =>
        Object.freeze({
          host_id: operationId(),
          access_profile_id: operationId(),
          name: row.name,
          address: row.address,
          port: row.port,
          username: row.username,
          ...(row.login_name === undefined
            ? {}
            : { login_name: row.login_name }),
        }),
      ),
    };
    Object.freeze(body.rows);
    Object.freeze(body);
    const ids = body.rows.flatMap((row) => [
      row.host_id,
      row.access_profile_id,
    ]);
    if (new Set(ids).size !== ids.length)
      throw new InventoryCsvFailure("unavailable");
    if (new TextEncoder().encode(JSON.stringify(body)).length > 2_097_152)
      throw new InventoryCsvFailure("request_too_large");
    return body;
  }
  async prepare(file: Pick<File, "size" | "arrayBuffer">): Promise<void> {
    this.current();
    if (this.#running || this.state.pending) return;
    this.#running = true;
    const source = this.state.source ?? "csv";
    this.state = { phase: "parsing", source, imported: 0 };
    let input: Uint8Array | undefined;
    try {
      if (file.size > 1_048_576) throw new InventoryCsvFailure("too_large");
      try {
        input = new Uint8Array(await file.arrayBuffer());
      } catch {
        throw new InventoryCsvFailure("unreadable");
      }
      this.current();
      if (input.byteLength > 1_048_576)
        throw new InventoryCsvFailure("too_large");
      if (source === "openssh") {
        if (!this.openssh) throw new InventoryOpenSshFailure("unavailable");
        const candidates = await this.openssh.parse(input);
        this.current();
        this.state = {
          phase: "preview",
          source,
          imported: 0,
          candidates: Object.freeze(
            candidates.map((candidate) =>
              candidate.status === "ready"
                ? Object.freeze({
                    ...candidate,
                    fields: Object.freeze({ ...candidate.fields }),
                  })
                : Object.freeze({
                    ...candidate,
                    diagnostic: Object.freeze({ ...candidate.diagnostic }),
                  }),
            ),
          ),
          selected: Object.freeze([]),
        };
        return;
      }
      const fields = await this.parser.parse(input);
      this.current();
      const body = this.prepareRows(fields);
      this.state = { phase: "preview", preview: body, imported: 0 };
    } catch (error) {
      this.current();
      this.state = {
        phase: "empty",
        source,
        failure:
          error instanceof InventoryCsvFailure ||
          error instanceof InventoryOpenSshFailure
            ? error
            : new InventoryCsvFailure("unavailable"),
        imported: 0,
      };
    } finally {
      input?.fill(0);
      this.#running = false;
    }
  }
  async submit(): Promise<void> {
    this.current();
    if (this.#running || this.state.pending) return;
    if (!this.state.preview && this.state.candidates) {
      const selected = new Set(this.state.selected);
      const fields = this.state.candidates.flatMap((candidate) =>
        candidate.status === "ready" && selected.has(candidate.candidate)
          ? [candidate.fields]
          : [],
      );
      if (!fields.length) return;
      try {
        const preview = this.prepareRows(fields);
        this.state = {
          ...this.state,
          preview,
          candidates: undefined,
          selected: undefined,
          failure: undefined,
        };
      } catch (error) {
        this.state = {
          ...this.state,
          failure:
            error instanceof InventoryCsvFailure
              ? error
              : new InventoryCsvFailure("unavailable"),
        };
        return;
      }
    }
    if (!this.state.preview) return;
    let key: string;
    try {
      key = operationId();
    } catch {
      this.state = {
        ...this.state,
        failure: new RequestFailure("import_preparation_failed"),
      };
      return;
    }
    const pending = Object.freeze({
      body: this.state.preview,
      key,
      deadline: Date.now() + 86_400_000,
      context: this.api.context,
    });
    this.state = { ...this.state, pending };
    await this.attempt(true);
  }
  async confirmOriginal(): Promise<void> {
    this.current();
    if (this.#running || !this.state.pending) return;
    if (Date.now() >= this.state.pending.deadline) return;
    await this.attempt(false);
  }
  private async attempt(initial: boolean): Promise<void> {
    this.current();
    const intent = this.state.pending!;
    this.#running = true;
    this.state = {
      ...this.state,
      phase: initial ? "importing" : "confirming",
      failure: undefined,
    };
    try {
      await this.api.create(intent.body, intent.key);
      this.current();
      this.state = { phase: "complete", imported: intent.body.rows.length };
    } catch (error) {
      this.current();
      const unchanged =
        initial &&
        error instanceof RequestFailure &&
        !error.changed &&
        error.code !== "session_changed";
      this.state = {
        ...this.state,
        phase: unchanged ? "preview" : "uncertain",
        pending: unchanged ? undefined : intent,
        failure: error,
      };
    } finally {
      this.#running = false;
    }
  }
}
