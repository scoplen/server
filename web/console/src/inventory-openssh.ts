// SPDX-License-Identifier: AGPL-3.0-only
import type { InventoryImportFields } from "./generated/api.ts";
import { object, strictJson } from "./wire.ts";

const fileKinds = [
  "raw_too_large",
  "invalid_utf8",
  "invalid_syntax",
  "unsupported_scope",
  "no_candidates",
  "too_many_candidates",
] as const;
const diagnosticKinds = [
  "unsupported_option",
  "unsupported_value",
  "invalid_field",
  "missing_username",
] as const;
const fields = ["name", "address", "port", "username"] as const;
export type OpenSshFileKind = (typeof fileKinds)[number] | "unavailable";
export interface InventoryOpenSshDiagnostic {
  kind: (typeof diagnosticKinds)[number];
  candidate: number;
  line?: number;
  field?: (typeof fields)[number];
}
export type InventoryOpenSshCandidate =
  | { status: "ready"; candidate: number; fields: InventoryImportFields }
  | { status: "blocked"; diagnostic: InventoryOpenSshDiagnostic };
export interface InventoryOpenSshParser {
  parse(input: Uint8Array): Promise<InventoryOpenSshCandidate[]>;
}
export class InventoryOpenSshFailure extends Error {
  readonly kind: OpenSshFileKind;
  readonly line?: number;
  constructor(kind: OpenSshFileKind, line?: number) {
    super(kind);
    this.kind = kind;
    this.line = line;
  }
}

function keys(
  value: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) {
  if (
    required.some((key) => !(key in value)) ||
    Object.keys(value).some(
      (key) => !required.includes(key) && !optional.includes(key),
    )
  )
    throw new Error("Invalid preparation fields.");
}
function line(value: unknown): number | undefined {
  if (value === undefined) return;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 1_048_577
  )
    throw new Error("Invalid preparation line.");
  return value;
}

/** Decode only fixed metadata; never retain a thrown message or source-derived value. */
export function openSshFailure(value: unknown): InventoryOpenSshFailure {
  try {
    if (typeof value !== "string" || value.length > 128) throw new Error();
    const input = object(strictJson(value));
    keys(input, ["kind"], ["line"]);
    if (!fileKinds.includes(input.kind as (typeof fileKinds)[number]))
      throw new Error();
    return new InventoryOpenSshFailure(
      input.kind as OpenSshFileKind,
      line(input.line),
    );
  } catch {
    return new InventoryOpenSshFailure("unavailable");
  }
}

/** Decode the shared projection without interpreting configuration or selecting any row. */
export function parsedInventoryOpenSsh(
  source: string,
): InventoryOpenSshCandidate[] {
  try {
    const input = object(strictJson(source));
    keys(input, ["candidates"]);
    if (
      !Array.isArray(input.candidates) ||
      input.candidates.length < 1 ||
      input.candidates.length > 100
    )
      throw new Error();
    return input.candidates.map((value, index) => {
      const candidate = object(value);
      if (candidate.status === "ready") {
        keys(candidate, ["status", "candidate", "fields"]);
        const row = object(candidate.fields);
        keys(row, [...fields]);
        if (
          candidate.candidate !== index + 1 ||
          typeof row.name !== "string" ||
          !row.name ||
          typeof row.address !== "string" ||
          !row.address ||
          typeof row.username !== "string" ||
          !row.username ||
          !Number.isInteger(row.port) ||
          Number(row.port) < 1 ||
          Number(row.port) > 65535
        )
          throw new Error();
        return {
          status: "ready",
          candidate: index + 1,
          fields: {
            name: row.name,
            address: row.address,
            port: row.port as number,
            username: row.username,
          },
        };
      }
      if (candidate.status !== "blocked") throw new Error();
      keys(candidate, ["status", "diagnostic"]);
      const diagnostic = object(candidate.diagnostic);
      keys(diagnostic, ["kind", "candidate"], ["line", "field"]);
      if (
        diagnostic.candidate !== index + 1 ||
        !diagnosticKinds.includes(
          diagnostic.kind as (typeof diagnosticKinds)[number],
        ) ||
        (diagnostic.field !== undefined &&
          !fields.includes(diagnostic.field as (typeof fields)[number]))
      )
        throw new Error();
      return {
        status: "blocked",
        diagnostic: {
          kind: diagnostic.kind as InventoryOpenSshDiagnostic["kind"],
          candidate: index + 1,
          ...(diagnostic.line === undefined
            ? {}
            : { line: line(diagnostic.line) }),
          ...(diagnostic.field === undefined
            ? {}
            : {
                field: diagnostic.field as InventoryOpenSshDiagnostic["field"],
              }),
        },
      };
    });
  } catch {
    throw new InventoryOpenSshFailure("unavailable");
  }
}
