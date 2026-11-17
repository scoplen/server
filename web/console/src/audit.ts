// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AuditCategory,
  AuditCheckpoint,
  AuditEvent,
  AuditOutcome,
  AuditPage,
  AuditRangeQuery,
  AuditResourceKind,
  AuditVerification,
} from "./generated/api.ts";
import type { AccountTransport } from "./team.ts";
import { bytes, object, strictJson, text, uuid } from "./wire.ts";

export interface AuditFilters {
  fromTime: string;
  beforeTime: string;
  actor: string;
  resource: string;
  eventClass: string;
  outcome: string;
}
export const emptyAuditFilters = (): AuditFilters => ({
  fromTime: "",
  beforeTime: "",
  actor: "",
  resource: "",
  eventClass: "",
  outcome: "",
});
export class AuditInputError extends Error {
  readonly field: keyof AuditFilters | "range";
  constructor(field: keyof AuditFilters | "range") {
    super("invalid_audit_input");
    this.field = field;
  }
}
const maximumSequence = 18_446_744_073_709_551_615n;
const encoder = new TextEncoder();
const outcomes: AuditOutcome[] = ["success", "failure", "unknown"];
const categories: AuditCategory[] = [
  "authentication",
  "authorization",
  "account_change",
  "scoplen",
  "unknown",
];
const resourceKinds: AuditResourceKind[] = [
  "organization",
  "invitation",
  "membership",
  "host",
  "host_group",
  "access_profile",
  "route",
  "trust_record",
  "snippet",
  "gateway_network",
  "group",
  "policy",
  "grant",
  "certificate_authority",
  "certificate",
];
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== "string" || !choices.includes(value as T))
    throw new Error("Invalid audit label.");
  return value as T;
}
export function auditSequence(value: unknown, zero = false): string {
  const result = text(value);
  if (
    !/^(?:0|[1-9][0-9]{0,19})$/.test(result) ||
    (!zero && result === "0") ||
    BigInt(result) > maximumSequence
  )
    throw new Error("Invalid audit sequence.");
  return result;
}
export function auditTime(value: unknown, positive = false): string {
  const result = text(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(result))
    throw new Error("Invalid audit time.");
  const milliseconds = Date.parse(result);
  if (!Number.isSafeInteger(milliseconds) || (positive && milliseconds <= 0))
    throw new Error("Invalid audit time.");
  const normalized = new Date(milliseconds)
    .toISOString()
    .replace(/\.(\d{3})Z$/, (_, fraction: string) => {
      const digits = fraction.replace(/0+$/, "");
      return digits ? `.${digits}Z` : "Z";
    });
  if (normalized !== result) throw new Error("Invalid audit time.");
  return result;
}
function eventClass(value: unknown): string {
  const result = text(value);
  if (
    result.length > 128 ||
    !/^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$/.test(result)
  )
    throw new Error("Invalid audit class.");
  return result;
}
function hash(value: unknown): string {
  const result = text(value);
  if (!/^[0-9a-f]{64}$/.test(result)) throw new Error("Invalid audit hash.");
  return result;
}
function optionalId(value: unknown): string | null {
  return value === null ? null : uuid(value);
}
function optionalSequence(value: unknown): string | null {
  return value === null ? null : auditSequence(value);
}
function optionalHash(value: unknown): string | null {
  return value === null ? null : hash(value);
}

function resource(value: unknown): AuditEvent["resource"] {
  if (value === null) return null;
  const input = object(value);
  return { kind: choice(input.kind, resourceKinds), id: uuid(input.id) };
}
function event(value: unknown): AuditEvent {
  const input = object(value);
  return {
    organization_id: uuid(input.organization_id),
    sequence: auditSequence(input.sequence),
    occurred_at: auditTime(input.occurred_at, true),
    category: choice(input.category, categories),
    event_class:
      input.event_class === null ? null : eventClass(input.event_class),
    outcome: choice(input.outcome, outcomes),
    actor_account_id: optionalId(input.actor_account_id),
    actor_device_id: optionalId(input.actor_device_id),
    actor_browser_family_id: optionalId(input.actor_browser_family_id),
    resource: resource(input.resource),
    previous_hash: hash(input.previous_hash),
    event_hash: hash(input.event_hash),
  };
}
interface Selection {
  parameters: URLSearchParams;
  limit: number;
  cursor?: string;
  matches: (item: AuditEvent) => boolean;
}
function selection(
  filters: AuditFilters,
  cursor?: string,
  limit = 50,
): Selection {
  const fields = Object.fromEntries(
    Object.entries(filters).map(([key, value]) => [key, value.trim()]),
  ) as unknown as AuditFilters;
  const clauses: string[] = [];
  for (const [key, field, operator, validate] of [
    ["fromTime", "occurred_at", "ge", auditTime],
    ["beforeTime", "occurred_at", "lt", auditTime],
    ["actor", "actor_account_id", "eq", uuid],
    ["eventClass", "event_class", "eq", eventClass],
  ] as const) {
    if (!fields[key]) continue;
    try {
      if (key === "fromTime" || key === "beforeTime")
        auditTime(fields[key], true);
      else validate(fields[key]);
    } catch {
      throw new AuditInputError(key);
    }
    clauses.push(`${field} ${operator} "${fields[key]}"`);
  }
  if (
    fields.fromTime &&
    fields.beforeTime &&
    Date.parse(fields.fromTime) >= Date.parse(fields.beforeTime)
  )
    throw new AuditInputError("beforeTime");
  let target: AuditEvent["resource"] = null;
  if (fields.resource) {
    const split = fields.resource.indexOf(":");
    try {
      target = resource({
        kind: fields.resource.slice(0, split),
        id: fields.resource.slice(split + 1),
      });
    } catch {
      throw new AuditInputError("resource");
    }
    clauses.push(`resource eq "${fields.resource}"`);
  }
  if (fields.outcome) {
    try {
      choice(fields.outcome, outcomes);
    } catch {
      throw new AuditInputError("outcome");
    }
    clauses.push(`outcome eq "${fields.outcome}"`);
  }
  const filter = clauses.join(" and ");
  if (encoder.encode(filter).length > 2_048)
    throw new AuditInputError("eventClass");
  if (!Number.isInteger(limit) || limit < 1 || limit > 500)
    throw new Error("Invalid audit page size.");
  const parameters = new URLSearchParams({
    limit: String(limit),
    sort: "-sequence",
  });
  if (cursor !== undefined) parameters.set("cursor", auditSequence(cursor));
  if (filter) parameters.set("filter", filter);
  return {
    parameters,
    limit,
    cursor,
    matches: (item) =>
      (!fields.fromTime ||
        Date.parse(item.occurred_at) >= Date.parse(fields.fromTime)) &&
      (!fields.beforeTime ||
        Date.parse(item.occurred_at) < Date.parse(fields.beforeTime)) &&
      (!fields.actor || item.actor_account_id === fields.actor) &&
      (!fields.eventClass || item.event_class === fields.eventClass) &&
      (!fields.outcome || item.outcome === fields.outcome) &&
      (!target ||
        (item.resource?.kind === target.kind &&
          item.resource.id === target.id)),
  };
}
function page(
  value: unknown,
  organization: string,
  query: Selection,
): AuditPage {
  const input = object(value);
  if (!Array.isArray(input.items) || input.items.length > query.limit)
    throw new Error("Invalid audit page.");
  const items = input.items.map(event);
  let previous =
    query.cursor === undefined ? maximumSequence + 1n : BigInt(query.cursor);
  for (const item of items) {
    if (
      item.organization_id !== organization ||
      BigInt(item.sequence) >= previous ||
      !query.matches(item)
    )
      throw new Error("Mismatched audit page.");
    previous = BigInt(item.sequence);
  }
  const next_cursor = optionalSequence(input.next_cursor);
  if (next_cursor !== null && next_cursor !== items.at(-1)?.sequence)
    throw new Error("Invalid audit continuation.");
  return { items, next_cursor };
}
function decodePage(
  source: string,
  organization: string,
  query: Selection,
): AuditPage {
  if (encoder.encode(source).length > 1_048_576)
    throw new Error("Audit page exceeds its limit.");
  const value = strictJson(source, (path, start, end) => {
    if (
      path.length === 2 &&
      path[0] === "items" &&
      typeof path[1] === "number" &&
      encoder.encode(source.slice(start, end)).length > 2_048
    )
      throw new Error("Audit event exceeds its limit.");
  });
  return page(value, organization, query);
}
export function parseAuditPage(
  source: string,
  organization: string,
  filters = emptyAuditFilters(),
  cursor?: string,
  limit = 50,
): AuditPage {
  return decodePage(
    source,
    uuid(organization),
    selection(filters, cursor, limit),
  );
}
export function auditRange(from: string, to: string): AuditRangeQuery {
  try {
    const from_sequence = auditSequence(from),
      to_sequence = auditSequence(to);
    if (
      BigInt(to_sequence) < BigInt(from_sequence) ||
      BigInt(to_sequence) - BigInt(from_sequence) >= 4_096n
    )
      throw new Error("Invalid audit interval.");
    return { from_sequence, to_sequence };
  } catch {
    throw new AuditInputError("range");
  }
}
function checkpoint(value: unknown): AuditCheckpoint | null {
  if (value === null) return null;
  const input = object(value),
    signature = text(input.signature);
  bytes(signature, 64);
  return {
    sequence: auditSequence(input.sequence),
    head_hash: hash(input.head_hash),
    signed_at: auditTime(input.signed_at, true),
    signature,
  };
}
function verification(
  value: unknown,
  organization: string,
  range: AuditRangeQuery,
): AuditVerification {
  const input = object(value);
  if (typeof input.valid !== "boolean")
    throw new Error("Invalid audit result.");
  const result: AuditVerification = {
    organization_id: uuid(input.organization_id),
    from_sequence: auditSequence(input.from_sequence),
    to_sequence: auditSequence(input.to_sequence),
    checked_events: auditSequence(input.checked_events, true),
    valid: input.valid,
    failure_sequence: optionalSequence(input.failure_sequence),
    previous_hash: optionalHash(input.previous_hash),
    head_hash: optionalHash(input.head_hash),
    checkpoint: checkpoint(input.checkpoint),
    uncheckpointed_from_sequence: optionalSequence(
      input.uncheckpointed_from_sequence,
    ),
  };
  if (
    result.organization_id !== organization ||
    result.from_sequence !== range.from_sequence ||
    result.to_sequence !== range.to_sequence
  )
    throw new Error("Mismatched audit range.");
  const from = BigInt(result.from_sequence),
    to = BigInt(result.to_sequence);
  if (!result.valid) {
    if (
      result.failure_sequence === null ||
      BigInt(result.failure_sequence) < from ||
      BigInt(result.failure_sequence) > to ||
      BigInt(result.checked_events) !==
        BigInt(result.failure_sequence) - from ||
      result.previous_hash !== null ||
      result.head_hash !== null ||
      result.checkpoint !== null ||
      result.uncheckpointed_from_sequence !== null
    )
      throw new Error("Invalid failed audit result.");
  } else {
    if (
      BigInt(result.checked_events) !== to - from + 1n ||
      result.failure_sequence !== null ||
      result.previous_hash === null ||
      result.head_hash === null ||
      (from === 1n && result.previous_hash !== "0".repeat(64))
    )
      throw new Error("Invalid successful audit result.");
    let uncovered: string | null = range.from_sequence;
    if (result.checkpoint) {
      const sequence = BigInt(result.checkpoint.sequence);
      if (
        sequence < from ||
        sequence > to ||
        (sequence === to && result.checkpoint.head_hash !== result.head_hash)
      )
        throw new Error("Invalid audit checkpoint position.");
      uncovered = sequence === to ? null : String(sequence + 1n);
    }
    if (result.uncheckpointed_from_sequence !== uncovered)
      throw new Error("Invalid audit coverage.");
  }
  return result;
}
export function parseAuditVerification(
  source: string,
  organization: string,
  range: AuditRangeQuery,
): AuditVerification {
  const selected = auditRange(range.from_sequence, range.to_sequence);
  if (encoder.encode(source).length > 4_096)
    throw new Error("Audit result exceeds its limit.");
  return verification(strictJson(source), uuid(organization), selected);
}

export class AuditApi {
  readonly transport: AccountTransport;
  constructor(transport: AccountTransport) {
    this.transport = transport;
  }
  async list(
    organization: string,
    filters = emptyAuditFilters(),
    cursor?: string,
    limit = 50,
  ): Promise<AuditPage> {
    uuid(organization);
    const query = selection({ ...filters }, cursor, limit);
    const reply = await this.transport.request(
      "GET",
      `/api/v1/orgs/${organization}/audit-events?${query.parameters}`,
      {
        maximum: 1_048_576,
        decode: (source) => decodePage(source, organization, query),
      },
    );
    return page(reply.value, organization, query);
  }
  async verify(
    organization: string,
    range: AuditRangeQuery,
  ): Promise<AuditVerification> {
    uuid(organization);
    const selected = auditRange(range.from_sequence, range.to_sequence);
    const reply = await this.transport.request(
      "GET",
      `/api/v1/orgs/${organization}/audit-events/verify?${new URLSearchParams({ ...selected })}`,
      {
        maximum: 4_096,
        decode: (source) =>
          parseAuditVerification(source, organization, selected),
      },
    );
    return verification(reply.value, organization, selected);
  }
}
