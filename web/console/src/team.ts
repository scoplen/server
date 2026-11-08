// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AccountProfile,
  OrganizationResource,
  OrganizationPage,
  TeamInvitationResource,
  TeamInvitationPage,
  TeamMemberResource,
  TeamMemberPage,
  TeamRole,
  TeamInvitationCreateRequest,
  TeamMemberUpdateRequest,
  TeamAcceptanceReceipt,
  TeamDissolutionReceipt,
  InventoryHostFields,
  InventoryAccessProfileFields,
  InventoryRouteFields,
  InventoryHostGroupFields,
  InventoryHostResource,
  InventoryAccessProfileResource,
  InventoryRouteResource,
  InventoryHostGroupResource,
  GroupFields,
  GroupResource,
  PolicyFields,
  PolicyResource,
} from "./generated/api.ts";
import { object, text, timestamp, uuid } from "./wire.ts";

export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export interface RequestOptions {
  body?: unknown;
  key?: string;
  etag?: string;
  success?: number;
  maximum?: number;
}
export interface ApiResponse {
  value: unknown;
  etag: string | null;
}
export interface AccountTransport {
  readonly origin: string;
  request(
    method: Method,
    path: string,
    options?: RequestOptions,
  ): Promise<ApiResponse>;
}
export class RequestFailure extends Error {
  readonly code: string;
  readonly status: number;
  readonly changed: boolean;
  readonly retryable: boolean;
  readonly requestId: string;
  readonly retryAfter: number;
  constructor(
    code: string,
    status = 0,
    changed = false,
    retryable = false,
    requestId = "",
    retryAfter = 0,
  ) {
    super(code);
    this.code = code;
    this.status = status;
    this.changed = changed;
    this.retryable = retryable;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
  }
}

export type InventoryKind =
  "hosts" | "access-profiles" | "routes" | "host-groups";
export type CollectionKind = InventoryKind | "groups" | "policies";
export interface FieldsByKind {
  hosts: InventoryHostFields;
  "access-profiles": InventoryAccessProfileFields;
  routes: InventoryRouteFields;
  "host-groups": InventoryHostGroupFields;
  groups: GroupFields;
  policies: PolicyFields;
}
export interface ResourcesByKind {
  hosts: InventoryHostResource;
  "access-profiles": InventoryAccessProfileResource;
  routes: InventoryRouteResource;
  "host-groups": InventoryHostGroupResource;
  groups: GroupResource;
  policies: PolicyResource;
}
export type AnyResource = ResourcesByKind[CollectionKind];
export type AnyFields = FieldsByKind[CollectionKind];
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  [extension: string]: unknown;
}
export const teamRoles: TeamRole[] = [
  "administrator",
  "approver",
  "member",
  "owner",
  "security_auditor",
];

export function operationId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let time = BigInt(Date.now());
  if (time < 0n || time > 0xffffffffffffn)
    throw new Error("Clock outside UUID range.");
  for (let index = 5; index >= 0; index--) {
    bytes[index] = Number(time & 255n);
    time >>= 8n;
  }
  bytes[6] = (bytes[6] & 15) | 0x70;
  bytes[8] = (bytes[8] & 63) | 0x80;
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function boundedText(value: unknown, maximum = 16_384, minimum = 0): string {
  const result = text(value);
  const length = new TextEncoder().encode(result).length;
  if (!result.isWellFormed() || length < minimum || length > maximum)
    throw new Error("Invalid response text.");
  return result;
}
function modelText(value: unknown): string {
  const result = boundedText(value);
  if (result.normalize("NFC") !== result)
    throw new Error("Invalid model text.");
  return result;
}
function name(value: unknown): string {
  const result = boundedText(value, 128, 1);
  if (
    /\p{Cc}/u.test(result) ||
    /^\p{White_Space}|\p{White_Space}$/u.test(result)
  )
    throw new Error("Invalid response name.");
  return result;
}
function username(value: unknown): string {
  const result = text(value);
  if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(result))
    throw new Error("Invalid response username.");
  return result;
}
export function strongEtag(value: unknown): string {
  const result = text(value);
  if (result.length > 256 || !/^"[\x21\x23-\x7e]*"$/.test(result))
    throw new Error("Invalid resource version.");
  return result;
}
function resourceTimestamp(value: unknown): string {
  const result = text(value);
  timestamp(result.replace(/\.\d+Z$/, "Z"));
  return result;
}
function resource(value: unknown, etag?: string | null) {
  const input = object(value);
  const result = {
    id: uuid(input.id),
    etag: strongEtag(input.etag),
    created_at: resourceTimestamp(input.created_at),
    updated_at: resourceTimestamp(input.updated_at),
  };
  if (etag !== undefined && etag !== result.etag)
    throw new Error("Mismatched resource version.");
  return { ...result, data: object(input.data) };
}
function array<T>(
  value: unknown,
  parse: (item: unknown) => T,
  maximum = 4_096,
): T[] {
  if (!Array.isArray(value) || value.length > maximum)
    throw new Error("Invalid response array.");
  return value.map(parse);
}
function distinct<T>(values: T[]): T[] {
  if (new Set(values).size !== values.length)
    throw new Error("Repeated response value.");
  return values;
}
function roles(value: unknown, known = true): TeamRole[] {
  const values = distinct(array(value, text, known ? 5 : 32));
  if (
    values.length === 0 ||
    values.some((role) =>
      known
        ? !teamRoles.includes(role as TeamRole)
        : !/^[a-z][a-z0-9_]{0,63}$/.test(role),
    )
  )
    throw new Error("Invalid roles.");
  return values as TeamRole[];
}
export function parseOrganization(
  value: unknown,
  account: string,
  etag?: string | null,
): OrganizationResource {
  const result = resource(value, etag),
    membership = object(result.data.membership);
  if (uuid(membership.account_id) !== account)
    throw new Error("Mismatched membership account.");
  return {
    ...result,
    data: {
      name: name(result.data.name),
      membership: {
        id: uuid(membership.id),
        account_id: account,
        roles: roles(membership.roles, false),
      },
    },
  };
}
export function parseInvitation(
  value: unknown,
  org: string,
  etag?: string | null,
): TeamInvitationResource {
  const result = resource(value, etag),
    input = result.data;
  if (
    uuid(input.organization_id) !== org ||
    !["pending", "accepted", "revoked", "expired", "locked"].includes(
      text(input.status),
    )
  )
    throw new Error("Invalid invitation context.");
  const membership =
    input.status === "accepted"
      ? uuid(input.membership_id)
      : input.membership_id;
  if (input.status !== "accepted" && membership !== null)
    throw new Error("Invalid invitation membership.");
  return {
    ...result,
    data: {
      organization_id: org,
      organization_name: name(input.organization_name),
      recipient_account_id: uuid(input.recipient_account_id),
      recipient_username: username(input.recipient_username),
      roles: roles(input.roles),
      issuer_account_id: uuid(input.issuer_account_id),
      expires_at: resourceTimestamp(input.expires_at),
      status: input.status,
      membership_id: membership,
    },
  } as TeamInvitationResource;
}
export function parseMember(
  value: unknown,
  org: string,
  etag?: string | null,
): TeamMemberResource {
  const result = resource(value, etag),
    input = result.data;
  if (
    uuid(input.organization_id) !== org ||
    !["active", "suspended", "removed"].includes(text(input.status))
  )
    throw new Error("Invalid member context.");
  return {
    ...result,
    data: {
      organization_id: org,
      account_id: uuid(input.account_id),
      username: username(input.username),
      roles: roles(input.roles),
      status: input.status as TeamMemberResource["data"]["status"],
    },
  };
}
export function parsePage<T extends { id: string }>(
  value: unknown,
  parse: (item: unknown) => T,
  cursor?: string,
): Page<T> {
  const input = object(value),
    items = array(input.items, parse, 500);
  let previous = cursor ?? "";
  for (const item of items) {
    if (item.id <= previous) throw new Error("Invalid response ordering.");
    previous = item.id;
  }
  const next = input.next_cursor === null ? null : uuid(input.next_cursor);
  if (next !== null && (items.length === 0 || next !== previous))
    throw new Error("Invalid page continuation.");
  return { items, next_cursor: next };
}
function stringMap(value: unknown): Record<string, string> {
  const entries = Object.entries(object(value));
  if (entries.length > 4_096) throw new Error("Too many map values.");
  return Object.fromEntries(
    entries.map(([key, value]) => [modelText(key), modelText(value)]),
  );
}
function booleanMap(value: unknown): Record<string, true> {
  const entries = Object.entries(object(value));
  if (
    entries.length > 4_096 ||
    entries.some(([key, value]) => {
      uuid(key);
      return value !== true;
    })
  )
    throw new Error("Invalid group map.");
  return Object.fromEntries(entries) as Record<string, true>;
}
function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("Invalid boolean.");
  return value;
}

/** Reject unknown model fields so an editor cannot silently erase an unsupported replacement field. */
export function parseFields<K extends InventoryKind>(
  kind: K,
  value: unknown,
): FieldsByKind[K] {
  const input = object(value);
  const allowed: Record<InventoryKind, string[]> = {
    hosts: [
      "name",
      "address",
      "port",
      "tags",
      "groups",
      "favorite",
      "notes",
      "default_profile",
      "ssh_options",
      "mosh",
    ],
    "access-profiles": [
      "host",
      "name",
      "username",
      "route",
      "terminal_profile",
      "startup_command",
      "agent_forwarding",
    ],
    routes: ["name", "kind", "hops", "proxy", "command", "gateway_network"],
    "host-groups": ["name", "parent", "color", "defaults"],
  };
  if (Object.keys(input).some((key) => !allowed[kind].includes(key)))
    throw new Error("Unsupported inventory field.");
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (["host", "parent", "default_profile", "gateway_network"].includes(key))
      output[key] = uuid(value);
    else if (["tags", "defaults", "ssh_options", "mosh"].includes(key))
      output[key] = stringMap(value);
    else if (key === "groups") output[key] = booleanMap(value);
    else if (key === "hops") output[key] = array(value, uuid, 64);
    else if (key === "route") output[key] = value === 0 ? 0 : uuid(value);
    else if (["favorite", "agent_forwarding"].includes(key))
      output[key] = bool(value);
    else if (["kind", "port"].includes(key)) {
      if (
        typeof value !== "number" ||
        !Number.isSafeInteger(value) ||
        value < 1 ||
        value > (key === "kind" ? 5 : 65_535)
      )
        throw new Error("Invalid numeric field.");
      output[key] = value;
    } else output[key] = modelText(value);
  }
  const required =
    kind === "hosts"
      ? ["name", "address"]
      : kind === "access-profiles"
        ? ["host", "username"]
        : kind === "routes"
          ? ["name", "kind"]
          : ["name"];
  if (required.some((key) => !(key in output) || output[key] === ""))
    throw new Error("Missing inventory field.");
  if (kind === "routes") {
    const expected =
      output.kind === 1
        ? "hops"
        : output.kind === 2 || output.kind === 3
          ? "proxy"
          : output.kind === 4
            ? "command"
            : "gateway_network";
    if (
      !(expected in output) ||
      ["hops", "proxy", "command", "gateway_network"].some(
        (key) => key in output && key !== expected,
      )
    )
      throw new Error("Invalid route fields.");
  }
  return output as FieldsByKind[K];
}
export function parseCollection<K extends CollectionKind>(
  kind: K,
  value: unknown,
  etag?: string | null,
): ResourcesByKind[K] {
  const result = resource(value, etag),
    input = result.data;
  if (kind === "groups") {
    if (!["local", "IdP"].includes(text(input.source)))
      throw new Error("Invalid group source.");
    return {
      ...result,
      data: {
        name: name(input.name),
        members: distinct(array(input.members, uuid)),
        source: input.source,
      },
    } as ResourcesByKind[K];
  }
  if (kind === "policies")
    return {
      ...result,
      data: {
        name: name(input.name),
        source: boundedText(input.source, 65_536, 1),
        enabled: bool(input.enabled),
      },
    } as ResourcesByKind[K];
  if (input.schema !== 1) throw new Error("Unsupported object schema.");
  return {
    ...result,
    data: {
      schema: 1,
      fields: parseFields(kind as InventoryKind, input.fields),
    },
  } as ResourcesByKind[K];
}

export class TeamApi {
  accountId = "";
  readonly transport: AccountTransport;
  constructor(transport: AccountTransport) {
    this.transport = transport;
  }
  async profile(): Promise<AccountProfile> {
    const reply = await this.transport.request("GET", "/api/v1/accounts/me", {
      maximum: 4_096,
    });
    const result = resource(reply.value, reply.etag),
      email = result.data.email;
    if (
      email !== null &&
      (typeof email !== "string" ||
        !email ||
        new TextEncoder().encode(email).length > 320 ||
        /[\p{Cc}\s]/u.test(email))
    )
      throw new Error("Invalid account profile.");
    if (this.accountId && this.accountId !== result.id)
      throw new Error("Account changed.");
    this.accountId = result.id;
    return { ...result, data: { email } };
  }
  async organizations(cursor?: string): Promise<OrganizationPage> {
    const { value } = await this.transport.request(
      "GET",
      pagePath("/api/v1/orgs", cursor),
      { maximum: 2_097_152 },
    );
    return parsePage(
      value,
      (item) => parseOrganization(item, this.accountId),
      cursor,
    );
  }
  async organization(org: string): Promise<OrganizationResource> {
    const reply = await this.transport.request("GET", orgPath(org), {
      maximum: 4_096,
    });
    const result = parseOrganization(reply.value, this.accountId, reply.etag);
    if (result.id !== org) throw new Error("Mismatched organization.");
    return result;
  }
  async createTeam(name: string, key: string): Promise<OrganizationResource> {
    const reply = await this.transport.request("POST", "/api/v1/orgs", {
      body: { data: { name } },
      key,
      success: 201,
      maximum: 4_096,
    });
    return parseOrganization(reply.value, this.accountId, reply.etag);
  }
  async rename(
    org: OrganizationResource,
    name: string,
  ): Promise<OrganizationResource> {
    const reply = await this.transport.request("PATCH", orgPath(org.id), {
      body: { data: { name } },
      etag: org.etag,
      maximum: 4_096,
    });
    const result = parseOrganization(reply.value, this.accountId, reply.etag);
    if (result.id !== org.id) throw new Error("Mismatched organization.");
    return result;
  }
  async invitations(org: string, cursor?: string): Promise<TeamInvitationPage> {
    const { value } = await this.transport.request(
      "GET",
      pagePath(`${orgPath(org)}/invitations`, cursor),
      { maximum: 2_097_152 },
    );
    return parsePage(value, (item) => parseInvitation(item, org), cursor);
  }
  async invitation(org: string, id: string): Promise<TeamInvitationResource> {
    const reply = await this.transport.request("GET", invitationPath(org, id), {
      maximum: 4_096,
    });
    const result = parseInvitation(reply.value, org, reply.etag);
    if (result.id !== id) throw new Error("Mismatched invitation.");
    return result;
  }
  async createInvitation(
    org: string,
    body: TeamInvitationCreateRequest,
    key: string,
  ): Promise<TeamInvitationResource> {
    const reply = await this.transport.request(
      "POST",
      `${orgPath(org)}/invitations`,
      { body, key, success: 201, maximum: 4_096 },
    );
    const result = parseInvitation(reply.value, org, reply.etag);
    if (
      result.id !== body.invitation_id ||
      result.data.recipient_username !== body.recipient_username ||
      [...result.data.roles].sort().join() !== [...body.roles].sort().join()
    )
      throw new Error("Mismatched invitation result.");
    return result;
  }
  async accept(
    org: string,
    invitation: string,
    password: string,
    key: string,
  ): Promise<TeamAcceptanceReceipt> {
    const { value } = await this.transport.request(
      "POST",
      `${invitationPath(org, invitation)}/accept`,
      { body: { password }, key, maximum: 1_024 },
    );
    const input = object(value);
    if (
      uuid(input.organization_id) !== org ||
      uuid(input.invitation_id) !== invitation ||
      uuid(input.account_id) !== this.accountId
    )
      throw new Error("Mismatched acceptance receipt.");
    return {
      organization_id: org,
      invitation_id: invitation,
      account_id: this.accountId,
      membership_id: uuid(input.membership_id),
      accepted_at: resourceTimestamp(input.accepted_at),
    };
  }
  async revoke(org: string, invitation: TeamInvitationResource): Promise<void> {
    await this.transport.request("DELETE", invitationPath(org, invitation.id), {
      etag: invitation.etag,
      success: 204,
    });
  }
  async members(org: string, cursor?: string): Promise<TeamMemberPage> {
    const { value } = await this.transport.request(
      "GET",
      pagePath(`${orgPath(org)}/members`, cursor),
      { maximum: 2_097_152 },
    );
    return parsePage(value, (item) => parseMember(item, org), cursor);
  }
  async updateMember(
    org: string,
    member: TeamMemberResource,
    body: TeamMemberUpdateRequest,
  ): Promise<TeamMemberResource> {
    const reply = await this.transport.request(
      "PATCH",
      `${orgPath(org)}/members/${uuid(member.id)}`,
      { body, etag: member.etag, maximum: 4_096 },
    );
    const result = parseMember(reply.value, org, reply.etag);
    if (
      result.id !== member.id ||
      result.data.account_id !== member.data.account_id
    )
      throw new Error("Mismatched member result.");
    return result;
  }
  async removeMember(
    org: string,
    member: Pick<TeamMemberResource, "id" | "etag">,
  ): Promise<void> {
    await this.transport.request(
      "DELETE",
      `${orgPath(org)}/members/${uuid(member.id)}`,
      { etag: member.etag, success: 204 },
    );
  }
  async dissolve(
    org: OrganizationResource,
    key: string,
  ): Promise<TeamDissolutionReceipt> {
    const { value } = await this.transport.request(
      "POST",
      `${orgPath(org.id)}/dissolve`,
      { body: { organization_id: org.id }, key, etag: org.etag, maximum: 512 },
    );
    const input = object(value);
    if (uuid(input.organization_id) !== org.id)
      throw new Error("Mismatched dissolution receipt.");
    return {
      organization_id: org.id,
      dissolved_at: resourceTimestamp(input.dissolved_at),
    };
  }
  async list<K extends CollectionKind>(
    org: string,
    kind: K,
    cursor?: string,
  ): Promise<Page<ResourcesByKind[K]>> {
    const { value } = await this.transport.request(
      "GET",
      pagePath(`${orgPath(org)}/${kind}`, cursor),
      { maximum: 8_388_608 },
    );
    return parsePage(value, (item) => parseCollection(kind, item), cursor);
  }
  async save<K extends CollectionKind>(
    org: string,
    kind: K,
    fields: FieldsByKind[K],
    original?: ResourcesByKind[K],
    creation?: { id: string; key: string },
  ): Promise<ResourcesByKind[K]> {
    const path = `${orgPath(org)}/${kind}${original ? `/${uuid(original.id)}` : ""}`;
    if (!original && !creation) throw new Error("Create operation is missing.");
    const data = kind === "groups" || kind === "policies" ? fields : { fields };
    const body = original ? { data } : { id: creation!.id, data };
    const reply = await this.transport.request(
      original ? "PUT" : "POST",
      path,
      {
        body,
        etag: original?.etag,
        key: creation?.key,
        success: original ? 200 : 201,
        maximum: kind === "groups" || kind === "policies" ? 262_144 : 2_097_152,
      },
    );
    const result = parseCollection(kind, reply.value, reply.etag);
    if (result.id !== (original?.id ?? creation!.id))
      throw new Error("Mismatched resource result.");
    return result;
  }
  async remove(
    org: string,
    kind: CollectionKind,
    original: AnyResource,
  ): Promise<void> {
    await this.transport.request(
      "DELETE",
      `${orgPath(org)}/${kind}/${uuid(original.id)}`,
      { etag: original.etag, success: 204 },
    );
  }
}

function orgPath(org: string): string {
  return `/api/v1/orgs/${uuid(org)}`;
}
function invitationPath(org: string, invitation: string): string {
  return `${orgPath(org)}/invitations/${uuid(invitation)}`;
}
function pagePath(path: string, cursor?: string): string {
  return `${path}?limit=50${cursor ? `&cursor=${uuid(cursor)}` : ""}`;
}
