// SPDX-License-Identifier: AGPL-3.0-only
import type {
  BrowserAuthTokenResponse,
  OperatorCreationOptions,
  OperatorLoginOptionsResponse,
  OperatorRequestOptions,
  OperatorSetupOptionsResponse,
  PersonalInvitationResponse,
} from "./generated/api.ts";

export function bytes(
  value: string,
  minimum: number,
  maximum = minimum,
): Uint8Array<ArrayBuffer> {
  if (
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw new Error("Invalid encoded response.");
  const raw = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  const result = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  if (
    result.length < minimum ||
    result.length > maximum ||
    encoded(result) !== value
  )
    throw new Error("Invalid encoded response.");
  return result;
}

export function encoded(value: ArrayBuffer | Uint8Array): string {
  const data = value instanceof Uint8Array ? value : new Uint8Array(value);
  return btoa(String.fromCharCode(...data))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid response object.");
  return value as Record<string, unknown>;
}

export function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("Invalid response text.");
  return value;
}

export function uuid(value: unknown): string {
  const result = text(value);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      result,
    )
  )
    throw new Error("Invalid response identifier.");
  return result;
}

export function timestamp(value: unknown): string {
  const result = text(value);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(result) ||
    !Number.isFinite(Date.parse(result)) ||
    new Date(result).toISOString() !== result.replace("Z", ".000Z")
  )
    throw new Error("Invalid response expiry.");
  return result;
}

function positive(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
    throw new Error("Invalid response lifetime.");
  return value;
}

/** Check duplicate names before JSON.parse can discard them, including ignored extensions. */
export function strictJson(source: string): unknown {
  const tokens =
    source.match(/"(?:\\.|[^"\\])*"|[{}[\]:,]|[^\s{}[\]:,]+/g) ?? [];
  let index = 0;
  function value(depth: number): void {
    if (depth > 64) throw new Error("Response nesting is too deep.");
    const token = tokens[index++];
    if (token === "{") {
      const names = new Set<string>();
      if (tokens[index] === "}") {
        index++;
        return;
      }
      for (;;) {
        const name: unknown = JSON.parse(tokens[index++] ?? "");
        if (
          typeof name !== "string" ||
          names.has(name) ||
          tokens[index++] !== ":"
        )
          throw new Error("Ambiguous response object.");
        names.add(name);
        value(depth + 1);
        const separator = tokens[index++];
        if (separator === "}") return;
        if (separator !== ",") throw new Error("Invalid response object.");
      }
    }
    if (token === "[") {
      if (tokens[index] === "]") {
        index++;
        return;
      }
      for (;;) {
        value(depth + 1);
        const separator = tokens[index++];
        if (separator === "]") return;
        if (separator !== ",") throw new Error("Invalid response array.");
      }
    }
    JSON.parse(token ?? "");
  }
  value(0);
  if (index !== tokens.length) throw new Error("Invalid response JSON.");
  return JSON.parse(source) as unknown;
}

export async function jsonResponse(
  response: Response,
  maximum: number,
): Promise<unknown> {
  if (!response.body) throw new Error("The server returned an empty response.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let length = 0;
  let source = "";
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      if (length > maximum)
        throw new Error("The server response exceeds its limit.");
      source += decoder.decode(part.value, { stream: true });
    }
    source += decoder.decode();
    return strictJson(source);
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export function sessionResponse(value: unknown): BrowserAuthTokenResponse {
  const input = object(value);
  const access_token = text(input.access_token);
  if (
    !/^[\x21-\x7E]{1,4096}$/.test(access_token) ||
    input.token_type !== "DPoP" ||
    "refresh_token" in input
  )
    throw new Error("Invalid browser session response.");
  return {
    access_token,
    token_type: "DPoP",
    expires_in: positive(input.expires_in),
    refresh_expires_in: positive(input.refresh_expires_in),
  };
}

export function creationOptions(
  value: unknown,
  origin: string,
): OperatorSetupOptionsResponse {
  const input = object(value),
    publicKey = object(input.public_key),
    rp = object(publicKey.rp),
    user = object(publicKey.user),
    selection = object(publicKey.authenticatorSelection);
  const userId = bytes(text(user.id), 16);
  const hex = Array.from(userId, (part) =>
    part.toString(16).padStart(2, "0"),
  ).join("");
  const operator = uuid(
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
  );
  const algorithms = publicKey.pubKeyCredParams;
  if (
    rp.id !== new URL(origin).hostname ||
    rp.name !== "Scoplen" ||
    user.name !== `operator:${operator}` ||
    user.displayName !== "Deployment operator" ||
    !Array.isArray(algorithms) ||
    algorithms.length !== 1 ||
    object(algorithms[0]).type !== "public-key" ||
    object(algorithms[0]).alg !== -7 ||
    !Array.isArray(publicKey.excludeCredentials) ||
    publicKey.excludeCredentials.length !== 0 ||
    selection.residentKey !== "required" ||
    selection.requireResidentKey !== true ||
    selection.userVerification !== "required" ||
    publicKey.attestation !== "none"
  )
    throw new Error("Invalid passkey creation options.");
  bytes(text(publicKey.challenge), 32);
  const timeout = positive(publicKey.timeout);
  if (timeout < 1_000 || timeout > 300_000 || timeout % 1_000 !== 0)
    throw new Error("Invalid passkey timeout.");
  return {
    ceremony_id: uuid(input.ceremony_id),
    expires_at: timestamp(input.expires_at),
    public_key: publicKey as unknown as OperatorCreationOptions,
  };
}

export function requestOptions(
  value: unknown,
  origin: string,
): OperatorLoginOptionsResponse {
  const input = object(value),
    publicKey = object(input.public_key);
  if (
    publicKey.rpId !== new URL(origin).hostname ||
    publicKey.timeout !== 300_000 ||
    !Array.isArray(publicKey.allowCredentials) ||
    publicKey.allowCredentials.length !== 0 ||
    publicKey.userVerification !== "required"
  )
    throw new Error("Invalid passkey sign-in options.");
  bytes(text(publicKey.challenge), 32);
  return {
    ceremony_id: uuid(input.ceremony_id),
    expires_at: timestamp(input.expires_at),
    public_key: publicKey as unknown as OperatorRequestOptions,
  };
}

export function invitationResponse(
  value: unknown,
  origin: string,
): PersonalInvitationResponse {
  const input = object(value),
    invitation_url = text(input.invitation_url),
    expires_at = timestamp(input.expires_at);
  const prefix = `${origin}/invite#token=`;
  if (!invitation_url.startsWith(prefix))
    throw new Error("Invalid invitation origin.");
  bytes(invitation_url.slice(prefix.length), 32);
  return { invitation_url, expires_at };
}
