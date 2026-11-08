// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AccountBrowserPasswordOptionsResponse,
  AccountBrowserRefreshResponse,
} from "./generated/api.ts";
import { bytes, object, text } from "./wire.ts";

export function passwordOptions(
  value: unknown,
): AccountBrowserPasswordOptionsResponse {
  const input = object(value);
  bytes(text(input.attempt_id), 32);
  bytes(text(input.salt), 16);
  const expires = text(input.expires_at_ms);
  if (
    input.profile !== 1 ||
    !/^[1-9][0-9]{0,19}$/.test(expires) ||
    BigInt(expires) > 18_446_744_073_709_551_615n
  )
    throw new Error("Invalid password options.");
  return {
    profile: 1,
    attempt_id: input.attempt_id as string,
    salt: input.salt as string,
    expires_at_ms: expires,
  };
}

export function accountSession(value: unknown, login = false) {
  const input = object(value);
  const token = text(input.access_token);
  if (
    token.length !== 47 ||
    !token.startsWith("ab1_") ||
    input.token_type !== "DPoP" ||
    input.expires_in !== 600 ||
    typeof input.refresh_expires_in !== "number" ||
    !Number.isSafeInteger(input.refresh_expires_in) ||
    input.refresh_expires_in < 1 ||
    input.refresh_expires_in > 2_592_000 ||
    (login && input.refresh_expires_in !== 2_592_000) ||
    ["refresh_token", "admission_token", "snapshot"].some((key) => key in input)
  )
    throw new Error("Invalid Account browser session.");
  bytes(token.slice(4), 32);
  return {
    access_token: token as `ab1_${string}`,
    token_type: "DPoP" as const,
    expires_in: 600,
    refresh_expires_in: input.refresh_expires_in,
  } satisfies AccountBrowserRefreshResponse;
}
