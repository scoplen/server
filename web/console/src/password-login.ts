// SPDX-License-Identifier: AGPL-3.0-only
import type {
  AccountBrowserPasswordLoginRequest,
  AccountBrowserPasswordOptionsRequest,
} from "./generated/api.ts";
import { AccountProofKey, canonicalOrigin } from "./account-proof.ts";
import { AccountFailure, accountFetch } from "./account-http.ts";
import { accountSession, passwordOptions } from "./account-wire.ts";
import type { PasswordLoginResult } from "./account.ts";
import { bytes, encoded } from "./wire.ts";

export type PasswordDerivation = (
  origin: string,
  username: string,
  profile: number,
  salt: Uint8Array,
  password: Uint8Array,
  output: Uint8Array,
) => Promise<void>;

/** Runs inside a one-use Worker. Only its browser session and non-extractable key leave it. */
export async function performPasswordLogin(
  origin: string,
  username: string,
  password: Uint8Array,
  derive: PasswordDerivation,
): Promise<PasswordLoginResult> {
  const auth = new Uint8Array(32);
  try {
    canonicalOrigin(origin);
    if (
      !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username) ||
      password.length > 2_048
    )
      throw new AccountFailure("options", "invalid_password_input");
    const key = await AccountProofKey.create();
    const optionsReply = await accountFetch({
      origin,
      key,
      method: "POST",
      path: "/api/v1/auth/accounts/browser/password/options",
      operation: "options",
      options: {
        body: { username } satisfies AccountBrowserPasswordOptionsRequest,
        maximum: 1_024,
      },
    });
    let options: ReturnType<typeof passwordOptions>;
    try {
      options = passwordOptions(optionsReply.value);
    } catch {
      throw new AccountFailure("options", "invalid_response", 200);
    }
    const fresh = () => {
      if (BigInt(options.expires_at_ms) <= BigInt(Date.now()))
        throw new AccountFailure("login", "password_attempt_expired");
    };
    fresh();
    try {
      await derive(
        origin,
        username,
        options.profile,
        bytes(options.salt, 16),
        password,
        auth,
      );
    } catch {
      throw new AccountFailure("login", "password_derivation_failed");
    }
    fresh();
    const startedAt = Date.now();
    const result = await accountFetch({
      origin,
      key,
      method: "POST",
      path: "/api/v1/auth/accounts/browser/password/login",
      operation: "login",
      options: {
        body: {
          attempt_id: options.attempt_id,
          auth_secret: encoded(auth),
        } satisfies AccountBrowserPasswordLoginRequest,
        maximum: 8_192,
      },
    });
    try {
      return {
        ...key.transfer(),
        session: accountSession(result.value, true),
        startedAt,
      };
    } catch {
      throw new AccountFailure("login", "invalid_response", 200, true);
    }
  } finally {
    password.fill(0);
    auth.fill(0);
  }
}
