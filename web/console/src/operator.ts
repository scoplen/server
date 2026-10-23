// SPDX-License-Identifier: AGPL-3.0-only
import type {
  OperatorSetupFinishRequest,
  OperatorLoginFinishRequest,
  PersonalInvitationResponse,
  BrowserAuthTokenResponse,
} from "./generated/api.ts";
import {
  bytes,
  encoded,
  object,
  uuid,
  jsonResponse,
  sessionResponse,
  creationOptions,
  requestOptions,
  invitationResponse,
} from "./wire.ts";

export type Operation =
  "options" | "setup" | "login" | "refresh" | "invitation";
export class ConsoleFailure extends Error {
  readonly operation: Operation;
  readonly code: string;
  readonly uncertain: boolean;
  readonly retryAfter: number;
  constructor(
    operation: Operation,
    code: string,
    uncertain = false,
    retryAfter = 0,
  ) {
    super(code);
    this.operation = operation;
    this.code = code;
    this.uncertain = uncertain;
    this.retryAfter = retryAfter;
  }
}

function artifact(
  value: ArrayBuffer,
  minimum: number,
  maximum: number,
): string {
  if (value.byteLength < minimum || value.byteLength > maximum)
    throw new Error("The passkey returned an invalid artifact.");
  return encoded(value);
}

export function takeSetupFragment(
  url: URL,
  replace: (path: string) => void,
): string | undefined {
  const fragment = url.hash;
  if (fragment) replace(url.pathname);
  if (url.pathname !== "/setup" || !fragment) return undefined;
  if (!/^#token=[A-Za-z0-9_-]{43}$/.test(fragment))
    throw new Error("invalid setup link");
  const token = fragment.slice(7);
  bytes(token, 32);
  return token;
}

export class BrowserProofKey {
  #pair: CryptoKeyPair;
  #jwk: JsonWebKey;
  private constructor(pair: CryptoKeyPair, jwk: JsonWebKey) {
    this.#pair = pair;
    this.#jwk = jwk;
  }

  static async create(): Promise<BrowserProofKey> {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    if (pair.privateKey.extractable)
      throw new Error("Private proof key must remain non-extractable.");
    const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
    return new BrowserProofKey(pair, {
      kty: "EC",
      crv: "P-256",
      x: publicKey.x,
      y: publicKey.y,
    });
  }

  async proof(origin: string, path: string, token?: string): Promise<string> {
    const encoder = new TextEncoder();
    const header = encoded(
      encoder.encode(
        JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: this.#jwk }),
      ),
    );
    const claims: Record<string, string | number> = {
      jti: encoded(crypto.getRandomValues(new Uint8Array(16))),
      htm: "POST",
      htu: origin + path,
      iat: Math.floor(Date.now() / 1_000),
    };
    if (token)
      claims.ath = encoded(
        await crypto.subtle.digest("SHA-256", encoder.encode(token)),
      );
    const payload = encoded(encoder.encode(JSON.stringify(claims)));
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.#pair.privateKey,
      encoder.encode(`${header}.${payload}`),
    );
    if (signature.byteLength !== 64)
      throw new Error("Invalid browser signature format.");
    return `${header}.${payload}.${encoded(signature)}`;
  }
}

export class OperatorClient {
  #key?: BrowserProofKey;
  #token?: string;
  #expiresAt = 0;
  #refreshing?: Promise<void>;
  #setupToken?: string;
  #setupRecovery: "ready" | "login-required" | "login-failed" = "ready";
  readonly origin: string;

  constructor(origin: string, setupToken?: string) {
    this.origin = origin;
    this.#setupToken = setupToken;
  }
  get canSetup(): boolean {
    return this.#setupToken !== undefined;
  }
  get canReturnToSetup(): boolean {
    return this.canSetup && this.#setupRecovery !== "login-required";
  }
  lock(): void {
    this.#token = undefined;
    this.#key = undefined;
    this.#expiresAt = 0;
  }

  async #request(
    operation: Operation,
    path: string,
    body: unknown,
    success: number,
    limit: number,
    token?: string,
  ): Promise<unknown> {
    if (new URL(this.origin).protocol !== "https:")
      throw new ConsoleFailure(operation, "https_required");
    this.#key ??= await BrowserProofKey.create();
    const proof = await this.#key.proof(this.origin, path, token);
    let result: Response;
    try {
      result = await fetch(this.origin + path, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          DPoP: proof,
          ...(token ? { Authorization: `DPoP ${token}` } : {}),
        },
        body: JSON.stringify(body),
        credentials: "same-origin",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      throw new ConsoleFailure(
        operation,
        "response_lost",
        operation !== "options",
      );
    }
    const expectedType =
      result.status === success
        ? "application/json"
        : "application/problem+json";
    const contentType = result.headers.get("Content-Type")?.split(";")[0];
    let value: unknown;
    try {
      if (contentType !== expectedType)
        throw new Error("Invalid content type.");
      value = await jsonResponse(
        result,
        result.status === success ? limit : 4_096,
      );
    } catch {
      throw new ConsoleFailure(
        operation,
        "invalid_response",
        operation !== "options",
      );
    }
    if (result.status !== success) {
      let problem: Record<string, unknown>;
      try {
        problem = object(value);
      } catch {
        throw new ConsoleFailure(
          operation,
          "invalid_response",
          operation !== "options",
        );
      }
      if (
        problem.status !== result.status ||
        typeof problem.code !== "string" ||
        typeof problem.changed !== "boolean" ||
        typeof problem.retryable !== "boolean"
      )
        throw new ConsoleFailure(
          operation,
          "invalid_response",
          operation !== "options",
        );
      const delay = Number(result.headers.get("Retry-After"));
      throw new ConsoleFailure(
        operation,
        problem.code,
        problem.code === "auth.commit_outcome_unknown",
        Number.isInteger(delay) && delay >= 1 && delay <= 300 ? delay : 0,
      );
    }
    return value;
  }

  async register(): Promise<void> {
    if (!this.#setupToken)
      throw new ConsoleFailure("setup", "setup_link_required");
    if (!this.canReturnToSetup)
      throw new ConsoleFailure("setup", "sign_in_required");
    const options = creationOptions(
      await this.#request(
        "options",
        "/api/v1/auth/operator/setup/options",
        { setup_token: this.#setupToken },
        200,
        4_096,
      ),
      this.origin,
    );
    const wire = options.public_key;
    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { id: wire.rp.id, name: wire.rp.name },
        user: {
          id: bytes(wire.user.id, 16),
          name: wire.user.name,
          displayName: wire.user.displayName,
        },
        challenge: bytes(wire.challenge, 32),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        timeout: wire.timeout,
        excludeCredentials: [],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        attestation: "none",
      },
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      !(credential.response instanceof AuthenticatorAttestationResponse)
    )
      throw new ConsoleFailure("setup", "passkey_unavailable");
    if (Date.now() >= Date.parse(options.expires_at))
      throw new ConsoleFailure("setup", "ceremony_expired");
    const body: OperatorSetupFinishRequest = {
      setup_token: this.#setupToken,
      ceremony_id: options.ceremony_id,
      credential_id: artifact(credential.rawId, 1, 1023),
      client_data_json: artifact(credential.response.clientDataJSON, 1, 4096),
      attestation_object: artifact(
        credential.response.attestationObject,
        1,
        16384,
      ),
    };
    try {
      const result = await this.#request(
        "setup",
        "/api/v1/auth/operator/setup/finish",
        body,
        201,
        256,
      );
      try {
        uuid(object(result).operator_id);
      } catch {
        throw new ConsoleFailure("setup", "invalid_response", true);
      }
    } catch (error) {
      if (error instanceof ConsoleFailure && error.uncertain)
        this.#setupRecovery = "login-required";
      throw error;
    }
    this.#setupToken = undefined;
  }

  async signIn(): Promise<void> {
    try {
      await this.#signIn();
    } catch (error) {
      this.#token = undefined;
      if (this.#setupRecovery === "login-required")
        this.#setupRecovery = "login-failed";
      throw error;
    }
  }

  async #signIn(): Promise<void> {
    const options = requestOptions(
      await this.#request(
        "options",
        "/api/v1/auth/operator/login/options",
        {},
        200,
        4_096,
      ),
      this.origin,
    );
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: bytes(options.public_key.challenge, 32),
        timeout: 300_000,
        rpId: options.public_key.rpId,
        allowCredentials: [],
        userVerification: "required",
      },
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      !(credential.response instanceof AuthenticatorAssertionResponse) ||
      !credential.response.userHandle
    )
      throw new ConsoleFailure("login", "passkey_unavailable");
    if (Date.now() >= Date.parse(options.expires_at))
      throw new ConsoleFailure("login", "ceremony_expired");
    const body: OperatorLoginFinishRequest = {
      ceremony_id: options.ceremony_id,
      credential_id: artifact(credential.rawId, 1, 1023),
      client_data_json: artifact(credential.response.clientDataJSON, 1, 4096),
      authenticator_data: artifact(
        credential.response.authenticatorData,
        37,
        4096,
      ),
      signature: artifact(credential.response.signature, 8, 72),
      user_handle: artifact(credential.response.userHandle, 16, 16),
    };
    this.#accept(
      await this.#request(
        "login",
        "/api/v1/auth/operator/login/finish",
        body,
        200,
        8_192,
      ),
      "login",
    );
    this.#setupToken = undefined;
  }

  #accept(value: unknown, operation: "login" | "refresh"): void {
    let session: BrowserAuthTokenResponse;
    try {
      session = sessionResponse(value);
    } catch {
      throw new ConsoleFailure(operation, "invalid_response", true);
    }
    this.#token = session.access_token;
    this.#expiresAt = Date.now() + Math.min(session.expires_in, 86_400) * 1_000;
  }

  async #accessToken(): Promise<string> {
    if (!this.#token)
      throw new ConsoleFailure("invitation", "sign_in_required");
    if (this.#expiresAt - Date.now() <= 30_000) {
      this.#refreshing ??= navigator.locks
        .request<void>("scoplen-operator-refresh", async () => {
          try {
            this.#accept(
              await this.#request(
                "refresh",
                "/api/v1/auth/refresh",
                {},
                200,
                8_192,
              ),
              "refresh",
            );
          } catch (error) {
            this.lock();
            throw error;
          }
        })
        .finally(() => {
          this.#refreshing = undefined;
        });
      await this.#refreshing;
    }
    if (!this.#token)
      throw new ConsoleFailure("invitation", "sign_in_required");
    return this.#token;
  }

  async invite(): Promise<PersonalInvitationResponse> {
    const token = await this.#accessToken();
    let result: unknown;
    try {
      result = await this.#request(
        "invitation",
        "/api/v1/admin/personal-invitations",
        {},
        201,
        4_096,
        token,
      );
    } catch (error) {
      if (
        error instanceof ConsoleFailure &&
        ["auth.authentication_required", "auth.invalid_dpop_proof"].includes(
          error.code,
        )
      )
        this.lock();
      throw error;
    }
    try {
      return invitationResponse(result, this.origin);
    } catch {
      throw new ConsoleFailure("invitation", "invalid_response", true);
    }
  }
}
