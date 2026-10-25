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
  logoutResponse,
} from "./wire.ts";

export type Operation =
  "options" | "setup" | "login" | "refresh" | "invitation" | "logout";
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
  #generation = 0;
  #activeGeneration = 0;
  #pending: Promise<void> = Promise.resolve();
  #logoutAttempted = false;
  #logoutState: "idle" | "pending" | "failed" | "uncertain" = "idle";
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
  get logoutState(): "idle" | "pending" | "failed" | "uncertain" | "expired" {
    if (
      this.#logoutState !== "pending" &&
      this.#logoutAttempted &&
      Date.now() >= this.#expiresAt
    )
      return "expired";
    return this.#logoutState;
  }
  get logoutExpiresAt(): number {
    return this.#expiresAt;
  }
  lock(): void {
    this.#generation++;
    this.#token = undefined;
    this.#key = undefined;
    this.#expiresAt = 0;
    this.#logoutAttempted = false;
    this.#logoutState = "idle";
  }

  #assertCurrent(
    operation: Operation,
    generation = this.#activeGeneration,
  ): void {
    if (generation !== this.#generation)
      throw new ConsoleFailure(operation, "session_changed");
  }

  #serialize<T>(operation: Operation, run: () => Promise<T>): Promise<T> {
    const generation = this.#generation;
    const result = this.#pending.then(() => {
      this.#assertCurrent(operation, generation);
      this.#activeGeneration = generation;
      return run();
    });
    this.#pending = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async #request(
    operation: Operation,
    path: string,
    body: unknown,
    success: number,
    limit: number,
    token?: string,
  ): Promise<unknown> {
    const generation = this.#activeGeneration;
    this.#assertCurrent(operation, generation);
    if (new URL(this.origin).protocol !== "https:")
      throw new ConsoleFailure(operation, "https_required");
    const key = this.#key ?? (await BrowserProofKey.create());
    this.#assertCurrent(operation, generation);
    this.#key = key;
    const proof = await key.proof(this.origin, path, token);
    this.#assertCurrent(operation, generation);
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
        credentials: operation === "logout" ? "omit" : "same-origin",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      this.#assertCurrent(operation, generation);
      throw new ConsoleFailure(
        operation,
        "response_lost",
        operation !== "options",
      );
    }
    this.#assertCurrent(operation, generation);
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
      this.#assertCurrent(operation, generation);
      throw new ConsoleFailure(
        operation,
        "invalid_response",
        operation !== "options",
      );
    }
    this.#assertCurrent(operation, generation);
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
      if (operation === "logout") {
        const denied =
          [400, 401, 403, 413, 415].includes(result.status) &&
          problem.changed === false &&
          problem.retryable === false &&
          ((result.status === 400 &&
            ["auth.invalid_request", "auth.invalid_dpop_proof"].includes(
              problem.code,
            )) ||
            (result.status === 401 &&
              problem.code === "auth.authentication_required") ||
            (result.status === 403 && problem.code === "policy.denied") ||
            ([413, 415].includes(result.status) &&
              problem.code === "auth.invalid_request"));
        const rate =
          result.status === 429 &&
          problem.code === "auth.rate_limited" &&
          problem.changed === false &&
          problem.retryable === true;
        const storage =
          result.status === 503 &&
          problem.code === "auth.storage_unavailable" &&
          problem.changed === false &&
          problem.retryable === true;
        const unknown =
          result.status === 503 &&
          problem.code === "auth.commit_outcome_unknown" &&
          problem.changed === true &&
          problem.retryable === true;
        if (!denied && !rate && !storage && !unknown)
          throw new ConsoleFailure("logout", "invalid_response", true);
      }
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
    return this.#serialize("setup", () => this.#register());
  }

  async #register(): Promise<void> {
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
    return this.#serialize("login", () => this.#login());
  }

  async #login(): Promise<void> {
    if (this.#logoutAttempted)
      throw new ConsoleFailure("login", "logout_unresolved");
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
    this.#assertCurrent(operation);
    let session: BrowserAuthTokenResponse;
    try {
      session = sessionResponse(value);
    } catch {
      throw new ConsoleFailure(operation, "invalid_response", true);
    }
    this.#token = session.access_token;
    this.#expiresAt = Date.now() + Math.min(session.expires_in, 86_400) * 1_000;
  }

  async #accessToken(operation: Operation = "invitation"): Promise<string> {
    this.#assertCurrent(operation);
    if (!this.#token) throw new ConsoleFailure(operation, "sign_in_required");
    if (this.#expiresAt - Date.now() <= 30_000) {
      this.#refreshing ??= navigator.locks
        .request<void>("scoplen-operator-refresh", async () => {
          this.#assertCurrent(operation);
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
            if (this.#activeGeneration === this.#generation) this.lock();
            throw error;
          }
        })
        .finally(() => {
          this.#refreshing = undefined;
        });
      await this.#refreshing;
    }
    if (!this.#token) throw new ConsoleFailure(operation, "sign_in_required");
    return this.#token;
  }

  async invite(): Promise<PersonalInvitationResponse> {
    return this.#serialize("invitation", () => this.#invite());
  }

  async #invite(): Promise<PersonalInvitationResponse> {
    if (this.#logoutAttempted)
      throw new ConsoleFailure("invitation", "logout_unresolved");
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

  async signOut(): Promise<void> {
    return this.#serialize("logout", async () => {
      const token = this.#logoutAttempted
        ? this.#token
        : await this.#accessToken("logout");
      if (!token || Date.now() >= this.#expiresAt)
        throw new ConsoleFailure("logout", "logout_expired");
      this.#logoutAttempted = true;
      this.#logoutState = "pending";
      try {
        const value = await this.#request(
          "logout",
          "/api/v1/auth/operator/logout",
          {},
          200,
          256,
          token,
        );
        try {
          logoutResponse(value);
        } catch {
          throw new ConsoleFailure("logout", "invalid_response", true);
        }
        this.#assertCurrent("logout");
        this.lock();
      } catch (error) {
        if (this.#activeGeneration === this.#generation)
          this.#logoutState =
            error instanceof ConsoleFailure && error.uncertain
              ? "uncertain"
              : "failed";
        throw error;
      }
    });
  }
}
