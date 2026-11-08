// SPDX-License-Identifier: AGPL-3.0-only
import { bytes, encoded, text } from "./wire.ts";
import type { Method } from "./team.ts";

export interface ProofTransfer {
  keyPair: CryptoKeyPair;
  publicJwk: JsonWebKey;
}

export function canonicalOrigin(origin: string): string {
  const url = new URL(origin);
  if (
    origin !== url.origin ||
    url.protocol !== "https:" ||
    origin.length > 2_048 ||
    !/^[\x21-\x7e]+$/.test(origin)
  )
    throw new Error("A canonical HTTPS deployment origin is required.");
  return origin;
}

export function targetUrl(origin: string, path: string): URL {
  canonicalOrigin(origin);
  const url = new URL(path, origin);
  if (
    url.origin !== origin ||
    url.hash ||
    url.username ||
    url.password ||
    url.href !== origin + path ||
    !path.startsWith("/api/v1/")
  )
    throw new Error("Invalid same-origin API target.");
  return url;
}

export class AccountProofKey {
  #pair: CryptoKeyPair;
  #jwk: JsonWebKey;
  private constructor(pair: CryptoKeyPair, jwk: JsonWebKey) {
    this.#pair = pair;
    this.#jwk = jwk;
  }
  static async create(): Promise<AccountProofKey> {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    return this.adopt({
      keyPair,
      publicJwk: await crypto.subtle.exportKey("jwk", keyPair.publicKey),
    });
  }
  static async adopt(input: ProofTransfer): Promise<AccountProofKey> {
    const { privateKey, publicKey } = input.keyPair;
    if (
      privateKey.type !== "private" ||
      privateKey.extractable ||
      privateKey.algorithm.name !== "ECDSA" ||
      (privateKey.algorithm as EcKeyAlgorithm).namedCurve !== "P-256" ||
      !privateKey.usages.includes("sign") ||
      publicKey.type !== "public" ||
      publicKey.algorithm.name !== "ECDSA" ||
      (publicKey.algorithm as EcKeyAlgorithm).namedCurve !== "P-256"
    )
      throw new Error("Invalid non-extractable browser proof key.");
    const publicJwk = await crypto.subtle.exportKey("jwk", publicKey);
    if (
      input.publicJwk.kty !== "EC" ||
      input.publicJwk.crv !== "P-256" ||
      input.publicJwk.d !== undefined ||
      input.publicJwk.x !== publicJwk.x ||
      input.publicJwk.y !== publicJwk.y
    )
      throw new Error("Mismatched browser proof key.");
    bytes(text(publicJwk.x), 32);
    bytes(text(publicJwk.y), 32);
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      challenge,
    );
    if (
      !(await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        signature,
        challenge,
      ))
    )
      throw new Error("Mismatched browser proof key pair.");
    return new AccountProofKey(input.keyPair, {
      kty: "EC",
      crv: "P-256",
      x: publicJwk.x,
      y: publicJwk.y,
    });
  }
  transfer(): ProofTransfer {
    return { keyPair: this.#pair, publicJwk: { ...this.#jwk } };
  }
  async proof(origin: string, path: string, method: Method, token?: string) {
    const url = targetUrl(origin, path);
    const encoder = new TextEncoder();
    const header = encoded(
      encoder.encode(
        JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: this.#jwk }),
      ),
    );
    const claims: Record<string, string | number> = {
      jti: encoded(crypto.getRandomValues(new Uint8Array(16))),
      htm: method,
      htu: url.origin + url.pathname,
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
