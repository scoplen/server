// SPDX-License-Identifier: AGPL-3.0-only
import { AccountProofKey, targetUrl } from "./account-proof.ts";
import {
  RequestFailure,
  type ApiResponse,
  type Method,
  type RequestOptions,
} from "./team.ts";
import { jsonResponse, object } from "./wire.ts";

export type AccountOperation =
  "options" | "login" | "refresh" | "logout" | "request";
export class AccountFailure extends RequestFailure {
  readonly operation: AccountOperation;
  constructor(
    operation: AccountOperation,
    code: string,
    status = 0,
    changed = false,
    retryable = false,
    requestId = "",
    retryAfter = 0,
  ) {
    super(code, status, changed, retryable, requestId, retryAfter);
    this.operation = operation;
  }
}

function problem(
  value: unknown,
  status: number,
  requestId: string,
  operation: AccountOperation,
  retryAfter: number,
): AccountFailure {
  const input = object(value);
  if (
    status < 400 ||
    status > 599 ||
    input.status !== status ||
    ["type", "title", "detail", "instance", "code"].some(
      (key) => typeof input[key] !== "string",
    ) ||
    input.instance !== requestId ||
    !/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/.test(String(input.code)) ||
    String(input.code).length > 128 ||
    typeof input.changed !== "boolean" ||
    typeof input.retryable !== "boolean"
  )
    throw new Error("Invalid problem response.");
  if (operation === "logout") {
    const rejected =
      input.changed === false &&
      input.retryable === false &&
      ((status === 400 &&
        ["auth.invalid_request", "auth.invalid_dpop_proof"].includes(
          String(input.code),
        )) ||
        (status === 401 && input.code === "auth.authentication_required") ||
        (status === 403 && input.code === "policy.denied") ||
        ([413, 415].includes(status) && input.code === "auth.invalid_request"));
    const retry =
      input.retryable === true &&
      ((status === 429 &&
        input.code === "auth.rate_limited" &&
        input.changed === false) ||
        (status === 503 &&
          input.code === "auth.storage_unavailable" &&
          input.changed === false) ||
        (status === 503 &&
          input.code === "auth.commit_outcome_unknown" &&
          input.changed === true));
    if (!rejected && !retry)
      throw new Error("Invalid sign-out problem response.");
  }
  return new AccountFailure(
    operation,
    input.code as string,
    status,
    input.changed,
    input.retryable,
    requestId,
    retryAfter,
  );
}

export async function accountFetch({
  origin,
  key,
  method,
  path,
  operation,
  options = {},
  token,
  current = () => {},
}: {
  origin: string;
  key: AccountProofKey;
  method: Method;
  path: string;
  operation: AccountOperation;
  options?: RequestOptions;
  token?: string;
  current?: () => void;
}): Promise<ApiResponse> {
  const url = targetUrl(origin, path);
  current();
  const proof = await key.proof(origin, path, method, token);
  current();
  const changed = method !== "GET" && operation !== "options";
  let response: Response;
  try {
    response = await fetch(url.href, {
      method,
      headers: {
        Accept: "application/json",
        DPoP: proof,
        ...(options.body === undefined
          ? {}
          : { "Content-Type": "application/json" }),
        ...(token ? { Authorization: `DPoP ${token}` } : {}),
        ...(options.key ? { "Idempotency-Key": options.key } : {}),
        ...(options.etag ? { "If-Match": options.etag } : {}),
      },
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials:
        operation === "login" || operation === "refresh"
          ? "same-origin"
          : "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    current();
    throw new AccountFailure(operation, "response_lost", 0, changed);
  }
  try {
    current();
  } catch (error) {
    await response.body?.cancel().catch(() => undefined);
    throw error;
  }
  const success = options.success ?? 200;
  const headerId = response.headers.get("X-Request-ID") ?? "";
  const requestId = /^[A-Za-z0-9._:-]{1,128}$/.test(headerId) ? headerId : "";
  let value: unknown;
  try {
    if (
      response.redirected ||
      !requestId ||
      !/(?:^|,)\s*no-store\s*(?:,|$)/i.test(
        response.headers.get("Cache-Control") ?? "",
      ) ||
      !/(?:^|,)\s*no-cache\s*(?:,|$)/i.test(
        response.headers.get("Pragma") ?? "",
      ) ||
      ![null, "identity"].includes(response.headers.get("Content-Encoding"))
    )
      throw new Error("Invalid response metadata.");
    if (response.status === 204 && success === 204) {
      if (response.body !== null) throw new Error("Unexpected response body.");
    } else {
      const expected =
        response.status === success
          ? "application/json"
          : "application/problem+json";
      const contentType = response.headers.get("Content-Type") ?? "";
      if (
        !new RegExp(
          `^${expected.replace("+", "\\+")}(?:;\\s*charset=utf-8)?$`,
          "i",
        ).test(contentType)
      )
        throw new Error("Invalid response content type.");
      value = await jsonResponse(
        response,
        response.status === success ? (options.maximum ?? 8_192) : 4_096,
      );
    }
  } catch {
    await response.body?.cancel().catch(() => undefined);
    current();
    throw new AccountFailure(
      operation,
      "invalid_response",
      response.status,
      changed,
      false,
      requestId,
    );
  }
  current();
  if (response.status !== success) {
    const delay = Number(response.headers.get("Retry-After"));
    let failure: AccountFailure;
    try {
      failure = problem(
        value,
        response.status,
        requestId,
        operation,
        Number.isInteger(delay) && delay >= 1 && delay <= 300 ? delay : 0,
      );
    } catch {
      throw new AccountFailure(
        operation,
        "invalid_response",
        response.status,
        changed,
        false,
        requestId,
      );
    }
    throw failure;
  }
  return { value, etag: response.headers.get("ETag") };
}
