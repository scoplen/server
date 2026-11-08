// SPDX-License-Identifier: AGPL-3.0-only
import type {
  TeamAcceptanceReceipt,
  TeamInvitationCreateRequest,
  TeamInvitationResource,
  TeamRole,
} from "./generated/api.ts";
import { RequestFailure, TeamApi, operationId } from "./team.ts";
import { encoded, uuid } from "./wire.ts";

export interface InvitationCrypto {
  generate(
    origin: string,
    organization: string,
    invitation: string,
    password: Uint8Array,
    verifier: Uint8Array,
  ): Promise<void>;
  parse(password: Uint8Array): Promise<void>;
}
export interface JoinTarget {
  organization: string;
  invitation: string;
}

export function parseJoinLink(source: string, origin: string): JoinTarget {
  const url = new URL(source);
  if (
    url.origin !== origin ||
    url.username ||
    url.password ||
    url.pathname !== "/join-team" ||
    url.search ||
    !/^#organization=[0-9a-f-]{36}&invitation=[0-9a-f-]{36}$/.test(url.hash)
  )
    throw new Error("Invalid team invitation link.");
  const [organization, invitation] = url.hash
    .slice(1)
    .split("&")
    .map((part) => part.split("=")[1]);
  return { organization: uuid(organization), invitation: uuid(invitation) };
}

export function takeJoinFragment(
  url: URL,
  replace: (path: string) => void,
): JoinTarget | undefined {
  if (url.pathname !== "/join-team") return undefined;
  if (url.hash) replace(url.pathname);
  return parseJoinLink(url.href, url.origin);
}

/** Secret-bearing state is deliberately owned here, never in workspace resources or UI event state. */
export class InvitationOperation {
  readonly kind: "create" | "accept";
  readonly origin: string;
  readonly account: string;
  readonly organization: string;
  readonly invitation: string;
  readonly key: string;
  readonly deadline: number;
  readonly recipient: string;
  #password: Uint8Array;
  #verifier?: Uint8Array;
  #createPayload?: string;
  #state:
    "ready" | "pending" | "failed" | "uncertain" | "confirmed" | "disposed" =
    "ready";
  #result?: TeamInvitationResource | TeamAcceptanceReceipt;

  private constructor(
    api: TeamApi,
    kind: "create" | "accept",
    org: string,
    invitation: string,
    password: Uint8Array,
    recipient = "",
  ) {
    this.kind = kind;
    this.origin = api.transport.origin;
    this.account = api.accountId;
    this.organization = uuid(org);
    this.invitation = uuid(invitation);
    this.key = operationId();
    this.deadline = Date.now() + 86_400_000;
    this.#password = password;
    this.recipient = recipient;
  }
  static async create(
    api: TeamApi,
    shared: InvitationCrypto,
    org: string,
    recipient: string,
    roles: TeamRole[],
  ): Promise<InvitationOperation> {
    const password = new Uint8Array(8),
      verifier = new Uint8Array(32);
    const invitation = operationId();
    try {
      await shared.generate(
        api.transport.origin,
        org,
        invitation,
        password,
        verifier,
      );
      const result = new InvitationOperation(
        api,
        "create",
        org,
        invitation,
        password,
        recipient,
      );
      result.#verifier = verifier;
      const payload: TeamInvitationCreateRequest = {
        invitation_id: invitation,
        recipient_username: recipient,
        roles: [...roles].sort(),
        password_verifier: encoded(verifier),
      };
      result.#createPayload = JSON.stringify(payload);
      return result;
    } catch {
      password.fill(0);
      verifier.fill(0);
      throw new RequestFailure("invitation_preparation_failed");
    }
  }
  static async accept(
    api: TeamApi,
    shared: InvitationCrypto,
    target: JoinTarget,
    input: string,
  ): Promise<InvitationOperation> {
    const password = new TextEncoder().encode(input);
    try {
      await shared.parse(password);
      return new InvitationOperation(
        api,
        "accept",
        target.organization,
        target.invitation,
        password,
      );
    } catch {
      password.fill(0);
      throw new RequestFailure("invalid_invitation_password");
    }
  }
  get state() {
    return this.#state;
  }
  get result() {
    return this.#result;
  }
  get canRetry() {
    return (
      this.#state !== "disposed" &&
      this.#state !== "pending" &&
      this.#state !== "confirmed" &&
      Date.now() < this.deadline
    );
  }
  get hasSecret() {
    return this.#state !== "disposed";
  }
  get link(): string {
    return `${this.origin}/join-team#organization=${this.organization}&invitation=${this.invitation}`;
  }
  revealPassword(): string {
    if (this.kind !== "create" || this.#state !== "confirmed")
      throw new Error("Password is unavailable before confirmation.");
    return new TextDecoder("utf-8", { fatal: true }).decode(this.#password);
  }
  async submit(api: TeamApi): Promise<void> {
    if (
      !this.canRetry ||
      api.transport.origin !== this.origin ||
      api.accountId !== this.account
    )
      throw new Error("Original invitation operation is unavailable.");
    this.#state = "pending";
    try {
      const result =
        this.kind === "create"
          ? await api.createInvitation(
              this.organization,
              JSON.parse(this.#createPayload!) as TeamInvitationCreateRequest,
              this.key,
            )
          : await api.accept(
              this.organization,
              this.invitation,
              new TextDecoder("utf-8", { fatal: true }).decode(this.#password),
              this.key,
            );
      if (!this.hasSecret) return;
      this.#result = result;
      this.#state = "confirmed";
    } catch (error) {
      if (this.hasSecret)
        this.#state =
          !(error instanceof RequestFailure) || error.changed
            ? "uncertain"
            : "failed";
      throw error;
    }
  }
  dispose(): void {
    this.#password.fill(0);
    this.#verifier?.fill(0);
    this.#createPayload = undefined;
    this.#result = undefined;
    this.#state = "disposed";
  }
  toJSON(): never {
    throw new Error("Invitation operations cannot be serialized.");
  }
}
