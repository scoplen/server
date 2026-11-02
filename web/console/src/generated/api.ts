// Source: https://raw.githubusercontent.com/scoplen/proto/328f16d66851846e6e8ea17b5c4529e08481f1f4/crates/scoplen-api/openapi/types.ts
// SPDX-License-Identifier: Apache-2.0
// Generated from v1.yaml by the Scoplen OpenAPI generator.

export interface components {
  schemas: {
    UserCaCreateRequest: UserCaCreateRequest;
    UserCaResource: UserCaResource;
    UserCaPage: UserCaPage;
    GroupSource: GroupSource;
    GroupFields: GroupFields;
    GroupCreateRequest: GroupCreateRequest;
    GroupReplaceRequest: GroupReplaceRequest;
    GroupResource: GroupResource;
    GroupPage: GroupPage;
    PolicyFields: PolicyFields;
    PolicyCreateRequest: PolicyCreateRequest;
    PolicyReplaceRequest: PolicyReplaceRequest;
    PolicyResource: PolicyResource;
    PolicyPage: PolicyPage;
    SimpleRuleSelector: SimpleRuleSelector;
    SimpleRuleConnect: SimpleRuleConnect;
    SimpleRuleInput: SimpleRuleInput;
    GroupPolicyBodyTooLargeProblem: GroupPolicyBodyTooLargeProblem;
    InventorySnippetVariable: InventorySnippetVariable;
    InventoryBodyTooLargeProblem: InventoryBodyTooLargeProblem;
    InventoryHostFields: InventoryHostFields;
    InventoryHostReadFields: InventoryHostReadFields;
    InventoryHostCreateRequest: InventoryHostCreateRequest;
    InventoryHostReplaceRequest: InventoryHostReplaceRequest;
    InventoryHostResource: InventoryHostResource;
    InventoryHostPage: InventoryHostPage;
    InventoryAccessProfileFields: InventoryAccessProfileFields;
    InventoryAccessProfileReadFields: InventoryAccessProfileReadFields;
    InventoryAccessProfileCreateRequest: InventoryAccessProfileCreateRequest;
    InventoryAccessProfileReplaceRequest: InventoryAccessProfileReplaceRequest;
    InventoryAccessProfileResource: InventoryAccessProfileResource;
    InventoryAccessProfilePage: InventoryAccessProfilePage;
    InventoryRouteFields: InventoryRouteFields;
    InventoryRouteReadFields: InventoryRouteReadFields;
    InventoryRouteCreateRequest: InventoryRouteCreateRequest;
    InventoryRouteReplaceRequest: InventoryRouteReplaceRequest;
    InventoryRouteResource: InventoryRouteResource;
    InventoryRoutePage: InventoryRoutePage;
    InventoryHostGroupFields: InventoryHostGroupFields;
    InventoryHostGroupReadFields: InventoryHostGroupReadFields;
    InventoryHostGroupCreateRequest: InventoryHostGroupCreateRequest;
    InventoryHostGroupReplaceRequest: InventoryHostGroupReplaceRequest;
    InventoryHostGroupResource: InventoryHostGroupResource;
    InventoryHostGroupPage: InventoryHostGroupPage;
    InventoryTrustRecordFields: InventoryTrustRecordFields;
    InventoryTrustRecordReadFields: InventoryTrustRecordReadFields;
    InventoryTrustRecordCreateRequest: InventoryTrustRecordCreateRequest;
    InventoryTrustRecordReplaceRequest: InventoryTrustRecordReplaceRequest;
    InventoryTrustRecordResource: InventoryTrustRecordResource;
    InventoryTrustRecordPage: InventoryTrustRecordPage;
    InventorySnippetFields: InventorySnippetFields;
    InventorySnippetReadFields: InventorySnippetReadFields;
    InventorySnippetCreateRequest: InventorySnippetCreateRequest;
    InventorySnippetReplaceRequest: InventorySnippetReplaceRequest;
    InventorySnippetResource: InventorySnippetResource;
    InventorySnippetPage: InventorySnippetPage;
    InventoryGatewayNetworkFields: InventoryGatewayNetworkFields;
    InventoryGatewayNetworkReadFields: InventoryGatewayNetworkReadFields;
    InventoryGatewayNetworkCreateRequest: InventoryGatewayNetworkCreateRequest;
    InventoryGatewayNetworkReplaceRequest: InventoryGatewayNetworkReplaceRequest;
    InventoryGatewayNetworkResource: InventoryGatewayNetworkResource;
    InventoryGatewayNetworkPage: InventoryGatewayNetworkPage;
    TeamRole: TeamRole;
    TeamInvitationStatus: TeamInvitationStatus;
    TeamMemberStatus: TeamMemberStatus;
    TeamInvitationCreateRequest: TeamInvitationCreateRequest;
    TeamInvitationAcceptRequest: TeamInvitationAcceptRequest;
    TeamInvitationResource: TeamInvitationResource;
    TeamInvitationPage: TeamInvitationPage;
    TeamMemberUpdateRequest: TeamMemberUpdateRequest;
    TeamMemberResource: TeamMemberResource;
    TeamMemberPage: TeamMemberPage;
    TeamAcceptanceReceipt: TeamAcceptanceReceipt;
    TeamDissolveRequest: TeamDissolveRequest;
    TeamDissolutionReceipt: TeamDissolutionReceipt;
    TeamInvitationDeniedProblem: TeamInvitationDeniedProblem;
    TeamBodyTooLargeProblem: TeamBodyTooLargeProblem;
    OrganizationCreateRequest: OrganizationCreateRequest;
    OrganizationResource: OrganizationResource;
    OrganizationMembership: OrganizationMembership;
    OrganizationPage: OrganizationPage;
    OrganizationInvalidRequestProblem: OrganizationInvalidRequestProblem;
    OrganizationContentTypeProblem: OrganizationContentTypeProblem;
    OrganizationAuthenticationRequiredProblem: OrganizationAuthenticationRequiredProblem;
    OrganizationDeniedProblem: OrganizationDeniedProblem;
    OrganizationNotFoundProblem: OrganizationNotFoundProblem;
    OrganizationConflictProblem: OrganizationConflictProblem;
    OrganizationPreconditionFailedProblem: OrganizationPreconditionFailedProblem;
    OrganizationPreconditionRequiredProblem: OrganizationPreconditionRequiredProblem;
    OrganizationStorageUnavailableProblem: OrganizationStorageUnavailableProblem;
    OrganizationCommitOutcomeUnknownProblem: OrganizationCommitOutcomeUnknownProblem;
    OrganizationUpdateCommitOutcomeUnknownProblem: OrganizationUpdateCommitOutcomeUnknownProblem;
    Resource: Resource;
    ResourcePage: ResourcePage;
    ProblemDetails: ProblemDetails;
    AuthChallengeRequest: AuthChallengeRequest;
    AuthChallengeResponse: AuthChallengeResponse;
    AuthDeviceRequest: AuthDeviceRequest;
    AuthTokenResponse: AuthTokenResponse;
    AuthRefreshRequest: AuthRefreshRequest;
    BrowserAuthRefreshRequest: BrowserAuthRefreshRequest;
    BrowserAuthTokenResponse: BrowserAuthTokenResponse;
    AuthJwk: AuthJwk;
    AuthJwks: AuthJwks;
    OperatorSetupOptionsRequest: OperatorSetupOptionsRequest;
    OperatorSetupFinishRequest: OperatorSetupFinishRequest;
    OperatorLoginOptionsRequest: OperatorLoginOptionsRequest;
    OperatorLoginFinishRequest: OperatorLoginFinishRequest;
    OperatorLogoutRequest: OperatorLogoutRequest;
    OperatorSetupOptionsResponse: OperatorSetupOptionsResponse;
    OperatorLoginOptionsResponse: OperatorLoginOptionsResponse;
    OperatorSetupFinishResponse: OperatorSetupFinishResponse;
    OperatorLogoutResponse: OperatorLogoutResponse;
    OperatorCreationOptions: OperatorCreationOptions;
    OperatorRequestOptions: OperatorRequestOptions;
    OperatorInvalidRequestProblem: OperatorInvalidRequestProblem;
    OperatorInvalidDpopProblem: OperatorInvalidDpopProblem;
    OperatorOriginDeniedProblem: OperatorOriginDeniedProblem;
    OperatorBodyTooLargeProblem: OperatorBodyTooLargeProblem;
    OperatorContentTypeProblem: OperatorContentTypeProblem;
    OperatorLogoutAuthenticationRequiredProblem: OperatorLogoutAuthenticationRequiredProblem;
    OperatorLogoutCommitOutcomeUnknownProblem: OperatorLogoutCommitOutcomeUnknownProblem;
    OperatorLogoutStorageFailureProblem: OperatorLogoutStorageFailureProblem;
    AuthRateLimitedProblem: AuthRateLimitedProblem;
    AuthAuthenticationRequiredProblem: AuthAuthenticationRequiredProblem;
    AuthStorageUnavailableProblem: AuthStorageUnavailableProblem;
    AuthCommitOutcomeUnknownProblem: AuthCommitOutcomeUnknownProblem;
    GatewayTicketRequest: GatewayTicketRequest;
    GatewayEdgeAddress: GatewayEdgeAddress;
    GatewayTicketResponse: GatewayTicketResponse;
    ListQuery: ListQuery;
    WriteRequest: WriteRequest;
    DecisionRequest: DecisionRequest;
    PolicyEvaluationRequest: PolicyEvaluationRequest;
    PolicyEvaluationResponse: PolicyEvaluationResponse;
    CertificateRequest: CertificateRequest;
    CertificateHostRequest: CertificateHostRequest;
    CertificateHostGroupRequest: CertificateHostGroupRequest;
    CertificateIssuanceResponse: CertificateIssuanceResponse;
    AccountProfile: AccountProfile;
    AccountDeviceStatements: AccountDeviceStatements;
    AccountRequestChallengeRequest: AccountRequestChallengeRequest;
    AccountRequestChallengeResponse: AccountRequestChallengeResponse;
    AccountPasswordOptionsRequest: AccountPasswordOptionsRequest;
    AccountPasswordOptionsResponse: AccountPasswordOptionsResponse;
    AccountPasswordLoginRequest: AccountPasswordLoginRequest;
    AccountPasswordLoginResponse: AccountPasswordLoginResponse;
    AccountRegistrationRequest: AccountRegistrationRequest;
    AccountDeviceAdmissionRequest: AccountDeviceAdmissionRequest;
    AccountCommittedConfirmation: AccountCommittedConfirmation;
    AccountEntryInvalidRequestProblem: AccountEntryInvalidRequestProblem;
    AccountEntryAuthenticationRequiredProblem: AccountEntryAuthenticationRequiredProblem;
    AccountEntryPolicyDeniedProblem: AccountEntryPolicyDeniedProblem;
    AccountEntryMediaTypeProblem: AccountEntryMediaTypeProblem;
    AccountEntryRateLimitedProblem: AccountEntryRateLimitedProblem;
    AccountEntryRegistrationDeniedProblem: AccountEntryRegistrationDeniedProblem;
    AccountEntryAdmissionConflictProblem: AccountEntryAdmissionConflictProblem;
    AccountEntryBodyTooLargeProblem: AccountEntryBodyTooLargeProblem;
    AccountEntryStorageUnavailableProblem: AccountEntryStorageUnavailableProblem;
    Account: Resource;
    Device: Resource;
    Organization: Resource;
    IdentityProvider: Resource;
    ServicePrincipal: Resource;
    InventoryImport: Resource;
    Role: Resource;
    Grant: Resource;
    AccessRequest: Resource;
    AccessDecision: Resource;
    Certificate: Resource;
    Gateway: Resource;
    JoinToken: Resource;
    Credential: Resource;
    HostAgent: Resource;
    Session: Resource;
    Recording: Resource;
    AuditEvent: Resource;
    AuditExport: Resource;
    Integration: Resource;
  };
}

export interface Resource {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: Record<string, unknown>;
}
export interface ResourcePage { items: Resource[]; next_cursor: string | null; }
// BEGIN GENERATED AccountProfile
export interface AccountProfile {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: AccountProfileData;
  [extension: string]: unknown;
}

export interface AccountProfileData {
  email: string | null;
  [extension: string]: unknown;
}
// END GENERATED AccountProfile
// BEGIN GENERATED AccountDeviceStatements
/** Complete JSON <=6291456 bytes; decoded statements total <=4194304 bytes. */
export interface AccountDeviceStatements {
  account_id: string;
  /** Canonical unpadded base64url, 1..65536 decoded bytes each, strictly ordered by decoded bytes. */
  certificates: string[];
  /** Same bounds/order as certificates; consumers verify every account signature before use. */
  revocations: string[];
  [extension: string]: unknown;
}
// END GENERATED AccountDeviceStatements
// BEGIN GENERATED ProblemDetails
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  code: string;
  /** False guarantees no business-state mutation from the failed operation; true means a mutation occurred or cannot be ruled out, not that success was established. Admission counters and failure-audit records are not business-state mutations. */
  changed: boolean;
  /** Whether the same request may safely be retried; false forbids automatic replay. */
  retryable: boolean;
  [extension: string]: unknown;
}
// END GENERATED ProblemDetails
// BEGIN GENERATED Authentication
export interface AuthChallengeRequest {
  device_id: string;
}

export interface AuthChallengeResponse {
  nonce: string;
  server_time: string;
  [extension: string]: unknown;
}

export interface AuthDeviceRequest {
  device_id: string;
  nonce: string;
  signature: string;
}

export interface AuthRefreshRequest {
  refresh_token: string;
}

export type BrowserAuthRefreshRequest = Record<string, never>;

export interface AuthTokenResponse {
  access_token: string;
  token_type: "DPoP";
  expires_in: number;
  refresh_token: string;
  refresh_expires_in: number;
  [extension: string]: unknown;
}

export interface BrowserAuthTokenResponse {
  access_token: string;
  token_type: "DPoP";
  expires_in: number;
  refresh_expires_in: number;
  refresh_token?: never;
  [extension: string]: unknown;
}

export type AuthRateLimitedProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 429;
  code: "auth.rate_limited";
  changed: false;
  retryable: true;
};

export type AuthAuthenticationRequiredProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 401;
  code: "auth.authentication_required";
  changed: boolean;
  retryable: false;
};

export type AuthStorageUnavailableProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 503;
  code: "auth.storage_unavailable";
  changed: false;
  retryable: true;
};

export type AuthCommitOutcomeUnknownProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & {
  status: 503;
  code: "auth.commit_outcome_unknown";
  changed: true;
  retryable: false;
};

export interface AuthJwk {
  kty: "OKP";
  crv: "Ed25519";
  /** Canonical unpadded base64url, exactly 32 decoded bytes. */
  x: string;
  /** 1..128 ASCII letters, digits, dots, hyphens, or underscores. */
  kid: string;
  alg: "Ed25519";
  use: "sig";
  d?: never;
  [extension: string]: unknown;
}

export interface AuthJwks {
  /** One or two distinct kid values; the complete document is at most 4096 bytes. */
  keys: [AuthJwk] | [AuthJwk, AuthJwk];
  [extension: string]: unknown;
}

export interface AuthRateLimitHeaders {
  /** Decimal 1..300 seconds; RateLimit.t equals this delay. */
  "Retry-After": string;
  "RateLimit-Policy": '"authentication";q=30;w=60';
  RateLimit: string;
  "Cache-Control": "no-store";
  Pragma: "no-cache";
}

export type AuthStorageFailureProblem = AuthStorageUnavailableProblem | AuthCommitOutcomeUnknownProblem;
// END GENERATED Authentication
// BEGIN GENERATED GatewayTicket
export interface GatewayTicketRequest {
  host: string;
  remote_user: string;
  ssh_public_key: string;
}

export interface GatewayEdgeAddress {
  host: string;
  port: number;
  [extension: string]: unknown;
}

export interface GatewayTicketResponse {
  ticket: string;
  edge_addresses: GatewayEdgeAddress[];
  gateway_host_ca_public_key: string;
  [extension: string]: unknown;
}
// END GENERATED GatewayTicket
export interface ListQuery { limit?: number; cursor?: string; filter?: string; sort?: string; }
export interface WriteRequest { data: Record<string, unknown>; }
export interface DecisionRequest { decision: "approve" | "deny"; reason?: string; }
export interface PolicyEvaluationRequest { action: string; resource: Record<string, unknown>; context: Record<string, unknown>; }
export interface PolicyEvaluationResponse { decision: "allow" | "deny"; policies: string[]; }
// BEGIN GENERATED CertificateRequest
export interface CertificateHostRequest {
  public_key: string;
  hosts: string[];
  host_groups?: never;
  remote_user: string;
  ttl_seconds: number;
}

export interface CertificateHostGroupRequest {
  public_key: string;
  host_groups: string[];
  hosts?: never;
  remote_user: string;
  ttl_seconds: number;
}

export type CertificateRequest = CertificateHostRequest | CertificateHostGroupRequest;
// END GENERATED CertificateRequest
// BEGIN GENERATED CertificateIssuanceResponse
export interface CertificateIssuanceResponse {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: CertificateIssuanceData;
  [extension: string]: unknown;
}

export interface CertificateIssuanceData {
  certificate: string;
  [extension: string]: unknown;
}
// END GENERATED CertificateIssuanceResponse

export interface paths {
  [path: string]: {
    get?: unknown; post?: unknown; put?: unknown; patch?: unknown; delete?: unknown;
  };
}
// BEGIN GENERATED OperatorAuthentication
export interface OperatorSetupOptionsRequest {
  /** Canonical unpadded base64url, 32..32 decoded bytes; no aliases or unused nonzero pad bits. */
  setup_token: string;
}

export interface OperatorSetupFinishRequest {
  /** Canonical unpadded base64url, 32..32 decoded bytes; no aliases or unused nonzero pad bits. */
  setup_token: string;
  ceremony_id: string;
  /** Canonical unpadded base64url, 1..1023 decoded bytes; no aliases or unused nonzero pad bits. */
  credential_id: string;
  /** Canonical unpadded base64url, 1..4096 decoded bytes; no aliases or unused nonzero pad bits. */
  client_data_json: string;
  /** Canonical unpadded base64url, 1..16384 decoded bytes; no aliases or unused nonzero pad bits. */
  attestation_object: string;
}

export type OperatorLoginOptionsRequest = Record<string, never>;

export interface OperatorLoginFinishRequest {
  ceremony_id: string;
  /** Canonical unpadded base64url, 1..1023 decoded bytes; no aliases or unused nonzero pad bits. */
  credential_id: string;
  /** Canonical unpadded base64url, 1..4096 decoded bytes; no aliases or unused nonzero pad bits. */
  client_data_json: string;
  /** Canonical unpadded base64url, 37..4096 decoded bytes; no aliases or unused nonzero pad bits. */
  authenticator_data: string;
  /** Canonical unpadded base64url, 8..72 decoded bytes; no aliases or unused nonzero pad bits. */
  signature: string;
  /** Canonical unpadded base64url, 16..16 decoded bytes; no aliases or unused nonzero pad bits. */
  user_handle: string;
}

export interface OperatorSetupOptionsResponse {
  ceremony_id: string;
  /** Valid Gregorian UTC calendar instant, exactly whole-second precision. */
  expires_at: string;
  public_key: OperatorCreationOptions;
  [extension: string]: unknown;
}

export interface OperatorLoginOptionsResponse {
  ceremony_id: string;
  /** Valid Gregorian UTC calendar instant, exactly whole-second precision. */
  expires_at: string;
  public_key: OperatorRequestOptions;
  [extension: string]: unknown;
}

export interface OperatorSetupFinishResponse {
  operator_id: string;
  [extension: string]: unknown;
}

export interface OperatorCreationOptions {
  rp: { id: string; name: "Scoplen"; [extension: string]: unknown; };
  user: { id: string; name: string; displayName: "Deployment operator"; [extension: string]: unknown; };
  /** Canonical unpadded base64url, 32..32 decoded bytes; no aliases or unused nonzero pad bits. */
  challenge: string;
  pubKeyCredParams: Array<{ type: "public-key"; alg: -7; [extension: string]: unknown; }>;
  timeout: number;
  excludeCredentials: [];
  authenticatorSelection: { residentKey: "required"; requireResidentKey: true; userVerification: "required"; [extension: string]: unknown; };
  attestation: "none";
  [extension: string]: unknown;
}

export interface OperatorRequestOptions {
  /** Canonical unpadded base64url, 32..32 decoded bytes; no aliases or unused nonzero pad bits. */
  challenge: string;
  timeout: 300000;
  /** Configured canonical lowercase DNS RP host; no IP literal, scheme, port or trailing dot. */
  rpId: string;
  allowCredentials: [];
  userVerification: "required";
  [extension: string]: unknown;
}

export type OperatorLogoutRequest = Record<string, never>;

export interface OperatorLogoutResponse {
  revoked: true;
}

export type OperatorInvalidRequestProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 400; code: "auth.invalid_request"; changed: false; retryable: false; };

export type OperatorInvalidDpopProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 400; code: "auth.invalid_dpop_proof"; changed: false; retryable: false; };

export type OperatorOriginDeniedProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 403; code: "policy.denied"; changed: false; retryable: false; };

export type OperatorBodyTooLargeProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 413; code: "auth.invalid_request"; changed: false; retryable: false; };

export type OperatorContentTypeProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 415; code: "auth.invalid_request"; changed: false; retryable: false; };

export type OperatorLogoutAuthenticationRequiredProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 401; code: "auth.authentication_required"; changed: false; retryable: false; };

export type OperatorLogoutCommitOutcomeUnknownProblem = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & { status: 503; code: "auth.commit_outcome_unknown"; changed: true; retryable: true; };

export type OperatorLogoutStorageFailureProblem = AuthStorageUnavailableProblem | OperatorLogoutCommitOutcomeUnknownProblem;
// END GENERATED OperatorAuthentication

// BEGIN GENERATED AccountAdmission
export interface AccountRequestChallengeRequest {
  kind: "register" | "admit";
  intent: "submit" | "confirm";
  operation_id: string;
  device_id: string;
}

export interface AccountRequestChallengeResponse {
  attempt_id: string;
  nonce: string;
  expires_at_ms: string;
  [extension: string]: unknown;
}

export interface AccountPasswordOptionsRequest {
  username: string;
}

export interface AccountPasswordOptionsResponse {
  attempt_id: string;
  profile: 1;
  salt: string;
  expires_at_ms: string;
  [extension: string]: unknown;
}

export interface AccountPasswordLoginRequest {
  attempt_id: string;
  auth_secret: string;
}

export interface AccountPasswordLoginResponse {
  admission_token: string;
  expires_at_ms: string;
  snapshot: string;
  [extension: string]: unknown;
}

export interface AccountRegistrationRequest {
  intent: "submit" | "confirm";
  payload: string;
  account_signature: string;
  attempt_id: string;
  nonce: string;
  device_proof: string;
}

export type AccountDeviceAdmissionRequest =
  | (AccountDeviceAdmissionFields & { intent: "submit"; admission_token: string })
  | (AccountDeviceAdmissionFields & { intent: "confirm"; admission_token: null });

export interface AccountDeviceAdmissionFields {
  payload: string;
  account_signature: string;
  attempt_id: string;
  nonce: string;
  device_proof: string;
}

export interface AccountCommittedConfirmation {
  outcome: "committed";
  kind: "register" | "admit";
  operation_id: string;
  request_digest: string;
  account_id: string;
  personal_vault_id: string;
  device_id: string;
  admitted_key_revision: string;
  [extension: string]: unknown;
}

export type AccountEntryInvalidRequestProblem = ProblemDetails & { status: 400; code: "auth.invalid_request"; changed: false; retryable: false; };

export type AccountEntryAuthenticationRequiredProblem = ProblemDetails & { status: 401; code: "auth.authentication_required"; changed: false; retryable: false; };

export type AccountEntryPolicyDeniedProblem = ProblemDetails & { status: 403; code: "policy.denied"; changed: false; retryable: false; };

export type AccountEntryMediaTypeProblem = ProblemDetails & { status: 415; code: "auth.invalid_request"; changed: false; retryable: false; };

export type AccountEntryRateLimitedProblem = ProblemDetails & { status: 429; code: "auth.rate_limited"; changed: false; retryable: true; };

export type AccountEntryRegistrationDeniedProblem = ProblemDetails & { status: 409; code: "auth.registration_denied"; changed: false; retryable: false; };

export type AccountEntryAdmissionConflictProblem = ProblemDetails & { status: 409; code: "auth.admission_conflict"; changed: false; retryable: false; };

export type AccountEntryBodyTooLargeProblem = ProblemDetails & { status: 413; code: "auth.invalid_request"; changed: false; retryable: false; };

export type AccountEntryStorageUnavailableProblem = ProblemDetails & { status: 503; code: "auth.storage_unavailable"; changed: false; retryable: true; };

export type AccountEntryTooLargeProblem =
  | (ProblemDetails & { status: 413; code: "auth.invalid_request"; changed: false; retryable: false; })
  | (ProblemDetails & { status: 413; code: "auth.quota_exceeded"; changed: false; retryable: false; });

export type AccountEntryStorageFailureProblem =
  | (ProblemDetails & { status: 503; code: "auth.storage_unavailable"; changed: false; retryable: true; })
  | (ProblemDetails & { status: 503; code: "auth.commit_outcome_unknown"; changed: true; retryable: false; });

export interface AccountEntryRateLimitHeaders {
  "Retry-After": string;
  "RateLimit-Policy": '"authentication";q=30;w=60';
  RateLimit: string;
  "Cache-Control": "no-store";
  Pragma: "no-cache";
}

// END GENERATED AccountAdmission

// BEGIN GENERATED Organizations
export interface OrganizationCreateRequest { data: { name: string }; }
export interface OrganizationUpdateRequest { data: { name: string }; }
export interface OrganizationMembership {
  id: string;
  account_id: string;
  roles: string[];
  [extension: string]: unknown;
}
export interface OrganizationResource {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: { name: string; membership: OrganizationMembership; [extension: string]: unknown };
  [extension: string]: unknown;
}
export interface OrganizationPage {
  items: OrganizationResource[];
  next_cursor: string | null;
  [extension: string]: unknown;
}

export type OrganizationInvalidRequestProblem = ProblemDetails & { status: 400; code: "organization.invalid_request"; changed: false; retryable: false; };

export type OrganizationContentTypeProblem = ProblemDetails & { status: 415; code: "organization.invalid_request"; changed: false; retryable: false; };

export type OrganizationAuthenticationRequiredProblem = ProblemDetails & { status: 401; code: "auth.authentication_required"; changed: false; retryable: false; };

export type OrganizationDeniedProblem = ProblemDetails & { status: 403; code: "policy.denied"; changed: false; retryable: false; };

export type OrganizationNotFoundProblem = ProblemDetails & { status: 404; code: "organization.not_found"; changed: false; retryable: false; };

export type OrganizationConflictProblem = ProblemDetails & { status: 409; code: "organization.conflict"; changed: false; retryable: false; };

export type OrganizationPreconditionFailedProblem = ProblemDetails & { status: 412; code: "organization.precondition_failed"; changed: false; retryable: false; };

export type OrganizationPreconditionRequiredProblem = ProblemDetails & { status: 428; code: "organization.precondition_required"; changed: false; retryable: false; };

export type OrganizationStorageUnavailableProblem = ProblemDetails & { status: 503; code: "organization.storage_unavailable"; changed: false; retryable: true; };

export type OrganizationCommitOutcomeUnknownProblem = ProblemDetails & { status: 503; code: "organization.commit_outcome_unknown"; changed: true; retryable: true; };

export type OrganizationUpdateCommitOutcomeUnknownProblem = ProblemDetails & { status: 503; code: "organization.commit_outcome_unknown"; changed: true; retryable: false; };
// END GENERATED Organizations

// BEGIN GENERATED TeamMembership
export type TeamRole = "administrator" | "approver" | "member" | "owner" | "security_auditor";
export type TeamInvitationStatus = "pending" | "accepted" | "revoked" | "expired" | "locked";
export type TeamMemberStatus = "active" | "suspended" | "removed";
export interface TeamInvitationCreateRequest { invitation_id: string; recipient_username: string; roles: TeamRole[]; password_verifier: string; }
export interface TeamInvitationAcceptRequest { password: string; }
export interface TeamInvitationResource {
  id: string; etag: string; created_at: string; updated_at: string;
  data: { organization_id: string; organization_name: string; recipient_account_id: string; recipient_username: string; roles: TeamRole[]; issuer_account_id: string; expires_at: string; [extension: string]: unknown; } &
    ({ status: "accepted"; membership_id: string } | { status: Exclude<TeamInvitationStatus, "accepted">; membership_id: null });
  [extension: string]: unknown;
}
export interface TeamInvitationPage { items: TeamInvitationResource[]; next_cursor: string | null; [extension: string]: unknown; }
export interface TeamMemberUpdateRequest { roles: TeamRole[]; status: "active" | "suspended"; }
export interface TeamMemberResource {
  id: string; etag: string; created_at: string; updated_at: string;
  data: { organization_id: string; account_id: string; username: string; roles: TeamRole[]; status: TeamMemberStatus; [extension: string]: unknown };
  [extension: string]: unknown;
}
export interface TeamMemberPage { items: TeamMemberResource[]; next_cursor: string | null; [extension: string]: unknown; }
/** Historical confirmation only; every echoed id must bind the captured original operation. */
export interface TeamAcceptanceReceipt { invitation_id: string; organization_id: string; account_id: string; membership_id: string; accepted_at: string; [extension: string]: unknown; }
export interface TeamDissolveRequest { organization_id: string; }
/** Historical confirmation only; conveys no current team-data access. */
export interface TeamDissolutionReceipt { organization_id: string; dissolved_at: string; [extension: string]: unknown; }

export type TeamInvitationDeniedProblem = ProblemDetails & { status: 409; code: "organization.invitation_denied"; changed: false; retryable: false; };

export type TeamBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false; };
// END GENERATED TeamMembership

// BEGIN GENERATED UserCa
export interface UserCaCreateRequest { id: string; data: { kind: "user"; backend: "local" }; }
/** Authenticated request provenance supplies Organization ownership; parsing alone never establishes CA trust. */
export interface UserCaResource {
  id: string; etag: string; created_at: string; updated_at: string;
  data: { kind: "user"; backend: "local"; state: "active"; public_key: string; fingerprint: string; [extension: string]: unknown };
  [extension: string]: unknown;
}
export interface UserCaPage { items: UserCaResource[]; next_cursor: string | null; [extension: string]: unknown; }
// END GENERATED UserCa
// BEGIN GENERATED GroupPolicy
export type GroupSource = "local" | "IdP";
export interface GroupFields { name: string; members: string[]; }
export interface GroupCreateRequest { id: string; data: GroupFields; }
export interface GroupReplaceRequest { data: GroupFields; }
export interface GroupResource {
  id: string; etag: string; created_at: string; updated_at: string;
  data: GroupFields & { source: GroupSource; [extension: string]: unknown };
  [extension: string]: unknown;
}
export interface GroupPage { items: GroupResource[]; next_cursor: string | null; [extension: string]: unknown; }
export interface PolicyFields { name: string; source: string; enabled: boolean; }
export interface PolicyCreateRequest { id: string; data: PolicyFields; }
export interface PolicyReplaceRequest { data: PolicyFields; }
export interface PolicyResource {
  id: string; etag: string; created_at: string; updated_at: string;
  data: PolicyFields & { [extension: string]: unknown };
  [extension: string]: unknown;
}
export interface PolicyPage { items: PolicyResource[]; next_cursor: string | null; [extension: string]: unknown; }
export interface SimpleRuleSelector { type: 1 | 2 | 4 | 5 | 6 | 7 | 11; id: string; }
export interface SimpleRuleConnect { hosts: string[]; host_groups: string[]; remote_user: string; }
export type SimpleRuleSubject = { membership: string; group?: never } | { group: string; membership?: never };
export type SimpleRule = { view: SimpleRuleSelector[]; connect?: never } | { connect: SimpleRuleConnect; view?: never };
/** Pure preview input; use the shared native generator and persist through the authorized policy route. */
export type SimpleRuleInput = { organization: string } & SimpleRuleSubject & SimpleRule;
export type GroupPolicyBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false; };
// END GENERATED GroupPolicy

// BEGIN GENERATED OrganizationInventory
export type InventorySnippetVariable = { kind: 1; default?: string } | { kind: 2; default?: string } | { kind: 3; choices: string[]; default?: string } | { kind: 4 };
export type InventoryBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false };

export type InventoryHostFields = { name: string; address: string; port?: number; tags?: Record<string, string>; groups?: Record<string, true>; favorite?: boolean; notes?: string; default_profile?: string; ssh_options?: Record<string, string>; mosh?: Record<string, string>; };
export type InventoryHostReadFields = InventoryHostFields;
export interface InventoryHostCreateRequest { id: string; data: { fields: InventoryHostFields }; }
export interface InventoryHostReplaceRequest { data: { fields: InventoryHostFields }; }
export interface InventoryHostResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventoryHostReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventoryHostPage { items: InventoryHostResource[]; next_cursor: string | null; [extension: string]: unknown; }

export type InventoryAccessProfileFields = { host: string; name?: string; username: string; route?: string | 0; terminal_profile?: string; startup_command?: string; agent_forwarding?: boolean; };
export type InventoryAccessProfileReadFields = InventoryAccessProfileFields;
export interface InventoryAccessProfileCreateRequest { id: string; data: { fields: InventoryAccessProfileFields }; }
export interface InventoryAccessProfileReplaceRequest { data: { fields: InventoryAccessProfileFields }; }
export interface InventoryAccessProfileResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventoryAccessProfileReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventoryAccessProfilePage { items: InventoryAccessProfileResource[]; next_cursor: string | null; [extension: string]: unknown; }

export type InventoryRouteFields = { name: string; kind: 1; hops: string[] } | { name: string; kind: 2 | 3; proxy: string } | { name: string; kind: 4; command: string } | { name: string; kind: 5; gateway_network: string };
export type InventoryRouteReadFields = InventoryRouteFields;
export interface InventoryRouteCreateRequest { id: string; data: { fields: InventoryRouteFields }; }
export interface InventoryRouteReplaceRequest { data: { fields: InventoryRouteFields }; }
export interface InventoryRouteResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventoryRouteReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventoryRoutePage { items: InventoryRouteResource[]; next_cursor: string | null; [extension: string]: unknown; }

export type InventoryHostGroupFields = { name: string; parent?: string; color?: string; defaults?: Record<string, string>; };
export type InventoryHostGroupReadFields = InventoryHostGroupFields;
export interface InventoryHostGroupCreateRequest { id: string; data: { fields: InventoryHostGroupFields }; }
export interface InventoryHostGroupReplaceRequest { data: { fields: InventoryHostGroupFields }; }
export interface InventoryHostGroupResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventoryHostGroupReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventoryHostGroupPage { items: InventoryHostGroupResource[]; next_cursor: string | null; [extension: string]: unknown; }

export type InventoryTrustRecordFields = { host?: string; pattern?: string; key?: string; fingerprint?: string; provenance?: 1 | 2 | 3 | 4; revoked?: boolean; ca?: boolean; } & ({ host: string } | { pattern: string });
export type InventoryTrustRecordReadFields = InventoryTrustRecordFields & { accepted_at: string; accepted_by_device: string; accepted_by_account: string };
export interface InventoryTrustRecordCreateRequest { id: string; data: { fields: InventoryTrustRecordFields }; }
export interface InventoryTrustRecordReplaceRequest { data: { fields: InventoryTrustRecordFields }; }
export interface InventoryTrustRecordResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventoryTrustRecordReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventoryTrustRecordPage { items: InventoryTrustRecordResource[]; next_cursor: string | null; [extension: string]: unknown; }

export type InventorySnippetFields = { name: string; template: string; variables?: Record<string, InventorySnippetVariable>; tags?: Record<string, true>; folder?: string; };
export type InventorySnippetReadFields = InventorySnippetFields;
export interface InventorySnippetCreateRequest { id: string; data: { fields: InventorySnippetFields }; }
export interface InventorySnippetReplaceRequest { data: { fields: InventorySnippetFields }; }
export interface InventorySnippetResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventorySnippetReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventorySnippetPage { items: InventorySnippetResource[]; next_cursor: string | null; [extension: string]: unknown; }

export type InventoryGatewayNetworkFields = { name?: string; description?: string; };
export type InventoryGatewayNetworkReadFields = InventoryGatewayNetworkFields;
export interface InventoryGatewayNetworkCreateRequest { id: string; data: { fields: InventoryGatewayNetworkFields }; }
export interface InventoryGatewayNetworkReplaceRequest { data: { fields: InventoryGatewayNetworkFields }; }
export interface InventoryGatewayNetworkResource { id: string; etag: string; created_at: string; updated_at: string; data: { schema: 1; fields: InventoryGatewayNetworkReadFields; [extension: string]: unknown }; [extension: string]: unknown; }
export interface InventoryGatewayNetworkPage { items: InventoryGatewayNetworkResource[]; next_cursor: string | null; [extension: string]: unknown; }
// END GENERATED OrganizationInventory
