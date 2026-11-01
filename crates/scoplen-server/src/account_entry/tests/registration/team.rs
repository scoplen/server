// SPDX-License-Identifier: AGPL-3.0-only
//! Real password registration and Device-authenticated public team lifecycle acceptance.

use scoplen_api::{
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthRefreshRequest,
        AuthTokenResponse,
    },
    organization::{OrganizationCreateRequest, OrganizationPage, OrganizationResource},
    team::{
        TeamAcceptanceReceipt, TeamDissolutionReceipt, TeamDissolveRequest,
        TeamInvitationAcceptRequest, TeamInvitationCreateRequest, TeamInvitationResource,
        TeamInvitationStatus, TeamMemberResource, TeamMemberStatus, TeamMemberUpdateRequest,
        TeamRole,
    },
};
use scoplen_crypto::{DeviceAuthContext, DpopProof, DpopTarget, DpopToken, TeamInvitationPassword};
use scoplen_store::{ObjectStorage, ObjectStorageConfig};

use super::*;

struct Fixture {
    backend: AuthBackend,
    directory: PathBuf,
    address: SocketAddr,
    server: JoinHandle<()>,
}

impl Fixture {
    async fn start(backend: AuthBackend, directory: PathBuf) -> Self {
        let kms = test_kms();
        let policy = AccountSettings { registration_enabled: true, ..AccountSettings::default() };
        match &backend {
            AuthBackend::Sqlite(store) => {
                store
                    .initialize_account_id_retention(policy.used_account_id_limit)
                    .await
                    .expect("retention");
                store.ensure_account_probe_key(kms.as_ref()).await.expect("probe key");
            }
            AuthBackend::Postgres(store) => {
                store
                    .initialize_account_id_retention(policy.used_account_id_limit)
                    .await
                    .expect("retention");
                store.ensure_account_probe_key(kms.as_ref()).await.expect("probe key");
            }
        }
        let database = match &backend {
            AuthBackend::Sqlite(store) => crate::runtime::ListenerDatabase::Sqlite(store.clone()),
            AuthBackend::Postgres(store) => {
                crate::runtime::ListenerDatabase::Postgres(store.clone())
            }
        };
        let storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: directory.join("objects"),
        })
        .expect("object storage");
        let app = crate::runtime::api_router_with_notifications(
            database,
            Arc::new(storage),
            kms,
            ORIGIN.into(),
            true,
            scoplen_sync::http::WriteRateLimits::default(),
            scoplen_sync::http::WriteBodyLimits::default(),
            scoplen_sync::http::ReadBodyLimits::default(),
            scoplen_sync::notify::NotificationHub::default(),
            policy,
            crate::OrganizationSettings { allow_creation: true },
        );
        let (address, server) = serve_router(app).await;
        Self { backend, directory, address, server }
    }

    async fn close(self) {
        stop(self.server).await;
        match &self.backend {
            AuthBackend::Sqlite(store) => store.pool().close().await,
            AuthBackend::Postgres(store) => store.pool().close().await,
        }
        crate::test_support::remove_test_directory(self.directory).await;
    }

    async fn execute(&self, sql: &str) {
        match &self.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::raw_sql(sql).execute(store.pool()).await.expect("owned fixture mutation");
            }
            AuthBackend::Postgres(store) => {
                sqlx::raw_sql(sql).execute(store.pool()).await.expect("owned fixture mutation");
            }
        }
    }

    async fn count(&self, sql: &str) -> i64 {
        match &self.backend {
            AuthBackend::Sqlite(store) => {
                sqlx::query_scalar(sql).fetch_one(store.pool()).await.expect("owned count")
            }
            AuthBackend::Postgres(store) => {
                sqlx::query_scalar(sql).fetch_one(store.pool()).await.expect("owned count")
            }
        }
    }

    async fn revision(&self, organization: Uuid) -> u64 {
        let sql = "SELECT view_revision FROM organizations WHERE id=$1";
        let value: Vec<u8> = match &self.backend {
            AuthBackend::Sqlite(store) => sqlx::query_scalar(sql)
                .bind(organization.as_bytes().as_slice())
                .fetch_one(store.pool())
                .await
                .expect("team revision"),
            AuthBackend::Postgres(store) => sqlx::query_scalar(sql)
                .bind(organization.as_bytes().as_slice())
                .fetch_one(store.pool())
                .await
                .expect("team revision"),
        };
        u64::from_be_bytes(value.try_into().expect("full unsigned revision"))
    }

    async fn audit_failure(&self, enabled: bool) {
        let sql = match (&self.backend, enabled) {
            (AuthBackend::Sqlite(_), true) => {
                "CREATE TRIGGER team_audit_failure BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'owned fixture failure'); END;"
            }
            (AuthBackend::Sqlite(_), false) => "DROP TRIGGER team_audit_failure;",
            (AuthBackend::Postgres(_), true) => {
                "CREATE FUNCTION team_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture failure'; END $$; CREATE TRIGGER team_audit_failure BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION team_audit_failure();"
            }
            (AuthBackend::Postgres(_), false) => {
                "DROP TRIGGER team_audit_failure ON audit_events; DROP FUNCTION team_audit_failure();"
            }
        };
        self.execute(sql).await;
    }

    async fn commit_failure(&self, enabled: bool) {
        if enabled {
            self.execute("CREATE TABLE IF NOT EXISTS team_commit_parent (id INTEGER PRIMARY KEY); CREATE TABLE IF NOT EXISTS team_commit_child (id INTEGER REFERENCES team_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);").await;
        }
        let sql = match (&self.backend, enabled) {
            (AuthBackend::Sqlite(_), true) => {
                "CREATE TRIGGER team_commit_failure AFTER INSERT ON organization_operation_receipts BEGIN INSERT INTO team_commit_child VALUES(1); END;"
            }
            (AuthBackend::Sqlite(_), false) => "DROP TRIGGER team_commit_failure;",
            (AuthBackend::Postgres(_), true) => {
                "CREATE FUNCTION team_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO team_commit_child VALUES(1); RETURN NEW; END $$; CREATE TRIGGER team_commit_failure AFTER INSERT ON organization_operation_receipts FOR EACH ROW EXECUTE FUNCTION team_commit_failure();"
            }
            (AuthBackend::Postgres(_), false) => {
                "DROP TRIGGER team_commit_failure ON organization_operation_receipts; DROP FUNCTION team_commit_failure();"
            }
        };
        self.execute(sql).await;
    }
}

struct Actor {
    registration: Registration,
    token: AuthTokenResponse,
}

async fn actor(f: &Fixture, username: &str) -> Actor {
    let registration = Registration::with_username(username);
    let request = registration.request(f.address, AccountRequestIntent::Submit).await;
    let response =
        http(f.address, "POST", REGISTER, &request.to_json().expect("registration JSON"), JSON)
            .await;
    committed(&response, &request, 201);
    let token = authenticate(f, &registration).await;
    Actor { registration, token }
}

async fn authenticate(f: &Fixture, registration: &Registration) -> AuthTokenResponse {
    let challenge = AuthChallengeRequest::new(registration.payload.device_id)
        .and_then(|value| value.to_json())
        .expect("challenge");
    let response =
        http(f.address, "POST", "/api/v1/auth/challenge", challenge.as_bytes(), JSON).await;
    assert_eq!(response.status, 200);
    let challenge =
        AuthChallengeResponse::from_json(std::str::from_utf8(&response.body).expect("UTF-8"))
            .expect("challenge response");
    let context = DeviceAuthContext::new(ORIGIN, &challenge.nonce, registration.payload.device_id)
        .expect("Device context");
    let signature = registration.device.sign(&context.signature_input());
    let mut encoded = String::new();
    for byte in signature {
        write!(encoded, "{byte:02x}").expect("String write");
    }
    let request = AuthDeviceRequest::new(registration.payload.device_id, challenge.nonce, encoded)
        .and_then(|value| value.to_json())
        .expect("Device request");
    let response = http(f.address, "POST", "/api/v1/auth/device", request.as_bytes(), JSON).await;
    assert_eq!(response.status, 200);
    AuthTokenResponse::from_json(std::str::from_utf8(&response.body).expect("UTF-8"))
        .expect("Device credentials")
}

async fn narrow(f: &Fixture, a: &mut Actor, scope: &str) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            sqlx::query("UPDATE device_refresh_families SET scope=$1 WHERE account_id=$2")
                .bind(scope)
                .bind(a.registration.payload.account_id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("scope ceiling");
        }
        AuthBackend::Postgres(store) => {
            sqlx::query("UPDATE device_refresh_families SET scope=$1 WHERE account_id=$2")
                .bind(scope)
                .bind(a.registration.payload.account_id.as_bytes().as_slice())
                .execute(store.pool())
                .await
                .expect("scope ceiling");
        }
    }
    let path = "/api/v1/auth/refresh";
    let proof = DpopProof::sign(
        &a.registration.device,
        &a.registration.device.public_key_sec1(),
        &DpopTarget::new("POST", ORIGIN, path).expect("refresh target"),
        DpopToken::Refresh,
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("refresh proof");
    let body = AuthRefreshRequest::new(a.token.refresh_token.clone())
        .and_then(|request| request.to_json())
        .expect("refresh body");
    let reply = http(
        f.address,
        "POST",
        path,
        body.as_bytes(),
        &[("Content-Type", "application/json"), ("DPoP", proof.as_str())],
    )
    .await;
    assert_eq!(reply.status, 200);
    a.token = AuthTokenResponse::from_json(std::str::from_utf8(&reply.body).expect("UTF-8"))
        .expect("narrowed credentials");
}

async fn call(
    f: &Fixture,
    a: &Actor,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Reply {
    let proof = DpopProof::sign(
        &a.registration.device,
        &a.registration.device.public_key_sec1(),
        &DpopTarget::new(method, ORIGIN, path.split('?').next().expect("path"))
            .expect("DPoP target"),
        DpopToken::Protected(&a.token.access_token),
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("clock"),
        None,
    )
    .expect("DPoP proof");
    let auth = format!("DPoP {}", a.token.access_token);
    let mut all = vec![
        ("Content-Type", "application/json"),
        ("Authorization", auth.as_str()),
        ("DPoP", proof.as_str()),
        ("Origin", ORIGIN),
    ];
    all.extend_from_slice(headers);
    http(f.address, method, path, body, &all).await
}

fn problem(reply: &Reply, status: u16, code: &str) {
    reply.problem(status, code, status >= 500);
    assert!(reply.header("etag").is_none());
}

fn invitation(reply: &Reply, status: u16) -> TeamInvitationResource {
    assert_eq!(reply.status, status, "{:?}", String::from_utf8_lossy(&reply.body));
    reply.private();
    let value = TeamInvitationResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .expect("invitation Resource");
    let text = String::from_utf8_lossy(&reply.body);
    for secret in ["password_verifier", "wrong_passwords", "email", "password\""] {
        assert!(!text.contains(secret));
    }
    value
}

async fn create_team(f: &Fixture, a: &Actor) -> OrganizationResource {
    let body = OrganizationCreateRequest::new("Lifecycle team")
        .and_then(|value| value.to_json())
        .expect("team request");
    let reply = call(
        f,
        a,
        "POST",
        "/api/v1/orgs",
        &body,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 201);
    OrganizationResource::from_json(&reply.body).expect("team Resource")
}

async fn current_team(f: &Fixture, a: &Actor, org: Uuid) -> OrganizationResource {
    let reply = call(f, a, "GET", &format!("/api/v1/orgs/{org}"), &[], &[]).await;
    assert_eq!(reply.status, 200);
    OrganizationResource::from_json(&reply.body).expect("team Resource")
}

async fn issue(
    f: &Fixture,
    a: &Actor,
    b: &Actor,
    org: Uuid,
    roles: Vec<TeamRole>,
) -> (TeamInvitationResource, TeamInvitationPassword, Uuid, SecretVec) {
    let id = Uuid::now_v7();
    let key = Uuid::now_v7();
    let password = TeamInvitationPassword::generate().expect("OS invitation password");
    let body = TeamInvitationCreateRequest {
        invitation_id: id,
        recipient_username: b.registration.payload.username.clone(),
        roles,
        password_verifier: password.verifier(ORIGIN, &org, &id).expect("shared verifier"),
    }
    .to_json()
    .expect("create invitation");
    let reply = call(
        f,
        a,
        "POST",
        &format!("/api/v1/orgs/{org}/invitations"),
        body.as_bytes(),
        &[("Idempotency-Key", &key.to_string())],
    )
    .await;
    (invitation(&reply, 201), password, key, body)
}

#[allow(clippy::too_many_lines)]
async fn lifecycle(f: &Fixture) {
    let landing = http(f.address, "GET", "/join-team", &[], &[]).await;
    assert_eq!(landing.status, 200);
    landing.private();
    assert!(landing.header("x-request-id").is_some());
    let html = String::from_utf8(landing.body).expect("UTF-8 landing");
    assert!(html.contains("Open Join team in Scoplen"));
    assert!(!html.contains("<form"));
    let a = actor(f, "team-owner").await;
    let b = actor(f, "team-recipient").await;
    let c = actor(f, "other-account").await;
    let team = create_team(f, &a).await;
    let other = create_team(f, &b).await;
    let org = team.id;
    assert_eq!(f.revision(org).await, 1);
    let root = format!("/api/v1/orgs/{org}");
    let (inv, password, create_key, create_body) =
        issue(f, &a, &b, org, vec![TeamRole::Administrator]).await;
    assert_eq!(f.revision(org).await, 1);
    let path = format!("{root}/invitations/{}", inv.id);
    let accept = format!("{path}/accept");
    let accept_key = Uuid::now_v7();
    let accept_body = TeamInvitationAcceptRequest { password: password.clone() }
        .to_json()
        .expect("accept request");
    problem(&call(f, &c, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    problem(
        &call(
            f,
            &c,
            "POST",
            &accept,
            accept_body.as_bytes(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        404,
        "organization.not_found",
    );
    assert_eq!(
        f.count("SELECT CAST(SUM(wrong_passwords) AS BIGINT) FROM organization_invitations").await,
        0
    );
    assert_eq!(
        invitation(&call(f, &b, "GET", &path, &[], &[]).await, 200).recipient_account_id,
        b.registration.payload.account_id
    );
    let reply = call(
        f,
        &b,
        "POST",
        &accept,
        accept_body.as_bytes(),
        &[("Idempotency-Key", &accept_key.to_string())],
    )
    .await;
    assert_eq!(reply.status, 200);
    let receipt = TeamAcceptanceReceipt::from_json(&reply.body).expect("accept receipt");
    assert_eq!(receipt.account_id, b.registration.payload.account_id);
    assert_eq!(receipt.organization_id, org);
    let accepted_body = reply.body;
    assert_eq!(f.revision(org).await, 2);
    assert_eq!(current_team(f, &b, org).await.membership.id, receipt.membership_id);
    let creation_confirmation = call(
        f,
        &a,
        "POST",
        &format!("{root}/invitations"),
        create_body.as_bytes(),
        &[("Idempotency-Key", &create_key.to_string())],
    )
    .await;
    assert_eq!(invitation(&creation_confirmation, 201).status, TeamInvitationStatus::Accepted);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_memberships").await, 3);
    let owner_invite = TeamInvitationCreateRequest {
        invitation_id: Uuid::now_v7(),
        recipient_username: c.registration.payload.username.clone(),
        roles: vec![TeamRole::Owner],
        password_verifier: password.verifier(ORIGIN, &org, &Uuid::now_v7()).expect("test verifier"),
    }
    .to_json()
    .expect("owner request");
    problem(
        &call(
            f,
            &b,
            "POST",
            &format!("{root}/invitations"),
            owner_invite.as_bytes(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        403,
        "policy.denied",
    );
    let member_path = format!("{root}/members/{}", receipt.membership_id);
    let reply = call(f, &a, "GET", &member_path, &[], &[]).await;
    assert_eq!(reply.status, 200);
    let member = TeamMemberResource::from_json(&reply.body).expect("member Resource");
    problem(
        &call(f, &a, "DELETE", &member_path, &[], &[]).await,
        428,
        "organization.precondition_required",
    );
    let suspension_body = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Member],
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .expect("suspend JSON");
    problem(
        &call(f, &a, "PATCH", &member_path, &suspension_body, &[("If-Match", "\"stale\"")]).await,
        412,
        "organization.precondition_failed",
    );
    let reply =
        call(f, &a, "PATCH", &member_path, &suspension_body, &[("If-Match", &member.etag)]).await;
    assert_eq!(reply.status, 200);
    let suspended = TeamMemberResource::from_json(&reply.body).expect("suspended Resource");
    assert_eq!(suspended.status, TeamMemberStatus::Suspended);
    problem(&call(f, &b, "GET", &root, &[], &[]).await, 404, "organization.not_found");
    assert_eq!(
        call(
            f,
            &b,
            "POST",
            &accept,
            accept_body.as_bytes(),
            &[("Idempotency-Key", &accept_key.to_string())]
        )
        .await
        .body,
        accepted_body
    );
    let activate =
        TeamMemberUpdateRequest { roles: vec![TeamRole::Member], status: TeamMemberStatus::Active }
            .to_json()
            .expect("restore JSON");
    let reply =
        call(f, &a, "PATCH", &member_path, &activate, &[("If-Match", &suspended.etag)]).await;
    assert_eq!(reply.status, 200);
    let active = TeamMemberResource::from_json(&reply.body).expect("active Resource");
    let before = f.count("SELECT COUNT(*) FROM audit_events").await;
    let revision = f.revision(org).await;
    assert_eq!(
        call(f, &a, "PATCH", &member_path, &activate, &[("If-Match", &active.etag)]).await.status,
        200
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, before);
    assert_eq!(f.revision(org).await, revision);
    let own = current_team(f, &b, org).await;
    assert_eq!(
        call(f, &b, "DELETE", &member_path, &[], &[("If-Match", &own.etag)]).await.status,
        204
    );
    assert_eq!(f.revision(org).await, revision + 1);
    assert_eq!(
        call(
            f,
            &b,
            "POST",
            &accept,
            accept_body.as_bytes(),
            &[("Idempotency-Key", &accept_key.to_string())]
        )
        .await
        .body,
        accepted_body
    );
    problem(&call(f, &b, "GET", &root, &[], &[]).await, 404, "organization.not_found");
    let removed = call(f, &a, "GET", &member_path, &[], &[]).await;
    let removed = TeamMemberResource::from_json(&removed.body).expect("removed Resource");
    problem(
        &call(f, &a, "PATCH", &member_path, &activate, &[("If-Match", &removed.etag)]).await,
        409,
        "organization.conflict",
    );
    let (fresh, fresh_password, _, _) = issue(f, &a, &b, org, vec![TeamRole::Member]).await;
    let fresh_accept = format!("{root}/invitations/{}/accept", fresh.id);
    let body =
        TeamInvitationAcceptRequest { password: fresh_password }.to_json().expect("fresh accept");
    let reply = call(
        f,
        &b,
        "POST",
        &fresh_accept,
        body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        TeamAcceptanceReceipt::from_json(&reply.body).expect("fresh receipt").membership_id,
        receipt.membership_id
    );
    let current = current_team(f, &a, org).await;
    let revision = f.revision(org).await;
    problem(
        &call(
            f,
            &a,
            "DELETE",
            &format!("{root}/members/{}", team.membership.id),
            &[],
            &[("If-Match", &current.etag)],
        )
        .await,
        409,
        "organization.conflict",
    );
    assert_eq!(f.revision(org).await, revision);
    let dissolve = TeamDissolveRequest { organization_id: org }.to_json().expect("dissolve JSON");
    let key = Uuid::now_v7().to_string();
    let headers = [("If-Match", current.etag.as_str()), ("Idempotency-Key", key.as_str())];
    let reply = call(f, &a, "POST", &format!("{root}/dissolve"), &dissolve, &headers).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        TeamDissolutionReceipt::from_json(&reply.body)
            .expect("dissolution receipt")
            .organization_id,
        org
    );
    assert_eq!(f.revision(org).await, revision + 1);
    assert_eq!(
        call(f, &a, "POST", &format!("{root}/dissolve"), &dissolve, &headers).await.body,
        reply.body
    );
    assert_eq!(f.revision(org).await, revision + 1);
    problem(&call(f, &a, "GET", &root, &[], &[]).await, 404, "organization.not_found");
    problem(&call(f, &b, "GET", &root, &[], &[]).await, 404, "organization.not_found");
    assert_eq!(current_team(f, &b, other.id).await.id, other.id);
    let discovery = call(f, &b, "GET", "/api/v1/orgs", &[], &[]).await;
    assert_eq!(
        OrganizationPage::from_json(&discovery.body).expect("current discovery").items.len(),
        1
    );
    let own_keys = call(f, &b, "GET", "/sync/v1/keys", &[], &[]).await;
    assert_eq!(own_keys.status, 200, "Personal keys remain usable after team dissolution");
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            store.verify_audit_chain(org.into_bytes()).await.expect("complete audit chain");
        }
        AuthBackend::Postgres(store) => {
            store.verify_audit_chain(org.into_bytes()).await.expect("complete audit chain");
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn refusals(f: &Fixture) {
    let a = actor(f, "guard-owner").await;
    let b = actor(f, "guard-recipient").await;
    let org = create_team(f, &a).await.id;
    let root = format!("/api/v1/orgs/{org}");
    let invitation_id = Uuid::now_v7();
    let key = Uuid::now_v7().to_string();
    let password = TeamInvitationPassword::generate().expect("OS password");
    let body = TeamInvitationCreateRequest {
        invitation_id,
        recipient_username: b.registration.payload.username.clone(),
        roles: vec![TeamRole::Member],
        password_verifier: password
            .verifier(ORIGIN, &org, &invitation_id)
            .expect("shared verifier"),
    }
    .to_json()
    .expect("invitation JSON");
    let path = format!("{root}/invitations");
    problem(
        &call(f, &a, "POST", &path, body.as_bytes(), &[]).await,
        400,
        "organization.invalid_request",
    );
    let mut duplicate = body.as_bytes().to_vec();
    assert_eq!(duplicate.pop(), Some(b'}'));
    duplicate.extend_from_slice(b",\"roles\":[\"member\"]}");
    problem(
        &call(
            f,
            &a,
            "POST",
            &path,
            &duplicate,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        400,
        "organization.invalid_request",
    );
    problem(
        &call(
            f,
            &a,
            "POST",
            &path,
            &[b' '; 4097],
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        413,
        "organization.invalid_request",
    );
    f.audit_failure(true).await;
    problem(
        &call(f, &a, "POST", &path, body.as_bytes(), &[("Idempotency-Key", &key)]).await,
        503,
        "organization.storage_unavailable",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_invitations").await, 0);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_operation_receipts").await, 0);
    f.audit_failure(false).await;
    let created = invitation(
        &call(f, &a, "POST", &path, body.as_bytes(), &[("Idempotency-Key", &key)]).await,
        201,
    );
    let bad_body = TeamInvitationCreateRequest {
        invitation_id: Uuid::now_v7(),
        recipient_username: b.registration.payload.username.clone(),
        roles: vec![TeamRole::Member],
        password_verifier: password.verifier(ORIGIN, &org, &Uuid::now_v7()).expect("test verifier"),
    }
    .to_json()
    .expect("changed request");
    problem(
        &call(f, &a, "POST", &path, bad_body.as_bytes(), &[("Idempotency-Key", &key)]).await,
        409,
        "organization.conflict",
    );
    let preview = format!("{path}/{}", created.id);
    let accept = format!("{preview}/accept");
    let accept_key = Uuid::now_v7().to_string();
    let correct =
        TeamInvitationAcceptRequest { password: password.clone() }.to_json().expect("correct body");
    f.audit_failure(true).await;
    problem(
        &call(f, &b, "POST", &accept, correct.as_bytes(), &[("Idempotency-Key", &accept_key)])
            .await,
        503,
        "organization.storage_unavailable",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_memberships").await, 1);
    assert_eq!(
        invitation(&call(f, &b, "GET", &preview, &[], &[]).await, 200).status,
        TeamInvitationStatus::Pending
    );
    f.audit_failure(false).await;
    let incorrect = if password.as_bytes() == b"00000000" { b"11111111" } else { b"00000000" };
    let wrong = TeamInvitationAcceptRequest {
        password: TeamInvitationPassword::parse(incorrect).expect("different valid password"),
    }
    .to_json()
    .expect("wrong body");
    for _ in 0..5 {
        problem(
            &call(
                f,
                &b,
                "POST",
                &accept,
                wrong.as_bytes(),
                &[("Idempotency-Key", &Uuid::now_v7().to_string())],
            )
            .await,
            409,
            "organization.invitation_denied",
        );
    }
    let locked = invitation(&call(f, &b, "GET", &preview, &[], &[]).await, 200);
    assert_eq!(locked.status, TeamInvitationStatus::Locked);
    assert_eq!(
        f.count("SELECT CAST(SUM(wrong_passwords) AS BIGINT) FROM organization_invitations").await,
        5
    );
    problem(
        &call(f, &b, "POST", &accept, correct.as_bytes(), &[("Idempotency-Key", &accept_key)])
            .await,
        409,
        "organization.invitation_denied",
    );
    assert_eq!(
        call(f, &a, "DELETE", &preview, &[], &[("If-Match", &locked.etag)]).await.status,
        204
    );
    let revoked = invitation(&call(f, &a, "GET", &preview, &[], &[]).await, 200);
    let audit_count = f.count("SELECT COUNT(*) FROM audit_events").await;
    assert_eq!(
        call(f, &a, "DELETE", &preview, &[], &[("If-Match", &revoked.etag)]).await.status,
        204
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, audit_count);
    let (expired, expired_password, _, _) = issue(f, &a, &b, org, vec![TeamRole::Member]).await;
    f.execute("UPDATE organization_invitations SET created_at_ms=created_at_ms-86400000,expires_at_ms=expires_at_ms-86400000 WHERE status='pending'").await;
    let expired_path = format!("{path}/{}", expired.id);
    let expired = invitation(&call(f, &b, "GET", &expired_path, &[], &[]).await, 200);
    assert_eq!(expired.status, TeamInvitationStatus::Expired);
    let body =
        TeamInvitationAcceptRequest { password: expired_password }.to_json().expect("expired body");
    problem(
        &call(
            f,
            &b,
            "POST",
            &format!("{expired_path}/accept"),
            body.as_bytes(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        409,
        "organization.invitation_denied",
    );
    problem(
        &call(f, &a, "DELETE", &expired_path, &[], &[("If-Match", &expired.etag)]).await,
        409,
        "organization.conflict",
    );
    let (lost_authority, lost_password, _, _) = issue(f, &a, &b, org, vec![TeamRole::Member]).await;
    f.execute(
        "UPDATE organization_memberships SET roles_json='[\"member\"]' WHERE status='active'",
    )
    .await;
    let body = TeamInvitationAcceptRequest { password: lost_password }
        .to_json()
        .expect("lost authority body");
    problem(
        &call(
            f,
            &b,
            "POST",
            &format!("{path}/{}/accept", lost_authority.id),
            body.as_bytes(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        409,
        "organization.invitation_denied",
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_memberships").await, 1);
}

fn unknown(reply: &Reply) {
    assert_eq!(reply.status, 503);
    reply.private();
    let value: serde_json::Value = serde_json::from_slice(&reply.body).expect("commit problem");
    assert_eq!(value["code"], "organization.commit_outcome_unknown");
    assert_eq!(value["changed"], true);
    assert_eq!(value["retryable"], true);
}

#[allow(clippy::too_many_lines)]
async fn uncertain_receipts(f: &Fixture) {
    let a = actor(f, "uncertain-owner").await;
    let b = actor(f, "uncertain-recipient").await;
    let team = create_team(f, &a).await;
    let root = format!("/api/v1/orgs/{}", team.id);
    let id = Uuid::now_v7();
    let key = Uuid::now_v7().to_string();
    let password = TeamInvitationPassword::generate().expect("OS password");
    let body = TeamInvitationCreateRequest {
        invitation_id: id,
        recipient_username: b.registration.payload.username.clone(),
        roles: vec![TeamRole::Member],
        password_verifier: password.verifier(ORIGIN, &team.id, &id).expect("shared verifier"),
    }
    .to_json()
    .expect("invitation JSON");
    f.commit_failure(true).await;
    unknown(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/invitations"),
            body.as_bytes(),
            &[("Idempotency-Key", &key)],
        )
        .await,
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_invitations").await, 0);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_operation_receipts").await, 0);
    f.commit_failure(false).await;
    invitation(
        &call(
            f,
            &a,
            "POST",
            &format!("{root}/invitations"),
            body.as_bytes(),
            &[("Idempotency-Key", &key)],
        )
        .await,
        201,
    );
    let key = Uuid::now_v7().to_string();
    let body = TeamInvitationAcceptRequest { password }.to_json().expect("accept body");
    let accept = format!("{root}/invitations/{id}/accept");
    f.commit_failure(true).await;
    unknown(&call(f, &b, "POST", &accept, body.as_bytes(), &[("Idempotency-Key", &key)]).await);
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_memberships").await, 1);
    f.commit_failure(false).await;
    assert_eq!(
        call(f, &b, "POST", &accept, body.as_bytes(), &[("Idempotency-Key", &key)]).await.status,
        200
    );
    let team = current_team(f, &a, team.id).await;
    let key = Uuid::now_v7().to_string();
    let body = TeamDissolveRequest { organization_id: team.id }.to_json().expect("dissolve body");
    let headers = [("If-Match", team.etag.as_str()), ("Idempotency-Key", key.as_str())];
    f.commit_failure(true).await;
    unknown(&call(f, &a, "POST", &format!("{root}/dissolve"), &body, &headers).await);
    assert_eq!(current_team(f, &a, team.id).await, team);
    assert_eq!(current_team(f, &b, team.id).await.id, team.id);
    f.commit_failure(false).await;
    assert_eq!(call(f, &a, "POST", &format!("{root}/dissolve"), &body, &headers).await.status, 200);
}

async fn overlapping_posts(
    f: &Fixture,
    a: &Actor,
    organization: Uuid,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> (Reply, Reply) {
    match &f.backend {
        AuthBackend::Sqlite(store) => {
            let held = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("owned writer gate");
            let release = async {
                tokio::task::yield_now().await;
                held.commit().await.expect("release owned writer gate");
            };
            let (first, second, ()) = tokio::join!(
                call(f, a, "POST", path, body, headers),
                call(f, a, "POST", path, body, headers),
                release
            );
            (first, second)
        }
        AuthBackend::Postgres(store) => {
            let mut held = store.pool().begin().await.expect("owned team gate");
            let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *held)
                .await
                .expect("gate identity");
            sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
                .bind(organization.as_bytes().as_slice())
                .fetch_one(&mut *held)
                .await
                .expect("owned team gate");
            let release = async {
                tokio::time::timeout(std::time::Duration::from_secs(10),async {
                    loop {
                        let waiting:i64=sqlx::query_scalar("WITH RECURSIVE waiters(pid) AS (SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN waiters w ON w.pid=ANY(pg_blocking_pids(a.pid))) SELECT COUNT(*) FROM waiters")
                            .bind(holder).fetch_one(store.pool()).await.expect("observe exact overlapping requests");
                        if waiting>=2 {break;}
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }).await.expect("both original requests reached the team gate");
                held.commit().await.expect("release owned team gate");
            };
            let (first, second, ()) = tokio::join!(
                call(f, a, "POST", path, body, headers),
                call(f, a, "POST", path, body, headers),
                release
            );
            (first, second)
        }
    }
}

async fn overlapping_receipts(f: &Fixture) {
    let a = actor(f, "overlap-owner").await;
    let b = actor(f, "overlap-recipient").await;
    let team = create_team(f, &a).await;
    let (invitation, password, _, _) = issue(f, &a, &b, team.id, vec![TeamRole::Member]).await;
    let accept = format!("/api/v1/orgs/{}/invitations/{}/accept", team.id, invitation.id);
    let body = TeamInvitationAcceptRequest { password }.to_json().expect("accept JSON");
    let key = Uuid::now_v7().to_string();
    let before = f.count("SELECT COUNT(*) FROM audit_events").await;
    let accepted =
        overlapping_posts(f, &b, team.id, &accept, body.as_bytes(), &[("Idempotency-Key", &key)])
            .await;
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_memberships").await, 2);
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, before + 1);
    let team = current_team(f, &a, team.id).await;
    let path = format!("/api/v1/orgs/{}/dissolve", team.id);
    let body = TeamDissolveRequest { organization_id: team.id }.to_json().expect("dissolve JSON");
    let key = Uuid::now_v7().to_string();
    let dissolved = overlapping_posts(
        f,
        &a,
        team.id,
        &path,
        &body,
        &[("Idempotency-Key", &key), ("If-Match", &team.etag)],
    )
    .await;
    assert_eq!(f.count("SELECT COUNT(*) FROM audit_events").await, before + 2);
    assert_eq!(
        [accepted.0.status, accepted.1.status, dissolved.0.status, dissolved.1.status],
        [200; 4]
    );
    assert_eq!(accepted.0.body, accepted.1.body);
    assert_eq!(dissolved.0.body, dissolved.1.body);
}

#[tokio::test]
async fn sqlite_team_original_receipts_survive_overlapping_retries() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    overlapping_receipts(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_original_receipts_survive_overlapping_retries() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    overlapping_receipts(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

async fn quotas(f: &Fixture) {
    let a = actor(f, "quota-owner").await;
    let team = create_team(f, &a).await;
    let path = format!("/api/v1/orgs/{}/invitations", team.id);
    for _ in 0..10 {
        problem(
            &call(f, &a, "POST", &path, b"{}", &[("Idempotency-Key", &Uuid::now_v7().to_string())])
                .await,
            400,
            "organization.invalid_request",
        );
    }
    let limited =
        call(f, &a, "POST", &path, b"{}", &[("Idempotency-Key", &Uuid::now_v7().to_string())])
            .await;
    limited.problem(429, "auth.rate_limited", true);
    for header in ["retry-after", "ratelimit", "ratelimit-policy"] {
        assert!(limited.header(header).is_some());
    }
    assert_eq!(f.count("SELECT COUNT(*) FROM organization_invitations").await, 0);
    let dissolve = format!("/api/v1/orgs/{}/dissolve", team.id);
    problem(
        &call(f, &a, "POST", &dissolve, b"{}", &[("Idempotency-Key", &Uuid::now_v7().to_string())])
            .await,
        428,
        "organization.precondition_required",
    );
    let endpoint =
        scoplen_store::account_entry_admission::AccountEntryEndpoint::TeamInvitationCreate;
    for _ in 0..19 {
        let decision = match &f.backend {
            AuthBackend::Sqlite(store) => {
                store
                    .admit_account_entry_source(endpoint, "127.0.0.1".parse().expect("source"))
                    .await
            }
            AuthBackend::Postgres(store) => {
                store
                    .admit_account_entry_source(endpoint, "127.0.0.1".parse().expect("source"))
                    .await
            }
        }
        .expect("source quota");
        assert_eq!(
            decision,
            scoplen_store::account_entry_admission::AccountEntryAdmissionDecision::Admitted
        );
    }
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n"
    );
    exchange(f.address, request.as_bytes()).await.problem(429, "auth.rate_limited", true);
}

#[allow(clippy::too_many_lines)]
async fn scope_branches(f: &Fixture) {
    let a = actor(f, "scope-owner").await;
    let mut b = actor(f, "scope-recipient").await;
    let team = create_team(f, &a).await;
    let (inv, password, _, _) = issue(f, &a, &b, team.id, vec![TeamRole::Member]).await;
    let root = format!("/api/v1/orgs/{}", team.id);
    let path = format!("{root}/invitations/{}", inv.id);
    let body = TeamInvitationAcceptRequest { password }.to_json().expect("accept body");
    narrow(f, &mut b, "teams:manage").await;
    problem(&call(f, &b, "GET", &path, &[], &[]).await, 404, "organization.not_found");
    problem(
        &call(
            f,
            &b,
            "POST",
            &format!("{path}/accept"),
            body.as_bytes(),
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        )
        .await,
        403,
        "policy.denied",
    );
    b.token = authenticate(f, &b.registration).await;
    narrow(f, &mut b, "teams:join").await;
    invitation(&call(f, &b, "GET", &path, &[], &[]).await, 200);
    let reply = call(
        f,
        &b,
        "POST",
        &format!("{path}/accept"),
        body.as_bytes(),
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
    )
    .await;
    assert_eq!(reply.status, 200);
    let receipt = TeamAcceptanceReceipt::from_json(&reply.body).expect("accept receipt");
    problem(&call(f, &b, "GET", &format!("{root}/members"), &[], &[]).await, 403, "policy.denied");
    problem(
        &call(
            f,
            &b,
            "DELETE",
            &format!("{root}/members/{}", team.membership.id),
            &[],
            &[("If-Match", &team.etag)],
        )
        .await,
        404,
        "organization.not_found",
    );
    let member =
        call(f, &a, "GET", &format!("{root}/members/{}", receipt.membership_id), &[], &[]).await;
    let member = TeamMemberResource::from_json(&member.body).expect("current member");
    let path = format!("{root}/members/{}", receipt.membership_id);
    let suspension_body = TeamMemberUpdateRequest {
        roles: vec![TeamRole::Member],
        status: TeamMemberStatus::Suspended,
    }
    .to_json()
    .expect("suspend JSON");
    let suspended =
        call(f, &a, "PATCH", &path, &suspension_body, &[("If-Match", &member.etag)]).await;
    assert_eq!(suspended.status, 200);
    let suspended = TeamMemberResource::from_json(&suspended.body).expect("suspended member");
    problem(&call(f, &b, "GET", &format!("{root}/members"), &[], &[]).await, 403, "policy.denied");
    problem(
        &call(f, &b, "DELETE", &path, &[], &[("If-Match", &member.etag)]).await,
        412,
        "organization.precondition_failed",
    );
    assert_eq!(
        call(f, &b, "DELETE", &path, &[], &[("If-Match", &suspended.etag)]).await.status,
        204
    );
    problem(
        &call(f, &b, "DELETE", &path, &[], &[("If-Match", &suspended.etag)]).await,
        404,
        "organization.not_found",
    );
}

#[tokio::test]
async fn sqlite_team_union_routes_preserve_exact_verified_scope_branch() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    scope_branches(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_union_routes_preserve_exact_verified_scope_branch() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    scope_branches(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[tokio::test]
async fn sqlite_team_mutation_source_and_account_quota_are_independent_and_precede_body() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    quotas(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_mutation_source_and_account_quota_are_independent_and_precede_body() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    quotas(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[tokio::test]
async fn sqlite_team_receipt_mutations_report_uncertain_commit_and_allow_only_original_retry() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    uncertain_receipts(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_receipt_mutations_report_uncertain_commit_and_allow_only_original_retry() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    uncertain_receipts(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[tokio::test]
async fn sqlite_team_invitation_lock_expiry_issuer_checks_and_audit_rollback() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    refusals(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_team_invitation_lock_expiry_issuer_checks_and_audit_rollback() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    refusals(&fixture).await;
    fixture.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}

#[tokio::test]
async fn sqlite_public_named_account_team_lifecycle() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let fixture = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    lifecycle(&fixture).await;
    fixture.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_public_named_account_team_lifecycle() {
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let fixture = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    lifecycle(&fixture).await;
    fixture.close().await;
    assert!(
        schema.starts_with("account_entry_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
