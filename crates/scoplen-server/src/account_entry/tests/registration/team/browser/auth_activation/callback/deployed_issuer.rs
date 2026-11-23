// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit deployment acceptance against a separately provisioned Auth issuer.

use std::path::PathBuf;

use reqwest::{Client, header};
use scoplen_api::auth_connection_draft::test_login::DraftLoginCredentials;
use scoplen_api::member_link::{LinkMembership, MemberLink, SelfLinkStatus};
use serde::Deserialize;
use serde_json::json;
use zeroize::{Zeroize as _, Zeroizing};

use super::member_link::{confirm_link, metadata, start_link};
use super::*;
use crate::{EnterpriseIdentitySettings, TrustedIssuerSettings};

#[derive(Deserialize)]
struct IssuerFixture {
    issuer: String,
    ca_certificate: PathBuf,
    allowed_address: String,
    space_id: String,
    client_id: String,
    client_secret: String,
    sqlite_login: LoginFixture,
    postgres_login: LoginFixture,
}

impl Drop for IssuerFixture {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}

#[derive(Deserialize)]
struct LoginFixture {
    email: String,
    password: String,
}

impl Drop for LoginFixture {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl IssuerFixture {
    fn load() -> Self {
        let path = std::env::var_os("SCOPLEN_ACCEPTANCE_ISSUER_FIXTURE")
            .expect("set the disposable issuer fixture path");
        let bytes = Zeroizing::new(std::fs::read(path).expect("read the issuer fixture"));
        serde_json::from_slice(&bytes).expect("parse the issuer fixture")
    }

    // Drive Auth's public same-origin interaction API until the hosted pages are available.
    async fn authorize(&self, login: &LoginFixture, authorization_url: &[u8]) -> Zeroizing<String> {
        let ca = std::fs::read(&self.ca_certificate).expect("read the issuer CA");
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .tls_certs_merge([reqwest::Certificate::from_pem(&ca).expect("parse the issuer CA")])
            .build()
            .expect("build the browser test client");
        let endpoint =
            url::Url::parse(std::str::from_utf8(authorization_url).expect("OIDC URL is UTF-8"))
                .expect("parse OIDC URL");
        let issuer = url::Url::parse(&self.issuer).expect("parse configured issuer");
        assert_eq!(endpoint.origin(), issuer.origin());
        let origin = issuer.origin().ascii_serialization();
        let payload: std::collections::BTreeMap<_, _> =
            endpoint.query_pairs().into_owned().collect();
        let base = format!("{origin}/v1/auth/oidc-interactions");
        let start = client
            .post(&base)
            .header(header::ORIGIN, &origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&payload).unwrap())
            .send()
            .await
            .unwrap_or_else(|_| panic!("start the Auth browser interaction"));
        assert_eq!(start.status().as_u16(), 201);
        let cookie = Zeroizing::new(
            start
                .headers()
                .get(header::SET_COOKIE)
                .expect("interaction cookie")
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned(),
        );
        let started = interaction_data(start).await;
        let id = started["id"].as_str().expect("interaction identifier");
        assert!(
            id.starts_with("lrq_")
                && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        let send = |step: &str, body: serde_json::Value| {
            client
                .post(format!("{base}/{id}/{step}"))
                .header(header::ORIGIN, &origin)
                .header(header::COOKIE, cookie.as_str())
                .header(header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&body).unwrap())
                .send()
        };
        let identified = interaction_data(
            send("identify", json!({"email":login.email,"method":"password"}))
                .await
                .unwrap_or_else(|_| panic!("identify the test human")),
        )
        .await;
        assert_eq!(identified["next_step"], "password");
        let authenticated = interaction_data(
            send("authenticate", json!({"password":login.password}))
                .await
                .unwrap_or_else(|_| panic!("authenticate the test human")),
        )
        .await;
        assert_eq!(authenticated["next_step"], "consent");
        let approved = interaction_data(
            send("decision", json!({"decision":"approve"}))
                .await
                .unwrap_or_else(|_| panic!("approve the test request")),
        )
        .await;
        Zeroizing::new(approved["redirect_to"].as_str().expect("registered callback").into())
    }
}

async fn interaction_data(response: reqwest::Response) -> serde_json::Value {
    assert!(response.status().is_success(), "Auth interaction returned HTTP {}", response.status());
    let bytes = response.bytes().await.unwrap_or_else(|_| panic!("read Auth interaction"));
    let mut response: serde_json::Value =
        serde_json::from_slice(&bytes).expect("decode Auth interaction");
    response["data"].take()
}

async fn verify_callback(
    tls: &TlsFixture,
    fixture: &IssuerFixture,
    login: &LoginFixture,
    authorization_url: &SecretVec,
    cookie: &str,
) {
    let redirect = fixture.authorize(login, authorization_url.as_bytes()).await;
    let redirect = url::Url::parse(&redirect).expect("parse the returned callback");
    assert_eq!(redirect.origin().ascii_serialization(), ORIGIN);
    let navigation = Zeroizing::new(format!(
        "{}?{}",
        redirect.path(),
        redirect.query().expect("callback query")
    ));
    let callback = visit(tls, &navigation, cookie).await;
    check_callback(&callback, Some(cookie.split_once('=').unwrap().0));
}

async fn activation(f: &Fixture, fixture: &IssuerFixture, login_fixture: &LoginFixture) {
    let tls = TlsFixture::start_with_enterprise_identity(
        f,
        EnterpriseIdentitySettings {
            trusted_issuers: vec![TrustedIssuerSettings {
                issuer: fixture.issuer.clone(),
                addresses: vec![fixture.allowed_address.clone()],
                ca_certificate: Some(fixture.ca_certificate.clone()),
            }],
        },
    )
    .await;
    let owner = actor(f, "deployed-issuer-owner").await;
    let org = create_team(f, &owner).await.id;
    let native = create_team(f, &owner).await.id;
    let browser = login(f, &owner.registration).await;
    assert_native_identity_boundary(&tls, &owner, &browser, org, native).await;
    let draft = save_draft(&tls, &browser, org, &fixture.issuer).await;
    let candidate = ActivationCandidate {
        draft_generation: draft.id,
        space_id: fixture.space_id.clone(),
        credentials: DraftLoginCredentials {
            client_id: SecretVec::new(fixture.client_id.as_bytes().to_vec()),
            client_secret: SecretVec::new(fixture.client_secret.as_bytes().to_vec()),
        },
    }
    .to_json()
    .unwrap();
    let target = ConnectionTarget {
        issuer: fixture.issuer.clone(),
        client_id: fixture.client_id.clone(),
        space_id: fixture.space_id.clone(),
    };
    let path = format!("/api/v1/orgs/{org}/auth-connection/activations");
    let condition = ("If-None-Match", "*");
    let reply =
        send(&tls, &browser, "POST", &path, &start_headers(condition), candidate.as_bytes()).await;
    assert_eq!(reply.status, 201);
    let start = ActivationStarted::from_http_json(
        &reply.body,
        &ActivationContext {
            organization_id: org,
            draft_generation: draft.id,
            expected_revision: ExpectedRevision::Empty,
            target: target.clone(),
        },
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .unwrap();
    let cookie =
        reply.header("set-cookie").expect("Scoplen callback cookie").split(';').next().unwrap();
    verify_callback(&tls, fixture, login_fixture, &start.authorization_url, cookie).await;
    let installed =
        confirm(&tls, &browser, &start.attempt, condition, &Uuid::now_v7().to_string()).await;
    assert_eq!(connection(&installed, org, ConnectionStatus::Active).target, target);
    link_member(f, &tls, fixture, login_fixture, &owner, org).await;
    assert_native_identity_boundary(&tls, &owner, &browser, org, native).await;
}

async fn link_member(
    f: &Fixture,
    tls: &TlsFixture,
    fixture: &IssuerFixture,
    login_fixture: &LoginFixture,
    owner: &Actor,
    org: Uuid,
) {
    let member = actor(f, "deployed-issuer-member").await;
    let (invitation, password, _, _) = issue(f, owner, &member, org, vec![TeamRole::Member]).await;
    let accept = format!("/api/v1/orgs/{org}/invitations/{}/accept", invitation.id);
    let body = TeamInvitationAcceptRequest { password }.to_json().unwrap();
    let key = Uuid::now_v7().to_string();
    assert_eq!(
        call(f, &member, "POST", &accept, body.as_bytes(), &[("Idempotency-Key", &key)])
            .await
            .status,
        200
    );
    let membership = LinkMembership {
        organization_id: org,
        membership_id: current_team(f, &member, org).await.membership.id,
    };
    let original = login(f, &member.registration).await;
    let other_family = login(f, &member.registration).await;
    let (start, cookie) = start_link(tls, &original, membership).await;
    verify_callback(tls, fixture, login_fixture, &start.authorization_url, &cookie).await;
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);
    let key = Uuid::now_v7().to_string();
    confirm_link(tls, &other_family, &start.attempt, &key).await.problem(
        404,
        "organization.not_found",
        false,
    );
    let confirmed = confirm_link(tls, &original, &start.attempt, &key).await;
    assert_eq!(confirmed.status, 201);
    let link =
        MemberLink::from_http_json(&confirmed.body, membership, metadata(&confirmed)).unwrap();
    let root = format!("/api/v1/orgs/{org}/auth-link");
    let status = send(tls, &original, "GET", &root, &[], &[]).await;
    assert_eq!(status.status, 200);
    assert_eq!(
        SelfLinkStatus::from_http_json(&status.body, membership, metadata(&status))
            .unwrap()
            .status
            .link,
        Some(link.clone())
    );
    let removed = send(
        tls,
        &original,
        "DELETE",
        &root,
        &[("Origin", ORIGIN), ("If-Match", &link.etag())],
        &[],
    )
    .await;
    assert_eq!(removed.status, 204);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_links").await, 0);
    assert_eq!(current_team(f, &member, org).await.membership.id, membership.membership_id);
}

#[tokio::test]
#[ignore = "requires a disposable independently deployed HTTPS issuer and registered confidential application"]
async fn sqlite_deployed_issuer_native_boundary() {
    let fixture = IssuerFixture::load();
    let directory = directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("owned SQLite");
    let f = Fixture::start(AuthBackend::Sqlite(Arc::new(store)), directory).await;
    activation(&f, &fixture, &fixture.sqlite_login).await;
    f.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
#[ignore = "requires a disposable independently deployed HTTPS issuer and registered confidential application"]
async fn postgres_deployed_issuer_native_boundary() {
    let fixture = IssuerFixture::load();
    let (store, admin, schema, _) = crate::account_entry::tests::postgres_fixture().await;
    let f = Fixture::start(AuthBackend::Postgres(Arc::new(store)), directory()).await;
    activation(&f, &fixture, &fixture.postgres_login).await;
    f.close().await;
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
