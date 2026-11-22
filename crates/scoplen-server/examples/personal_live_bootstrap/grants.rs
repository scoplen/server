// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine HTTPS Grant acceptance; no database seeds or exported credentials.

use std::fmt::Write as _;

use scoplen_api::{
    ProblemDetails,
    auth::AuthTokenResponse,
    certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateTargets},
    grant::{GrantCreateRequest, GrantFields, GrantPage, GrantReplaceRequest, GrantResource},
    group_policy::{
        PolicyCreateRequest, PolicyFields, PolicyResource, SimpleRule, SimpleRuleInput,
        SimpleRuleSelector, SimpleRuleSubject,
    },
    inventory::{InventoryResource, InventoryType},
    organization::OrganizationListQuery,
    sync::{
        SessionVault, SyncOrganizationViewQuery, SyncOrganizationViewResponse, SyncSessionRequest,
        SyncSessionResponse,
    },
    team::{TeamMemberStatus, TeamRole},
    user_ca::{UserCaCreateRequest, UserCaResource},
};
use scoplen_crypto::random_key;
use scoplen_model::ObjectType;
use serde_json::{Value, json};
use ssh_key::{Certificate, PublicKey, certificate::CertType, private::Ed25519Keypair};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Registration,
    audit::{Actor, Browser, Reply, create_team, exchange, invite, member, native, update_member},
};
use crate::{Https, Result};

#[path = "grants_handoff.rs"]
mod handoff;
#[path = "inventory_import.rs"]
mod inventory_import;
#[path = "requests.rs"]
mod requests;

pub(super) async fn verify_inventory_import(
    https: &Https,
    source: crate::InventoryImportSource,
) -> Result<()> {
    inventory_import::verify(https, source).await
}

pub(super) async fn verify_requests(https: &Https) -> Result<()> {
    requests::verify(https).await
}

/// Verify the smallest genuine two-tenant negative matrix used by D-126.
///
/// This deliberately uses two newly registered Accounts and two newly created
/// Organizations. It proves that inventory reads resolve the durable tenant,
/// that absent and foreign objects share the same public boundary, and that
/// removing one membership withdraws only that Organization's view.
#[allow(clippy::too_many_lines)]
pub(super) async fn verify_tenant_isolation(https: &Https) -> Result<()> {
    println!("Tenant isolation acceptance: two Accounts and two Organizations");
    let first = Registration::new(&https.origin)?;
    first.register(https).await?;
    let second = Registration::new(&https.origin)?;
    second.register(https).await?;
    let first_token = first.device.refresh(https, first.device.authenticate(https).await?).await?;
    let second_token =
        second.device.refresh(https, second.device.authenticate(https).await?).await?;
    let first_browser = Browser::login(https, &first).await?;
    let second_browser = Browser::login(https, &second).await?;
    let first_actor = native(&first, &first_token);
    let second_actor = native(&second, &second_token);
    let first_personal = super::host(first.device.id)?;
    let second_personal = super::host(second.device.id)?;
    super::upload(
        https,
        &first.device,
        &first_token,
        first.payload.personal_vault_id,
        &first.vault_key,
        &first_personal,
        None,
    )
    .await?;
    super::upload(
        https,
        &second.device,
        &second_token,
        second.payload.personal_vault_id,
        &second.vault_key,
        &second_personal,
        None,
    )
    .await?;
    let first_org = create_team(https, first_actor).await?;
    let second_org = create_team(https, second_actor).await?;
    let first_host = asset(
        https,
        first_browser.actor(),
        first_org.id,
        InventoryType::Host,
        json!({"name":"First tenant host","address":"first.example.test"}),
    )
    .await?;
    let second_host = asset(
        https,
        second_browser.actor(),
        second_org.id,
        InventoryType::Host,
        json!({"name":"Second tenant host","address":"second.example.test"}),
    )
    .await?;
    let absent = Uuid::now_v7();
    policy(
        https,
        first_actor,
        first_org.id,
        format!(
            "permit(principal, action == Action::\"view_inventory\", resource == Host::\"{}\");",
            first_host.id
        ),
    )
    .await?;
    for (actor, foreign_org, foreign_host) in
        [(first_actor, second_org.id, second_host.id), (second_actor, first_org.id, first_host.id)]
    {
        let foreign = problem(
            &exchange(
                https,
                actor,
                "GET",
                &format!("/api/v1/orgs/{foreign_org}/hosts/{foreign_host}"),
                &[],
                &[],
                404,
            )
            .await?,
            404,
            "organization.not_found",
        )?;
        let missing = problem(
            &exchange(
                https,
                actor,
                "GET",
                &format!("/api/v1/orgs/{foreign_org}/hosts/{absent}"),
                &[],
                &[],
                404,
            )
            .await?,
            404,
            "organization.not_found",
        )?;
        if foreign != missing {
            return Err("foreign and absent inventory reads disclose different facts");
        }
    }

    let membership =
        invite(https, first_actor, second_browser.actor(), &second, first_org.id).await?;
    rule(
        https,
        first_actor,
        first_org.id,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector {
                object_type: ObjectType::HOST,
                id: first_host.id,
            }],
        },
    )
    .await?;
    let visible = exchange(
        https,
        second_actor,
        "GET",
        &format!("/api/v1/orgs/{}/hosts/{}", first_org.id, first_host.id),
        &[],
        &[],
        200,
    )
    .await?;
    inventory(&visible, InventoryType::Host, first_host.id)?;
    let (vault, view) = organization_view(https, &second, &second_token, first_org.id).await?;
    if !view.objects.iter().any(|change| change.object_id == first_host.id) {
        return Err("authorized member view omitted its permitted Host");
    }
    let old_revision =
        vault.organization.ok_or("Organization vault context missing")?.view_revision;
    let _revision_policy = rule(
        https,
        first_actor,
        first_org.id,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector {
                object_type: ObjectType::HOST,
                id: first_host.id,
            }],
        },
    )
    .await?;
    let stale_path =
        format!("/sync/v1/vaults/{}/view?revision={old_revision}&after=0&limit=100", vault.id);
    let stale = https
        .exchange(
            "GET",
            &stale_path,
            &[],
            Some((&second.device.keys.signing, Some(second_token.access_token.as_str()))),
            409,
        )
        .await?;
    let stale_problem = scoplen_api::ProblemDetails::from_cbor(&stale)
        .map_err(|_| "stale Organization view problem invalid")?;
    if stale_problem.code.as_str() != "sync.view_changed" {
        return Err("policy-only Organization view change used the wrong error");
    }
    let _ = organization_view(https, &second, &second_token, first_org.id).await?;
    let trust = ca(https, first_actor, first_org.id).await?;
    let connect_request = request(CertificateTargets::Hosts(vec![first_host.id]))?;
    deny_sign(https, second_actor, first_org.id, &connect_request, Uuid::now_v7(), 403).await?;
    let foreign_grant = GrantCreateRequest {
        id: Uuid::now_v7(),
        fields: GrantFields {
            membership: second_org.membership.id,
            host: first_host.id,
            remote_user: "operator".into(),
            valid_from: 0,
            valid_until: None,
        },
    }
    .to_json()
    .map_err(|_| "foreign Grant reference request invalid")?;
    problem(
        &exchange(
            https,
            first_actor,
            "POST",
            &format!("/api/v1/orgs/{}/grants", first_org.id),
            &foreign_grant,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
            400,
        )
        .await?,
        400,
        "organization.invalid_request",
    )?;

    let current = member(https, first_actor, first_org.id, membership).await?;
    exchange(
        https,
        first_actor,
        "DELETE",
        &format!("/api/v1/orgs/{}/members/{membership}", first_org.id),
        &[],
        &[("If-Match", &current.etag)],
        204,
    )
    .await?;
    problem(
        &exchange(
            https,
            second_actor,
            "GET",
            &format!("/api/v1/orgs/{}/hosts/{}", first_org.id, first_host.id),
            &[],
            &[],
            404,
        )
        .await?,
        404,
        "organization.not_found",
    )?;
    let _ = https
        .exchange(
            "GET",
            &format!(
                "/sync/v1/vaults/{}/view?revision={}&after=0&limit=100",
                vault.id,
                vault.organization.ok_or("Organization vault context missing")?.view_revision
            ),
            &[],
            Some((&second.device.keys.signing, Some(second_token.access_token.as_str()))),
            404,
        )
        .await?;
    let (remaining_vault, _) =
        organization_view(https, &second, &second_token, second_org.id).await?;
    if remaining_vault.organization.ok_or("second Organization context missing")?.organization
        != second_org.id
    {
        return Err("membership removal affected the wrong Organization");
    }
    super::download(
        https,
        &second.device,
        &second_token,
        (second.payload.personal_vault_id, &second.vault_key),
        &second.device,
        &second_personal,
        1,
    )
    .await?;
    let _ = trust;
    println!(
        "Tenant isolation acceptance: foreign/absent inventory, scoped view and membership removal passed"
    );
    Ok(())
}

async fn organization_view(
    https: &Https,
    account: &Registration,
    token: &AuthTokenResponse,
    organization: Uuid,
) -> Result<(SessionVault, SyncOrganizationViewResponse)> {
    let body = SyncSessionRequest {
        client_version: "0.1.0".into(),
        model_version: 1,
        device_id: account.device.id,
    }
    .to_cbor()
    .map_err(|_| "tenant isolation session request invalid")?;
    let proof = Some((&account.device.keys.signing, Some(token.access_token.as_str())));
    let bytes = https.exchange("POST", "/sync/v1/session", &body, proof, 200).await?;
    let session = SyncSessionResponse::from_cbor(&bytes)
        .map_err(|_| "tenant isolation session response invalid")?;
    let vault = session
        .vaults
        .into_iter()
        .find(|vault| {
            vault.organization.is_some_and(|context| context.organization == organization)
        })
        .ok_or("tenant isolation Organization vault missing")?;
    let source = vault.organization.ok_or("tenant isolation Organization context missing")?;
    let query =
        SyncOrganizationViewQuery { view_revision: source.view_revision, after: 0, limit: 100 };
    let path = format!(
        "/sync/v1/vaults/{}/view?{}",
        vault.id,
        query.to_query().map_err(|_| "tenant isolation view query invalid")?
    );
    let bytes = https.exchange("GET", &path, &[], proof, 200).await?;
    let view = SyncOrganizationViewResponse::from_cbor(&bytes)
        .map_err(|_| "tenant isolation view response invalid")?;
    view.validate_for_query(source, vault.id, &query)
        .map_err(|_| "tenant isolation view source differs")?;
    Ok((vault, view))
}

pub(super) async fn prepare_client(
    https: &Https,
    directory: &std::path::Path,
    openssh_descriptor: &std::path::Path,
    import_inventory: Option<crate::InventoryImportSource>,
) -> Result<()> {
    handoff::prepare(https, directory, openssh_descriptor, import_inventory).await
}

pub(super) async fn prepare_request_client(
    https: &Https,
    directory: &std::path::Path,
    openssh_descriptor: &std::path::Path,
) -> Result<()> {
    handoff::prepare_request_client(https, directory, openssh_descriptor).await
}

pub(super) async fn prepare_snippet_client(
    https: &Https,
    directory: &std::path::Path,
    openssh_descriptor: &std::path::Path,
) -> Result<()> {
    handoff::prepare_snippet_client(https, directory, openssh_descriptor).await
}

struct Created {
    request: GrantCreateRequest,
    key: String,
    original: Zeroizing<Vec<u8>>,
    resource: GrantResource,
}

fn grant(reply: &Reply) -> Result<GrantResource> {
    GrantResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Grant acceptance Resource invalid")
}

fn problem(reply: &Reply, status: u16, code: &str) -> Result<ProblemDetails> {
    let mut value = ProblemDetails::from_json(&reply.body, 4_096)
        .map_err(|_| "Grant acceptance problem invalid")?;
    if value.status != status
        || value.code.as_str() != code
        || value.changed
        || value.retryable
        || reply.header("etag").is_some()
    {
        return Err("Grant acceptance denial profile differs");
    }
    value.instance.clear();
    Ok(value)
}

async fn create(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    fields: GrantFields,
) -> Result<Created> {
    let request = GrantCreateRequest { id: Uuid::now_v7(), fields };
    let body = request.to_json().map_err(|_| "Grant acceptance create request invalid")?;
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/grants"),
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    let resource = grant(&reply)?;
    resource.validate_for_create(&request).map_err(|_| "Grant creation context differs")?;
    Ok(Created { request, key, original: reply.body, resource })
}

async fn confirm(https: &Https, actor: Actor<'_>, org: Uuid, created: &Created) -> Result<()> {
    let body = created.request.to_json().map_err(|_| "Grant confirmation request invalid")?;
    let reply = exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/grants"),
        &body,
        &[("Idempotency-Key", &created.key)],
        201,
    )
    .await?;
    if grant(&reply)? != created.resource || reply.body != created.original {
        return Err("Grant confirmation changed original bytes");
    }
    Ok(())
}

async fn replace(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    current: &GrantResource,
    fields: GrantFields,
) -> Result<GrantResource> {
    let body = GrantReplaceRequest { fields: fields.clone() }
        .to_json()
        .map_err(|_| "Grant replacement request invalid")?;
    let reply = exchange(
        https,
        actor,
        "PUT",
        &format!("/api/v1/orgs/{org}/grants/{}", current.id),
        &body,
        &[("If-Match", &current.etag)],
        200,
    )
    .await?;
    let updated = grant(&reply)?;
    updated.validate_for_id(current.id).map_err(|_| "Grant replacement id differs")?;
    updated.validate_for_fields(&fields).map_err(|_| "Grant replacement fields differ")?;
    if updated.created_at != current.created_at
        || (updated.fields == current.fields && updated != *current)
        || (updated.fields != current.fields && updated.etag == current.etag)
    {
        return Err("Grant replacement metadata differs");
    }
    Ok(updated)
}

async fn withdraw(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    current: &GrantResource,
) -> Result<()> {
    exchange(
        https,
        actor,
        "DELETE",
        &format!("/api/v1/orgs/{org}/grants/{}", current.id),
        &[],
        &[("If-Match", &current.etag)],
        204,
    )
    .await?;
    Ok(())
}

async fn missing(https: &Https, actor: Actor<'_>, org: Uuid, id: Uuid) -> Result<ProblemDetails> {
    problem(
        &exchange(https, actor, "GET", &format!("/api/v1/orgs/{org}/grants/{id}"), &[], &[], 404)
            .await?,
        404,
        "organization.not_found",
    )
}

async fn list(https: &Https, actor: Actor<'_>, org: Uuid) -> Result<Vec<GrantResource>> {
    let mut query = OrganizationListQuery { limit: 2, cursor: None };
    let mut items = Vec::new();
    for _ in 0..4 {
        let mut path = format!("/api/v1/orgs/{org}/grants?limit=2");
        if let Some(cursor) = query.cursor {
            write!(path, "&cursor={cursor}").map_err(|_| "Grant Page query encoding failed")?;
        }
        let reply = exchange(https, actor, "GET", &path, &[], &[], 200).await?;
        if reply.header("etag").is_some() {
            return Err("Grant Page disclosed a Resource validator");
        }
        let page = GrantPage::from_http_json(
            &reply.body,
            reply.header("cache-control"),
            reply.header("pragma"),
        )
        .map_err(|_| "Grant Page invalid")?;
        page.validate_for_query(query).map_err(|_| "Grant Page continuation differs")?;
        items.extend(page.items);
        query.cursor = page.next_cursor;
        if query.cursor.is_none() {
            return Ok(items);
        }
    }
    Err("Grant acceptance Page exceeded its expected finite inventory")
}

async fn asset(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    kind: InventoryType,
    fields: Value,
) -> Result<InventoryResource> {
    let id = Uuid::now_v7();
    let body = serde_json::to_vec(&json!({"id":id,"data":{"fields":fields}}))
        .map_err(|_| "Grant acceptance inventory request invalid")?;
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/{}", kind.segment()),
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    inventory(&reply, kind, id)
}

fn inventory(reply: &Reply, kind: InventoryType, id: Uuid) -> Result<InventoryResource> {
    let value = InventoryResource::from_http_json(
        kind,
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Grant acceptance inventory Resource invalid")?;
    value
        .validate_for_request(kind, id)
        .map_err(|_| "Grant acceptance inventory context differs")?;
    Ok(value)
}

async fn policy(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    source: String,
) -> Result<PolicyResource> {
    let id = Uuid::now_v7();
    let body = PolicyCreateRequest {
        id,
        fields: PolicyFields { name: "Grant HTTPS acceptance".into(), source, enabled: true },
    }
    .to_json()
    .map_err(|_| "Grant acceptance policy request invalid")?;
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/policies"),
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    let value = PolicyResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Grant acceptance policy Resource invalid")?;
    value.validate_for_request(org, id).map_err(|_| "Grant acceptance policy context differs")?;
    Ok(value)
}

async fn rule(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    membership: Uuid,
    rule: SimpleRule,
) -> Result<PolicyResource> {
    let source = SimpleRuleInput {
        organization: org,
        subject: SimpleRuleSubject::Membership(membership),
        rule,
    }
    .generate()
    .map_err(|_| "Grant acceptance simple rule invalid")?;
    policy(https, actor, org, source).await
}

async fn ca(https: &Https, actor: Actor<'_>, org: Uuid) -> Result<UserCaResource> {
    let id = Uuid::now_v7();
    let body =
        UserCaCreateRequest { id }.to_json().map_err(|_| "Grant acceptance CA request invalid")?;
    let key = Uuid::now_v7().to_string();
    let reply = exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/certificate-authorities"),
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    let value = UserCaResource::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Grant acceptance CA Resource invalid")?;
    if value.id != id {
        return Err("Grant acceptance CA id differs");
    }
    Ok(value)
}

fn request(targets: CertificateTargets) -> Result<CertificateIssuanceRequest> {
    let seed = random_key().map_err(|_| "Grant acceptance subject generation failed")?;
    let public = PublicKey::new(Ed25519Keypair::from_seed(seed.as_bytes()).public.into(), "")
        .to_openssh()
        .map_err(|_| "Grant acceptance public subject invalid")?;
    CertificateIssuanceRequest::new(public, targets, "deploy", 86_400)
        .map_err(|_| "Grant acceptance certificate request invalid")
}

async fn sign(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    request: &CertificateIssuanceRequest,
    key: Uuid,
    expected: u16,
) -> Result<Reply> {
    let body = request.to_json().map_err(|_| "Grant acceptance issuance body invalid")?;
    exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/certificates"),
        &body,
        &[("Idempotency-Key", &key.to_string())],
        expected,
    )
    .await
}

fn issued(
    reply: &Reply,
    request: &CertificateIssuanceRequest,
    ca: &UserCaResource,
    org: Uuid,
    requester: &Registration,
    cap: Option<u64>,
) -> Result<()> {
    let response = CertificateIssuanceResponse::from_http_json(
        &reply.body,
        reply.header("etag"),
        reply.header("cache-control"),
        reply.header("pragma"),
    )
    .map_err(|_| "Grant acceptance certificate Resource invalid")?;
    response.validate_request_subject(request).map_err(|_| "Grant certificate subject differs")?;
    let certificate = Certificate::from_openssh(&response.certificate)
        .map_err(|_| "Grant acceptance SSH certificate invalid")?;
    certificate.verify_signature().map_err(|_| "Grant certificate signature invalid")?;
    let trusted = PublicKey::from_openssh(&ca.public_key)
        .map_err(|_| "Grant acceptance trusted CA invalid")?;
    let (kind, ids) = match &request.targets {
        CertificateTargets::Hosts(ids) => ("h", ids),
        CertificateTargets::HostGroups(ids) => ("g", ids),
    };
    let principals: Vec<_> =
        ids.iter().map(|id| format!("spl:{org}:{kind}:{id}:{}", request.remote_user)).collect();
    let key_id = format!(
        "spl:{org}:{}:{}:{}",
        requester.payload.account_id, requester.device.id, response.id
    );
    let lifetime = certificate
        .valid_before()
        .checked_sub(certificate.valid_after())
        .ok_or("Grant certificate validity reversed")?;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| "Grant certificate verification clock invalid")?;
    if certificate.cert_type() != CertType::User
        || certificate.signature_key() != trusted.key_data()
        || certificate.key_id() != key_id
        || certificate.valid_principals() != principals
        || certificate.valid_after() > now
        || certificate.valid_before() <= now
        || lifetime == 0
        || lifetime > 1_860
        || cap.is_some_and(|end| certificate.valid_before() != end)
        || (cap.is_none() && lifetime != 1_860)
        || !certificate.critical_options().is_empty()
        || certificate.extensions().len() != 2
        || certificate.extensions().get("permit-pty").map(String::as_str) != Some("")
        || certificate.extensions().get("org@scoplen.com") != Some(&org.to_string())
    {
        return Err("Grant certificate trust, scope or expiry differs");
    }
    Ok(())
}

async fn deny_sign(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    request: &CertificateIssuanceRequest,
    key: Uuid,
    status: u16,
) -> Result<()> {
    problem(
        &sign(https, actor, org, request, key, status).await?,
        status,
        if status == 403 { "policy.denied" } else { "organization.not_found" },
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn bounded(
    https: &Https,
    owner: &Registration,
    owner_actor: Actor<'_>,
    owner_browser: &mut Browser,
    recipient: &Registration,
    recipient_actor: Actor<'_>,
    recipient_browser: &Browser,
) -> Result<(Uuid, Uuid, Uuid)> {
    println!("Grant acceptance: browser management and bounded certificate authority");
    let org = create_team(https, owner_actor).await?.id;
    let membership =
        invite(https, owner_browser.actor(), recipient_browser.actor(), recipient, org).await?;
    let trust = ca(https, owner_actor, org).await?;
    let group = asset(
        https,
        owner_browser.actor(),
        org,
        InventoryType::HostGroup,
        json!({"name":"Grant targets"}),
    )
    .await?;
    let first = asset(
        https,
        owner_actor,
        org,
        InventoryType::Host,
        json!({"name":"First Grant target","address":"first.example.test",
            "groups":{group.id.to_string():true}}),
    )
    .await?;
    let second = asset(
        https,
        owner_actor,
        org,
        InventoryType::Host,
        json!({"name":"Second Grant target","address":"second.example.test",
            "groups":{group.id.to_string():true}}),
    )
    .await?;
    rule(
        https,
        owner_browser.actor(),
        org,
        membership,
        SimpleRule::View {
            resources: vec![
                SimpleRuleSelector { object_type: ObjectType::HOST, id: first.id },
                SimpleRuleSelector { object_type: ObjectType::HOST, id: second.id },
                SimpleRuleSelector { object_type: ObjectType::HOST_GROUP, id: group.id },
            ],
        },
    )
    .await?;
    inventory(
        &exchange(
            https,
            recipient_actor,
            "GET",
            &format!("/api/v1/orgs/{org}/hosts/{}", first.id),
            &[],
            &[],
            200,
        )
        .await?,
        InventoryType::Host,
        first.id,
    )?;
    let single = request(CertificateTargets::Hosts(vec![first.id]))?;
    // Ten issuance calls for this Account; production admission remains unchanged.
    deny_sign(https, recipient_actor, org, &single, Uuid::now_v7(), 403).await?;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| "Grant acceptance clock invalid")?;
    let fields = GrantFields {
        membership,
        host: first.id,
        remote_user: "deploy".into(),
        valid_from: 0,
        valid_until: Some(now + 600),
    };
    let first_grant = create(https, owner_browser.actor(), org, fields.clone()).await?;
    let key = Uuid::now_v7();
    let original = sign(https, recipient_actor, org, &single, key, 201).await?;
    issued(&original, &single, &trust, org, recipient, Some(now + 600))?;
    let confirmation = sign(https, recipient_actor, org, &single, key, 201).await?;
    issued(&confirmation, &single, &trust, org, recipient, Some(now + 600))?;
    if confirmation.body != original.body {
        return Err("Grant certificate confirmation renewed or changed its original");
    }
    owner_browser.refresh(https).await?;
    confirm(https, owner_browser.actor(), org, &first_grant).await?;
    let other_family = Browser::login(https, owner).await?;
    let body = first_grant.request.to_json().map_err(|_| "Grant family request invalid")?;
    problem(
        &exchange(
            https,
            other_family.actor(),
            "POST",
            &format!("/api/v1/orgs/{org}/grants"),
            &body,
            &[("Idempotency-Key", &first_grant.key)],
            409,
        )
        .await?,
        409,
        "organization.conflict",
    )?;
    let changed = GrantFields { valid_until: Some(now + 650), ..fields.clone() };
    let replaced =
        replace(https, owner_browser.actor(), org, &first_grant.resource, changed.clone()).await?;
    let put = GrantReplaceRequest { fields: changed.clone() }
        .to_json()
        .map_err(|_| "Grant stale request invalid")?;
    let path = format!("/api/v1/orgs/{org}/grants/{}", replaced.id);
    problem(
        &exchange(https, recipient_browser.actor(), "PUT", &path, &put, &[], 403).await?,
        403,
        "policy.denied",
    )?;
    problem(
        &exchange(
            https,
            owner_browser.actor(),
            "PUT",
            &path,
            &put,
            &[("If-Match", &first_grant.resource.etag)],
            412,
        )
        .await?,
        412,
        "organization.precondition_failed",
    )?;
    replace(https, owner_browser.actor(), org, &replaced, changed).await?;
    let later = create(
        https,
        owner_browser.actor(),
        org,
        GrantFields { valid_until: Some(now + 1_200), ..fields.clone() },
    )
    .await?;
    issued(
        &sign(https, recipient_actor, org, &single, Uuid::now_v7(), 201).await?,
        &single,
        &trust,
        org,
        recipient,
        Some(now + 1_200),
    )?;
    let other = create(
        https,
        owner_browser.actor(),
        org,
        GrantFields { host: second.id, valid_until: Some(now + 900), ..fields },
    )
    .await?;
    let multiple = request(CertificateTargets::Hosts(vec![first.id, second.id]))?;
    issued(
        &sign(https, recipient_actor, org, &multiple, Uuid::now_v7(), 201).await?,
        &multiple,
        &trust,
        org,
        recipient,
        Some(now + 900),
    )?;
    deny_sign(
        https,
        recipient_actor,
        org,
        &request(CertificateTargets::HostGroups(vec![group.id]))?,
        Uuid::now_v7(),
        403,
    )
    .await?;
    let mut expected = vec![replaced.clone(), later.resource.clone(), other.resource.clone()];
    expected.sort_by_key(|value| value.id);
    if list(https, owner_actor, org).await? != expected
        || list(https, owner_browser.actor(), org).await? != expected
        || grant(&exchange(https, owner_actor, "GET", &path, &[], &[], 200).await?)? != replaced
    {
        return Err("Grant Device/browser reads or pagination differ");
    }
    let ordinary = rule(
        https,
        owner_browser.actor(),
        org,
        membership,
        SimpleRule::Connect {
            hosts: vec![first.id, second.id],
            host_groups: vec![],
            remote_user: "deploy".into(),
        },
    )
    .await?;
    let ordinary_key = Uuid::now_v7();
    issued(
        &sign(https, recipient_actor, org, &single, ordinary_key, 201).await?,
        &single,
        &trust,
        org,
        recipient,
        None,
    )?;
    let forbid = policy(
        https,
        owner_browser.actor(),
        org,
        "forbid(principal, action == Action::\"connect\", resource);".into(),
    )
    .await?;
    deny_sign(https, recipient_actor, org, &single, ordinary_key, 403).await?;
    for current in [&forbid, &ordinary] {
        exchange(
            https,
            owner_browser.actor(),
            "DELETE",
            &format!("/api/v1/orgs/{org}/policies/{}", current.id),
            &[],
            &[("If-Match", &current.etag)],
            204,
        )
        .await?;
    }
    for current in [&replaced, &later.resource, &other.resource] {
        withdraw(https, owner_browser.actor(), org, current).await?;
    }
    missing(https, owner_browser.actor(), org, replaced.id).await?;
    confirm(https, owner_browser.actor(), org, &first_grant).await?;
    missing(https, owner_actor, org, replaced.id).await?;
    if !list(https, owner_actor, org).await?.is_empty() {
        return Err("Grant withdrawal retained current list authority");
    }
    deny_sign(https, recipient_actor, org, &single, key, 403).await?;
    deny_sign(https, recipient_actor, org, &single, Uuid::now_v7(), 403).await?;
    Ok((org, membership, first_grant.request.id))
}

#[allow(clippy::too_many_lines)]
async fn lifecycle(
    https: &Https,
    manager: Actor<'_>,
    manager_browser: &Browser,
    recipient: &Registration,
    recipient_actor: Actor<'_>,
    recipient_browser: &Browser,
    foreign: (Uuid, Uuid, Uuid),
) -> Result<()> {
    println!("Grant acceptance: intervals, lifecycle and tenant isolation");
    let org = create_team(https, manager_browser.actor()).await?.id;
    let membership = invite(https, manager, recipient_browser.actor(), recipient, org).await?;
    let trust = ca(https, manager, org).await?;
    let host = asset(
        https,
        manager,
        org,
        InventoryType::Host,
        json!({"name":"Interval target","address":"interval.example.test"}),
    )
    .await?;
    let visibility = rule(
        https,
        manager,
        org,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: host.id }],
        },
    )
    .await?;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| "Grant acceptance clock invalid")?;
    let fields = GrantFields {
        membership,
        host: host.id,
        remote_user: "deploy".into(),
        valid_from: now + 600,
        valid_until: Some(now + 900),
    };
    let future = create(https, manager, org, fields.clone()).await?;
    let single = request(CertificateTargets::Hosts(vec![host.id]))?;
    // Nine calls for this Account and one foreign-team check by the manager; source total twenty.
    deny_sign(https, recipient_actor, org, &single, Uuid::now_v7(), 403).await?;
    let expired = create(
        https,
        manager,
        org,
        GrantFields { valid_from: now - 600, valid_until: Some(now - 300), ..fields.clone() },
    )
    .await?;
    deny_sign(https, recipient_actor, org, &single, Uuid::now_v7(), 403).await?;
    let unlimited = create(
        https,
        manager,
        org,
        GrantFields { valid_from: 0, valid_until: None, ..fields.clone() },
    )
    .await?;
    issued(
        &sign(https, recipient_actor, org, &single, Uuid::now_v7(), 201).await?,
        &single,
        &trust,
        org,
        recipient,
        None,
    )?;
    let wrong_user = CertificateIssuanceRequest { remote_user: "other".into(), ..single.clone() };
    deny_sign(https, recipient_actor, org, &wrong_user, Uuid::now_v7(), 403).await?;
    let current = replace(
        https,
        manager,
        org,
        &unlimited.resource,
        GrantFields { valid_from: 0, valid_until: Some(now + 450), ..fields.clone() },
    )
    .await?;
    issued(
        &sign(https, recipient_actor, org, &single, Uuid::now_v7(), 201).await?,
        &single,
        &trust,
        org,
        recipient,
        Some(now + 450),
    )?;
    let replace_body = GrantReplaceRequest { fields: current.fields.clone() }
        .to_json()
        .map_err(|_| "Grant stale replacement invalid")?;
    problem(
        &exchange(
            https,
            manager,
            "PUT",
            &format!("/api/v1/orgs/{org}/grants/{}", current.id),
            &replace_body,
            &[("If-Match", &unlimited.resource.etag)],
            412,
        )
        .await?,
        412,
        "organization.precondition_failed",
    )?;
    // Remove the independent policy reference before isolating the Grant deletion guard.
    exchange(
        https,
        manager,
        "DELETE",
        &format!("/api/v1/orgs/{org}/policies/{}", visibility.id),
        &[],
        &[("If-Match", &visibility.etag)],
        204,
    )
    .await?;
    let host_path = format!("/api/v1/orgs/{org}/hosts/{}", host.id);
    let future_host = asset(
        https,
        manager,
        org,
        InventoryType::Host,
        json!({"name":"Future reference target","address":"future.example.test"}),
    )
    .await?;
    let expired_host = asset(
        https,
        manager,
        org,
        InventoryType::Host,
        json!({"name":"Expired reference target","address":"expired.example.test"}),
    )
    .await?;
    let future_current = replace(
        https,
        manager,
        org,
        &future.resource,
        GrantFields { host: future_host.id, ..future.resource.fields.clone() },
    )
    .await?;
    let expired_current = replace(
        https,
        manager,
        org,
        &expired.resource,
        GrantFields { host: expired_host.id, ..expired.resource.fields.clone() },
    )
    .await?;
    for (current, protected) in
        [(&current, &host), (&future_current, &future_host), (&expired_current, &expired_host)]
    {
        let protected_path = format!("/api/v1/orgs/{org}/hosts/{}", protected.id);
        problem(
            &exchange(
                https,
                manager,
                "DELETE",
                &protected_path,
                &[],
                &[("If-Match", &protected.etag)],
                409,
            )
            .await?,
            409,
            "organization.conflict",
        )?;
        withdraw(https, manager, org, current).await?;
        exchange(
            https,
            manager,
            "DELETE",
            &protected_path,
            &[],
            &[("If-Match", &protected.etag)],
            204,
        )
        .await?;
    }
    confirm(https, manager, org, &unlimited).await?;
    missing(https, manager, org, unlimited.request.id).await?;
    problem(
        &exchange(https, manager, "GET", &host_path, &[], &[], 404).await?,
        404,
        "organization.not_found",
    )?;
    let next = asset(
        https,
        manager,
        org,
        InventoryType::Host,
        json!({"name":"Lifecycle target","address":"lifecycle.example.test"}),
    )
    .await?;
    rule(
        https,
        manager,
        org,
        membership,
        SimpleRule::View {
            resources: vec![SimpleRuleSelector { object_type: ObjectType::HOST, id: next.id }],
        },
    )
    .await?;
    let fields = GrantFields { host: next.id, valid_from: 0, valid_until: None, ..fields };
    let original = create(https, manager, org, fields.clone()).await?;
    let foreign_absent = missing(https, manager, foreign.0, Uuid::now_v7()).await?;
    if missing(https, manager, foreign.0, foreign.2).await? != foreign_absent {
        return Err("Grant foreign and absent reads disclose different facts");
    }
    let reused = GrantCreateRequest { id: foreign.2, fields: fields.clone() }
        .to_json()
        .map_err(|_| "Grant reused-id request invalid")?;
    problem(
        &exchange(
            https,
            manager,
            "POST",
            &format!("/api/v1/orgs/{org}/grants"),
            &reused,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
            409,
        )
        .await?,
        409,
        "organization.conflict",
    )?;
    let foreign_ref = GrantCreateRequest {
        id: Uuid::now_v7(),
        fields: GrantFields { membership: foreign.1, ..fields.clone() },
    }
    .to_json()
    .map_err(|_| "Grant foreign-reference request invalid")?;
    problem(
        &exchange(
            https,
            manager,
            "POST",
            &format!("/api/v1/orgs/{org}/grants"),
            &foreign_ref,
            &[("Idempotency-Key", &Uuid::now_v7().to_string())],
            400,
        )
        .await?,
        400,
        "organization.invalid_request",
    )?;
    update_member(
        https,
        manager_browser.actor(),
        org,
        membership,
        TeamRole::Member,
        TeamMemberStatus::Suspended,
    )
    .await?;
    let lifecycle_request = request(CertificateTargets::Hosts(vec![next.id]))?;
    deny_sign(https, recipient_actor, org, &lifecycle_request, Uuid::now_v7(), 404).await?;
    missing(https, manager_browser.actor(), org, original.request.id).await?;
    update_member(
        https,
        manager_browser.actor(),
        org,
        membership,
        TeamRole::Member,
        TeamMemberStatus::Active,
    )
    .await?;
    missing(https, manager, org, original.request.id).await?;
    deny_sign(https, recipient_actor, org, &lifecycle_request, Uuid::now_v7(), 403).await?;
    let fresh = create(https, manager, org, fields).await?;
    let issuance_key = Uuid::now_v7();
    issued(
        &sign(https, recipient_actor, org, &lifecycle_request, issuance_key, 201).await?,
        &lifecycle_request,
        &trust,
        org,
        recipient,
        None,
    )?;
    let current_member = member(https, manager, org, membership).await?;
    exchange(
        https,
        manager_browser.actor(),
        "DELETE",
        &format!("/api/v1/orgs/{org}/members/{membership}"),
        &[],
        &[("If-Match", &current_member.etag)],
        204,
    )
    .await?;
    missing(https, manager, org, fresh.request.id).await?;
    deny_sign(https, recipient_actor, org, &lifecycle_request, issuance_key, 404).await?;
    confirm(https, manager, org, &fresh).await?;
    missing(https, manager, org, fresh.request.id).await?;
    deny_sign(https, manager, foreign.0, &lifecycle_request, Uuid::now_v7(), 404).await?;
    Ok(())
}

pub(super) async fn verify(https: &Https) -> Result<()> {
    println!("Grant acceptance: genuine public Account, Device and browser authentication");
    let owner = Registration::new(&https.origin)?;
    owner.register(https).await?;
    let recipient = Registration::new(&https.origin)?;
    recipient.register(https).await?;
    let manager = Registration::new(&https.origin)?;
    manager.register(https).await?;
    let owner_token = owner.device.authenticate(https).await?;
    let owner_token = owner.device.refresh(https, owner_token).await?;
    let recipient_token = recipient.device.authenticate(https).await?;
    let recipient_token = recipient.device.refresh(https, recipient_token).await?;
    let manager_token = manager.device.authenticate(https).await?;
    let manager_token = manager.device.refresh(https, manager_token).await?;
    let mut owner_browser = Browser::login(https, &owner).await?;
    let recipient_browser = Browser::login(https, &recipient).await?;
    let manager_browser = Browser::login(https, &manager).await?;
    let owner_actor = native(&owner, &owner_token);
    let recipient_actor = native(&recipient, &recipient_token);
    let manager_actor = native(&manager, &manager_token);
    let owner_personal = super::host(owner.device.id)?;
    let recipient_personal = super::host(recipient.device.id)?;
    for (account, token, object) in [
        (&owner, &owner_token, &owner_personal),
        (&recipient, &recipient_token, &recipient_personal),
    ] {
        super::upload(
            https,
            &account.device,
            token,
            account.payload.personal_vault_id,
            &account.vault_key,
            object,
            None,
        )
        .await?;
    }
    let foreign = bounded(
        https,
        &owner,
        owner_actor,
        &mut owner_browser,
        &recipient,
        recipient_actor,
        &recipient_browser,
    )
    .await?;
    lifecycle(https, manager_actor, &manager_browser, &owner, owner_actor, &owner_browser, foreign)
        .await?;
    println!("Grant acceptance: encrypted Personal access remains usable");
    for (account, token, object) in [
        (&owner, &owner_token, &owner_personal),
        (&recipient, &recipient_token, &recipient_personal),
    ] {
        super::download(
            https,
            &account.device,
            token,
            (account.payload.personal_vault_id, &account.vault_key),
            &account.device,
            object,
            1,
        )
        .await?;
    }
    Ok(())
}
