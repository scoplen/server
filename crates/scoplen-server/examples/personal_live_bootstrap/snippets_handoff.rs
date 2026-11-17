// SPDX-License-Identifier: AGPL-3.0-only
//! Browser-authored Snippets and six finite phases for an independent native consumer.

use std::fmt::Write as _;

use scoplen_api::{
    audit::{AuditEvent, AuditOutcome, AuditResource, AuditResourceKind},
    auth::AuthTokenResponse,
    inventory::{InventoryCreateRequest, InventoryFields, InventoryPage, InventoryReplaceRequest},
    organization::OrganizationListQuery,
    sync::{
        SessionVault, SyncOrganizationAckRequest, SyncOrganizationAckResponse,
        SyncOrganizationViewQuery, SyncOrganizationViewResponse, SyncSessionRequest,
        SyncSessionResponse, SyncVersionsResponse,
    },
    user_ca::UserCaPage,
};
use scoplen_model::{Object, validate_uuid_v7};
use serde_json::Value;

use super::super::super::{
    PersonalConsumer,
    audit::{Actor, lose_response, member, replace_policy, timeline},
    write_browser_password,
};
use super::super::problem;
use super::{
    Browser, Duration, GrantFields, Https, InventoryResource, InventoryType, MAX_DESCRIPTOR_BYTES,
    ObjectType, OwnedOpenSsh, Path, PathBuf, Prepared, Registration, Result, SSH_USER, Serialize,
    SimpleRule, SimpleRuleSelector, Uuid, asset, create, create_team, exchange, fs, inventory,
    json, native, prepare_target, read_bounded, rule, write_private,
};

const PHASES: [&str; 6] =
    ["published", "replaced", "view-withdrawn", "restored", "membership-withdrawn", "deleted"];

#[derive(Serialize)]
struct Descriptor<'a> {
    disposable: bool,
    phase: &'a str,
    origin: &'a str,
    ca_certificate: PathBuf,
    member_username: String,
    member_password_file: PathBuf,
    organization_id: Uuid,
    host_id: Uuid,
    profile_id: Uuid,
    snippet_id: Uuid,
    secret_snippet_id: Uuid,
    writer_family_id: Uuid,
    fields: Value,
    secret_fields: Value,
    inputs: std::collections::BTreeMap<String, String>,
    output_marker: String,
}

fn fields(value: &Value) -> Result<InventoryFields> {
    InventoryFields::from_json(
        InventoryType::Snippet,
        &serde_json::to_vec(value).map_err(|_| "Snippet fields encoding failed")?,
    )
    .map_err(|_| "Snippet fields are invalid")
}

fn projection(value: &InventoryFields) -> Result<Value> {
    serde_json::from_slice(&value.to_json().map_err(|_| "Snippet projection encoding failed")?)
        .map_err(|_| "Snippet projection is invalid")
}

fn executable(marker: &str, replaced: bool) -> Result<InventoryFields> {
    if !(2..=128).contains(&marker.len())
        || !marker.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("Snippet output marker is invalid");
    }
    let (first, second) = marker.split_at(marker.len() / 2);
    let format = if replaced { "%s|%s|%s|replaced" } else { "%s|%s|%s" };
    fields(&json!({
        "name": if replaced { "Team command revised" } else { "Team command" },
        "template": format!(
            "printf '%s%s\\n' '{first}' '{second}'; printf '{format}\\n' '{{{{message}}}}' '{{{{count}}}}' '{{{{color}}}}'"
        ),
        "variables": {
            "message": {"kind":1,"default":if replaced {"revised text"} else {"stored text"}},
            "count": {"kind":2,"default":if replaced {"9"} else {"-7"}},
            "color": {"kind":3,"default":if replaced {"green"} else {"blue"},
                "choices":if replaced {json!(["amber","green"])} else {json!(["blue","green"])}}
        },
        "tags": {"acceptance":true,"team":true},
        "folder": if replaced {"Operations/Revised"} else {"Operations"}
    }))
}

fn secret() -> Result<InventoryFields> {
    fields(&json!({
        "name":"Team secret definition",
        "template":"printf '%s' '{{secret}}'",
        "variables":{"secret":{"kind":4}},
        "tags":{"acceptance":true},
        "folder":"Operations"
    }))
}

fn descriptor_json(value: &Descriptor<'_>) -> Result<String> {
    let ids = [
        value.organization_id,
        value.host_id,
        value.profile_id,
        value.snippet_id,
        value.secret_snippet_id,
        value.writer_family_id,
    ];
    if !value.disposable
        || !PHASES.contains(&value.phase)
        || value
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_none_or(|port| port < 1_024)
        || !value.ca_certificate.is_absolute()
        || !value.member_password_file.is_absolute()
        || ids.iter().any(|id| validate_uuid_v7(*id).is_err())
        || ids.iter().enumerate().any(|(index, id)| ids[..index].contains(id))
        || value.member_username.is_empty()
        || value.output_marker.is_empty()
        || value.output_marker.len() > 128
        || !value.output_marker.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value.inputs != inputs()
        || fields(&value.fields)? != executable(&value.output_marker, value.phase != PHASES[0])?
        || fields(&value.secret_fields)? != secret()?
    {
        return Err("Snippet client descriptor context is invalid");
    }
    let text =
        serde_json::to_string(value).map_err(|_| "Snippet client descriptor encoding failed")?;
    // write_private appends one LF, which is part of the complete-file byte budget.
    if text.len() >= MAX_DESCRIPTOR_BYTES {
        return Err("Snippet client descriptor exceeds its bound");
    }
    Ok(text)
}

fn inputs() -> std::collections::BTreeMap<String, String> {
    [("message", "native value"), ("count", "42"), ("color", "green")]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect()
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("Snippet client handoff files already exist; abandon this fixture"),
        Err(_) => Err("could not inspect Snippet client handoff path"),
    }
}

fn completion(signal: &str) -> Result<()> {
    if signal == "passed\n" { Ok(()) } else { Err("Snippet client completion signal is invalid") }
}

async fn phase(directory: &Path, descriptor: &Descriptor<'_>) -> Result<()> {
    let name = descriptor.phase;
    let complete = directory.join(format!("snippet-client-{name}.complete"));
    require_absent(&complete)?;
    write_private(
        &directory.join(format!("snippet-client-{name}.json")),
        &descriptor_json(descriptor)?,
    )?;
    write_private(&directory.join(format!("snippet-client-{name}.ready")), "ready")?;
    println!("Snippet client phase ready: {name}");
    tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            match fs::symlink_metadata(&complete) {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        return Err("Snippet client completion signal is invalid");
                    }
                    return completion(&read_bounded(&complete, 16)?);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => return Err("could not inspect Snippet client completion signal"),
            }
        }
    })
    .await
    .map_err(|_| "Snippet client phase exceeded its deadline; abandon this fixture")?
}

#[derive(Eq, PartialEq)]
struct CurrentView {
    vault: SessionVault,
    view: SyncOrganizationViewResponse,
}

#[derive(Eq, PartialEq)]
struct Snapshot {
    current: CurrentView,
    events: Vec<AuditEvent>,
}

async fn session(
    https: &Https,
    account: &Registration,
    token: &AuthTokenResponse,
) -> Result<SyncSessionResponse> {
    let body = SyncSessionRequest {
        client_version: "0.1.0".into(),
        model_version: 1,
        device_id: account.device.id,
    }
    .to_cbor()
    .map_err(|_| "Snippet session request is invalid")?;
    let bytes = https
        .exchange(
            "POST",
            "/sync/v1/session",
            &body,
            Some((&account.device.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    SyncSessionResponse::from_cbor(&bytes).map_err(|_| "Snippet session response is invalid")
}

async fn current_view(
    https: &Https,
    account: &Registration,
    token: &AuthTokenResponse,
    org: Uuid,
) -> Result<CurrentView> {
    let vault = session(https, account, token)
        .await?
        .vaults
        .into_iter()
        .find(|vault| vault.organization.is_some_and(|source| source.organization == org))
        .ok_or("Snippet current Organization vault is missing")?;
    let source = vault.organization.ok_or("Snippet current Organization source is missing")?;
    let query =
        SyncOrganizationViewQuery { view_revision: source.view_revision, after: 0, limit: 100 };
    let path = format!(
        "/sync/v1/vaults/{}/view?{}",
        vault.id,
        query.to_query().map_err(|_| "Snippet view query is invalid")?
    );
    let bytes = https
        .exchange(
            "GET",
            &path,
            &[],
            Some((&account.device.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let view = SyncOrganizationViewResponse::from_cbor(&bytes)
        .map_err(|_| "Snippet complete current view is invalid")?;
    view.validate_for_query(source, vault.id, &query)
        .map_err(|_| "Snippet current view source differs")?;
    if view.more || view.next_cursor != vault.seq {
        return Err("Snippet current view is incomplete");
    }
    Ok(CurrentView { vault, view })
}

async fn ack(
    https: &Https,
    account: &Registration,
    token: &AuthTokenResponse,
    current: &CurrentView,
) -> Result<()> {
    let request = SyncOrganizationAckRequest {
        cursor: current.view.next_cursor,
        view_revision: current.view.view_revision,
    };
    let bytes = https
        .exchange(
            "POST",
            &format!("/sync/v1/vaults/{}/ack", current.vault.id),
            &request.to_cbor().map_err(|_| "Snippet ACK request is invalid")?,
            Some((&account.device.keys.signing, Some(&token.access_token))),
            200,
        )
        .await?;
    let response = SyncOrganizationAckResponse::from_cbor(&bytes)
        .map_err(|_| "Snippet ACK response is invalid")?;
    response
        .validate_for_request(&request)
        .map_err(|_| "Snippet ACK lost its captured revision and cursor")?;
    if response.cursor != request.cursor {
        return Err("Snippet ACK cursor differs from its complete current view");
    }
    Ok(())
}

struct Context<'a> {
    https: &'a Https,
    owner: &'a Registration,
    token: AuthTokenResponse,
    org: Uuid,
}

impl Context<'_> {
    fn actor(&self) -> Actor<'_> {
        native(self.owner, &self.token)
    }

    async fn refresh(&mut self) -> Result<()> {
        self.token = self.owner.device.refresh(self.https, self.token.clone()).await?;
        Ok(())
    }

    fn path(&self) -> String {
        format!("/api/v1/orgs/{}/snippets", self.org)
    }

    async fn snapshot(&self) -> Result<Snapshot> {
        Ok(Snapshot {
            current: current_view(self.https, self.owner, &self.token, self.org).await?,
            events: timeline(self.https, self.actor(), self.org, 100, None).await?,
        })
    }

    async fn get(&self, actor: Actor<'_>, id: Uuid) -> Result<InventoryResource> {
        inventory(
            &exchange(self.https, actor, "GET", &format!("{}/{id}", self.path()), &[], &[], 200)
                .await?,
            InventoryType::Snippet,
            id,
        )
    }

    async fn list(&self, actor: Actor<'_>) -> Result<Vec<InventoryResource>> {
        let mut items = Vec::new();
        let mut query = OrganizationListQuery { limit: 1, cursor: None };
        for _ in 0..3 {
            let mut path = format!("{}?limit=1", self.path());
            if let Some(cursor) = query.cursor {
                write!(path, "&cursor={cursor}")
                    .map_err(|_| "Snippet Page query encoding failed")?;
            }
            let reply = exchange(self.https, actor, "GET", &path, &[], &[], 200).await?;
            if reply.header("etag").is_some() {
                return Err("Snippet Page disclosed a Resource validator");
            }
            let page = InventoryPage::from_http_json(
                InventoryType::Snippet,
                &reply.body,
                reply.header("cache-control"),
                reply.header("pragma"),
            )
            .map_err(|_| "Snippet Page is invalid")?;
            page.validate_for_request(InventoryType::Snippet, query)
                .map_err(|_| "Snippet Page differs from its captured query")?;
            items.extend(page.items);
            query.cursor = page.next_cursor;
            if query.cursor.is_none() {
                return Ok(items);
            }
        }
        Err("Snippet fixture Page exceeded its finite inventory")
    }

    async fn replace(
        &self,
        actor: Actor<'_>,
        current: &InventoryResource,
        desired: &InventoryFields,
    ) -> Result<InventoryResource> {
        let body = InventoryReplaceRequest { fields: desired.clone() }
            .to_json()
            .map_err(|_| "Snippet replacement request is invalid")?;
        let updated = inventory(
            &exchange(
                self.https,
                actor,
                "PUT",
                &format!("{}/{}", self.path(), current.id),
                &body,
                &[("If-Match", &current.etag)],
                200,
            )
            .await?,
            InventoryType::Snippet,
            current.id,
        )?;
        if updated.fields != *desired || updated.created_at != current.created_at {
            return Err("Snippet replacement changed its desired fields or creation metadata");
        }
        Ok(updated)
    }

    async fn write_ssh_setup(
        &self,
        directory: &Path,
        openssh_descriptor: &Path,
        host: &InventoryResource,
    ) -> Result<()> {
        let ssh = OwnedOpenSsh::load(openssh_descriptor)?;
        ssh.verify().await?;
        let host_fields: Value = serde_json::from_slice(
            &host.fields.to_json().map_err(|_| "Snippet SSH Host fields are invalid")?,
        )
        .map_err(|_| "Snippet SSH Host projection is invalid")?;
        if host_fields["address"] != "127.0.0.1" || host_fields["port"] != ssh.port {
            return Err("Snippet SSH setup differs from its already-published loopback Host");
        }
        let reply = exchange(
            self.https,
            self.actor(),
            "GET",
            &format!("/api/v1/orgs/{}/certificate-authorities?limit=1", self.org),
            &[],
            &[],
            200,
        )
        .await?;
        if reply.header("etag").is_some() {
            return Err("Snippet public CA Page disclosed a Resource validator");
        }
        let page = UserCaPage::from_http_json(
            &reply.body,
            reply.header("cache-control"),
            reply.header("pragma"),
        )
        .map_err(|_| "Snippet public CA Page is invalid")?;
        page.validate_for_query(OrganizationListQuery { limit: 1, cursor: None })
            .map_err(|_| "Snippet public CA query context differs")?;
        let [ca] = page.items.as_slice() else {
            return Err("Snippet SSH target requires exactly one current public CA");
        };
        if page.next_cursor.is_some() {
            return Err("Snippet SSH public CA Page is incomplete");
        }
        let setup = json!({
            "disposable":true,"origin":self.https.origin,
            "container":ssh.container,"owner":ssh.owner,"port":ssh.port,
            "organization_id":self.org,"host_id":host.id,"remote_user":SSH_USER,
            "ca_id":ca.id,"ca_public_key":ca.public_key,"ca_fingerprint":ca.fingerprint,
            "principal":format!("spl:{}:h:{}:{SSH_USER}", self.org, host.id),
        });
        let text = serde_json::to_string(&setup)
            .map_err(|_| "Snippet public SSH setup encoding failed")?;
        if text.len() >= MAX_DESCRIPTOR_BYTES {
            return Err("Snippet public SSH setup exceeds its bound");
        }
        write_private(&directory.join("snippet-client-ssh-setup.json"), &text)
    }
}

fn object(current: &CurrentView, resource: &InventoryResource, family: Uuid) -> Result<Object> {
    let matches: Vec<_> =
        current.view.objects.iter().filter(|change| change.object_id == resource.id).collect();
    let [change] = matches.as_slice() else {
        return Err("Snippet current view does not contain exactly one expected object");
    };
    let object = Object::decode(&change.payload).map_err(|_| "Snippet K-1 object is invalid")?;
    if object.id != resource.id
        || object.object_type != ObjectType::SNIPPET
        || object.tombstone.is_some()
        || object.fields.values().any(|entry| entry.origin != family)
        || InventoryFields::from_object(&object).map_err(|_| "Snippet K-1 fields are invalid")?
            != resource.fields
    {
        return Err("Snippet current K-1 fields or genuine browser origin differs");
    }
    Ok(object)
}

fn effect(
    before: &Snapshot,
    after: &Snapshot,
    resource: &InventoryResource,
    account: Uuid,
    expected_family: Option<Uuid>,
    class: &str,
) -> Result<Uuid> {
    if after.current.vault.id != before.current.vault.id
        || after.current.vault.seq != before.current.vault.seq + 1
        || after.current.view.view_revision != before.current.view.view_revision + 1
        || after.events.len() != before.events.len() + 1
        || !after.events.ends_with(&before.events)
    {
        return Err("Snippet mutation did not commit exactly one sequence, revision and audit");
    }
    let event = &after.events[0];
    let family = event.actor_browser_family_id.ok_or("Snippet audit browser family is absent")?;
    if event.event_class.as_deref() != Some(class)
        || event.outcome != AuditOutcome::Success
        || event.actor_account_id != Some(account)
        || event.actor_device_id.is_some()
        || expected_family.is_some_and(|expected| family != expected)
        || event.resource
            != Some(AuditResource { kind: AuditResourceKind::Snippet, id: resource.id })
    {
        return Err("Snippet audit action, resource or original browser actor differs");
    }
    if class == "organization.inventory_deleted" {
        if after.current.view.objects.iter().any(|change| change.object_id == resource.id) {
            return Err("Deleted Snippet remains in the complete live view");
        }
    } else {
        object(&after.current, resource, family)?;
    }
    Ok(family)
}

struct Created {
    resource: InventoryResource,
    body: Vec<u8>,
    key: String,
    family: Uuid,
}

async fn create_snippet(
    context: &Context<'_>,
    browser: &mut Browser,
    desired: InventoryFields,
    lose_reply: bool,
) -> Result<Created> {
    let request = InventoryCreateRequest { id: Uuid::now_v7(), fields: desired };
    let body = request.to_json().map_err(|_| "Snippet original create request is invalid")?;
    let key = Uuid::now_v7().to_string();
    let path = context.path();
    let before = context.snapshot().await?;
    let lost_reply_state = if lose_reply {
        lose_response(context.https, browser.actor(), &path, &body, &[("Idempotency-Key", &key)])
            .await?;
        let observed = context.snapshot().await?;
        browser.refresh(context.https).await?;
        Some(observed)
    } else {
        None
    };
    // A lost reply permits only explicit confirmation with this retained request context.
    let reply = exchange(
        context.https,
        browser.actor(),
        "POST",
        &path,
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    let resource = inventory(&reply, InventoryType::Snippet, request.id)?;
    if resource.fields != request.fields {
        return Err("Snippet create/confirmation changed its original typed payload");
    }
    let after = context.snapshot().await?;
    if lost_reply_state.is_some_and(|observed| observed != after) {
        return Err("Snippet lost-reply confirmation changed the independently observed state");
    }
    let family = effect(
        &before,
        &after,
        &resource,
        context.owner.payload.account_id,
        None,
        "organization.inventory_created",
    )?;
    browser.refresh(context.https).await?;
    let confirmed = exchange(
        context.https,
        browser.actor(),
        "POST",
        &path,
        &body,
        &[("Idempotency-Key", &key)],
        201,
    )
    .await?;
    if confirmed.body != reply.body
        || inventory(&confirmed, InventoryType::Snippet, request.id)? != resource
        || context.snapshot().await? != after
    {
        return Err("Snippet same-family confirmation changed original bytes or repeated mutation");
    }
    Ok(Created { resource, body, key, family })
}

async fn receipt_refused(context: &Context<'_>, actor: Actor<'_>, created: &Created) -> Result<()> {
    let before = context.snapshot().await?;
    let reply = exchange(
        context.https,
        actor,
        "POST",
        &context.path(),
        &created.body,
        &[("Idempotency-Key", &created.key)],
        409,
    )
    .await?;
    problem(&reply, 409, "organization.conflict")?;
    if context.snapshot().await? != before {
        return Err("Snippet wrong-writer confirmation changed inventory or audit");
    }
    Ok(())
}

async fn missing(context: &Context<'_>, actor: Actor<'_>, id: Uuid) -> Result<()> {
    let reply =
        exchange(context.https, actor, "GET", &format!("{}/{id}", context.path()), &[], &[], 404)
            .await?;
    problem(&reply, 404, "organization.not_found")?;
    Ok(())
}

async fn preconditions(
    context: &Context<'_>,
    actor: Actor<'_>,
    current: &InventoryResource,
    stale: Option<&str>,
) -> Result<()> {
    let before = context.snapshot().await?;
    let body = InventoryReplaceRequest { fields: current.fields.clone() }
        .to_json()
        .map_err(|_| "Snippet precondition request is invalid")?;
    let path = format!("{}/{}", context.path(), current.id);
    let mut cases = vec![(None, 428, "organization.precondition_required")];
    if let Some(stale) = stale {
        cases.push((Some(stale), 412, "organization.precondition_failed"));
    }
    for (etag, status, code) in cases {
        let headers: Vec<_> = etag.into_iter().map(|etag| ("If-Match", etag)).collect();
        let reply = exchange(context.https, actor, "PUT", &path, &body, &headers, status).await?;
        problem(&reply, status, code)?;
    }
    if context.snapshot().await? != before {
        return Err("Snippet precondition refusal changed inventory or audit");
    }
    Ok(())
}

async fn member_delivery(
    context: &Context<'_>,
    personal: &PersonalConsumer,
    browser: &Browser,
    resources: &[&InventoryResource],
    family: Uuid,
    visible: bool,
) -> Result<()> {
    let current =
        current_view(context.https, &personal.account, &personal.first_token, context.org).await?;
    for resource in resources {
        if visible {
            object(&current, resource, family)?;
            if context.get(browser.actor(), resource.id).await? != **resource {
                return Err("Snippet member Resource differs from the delivered complete view");
            }
        } else {
            if current.view.objects.iter().any(|change| change.object_id == resource.id) {
                return Err("Withdrawn Snippet remains in the member's complete current view");
            }
            missing(context, browser.actor(), resource.id).await?;
        }
    }
    let mut expected: Vec<_> = if visible {
        resources.iter().map(|resource| (**resource).clone()).collect()
    } else {
        Vec::new()
    };
    expected.sort_unstable_by_key(|resource| resource.id);
    if context.list(browser.actor()).await? != expected {
        return Err("Snippet member Page does not match current per-object visibility");
    }
    ack(context.https, &personal.account, &personal.first_token, &current).await
}

async fn preserve(
    https: &Https,
    mut personal: PersonalConsumer,
    foreign: &mut Context<'_>,
    original: &Snapshot,
) -> Result<PersonalConsumer> {
    foreign.refresh().await?;
    if foreign.snapshot().await? != *original {
        return Err("Snippet lifecycle changed the unrelated team's public state or audit");
    }
    personal.first_token = personal.account.device.refresh(https, personal.first_token).await?;
    // Independent consumers may enroll more Devices; the preserved data has no fixed device count.
    personal.read_personal_from_original_device(https).await?;
    Ok(personal)
}

async fn history(
    context: &Context<'_>,
    vault: Uuid,
    resources: &[&InventoryResource],
    family: Uuid,
    removed: &PersonalConsumer,
) -> Result<()> {
    let id = resources.last().ok_or("Snippet retained history expectation is empty")?.id;
    let path = format!("/sync/v1/vaults/{vault}/objects/{id}/versions");
    let bytes = context
        .https
        .exchange(
            "GET",
            &path,
            &[],
            Some((&context.owner.device.keys.signing, Some(&context.token.access_token))),
            200,
        )
        .await?;
    let history = SyncVersionsResponse::from_cbor(&bytes)
        .map_err(|_| "Snippet retained history is invalid")?;
    if history.versions.len() != resources.len() + 1 {
        return Err("Snippet retained history has missing or duplicate versions");
    }
    for (index, change) in history.versions.iter().enumerate() {
        let deleted = index == resources.len();
        let expected = resources[index.min(resources.len() - 1)];
        let mut object = Object::decode(&change.payload)
            .map_err(|_| "Snippet retained K-1 history is invalid")?;
        if change.object_id != id
            || object.id != id
            || change.tombstone != deleted
            || object.tombstone.is_some() != deleted
            || object.tombstone.is_some_and(|tombstone| tombstone.origin != family)
            || object.fields.values().any(|entry| entry.origin != family)
        {
            return Err("Snippet retained versions or real tombstone writer differs");
        }
        object.tombstone = None;
        if InventoryFields::from_object(&object)
            .map_err(|_| "Snippet retained field projection is invalid")?
            != expected.fields
        {
            return Err("Snippet deletion rewrote its retained typed history");
        }
    }
    context
        .https
        .exchange(
            "GET",
            &path,
            &[],
            Some((&removed.account.device.keys.signing, Some(&removed.first_token.access_token))),
            404,
        )
        .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn prepare(
    https: &Https,
    directory: &Path,
    openssh_descriptor: &Path,
) -> Result<()> {
    for name in PHASES {
        for suffix in ["json", "ready", "complete"] {
            require_absent(&directory.join(format!("snippet-client-{name}.{suffix}")))?;
        }
    }
    require_absent(&directory.join("snippet-client-member-password.txt"))?;
    require_absent(&directory.join("snippet-client-ssh-setup.json"))?;
    let Prepared { owner, member: account, mut owner_browser, org, membership, host, profile } =
        prepare_target(https, openssh_descriptor).await?;
    let mut personal =
        PersonalConsumer::from_registered(https, account).await?.exchange(https).await?;
    let mut member_browser = Browser::login(https, &personal.account).await?;
    let mut context =
        Context { https, owner: &owner, token: owner.device.authenticate(https).await?, org };
    context.write_ssh_setup(directory, openssh_descriptor, &host).await?;
    let other = Registration::new(&https.origin)?;
    other.register(https).await?;
    let other_browser = Browser::login(https, &other).await?;
    let foreign_org = create_team(https, other_browser.actor()).await?.id;
    asset(
        https,
        other_browser.actor(),
        foreign_org,
        InventoryType::Host,
        json!({"name":"Unrelated team Host","address":"unrelated.example.test"}),
    )
    .await?;
    let mut foreign = Context {
        https,
        owner: &other,
        token: other.device.authenticate(https).await?,
        org: foreign_org,
    };
    let foreign_before = foreign.snapshot().await?;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| "Snippet connect Grant clock is invalid")?;
    create(
        https,
        owner_browser.actor(),
        org,
        GrantFields {
            membership,
            host: host.id,
            remote_user: SSH_USER.into(),
            valid_from: now,
            valid_until: Some(
                now.checked_add(1_800).ok_or("Snippet connect Grant deadline is invalid")?,
            ),
        },
    )
    .await?;
    let marker = format!("scoplen-snippet-{}", Uuid::now_v7());
    let created =
        create_snippet(&context, &mut owner_browser, executable(&marker, false)?, true).await?;
    let secret = create_snippet(&context, &mut owner_browser, secret()?, false).await?;
    if created.family != secret.family {
        return Err("Snippet definitions were not authored by the same genuine browser family");
    }
    let second_family = Browser::login(https, &owner).await?;
    receipt_refused(&context, second_family.actor(), &created).await?;
    receipt_refused(&context, context.actor(), &created).await?;
    missing(&context, other_browser.actor(), created.resource.id).await?;
    missing(&foreign, owner_browser.actor(), created.resource.id).await?;
    preconditions(&context, owner_browser.actor(), &created.resource, None).await?;
    let before_noop = context.snapshot().await?;
    let no_op =
        context.replace(owner_browser.actor(), &created.resource, &created.resource.fields).await?;
    if no_op != created.resource || context.snapshot().await? != before_noop {
        return Err("Snippet equal-value replacement changed ETag, sequence, revision or audit");
    }
    member_delivery(
        &context,
        &personal,
        &member_browser,
        &[&created.resource, &secret.resource],
        created.family,
        false,
    )
    .await?;
    let mut view_policy = rule(
        https,
        owner_browser.actor(),
        org,
        membership,
        SimpleRule::View {
            resources: vec![
                SimpleRuleSelector { object_type: ObjectType::SNIPPET, id: created.resource.id },
                SimpleRuleSelector { object_type: ObjectType::SNIPPET, id: secret.resource.id },
            ],
        },
    )
    .await?;
    let password_file = directory.join("snippet-client-member-password.txt");
    write_browser_password(&password_file, &personal.account.password)?;
    let mut descriptor = Descriptor {
        disposable: true,
        phase: PHASES[0],
        origin: &https.origin,
        ca_certificate: directory.join("ca.pem"),
        member_username: personal.account.payload.username.clone(),
        member_password_file: password_file,
        organization_id: org,
        host_id: host.id,
        profile_id: profile.id,
        snippet_id: created.resource.id,
        secret_snippet_id: secret.resource.id,
        writer_family_id: created.family,
        fields: projection(&created.resource.fields)?,
        secret_fields: projection(&secret.resource.fields)?,
        inputs: inputs(),
        output_marker: marker,
    };
    member_delivery(
        &context,
        &personal,
        &member_browser,
        &[&created.resource, &secret.resource],
        created.family,
        true,
    )
    .await?;
    phase(directory, &descriptor).await?;
    personal = preserve(https, personal, &mut foreign, &foreign_before).await?;

    context.refresh().await?;
    owner_browser.refresh(https).await?;
    member_browser.refresh(https).await?;
    let before = context.snapshot().await?;
    let updated = context
        .replace(
            owner_browser.actor(),
            &created.resource,
            &executable(&descriptor.output_marker, true)?,
        )
        .await?;
    if updated.etag == created.resource.etag {
        return Err("Snippet changed replacement retained its stale Resource validator");
    }
    effect(
        &before,
        &context.snapshot().await?,
        &updated,
        owner.payload.account_id,
        Some(created.family),
        "organization.inventory_updated",
    )?;
    preconditions(&context, owner_browser.actor(), &updated, Some(&created.resource.etag)).await?;
    descriptor.phase = PHASES[1];
    descriptor.fields = projection(&updated.fields)?;
    member_delivery(
        &context,
        &personal,
        &member_browser,
        &[&updated, &secret.resource],
        created.family,
        true,
    )
    .await?;
    phase(directory, &descriptor).await?;
    personal = preserve(https, personal, &mut foreign, &foreign_before).await?;

    context.refresh().await?;
    owner_browser.refresh(https).await?;
    member_browser.refresh(https).await?;
    view_policy = replace_policy(https, owner_browser.actor(), org, view_policy, false).await?;
    member_delivery(
        &context,
        &personal,
        &member_browser,
        &[&updated, &secret.resource],
        created.family,
        false,
    )
    .await?;
    descriptor.phase = PHASES[2];
    phase(directory, &descriptor).await?;
    personal = preserve(https, personal, &mut foreign, &foreign_before).await?;

    context.refresh().await?;
    owner_browser.refresh(https).await?;
    member_browser.refresh(https).await?;
    replace_policy(https, owner_browser.actor(), org, view_policy, true).await?;
    member_delivery(
        &context,
        &personal,
        &member_browser,
        &[&updated, &secret.resource],
        created.family,
        true,
    )
    .await?;
    descriptor.phase = PHASES[3];
    phase(directory, &descriptor).await?;
    personal = preserve(https, personal, &mut foreign, &foreign_before).await?;

    context.refresh().await?;
    owner_browser.refresh(https).await?;
    member_browser.refresh(https).await?;
    let current = member(https, owner_browser.actor(), org, membership).await?;
    exchange(
        https,
        owner_browser.actor(),
        "DELETE",
        &format!("/api/v1/orgs/{org}/members/{membership}"),
        &[],
        &[("If-Match", &current.etag)],
        204,
    )
    .await?;
    if session(https, &personal.account, &personal.first_token)
        .await?
        .vaults
        .iter()
        .any(|vault| vault.organization.is_some_and(|source| source.organization == org))
    {
        return Err("Snippet removed member retains its Organization session source");
    }
    missing(&context, member_browser.actor(), updated.id).await?;
    descriptor.phase = PHASES[4];
    phase(directory, &descriptor).await?;
    personal = preserve(https, personal, &mut foreign, &foreign_before).await?;

    context.refresh().await?;
    owner_browser.refresh(https).await?;
    let vault = context.snapshot().await?.current.vault.id;
    for resource in [&updated, &secret.resource] {
        let before = context.snapshot().await?;
        exchange(
            https,
            owner_browser.actor(),
            "DELETE",
            &format!("{}/{}", context.path(), resource.id),
            &[],
            &[("If-Match", &resource.etag)],
            204,
        )
        .await?;
        effect(
            &before,
            &context.snapshot().await?,
            resource,
            owner.payload.account_id,
            Some(created.family),
            "organization.inventory_deleted",
        )?;
        missing(&context, owner_browser.actor(), resource.id).await?;
        missing(&context, member_browser.actor(), resource.id).await?;
    }
    if !context.list(owner_browser.actor()).await?.is_empty() {
        return Err("Deleted Snippets remain in the owner's live Page");
    }
    history(&context, vault, &[&created.resource, &updated], created.family, &personal).await?;
    history(&context, vault, &[&secret.resource], created.family, &personal).await?;
    descriptor.phase = PHASES[5];
    phase(directory, &descriptor).await?;
    preserve(https, personal, &mut foreign, &foreign_before).await?;
    println!("Snippet producer verified browser lifecycle, retained owner history and isolation");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Descriptor<'static> {
        let root = std::env::temp_dir();
        let marker = "scoplen-snippet-synthetic";
        Descriptor {
            disposable: true,
            phase: PHASES[0],
            origin: "https://localhost:18443",
            ca_certificate: root.join("ca.pem"),
            member_username: "synthetic-member".into(),
            member_password_file: root.join("synthetic-member-password.txt"),
            organization_id: Uuid::now_v7(),
            host_id: Uuid::now_v7(),
            profile_id: Uuid::now_v7(),
            snippet_id: Uuid::now_v7(),
            secret_snippet_id: Uuid::now_v7(),
            writer_family_id: Uuid::now_v7(),
            fields: projection(&executable(marker, false).unwrap()).unwrap(),
            secret_fields: projection(&secret().unwrap()).unwrap(),
            inputs: inputs(),
            output_marker: marker.into(),
        }
    }

    #[test]
    fn snippet_descriptor_freezes_exact_fields_and_two_distinct_typed_definitions() {
        let mut descriptor = descriptor();
        for phase in PHASES {
            descriptor.phase = phase;
            descriptor.fields =
                projection(&executable(&descriptor.output_marker, phase != PHASES[0]).unwrap())
                    .unwrap();
            let text = descriptor_json(&descriptor).unwrap();
            assert!(text.len() < MAX_DESCRIPTOR_BYTES);
            let value: Value = serde_json::from_str(&text).unwrap();
            let mut names: Vec<_> = value.as_object().unwrap().keys().map(String::as_str).collect();
            names.sort_unstable();
            assert_eq!(
                names,
                [
                    "ca_certificate",
                    "disposable",
                    "fields",
                    "host_id",
                    "inputs",
                    "member_password_file",
                    "member_username",
                    "organization_id",
                    "origin",
                    "output_marker",
                    "phase",
                    "profile_id",
                    "secret_fields",
                    "secret_snippet_id",
                    "snippet_id",
                    "writer_family_id",
                ]
            );
            assert_eq!(value["fields"]["variables"].as_object().unwrap().len(), 3);
            assert_eq!(value["fields"]["variables"]["count"]["kind"], 2);
            assert!(value["fields"]["variables"]["count"]["default"].is_string());
            assert_eq!(value["secret_fields"]["variables"]["secret"], json!({"kind":4}));
            let command = value["fields"]["template"].as_str().unwrap();
            assert!(!command.contains(&descriptor.output_marker));
            assert!(!command.contains(['\r', '\n']));
            assert!(
                command.contains("{{message}}")
                    && command.contains("{{count}}")
                    && command.contains("{{color}}")
            );
        }
    }

    #[test]
    fn snippet_descriptor_rejects_wrong_phase_secret_defaults_and_changed_context() {
        let mut value = descriptor();
        value.phase = "other";
        assert!(descriptor_json(&value).is_err());
        value.phase = PHASES[1];
        assert!(descriptor_json(&value).is_err());
        for default in [Value::Null, json!(""), json!("private")] {
            let mut value = descriptor();
            value.secret_fields["variables"]["secret"]["default"] = default;
            assert!(descriptor_json(&value).is_err());
        }
        let mut value = descriptor();
        value.secret_snippet_id = value.snippet_id;
        assert!(descriptor_json(&value).is_err());
        let mut value = descriptor();
        value.member_password_file = PathBuf::from("relative.txt");
        assert!(descriptor_json(&value).is_err());
        let mut value = descriptor();
        value.inputs.insert("secret".into(), "not-authorized".into());
        assert!(descriptor_json(&value).is_err());
        let mut value = descriptor();
        value.ca_certificate = std::env::temp_dir().join("x".repeat(MAX_DESCRIPTOR_BYTES));
        assert!(descriptor_json(&value).is_err());
    }

    #[test]
    fn snippet_completion_requires_the_whole_exact_atomic_signal() {
        assert!(completion("passed\n").is_ok());
        for signal in ["", "pass", "passed", "passed\r\n", "passed\n\n", "failed\n", " passed\n"] {
            assert!(completion(signal).is_err());
        }
    }
}
