// SPDX-License-Identifier: AGPL-3.0-only
//! Independent public HTTPS import acceptance, without storage access or seeded identities.

use scoplen_api::{
    audit::{AuditEvent, AuditOutcome, AuditResource, AuditResourceKind},
    auth::AuthTokenResponse,
    inventory::{InventoryFields, InventoryType},
    inventory_import::{
        InventoryImportRequest, InventoryImportResult, InventoryImportRow, parse_inventory_csv,
    },
    sync::{
        SessionVault, SyncOrganizationAckRequest, SyncOrganizationAckResponse,
        SyncOrganizationViewQuery, SyncOrganizationViewResponse, SyncSessionRequest,
        SyncSessionResponse,
    },
};
use scoplen_model::Object;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::super::audit::{Actor, timeline};
use super::{
    Browser, Https, Registration, Result, create_team, exchange, inventory, native, problem,
};

#[derive(Eq, PartialEq)]
struct Snapshot {
    vault: SessionVault,
    view: SyncOrganizationViewResponse,
    events: Vec<AuditEvent>,
}

struct Context<'a> {
    https: &'a Https,
    owner: &'a Registration,
    token: &'a AuthTokenResponse,
    org: Uuid,
}

struct Imported {
    request: InventoryImportRequest,
    key: String,
    original: Zeroizing<Vec<u8>>,
}

pub(super) async fn target(
    https: &Https,
    actor: Actor<'_>,
    org: Uuid,
    port: u16,
) -> Result<(scoplen_api::inventory::InventoryResource, scoplen_api::inventory::InventoryResource)>
{
    let csv = format!(
        "name,address,port,username,login_name\nImported SSH target,127.0.0.1,{port},smoke,Operations\n"
    );
    let fields = parse_inventory_csv(csv.as_bytes())
        .map_err(|_| "Inventory SSH target CSV preparation failed")?;
    let request = InventoryImportRequest {
        rows: fields
            .into_iter()
            .map(|fields| InventoryImportRow {
                host_id: Uuid::now_v7(),
                access_profile_id: Uuid::now_v7(),
                fields,
            })
            .collect(),
    };
    let body = request.to_json().map_err(|_| "Inventory SSH import request is invalid")?;
    let reply = exchange(
        https,
        actor,
        "POST",
        &format!("/api/v1/orgs/{org}/inventory/imports"),
        &body,
        &[("Idempotency-Key", &Uuid::now_v7().to_string())],
        201,
    )
    .await?;
    InventoryImportResult::from_http_json(
        &reply.body,
        reply.header("cache-control"),
        reply.header("pragma"),
        &request,
    )
    .map_err(|_| "Inventory SSH import result differs from its original intent")?;
    let (host, login) = request.rows[0]
        .inventory_creates()
        .map_err(|_| "Inventory SSH imported pair is invalid")?;
    let mut resources = Vec::new();
    for expected in [host, login] {
        let kind = expected.fields.kind();
        let reply = exchange(
            https,
            actor,
            "GET",
            &format!("/api/v1/orgs/{org}/{}/{}", kind.segment(), expected.id),
            &[],
            &[],
            200,
        )
        .await?;
        let current = inventory(&reply, kind, expected.id)?;
        if current.fields != expected.fields {
            return Err("Inventory SSH imported default Login required repair");
        }
        resources.push(current);
    }
    let [host, login] = resources.try_into().map_err(|_| "Inventory SSH pair is incomplete")?;
    Ok((host, login))
}

fn reviewed_request() -> Result<InventoryImportRequest> {
    let fields = parse_inventory_csv(
        b"name,address,port,username,login_name\r\n\"Same, host\",example.test,,operator,\r\n\"Same, host\",example.test,22,operator,Operations\r\n",
    )
    .map_err(|_| "Inventory HTTPS shared CSV preparation failed")?;
    let request = InventoryImportRequest {
        rows: fields
            .into_iter()
            .map(|fields| InventoryImportRow {
                host_id: Uuid::now_v7(),
                access_profile_id: Uuid::now_v7(),
                fields,
            })
            .collect(),
    };
    request.validate().map_err(|_| "Inventory HTTPS reviewed request is invalid")?;
    Ok(request)
}

impl Context<'_> {
    fn path(&self) -> String {
        format!("/api/v1/orgs/{}/inventory/imports", self.org)
    }

    async fn snapshot(&self) -> Result<Snapshot> {
        let body = SyncSessionRequest {
            client_version: "0.1.0".into(),
            model_version: 1,
            device_id: self.owner.device.id,
        }
        .to_cbor()
        .map_err(|_| "Inventory HTTPS session request is invalid")?;
        let proof = Some((&self.owner.device.keys.signing, Some(self.token.access_token.as_str())));
        let bytes = self.https.exchange("POST", "/sync/v1/session", &body, proof, 200).await?;
        let session = SyncSessionResponse::from_cbor(&bytes)
            .map_err(|_| "Inventory HTTPS session response is invalid")?;
        let vault = session
            .vaults
            .into_iter()
            .find(|vault| {
                vault.organization.is_some_and(|context| context.organization == self.org)
            })
            .ok_or("Inventory HTTPS current team vault is missing")?;
        let source = vault.organization.ok_or("Inventory HTTPS team source is missing")?;
        let query =
            SyncOrganizationViewQuery { view_revision: source.view_revision, after: 0, limit: 100 };
        let path = format!(
            "/sync/v1/vaults/{}/view?{}",
            vault.id,
            query.to_query().map_err(|_| "Inventory HTTPS view query is invalid")?
        );
        let bytes = self.https.exchange("GET", &path, &[], proof, 200).await?;
        let view = SyncOrganizationViewResponse::from_cbor(&bytes)
            .map_err(|_| "Inventory HTTPS complete view is invalid")?;
        view.validate_for_query(source, vault.id, &query)
            .map_err(|_| "Inventory HTTPS view source differs")?;
        if view.more || view.next_cursor != vault.seq {
            return Err("Inventory HTTPS fixture view is incomplete");
        }
        let events =
            timeline(self.https, native(self.owner, self.token), self.org, 100, None).await?;
        Ok(Snapshot { vault, view, events })
    }

    async fn submit(&self, actor: Actor<'_>) -> Result<Imported> {
        let request = reviewed_request()?;
        let key = Uuid::now_v7().to_string();
        let body = request.to_json().map_err(|_| "Inventory HTTPS import encoding failed")?;
        let reply = exchange(
            self.https,
            actor,
            "POST",
            &self.path(),
            &body,
            &[("Idempotency-Key", &key)],
            201,
        )
        .await?;
        InventoryImportResult::from_http_json(
            &reply.body,
            reply.header("cache-control"),
            reply.header("pragma"),
            &request,
        )
        .map_err(|_| "Inventory HTTPS import result differs from reviewed intent")?;
        if reply.header("location").is_some() || reply.header("etag").is_some() {
            return Err("Inventory HTTPS import incorrectly returned a job or Resource");
        }
        for row in &request.rows {
            let (host, login) =
                row.inventory_creates().map_err(|_| "Inventory HTTPS pair is invalid")?;
            for expected in [host, login] {
                let kind = expected.fields.kind();
                let reply = exchange(
                    self.https,
                    actor,
                    "GET",
                    &format!("/api/v1/orgs/{}/{}/{}", self.org, kind.segment(), expected.id),
                    &[],
                    &[],
                    200,
                )
                .await?;
                if inventory(&reply, kind, expected.id)?.fields != expected.fields {
                    return Err("Inventory HTTPS imported pair needed repair or changed fields");
                }
            }
        }
        Ok(Imported { request, key, original: reply.body })
    }

    async fn confirm(&self, actor: Actor<'_>, imported: &Imported) -> Result<()> {
        let body = imported
            .request
            .to_json()
            .map_err(|_| "Inventory HTTPS confirmation encoding failed")?;
        let reply = exchange(
            self.https,
            actor,
            "POST",
            &self.path(),
            &body,
            &[("Idempotency-Key", &imported.key)],
            201,
        )
        .await?;
        InventoryImportResult::from_http_json(
            &reply.body,
            reply.header("cache-control"),
            reply.header("pragma"),
            &imported.request,
        )
        .map_err(|_| "Inventory HTTPS confirmation lost original request binding")?;
        if reply.body != imported.original {
            return Err("Inventory HTTPS confirmation changed original bytes");
        }
        Ok(())
    }

    async fn failure(
        &self,
        actor: Actor<'_>,
        path: &str,
        body: &[u8],
        key: &str,
        status: u16,
        code: &str,
    ) -> Result<()> {
        let before = self.snapshot().await?;
        let reply =
            exchange(self.https, actor, "POST", path, body, &[("Idempotency-Key", key)], status)
                .await?;
        problem(&reply, status, code)?;
        if before != self.snapshot().await? {
            return Err("Inventory HTTPS refusal partially published inventory or audit");
        }
        Ok(())
    }

    async fn ack(&self, snapshot: &Snapshot) -> Result<()> {
        let request = SyncOrganizationAckRequest {
            cursor: snapshot.vault.seq,
            view_revision: snapshot.view.view_revision,
        };
        let body = request.to_cbor().map_err(|_| "Inventory HTTPS ACK encoding failed")?;
        let bytes = self
            .https
            .exchange(
                "POST",
                &format!("/sync/v1/vaults/{}/ack", snapshot.vault.id),
                &body,
                Some((&self.owner.device.keys.signing, Some(&self.token.access_token))),
                200,
            )
            .await?;
        SyncOrganizationAckResponse::from_cbor(&bytes)
            .and_then(|response| response.validate_for_request(&request))
            .map_err(|_| "Inventory HTTPS ACK lost imported view binding")
    }
}

fn effect(
    before: &Snapshot,
    after: &Snapshot,
    imported: &Imported,
    account: Uuid,
    device: Option<Uuid>,
) -> Result<()> {
    let count = imported.request.rows.len() * 2;
    if after.vault.id != before.vault.id
        || after.vault.seq != before.vault.seq + count as u64
        || after.view.view_revision != before.view.view_revision + 1
        || after.view.objects.len() != before.view.objects.len() + count
        || after.events.len() != before.events.len() + count
        || !after.view.objects.starts_with(&before.view.objects)
        || !after.events.ends_with(&before.events)
    {
        return Err("Inventory HTTPS batch did not publish exactly one complete view transition");
    }
    let creates = imported
        .request
        .rows
        .iter()
        .map(InventoryImportRow::inventory_creates)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "Inventory HTTPS original pairs are invalid")?;
    let expected = creates.into_iter().flat_map(|(host, login)| [host, login]);
    let mut browser_family = None;
    for ((expected, change), event) in expected
        .zip(after.view.objects.iter().skip(before.view.objects.len()))
        .zip(after.events.iter().take(count).rev())
    {
        let object = Object::decode(&change.payload)
            .map_err(|_| "Inventory HTTPS imported K-1 is invalid")?;
        let kind = match expected.fields.kind() {
            InventoryType::Host => AuditResourceKind::Host,
            InventoryType::AccessProfile => AuditResourceKind::AccessProfile,
            _ => return Err("Inventory HTTPS import created an unexpected object type"),
        };
        if change.object_id != expected.id
            || object.id != expected.id
            || InventoryFields::from_object(&object)
                .map_err(|_| "Inventory HTTPS K-1 projection is invalid")?
                != expected.fields
            || event.event_class.as_deref() != Some("organization.inventory_created")
            || event.outcome != AuditOutcome::Success
            || event.actor_account_id != Some(account)
            || event.actor_device_id != device
            || event.actor_browser_family_id.is_some() != device.is_none()
            || event.resource != Some(AuditResource { kind, id: expected.id })
        {
            return Err("Inventory HTTPS object, audit or real writer attribution differs");
        }
        if let Some(family) = event.actor_browser_family_id {
            if browser_family.is_some_and(|previous| previous != family) {
                return Err("Inventory HTTPS one batch has multiple browser-family writers");
            }
            browser_family = Some(family);
        }
        let writer =
            device.or(event.actor_browser_family_id).ok_or("Inventory HTTPS writer is absent")?;
        if object.fields.values().any(|entry| entry.origin != writer) {
            return Err("Inventory HTTPS K-1 writer differs from its attributable audit");
        }
    }
    let added = &after.view.objects[before.view.objects.len()..];
    if added
        .iter()
        .enumerate()
        .any(|(index, change)| change.seq != before.vault.seq + index as u64 + 1)
    {
        return Err("Inventory HTTPS batch sequences are not contiguous in reviewed row order");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn verify(https: &Https) -> Result<()> {
    println!("Inventory import acceptance: genuine Account, Device and browser writers");
    let owner = Registration::new(&https.origin)?;
    owner.register(https).await?;
    let other = Registration::new(&https.origin)?;
    other.register(https).await?;
    let token = owner.device.authenticate(https).await?;
    let mut browser = Browser::login(https, &owner).await?;
    let other_browser = Browser::login(https, &other).await?;
    let org = create_team(https, browser.actor()).await?.id;
    let foreign = create_team(https, other_browser.actor()).await?.id;
    let c = Context { https, owner: &owner, token: &token, org };
    let actor = native(&owner, &token);
    let before = c.snapshot().await?;
    let device_import = c.submit(actor).await?;
    let after = c.snapshot().await?;
    effect(&before, &after, &device_import, owner.payload.account_id, Some(owner.device.id))?;
    c.confirm(actor, &device_import).await?;
    if after != c.snapshot().await? {
        return Err("Inventory HTTPS Device confirmation repeated a mutation");
    }
    let body = device_import
        .request
        .to_json()
        .map_err(|_| "Inventory HTTPS retained request is invalid")?;
    c.failure(browser.actor(), &c.path(), &body, &device_import.key, 409, "organization.conflict")
        .await?;
    c.failure(actor, &c.path(), &body, &Uuid::now_v7().to_string(), 409, "organization.conflict")
        .await?;
    let mut changed = device_import.request.clone();
    changed.rows[0].fields.name.push('x');
    c.failure(
        actor,
        &c.path(),
        &changed.to_json().map_err(|_| "Inventory HTTPS changed request is invalid")?,
        &device_import.key,
        409,
        "organization.conflict",
    )
    .await?;
    c.failure(
        other_browser.actor(),
        &c.path(),
        &body,
        &Uuid::now_v7().to_string(),
        404,
        "organization.not_found",
    )
    .await?;
    c.failure(
        actor,
        &format!("/api/v1/orgs/{foreign}/inventory/imports"),
        &body,
        &Uuid::now_v7().to_string(),
        404,
        "organization.not_found",
    )
    .await?;
    println!("Inventory import acceptance: current admission window before browser batch checks");
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    let before = c.snapshot().await?;
    let browser_import = c.submit(browser.actor()).await?;
    let after = c.snapshot().await?;
    effect(&before, &after, &browser_import, owner.payload.account_id, None)?;
    browser.refresh(https).await?;
    c.confirm(browser.actor(), &browser_import).await?;
    if after != c.snapshot().await? {
        return Err("Inventory HTTPS same-family refresh confirmation repeated a mutation");
    }
    let second_family = Browser::login(https, &owner).await?;
    let body = browser_import
        .request
        .to_json()
        .map_err(|_| "Inventory HTTPS browser intent is invalid")?;
    c.failure(
        second_family.actor(),
        &c.path(),
        &body,
        &browser_import.key,
        409,
        "organization.conflict",
    )
    .await?;
    c.failure(actor, &c.path(), &body, &browser_import.key, 409, "organization.conflict").await?;
    let fresh = reviewed_request()?
        .to_json()
        .map_err(|_| "Inventory HTTPS malformed control is invalid")?;
    let mut malformed: serde_json::Value =
        serde_json::from_slice(&fresh).map_err(|_| "Inventory HTTPS JSON control is invalid")?;
    malformed["rows"][1]["credential"] = serde_json::json!("not-accepted");
    let malformed =
        serde_json::to_vec(&malformed).map_err(|_| "Inventory HTTPS control encoding failed")?;
    c.failure(
        browser.actor(),
        &c.path(),
        &malformed,
        &Uuid::now_v7().to_string(),
        400,
        "organization.invalid_request",
    )
    .await?;
    c.ack(&c.snapshot().await?).await?;
    println!(
        "Inventory import acceptance: atomic pairs, current views, original confirmation and tenant isolation passed"
    );
    Ok(())
}
