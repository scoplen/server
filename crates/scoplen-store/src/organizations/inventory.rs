// SPDX-License-Identifier: AGPL-3.0-only
//! Transaction-current Organization inventory and complete authorized views.

use super::{
    CurrentPrincipal, OrganizationPrincipal, OrganizationResource, OrganizationStoreError as Error,
    PostgresStore, SqliteStore, Uuid, actor_audit, append_audit_event_in_postgres_transaction,
    append_audit_event_in_transaction, check_current_identity, check_identity, lock_postgres,
    lock_sqlite, now_ms, postgres_actor, postgres_principal, sqlite_actor, sqlite_principal,
    timestamp,
};
use cedar_policy::{Context, Decision, Entities, EntityUid, PolicySet, Request};
use scoplen_api::{
    control_plane::{OrganizationAuthorizationContext, OrganizationAuthorizer},
    inventory::{
        InventoryCreateRequest, InventoryFields, InventoryPage, InventoryReplaceRequest,
        InventoryResource, InventoryType,
    },
    organization::OrganizationListQuery,
    sync::{
        OrganizationVaultContext, SessionVault, SyncChange, SyncOrganizationAckRequest,
        SyncOrganizationAckResponse, SyncOrganizationViewQuery, SyncOrganizationViewResponse,
        SyncReadLimits, VaultKind,
    },
};
use scoplen_model::{Hlc, Object, ObjectType, Tombstone, cbor::Value};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

/// One desired mutation. HTTP owns exact scope, `DPoP` and strict header admission.
pub enum InventoryWrite<'a> {
    Create { key: Uuid, request: &'a InventoryCreateRequest },
    Replace { if_match: &'a str, request: &'a InventoryReplaceRequest },
    Delete { if_match: &'a str },
}

/// Immutable tenant, type and object selected by the authenticated HTTP route.
#[derive(Clone, Copy)]
pub struct InventoryTarget {
    pub org: Uuid,
    pub kind: InventoryType,
    pub id: Uuid,
}

/// A complete authoritative write result, suitable for post-commit notification.
pub struct InventoryWriteResult {
    pub resource: Option<InventoryResource>,
    pub vault: Uuid,
    pub sequence: u64,
    pub view_revision: u64,
    pub changed: bool,
}

fn entity_ref(kind: &str, id: Uuid) -> Json {
    json!({"__entity":{"type":kind,"id":id.to_string()}})
}
fn entity(kind: &str, id: Uuid, attrs: &Json) -> Json {
    json!({"uid":{"type":kind,"id":id.to_string()},"attrs":attrs,"parents":[]})
}
fn uid(kind: &str, id: Uuid) -> Result<EntityUid, Error> {
    format!("{kind}::\"{id}\"").parse().map_err(|_| Error::StorageUnavailable)
}
pub(super) fn row_uuid<R: Row>(row: &R, field: &str) -> Result<Uuid, Error>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let bytes: [u8; 16] =
        row.try_get::<Vec<u8>, _>(field)?.try_into().map_err(|_| Error::StorageUnavailable)?;
    let id = Uuid::from_bytes(bytes);
    scoplen_model::validate_uuid_v7(id).map_err(|_| Error::StorageUnavailable)?;
    Ok(id)
}
fn revision(bytes: Vec<u8>) -> Result<u64, Error> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| Error::StorageUnavailable)?;
    let value = u64::from_be_bytes(bytes);
    if value == 0 {
        return Err(Error::StorageUnavailable);
    }
    Ok(value)
}
fn number(value: i64) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::StorageUnavailable)
}
fn sql_number(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::InvalidRequest)
}
fn type_from_sql(value: i64) -> Result<InventoryType, Error> {
    InventoryType::from_object_type(
        ObjectType::from_wire(number(value)?).map_err(|_| Error::StorageUnavailable)?,
    )
    .map_err(|_| Error::StorageUnavailable)
}
fn content_equal(left: &InventoryFields, right: &InventoryFields) -> Result<bool, Error> {
    let mut existing: Json =
        serde_json::from_slice(&left.to_json().map_err(|_| Error::StorageUnavailable)?)
            .map_err(|_| Error::StorageUnavailable)?;
    if left.kind() == InventoryType::TrustRecord {
        for name in ["accepted_at", "accepted_by_device", "accepted_by_account"] {
            existing.as_object_mut().ok_or(Error::StorageUnavailable)?.remove(name);
        }
    }
    let desired: Json =
        serde_json::from_slice(&right.to_json().map_err(|_| Error::InvalidRequest)?)
            .map_err(|_| Error::InvalidRequest)?;
    Ok(existing == desired)
}

fn browser_inventory_type(
    expected: &impl OrganizationPrincipal,
    kind: InventoryType,
) -> Result<(), Error> {
    if expected.is_account_browser()
        && !matches!(
            kind,
            InventoryType::Host
                | InventoryType::HostGroup
                | InventoryType::AccessProfile
                | InventoryType::Route
        )
    {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

pub(super) struct Graph {
    organization: OrganizationResource,
    authorizer: OrganizationAuthorizer,
    entities: BTreeMap<(String, Uuid), Json>,
    now: i64,
    connect_observes_source_ip: bool,
}
impl Graph {
    pub(super) fn authorize(&self, action: &str, kind: &str, id: Uuid) -> Result<bool, Error> {
        let org = self.organization.id;
        let member = self.organization.membership.id;
        let context = Context::from_json_value(
            json!({"organization":entity_ref("Organization",org),
            "membership":entity_ref("Membership",member),"now":self.now.div_euclid(1000)}),
            None,
        )
        .map_err(|_| Error::StorageUnavailable)?;
        self.authorize_context(action, kind, id, context)
    }

    pub(super) fn authorize_connect(
        &self,
        device: Uuid,
        host: Uuid,
        remote_user: &str,
        source: std::net::IpAddr,
    ) -> Result<bool, Error> {
        if self.connect_observes_source_ip {
            return Ok(false);
        }
        let context = Context::from_json_value(
            json!({"organization":entity_ref("Organization",self.organization.id),
                "membership":entity_ref("Membership",self.organization.membership.id),
                "now":self.now.div_euclid(1000),"device":entity_ref("Device",device),
                "remote_user":remote_user,"route_kind":"direct","source_ip":source.to_string()}),
            None,
        )
        .map_err(|_| Error::StorageUnavailable)?;
        self.authorize_context("connect", "Host", host, context)
    }

    fn authorize_context(
        &self,
        action: &str,
        kind: &str,
        id: Uuid,
        context: Context,
    ) -> Result<bool, Error> {
        let account = self.organization.membership.account_id;
        let trusted = OrganizationAuthorizationContext::new(
            account,
            self.organization.id,
            self.organization.membership.id,
            self.now.div_euclid(1000),
        )
        .map_err(|_| Error::StorageUnavailable)?;
        let request = Request::new(
            uid("Account", account)?,
            format!("Action::\"{action}\"")
                .parse::<EntityUid>()
                .map_err(|_| Error::StorageUnavailable)?,
            uid(kind, id)?,
            context,
            None,
        )
        .map_err(|_| Error::StorageUnavailable)?;
        let entities =
            Entities::from_json_value(Json::Array(self.entities.values().cloned().collect()), None)
                .map_err(|_| Error::StorageUnavailable)?;
        match self.authorizer.authorize(&trusted, &request, &entities) {
            Ok(Decision::Allow) => Ok(true),
            Ok(Decision::Deny) => Ok(false),
            Err(_) => Err(Error::StorageUnavailable),
        }
    }
}

fn object_entity(object: &Object, organization: Uuid) -> Result<Json, Error> {
    let mut attrs = serde_json::Map::from_iter([(
        "organization".into(),
        entity_ref("Organization", organization),
    )]);
    let scalar_id = |field| -> Result<Option<Uuid>, Error> {
        match object.fields.get(&scoplen_model::FieldPath::Field(field)).map(|entry| &entry.value) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bytes(bytes)) => {
                Uuid::from_slice(bytes).map(Some).map_err(|_| Error::StorageUnavailable)
            }
            _ => Err(Error::StorageUnavailable),
        }
    };
    let set = |field, kind: &str| -> Result<Vec<Json>, Error> {
        let mut result = Vec::new();
        for (path, entry) in &object.fields {
            if let scoplen_model::FieldPath::MapEntry {
                field: actual,
                key: scoplen_model::MapKey::Bytes(bytes),
            } = path
                && *actual == field
                && entry.value != Value::Null
            {
                let id = Uuid::from_slice(bytes).map_err(|_| Error::StorageUnavailable)?;
                result.push(entity_ref(kind, id));
            }
        }
        Ok(result)
    };
    match object.object_type {
        ObjectType::HOST => {
            let labels = object
                .fields
                .iter()
                .filter_map(|(path, entry)| {
                    if let scoplen_model::FieldPath::MapEntry {
                        field: 4,
                        key: scoplen_model::MapKey::Text(name),
                    } = path
                        && let Value::Text(value) = &entry.value
                    {
                        Some(Json::String(format!("{name}={value}")))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            attrs.insert("labels".into(), json!(labels));
            attrs.insert("host_groups".into(), json!(set(5, "HostGroup")?));
        }
        ObjectType::HOST_GROUP => {
            attrs.insert(
                "name".into(),
                json!(object.required_text(1).map_err(|_| Error::StorageUnavailable)?),
            );
            attrs.insert(
                "parents".into(),
                json!(
                    scalar_id(2)?
                        .map(|id| entity_ref("HostGroup", id))
                        .into_iter()
                        .collect::<Vec<_>>()
                ),
            );
        }
        ObjectType::GATEWAY_NETWORK => {
            attrs.insert(
                "name".into(),
                json!(object.required_text(1).map_err(|_| Error::StorageUnavailable)?),
            );
        }
        ObjectType::ACCESS_PROFILE => {
            attrs.insert(
                "host".into(),
                entity_ref("Host", scalar_id(1)?.ok_or(Error::StorageUnavailable)?),
            );
        }
        ObjectType::TRUST_RECORD => {
            if let Some(host) = scalar_id(1)? {
                attrs.insert("host".into(), entity_ref("Host", host));
            }
        }
        ObjectType::ROUTE | ObjectType::SNIPPET => {}
        _ => return Err(Error::StorageUnavailable),
    }
    Ok(entity(&object.object_type.to_string(), object.id, &Json::Object(attrs)))
}

macro_rules! inventory {
    ($store:ty,$db:ty,$begin:literal,$lock:ident,$principal:ident,$actor:ident,$audit:ident,$postgres:literal,$versions:ident) => {
        impl $store {
            /// Resolve retained membership targets for content-free post-commit rediscovery.
            /// # Errors
            /// Returns a storage error if the internal membership projection is damaged.
            pub async fn organization_membership_accounts(&self,organization:Uuid,membership:Option<Uuid>)->Result<Vec<[u8;16]>,Error> {
                let rows=sqlx::query("SELECT account_id FROM organization_memberships WHERE organization_id=$1 AND ($2 IS NULL OR id=$2)")
                    .bind(organization.as_bytes().as_slice()).bind(membership.map(|id|id.into_bytes().to_vec())).fetch_all(&self.pool).await?;
                rows.iter().map(|row|row.try_get::<Vec<u8>,_>("account_id")?.try_into().map_err(|_|Error::StorageUnavailable)).collect()
            }
            /// Check current descriptor authority for a connected-device notification recipient.
            /// The socket lifecycle separately enforces its original access-token expiry.
            /// # Errors
            /// Invalid current identity or unavailable membership storage fails closed.
            pub async fn organization_notification_recipient(&self,expected:&CurrentPrincipal,organization:Uuid,vault:Uuid)->Result<bool,Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_current_identity($principal(&mut tx,expected.device_id).await?,expected)?;
                let found=sqlx::query_scalar::<_,Vec<u8>>("SELECT o.id FROM organizations o JOIN organization_inventory_vaults v ON v.organization_id=o.id JOIN organization_memberships m ON m.organization_id=o.id WHERE o.id=$1 AND v.vault_id=$2 AND m.account_id=$3 AND m.status='active' AND o.dissolved_at_ms IS NULL")
                    .bind(organization.as_bytes().as_slice()).bind(vault.as_bytes().as_slice()).bind(expected.account_id.as_slice()).fetch_optional(&mut *tx).await?.is_some();
                check_current_identity($principal(&mut tx,expected.device_id).await?,expected)?;
                tx.commit().await?;Ok(found)
            }

            /// Read the current content-free event after an authoring commit.
            /// # Errors
            /// Missing owners, damaged revisions or unavailable storage fail closed.
            pub async fn organization_inventory_event(&self,organization:Uuid)->Result<scoplen_api::sync::SyncNotification,Error> {
                let row=sqlx::query("SELECT v.vault_id,o.view_revision FROM organizations o JOIN organization_inventory_vaults v ON v.organization_id=o.id WHERE o.id=$1 AND o.dissolved_at_ms IS NULL")
                    .bind(organization.as_bytes().as_slice()).fetch_optional(&self.pool).await?.ok_or(Error::NotFound)?;
                Ok(scoplen_api::sync::SyncNotification::OrganizationViewChanged{organization,vault:row_uuid(&row,"vault_id")?,view_revision:revision(row.try_get("view_revision")?)?})
            }

            /// Read complete retained history only for a currently readable team object.
            /// # Errors
            /// Identity, tenant, visibility and read-budget checks share the history transaction.
            pub async fn organization_inventory_versions(&self,expected:&CurrentPrincipal,expires_at:u64,vault:Uuid,id:Uuid,limits:SyncReadLimits)->Result<Option<scoplen_api::sync::SyncVersionsResponse>,Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                let owner=sqlx::query("SELECT organization_id FROM organization_inventory_vaults WHERE vault_id=$1").bind(vault.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                let Some(owner)=owner else{tx.commit().await?;return Ok(None);};
                let org=row_uuid(&owner,"organization_id")?;
                let (current,bound,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                if bound!=vault{return Err(Error::NotFound);}
                let mut graph=Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                let object=Self::inventory_history_authorization_object(&mut tx,org,id).await?;
                if !Self::inventory_readable(&mut tx,&mut graph,&object).await?{return Err(Error::NotFound);}
                let versions=crate::sync::read::$versions(&mut tx,vault.into_bytes(),id.into_bytes(),Some(limits)).await.map_err(|_|Error::StorageUnavailable)?;
                let response=scoplen_api::sync::SyncVersionsResponse{versions:versions.into_iter().map(|version|SyncChange{object_id:Uuid::from_bytes(version.object_id),seq:version.sequence,payload:version.envelope,tombstone:version.tombstone,signer_device_id:version.signer_device_id.map(Uuid::from_bytes)}).collect()};
                response.validate_for_object_with_limits(id,limits).map_err(|_|Error::StorageUnavailable)?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(Some(response))
            }

            pub(super) async fn inventory_owner(tx:&mut Transaction<'_,$db>,expected: &impl OrganizationPrincipal,expires_at:u64,org:Uuid,write:bool)
                ->Result<(OrganizationResource,Uuid,u64,u64),Error> {
                $lock(tx,&expected.account_id(),false).await?;
                $actor(tx, expected, expires_at).await?;
                let suffix=if $postgres {if write {" FOR UPDATE OF o,v"}else{" FOR SHARE OF o,v"}} else {""};
                let row=sqlx::query(&format!("SELECT o.view_revision,v.vault_id,s.current_seq FROM organizations o JOIN organization_inventory_vaults v ON v.organization_id=o.id JOIN sync_vaults s ON s.vault_id=v.vault_id WHERE o.id=$1 AND o.dissolved_at_ms IS NULL AND s.kind='organization'{suffix}"))
                    .bind(org.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let current=Self::read_organization_in_transaction(tx,&expected.account_id(),org.as_bytes()).await?;
                Ok((current,row_uuid(&row,"vault_id")?,revision(row.try_get("view_revision")?)?,number(row.try_get("current_seq")?)?))
            }

            pub(super) async fn inventory_graph(tx:&mut Transaction<'_,$db>,organization:OrganizationResource,now:i64)->Result<Graph,Error> {
                let account=organization.membership.account_id;
                let org=organization.id;
                let group_rows=sqlx::query("SELECT id,name,source FROM organization_groups WHERE organization_id=$1 AND deleted_at_ms IS NULL ORDER BY id")
                    .bind(org.as_bytes().as_slice()).fetch_all(&mut **tx).await?;
                let mut entities=BTreeMap::new();
                for row in group_rows {
                    let id=row_uuid(&row,"id")?;
                    entities.insert(("Group".into(),id),entity("Group",id,&json!({"organization":entity_ref("Organization",org),"name":row.try_get::<String,_>("name")?,"source":row.try_get::<String,_>("source")?})));
                }
                entities.insert(("Organization".into(),org),entity("Organization",org,&json!({"name":organization.name})));
                let members=sqlx::query("SELECT m.id,m.account_id,m.roles_json,a.email FROM organization_memberships m JOIN identity_accounts a ON a.account_id=m.account_id WHERE m.organization_id=$1 AND m.status='active' ORDER BY m.id")
                    .bind(org.as_bytes().as_slice()).fetch_all(&mut **tx).await?;
                for row in members {
                    let member=row_uuid(&row,"id")?;
                    let member_account=row_uuid(&row,"account_id")?;
                    let memberships=sqlx::query("SELECT gm.group_id FROM organization_group_members gm JOIN organization_groups g ON g.organization_id=gm.organization_id AND g.id=gm.group_id WHERE gm.organization_id=$1 AND gm.membership_id=$2 AND g.deleted_at_ms IS NULL ORDER BY gm.group_id")
                        .bind(org.as_bytes().as_slice()).bind(member.as_bytes().as_slice()).fetch_all(&mut **tx).await?;
                    let groups=memberships.iter().map(|row|row_uuid(row,"group_id").map(|id|entity_ref("Group",id))).collect::<Result<Vec<_>,_>>()?;
                    let mut attrs=json!({"status":"active"});
                    if let Some(email)=row.try_get::<Option<String>,_>("email")? {attrs.as_object_mut().ok_or(Error::StorageUnavailable)?.insert("email".into(),json!(email));}
                    entities.insert(("Account".into(),member_account),entity("Account",member_account,&attrs));
                    let roles:Vec<String>=serde_json::from_str(&row.try_get::<String,_>("roles_json")?).map_err(|_|Error::StorageUnavailable)?;
                    entities.insert(("Membership".into(),member),entity("Membership",member,&json!({"account":entity_ref("Account",member_account),"organization":entity_ref("Organization",org),"status":"active","roles":roles,"groups":groups})));
                }
                if !entities.contains_key(&("Account".into(),account)){return Err(Error::NotFound);}
                let devices=sqlx::query("SELECT d.device_id,d.account_id,d.certificate,d.created_at_ms,a.account_signing_public_key FROM identity_devices d JOIN identity_accounts a ON a.account_id=d.account_id JOIN organization_memberships m ON m.account_id=d.account_id WHERE m.organization_id=$1 AND m.status='active' AND d.active=$2 ORDER BY d.device_id")
                    .bind(org.as_bytes().as_slice()).bind(true).fetch_all(&mut **tx).await?;
                for row in devices {
                    let id=row_uuid(&row,"device_id")?;
                    let owner=row_uuid(&row,"account_id")?;
                    let certificate=scoplen_crypto::DeviceCertificate::decode(&row.try_get::<Vec<u8>,_>("certificate")?).map_err(|_|Error::StorageUnavailable)?;
                    let public:[u8;32]=row.try_get::<Vec<u8>,_>("account_signing_public_key")?.try_into().map_err(|_|Error::StorageUnavailable)?;
                    certificate.verify(&public).map_err(|_|Error::StorageUnavailable)?;
                    if certificate.device_id!=id || certificate.account_id!=owner{return Err(Error::StorageUnavailable);}
                    let enrolled:i64=row.try_get("created_at_ms")?;
                    entities.insert(("Device".into(),id),entity("Device",id,&json!({"account":entity_ref("Account",owner),"platform":certificate.platform,"hardware_backed":false,"enrolled_at":enrolled.div_euclid(1000)})));
                }
                let rows=sqlx::query("SELECT source FROM organization_policies WHERE organization_id=$1 AND enabled=1 AND deleted_at_ms IS NULL ORDER BY id")
                    .bind(org.as_bytes().as_slice()).fetch_all(&mut **tx).await?;
                let mut policies=PolicySet::new();
                let mut policy_objects=BTreeSet::new();
                let mut connect_observes_source_ip=false;
                for row in rows {
                    let source:String=row.try_get("source")?;
                    let parsed=scoplen_api::group_policy::parse_policy_source(&source).map_err(|_|Error::StorageUnavailable)?;
                    connect_observes_source_ip|=scoplen_api::group_policy::connect_policy_observes_source_ip(&parsed).map_err(|_|Error::StorageUnavailable)?;
                    for reference in scoplen_api::group_policy::policy_references(&parsed,org).map_err(|_|Error::StorageUnavailable)? {
                        if matches!(reference.type_name().to_string().as_str(),"Host"|"HostGroup"|"GatewayNetwork"|"AccessProfile"|"Route"|"TrustRecord"|"Snippet") {
                            policy_objects.insert(Uuid::parse_str(reference.id().unescaped()).map_err(|_|Error::StorageUnavailable)?);
                        }
                    }
                    let single:PolicySet=source.parse().map_err(|_|Error::StorageUnavailable)?;
                    policies.merge(&single,true).map_err(|_|Error::StorageUnavailable)?;
                }
                let authorizer=OrganizationAuthorizer::new(org,&policies).map_err(|_|Error::StorageUnavailable)?;
                let mut graph=Graph{organization,authorizer,entities,now,connect_observes_source_ip};
                for id in policy_objects {
                    match Self::inventory_object(tx,org,id).await {
                        Ok((object,_))=>Self::inventory_hydrate(tx,&mut graph,&object).await?,
                        Err(Error::NotFound)=>{},
                        Err(error)=>return Err(error),
                    }
                }
                Ok(graph)
            }

            pub(super) async fn authorize_organization_action(tx:&mut Transaction<'_,$db>,current:&OrganizationResource,now:i64,action:&str)->Result<(),Error> {
                let graph=Self::inventory_graph(tx,current.clone(),now).await?;
                if graph.authorize(action,"Organization",current.id)? {Ok(())}else{Err(Error::PermissionDenied)}
            }

            pub(super) async fn inventory_object(tx:&mut Transaction<'_,$db>,org:Uuid,id:Uuid)->Result<(Object,InventoryResource),Error> {
                let row=sqlx::query("SELECT i.object_type,i.response_json,s.envelope FROM organization_inventory_objects i JOIN sync_objects s ON s.vault_id=i.vault_id AND s.object_id=i.object_id WHERE i.organization_id=$1 AND i.object_id=$2 AND s.tombstone=$3")
                    .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(false).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let kind=type_from_sql(row.try_get("object_type")?)?;
                let object=Object::decode(&row.try_get::<Vec<u8>,_>("envelope")?).map_err(|_|Error::StorageUnavailable)?;
                let resource=InventoryResource::from_json(kind,&row.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                if object.id!=id || object.object_type!=kind.object_type() || InventoryFields::from_object(&object).map_err(|_|Error::StorageUnavailable)?!=resource.fields {
                    return Err(Error::StorageUnavailable);
                }
                Ok((object,resource))
            }

            async fn inventory_history_authorization_object(tx:&mut Transaction<'_,$db>,org:Uuid,id:Uuid)->Result<Object,Error> {
                let row=sqlx::query("SELECT i.object_type,i.response_json,s.envelope,s.tombstone FROM organization_inventory_objects i JOIN sync_objects s ON s.vault_id=i.vault_id AND s.object_id=i.object_id WHERE i.organization_id=$1 AND i.object_id=$2")
                    .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let kind=type_from_sql(row.try_get("object_type")?)?;
                let mut projection=Object::decode(&row.try_get::<Vec<u8>,_>("envelope")?).map_err(|_|Error::StorageUnavailable)?;
                if projection.tombstone.is_some()!=row.try_get::<bool,_>("tombstone")? {return Err(Error::StorageUnavailable);}
                // Only this current-authorization projection is live; retained history bytes stay intact.
                projection.tombstone=None;
                let resource=InventoryResource::from_json(kind,&row.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                if projection.id!=id || projection.object_type!=kind.object_type() || InventoryFields::from_object(&projection).map_err(|_|Error::StorageUnavailable)?!=resource.fields {
                    return Err(Error::StorageUnavailable);
                }
                Ok(projection)
            }

            async fn inventory_hydrate(tx:&mut Transaction<'_,$db>,graph:&mut Graph,object:&Object)->Result<(),Error> {
                let mut pending=vec![object.clone()];
                let mut seen=BTreeSet::new();
                while let Some(current)=pending.pop() {
                    if !seen.insert(current.id) {continue;}
                    if seen.len()>100_000 {return Err(Error::StorageUnavailable);}
                    let fields=InventoryFields::from_object(&current).map_err(|_|Error::StorageUnavailable)?;
                    graph.entities.insert((current.object_type.to_string(),current.id),object_entity(&current,graph.organization.id)?);
                    for reference in fields.references().map_err(|_|Error::StorageUnavailable)? {
                        if !seen.contains(&reference.id) {
                            let (target,_)=Self::inventory_object(tx,graph.organization.id,reference.id).await?;
                            if target.object_type!=reference.kind.object_type() {return Err(Error::StorageUnavailable);}
                            pending.push(target);
                        }
                    }
                }
                Ok(())
            }

            pub(super) async fn inventory_readable(tx:&mut Transaction<'_,$db>,graph:&mut Graph,object:&Object)->Result<bool,Error> {
                Self::inventory_hydrate(tx,graph,object).await?;
                graph.authorize("view_inventory",&object.object_type.to_string(),object.id)
            }

            /// Read a live typed Resource through current membership and object authorization.
            /// # Errors
            /// Foreign, deleted and unreadable ids share `NotFound`; damaged state fails closed.
            pub async fn read_organization_inventory(&self,expected: &impl OrganizationPrincipal,expires_at:u64,org:Uuid,kind:InventoryType,id:Uuid)->Result<InventoryResource,Error> {
                browser_inventory_type(expected,kind)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                let mut graph=Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                let (object,value)=Self::inventory_object(&mut tx,org,id).await?;
                if object.object_type!=kind.object_type() || !Self::inventory_readable(&mut tx,&mut graph,&object).await? {return Err(Error::NotFound);}
                $actor(&mut tx, expected, expires_at).await?;
                tx.commit().await?;
                Ok(value)
            }

            /// Read only independently visible Resources, advancing solely over eligible ids.
            /// # Errors
            /// Returns current authentication, membership, query or storage errors.
            pub async fn list_organization_inventory(&self,expected: &impl OrganizationPrincipal,expires_at:u64,org:Uuid,kind:InventoryType,query:&OrganizationListQuery)->Result<InventoryPage,Error> {
                browser_inventory_type(expected,kind)?;
                query.validate().map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                let mut graph=Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                let mut after=query.cursor.map(|id|id.as_bytes().to_vec()).unwrap_or_default();
                let mut page=InventoryPage{kind,items:Vec::new(),next_cursor:None};
                'scan: loop {
                    let rows=sqlx::query("SELECT i.object_id FROM organization_inventory_objects i JOIN sync_objects s ON s.vault_id=i.vault_id AND s.object_id=i.object_id WHERE i.organization_id=$1 AND i.object_type=$2 AND i.object_id>$3 AND s.tombstone=$4 ORDER BY i.object_id LIMIT 100")
                        .bind(org.as_bytes().as_slice()).bind(i64::try_from(kind.object_type().to_wire()).map_err(|_|Error::InvalidRequest)?)
                        .bind(&after).bind(false).fetch_all(&mut *tx).await?;
                    if rows.is_empty(){break;}
                    for row in rows {
                        let id=row_uuid(&row,"object_id")?;
                        after=id.as_bytes().to_vec();
                        let (object,value)=Self::inventory_object(&mut tx,org,id).await?;
                        if !Self::inventory_readable(&mut tx,&mut graph,&object).await? {continue;}
                        if page.items.len()==usize::from(query.limit) {
                            page.next_cursor=page.items.last().map(|item|item.id);break 'scan;
                        }
                        page.items.push(value);
                        if page.to_json().is_err() {
                            page.items.pop();
                            if page.items.is_empty(){return Err(Error::StorageUnavailable);}
                            page.next_cursor=page.items.last().map(|item|item.id);break 'scan;
                        }
                    }
                }
                page.to_json().map_err(|_|Error::StorageUnavailable)?;
                $actor(&mut tx, expected, expires_at).await?;
                tx.commit().await?;
                Ok(page)
            }

            async fn inventory_references(tx:&mut Transaction<'_,$db>,graph:&mut Graph,id:Uuid,fields:&InventoryFields)->Result<(),Error> {
                if fields.kind()==InventoryType::AccessProfile {
                    let host=fields.references().map_err(|_|Error::InvalidRequest)?.into_iter().find(|reference|reference.kind==InventoryType::Host).ok_or(Error::InvalidRequest)?.id;
                    let defaults=sqlx::query("SELECT r.source_id FROM organization_inventory_references r JOIN organization_inventory_objects i ON i.organization_id=r.organization_id AND i.object_id=r.source_id JOIN sync_objects s ON s.vault_id=i.vault_id AND s.object_id=i.object_id WHERE r.organization_id=$1 AND r.target_id=$2 AND i.object_type=1 AND s.tombstone=$3")
                        .bind(graph.organization.id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(false).fetch_all(&mut **tx).await?;
                    for row in defaults {if row_uuid(&row,"source_id")?!=host {return Err(Error::Conflict);}}
                }
                for reference in fields.references().map_err(|_|Error::InvalidRequest)? {
                    if reference.id==id {return Err(Error::Conflict);}
                    let (object,_)=Self::inventory_object(tx,graph.organization.id,reference.id).await?;
                    if object.object_type!=reference.kind.object_type() || !Self::inventory_readable(tx,graph,&object).await? {return Err(Error::NotFound);}
                    if fields.kind()==InventoryType::Host && reference.kind==InventoryType::AccessProfile
                        && object.required_uuid(1).map_err(|_|Error::StorageUnavailable)?!=id {return Err(Error::InvalidRequest);}
                }
                // Only ancestry and routing edges prohibit cycles. A Host and its default
                // AccessProfile legitimately refer to each other.
                if matches!(fields.kind(),InventoryType::HostGroup|InventoryType::Route|InventoryType::AccessProfile) {
                    let mut pending=vec![fields.clone()];
                    let mut seen=BTreeSet::new();
                    while let Some(current)=pending.pop() {
                        for reference in current.references().map_err(|_|Error::InvalidRequest)? {
                            let follow=match fields.kind() {
                                InventoryType::HostGroup => reference.kind==InventoryType::HostGroup,
                                InventoryType::Route|InventoryType::AccessProfile => matches!(reference.kind,InventoryType::Route|InventoryType::AccessProfile),
                                _ => false,
                            };
                            if !follow {continue;}
                            if reference.id==id {return Err(Error::Conflict);}
                            if !seen.insert(reference.id) {continue;}
                            let (_,target)=Self::inventory_object(tx,graph.organization.id,reference.id).await?;
                            pending.push(target.fields);
                        }
                    }
                }
                Ok(())
            }

            /// Author one typed object, sequence, revision, audit and original-create receipt
            /// in the same currently authorized tenant transaction.
            /// # Errors
            /// Returns fixed authentication, current authority, reference, precondition,
            /// storage or uncertain-commit errors. Uncertain replacements are not replayable.
            #[allow(clippy::too_many_lines)]
            pub async fn write_organization_inventory(&self,expected: &impl OrganizationPrincipal,expires_at:u64,origin:&str,target:InventoryTarget,write:InventoryWrite<'_>)->Result<InventoryWriteResult,Error> {
                let InventoryTarget{org,kind,id}=target;
                browser_inventory_type(expected,kind)?;
                scoplen_model::validate_uuid_v7(id).map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,vault,view_revision,current_seq)=Self::inventory_owner(&mut tx,expected,expires_at,org,true).await?;
                let now=now_ms()?;
                let mut graph=Self::inventory_graph(&mut tx,current,now).await?;
                if !graph.authorize("manage_inventory","Organization",org)? {return Err(Error::PermissionDenied);}
                let mut create_receipt=None;
                let (previous,fields,deleting)=match write {
                    InventoryWrite::Create{key,request} => {
                        if request.id!=id || request.fields.kind()!=kind {return Err(Error::InvalidRequest);}
                        let canonical=request.to_json().map_err(|_|Error::InvalidRequest)?;
                        let mut hash=Sha256::new();
                        for part in [b"spl-organization-inventory-create-v1".as_slice(),origin.as_bytes(),expected.account_id().as_slice()] {
                            hash.update(part);hash.update([0]);
                        }
                        if let Some(kind)=expected.receipt_writer_kind() {hash.update(kind);hash.update([0]);}
                        for part in [expected.writer_id().as_slice(),b"POST",format!("/api/v1/orgs/{org}/{}",kind.segment()).as_bytes()] {
                            hash.update(part);hash.update([0]);
                        }
                        hash.update(canonical);
                        let digest:[u8;32]=hash.finalize().into();
                        let row=sqlx::query("SELECT request_digest,response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3")
                            .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice()).bind(now).fetch_optional(&mut *tx).await?;
                        Self::inventory_references(&mut tx,&mut graph,id,&request.fields).await?;
                        if let Some(row)=row {
                            if row.try_get::<Vec<u8>,_>("request_digest")?.as_slice()!=digest {return Err(Error::Conflict);}
                            let resource=InventoryResource::from_json(kind,&row.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                            if resource.id!=id {return Err(Error::StorageUnavailable);}
                            $actor(&mut tx, expected, expires_at).await?;
                            tx.commit().await?;
                            return Ok(InventoryWriteResult{resource:Some(resource),vault,sequence:current_seq,view_revision,changed:false});
                        }
                        let used:Option<Vec<u8>>=sqlx::query_scalar("SELECT object_id FROM organization_inventory_objects WHERE organization_id=$1 AND object_id=$2")
                            .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                        if used.is_some(){return Err(Error::Conflict);}
                        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sync_objects WHERE vault_id=$1")
                            .bind(vault.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                        if number(count)? >= self.sync_cardinality_limits.max_objects_per_vault {return Err(Error::Conflict);}
                        create_receipt=Some((key,digest));
                        (None,Some(request.fields.clone()),false)
                    }
                    InventoryWrite::Replace{if_match,request} => {
                        request.to_json().map_err(|_|Error::InvalidRequest)?;
                        if request.fields.kind()!=kind {return Err(Error::InvalidRequest);}
                        let (object,current)=Self::inventory_object(&mut tx,org,id).await?;
                        if object.object_type!=kind.object_type() || !Self::inventory_readable(&mut tx,&mut graph,&object).await? {return Err(Error::NotFound);}
                        if current.etag!=if_match {return Err(Error::PreconditionFailed);}
                        Self::inventory_references(&mut tx,&mut graph,id,&request.fields).await?;
                        if content_equal(&current.fields,&request.fields)? {
                            $actor(&mut tx, expected, expires_at).await?;
                            tx.commit().await?;
                            return Ok(InventoryWriteResult{resource:Some(current),vault,sequence:current_seq,view_revision,changed:false});
                        }
                        (Some((object,current)),Some(request.fields.clone()),false)
                    }
                    InventoryWrite::Delete{if_match} => {
                        let (object,current)=Self::inventory_object(&mut tx,org,id).await?;
                        if object.object_type!=kind.object_type() || !Self::inventory_readable(&mut tx,&mut graph,&object).await? {return Err(Error::NotFound);}
                        if current.etag!=if_match {return Err(Error::PreconditionFailed);}
                        let referenced:Option<Vec<u8>>=sqlx::query_scalar("SELECT source_id FROM organization_inventory_references WHERE organization_id=$1 AND target_id=$2 LIMIT 1")
                            .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                        if referenced.is_some(){return Err(Error::Conflict);}
                        (Some((object,current)),None,true)
                    }
                };
                let old_clock=previous.as_ref().and_then(|(object,_)|object.fields.values().map(|entry|entry.clock).max());
                let clock=Hlc::tick(old_clock,number(now)?).map_err(|_|Error::StorageUnavailable)?;
                let writer=Uuid::from_bytes(expected.writer_id());
                let fields=fields.map(|fields| if kind==InventoryType::TrustRecord {
                    fields.with_trust_attribution(number(now)?,Uuid::from_bytes(expected.account_id()),writer).map_err(|_|Error::InvalidRequest)
                } else {Ok(fields)}).transpose()?;
                let object=if let Some(fields)=&fields {
                    fields.to_object(id,clock,writer).map_err(|_|Error::InvalidRequest)?
                } else {
                    let mut object=previous.as_ref().ok_or(Error::StorageUnavailable)?.0.clone();
                    object.tombstone=Some(Tombstone::new(clock,writer).map_err(|_|Error::StorageUnavailable)?);
                    object
                };
                let encoded=object.encode().map_err(|_|Error::InvalidRequest)?;
                let created_at=previous.as_ref().map(|(_,resource)|resource.created_at.clone()).unwrap_or(timestamp(now)?);
                let resource=fields.map(|fields| {
                    let mut value=InventoryResource{id,etag:"\"pending\"".into(),created_at,updated_at:timestamp(now)?,fields};
                    let hash=Sha256::digest(&encoded);
                    let mut etag=String::from("\"sha256-");
                    for byte in hash {write!(etag,"{byte:02x}").expect("String write");}etag.push('"');
                    value.etag=etag;value.to_json().map_err(|_|Error::StorageUnavailable)?;Ok::<_,Error>(value)
                }).transpose()?;
                let sequence=current_seq.checked_add(1).ok_or(Error::StorageUnavailable)?;
                let sequence_sql=sql_number(sequence).map_err(|_|Error::StorageUnavailable)?;
                sqlx::query("UPDATE sync_vaults SET current_seq=$1 WHERE vault_id=$2")
                    .bind(sequence_sql).bind(vault.as_bytes().as_slice()).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO sync_objects (vault_id,object_id,sequence,envelope,tombstone,signer_device_id,written_at_ms,key_epoch) VALUES ($1,$2,$3,$4,$5,NULL,$6,1) ON CONFLICT (vault_id,object_id) DO UPDATE SET sequence=excluded.sequence,envelope=excluded.envelope,tombstone=excluded.tombstone,signer_device_id=NULL,written_at_ms=excluded.written_at_ms,key_epoch=1")
                    .bind(vault.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(sequence_sql).bind(&encoded).bind(deleting).bind(now).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO sync_object_versions (vault_id,object_id,sequence,envelope,tombstone,signer_device_id,written_at_ms,key_epoch) VALUES ($1,$2,$3,$4,$5,NULL,$6,1)")
                    .bind(vault.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(sequence_sql).bind(&encoded).bind(deleting).bind(now).execute(&mut *tx).await?;
                sqlx::query("DELETE FROM sync_object_versions WHERE vault_id=$1 AND object_id=$2 AND sequence NOT IN (SELECT sequence FROM sync_object_versions WHERE vault_id=$1 AND object_id=$2 ORDER BY sequence DESC LIMIT 21)")
                    .bind(vault.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                if let Some(resource)=&resource {
                    sqlx::query("INSERT INTO organization_inventory_objects (organization_id,vault_id,object_id,object_type,response_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$6) ON CONFLICT (organization_id,object_id) DO UPDATE SET response_json=excluded.response_json,updated_at_ms=excluded.updated_at_ms")
                        .bind(org.as_bytes().as_slice()).bind(vault.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
                        .bind(i64::try_from(kind.object_type().to_wire()).map_err(|_|Error::InvalidRequest)?)
                        .bind(resource.to_json().map_err(|_|Error::StorageUnavailable)?).bind(now).execute(&mut *tx).await?;
                }
                sqlx::query("DELETE FROM organization_inventory_references WHERE organization_id=$1 AND source_id=$2")
                    .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                if let Some(resource)=&resource {
                    let mut inserted=BTreeSet::new();
                    for reference in resource.fields.references().map_err(|_|Error::StorageUnavailable)? {
                        if !inserted.insert(reference.id){continue;}
                        sqlx::query("INSERT INTO organization_inventory_references (organization_id,source_id,target_id) VALUES ($1,$2,$3)")
                            .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(reference.id.as_bytes().as_slice()).execute(&mut *tx).await?;
                    }
                }
                Self::team_revision(&mut tx,org,now).await?;
                let next_revision=view_revision.checked_add(1).ok_or(Error::StorageUnavailable)?;
                let action=if deleting {"organization.inventory_deleted"}else if create_receipt.is_some(){"organization.inventory_created"}else{"organization.inventory_updated"};
                let event=actor_audit(expected,json!({"action":action,"account_id":Uuid::from_bytes(expected.account_id()),"organization_id":org,"object_id":id,"object_type":kind.object_type().to_wire(),"sequence":sequence,"view_revision":next_revision}))?;
                $audit(&mut tx,org.into_bytes(),&event,now).await.map_err(|_|Error::StorageUnavailable)?;
                if let Some((key,digest))=create_receipt {
                    sqlx::query("DELETE FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3")
                        .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                    sqlx::query("INSERT INTO organization_inventory_receipts (account_id,idempotency_key,organization_id,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                        .bind(expected.account_id().as_slice()).bind(key.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(digest.as_slice())
                        .bind(resource.as_ref().ok_or(Error::StorageUnavailable)?.to_json().map_err(|_|Error::StorageUnavailable)?)
                        .bind(now).bind(now.checked_add(86_400_000).ok_or(Error::StorageUnavailable)?).execute(&mut *tx).await?;
                }
                $actor(&mut tx, expected, expires_at).await?;
                let create=create_receipt.is_some();
                tx.commit().await.map_err(|_|if create {Error::CommitOutcomeUnknown}else{Error::UpdateCommitOutcomeUnknown})?;
                Ok(InventoryWriteResult{resource,vault,sequence,view_revision:next_revision,changed:true})
            }

            /// Discover immutable Organization vault owners from current active memberships.
            /// # Errors
            /// Invalid identities, incomplete ownership or malformed stored counters fail closed.
            pub async fn organization_sync_vaults(&self,expected:&CurrentPrincipal,expires_at:u64)->Result<Vec<SessionVault>,Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                let rows=sqlx::query("SELECT o.id FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id WHERE m.account_id=$1 AND m.status='active' AND o.dissolved_at_ms IS NULL ORDER BY o.id")
                    .bind(expected.account_id.as_slice()).fetch_all(&mut *tx).await?;
                let mut result=Vec::new();
                for row in rows {
                    let org=row_uuid(&row,"id")?;
                    let (_,vault,view_revision,seq)=Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                    result.push(SessionVault{id:vault,kind:VaultKind::Organization,seq,key_epoch:1,rotation_pending:false,organization:Some(OrganizationVaultContext{organization:org,view_revision})});
                }
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(result)
            }

            /// Pull a complete current authorized view fenced by the exact Organization revision.
            /// # Errors
            /// Missing/foreign/lost membership is `NotFound`; changed revision is `ViewChanged`.
            pub async fn organization_inventory_view(&self,expected:&CurrentPrincipal,expires_at:u64,vault:Uuid,query:&SyncOrganizationViewQuery,limits:SyncReadLimits)->Result<SyncOrganizationViewResponse,Error> {
                query.validate().map_err(|_|Error::InvalidRequest)?;
                limits.validate().map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let owner=sqlx::query("SELECT organization_id FROM organization_inventory_vaults WHERE vault_id=$1")
                    .bind(vault.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let org=row_uuid(&owner,"organization_id")?;
                let (current,bound_vault,view_revision,current_seq)=Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                if bound_vault!=vault {return Err(Error::NotFound);}
                if query.view_revision!=view_revision {return Err(Error::ViewChanged);}
                if query.after>current_seq {return Err(Error::Conflict);}
                let mut graph=Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                let mut result=SyncOrganizationViewResponse{organization:org,vault,view_revision,objects:Vec::new(),next_cursor:current_seq,more:false};
                let mut after=query.after;
                'scan: loop {
                    let rows=sqlx::query("SELECT object_id,sequence FROM sync_objects WHERE vault_id=$1 AND sequence>$2 AND tombstone=$3 ORDER BY sequence LIMIT 100")
                        .bind(vault.as_bytes().as_slice()).bind(sql_number(after)?).bind(false).fetch_all(&mut *tx).await?;
                    if rows.is_empty(){break;}
                    for row in rows {
                        let id=row_uuid(&row,"object_id")?;
                        let seq=number(row.try_get("sequence")?)?;
                        after=seq;
                        let (object,_)=Self::inventory_object(&mut tx,org,id).await?;
                        if !Self::inventory_readable(&mut tx,&mut graph,&object).await? {continue;}
                        if result.objects.len()==usize::from(query.limit) {
                            result.more=true;result.next_cursor=result.objects.last().ok_or(Error::StorageUnavailable)?.seq;break 'scan;
                        }
                        result.objects.push(SyncChange{object_id:id,seq,payload:object.encode().map_err(|_|Error::StorageUnavailable)?,tombstone:false,signer_device_id:None});
                        if result.to_cbor_with_limits(limits).is_err() {
                            result.objects.pop();
                            result.next_cursor=result.objects.last().ok_or(Error::StorageUnavailable)?.seq;
                            result.more=true;break 'scan;
                        }
                    }
                }
                result.validate_for_query_with_limits(OrganizationVaultContext{organization:org,view_revision},vault,query,limits).map_err(|_|Error::StorageUnavailable)?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(result)
            }

            /// Record only an ACK for the same current revision and a valid complete-view cursor.
            /// # Errors
            /// Current membership and revision are rechecked in the committing transaction.
            pub async fn ack_organization_inventory(&self,expected:&CurrentPrincipal,expires_at:u64,vault:Uuid,request:SyncOrganizationAckRequest)->Result<SyncOrganizationAckResponse,Error> {
                request.to_cbor().map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let owner=sqlx::query("SELECT organization_id FROM organization_inventory_vaults WHERE vault_id=$1")
                    .bind(vault.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let org=row_uuid(&owner,"organization_id")?;
                let (_,bound_vault,current_revision,current_seq)=Self::inventory_owner(&mut tx,expected,expires_at,org,true).await?;
                if bound_vault!=vault {return Err(Error::NotFound);}
                if request.view_revision!=current_revision {return Err(Error::ViewChanged);}
                if request.cursor>current_seq {return Err(Error::Conflict);}
                let previous:Option<i64>=sqlx::query_scalar("SELECT cursor FROM organization_inventory_acks WHERE vault_id=$1 AND device_id=$2 AND view_revision=$3")
                    .bind(vault.as_bytes().as_slice()).bind(expected.device_id.as_slice()).bind(current_revision.to_be_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                let cursor=request.cursor.max(previous.map(number).transpose()?.unwrap_or(0));
                if previous.is_some() && previous.map(number).transpose()?==Some(cursor) {
                    check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                    tx.commit().await?;
                    return Ok(SyncOrganizationAckResponse{cursor,view_revision:current_revision});
                }
                sqlx::query("INSERT INTO organization_inventory_acks (vault_id,device_id,view_revision,cursor,acknowledged_at_ms) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (vault_id,device_id) DO UPDATE SET view_revision=excluded.view_revision,cursor=excluded.cursor,acknowledged_at_ms=excluded.acknowledged_at_ms")
                    .bind(vault.as_bytes().as_slice()).bind(expected.device_id.as_slice()).bind(current_revision.to_be_bytes().as_slice())
                    .bind(sql_number(cursor)?).bind(now_ms()?).execute(&mut *tx).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|Error::UpdateCommitOutcomeUnknown)?;Ok(SyncOrganizationAckResponse{cursor,view_revision:current_revision})
            }
        }
    };
}

inventory!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_principal,
    sqlite_actor,
    append_audit_event_in_transaction,
    false,
    sqlite_versions_in_transaction
);
inventory!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_principal,
    postgres_actor,
    append_audit_event_in_postgres_transaction,
    true,
    postgres_versions_in_transaction
);

impl SqliteStore {
    pub(super) fn queue_organization_notification(
        _: &mut Transaction<'_, Sqlite>,
        _: Uuid,
        _: u64,
    ) -> std::future::Ready<Result<(), Error>> {
        std::future::ready(Ok(()))
    }
    pub(super) fn queue_memberships_notification(
        _: &mut Transaction<'_, Sqlite>,
        _: [u8; 16],
    ) -> std::future::Ready<Result<(), Error>> {
        std::future::ready(Ok(()))
    }
}
impl PostgresStore {
    pub(super) async fn queue_memberships_notification(
        tx: &mut Transaction<'_, Postgres>,
        account: [u8; 16],
    ) -> Result<(), Error> {
        crate::sync_notifications::publish_memberships_changed(tx, account)
            .await
            .map_err(|_| Error::StorageUnavailable)
    }
    pub(super) async fn queue_organization_notification(
        tx: &mut Transaction<'_, Postgres>,
        organization: Uuid,
        view_revision: u64,
    ) -> Result<(), Error> {
        let row = sqlx::query(
            "SELECT vault_id FROM organization_inventory_vaults WHERE organization_id=$1",
        )
        .bind(organization.as_bytes().as_slice())
        .fetch_one(&mut **tx)
        .await?;
        let event = scoplen_api::sync::SyncNotification::OrganizationViewChanged {
            organization,
            vault: row_uuid(&row, "vault_id")?,
            view_revision,
        };
        crate::sync_notifications::publish(tx, &event).await.map_err(|_| Error::StorageUnavailable)
    }
}
