// SPDX-License-Identifier: AGPL-3.0-only
//! Current-tenant local groups and validated persisted Cedar policies.

use super::{
    CurrentPrincipal, OrganizationStoreError as Error, PostgresStore, SqliteStore, Uuid,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction, check_identity,
    now_ms, postgres_principal, sqlite_principal, timestamp,
};
use scoplen_api::{
    group_policy::{
        GroupCreateRequest, GroupFields, GroupPage, GroupResource, GroupSource,
        PolicyCreateRequest, PolicyFields, PolicyPage, PolicyResource, parse_policy_source,
        policy_references,
    },
    organization::OrganizationListQuery,
};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use std::fmt::Write as _;

/// Exact control-plane collection; no arbitrary SQL identifiers are admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKind {
    Group,
    Policy,
}
impl ControlKind {
    fn table(self) -> &'static str {
        match self {
            Self::Group => "organization_groups",
            Self::Policy => "organization_policies",
        }
    }
    fn segment(self) -> &'static str {
        match self {
            Self::Group => "groups",
            Self::Policy => "policies",
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::Group => "manage_members",
            Self::Policy => "manage_policy",
        }
    }
}

/// Complete mutable data already decoded through the shared strict codecs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlFields {
    Group(GroupFields),
    Policy(PolicyFields),
}
impl ControlFields {
    fn kind(&self) -> ControlKind {
        match self {
            Self::Group(_) => ControlKind::Group,
            Self::Policy(_) => ControlKind::Policy,
        }
    }
    fn canonical(&self, id: Uuid) -> Result<Vec<u8>, Error> {
        match self {
            Self::Group(fields) => GroupCreateRequest { id, fields: fields.clone() }.to_json(),
            Self::Policy(fields) => PolicyCreateRequest { id, fields: fields.clone() }.to_json(),
        }
        .map_err(|_| Error::InvalidRequest)
    }
}

/// Typed retained create or current replacement result.
#[derive(Clone, Debug)]
pub enum ControlResource {
    Group(GroupResource),
    Policy(PolicyResource),
}
impl ControlResource {
    /// Encode the public Resource through its shared bounded codec.
    /// # Errors
    /// Damaged stored fields or metadata are unavailable, never partial responses.
    pub fn to_json(&self) -> Result<Vec<u8>, scoplen_api::organization::OrganizationCodecError> {
        match self {
            Self::Group(value) => value.to_json(),
            Self::Policy(value) => value.to_json(),
        }
    }
    /// The strong tag belonging to this exact Resource.
    #[must_use]
    pub fn etag(&self) -> &str {
        match self {
            Self::Group(value) => &value.etag,
            Self::Policy(value) => &value.etag,
        }
    }
    fn id(&self) -> Uuid {
        match self {
            Self::Group(value) => value.id,
            Self::Policy(value) => value.id,
        }
    }
    fn fields(&self) -> ControlFields {
        match self {
            Self::Group(value) => ControlFields::Group(value.fields.clone()),
            Self::Policy(value) => ControlFields::Policy(value.fields.clone()),
        }
    }
    fn created_at(&self) -> &str {
        match self {
            Self::Group(value) => &value.created_at,
            Self::Policy(value) => &value.created_at,
        }
    }
    fn decode(kind: ControlKind, bytes: &[u8]) -> Result<Self, Error> {
        match kind {
            ControlKind::Group => GroupResource::from_json(bytes).map(Self::Group),
            ControlKind::Policy => PolicyResource::from_json(bytes).map(Self::Policy),
        }
        .map_err(|_| Error::StorageUnavailable)
    }
    fn retag(&mut self) -> Result<(), Error> {
        match self {
            Self::Group(value) => value.etag = "\"pending\"".into(),
            Self::Policy(value) => value.etag = "\"pending\"".into(),
        }
        let digest = Sha256::digest(self.to_json().map_err(|_| Error::StorageUnavailable)?);
        let mut etag = String::from("\"sha256-");
        for byte in digest {
            write!(etag, "{byte:02x}").expect("String write");
        }
        etag.push('"');
        match self {
            Self::Group(value) => value.etag = etag,
            Self::Policy(value) => value.etag = etag,
        }
        Ok(())
    }
}

/// Current live id page, including only authorized collection entries.
pub struct ControlPage {
    pub kind: ControlKind,
    pub items: Vec<ControlResource>,
    pub next_cursor: Option<Uuid>,
}
impl ControlPage {
    /// Encode a bounded shared `GroupPage` or `PolicyPage`.
    /// # Errors
    /// Invalid pages and complete-body overflow are rejected.
    pub fn to_json(&self) -> Result<Vec<u8>, scoplen_api::organization::OrganizationCodecError> {
        match self.kind {
            ControlKind::Group => GroupPage {
                items: self
                    .items
                    .iter()
                    .filter_map(|item| {
                        if let ControlResource::Group(value) = item {
                            Some(value.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
                next_cursor: self.next_cursor,
            }
            .to_json(),
            ControlKind::Policy => PolicyPage {
                items: self
                    .items
                    .iter()
                    .filter_map(|item| {
                        if let ControlResource::Policy(value) = item {
                            Some(value.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
                next_cursor: self.next_cursor,
            }
            .to_json(),
        }
    }
}

/// One fully bound Resource target.
#[derive(Clone, Copy)]
pub struct ControlTarget {
    pub organization: Uuid,
    pub kind: ControlKind,
    pub id: Uuid,
}
/// One desired control-plane operation.
pub enum ControlWrite<'a> {
    Create { key: Uuid, fields: &'a ControlFields },
    Replace { if_match: &'a str, fields: &'a ControlFields },
    Delete { if_match: &'a str },
}
/// Confirmed mutation result; equal replacements and original-create replays do not notify.
pub struct ControlWriteResult {
    pub resource: Option<ControlResource>,
    pub changed: bool,
}

macro_rules! controls {
    ($store:ty,$db:ty,$begin:literal,$principal:ident,$audit:ident) => {
        impl $store {
            pub(super) async fn clear_organization_groups(tx:&mut Transaction<'_,$db>,organization:Uuid,member:Option<Uuid>,now:i64)->Result<(),Error> {
                let suffix=if member.is_some(){" AND membership_id=$3"}else{""};
                let update_sql=format!("UPDATE organization_groups SET updated_at_ms=CASE WHEN updated_at_ms>=$1 THEN updated_at_ms+1 ELSE $1 END WHERE organization_id=$2 AND id IN (SELECT group_id FROM organization_group_members WHERE organization_id=$2{suffix})");
                let mut update=sqlx::query(&update_sql)
                    .bind(now).bind(organization.as_bytes().as_slice());
                if let Some(id)=member {update=update.bind(id.as_bytes().to_vec());}
                update.execute(&mut **tx).await?;
                let sql=if member.is_some(){"DELETE FROM organization_group_members WHERE organization_id=$1 AND membership_id=$2"}else{"DELETE FROM organization_group_members WHERE organization_id=$1"};
                let mut delete=sqlx::query(sql).bind(organization.as_bytes().as_slice());
                if let Some(id)=member {delete=delete.bind(id.as_bytes().to_vec());}
                delete.execute(&mut **tx).await?;
                Ok(())
            }

            async fn control_resource(tx:&mut Transaction<'_,$db>,target:ControlTarget)->Result<ControlResource,Error> {
                let row=sqlx::query(&format!("SELECT response_json,updated_at_ms FROM {} WHERE organization_id=$1 AND id=$2 AND deleted_at_ms IS NULL",target.kind.table()))
                    .bind(target.organization.as_bytes().as_slice()).bind(target.id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                let mut value=ControlResource::decode(target.kind,&row.try_get::<Vec<u8>,_>("response_json")?)?;
                if value.id()!=target.id {return Err(Error::StorageUnavailable);}
                if let ControlResource::Group(group)=&mut value {
                    let rows=sqlx::query("SELECT gm.membership_id FROM organization_group_members gm JOIN organization_memberships m ON m.organization_id=gm.organization_id AND m.id=gm.membership_id WHERE gm.organization_id=$1 AND gm.group_id=$2 AND m.status='active' ORDER BY gm.membership_id")
                        .bind(target.organization.as_bytes().as_slice()).bind(target.id.as_bytes().as_slice()).fetch_all(&mut **tx).await?;
                    group.fields.members=rows.iter().map(|row|super::inventory::row_uuid(row,"membership_id")).collect::<Result<_,_>>()?;
                    group.updated_at=timestamp(row.try_get("updated_at_ms")?)?;
                    value.retag()?;
                }
                Ok(value)
            }

            async fn control_references(tx:&mut Transaction<'_,$db>,organization:Uuid,fields:&ControlFields)->Result<(),Error> {
                let org=organization.as_bytes().as_slice();
                match fields {
                    ControlFields::Group(fields)=>{
                        fields.validate().map_err(|_|Error::InvalidRequest)?;
                        for id in &fields.members {
                            let found:Option<Vec<u8>>=sqlx::query_scalar("SELECT id FROM organization_memberships WHERE organization_id=$1 AND id=$2 AND status='active'")
                                .bind(org).bind(id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
                            if found.is_none(){return Err(Error::NotFound);}
                        }
                    }
                    ControlFields::Policy(fields)=>{
                        fields.validate().map_err(|_|Error::InvalidRequest)?;
                        let policy=parse_policy_source(&fields.source).map_err(|_|Error::InvalidRequest)?;
                        for reference in policy_references(&policy,organization).map_err(|_|Error::NotFound)? {
                            let kind=reference.type_name().to_string();
                            let id=Uuid::parse_str(reference.id().unescaped()).map_err(|_|Error::InvalidRequest)?;
                            let found=match kind.as_str(){
                                "Organization"=>id==organization,
                                "Account"=>sqlx::query_scalar::<_,Vec<u8>>("SELECT account_id FROM organization_memberships WHERE organization_id=$1 AND account_id=$2 AND status='active'").bind(org).bind(id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.is_some(),
                                "Membership"=>sqlx::query_scalar::<_,Vec<u8>>("SELECT id FROM organization_memberships WHERE organization_id=$1 AND id=$2 AND status='active'").bind(org).bind(id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.is_some(),
                                "Device"=>sqlx::query_scalar::<_,Vec<u8>>("SELECT d.device_id FROM identity_devices d JOIN organization_memberships m ON m.account_id=d.account_id WHERE m.organization_id=$1 AND d.device_id=$2 AND m.status='active' AND d.active=$3").bind(org).bind(id.as_bytes().as_slice()).bind(true).fetch_optional(&mut **tx).await?.is_some(),
                                "Group"=>sqlx::query_scalar::<_,Vec<u8>>("SELECT id FROM organization_groups WHERE organization_id=$1 AND id=$2 AND deleted_at_ms IS NULL").bind(org).bind(id.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.is_some(),
                                "Host"|"HostGroup"|"GatewayNetwork"|"AccessProfile"|"Route"|"TrustRecord"|"Snippet"=>match Self::inventory_object(tx,organization,id).await {Ok((object,_))=>object.object_type.to_string()==kind,Err(Error::NotFound)=>false,Err(error)=>return Err(error)},
                                // These separate workflows have no current durable Resource in this profile.
                                _=>false,
                            };
                            if !found{return Err(Error::NotFound);}
                        }
                    }
                }
                Ok(())
            }

            async fn group_deletion_allowed(tx:&mut Transaction<'_,$db>,organization:Uuid,id:Uuid)->Result<(),Error> {
                let rows=sqlx::query("SELECT source FROM organization_policies WHERE organization_id=$1 AND deleted_at_ms IS NULL")
                    .bind(organization.as_bytes().as_slice()).fetch_all(&mut **tx).await?;
                for row in rows {
                    let policy=parse_policy_source(&row.try_get::<String,_>("source")?).map_err(|_|Error::StorageUnavailable)?;
                    if policy_references(&policy,organization).map_err(|_|Error::StorageUnavailable)?.iter().any(|reference|reference.type_name().to_string()=="Group"&&reference.id().unescaped()==id.to_string()) {return Err(Error::Conflict);}
                }
                Ok(())
            }

            /// Read a current Group or Policy through current tenant Cedar authority.
            /// # Errors
            /// Missing tenant membership and foreign ids share the fixed `NotFound` result.
            pub async fn read_organization_control(&self,expected:&CurrentPrincipal,expires_at:u64,target:ControlTarget)->Result<ControlResource,Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,target.organization,false).await?;
                let graph=Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                let can_read=graph.authorize("view_policy","Organization",target.organization)?
                    || (target.kind==ControlKind::Group&&graph.authorize("manage_members","Organization",target.organization)?);
                if !can_read{return Err(Error::PermissionDenied);}
                let value=Self::control_resource(&mut tx,target).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(value)
            }

            /// Read one authorized live, ascending and complete-body bounded page.
            /// # Errors
            /// Current identity, membership, policy, query and storage errors fail closed.
            pub async fn list_organization_control(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,kind:ControlKind,query:OrganizationListQuery)->Result<ControlPage,Error> {
                query.validate().map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,organization,false).await?;
                let graph=Self::inventory_graph(&mut tx,current,now_ms()?).await?;
                if !(graph.authorize("view_policy","Organization",organization)? || (kind==ControlKind::Group&&graph.authorize("manage_members","Organization",organization)?)){return Err(Error::PermissionDenied);}
                let rows=sqlx::query(&format!("SELECT id FROM {} WHERE organization_id=$1 AND deleted_at_ms IS NULL AND id>$2 ORDER BY id LIMIT $3",kind.table()))
                    .bind(organization.as_bytes().as_slice()).bind(query.cursor.map(|id|id.as_bytes().to_vec()).unwrap_or_default()).bind(i64::from(query.limit)+1).fetch_all(&mut *tx).await?;
                let mut page=ControlPage{kind,items:Vec::new(),next_cursor:None};
                for row in rows {
                    if page.items.len()==usize::from(query.limit){page.next_cursor=page.items.last().map(ControlResource::id);break;}
                    let id=super::inventory::row_uuid(&row,"id")?;
                    page.items.push(Self::control_resource(&mut tx,ControlTarget{organization,kind,id}).await?);
                    if page.to_json().is_err(){page.items.pop();page.next_cursor=page.items.last().map(ControlResource::id);if page.items.is_empty(){return Err(Error::StorageUnavailable);}break;}
                }
                page.to_json().map_err(|_|Error::StorageUnavailable)?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(page)
            }

            /// Persist one complete desired value, its associations, revision and audit atomically.
            /// # Errors
            /// Returns fixed current authority, precondition, reference or storage errors.
            #[allow(clippy::too_many_lines)]
            pub async fn write_organization_control(&self,expected:&CurrentPrincipal,expires_at:u64,origin:&str,target:ControlTarget,write:ControlWrite<'_>)->Result<ControlWriteResult,Error> {
                scoplen_model::validate_uuid_v7(target.id).map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,target.organization,true).await?;
                let now=now_ms()?;
                let graph=Self::inventory_graph(&mut tx,current,now).await?;
                if !graph.authorize(target.kind.action(),"Organization",target.organization)? {return Err(Error::PermissionDenied);}
                let org=target.organization.as_bytes().as_slice();
                let id=target.id.as_bytes().as_slice();
                let mut receipt=None;
                let (previous,fields)=match write {
                    ControlWrite::Create{key,fields}=>{
                        if fields.kind()!=target.kind{return Err(Error::InvalidRequest);}
                        let canonical=fields.canonical(target.id)?;
                        let mut hash=Sha256::new();
                        for part in [b"spl-organization-control-create-v1".as_slice(),origin.as_bytes(),expected.account_id.as_slice(),expected.device_id.as_slice(),b"POST",format!("/api/v1/orgs/{}/{}",target.organization,target.kind.segment()).as_bytes()] {hash.update(part);hash.update([0]);}
                        hash.update(canonical);let digest:[u8;32]=hash.finalize().into();
                        Self::control_references(&mut tx,target.organization,fields).await?;
                        let stored=sqlx::query("SELECT request_digest,response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3").bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(now).fetch_optional(&mut *tx).await?;
                        if let Some(row)=stored {
                            if row.try_get::<Vec<u8>,_>("request_digest")?.as_slice()!=digest {return Err(Error::Conflict);}
                            let retained=ControlResource::decode(target.kind,&row.try_get::<Vec<u8>,_>("response_json")?)?;
                            if retained.id()!=target.id{return Err(Error::StorageUnavailable);}
                            check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                            tx.commit().await?;return Ok(ControlWriteResult{resource:Some(retained),changed:false});
                        }
                        let used=sqlx::query_scalar::<_,Vec<u8>>(&format!("SELECT id FROM {} WHERE organization_id=$1 AND id=$2",target.kind.table())).bind(org).bind(id).fetch_optional(&mut *tx).await?;
                        if used.is_some(){return Err(Error::Conflict);}
                        receipt=Some((key,digest));(None,Some(fields.clone()))
                    }
                    ControlWrite::Replace{if_match,fields}=>{
                        if fields.kind()!=target.kind{return Err(Error::InvalidRequest);}
                        fields.canonical(target.id)?;
                        let current=Self::control_resource(&mut tx,target).await?;
                        if matches!(&current,ControlResource::Group(value) if value.source!=GroupSource::Local){return Err(Error::PermissionDenied);}
                        if current.etag()!=if_match{return Err(Error::PreconditionFailed);}
                        Self::control_references(&mut tx,target.organization,fields).await?;
                        if current.fields().canonical(target.id)?==fields.canonical(target.id)? {check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;tx.commit().await?;return Ok(ControlWriteResult{resource:Some(current),changed:false});}
                        (Some(current),Some(fields.clone()))
                    }
                    ControlWrite::Delete{if_match}=>{
                        let current=Self::control_resource(&mut tx,target).await?;
                        if matches!(&current,ControlResource::Group(value) if value.source!=GroupSource::Local){return Err(Error::PermissionDenied);}
                        if current.etag()!=if_match{return Err(Error::PreconditionFailed);}
                        if target.kind==ControlKind::Group {Self::group_deletion_allowed(&mut tx,target.organization,target.id).await?;}
                        (Some(current),None)
                    }
                };
                let created_at=previous.as_ref().map(|value|value.created_at().to_owned()).unwrap_or(timestamp(now)?);
                let updated_at=timestamp(now)?;
                let mut resource=fields.map(|fields|match fields {
                    ControlFields::Group(fields)=>ControlResource::Group(GroupResource{id:target.id,etag:"\"pending\"".into(),created_at:created_at.clone(),updated_at:updated_at.clone(),fields,source:GroupSource::Local}),
                    ControlFields::Policy(fields)=>ControlResource::Policy(PolicyResource{id:target.id,etag:"\"pending\"".into(),created_at:created_at.clone(),updated_at:updated_at.clone(),fields}),
                });
                if let Some(value)=&mut resource {value.retag()?;}
                match &resource {
                    Some(ControlResource::Group(value))=>{
                        sqlx::query("INSERT INTO organization_groups (organization_id,id,name,source,response_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'local',$4,$5,$5) ON CONFLICT (organization_id,id) DO UPDATE SET name=excluded.name,response_json=excluded.response_json,updated_at_ms=excluded.updated_at_ms")
                            .bind(org).bind(id).bind(&value.fields.name).bind(value.to_json().map_err(|_|Error::StorageUnavailable)?).bind(now).execute(&mut *tx).await?;
                    }
                    Some(ControlResource::Policy(value))=>{
                        sqlx::query("INSERT INTO organization_policies (organization_id,id,name,source,enabled,response_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT (organization_id,id) DO UPDATE SET name=excluded.name,source=excluded.source,enabled=excluded.enabled,response_json=excluded.response_json,updated_at_ms=excluded.updated_at_ms")
                            .bind(org).bind(id).bind(&value.fields.name).bind(&value.fields.source).bind(i64::from(value.fields.enabled)).bind(value.to_json().map_err(|_|Error::StorageUnavailable)?).bind(now).execute(&mut *tx).await?;
                    }
                    None=>{sqlx::query(&format!("UPDATE {} SET deleted_at_ms=$1,updated_at_ms=$1 WHERE organization_id=$2 AND id=$3",target.kind.table())).bind(now).bind(org).bind(id).execute(&mut *tx).await?;}
                }
                if target.kind==ControlKind::Group {
                    sqlx::query("DELETE FROM organization_group_members WHERE organization_id=$1 AND group_id=$2").bind(org).bind(id).execute(&mut *tx).await?;
                    if let Some(ControlResource::Group(value))=&resource {for member in &value.fields.members {sqlx::query("INSERT INTO organization_group_members (organization_id,group_id,membership_id) VALUES ($1,$2,$3)").bind(org).bind(id).bind(member.as_bytes().as_slice()).execute(&mut *tx).await?;}}
                }
                Self::team_revision(&mut tx,target.organization,now).await?;
                let event=serde_json::to_vec(&serde_json::json!({"action":format!("organization.{}_{}",target.kind.segment(),if resource.is_none(){"deleted"}else if receipt.is_some(){"created"}else{"updated"}),"account_id":Uuid::from_bytes(expected.account_id),"device_id":Uuid::from_bytes(expected.device_id),"organization_id":target.organization,"object_id":target.id})).map_err(|_|Error::StorageUnavailable)?;
                $audit(&mut tx,target.organization.into_bytes(),&event,now).await.map_err(|_|Error::StorageUnavailable)?;
                if let Some((key,digest))=receipt {
                    sqlx::query("DELETE FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3").bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                    sqlx::query("INSERT INTO organization_inventory_receipts (account_id,idempotency_key,organization_id,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)").bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(org).bind(digest.as_slice()).bind(resource.as_ref().ok_or(Error::StorageUnavailable)?.to_json().map_err(|_|Error::StorageUnavailable)?).bind(now).bind(now.checked_add(86_400_000).ok_or(Error::StorageUnavailable)?).execute(&mut *tx).await?;
                }
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|if receipt.is_some(){Error::CommitOutcomeUnknown}else{Error::UpdateCommitOutcomeUnknown})?;
                Ok(ControlWriteResult{resource,changed:true})
            }
        }
    };
}
controls!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    sqlite_principal,
    append_audit_event_in_transaction
);
controls!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_principal,
    append_audit_event_in_postgres_transaction
);
