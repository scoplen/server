// SPDX-License-Identifier: AGPL-3.0-only
//! Current-tenant local user-CA provisioning and audited direct SSH issuance.

use super::{
    CurrentPrincipal, OrganizationStoreError as Error, PostgresStore, SqliteStore, Uuid,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction, check_identity,
    inventory::Graph, now_ms, postgres_principal, sqlite_principal, timestamp,
};
use crate::kms::KeyManagementService;
use scoplen_api::{
    certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateTargets},
    inventory::InventoryType,
    organization::OrganizationListQuery,
    user_ca::{UserCaCreateRequest, UserCaPage, UserCaResource, user_ca_fingerprint},
};
use scoplen_ca::{LocalUserCa, UserCertificateContext};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use std::{collections::BTreeSet, fmt::Write as _, net::IpAddr};

fn digest(
    origin: &str,
    principal: &CurrentPrincipal,
    organization: Uuid,
    segment: &str,
    canonical: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        b"spl-organization-user-ca-operation-v1".as_slice(),
        origin.as_bytes(),
        principal.account_id.as_slice(),
        principal.device_id.as_slice(),
        b"POST",
        format!("/api/v1/orgs/{organization}/{segment}").as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(canonical);
    hash.finalize().into()
}

fn etag(canonical: &[u8]) -> String {
    let mut tag = String::from("\"sha256-");
    for byte in Sha256::digest(canonical) {
        write!(tag, "{byte:02x}").expect("String write");
    }
    tag.push('"');
    tag
}

macro_rules! user_ca {
    ($store:ty,$db:ty,$begin:literal,$principal:ident,$audit:ident) => {
        impl $store {
            async fn user_ca_receipt(tx:&mut Transaction<'_,$db>,expected:&CurrentPrincipal,key:Uuid,now:i64,digest:&[u8;32])->Result<Option<Vec<u8>>,Error> {
                let row=sqlx::query("SELECT request_digest,response_json FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3")
                    .bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(now).fetch_optional(&mut **tx).await?;
                row.map(|row| {
                    if row.try_get::<Vec<u8>,_>("request_digest")?.as_slice()!=digest {return Err(Error::Conflict);}
                    row.try_get("response_json").map_err(Into::into)
                }).transpose()
            }

            async fn append_user_ca_receipt(tx:&mut Transaction<'_,$db>,expected:&CurrentPrincipal,org:Uuid,key:Uuid,now:i64,digest:&[u8;32],response:&[u8])->Result<(),Error> {
                sqlx::query("DELETE FROM organization_inventory_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3")
                    .bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(now).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO organization_inventory_receipts (account_id,idempotency_key,organization_id,request_digest,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                    .bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(digest.as_slice())
                    .bind(response).bind(now).bind(now.checked_add(86_400_000).ok_or(Error::StorageUnavailable)?).execute(&mut **tx).await?;
                Ok(())
            }

            /// Provision one independently generated active CA with encrypted custody, audit and
            /// original-request confirmation in the current Organization transaction.
            /// # Errors
            /// Returns fixed identity, authority, conflict, storage or unknown-commit failures.
            #[allow(clippy::too_many_arguments)]
            pub async fn create_organization_user_ca(&self,expected:&CurrentPrincipal,expires_at:u64,origin:&str,org:Uuid,key:Uuid,request:&UserCaCreateRequest,kms:&dyn KeyManagementService)->Result<UserCaResource,Error> {
                scoplen_model::validate_uuid_v7(key).map_err(|_|Error::InvalidRequest)?;
                let canonical=request.to_json().map_err(|_|Error::InvalidRequest)?;
                let digest=digest(origin,expected,org,"certificate-authorities",&canonical);
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,org,true).await?;
                let now=now_ms()?;
                Self::authorize_organization_action(&mut tx,&current,now,"manage_ca").await?;
                if let Some(response)=Self::user_ca_receipt(&mut tx,expected,key,now,&digest).await? {
                    let resource=UserCaResource::from_json(&response).map_err(|_|Error::StorageUnavailable)?;
                    resource.validate_for_id(request.id).map_err(|_|Error::StorageUnavailable)?;
                    check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                    tx.commit().await?;
                    return Ok(resource);
                }
                let exists=sqlx::query("SELECT id FROM organization_user_cas WHERE organization_id=$1")
                    .bind(org.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.is_some();
                if exists {return Err(Error::Conflict);}
                let signer=LocalUserCa::generate().map_err(|_|Error::StorageUnavailable)?;
                let encrypted=signer.seal(kms.key_encryption_key(),org,request.id).map_err(|_|Error::StorageUnavailable)?;
                let public_key=signer.public_key().map_err(|_|Error::StorageUnavailable)?;
                let mut resource=UserCaResource{id:request.id,etag:"\"pending\"".into(),created_at:timestamp(now)?,updated_at:timestamp(now)?,fingerprint:user_ca_fingerprint(&public_key).map_err(|_|Error::StorageUnavailable)?,public_key};
                resource.etag=etag(&resource.to_json().map_err(|_|Error::StorageUnavailable)?);
                let response=resource.to_json().map_err(|_|Error::StorageUnavailable)?;
                sqlx::query("INSERT INTO organization_user_cas (organization_id,id,encrypted_seed,response_json,last_serial,created_at_ms) VALUES ($1,$2,$3,$4,$5,$6)")
                    .bind(org.as_bytes().as_slice()).bind(request.id.as_bytes().as_slice()).bind(encrypted).bind(&response).bind(0_u64.to_be_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                let event=serde_json::to_vec(&serde_json::json!({"action":"organization.user_ca_created","organization_id":org,"authority_id":request.id,"account_id":Uuid::from_bytes(expected.account_id),"device_id":Uuid::from_bytes(expected.device_id)})).map_err(|_|Error::StorageUnavailable)?;
                $audit(&mut tx,org.into_bytes(),&event,now).await.map_err(|_|Error::StorageUnavailable)?;
                Self::append_user_ca_receipt(&mut tx,expected,org,key,now,&digest,&response).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|Error::CommitOutcomeUnknown)?;
                Ok(resource)
            }

            /// Read only this current team's public trust metadata, independently of asset access.
            /// # Errors
            /// Foreign or unavailable ids return `NotFound`; invalid metadata fails closed.
            pub async fn read_organization_user_ca(&self,expected:&CurrentPrincipal,expires_at:u64,org:Uuid,id:Uuid)->Result<UserCaResource,Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                let response=sqlx::query_scalar::<_,Vec<u8>>("SELECT response_json FROM organization_user_cas WHERE organization_id=$1 AND id=$2")
                    .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let resource=UserCaResource::from_json(&response).map_err(|_|Error::StorageUnavailable)?;
                resource.validate_for_id(id).map_err(|_|Error::StorageUnavailable)?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(resource)
            }

            /// List the initial public active CA under current membership and bounded shared DTOs.
            /// # Errors
            /// Returns current identity, tenant, query or stored-metadata failure.
            pub async fn list_organization_user_cas(&self,expected:&CurrentPrincipal,expires_at:u64,org:Uuid,query:&OrganizationListQuery)->Result<UserCaPage,Error> {
                query.validate().map_err(|_|Error::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                let response=sqlx::query_scalar::<_,Vec<u8>>("SELECT response_json FROM organization_user_cas WHERE organization_id=$1 AND id>$2")
                    .bind(org.as_bytes().as_slice()).bind(query.cursor.map_or([0;16],Uuid::into_bytes).as_slice()).fetch_optional(&mut *tx).await?;
                let items=response.map(|bytes|UserCaResource::from_json(&bytes).map_err(|_|Error::StorageUnavailable)).transpose()?.into_iter().collect();
                let page=UserCaPage{items,next_cursor:None};
                page.validate_for_query(*query).map_err(|_|Error::StorageUnavailable)?;
                page.to_json().map_err(|_|Error::StorageUnavailable)?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await?;Ok(page)
            }

            async fn authorize_user_certificate_targets(tx:&mut Transaction<'_,$db>,graph:&mut Graph,expected:&CurrentPrincipal,org:Uuid,request:&CertificateIssuanceRequest,source:IpAddr)->Result<(),Error> {
                let mut hosts=BTreeSet::new();
                match &request.targets {
                    CertificateTargets::Hosts(ids)=>hosts.extend(ids.iter().copied()),
                    CertificateTargets::HostGroups(groups)=>{
                        for id in groups {
                            let (group,_)=Self::inventory_object(tx,org,*id).await?;
                            if group.object_type!=InventoryType::HostGroup.object_type() || !Self::inventory_readable(tx,graph,&group).await? {return Err(Error::NotFound);}
                            let rows=sqlx::query("SELECT r.source_id FROM organization_inventory_references r JOIN organization_inventory_objects i ON i.organization_id=r.organization_id AND i.object_id=r.source_id JOIN sync_objects s ON s.vault_id=i.vault_id AND s.object_id=i.object_id WHERE r.organization_id=$1 AND r.target_id=$2 AND i.object_type=1 AND s.tombstone=$3 ORDER BY r.source_id")
                                .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(false).fetch_all(&mut **tx).await?;
                            if rows.is_empty(){return Err(Error::PermissionDenied);}
                            for row in rows {hosts.insert(super::inventory::row_uuid(&row,"source_id")?);}
                        }
                    }
                }
                for id in hosts {
                    let (object,_)=Self::inventory_object(tx,org,id).await?;
                    if object.object_type!=InventoryType::Host.object_type() || !Self::inventory_readable(tx,graph,&object).await? {return Err(Error::NotFound);}
                    if !graph.authorize_connect(Uuid::from_bytes(expected.device_id),id,&request.remote_user,source)? {return Err(Error::PermissionDenied);}
                }
                Ok(())
            }

            /// Issue one real D-88/D-90 certificate after current direct-path authorization.
            /// Serial, issued Resource, original receipt and organization audit commit together.
            /// # Errors
            /// Denied/foreign targets disclose no certificate; unknown COMMIT supports only
            /// explicit original-key/body confirmation, which rechecks current authority.
            #[allow(clippy::too_many_arguments)]
            pub async fn issue_organization_user_certificate(&self,expected:&CurrentPrincipal,expires_at:u64,origin:&str,org:Uuid,key:Uuid,request:&CertificateIssuanceRequest,source:IpAddr,kms:&dyn KeyManagementService)->Result<CertificateIssuanceResponse,Error> {
                scoplen_model::validate_uuid_v7(key).map_err(|_|Error::InvalidRequest)?;
                let canonical=request.to_json().map_err(|_|Error::InvalidRequest)?;
                let digest=digest(origin,expected,org,"certificates",&canonical);
                let mut tx=self.pool.begin_with($begin).await?;
                let (current,_,_,_)=Self::inventory_owner(&mut tx,expected,expires_at,org,true).await?;
                let now=now_ms()?;
                let mut graph=Self::inventory_graph(&mut tx,current,now).await?;
                Self::authorize_user_certificate_targets(&mut tx,&mut graph,expected,org,request,source).await?;
                let row=sqlx::query("SELECT id,encrypted_seed,response_json,last_serial FROM organization_user_cas WHERE organization_id=$1")
                    .bind(org.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let authority=super::inventory::row_uuid(&row,"id")?;
                let metadata=UserCaResource::from_json(&row.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                metadata.validate_for_id(authority).map_err(|_|Error::StorageUnavailable)?;
                if let Some(response)=Self::user_ca_receipt(&mut tx,expected,key,now,&digest).await? {
                    let resource=CertificateIssuanceResponse::from_json(&response).map_err(|_|Error::StorageUnavailable)?;
                    resource.validate_request_subject(request).map_err(|_|Error::StorageUnavailable)?;
                    check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                    tx.commit().await?;return Ok(resource);
                }
                let last_serial:[u8;8]=row.try_get::<Vec<u8>,_>("last_serial")?.try_into().map_err(|_|Error::StorageUnavailable)?;
                let serial=u64::from_be_bytes(last_serial).checked_add(1).ok_or(Error::StorageUnavailable)?;
                let signer=LocalUserCa::open(&row.try_get::<Vec<u8>,_>("encrypted_seed")?,kms.key_encryption_key(),org,authority).map_err(|_|Error::StorageUnavailable)?;
                if signer.public_key().map_err(|_|Error::StorageUnavailable)?!=metadata.public_key {return Err(Error::StorageUnavailable);}
                let id=Uuid::now_v7();
                let certificate=signer.issue(request,&UserCertificateContext{organization:org,account:Uuid::from_bytes(expected.account_id),device:Uuid::from_bytes(expected.device_id),certificate:id,serial,now_seconds:u64::try_from(now.div_euclid(1000)).map_err(|_|Error::StorageUnavailable)?}).map_err(|_|Error::StorageUnavailable)?;
                let mut resource=CertificateIssuanceResponse::new(id,"\"pending\"",timestamp(now)?,timestamp(now)?,certificate).map_err(|_|Error::StorageUnavailable)?;
                resource.validate_request_subject(request).map_err(|_|Error::StorageUnavailable)?;
                resource.etag=etag(&resource.to_json().map_err(|_|Error::StorageUnavailable)?);
                let response=resource.to_json().map_err(|_|Error::StorageUnavailable)?;
                sqlx::query("UPDATE organization_user_cas SET last_serial=$3 WHERE organization_id=$1 AND id=$2")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(serial.to_be_bytes().as_slice()).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO organization_user_certificates (organization_id,id,authority_id,account_id,device_id,serial,response_json,created_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
                    .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(expected.account_id.as_slice()).bind(expected.device_id.as_slice()).bind(serial.to_be_bytes().as_slice()).bind(&response).bind(now).execute(&mut *tx).await?;
                let event=serde_json::to_vec(&serde_json::json!({"action":"organization.certificate_issued","organization_id":org,"authority_id":authority,"certificate_id":id,"account_id":Uuid::from_bytes(expected.account_id),"device_id":Uuid::from_bytes(expected.device_id),"serial":serial})).map_err(|_|Error::StorageUnavailable)?;
                $audit(&mut tx,org.into_bytes(),&event,now).await.map_err(|_|Error::StorageUnavailable)?;
                Self::append_user_ca_receipt(&mut tx,expected,org,key,now,&digest,&response).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|Error::CommitOutcomeUnknown)?;
                Ok(resource)
            }
        }
    };
}
user_ca!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    sqlite_principal,
    append_audit_event_in_transaction
);
user_ca!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_principal,
    append_audit_event_in_postgres_transaction
);
