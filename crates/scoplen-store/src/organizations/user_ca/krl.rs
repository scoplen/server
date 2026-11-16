// SPDX-License-Identifier: AGPL-3.0-only
//! Atomic D-141 activation, persisted snapshots and CA-owned serial revocations.

use super::{
    CertificateIssuanceResponse, CurrentPrincipal, Error, Postgres, PostgresStore, Row, Sqlite,
    SqliteStore, Transaction, UserCaResource, Uuid, append_audit_event_in_postgres_transaction,
    append_audit_event_in_transaction, check_identity, now_ms, postgres_principal,
    sqlite_principal,
};
use scoplen_api::krl::{MAX_USER_CA_KRL_BYTES, MAX_USER_CA_KRL_SERIALS, UserCaKrl};
use scoplen_ca::verify_stored_user_certificate;

fn number(bytes: Vec<u8>) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| Error::StorageUnavailable)?))
}

fn seconds(now: i64) -> Result<u64, Error> {
    u64::try_from(now.div_euclid(1_000)).map_err(|_| Error::StorageUnavailable)
}

macro_rules! krl_store {
    ($store:ty,$db:ty,$begin:literal,$principal:ident,$audit:ident,$postgres:literal) => {
        impl $store {
            /// Verify historical signed expiries and atomically activate complete CA snapshots.
            /// Older writers must be stopped before this forward-only activation begins.
            /// # Errors
            /// Fails closed on corrupt ownership, signature, serial, expiry or over-cap state.
            pub async fn initialize_organization_user_ca_krls(&self) -> Result<(),Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                Self::activate_user_ca_krls(&mut tx).await?;
                tx.commit().await.map_err(|_|Error::StorageUnavailable)
            }

            pub(in crate::organizations) async fn require_user_ca_krl_activation(tx:&mut Transaction<'_,$db>) -> Result<(),Error> {
                let active:i64=sqlx::query_scalar("SELECT activated FROM organization_user_ca_krl_activation WHERE singleton=1")
                    .fetch_one(&mut **tx).await?;
                if active!=1 {return Err(Error::StorageUnavailable);}
                Ok(())
            }

            pub(in crate::organizations) async fn activate_user_ca_krls(tx:&mut Transaction<'_,$db>) -> Result<(),Error> {
                let active:i64=sqlx::query_scalar("SELECT activated FROM organization_user_ca_krl_activation WHERE singleton=1")
                    .fetch_one(&mut **tx).await?;
                if active==1 {return Ok(());}
                let suffix=if $postgres {" FOR UPDATE"} else {""};
                let active:i64=sqlx::query_scalar(&format!("SELECT activated FROM organization_user_ca_krl_activation WHERE singleton=1{suffix}"))
                    .fetch_one(&mut **tx).await?;
                if active==1 {return Ok(());}
                if active!=0 {return Err(Error::StorageUnavailable);}
                let now=now_ms()?;
                let now_seconds=seconds(now)?;
                let cas=sqlx::query("SELECT c.organization_id,c.id,c.response_json,c.last_serial,o.dissolved_at_ms FROM organization_user_cas c JOIN organizations o ON o.id=c.organization_id ORDER BY c.organization_id,c.id")
                    .fetch_all(&mut **tx).await?;
                for ca in cas {
                    let org=super::super::inventory::row_uuid(&ca,"organization_id")?;
                    let authority=super::super::inventory::row_uuid(&ca,"id")?;
                    scoplen_model::validate_uuid_v7(org).map_err(|_|Error::StorageUnavailable)?;
                    let metadata=UserCaResource::from_json(&ca.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                    metadata.validate_for_id(authority).map_err(|_|Error::StorageUnavailable)?;
                    let last=number(ca.try_get("last_serial")?)?;
                    let dissolved=ca.try_get::<Option<i64>,_>("dissolved_at_ms")?.is_some();
                    let mut cursor=[0_u8;16];
                    let mut outstanding=0_usize;
                    loop {
                        // Bound certificate payload allocation independently of retained historical count.
                        let rows=sqlx::query("SELECT c.id,c.account_id,c.device_id,c.serial,c.response_json,m.status FROM organization_user_certificates c LEFT JOIN organization_memberships m ON m.organization_id=c.organization_id AND m.account_id=c.account_id WHERE c.organization_id=$1 AND c.authority_id=$2 AND c.id>$3 ORDER BY c.id LIMIT 128")
                            .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(cursor.as_slice()).fetch_all(&mut **tx).await?;
                        if rows.is_empty(){break;}
                        for row in rows {
                            let id=super::super::inventory::row_uuid(&row,"id")?;
                            let account=super::super::inventory::row_uuid(&row,"account_id")?;
                            let device=super::super::inventory::row_uuid(&row,"device_id")?;
                            let serial=number(row.try_get("serial")?)?;
                            if serial>last {return Err(Error::StorageUnavailable);}
                            let resource=CertificateIssuanceResponse::from_json(&row.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                            if resource.id!=id {return Err(Error::StorageUnavailable);}
                            let expiry=verify_stored_user_certificate(&resource.certificate,&metadata.public_key,org,account,device,id,serial).map_err(|_|Error::StorageUnavailable)?;
                            sqlx::query("UPDATE organization_user_certificates SET valid_before=$1 WHERE organization_id=$2 AND id=$3")
                                .bind(expiry.to_be_bytes().as_slice()).bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut **tx).await?;
                            if expiry>now_seconds {
                                outstanding+=1;
                                if outstanding>MAX_USER_CA_KRL_SERIALS {return Err(Error::StorageUnavailable);}
                                if dissolved || row.try_get::<Option<String>,_>("status")?.as_deref()!=Some("active") {
                                    sqlx::query("INSERT INTO organization_user_ca_revocations (organization_id,authority_id,serial,valid_before) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                                        .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(serial.to_be_bytes().as_slice()).bind(expiry.to_be_bytes().as_slice()).execute(&mut **tx).await?;
                                }
                            }
                            cursor=id.into_bytes();
                        }
                    }
                    let serials=Self::effective_user_ca_revocations(tx,org,authority,now_seconds).await?;
                    Self::insert_user_ca_krl(tx,org,authority,&metadata.public_key,now_seconds,&serials).await?;
                    let event=serde_json::to_vec(&serde_json::json!({"action":"organization.user_ca_krl_activated","organization_id":org,"authority_id":authority})).map_err(|_|Error::StorageUnavailable)?;
                    $audit(tx,org.into_bytes(),&event,now).await.map_err(|_|Error::StorageUnavailable)?;
                }
                let unbound:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_user_certificates WHERE valid_before IS NULL").fetch_one(&mut **tx).await?;
                if unbound!=0 {return Err(Error::StorageUnavailable);}
                sqlx::query("UPDATE organization_user_ca_krl_activation SET activated=1 WHERE singleton=1").execute(&mut **tx).await?;
                Ok(())
            }

            async fn effective_user_ca_revocations(tx:&mut Transaction<'_,$db>,org:Uuid,authority:Uuid,now:u64)->Result<Vec<u64>,Error> {
                let rows=sqlx::query_scalar::<_,Vec<u8>>("SELECT serial FROM organization_user_ca_revocations WHERE organization_id=$1 AND authority_id=$2 AND valid_before>$3 ORDER BY serial LIMIT 100001")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(now.to_be_bytes().as_slice()).fetch_all(&mut **tx).await?;
                if rows.len()>MAX_USER_CA_KRL_SERIALS {return Err(Error::StorageUnavailable);}
                rows.into_iter().map(number).collect()
            }

            pub(super) async fn insert_user_ca_krl(tx:&mut Transaction<'_,$db>,org:Uuid,authority:Uuid,public_key:&str,now:u64,serials:&[u64])->Result<(),Error> {
                let snapshot=UserCaKrl::new(public_key,1,now,serials).and_then(|value|value.to_bytes()).map_err(|_|Error::StorageUnavailable)?;
                sqlx::query("INSERT INTO organization_user_ca_krls (organization_id,authority_id,version,generated_at,snapshot) VALUES ($1,$2,$3,$4,$5)")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(1_u64.to_be_bytes().as_slice()).bind(now.to_be_bytes().as_slice()).bind(snapshot).execute(&mut **tx).await?;
                Ok(())
            }

            pub(super) async fn stored_user_ca_krl(tx:&mut Transaction<'_,$db>,org:Uuid,authority:Uuid,public_key:&str)->Result<(UserCaKrl,Vec<u8>),Error> {
                let row=sqlx::query("SELECT version,generated_at,CASE WHEN length(snapshot)<=4194304 THEN snapshot ELSE NULL END AS snapshot FROM organization_user_ca_krls WHERE organization_id=$1 AND authority_id=$2")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.ok_or(Error::StorageUnavailable)?;
                let bytes:Vec<u8>=row.try_get::<Option<Vec<u8>>,_>("snapshot")?.ok_or(Error::StorageUnavailable)?;
                if bytes.len()>MAX_USER_CA_KRL_BYTES {return Err(Error::StorageUnavailable);}
                let snapshot=UserCaKrl::from_bytes(&bytes,public_key).map_err(|_|Error::StorageUnavailable)?;
                if snapshot.version()!=number(row.try_get("version")?)? || snapshot.generated_at_seconds()!=number(row.try_get("generated_at")?)? {return Err(Error::StorageUnavailable);}
                Ok((snapshot,bytes))
            }

            /// Read one complete persisted KRL under current Device and tenant authority.
            /// This never initializes, repairs, regenerates or prunes snapshot state.
            /// # Errors
            /// Returns same-not-found isolation or a fixed storage error for incomplete bytes.
            pub async fn read_organization_user_ca_krl(&self,expected:&CurrentPrincipal,expires_at:u64,org:Uuid,authority:Uuid)->Result<Vec<u8>,Error> {
                let mut tx=self.pool.begin_with($begin).await?;
                Self::inventory_owner(&mut tx,expected,expires_at,org,false).await?;
                Self::require_user_ca_krl_activation(&mut tx).await?;
                let response=sqlx::query_scalar::<_,Vec<u8>>("SELECT response_json FROM organization_user_cas WHERE organization_id=$1 AND id=$2")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
                let metadata=UserCaResource::from_json(&response).map_err(|_|Error::StorageUnavailable)?;
                metadata.validate_for_id(authority).map_err(|_|Error::StorageUnavailable)?;
                let (_,bytes)=Self::stored_user_ca_krl(&mut tx,org,authority,&metadata.public_key).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|Error::StorageUnavailable)?;
                Ok(bytes)
            }

            pub(in crate::organizations) async fn revoke_user_ca_serials(tx:&mut Transaction<'_,$db>,org:Uuid,account:Option<Uuid>,now:i64)->Result<(),Error> {
                Self::require_user_ca_krl_activation(tx).await?;
                let row=sqlx::query("SELECT id,response_json FROM organization_user_cas WHERE organization_id=$1")
                    .bind(org.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
                let Some(row)=row else {return Ok(())};
                let authority=super::super::inventory::row_uuid(&row,"id")?;
                let metadata=UserCaResource::from_json(&row.try_get::<Vec<u8>,_>("response_json")?).map_err(|_|Error::StorageUnavailable)?;
                metadata.validate_for_id(authority).map_err(|_|Error::StorageUnavailable)?;
                let (previous,_)=Self::stored_user_ca_krl(tx,org,authority,&metadata.public_key).await?;
                let now=seconds(now)?;
                let unverified:i64=sqlx::query_scalar("SELECT COUNT(*) FROM organization_user_certificates WHERE organization_id=$1 AND authority_id=$2 AND valid_before IS NULL")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
                if unverified!=0 {return Err(Error::StorageUnavailable);}
                sqlx::query("INSERT INTO organization_user_ca_revocations (organization_id,authority_id,serial,valid_before) SELECT organization_id,authority_id,serial,valid_before FROM organization_user_certificates WHERE organization_id=$1 AND authority_id=$2 AND valid_before>$3 AND account_id=COALESCE($4,account_id) ON CONFLICT DO NOTHING")
                    .bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).bind(now.to_be_bytes().as_slice()).bind(account.map(|id|id.as_bytes().to_vec())).execute(&mut **tx).await?;
                let serials=Self::effective_user_ca_revocations(tx,org,authority,now).await?;
                if previous.revoked_serials()==serials {return Ok(());}
                let version=previous.version().checked_add(1).ok_or(Error::StorageUnavailable)?;
                let snapshot=UserCaKrl::new(&metadata.public_key,version,now,&serials).and_then(|value|value.to_bytes()).map_err(|_|Error::StorageUnavailable)?;
                sqlx::query("UPDATE organization_user_ca_krls SET version=$1,generated_at=$2,snapshot=$3 WHERE organization_id=$4 AND authority_id=$5")
                    .bind(version.to_be_bytes().as_slice()).bind(now.to_be_bytes().as_slice()).bind(snapshot).bind(org.as_bytes().as_slice()).bind(authority.as_bytes().as_slice()).execute(&mut **tx).await?;
                Ok(())
            }
        }
    };
}

krl_store!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    sqlite_principal,
    append_audit_event_in_transaction,
    false
);
krl_store!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_principal,
    append_audit_event_in_postgres_transaction,
    true
);
