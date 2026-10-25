// SPDX-License-Identifier: AGPL-3.0-only
//! Shared immutable historical facts and deployment-wide retained Device freshness.

use futures_util::TryStreamExt as _;
use scoplen_api::account_admission::{AccountCommittedConfirmation, AccountRequestKind};
use scoplen_crypto::{
    DeviceCertificate, RevocationStatement, SecretBytes, canonical_device_public_key,
};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiptError {
    InvalidMaterial,
    Conflict,
    QuotaExceeded,
    Storage,
}

impl From<sqlx::Error> for ReceiptError {
    fn from(error: sqlx::Error) -> Self {
        if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
            Self::Conflict
        } else {
            Self::Storage
        }
    }
}

pub(crate) struct AccountOperationReceipt {
    pub(crate) confirmation: AccountCommittedConfirmation,
    pub(crate) signing: [u8; 65],
    pub(crate) kem: [u8; 65],
    pub(crate) root: [u8; 32],
}

impl AccountOperationReceipt {
    pub(crate) fn matches(
        &self,
        expected: &AccountCommittedConfirmation,
        root: &[u8; 32],
        keys: &([u8; 65], [u8; 65]),
    ) -> bool {
        let actual = &self.confirmation;
        let digest_matches =
            SecretBytes::new(actual.request_digest) == SecretBytes::new(expected.request_digest);
        digest_matches
            && actual.kind == expected.kind
            && actual.operation_id == expected.operation_id
            && actual.account_id == expected.account_id
            && actual.personal_vault_id == expected.personal_vault_id
            && actual.device_id == expected.device_id
            && actual.admitted_key_revision == expected.admitted_key_revision
            && &self.root == root
            && (self.signing, self.kem) == *keys
    }
}

pub(crate) fn device_keys(certificate: &[u8]) -> Result<([u8; 65], [u8; 65]), ReceiptError> {
    let certificate =
        DeviceCertificate::decode(certificate).map_err(|_| ReceiptError::InvalidMaterial)?;
    Ok((
        canonical_device_public_key(&certificate.signing_public_key)
            .map_err(|_| ReceiptError::InvalidMaterial)?,
        canonical_device_public_key(&certificate.kem_public_key)
            .map_err(|_| ReceiptError::InvalidMaterial)?,
    ))
}

fn fixed<R: Row, const N: usize>(row: &R, name: &str) -> Result<[u8; N], ReceiptError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    row.try_get::<Vec<u8>, _>(name)
        .map_err(|_| ReceiptError::Storage)?
        .try_into()
        .map_err(|_| ReceiptError::Storage)
}

fn receipt_id(bytes: [u8; 16]) -> Result<Uuid, ReceiptError> {
    let id = Uuid::from_bytes(bytes);
    crate::account_entry_admission::valid_id(id).map_err(|_| ReceiptError::Storage)?;
    Ok(id)
}

macro_rules! receipts {
    ($db:ty,$read:ident,$append:ident,$fresh:ident,$postgres:literal) => {
        pub(crate) async fn $read(tx:&mut Transaction<'_,$db>,operation:Uuid)
            ->Result<Option<AccountOperationReceipt>,ReceiptError> {
            let length=if $postgres {"octet_length"} else {"length"};
            let fields=[("operation_id",16),("account_id",16),("personal_vault_id",16),("device_id",16),
                ("request_digest",32),("device_signing_public_key",65),("device_kem_public_key",65),("account_signing_public_key",32)]
                .map(|(field,size)|{
                    let blob=if $postgres {String::new()}else{format!("typeof({field})='blob' AND ")};
                    format!("CASE WHEN {blob}{length}({field})={size} THEN {field} END AS {field}")
                }).join(",");
            let row=sqlx::query(&format!("SELECT {fields},kind,admitted_key_revision,committed_at_ms FROM account_operation_receipts WHERE operation_id=$1"))
                .bind(operation.as_bytes().as_slice()).fetch_optional(&mut **tx).await?;
            let Some(row)=row else{return Ok(None);};
            let revision:i64=row.try_get("admitted_key_revision")?;
            let committed:i64=row.try_get("committed_at_ms")?;
            let kind=match row.try_get::<i64,_>("kind")? {1=>AccountRequestKind::Register,2=>AccountRequestKind::Admit,_=>return Err(ReceiptError::Storage)};
            let signing=fixed::<_,65>(&row,"device_signing_public_key")?;
            let kem=fixed::<_,65>(&row,"device_kem_public_key")?;
            let root=fixed::<_,32>(&row,"account_signing_public_key")?;
            if revision<=0 || committed<=0 || signing==kem
                || canonical_device_public_key(&signing).ok()!=Some(signing)
                || canonical_device_public_key(&kem).ok()!=Some(kem)
                || ed25519_dalek::VerifyingKey::from_bytes(&root).is_err() {return Err(ReceiptError::Storage);}
            Ok(Some(AccountOperationReceipt{confirmation:AccountCommittedConfirmation{
                kind,operation_id:receipt_id(fixed(&row,"operation_id")?)?,account_id:receipt_id(fixed(&row,"account_id")?)?,
                personal_vault_id:receipt_id(fixed(&row,"personal_vault_id")?)?,device_id:receipt_id(fixed(&row,"device_id")?)?,
                request_digest:fixed(&row,"request_digest")?,admitted_key_revision:u64::try_from(revision).map_err(|_|ReceiptError::Storage)?,
            },signing,kem,root}))
        }

        pub(crate) async fn $append(tx:&mut Transaction<'_,$db>,confirmation:&AccountCommittedConfirmation,
            keys:&([u8;65],[u8;65]),root:&[u8;32],now:i64)->Result<(),ReceiptError> {
            let exists:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts WHERE operation_id=$1")
                .bind(confirmation.operation_id.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
            if exists!=0 {return Err(ReceiptError::Conflict);}
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts WHERE account_id=$1")
                .bind(confirmation.account_id.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
            if !(0..=65_536).contains(&count) {return Err(ReceiptError::Storage);}
            if count==65_536 {return Err(ReceiptError::QuotaExceeded);}
            let kind=match confirmation.kind {AccountRequestKind::Register=>1_i64,AccountRequestKind::Admit=>2_i64};
            let revision=i64::try_from(confirmation.admitted_key_revision).map_err(|_|ReceiptError::Storage)?;
            let inserted=sqlx::query("INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                .bind(confirmation.operation_id.as_bytes().as_slice()).bind(confirmation.account_id.as_bytes().as_slice())
                .bind(confirmation.personal_vault_id.as_bytes().as_slice()).bind(confirmation.device_id.as_bytes().as_slice())
                .bind(confirmation.request_digest.as_slice()).bind(kind).bind(keys.0.as_slice()).bind(keys.1.as_slice())
                .bind(root.as_slice()).bind(revision).bind(now).execute(&mut **tx).await?.rows_affected();
            if inserted!=1 {return Err(ReceiptError::Storage);}
            Ok(())
        }

        // The owning coordinator holds the Account-entry singleton before calling this.
        pub(crate) async fn $fresh(tx:&mut Transaction<'_,$db>,device:Uuid,keys:&([u8;65],[u8;65]))->Result<(),ReceiptError> {
            let (signing,kem)=keys;
            let existing:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_devices WHERE device_id=$1")
                .bind(device.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
            let receipt:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM account_operation_receipts WHERE device_id=$1 OR device_signing_public_key IN ($2,$3) OR device_kem_public_key IN ($2,$3))")
                .bind(device.as_bytes().as_slice()).bind(signing.as_slice()).bind(kem.as_slice()).fetch_one(&mut **tx).await?;
            if signing==kem || existing!=0 || receipt {return Err(ReceiptError::Conflict);}
            // Stream SQL-bounded legacy artifacts, retaining no row-count-dependent cache.
            let length=if $postgres {"octet_length"} else {"length"};
            for (table,field,certificate) in [("identity_devices","certificate",true),
                ("sync_account_key_certificates","certificate",true),("sync_account_key_revocations","revocation",false)] {
                let blob=if $postgres {String::new()}else{format!("typeof({field})='blob' AND ")};
                let query=format!("SELECT CASE WHEN {blob}{length}({field}) BETWEEN 1 AND 65536 THEN {field} END AS artifact FROM {table} t JOIN identity_accounts a ON a.account_id=t.account_id");
                let mut rows=sqlx::query(&query).fetch(&mut **tx);
                while let Some(row)=rows.try_next().await? {
                    let bytes:Vec<u8>=row.try_get("artifact").map_err(|_|ReceiptError::Storage)?;
                    if certificate {
                        let cert=DeviceCertificate::decode(&bytes).map_err(|_|ReceiptError::Storage)?;
                        let old_signing=canonical_device_public_key(&cert.signing_public_key).map_err(|_|ReceiptError::Storage)?;
                        let old_kem=canonical_device_public_key(&cert.kem_public_key).map_err(|_|ReceiptError::Storage)?;
                        if cert.device_id==device || [old_signing,old_kem].iter().any(|key|key==signing || key==kem) {
                            return Err(ReceiptError::Conflict);
                        }
                    }else if RevocationStatement::decode(&bytes).map_err(|_|ReceiptError::Storage)?.device_id==device {
                        return Err(ReceiptError::Conflict);
                    }
                }
            }
            Ok(())
        }
    };
}

receipts!(Sqlite, read_sqlite_receipt, append_sqlite_receipt, fresh_sqlite_device, false);
receipts!(Postgres, read_postgres_receipt, append_postgres_receipt, fresh_postgres_device, true);
