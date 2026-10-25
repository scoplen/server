// SPDX-License-Identifier: AGPL-3.0-only
//! D-128 registration and explicit historical confirmation, with no session authority.
//!
//! HTTP must admit the actual source before collecting the body, validate native transport
//! metadata, and hold its bounded proof-validation permit/deadline. This module owns strict
//! structural decoding, private admission, proofs, receipts, mandatory audit and COMMIT.
//! The shared Account-entry singleton precedes D-129, Account and deployment-audit locks.

use std::net::IpAddr;

use futures_util::TryStreamExt as _;
use scoplen_api::account_admission::{
    AccountAdmissionCodecError, AccountCommittedConfirmation, AccountRegistrationPayload,
    AccountRegistrationRequest, AccountRequestChallengeRequest, AccountRequestIntent,
    AccountRequestKind,
};
use scoplen_crypto::{
    DeviceCertificate, RevocationStatement, SecretBytes, canonical_device_public_key,
};
use sqlx::{Acquire as _, Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    account_bootstrap::{self, AccountBootstrapError},
    account_entry_admission::{
        self, AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
        AccountEntryPrivateBucket, AccountEntryStateError, VerifiedAccountBucket,
    },
    account_request_challenges::{self, AccountRequestChallengeOutcome},
    account_used_ids::AccountIdRetentionError,
};

/// Complete preflighted JSON, disclosed only after this transaction's confirmed commit.
pub enum AccountRegistrationResult {
    /// HTTP 201: this submit created the complete aggregate and its immutable receipt.
    Created(Vec<u8>),
    /// HTTP 200: this explicit confirm established only historical committed facts.
    Confirmed(Vec<u8>),
}

impl std::fmt::Debug for AccountRegistrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountRegistrationResult([REDACTED])")
    }
}

/// Fixed public failure classes, without SQL diagnostics or submitted identity/material.
/// Every reported denial has mandatory audit; audit/storage failure overrides that denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccountRegistrationError {
    #[error("Account registration request is invalid")]
    InvalidRequest,
    #[error("Account registration request exceeds its bound")]
    RequestTooLarge,
    #[error("New Account registration is disabled")]
    PolicyDenied,
    #[error("Account authentication is required")]
    AuthenticationRequired,
    #[error("Account registration is denied")]
    RegistrationDenied,
    #[error("Account registration capacity is exhausted")]
    QuotaExceeded,
    #[error("Account entry is rate limited")]
    RateLimited(u64),
    #[error("Account registration storage is unavailable")]
    StorageUnavailable,
    /// A business COMMIT was attempted; no subsequent read changes this classification.
    #[error("Account registration commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for AccountRegistrationError {
    fn from(_: sqlx::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl From<AccountEntryStateError> for AccountRegistrationError {
    fn from(error: AccountEntryStateError) -> Self {
        match error {
            AccountEntryStateError::RateLimited(wait) => Self::RateLimited(wait),
            _ => Self::StorageUnavailable,
        }
    }
}

fn bootstrap_error(error: &AccountBootstrapError) -> AccountRegistrationError {
    match error {
        AccountBootstrapError::Conflict
        | AccountBootstrapError::Retention(AccountIdRetentionError::Conflict) => {
            AccountRegistrationError::RegistrationDenied
        }
        AccountBootstrapError::Retention(AccountIdRetentionError::QuotaExceeded) => {
            AccountRegistrationError::QuotaExceeded
        }
        _ => AccountRegistrationError::StorageUnavailable,
    }
}

struct Failure {
    error: AccountRegistrationError,
    audited: bool,
}

impl From<AccountRegistrationError> for Failure {
    fn from(error: AccountRegistrationError) -> Self {
        Self { error, audited: false }
    }
}

enum Pending {
    Denied(AccountRegistrationError),
    Created(Vec<u8>),
    Confirmed(Vec<u8>),
}

struct Receipt {
    confirmation: AccountCommittedConfirmation,
    signing: [u8; 65],
    kem: [u8; 65],
    root: [u8; 32],
}

fn confirmation(
    payload: &AccountRegistrationPayload,
    digest: [u8; 32],
) -> AccountCommittedConfirmation {
    AccountCommittedConfirmation {
        kind: AccountRequestKind::Register,
        operation_id: payload.operation_id,
        request_digest: digest,
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        admitted_key_revision: 1,
    }
}

fn original_keys(
    payload: &AccountRegistrationPayload,
) -> Result<([u8; 65], [u8; 65]), AccountRegistrationError> {
    let certificate = DeviceCertificate::decode(&payload.device_certificate)
        .map_err(|_| AccountRegistrationError::AuthenticationRequired)?;
    let signing = canonical_device_public_key(&certificate.signing_public_key)
        .map_err(|_| AccountRegistrationError::AuthenticationRequired)?;
    let kem = canonical_device_public_key(&certificate.kem_public_key)
        .map_err(|_| AccountRegistrationError::AuthenticationRequired)?;
    Ok((signing, kem))
}

fn matches_receipt(
    receipt: &Receipt,
    payload: &AccountRegistrationPayload,
    digest: [u8; 32],
) -> bool {
    let expected = confirmation(payload, digest);
    let actual = &receipt.confirmation;
    let digest_matches = SecretBytes::new(actual.request_digest) == SecretBytes::new(digest);
    digest_matches
        && actual.kind == expected.kind
        && actual.operation_id == expected.operation_id
        && actual.account_id == expected.account_id
        && actual.personal_vault_id == expected.personal_vault_id
        && actual.device_id == expected.device_id
        && actual.admitted_key_revision == expected.admitted_key_revision
        && receipt.root == payload.account_signing_public_key
        && original_keys(payload).is_ok_and(|keys| keys == (receipt.signing, receipt.kem))
}

fn fixed<R: Row, const N: usize>(row: &R, name: &str) -> Result<[u8; N], AccountRegistrationError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    row.try_get::<Vec<u8>, _>(name)
        .map_err(|_| AccountRegistrationError::StorageUnavailable)?
        .try_into()
        .map_err(|_| AccountRegistrationError::StorageUnavailable)
}

fn receipt_id(bytes: [u8; 16]) -> Result<Uuid, AccountRegistrationError> {
    let id = Uuid::from_bytes(bytes);
    account_entry_admission::valid_id(id)?;
    Ok(id)
}

macro_rules! registration {
    ($store:ty,$db:ty,$begin:ident,$execute:ident,$failure:ident,$prepare:ident,$read:ident,$fresh:ident,
     $now:path,$claim:path,$finish:path,$admit:path,$outcome:path,$create:path,$append:path,$postgres:literal) => {
        impl $store {
            /// Execute one strictly decoded submit or explicit receipt-only confirmation.
            /// Source/HTTP metadata/concurrency admission belongs to the native HTTP adapter.
            /// All other admission, proofs, challenge consumption, receipts and mandatory audit
            /// are owned here. Confirm never falls through to mutation, including after deletion.
            /// # Errors
            /// Denials are already audited; audit failure returns `StorageUnavailable`. Only an
            /// unacknowledged new-business COMMIT returns `CommitOutcomeUnknown` (changed:true).
            /// Uncertain confirmation COMMIT returns `StorageUnavailable` (changed:false).
            pub async fn execute_account_registration(&self,source:IpAddr,trusted_origin:&str,
                registration_enabled:bool,expected_account_id_ceiling:u64,body:&[u8],deadline:tokio::time::Instant)
                ->Result<AccountRegistrationResult,AccountRegistrationError> {
                match $execute(self,source,trusted_origin,registration_enabled,expected_account_id_ceiling,body,deadline).await {
                    Ok(result)=>Ok(result),
                    Err(failure)=>{
                        if !failure.audited && failure.error!=AccountRegistrationError::CommitOutcomeUnknown {
                            // After rollback, allow a bounded mandatory failure-audit attempt.
                            // Audit unavailability overrides every otherwise reportable denial.
                            tokio::time::timeout(std::time::Duration::from_secs(5),$failure(self,failure.error))
                                .await.map_err(|_|AccountRegistrationError::StorageUnavailable)??;
                        }
                        Err(failure.error)
                    }
                }
            }

            async fn audit_registration_authentication_failure(&self,source:IpAddr,device:AccountEntryPrivateBucket<'_>)
                ->Result<(),AccountRegistrationError> {
                tokio::time::timeout(std::time::Duration::from_secs(5),self.audit_account_entry_failure(
                    AccountEntryEndpoint::Register,source,AccountEntryFailureReason::AuthenticationDenied,&[device]))
                    .await.map_err(|_|AccountRegistrationError::StorageUnavailable)?
                    .map_err(AccountRegistrationError::from)
            }
        }

        async fn $failure(store:&$store,error:AccountRegistrationError)->Result<(),AccountRegistrationError> {
            let mut tx=$begin(store).await?;
            let now=$now(&mut tx).await?;
            let reason=match error {
                AccountRegistrationError::InvalidRequest=>1,
                AccountRegistrationError::RequestTooLarge=>2,
                AccountRegistrationError::PolicyDenied=>3,
                AccountRegistrationError::AuthenticationRequired=>4,
                AccountRegistrationError::RegistrationDenied=>5,
                AccountRegistrationError::QuotaExceeded=>6,
                AccountRegistrationError::RateLimited(_)=>7,
                AccountRegistrationError::StorageUnavailable=>8,
                AccountRegistrationError::CommitOutcomeUnknown=>return Err(AccountRegistrationError::StorageUnavailable),
            };
            let mut event=b"spl-account-registration-failure-v1".to_vec();
            event.push(reason);
            event.extend_from_slice(&now.to_be_bytes());
            $append(&mut tx,&event,now).await.map_err(|_|AccountRegistrationError::StorageUnavailable)?;
            tx.commit().await?;
            Ok(())
        }

        #[allow(clippy::too_many_lines)]
        async fn $execute(store:&$store,source:IpAddr,origin:&str,enabled:bool,ceiling:u64,body:&[u8],deadline:tokio::time::Instant)
            ->Result<AccountRegistrationResult,Failure> {
            let (request,payload)=AccountRegistrationRequest::decode_for_authentication(body)
                .map_err(AccountRegistrationError::from_codec)?;
            let device=AccountEntryPrivateBucket::DecodedDevice(payload.device_id);
            match tokio::time::timeout_at(deadline,store.admit_account_entry_private(AccountEntryEndpoint::Register,source,device))
                .await.map_err(|_|AccountRegistrationError::StorageUnavailable)? {
                Ok(AccountEntryAdmissionDecision::Admitted)=>(),
                Ok(AccountEntryAdmissionDecision::RateLimited(wait))=>return Err(Failure{error:AccountRegistrationError::RateLimited(wait),audited:true}),
                Err(error)=>return Err(AccountRegistrationError::from(error).into()),
            }
            if request.intent==AccountRequestIntent::Submit && !enabled {
                return Err(AccountRegistrationError::PolicyDenied.into());
            }
            let mut tx=tokio::time::timeout_at(deadline,$begin(store)).await
                .map_err(|_|AccountRegistrationError::StorageUnavailable)?.map_err(AccountRegistrationError::from)?;
            let binding=AccountRequestChallengeRequest {kind:AccountRequestKind::Register,intent:request.intent,
                operation_id:payload.operation_id,device_id:payload.device_id};
            let claim_result=tokio::time::timeout_at(deadline,$claim(&mut tx,origin,&binding,request.attempt_id.as_bytes(),request.nonce.as_bytes())).await;
            let Ok(claim_result)=claim_result else {
                tx.rollback().await.map_err(AccountRegistrationError::from)?;
                return Err(AccountRegistrationError::StorageUnavailable.into());
            };
            let claim=match claim_result {
                Ok(Some(claim))=>claim,
                result=>{
                    tx.rollback().await.map_err(AccountRegistrationError::from)?;
                    match result {
                        Ok(None)=>{
                            store.audit_registration_authentication_failure(source,device).await?;
                            return Err(Failure{error:AccountRegistrationError::AuthenticationRequired,audited:true});
                        },
                        Err(error)=>return Err(AccountRegistrationError::from(error).into()),
                        Ok(Some(_))=>unreachable!(),
                    }
                }
            };
            let mut private=vec![device];
            let pending=if claim.bindings_match() && claim.nonce_matches() {
                tokio::time::timeout_at(deadline,$prepare(&mut tx,origin,ceiling,&request,&payload,&mut private))
                    .await.unwrap_or(Err(AccountRegistrationError::StorageUnavailable))
            } else {Ok(Pending::Denied(AccountRegistrationError::AuthenticationRequired))};
            let pending=match pending {
                Ok(pending)=>pending,
                Err(error)=>{
                    tx.rollback().await.map_err(AccountRegistrationError::from)?;
                    return Err(error.into());
                }
            };
            let outcome=match &pending {
                Pending::Created(_)=>AccountRequestChallengeOutcome::Committed,
                Pending::Confirmed(_)=>AccountRequestChallengeOutcome::TerminalConfirmation,
                Pending::Denied(_)=>AccountRequestChallengeOutcome::Denied,
            };
            let finalized=tokio::time::timeout_at(deadline,async {
                match &pending {
                    Pending::Denied(AccountRegistrationError::AuthenticationRequired)=>$outcome(&mut tx,AccountEntryEndpoint::Register,source,&private,false).await?,
                    Pending::Created(_)|Pending::Confirmed(_)=>$outcome(&mut tx,AccountEntryEndpoint::Register,source,&private,true).await?,
                    Pending::Denied(_)=>(),
                }
                $finish(&mut tx,claim,outcome).await
            }).await.unwrap_or(Err(AccountEntryStateError::Storage));
            if let Err(error)=finalized {
                tx.rollback().await.map_err(AccountRegistrationError::from)?;
                if matches!(error,AccountEntryStateError::ChallengeExpired) {
                    store.audit_registration_authentication_failure(source,device).await?;
                    return Err(Failure{error:AccountRegistrationError::AuthenticationRequired,audited:true});
                }
                return Err(AccountRegistrationError::from(error).into());
            }
            if tokio::time::Instant::now()>=deadline {
                tx.rollback().await.map_err(AccountRegistrationError::from)?;
                return Err(AccountRegistrationError::StorageUnavailable.into());
            }
            // This is the only business COMMIT. Never infer its outcome through a later read.
            if tx.commit().await.is_err() {
                return Err(Failure{error:if matches!(pending,Pending::Created(_)) {
                    AccountRegistrationError::CommitOutcomeUnknown
                }else{AccountRegistrationError::StorageUnavailable},audited:true});
            }
            match pending {
                Pending::Created(bytes)=>Ok(AccountRegistrationResult::Created(bytes)),
                Pending::Confirmed(bytes)=>Ok(AccountRegistrationResult::Confirmed(bytes)),
                Pending::Denied(error)=>Err(Failure{error,audited:true}),
            }
        }

        async fn $prepare(tx:&mut Transaction<'_,$db>,origin:&str,ceiling:u64,request:&AccountRegistrationRequest,
            payload:&AccountRegistrationPayload,private:&mut Vec<AccountEntryPrivateBucket<'static>>)
            ->Result<Pending,AccountRegistrationError> {
            let Ok(digest)=request.verify_proof(origin) else {
                return Ok(Pending::Denied(AccountRegistrationError::AuthenticationRequired));
            };
            if request.intent==AccountRequestIntent::Confirm {
                let Some(receipt)=$read(tx,payload.operation_id).await? else {
                    return Ok(Pending::Denied(AccountRegistrationError::AuthenticationRequired));
                };
                if !matches_receipt(&receipt,payload,digest) {
                    return Ok(Pending::Denied(AccountRegistrationError::AuthenticationRequired));
                }
                let account=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(receipt.confirmation.account_id)?);
                match $admit(tx,AccountEntryEndpoint::Register,account).await? {
                    AccountEntryAdmissionDecision::Admitted=>private.push(account),
                    AccountEntryAdmissionDecision::RateLimited(wait)=>return Err(AccountRegistrationError::RateLimited(wait)),
                }
                return Ok(Pending::Confirmed(receipt.confirmation.to_json().map_err(|_|AccountRegistrationError::StorageUnavailable)?));
            }
            let result=confirmation(payload,digest);
            let response=result.to_json().map_err(|_|AccountRegistrationError::StorageUnavailable)?;
            let (signing,kem)=original_keys(payload)?;
            // A savepoint preserves the live proof claim for a checked namespace/quota denial,
            // including PostgreSQL's transaction-aborting unique violations.
            let mut business=tx.begin().await?;
            let staged=async {
                let exists:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts WHERE operation_id=$1")
                    .bind(payload.operation_id.as_bytes().as_slice()).fetch_one(&mut *business).await?;
                if exists!=0 {return Err(AccountRegistrationError::RegistrationDenied);}
                $fresh(&mut business,payload.device_id,&signing,&kem).await?;
                let now=$now(&mut business).await?;
                $create(&mut business,origin,ceiling,payload,now).await.map_err(|error|bootstrap_error(&error))?;
                let receipt_now=$now(&mut business).await?;
                let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_operation_receipts WHERE account_id=$1")
                    .bind(payload.account_id.as_bytes().as_slice()).fetch_one(&mut *business).await?;
                if !(0..=65_536).contains(&count) {return Err(AccountRegistrationError::StorageUnavailable);}
                if count==65_536 {return Err(AccountRegistrationError::QuotaExceeded);}
                let inserted=sqlx::query("INSERT INTO account_operation_receipts (operation_id,account_id,personal_vault_id,device_id,request_digest,kind,device_signing_public_key,device_kem_public_key,account_signing_public_key,admitted_key_revision,committed_at_ms) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,1,$9)")
                    .bind(payload.operation_id.as_bytes().as_slice()).bind(payload.account_id.as_bytes().as_slice())
                    .bind(payload.personal_vault_id.as_bytes().as_slice()).bind(payload.device_id.as_bytes().as_slice())
                    .bind(digest.as_slice()).bind(signing.as_slice()).bind(kem.as_slice())
                    .bind(payload.account_signing_public_key.as_slice()).bind(receipt_now)
                    .execute(&mut *business).await?.rows_affected();
                if inserted!=1 {return Err(AccountRegistrationError::StorageUnavailable);}
                Ok(())
            }.await;
            match staged {
                Ok(())=>{business.commit().await?;Ok(Pending::Created(response))},
                Err(error)=>{
                    business.rollback().await?;
                    match error {
                        AccountRegistrationError::RegistrationDenied|AccountRegistrationError::QuotaExceeded=>Ok(Pending::Denied(error)),
                        _=>Err(error),
                    }
                }
            }
        }

        async fn $read(tx:&mut Transaction<'_,$db>,operation:Uuid)->Result<Option<Receipt>,AccountRegistrationError> {
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
            let kind=match row.try_get::<i64,_>("kind")? {1=>AccountRequestKind::Register,2=>AccountRequestKind::Admit,_=>return Err(AccountRegistrationError::StorageUnavailable)};
            let signing=fixed::<_,65>(&row,"device_signing_public_key")?;
            let kem=fixed::<_,65>(&row,"device_kem_public_key")?;
            let root=fixed::<_,32>(&row,"account_signing_public_key")?;
            if revision<=0 || committed<=0 || signing==kem
                || canonical_device_public_key(&signing).ok()!=Some(signing)
                || canonical_device_public_key(&kem).ok()!=Some(kem)
                || ed25519_dalek::VerifyingKey::from_bytes(&root).is_err() {return Err(AccountRegistrationError::StorageUnavailable);}
            Ok(Some(Receipt{confirmation:AccountCommittedConfirmation{
                kind,operation_id:receipt_id(fixed(&row,"operation_id")?)?,account_id:receipt_id(fixed(&row,"account_id")?)?,
                personal_vault_id:receipt_id(fixed(&row,"personal_vault_id")?)?,device_id:receipt_id(fixed(&row,"device_id")?)?,
                request_digest:fixed(&row,"request_digest")?,admitted_key_revision:u64::try_from(revision).map_err(|_|AccountRegistrationError::StorageUnavailable)?,
            },signing,kem,root}))
        }

        async fn $fresh(tx:&mut Transaction<'_,$db>,device:Uuid,signing:&[u8;65],kem:&[u8;65])->Result<(),AccountRegistrationError> {
            let existing:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_devices WHERE device_id=$1")
                .bind(device.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
            let receipt:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM account_operation_receipts WHERE device_id=$1 OR device_signing_public_key IN ($2,$3) OR device_kem_public_key IN ($2,$3))")
                .bind(device.as_bytes().as_slice()).bind(signing.as_slice()).bind(kem.as_slice()).fetch_one(&mut **tx).await?;
            if signing==kem || existing!=0 || receipt {return Err(AccountRegistrationError::RegistrationDenied);}
            // Legacy states have no canonical-key index. Stream one bounded artifact at a time
            // across the deployment; do not retain an unbounded freshness cache or omit Accounts.
            let length=if $postgres {"octet_length"} else {"length"};
            for (table,field,certificate) in [("identity_devices","certificate",true),
                ("sync_account_key_certificates","certificate",true),("sync_account_key_revocations","revocation",false)] {
                let blob=if $postgres {String::new()}else{format!("typeof({field})='blob' AND ")};
                let query=format!("SELECT CASE WHEN {blob}{length}({field}) BETWEEN 1 AND 65536 THEN {field} END AS artifact FROM {table} t JOIN identity_accounts a ON a.account_id=t.account_id");
                let mut rows=sqlx::query(&query).fetch(&mut **tx);
                while let Some(row)=rows.try_next().await? {
                    let bytes:Vec<u8>=row.try_get("artifact").map_err(|_|AccountRegistrationError::StorageUnavailable)?;
                    if certificate {
                        let cert=DeviceCertificate::decode(&bytes).map_err(|_|AccountRegistrationError::StorageUnavailable)?;
                        let old_signing=canonical_device_public_key(&cert.signing_public_key).map_err(|_|AccountRegistrationError::StorageUnavailable)?;
                        let old_kem=canonical_device_public_key(&cert.kem_public_key).map_err(|_|AccountRegistrationError::StorageUnavailable)?;
                        if cert.device_id==device || [old_signing,old_kem].iter().any(|key|key==signing || key==kem) {
                            return Err(AccountRegistrationError::RegistrationDenied);
                        }
                    }else if RevocationStatement::decode(&bytes).map_err(|_|AccountRegistrationError::StorageUnavailable)?.device_id==device {
                        return Err(AccountRegistrationError::RegistrationDenied);
                    }
                }
            }
            Ok(())
        }
    };
}

impl AccountRegistrationError {
    fn from_codec(error: AccountAdmissionCodecError) -> Self {
        if error == AccountAdmissionCodecError::TooLarge {
            Self::RequestTooLarge
        } else {
            Self::InvalidRequest
        }
    }
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}

registration!(
    SqliteStore,
    Sqlite,
    sqlite_begin,
    sqlite_execute,
    sqlite_failure,
    sqlite_prepare,
    sqlite_receipt,
    sqlite_fresh,
    account_entry_admission::sqlite_account_entry_now,
    account_request_challenges::claim_sqlite_account_request_challenge_in_transaction,
    account_request_challenges::finish_sqlite_account_request_challenge_in_transaction,
    account_entry_admission::admit_sqlite_account_entry_private_in_transaction,
    account_entry_admission::sqlite_account_entry_outcome_in_transaction,
    account_bootstrap::create_sqlite_password_account_in_transaction,
    crate::append_deployment_audit_event_in_transaction,
    false
);
registration!(
    PostgresStore,
    Postgres,
    postgres_begin,
    postgres_execute,
    postgres_failure,
    postgres_prepare,
    postgres_receipt,
    postgres_fresh,
    account_entry_admission::postgres_account_entry_now,
    account_request_challenges::claim_postgres_account_request_challenge_in_transaction,
    account_request_challenges::finish_postgres_account_request_challenge_in_transaction,
    account_entry_admission::admit_postgres_account_entry_private_in_transaction,
    account_entry_admission::postgres_account_entry_outcome_in_transaction,
    account_bootstrap::create_postgres_password_account_in_transaction,
    crate::append_deployment_audit_event_in_postgres_transaction,
    true
);
