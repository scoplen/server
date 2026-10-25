// SPDX-License-Identifier: AGPL-3.0-only
//! D-128 independent Device admission and explicit immutable historical confirmation.
//!
//! The native adapter owns actual-source and HTTP metadata admission plus the bounded proof
//! permit. This coordinator owns structural decoding, private admission, current CAS/proofs,
//! challenge/capability consumption, complete response bounds, mandatory audit and COMMIT.
//! Account-entry serialization precedes Account locks and the deployment audit chain.

use std::{net::IpAddr, time::Duration};

use scoplen_api::{
    account_admission::{
        AccountAdmissionCodecError, AccountBootstrapSnapshot, AccountCommittedConfirmation,
        AccountDeviceAdmissionPayload, AccountDeviceAdmissionRequest, AccountPasswordLoginResponse,
        AccountRequestChallengeRequest, AccountRequestIntent, AccountRequestKind,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest, ed25519_verify,
};
use sqlx::{Postgres, Sqlite, Transaction};
use thiserror::Error;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    account_admission_capabilities::{self, ClaimedAccountAdmissionCapability},
    account_bootstrap::{self, AccountBootstrapError},
    account_entry_admission::{
        self, AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
        AccountEntryPrivateBucket, AccountEntryStateError, VerifiedAccountBucket,
    },
    account_keys::{self, AccountKeyStoreError},
    account_operation_receipts::{self, ReceiptError},
    account_request_challenges::{self, AccountRequestChallengeOutcome},
};

const ENDPOINT: AccountEntryEndpoint = AccountEntryEndpoint::DeviceAdmission;

/// Complete preflighted confirmation JSON, disclosed only after confirmed COMMIT.
pub enum AccountDeviceAdmissionResult {
    /// HTTP 201: exactly one new active Device, certificate and wrap were committed.
    Admitted(Vec<u8>),
    /// HTTP 200: only the original immutable committed facts were confirmed.
    Confirmed(Vec<u8>),
}

impl std::fmt::Debug for AccountDeviceAdmissionResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccountDeviceAdmissionResult([REDACTED])")
    }
}

/// Content-free public failures. Audit/storage failure overrides every checked denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccountDeviceAdmissionError {
    #[error("Device admission request is invalid")]
    InvalidRequest,
    #[error("Device admission request exceeds its bound")]
    RequestTooLarge,
    #[error("Account authentication is required")]
    AuthenticationRequired,
    #[error("Device admission conflicts with current Account state")]
    AdmissionConflict,
    #[error("Device admission capacity is exhausted")]
    QuotaExceeded,
    #[error("Account entry is rate limited")]
    RateLimited(u64),
    #[error("Device admission storage is unavailable")]
    StorageUnavailable,
    /// A new-business COMMIT was attempted. No later read can change this classification.
    #[error("Device admission commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for AccountDeviceAdmissionError {
    fn from(_: sqlx::Error) -> Self {
        Self::StorageUnavailable
    }
}
impl From<AccountEntryStateError> for AccountDeviceAdmissionError {
    fn from(error: AccountEntryStateError) -> Self {
        match error {
            AccountEntryStateError::RateLimited(wait) => Self::RateLimited(wait),
            _ => Self::StorageUnavailable,
        }
    }
}
impl From<ReceiptError> for AccountDeviceAdmissionError {
    fn from(error: ReceiptError) -> Self {
        match error {
            ReceiptError::InvalidMaterial => Self::AuthenticationRequired,
            ReceiptError::Conflict => Self::AdmissionConflict,
            ReceiptError::QuotaExceeded => Self::QuotaExceeded,
            ReceiptError::Storage => Self::StorageUnavailable,
        }
    }
}
impl AccountDeviceAdmissionError {
    fn codec(error: AccountAdmissionCodecError) -> Self {
        if error == AccountAdmissionCodecError::TooLarge {
            Self::RequestTooLarge
        } else {
            Self::InvalidRequest
        }
    }
    fn audit_reason(self) -> AccountEntryFailureReason {
        match self {
            Self::InvalidRequest | Self::RequestTooLarge => {
                AccountEntryFailureReason::InvalidRequest
            }
            Self::AuthenticationRequired => AccountEntryFailureReason::AuthenticationDenied,
            Self::RateLimited(_) => AccountEntryFailureReason::RateLimited,
            _ => AccountEntryFailureReason::StorageUnavailable,
        }
    }
}

struct Failure {
    error: AccountDeviceAdmissionError,
    audited: bool,
}
impl From<AccountDeviceAdmissionError> for Failure {
    fn from(error: AccountDeviceAdmissionError) -> Self {
        Self { error, audited: false }
    }
}
enum Pending {
    Denied(AccountDeviceAdmissionError),
    Expired(i64),
    Admitted(Vec<u8>),
    Confirmed(Vec<u8>),
}

fn confirmation(
    payload: &AccountDeviceAdmissionPayload,
    digest: [u8; 32],
) -> Result<AccountCommittedConfirmation, AccountDeviceAdmissionError> {
    let update = SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle)
        .map_err(|_| AccountDeviceAdmissionError::AuthenticationRequired)?;
    Ok(AccountCommittedConfirmation {
        kind: AccountRequestKind::Admit,
        operation_id: payload.operation_id,
        request_digest: digest,
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        admitted_key_revision: update.revision,
    })
}

fn bounded_snapshot(
    snapshot: &AccountBootstrapSnapshot,
    token: &[u8; 32],
) -> Result<SecretVec, AccountDeviceAdmissionError> {
    let quota = |error| {
        if error == AccountAdmissionCodecError::TooLarge {
            AccountDeviceAdmissionError::QuotaExceeded
        } else {
            AccountDeviceAdmissionError::StorageUnavailable
        }
    };
    let bytes = SecretVec::new(snapshot.to_cbor().map_err(quota)?);
    // Preflight the full future login envelope with the widest legal decimal expiry.
    // These private bytes are neither persisted nor returned and issue no new capability.
    let envelope = AccountPasswordLoginResponse {
        admission_token: SecretBytes::new(*token),
        expires_at_ms: u64::MAX,
        snapshot: bytes.clone(),
    };
    let _encoded = SecretVec::new(envelope.to_json().map_err(quota)?);
    Ok(bytes)
}

fn capacity_error(error: &AccountKeyStoreError) -> AccountDeviceAdmissionError {
    if matches!(error, AccountKeyStoreError::KeyResponseLimit) {
        AccountDeviceAdmissionError::QuotaExceeded
    } else {
        AccountDeviceAdmissionError::StorageUnavailable
    }
}
fn business_error(error: &sqlx::Error) -> AccountDeviceAdmissionError {
    if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
        AccountDeviceAdmissionError::AdmissionConflict
    } else {
        AccountDeviceAdmissionError::StorageUnavailable
    }
}
fn changed(rows: u64) -> Result<(), AccountDeviceAdmissionError> {
    if rows == 1 { Ok(()) } else { Err(AccountDeviceAdmissionError::StorageUnavailable) }
}

macro_rules! admission {
    ($module:ident,$store:ty,$db:ty,$postgres:literal,$read:ident,$fresh:ident,$receipt:ident,
     $now:ident,$challenge:ident,$finish_challenge:ident,$capability:ident,
     $admit:ident,$outcome:ident,$audit:ident,$bootstrap:ident,$capacity:ident) => {
        mod $module {
            use super::*;
            use sqlx::{Acquire as _,Row as _};
            use account_entry_admission::{$now,$admit,$outcome,$audit};
            use account_request_challenges::{$challenge,$finish_challenge};
            use account_admission_capabilities::$capability;
            use account_operation_receipts::{$read,$fresh,$receipt};
            use account_bootstrap::$bootstrap;
            use account_keys::$capacity;

            async fn begin(store:&$store)->Result<Transaction<'_,$db>,sqlx::Error> {
                if $postgres {store.pool().begin().await}
                else {store.pool().begin_with("BEGIN IMMEDIATE").await}
            }

            // Bound preparation only. In particular never cancel an attempted COMMIT.
            async fn failure(store:&$store,source:IpAddr,error:AccountDeviceAdmissionError,
                private:&[AccountEntryPrivateBucket<'_>])->Result<(),AccountDeviceAdmissionError> {
                let audit_deadline=tokio::time::Instant::now()+Duration::from_secs(5);
                let mut tx=tokio::time::timeout_at(audit_deadline,begin(store)).await
                    .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)??;
                let prepared=tokio::time::timeout_at(audit_deadline,
                    $audit(&mut tx,ENDPOINT,source,error.audit_reason(),private)).await;
                match prepared {
                    Ok(Ok(()))=>(),
                    _=>{tx.rollback().await?;return Err(AccountDeviceAdmissionError::StorageUnavailable);}
                }
                tx.commit().await?;
                Ok(())
            }

            async fn retain_time(tx:&mut Transaction<'_,$db>,observed:i64)->Result<(),AccountDeviceAdmissionError> {
                if observed<=0 {return Err(AccountDeviceAdmissionError::StorageUnavailable);}
                $now(tx).await?;
                changed(sqlx::query("UPDATE account_entry_state SET time_high_water_ms=CASE WHEN time_high_water_ms<$1 THEN $1 ELSE time_high_water_ms END WHERE singleton=1")
                    .bind(observed).execute(&mut **tx).await?.rows_affected())
            }

            // Business rollback must not revive observed expiry. A still-live matched challenge
            // is consumed with this independent denial; an expired/missing one grants no result.
            async fn expired(store:&$store,source:IpAddr,origin:&str,request:&AccountDeviceAdmissionRequest,
                payload:&AccountDeviceAdmissionPayload,observed:i64)->Result<(),AccountDeviceAdmissionError> {
                let audit_deadline=tokio::time::Instant::now()+Duration::from_secs(5);
                let mut tx=tokio::time::timeout_at(audit_deadline,begin(store)).await
                    .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)??;
                let prepared=tokio::time::timeout_at(audit_deadline,async {
                    retain_time(&mut tx,observed).await?;
                    let device=AccountEntryPrivateBucket::DecodedDevice(payload.device_id);
                    let binding=AccountRequestChallengeRequest {kind:AccountRequestKind::Admit,intent:request.intent,
                        operation_id:payload.operation_id,device_id:payload.device_id};
                    let mut denial=tx.begin().await?;
                    let claim=$challenge(&mut denial,origin,&binding,request.attempt_id.as_bytes(),request.nonce.as_bytes()).await?;
                    if let Some(claim)=claim {
                        $outcome(&mut denial,ENDPOINT,source,&[device],false).await?;
                        match $finish_challenge(&mut denial,claim,AccountRequestChallengeOutcome::Denied).await {
                            Ok(_)=>{denial.commit().await?;return Ok(());}
                            Err(AccountEntryStateError::ChallengeExpired)=>{
                                let late_now=$now(&mut denial).await?;
                                denial.rollback().await?;
                                retain_time(&mut tx,late_now).await?;
                            }
                            Err(error)=>{denial.rollback().await?;return Err(AccountDeviceAdmissionError::from(error));}
                        }
                    }else{denial.commit().await?;}
                    $audit(&mut tx,ENDPOINT,source,AccountEntryFailureReason::AuthenticationDenied,&[device]).await?;
                    Ok::<_,AccountDeviceAdmissionError>(())
                }).await;
                match prepared {
                    Ok(Ok(()))=>(),
                    _=>{tx.rollback().await?;return Err(AccountDeviceAdmissionError::StorageUnavailable);}
                }
                // A failed denial acknowledgement cannot become a business-unknown result.
                tx.commit().await?;
                Ok(())
            }

            impl $store {
                /// Execute one admission submit or explicit receipt-only confirmation.
                ///
                /// HTTP must first admit the actual source and validate native metadata while
                /// holding its proof permit. No capability or confirmation is disclosed before
                /// confirmed COMMIT. Confirmation grants no current authority and never mutates
                /// Device/Account business state, including after Account deletion.
                /// # Errors
                /// Checked denials have mandatory audit. Only an uncertain new-business COMMIT
                /// returns `CommitOutcomeUnknown`; confirmation/denial uncertainty is storage failure.
                pub async fn execute_account_device_admission(&self,source:IpAddr,trusted_origin:&str,
                    body:&[u8],deadline:tokio::time::Instant)
                    ->Result<AccountDeviceAdmissionResult,AccountDeviceAdmissionError> {
                    match execute(self,source,trusted_origin,body,deadline).await {
                        Ok(result)=>Ok(result),
                        Err(failed)=>{
                            if !failed.audited && failed.error!=AccountDeviceAdmissionError::CommitOutcomeUnknown {
                                failure(self,source,failed.error,&[]).await?;
                            }
                            Err(failed.error)
                        }
                    }
                }
            }

            async fn admit_device(store:&$store,source:IpAddr,device:AccountEntryPrivateBucket<'_>,
                deadline:tokio::time::Instant)->Result<(),Failure> {
                let mut tx=tokio::time::timeout_at(deadline,begin(store)).await
                    .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?
                    .map_err(AccountDeviceAdmissionError::from)?;
                let prepared=tokio::time::timeout_at(deadline,async {
                    let decision=$admit(&mut tx,ENDPOINT,device).await?;
                    if matches!(decision,AccountEntryAdmissionDecision::RateLimited(_)) {
                        $audit(&mut tx,ENDPOINT,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                    }
                    Ok::<_,AccountEntryStateError>(decision)
                }).await;
                let decision=match prepared {
                    Ok(Ok(value)) if tokio::time::Instant::now()<deadline=>value,
                    result=>{
                        tx.rollback().await.map_err(AccountDeviceAdmissionError::from)?;
                        return Err(match result {Ok(Err(error))=>AccountDeviceAdmissionError::from(error),
                            _=>AccountDeviceAdmissionError::StorageUnavailable}.into());
                    }
                };
                // This commits only earlier private rate debt, never Account/Device business state.
                if tx.commit().await.is_err() {return Err(Failure {
                    error:AccountDeviceAdmissionError::StorageUnavailable,audited:true});}
                match decision {
                    AccountEntryAdmissionDecision::Admitted=>Ok(()),
                    AccountEntryAdmissionDecision::RateLimited(wait)=>Err(Failure {
                        error:AccountDeviceAdmissionError::RateLimited(wait),audited:true}),
                }
            }

            #[allow(clippy::too_many_lines)]
            async fn execute(store:&$store,source:IpAddr,origin:&str,body:&[u8],deadline:tokio::time::Instant)
                ->Result<AccountDeviceAdmissionResult,Failure> {
                let (request,payload)=AccountDeviceAdmissionRequest::decode_for_authentication(body)
                    .map_err(AccountDeviceAdmissionError::codec)?;
                let device=AccountEntryPrivateBucket::DecodedDevice(payload.device_id);
                admit_device(store,source,device,deadline).await?;
                let mut tx=tokio::time::timeout_at(deadline,begin(store)).await
                    .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?
                    .map_err(AccountDeviceAdmissionError::from)?;
                let binding=AccountRequestChallengeRequest {kind:AccountRequestKind::Admit,intent:request.intent,
                    operation_id:payload.operation_id,device_id:payload.device_id};
                let claimed=tokio::time::timeout_at(deadline,$challenge(&mut tx,origin,&binding,
                    request.attempt_id.as_bytes(),request.nonce.as_bytes())).await;
                let claim=match claimed {
                    Ok(Ok(Some(value)))=>value,
                    result=>{
                        tx.rollback().await.map_err(AccountDeviceAdmissionError::from)?;
                        if matches!(result,Ok(Ok(None))) {
                            // This independent audit may already have committed despite a lost ACK.
                            failure(store,source,AccountDeviceAdmissionError::AuthenticationRequired,&[device])
                                .await.map_err(|error|Failure{error,audited:true})?;
                            return Err(Failure {error:AccountDeviceAdmissionError::AuthenticationRequired,audited:true});
                        }
                        return Err(match result {Ok(Err(error))=>AccountDeviceAdmissionError::from(error),
                            _=>AccountDeviceAdmissionError::StorageUnavailable}.into());
                    }
                };
                let mut private=vec![device];
                let prepared=if claim.bindings_match() && claim.nonce_matches() {
                    tokio::time::timeout_at(deadline,prepare(&mut tx,origin,&request,&payload,claim.expires_at_ms(),&mut private))
                        .await.unwrap_or(Err(AccountDeviceAdmissionError::StorageUnavailable))
                }else{Ok((Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired),None))};
                let (pending,capability)=match prepared {
                    Ok(value)=>value,
                    Err(error)=>{tx.rollback().await.map_err(AccountDeviceAdmissionError::from)?;return Err(error.into());}
                };
                if let Pending::Expired(observed)=&pending {
                    tx.rollback().await.map_err(AccountDeviceAdmissionError::from)?;
                    expired(store,source,origin,&request,&payload,*observed)
                        .await.map_err(|error|Failure{error,audited:true})?;
                    return Err(Failure {error:AccountDeviceAdmissionError::AuthenticationRequired,audited:true});
                }
                let outcome=match &pending {
                    Pending::Admitted(_)=>AccountRequestChallengeOutcome::Committed,
                    Pending::Confirmed(_)=>AccountRequestChallengeOutcome::TerminalConfirmation,
                    Pending::Denied(_) | Pending::Expired(_)=>AccountRequestChallengeOutcome::Denied,
                };
                let mut expiry_observed=None;
                let finalized=tokio::time::timeout_at(deadline,async {
                    match &pending {
                        Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired)=>
                            $outcome(&mut tx,ENDPOINT,source,&private,false).await?,
                        Pending::Admitted(_) | Pending::Confirmed(_)=>
                            $outcome(&mut tx,ENDPOINT,source,&private,true).await?,
                        Pending::Denied(_) | Pending::Expired(_)=>(),
                    }
                    let final_now=match $finish_challenge(&mut tx,claim,outcome).await {
                        Ok(now)=>now,
                        Err(AccountEntryStateError::ChallengeExpired)=>{
                            expiry_observed=Some($now(&mut tx).await?);
                            return Err(AccountEntryStateError::ChallengeExpired);
                        }
                        Err(error)=>return Err(error),
                    };
                    // Both expiries use the same final authoritative clock. No awaited work
                    // follows this paired check before the immediate outer COMMIT.
                    if capability.as_ref().is_some_and(|capability|final_now>=capability.expires_at_ms()) {
                        expiry_observed=Some(final_now);
                        return Err(AccountEntryStateError::ChallengeExpired);
                    }
                    Ok::<_,AccountEntryStateError>(())
                }).await.unwrap_or(Err(AccountEntryStateError::Storage));
                if let Err(error)=finalized {
                    tx.rollback().await.map_err(AccountDeviceAdmissionError::from)?;
                    if let Some(observed)=expiry_observed {
                        expired(store,source,origin,&request,&payload,observed)
                            .await.map_err(|error|Failure{error,audited:true})?;
                        return Err(Failure {error:AccountDeviceAdmissionError::AuthenticationRequired,audited:true});
                    }
                    return Err(AccountDeviceAdmissionError::from(error).into());
                }
                if tokio::time::Instant::now()>=deadline {
                    tx.rollback().await.map_err(AccountDeviceAdmissionError::from)?;
                    return Err(AccountDeviceAdmissionError::StorageUnavailable.into());
                }
                // Never cancel this COMMIT, read after its failure, or append supplemental audit.
                if tx.commit().await.is_err() {return Err(Failure {error:if matches!(pending,Pending::Admitted(_)) {
                    AccountDeviceAdmissionError::CommitOutcomeUnknown
                }else{AccountDeviceAdmissionError::StorageUnavailable},audited:true});}
                match pending {
                    Pending::Admitted(bytes)=>Ok(AccountDeviceAdmissionResult::Admitted(bytes)),
                    Pending::Confirmed(bytes)=>Ok(AccountDeviceAdmissionResult::Confirmed(bytes)),
                    Pending::Denied(error)=>Err(Failure {error,audited:true}),
                    Pending::Expired(_)=>unreachable!("expired preparation was rolled back"),
                }
            }

            async fn charge_account(tx:&mut Transaction<'_,$db>,account:uuid::Uuid)
                ->Result<AccountEntryPrivateBucket<'static>,AccountDeviceAdmissionError> {
                let bucket=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(account)?);
                match $admit(tx,ENDPOINT,bucket).await? {
                    AccountEntryAdmissionDecision::Admitted=>Ok(bucket),
                    AccountEntryAdmissionDecision::RateLimited(wait)=>Err(AccountDeviceAdmissionError::RateLimited(wait)),
                }
            }

            async fn prepare(tx:&mut Transaction<'_,$db>,origin:&str,request:&AccountDeviceAdmissionRequest,
                payload:&AccountDeviceAdmissionPayload,challenge_expiry:i64,private:&mut Vec<AccountEntryPrivateBucket<'static>>)
                ->Result<(Pending,Option<ClaimedAccountAdmissionCapability>),AccountDeviceAdmissionError> {
                if request.intent==AccountRequestIntent::Confirm {
                    let Some(receipt)=$read(tx,payload.operation_id).await? else {
                        return Ok((Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired),None));};
                    let root=&receipt.root;
                    let Ok(digest)=request.verify_proof(origin,root) else {
                        return Ok((Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired),None));};
                    let keys=account_operation_receipts::device_keys(&payload.device_certificate)?;
                    let expected=confirmation(payload,digest)?;
                    if !receipt.matches(&expected,root,&keys) {
                        return Ok((Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired),None));}
                    let now=$now(tx).await?;
                    if now>=challenge_expiry {return Ok((Pending::Expired(now),None));}
                    private.push(charge_account(tx,receipt.confirmation.account_id).await?);
                    return Ok((Pending::Confirmed(receipt.confirmation.to_json()
                        .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?),None));
                }
                let token=request.admission_token.as_ref().ok_or(AccountDeviceAdmissionError::InvalidRequest)?;
                let mut capability_tx=tx.begin().await?;
                let Some(capability)=$capability(&mut capability_tx,token.as_bytes()).await? else {
                    capability_tx.rollback().await?;
                    return Ok((Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired),None));};
                let expiry=challenge_expiry.min(capability.expires_at_ms());
                let staged=submit(&mut capability_tx,origin,request,payload,&capability,expiry,private).await;
                match staged {
                    Ok(Pending::Expired(observed))=>{capability_tx.rollback().await?;Ok((Pending::Expired(observed),None))}
                    Ok(Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired))=>{
                        capability_tx.rollback().await?;
                        Ok((Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired),None))
                    }
                    Ok(pending)=>{capability_tx.commit().await?;Ok((pending,Some(capability)))}
                    Err(AccountDeviceAdmissionError::QuotaExceeded)=>{
                        capability_tx.rollback().await?;
                        // Restore the capability while retaining authenticated Account rate debt.
                        // Singleton ownership prevents competing admissions between these charges.
                        if private.len()==2 {private.pop();private.push(charge_account(tx,payload.account_id).await?);}
                        Ok((Pending::Denied(AccountDeviceAdmissionError::QuotaExceeded),Some(capability)))
                    }
                    Err(error)=>{capability_tx.rollback().await?;Err(error)}
                }
            }

            #[allow(clippy::too_many_lines)]
            async fn submit(tx:&mut Transaction<'_,$db>,origin:&str,request:&AccountDeviceAdmissionRequest,
                payload:&AccountDeviceAdmissionPayload,capability:&ClaimedAccountAdmissionCapability,
                expiry:i64,private:&mut Vec<AccountEntryPrivateBucket<'static>>)
                ->Result<Pending,AccountDeviceAdmissionError> {
                let token=request.admission_token.as_ref().ok_or(AccountDeviceAdmissionError::InvalidRequest)?.as_bytes();
                let denied=||Pending::Denied(AccountDeviceAdmissionError::AuthenticationRequired);
                let conflict=||Pending::Denied(AccountDeviceAdmissionError::AdmissionConflict);
                if payload.origin!=origin || payload.account_id!=capability.account_id()
                    || payload.credential_generation!=capability.credential_generation()
                    || SecretBytes::new(payload.snapshot_digest)!=SecretBytes::new(*capability.snapshot_digest())
                    || SecretBytes::new(payload.capability_digest)!=SecretBytes::new(account_capability_digest(token)) {
                    return Ok(denied());
                }
                let account=payload.account_id.as_bytes().as_slice();
                if $postgres {
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1,'hex'),0))")
                        .bind(account).execute(&mut **tx).await?;
                    sqlx::query("SELECT account_id FROM identity_accounts WHERE account_id=$1 FOR UPDATE")
                        .bind(account).fetch_optional(&mut **tx).await?;
                }
                let now=$now(tx).await?;
                if now>=expiry {return Ok(Pending::Expired(now));}
                let length=if $postgres {"octet_length"}else{"length"};
                let row=sqlx::query(&format!("SELECT CASE WHEN {length}(username)<=64 THEN username END AS username,CASE WHEN {length}(personal_vault_id)=16 THEN personal_vault_id END AS vault FROM account_password_bootstrap WHERE account_id=$1"))
                    .bind(account).fetch_optional(&mut **tx).await?.ok_or(AccountDeviceAdmissionError::StorageUnavailable)?;
                let username:String=row.try_get("username").map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                let vault:Vec<u8>=row.try_get("vault").map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                if payload.username!=username || vault!=payload.personal_vault_id.as_bytes() {return Ok(denied());}
                let snapshot_result=$bootstrap(tx,origin,payload.account_id).await;
                let now=$now(tx).await?;
                if now>=expiry {return Ok(Pending::Expired(now));}
                let snapshot_bytes=match snapshot_result {
                    Ok(bytes)=>bytes,
                    Err(AccountBootstrapError::UnsupportedState)=>return Ok(conflict()),
                    Err(_)=>return Err(AccountDeviceAdmissionError::StorageUnavailable),
                };
                let snapshot=AccountBootstrapSnapshot::from_cbor(snapshot_bytes.as_bytes())
                    .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                if snapshot.credential_generation!=capability.credential_generation()
                    || SecretBytes::new(account_bootstrap_digest(snapshot_bytes.as_bytes()))!=SecretBytes::new(*capability.snapshot_digest()) {
                    // Valid original capability bindings establish stale CAS, not an old-root
                    // signature verification. No Account rate bucket is selected on this branch.
                    return Ok(conflict());
                }
                let Ok(digest)=request.verify_proof(origin,&snapshot.account_signing_public_key) else {return Ok(denied());};
                let update=SyncAccountKeyBundleUpdate::from_cbor(&payload.key_bundle)
                    .map_err(|_|AccountDeviceAdmissionError::AuthenticationRequired)?;
                if ed25519_verify(&snapshot.account_signing_public_key,&update.signature_input()
                    .map_err(|_|AccountDeviceAdmissionError::AuthenticationRequired)?,&update.signature).is_err() {return Ok(denied());}
                let now=$now(tx).await?;
                if now>=expiry {return Ok(Pending::Expired(now));}
                private.push(charge_account(tx,payload.account_id).await?);
                if payload.validate_for_snapshot(&snapshot,snapshot_bytes.as_bytes(),token).is_err() {return Ok(conflict());}
                let Ok(revision)=i64::try_from(update.revision) else {return Ok(conflict());};
                let old=SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle)
                    .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                let old_revision=i64::try_from(old.revision).map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                let mut next=snapshot.clone();
                next.key_bundle.clone_from(&payload.key_bundle);
                next.certificates.push(payload.device_certificate.clone());next.certificates.sort();
                let expected=bounded_snapshot(&next,token)?;
                let result=confirmation(payload,digest)?;
                let response=result.to_json().map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                let keys=account_operation_receipts::device_keys(&payload.device_certificate)?;
                let wrap=update.device_wraps.iter().find(|wrap|wrap.device_id==payload.device_id)
                    .ok_or(AccountDeviceAdmissionError::AdmissionConflict)?;
                let mut business=tx.begin().await?;
                let staged=async {
                    $fresh(&mut business,payload.device_id,&keys).await?;
                    let now=$now(&mut business).await?;
                    changed(sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES ($1,$2,$3,TRUE,$4)")
                        .bind(payload.device_id.as_bytes().as_slice()).bind(account).bind(&payload.device_certificate).bind(now)
                        .execute(&mut *business).await.map_err(|error|business_error(&error))?.rows_affected())?;
                    changed(sqlx::query("INSERT INTO sync_account_key_certificates (account_id,certificate) VALUES ($1,$2)")
                        .bind(account).bind(&payload.device_certificate).execute(&mut *business).await.map_err(|error|business_error(&error))?.rows_affected())?;
                    changed(sqlx::query("INSERT INTO sync_account_key_device_wraps (account_id,device_id,wrapped_ark) VALUES ($1,$2,$3)")
                        .bind(account).bind(payload.device_id.as_bytes().as_slice()).bind(&wrap.wrapped_ark)
                        .execute(&mut *business).await.map_err(|error|business_error(&error))?.rows_affected())?;
                    changed(sqlx::query("UPDATE sync_account_key_bundles SET revision=$1,signature=$2,accepted_put_cbor=$3,updated_at_ms=$4 WHERE account_id=$5 AND revision=$6")
                        .bind(revision).bind(&update.signature).bind(&payload.key_bundle).bind(now).bind(account).bind(old_revision)
                        .execute(&mut *business).await.map_err(|error|business_error(&error))?.rows_affected())?;
                    $capacity(&mut business,payload.account_id.into_bytes()).await.map_err(|error|capacity_error(&error))?;
                    let actual=$bootstrap(&mut business,origin,payload.account_id).await
                        .map_err(|_|AccountDeviceAdmissionError::StorageUnavailable)?;
                    if actual!=expected {return Err(AccountDeviceAdmissionError::StorageUnavailable);}
                    let now=$now(&mut business).await?;
                    $receipt(&mut business,&result,&keys,&snapshot.account_signing_public_key,now).await?;
                    Ok::<_,AccountDeviceAdmissionError>(())
                }.await;
                match staged {
                    Ok(())=>{business.commit().await?;Ok(Pending::Admitted(response))}
                    Err(error)=>{business.rollback().await?;if error==AccountDeviceAdmissionError::AdmissionConflict {
                        Ok(conflict())
                    }else{Err(error)}}
                }
            }
        }
    };
}

admission!(
    sqlite,
    SqliteStore,
    Sqlite,
    false,
    read_sqlite_receipt,
    fresh_sqlite_device,
    append_sqlite_receipt,
    sqlite_account_entry_now,
    claim_sqlite_account_request_challenge_in_transaction,
    finish_sqlite_account_request_challenge_in_transaction,
    claim_sqlite_account_admission_capability_in_transaction,
    admit_sqlite_account_entry_private_in_transaction,
    sqlite_account_entry_outcome_in_transaction,
    audit_sqlite_account_entry_failure_in_transaction,
    read_sqlite_password_bootstrap_in_transaction,
    check_sqlite_key_response_capacity
);
admission!(
    postgres,
    PostgresStore,
    Postgres,
    true,
    read_postgres_receipt,
    fresh_postgres_device,
    append_postgres_receipt,
    postgres_account_entry_now,
    claim_postgres_account_request_challenge_in_transaction,
    finish_postgres_account_request_challenge_in_transaction,
    claim_postgres_account_admission_capability_in_transaction,
    admit_postgres_account_entry_private_in_transaction,
    postgres_account_entry_outcome_in_transaction,
    audit_postgres_account_entry_failure_in_transaction,
    read_postgres_password_bootstrap_in_transaction,
    check_postgres_key_response_capacity
);
