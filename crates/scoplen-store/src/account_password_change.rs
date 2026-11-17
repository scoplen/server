// SPDX-License-Identifier: AGPL-3.0-only
//! D-152 ordinary native password change and explicit immutable historical confirmation.
//!
//! The native adapter owns actual-source and HTTP metadata admission plus the bounded proof
//! permit. This coordinator owns structural decoding, private admission, current CAS/proofs,
//! challenge/capability consumption, complete response bounds, mandatory audit and COMMIT.
//! Account-entry serialization precedes Account locks and the deployment audit chain.

use std::{net::IpAddr, time::Duration};

use scoplen_api::account_admission::{
    AccountAdmissionCodecError, AccountBootstrapSnapshot, AccountPasswordChangeConfirmation,
    AccountPasswordChangePayload, AccountPasswordChangeRequest, AccountPasswordLoginResponse,
    AccountRequestChallengeRequest, AccountRequestIntent, AccountRequestKind,
};
use scoplen_crypto::{SecretBytes, SecretVec, account_bootstrap_digest, account_capability_digest};
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
    account_operation_receipts::{self, ReceiptError},
    account_request_challenges::{self, AccountRequestChallengeOutcome},
    device_authentication::{self, CurrentPrincipal, DeviceAuthenticationError},
};

const ENDPOINT: AccountEntryEndpoint = AccountEntryEndpoint::PasswordChange;

/// Complete preflighted confirmation JSON, disclosed only after confirmed COMMIT.
pub enum AccountPasswordChangeResult {
    /// HTTP 201: one credential replacement and its receipt were committed.
    Changed(Vec<u8>),
    /// HTTP 200: only the original immutable committed facts were confirmed.
    Confirmed(Vec<u8>),
}

impl std::fmt::Debug for AccountPasswordChangeResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccountPasswordChangeResult([REDACTED])")
    }
}

/// Content-free public failures. Audit/storage failure overrides every checked denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccountPasswordChangeError {
    #[error("Password change request is invalid")]
    InvalidRequest,
    #[error("Password change request exceeds its bound")]
    RequestTooLarge,
    #[error("Account authentication is required")]
    AuthenticationRequired,
    #[error("Password change conflicts with current Account state")]
    AdmissionConflict,
    #[error("Password change capacity is exhausted")]
    QuotaExceeded,
    #[error("Account entry is rate limited")]
    RateLimited(u64),
    #[error("Password change storage is unavailable")]
    StorageUnavailable,
    /// A new-business COMMIT was attempted. No later read can change this classification.
    #[error("Password change commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for AccountPasswordChangeError {
    fn from(_: sqlx::Error) -> Self {
        Self::StorageUnavailable
    }
}
impl From<AccountEntryStateError> for AccountPasswordChangeError {
    fn from(error: AccountEntryStateError) -> Self {
        match error {
            AccountEntryStateError::RateLimited(wait) => Self::RateLimited(wait),
            _ => Self::StorageUnavailable,
        }
    }
}
impl From<ReceiptError> for AccountPasswordChangeError {
    fn from(error: ReceiptError) -> Self {
        match error {
            ReceiptError::InvalidMaterial => Self::AuthenticationRequired,
            ReceiptError::Conflict => Self::AdmissionConflict,
            ReceiptError::QuotaExceeded => Self::QuotaExceeded,
            ReceiptError::Storage => Self::StorageUnavailable,
        }
    }
}
impl AccountPasswordChangeError {
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
    error: AccountPasswordChangeError,
    audited: bool,
}
impl From<AccountPasswordChangeError> for Failure {
    fn from(error: AccountPasswordChangeError) -> Self {
        Self { error, audited: false }
    }
}
enum Pending {
    Denied(AccountPasswordChangeError),
    Expired(i64),
    Changed(Vec<u8>),
    Confirmed(Vec<u8>),
}

fn confirmation(
    payload: &AccountPasswordChangePayload,
    digest: [u8; 32],
) -> AccountPasswordChangeConfirmation {
    AccountPasswordChangeConfirmation {
        operation_id: payload.operation_id,
        request_digest: digest,
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        credential_generation: payload.new_credential_generation,
    }
}

fn bounded_snapshot(
    snapshot: &AccountBootstrapSnapshot,
    token: &[u8; 32],
) -> Result<SecretVec, AccountPasswordChangeError> {
    let quota = |error| {
        if error == AccountAdmissionCodecError::TooLarge {
            AccountPasswordChangeError::QuotaExceeded
        } else {
            AccountPasswordChangeError::StorageUnavailable
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

fn business_error(error: &sqlx::Error) -> AccountPasswordChangeError {
    if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
        AccountPasswordChangeError::AdmissionConflict
    } else {
        AccountPasswordChangeError::StorageUnavailable
    }
}
fn changed(rows: u64) -> Result<(), AccountPasswordChangeError> {
    if rows == 1 { Ok(()) } else { Err(AccountPasswordChangeError::StorageUnavailable) }
}

use device_authentication::load_sqlite_principal;

async fn load_postgres_password_change_principal(
    tx: &mut Transaction<'_, Postgres>,
    device: [u8; 16],
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    device_authentication::load_postgres_principal(tx, device, true).await
}

macro_rules! admission {
    ($module:ident,$store:ty,$db:ty,$postgres:literal,$read:ident,$receipt:ident,
     $now:ident,$challenge:ident,$finish_challenge:ident,$capability:ident,
     $admit:ident,$outcome:ident,$audit:ident,$bootstrap:ident,$principal:ident) => {
        mod $module {
            use super::*;
            use sqlx::{Acquire as _,Row as _};
            use account_entry_admission::{$now,$admit,$outcome,$audit};
            use account_request_challenges::{$challenge,$finish_challenge};
            use account_admission_capabilities::$capability;
            use account_operation_receipts::{$read,$receipt};
            use account_bootstrap::$bootstrap;


            async fn load_principal(tx:&mut Transaction<'_,$db>,device:[u8;16])
                ->Result<Option<CurrentPrincipal>,DeviceAuthenticationError> {
                $principal(tx,device).await
            }

            async fn begin(store:&$store)->Result<Transaction<'_,$db>,sqlx::Error> {
                if $postgres {store.pool().begin().await}
                else {store.pool().begin_with("BEGIN IMMEDIATE").await}
            }

            // Bound preparation only. In particular never cancel an attempted COMMIT.
            async fn failure(store:&$store,source:IpAddr,error:AccountPasswordChangeError,
                private:&[AccountEntryPrivateBucket<'_>])->Result<(),AccountPasswordChangeError> {
                let audit_deadline=tokio::time::Instant::now()+Duration::from_secs(5);
                let mut tx=tokio::time::timeout_at(audit_deadline,begin(store)).await
                    .map_err(|_|AccountPasswordChangeError::StorageUnavailable)??;
                let prepared=tokio::time::timeout_at(audit_deadline,
                    $audit(&mut tx,ENDPOINT,source,error.audit_reason(),private)).await;
                match prepared {
                    Ok(Ok(()))=>(),
                    _=>{tx.rollback().await?;return Err(AccountPasswordChangeError::StorageUnavailable);}
                }
                tx.commit().await?;
                Ok(())
            }

            async fn retain_time(tx:&mut Transaction<'_,$db>,observed:i64)->Result<(),AccountPasswordChangeError> {
                if observed<=0 {return Err(AccountPasswordChangeError::StorageUnavailable);}
                $now(tx).await?;
                changed(sqlx::query("UPDATE account_entry_state SET time_high_water_ms=CASE WHEN time_high_water_ms<$1 THEN $1 ELSE time_high_water_ms END WHERE singleton=1")
                    .bind(observed).execute(&mut **tx).await?.rows_affected())
            }

            // Business rollback must not revive observed expiry. A still-live matched challenge
            // is consumed with this independent denial; an expired/missing one grants no result.
            async fn expired(store:&$store,source:IpAddr,origin:&str,request:&AccountPasswordChangeRequest,
                payload:&AccountPasswordChangePayload,observed:i64)->Result<(),AccountPasswordChangeError> {
                let audit_deadline=tokio::time::Instant::now()+Duration::from_secs(5);
                let mut tx=tokio::time::timeout_at(audit_deadline,begin(store)).await
                    .map_err(|_|AccountPasswordChangeError::StorageUnavailable)??;
                let prepared=tokio::time::timeout_at(audit_deadline,async {
                    retain_time(&mut tx,observed).await?;
                    let device=AccountEntryPrivateBucket::DecodedDevice(payload.device_id);
                    let binding=AccountRequestChallengeRequest {kind:AccountRequestKind::PasswordChange,intent:request.intent,
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
                            Err(error)=>{denial.rollback().await?;return Err(AccountPasswordChangeError::from(error));}
                        }
                    }else{denial.commit().await?;}
                    $audit(&mut tx,ENDPOINT,source,AccountEntryFailureReason::AuthenticationDenied,&[device]).await?;
                    Ok::<_,AccountPasswordChangeError>(())
                }).await;
                match prepared {
                    Ok(Ok(()))=>(),
                    _=>{tx.rollback().await?;return Err(AccountPasswordChangeError::StorageUnavailable);}
                }
                // A failed denial acknowledgement cannot become a business-unknown result.
                tx.commit().await?;
                Ok(())
            }

            impl $store {
                /// Execute one password-change submit or explicit receipt-only confirmation.
                ///
                /// HTTP must first admit the actual source and validate native metadata while
                /// holding its proof permit. No capability or confirmation is disclosed before
                /// confirmed COMMIT. Confirmation grants no current authority and never mutates
                /// password business state, including after Account deletion.
                /// # Errors
                /// Checked denials have mandatory audit. Only an uncertain new-business COMMIT
                /// returns `CommitOutcomeUnknown`; confirmation/denial uncertainty is storage failure.
                pub async fn execute_account_password_change(&self,source:IpAddr,trusted_origin:&str,
                    body:&[u8],deadline:tokio::time::Instant)
                    ->Result<AccountPasswordChangeResult,AccountPasswordChangeError> {
                    match execute(self,source,trusted_origin,body,deadline).await {
                        Ok(result)=>Ok(result),
                        Err(failed)=>{
                            if !failed.audited && failed.error!=AccountPasswordChangeError::CommitOutcomeUnknown {
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
                    .map_err(|_|AccountPasswordChangeError::StorageUnavailable)?
                    .map_err(AccountPasswordChangeError::from)?;
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
                        tx.rollback().await.map_err(AccountPasswordChangeError::from)?;
                        return Err(match result {Ok(Err(error))=>AccountPasswordChangeError::from(error),
                            _=>AccountPasswordChangeError::StorageUnavailable}.into());
                    }
                };
                // This commits only earlier private rate debt, never Account/Device business state.
                if tx.commit().await.is_err() {return Err(Failure {
                    error:AccountPasswordChangeError::StorageUnavailable,audited:true});}
                match decision {
                    AccountEntryAdmissionDecision::Admitted=>Ok(()),
                    AccountEntryAdmissionDecision::RateLimited(wait)=>Err(Failure {
                        error:AccountPasswordChangeError::RateLimited(wait),audited:true}),
                }
            }

            #[allow(clippy::too_many_lines)]
            async fn execute(store:&$store,source:IpAddr,origin:&str,body:&[u8],deadline:tokio::time::Instant)
                ->Result<AccountPasswordChangeResult,Failure> {
                let (request,payload)=AccountPasswordChangeRequest::decode_for_authentication(body)
                    .map_err(AccountPasswordChangeError::codec)?;
                let device=AccountEntryPrivateBucket::DecodedDevice(payload.device_id);
                admit_device(store,source,device,deadline).await?;
                let mut tx=tokio::time::timeout_at(deadline,begin(store)).await
                    .map_err(|_|AccountPasswordChangeError::StorageUnavailable)?
                    .map_err(AccountPasswordChangeError::from)?;
                let binding=AccountRequestChallengeRequest {kind:AccountRequestKind::PasswordChange,intent:request.intent,
                    operation_id:payload.operation_id,device_id:payload.device_id};
                let claimed=tokio::time::timeout_at(deadline,$challenge(&mut tx,origin,&binding,
                    request.attempt_id.as_bytes(),request.nonce.as_bytes())).await;
                let claim=match claimed {
                    Ok(Ok(Some(value)))=>value,
                    result=>{
                        tx.rollback().await.map_err(AccountPasswordChangeError::from)?;
                        if matches!(result,Ok(Ok(None))) {
                            // This independent audit may already have committed despite a lost ACK.
                            failure(store,source,AccountPasswordChangeError::AuthenticationRequired,&[device])
                                .await.map_err(|error|Failure{error,audited:true})?;
                            return Err(Failure {error:AccountPasswordChangeError::AuthenticationRequired,audited:true});
                        }
                        return Err(match result {Ok(Err(error))=>AccountPasswordChangeError::from(error),
                            _=>AccountPasswordChangeError::StorageUnavailable}.into());
                    }
                };
                let mut private=vec![device];
                let prepared=if claim.bindings_match() && claim.nonce_matches() {
                    tokio::time::timeout_at(deadline,prepare(&mut tx,origin,&request,&payload,claim.expires_at_ms(),&mut private))
                        .await.unwrap_or(Err(AccountPasswordChangeError::StorageUnavailable))
                }else{Ok((Pending::Denied(AccountPasswordChangeError::AuthenticationRequired),None))};
                let (pending,capability)=match prepared {
                    Ok(value)=>value,
                    Err(error)=>{tx.rollback().await.map_err(AccountPasswordChangeError::from)?;return Err(error.into());}
                };
                if let Pending::Expired(observed)=&pending {
                    tx.rollback().await.map_err(AccountPasswordChangeError::from)?;
                    expired(store,source,origin,&request,&payload,*observed)
                        .await.map_err(|error|Failure{error,audited:true})?;
                    return Err(Failure {error:AccountPasswordChangeError::AuthenticationRequired,audited:true});
                }
                let outcome=match &pending {
                    Pending::Changed(_)=>AccountRequestChallengeOutcome::Committed,
                    Pending::Confirmed(_)=>AccountRequestChallengeOutcome::TerminalConfirmation,
                    Pending::Denied(_) | Pending::Expired(_)=>AccountRequestChallengeOutcome::Denied,
                };
                let mut expiry_observed=None;
                let finalized=tokio::time::timeout_at(deadline,async {
                    match &pending {
                        Pending::Denied(AccountPasswordChangeError::AuthenticationRequired)=>
                            $outcome(&mut tx,ENDPOINT,source,&private,false).await?,
                        Pending::Changed(_) | Pending::Confirmed(_)=>
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
                    tx.rollback().await.map_err(AccountPasswordChangeError::from)?;
                    if let Some(observed)=expiry_observed {
                        expired(store,source,origin,&request,&payload,observed)
                            .await.map_err(|error|Failure{error,audited:true})?;
                        return Err(Failure {error:AccountPasswordChangeError::AuthenticationRequired,audited:true});
                    }
                    return Err(AccountPasswordChangeError::from(error).into());
                }
                if tokio::time::Instant::now()>=deadline {
                    tx.rollback().await.map_err(AccountPasswordChangeError::from)?;
                    return Err(AccountPasswordChangeError::StorageUnavailable.into());
                }
                // Never cancel this COMMIT, read after its failure, or append supplemental audit.
                if tx.commit().await.is_err() {return Err(Failure {error:if matches!(pending,Pending::Changed(_)) {
                    AccountPasswordChangeError::CommitOutcomeUnknown
                }else{AccountPasswordChangeError::StorageUnavailable},audited:true});}
                match pending {
                    Pending::Changed(bytes)=>Ok(AccountPasswordChangeResult::Changed(bytes)),
                    Pending::Confirmed(bytes)=>Ok(AccountPasswordChangeResult::Confirmed(bytes)),
                    Pending::Denied(error)=>Err(Failure {error,audited:true}),
                    Pending::Expired(_)=>unreachable!("expired preparation was rolled back"),
                }
            }

            async fn charge_account(tx:&mut Transaction<'_,$db>,account:uuid::Uuid)
                ->Result<AccountEntryPrivateBucket<'static>,AccountPasswordChangeError> {
                let bucket=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(account)?);
                match $admit(tx,ENDPOINT,bucket).await? {
                    AccountEntryAdmissionDecision::Admitted=>Ok(bucket),
                    AccountEntryAdmissionDecision::RateLimited(wait)=>Err(AccountPasswordChangeError::RateLimited(wait)),
                }
            }

            async fn prepare(tx:&mut Transaction<'_,$db>,origin:&str,request:&AccountPasswordChangeRequest,
                payload:&AccountPasswordChangePayload,challenge_expiry:i64,private:&mut Vec<AccountEntryPrivateBucket<'static>>)
                ->Result<(Pending,Option<ClaimedAccountAdmissionCapability>),AccountPasswordChangeError> {
                if request.intent==AccountRequestIntent::Confirm {
                    let Some(receipt)=$read(tx,payload.operation_id).await? else {
                        return Ok((Pending::Denied(AccountPasswordChangeError::AuthenticationRequired),None));};
                    let root=&receipt.root;
                    let Ok(digest)=request.verify_proof(origin,root,&receipt.signing) else {
                        return Ok((Pending::Denied(AccountPasswordChangeError::AuthenticationRequired),None));};
                    let expected=confirmation(payload,digest);
                    if receipt.confirmation != expected {
                        return Ok((Pending::Denied(AccountPasswordChangeError::AuthenticationRequired),None));}
                    let now=$now(tx).await?;
                    if now>=challenge_expiry {return Ok((Pending::Expired(now),None));}
                    private.push(charge_account(tx,receipt.confirmation.account_id).await?);
                    return Ok((Pending::Confirmed(receipt.confirmation.to_json()
                        .map_err(|_|AccountPasswordChangeError::StorageUnavailable)?),None));
                }
                let token=request.admission_token.as_ref().ok_or(AccountPasswordChangeError::InvalidRequest)?;
                let mut capability_tx=tx.begin().await?;
                let Some(capability)=$capability(&mut capability_tx,token.as_bytes()).await? else {
                    capability_tx.rollback().await?;
                    return Ok((Pending::Denied(AccountPasswordChangeError::AuthenticationRequired),None));};
                let expiry=challenge_expiry.min(capability.expires_at_ms());
                let staged=submit(&mut capability_tx,origin,request,payload,&capability,expiry,private).await;
                match staged {
                    Ok(Pending::Expired(observed))=>{capability_tx.rollback().await?;Ok((Pending::Expired(observed),None))}
                    Ok(Pending::Denied(AccountPasswordChangeError::AuthenticationRequired))=>{
                        capability_tx.rollback().await?;
                        Ok((Pending::Denied(AccountPasswordChangeError::AuthenticationRequired),None))
                    }
                    Ok(pending)=>{capability_tx.commit().await?;Ok((pending,Some(capability)))}
                    Err(AccountPasswordChangeError::QuotaExceeded)=>{
                        capability_tx.rollback().await?;
                        // Restore the capability while retaining authenticated Account rate debt.
                        // Singleton ownership prevents competing admissions between these charges.
                        if private.len()==2 {private.pop();private.push(charge_account(tx,payload.account_id).await?);}
                        Ok((Pending::Denied(AccountPasswordChangeError::QuotaExceeded),Some(capability)))
                    }
                    Err(error)=>{capability_tx.rollback().await?;Err(error)}
                }
            }

            #[allow(clippy::too_many_lines)]
            async fn submit(tx:&mut Transaction<'_,$db>,origin:&str,request:&AccountPasswordChangeRequest,
                payload:&AccountPasswordChangePayload,capability:&ClaimedAccountAdmissionCapability,
                expiry:i64,private:&mut Vec<AccountEntryPrivateBucket<'static>>)
                ->Result<Pending,AccountPasswordChangeError> {
                let token=request.admission_token.as_ref().ok_or(AccountPasswordChangeError::InvalidRequest)?.as_bytes();
                let denied=||Pending::Denied(AccountPasswordChangeError::AuthenticationRequired);
                let conflict=||Pending::Denied(AccountPasswordChangeError::AdmissionConflict);
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
                    .bind(account).fetch_optional(&mut **tx).await?.ok_or(AccountPasswordChangeError::StorageUnavailable)?;
                let username:String=row.try_get("username").map_err(|_|AccountPasswordChangeError::StorageUnavailable)?;
                let vault:Vec<u8>=row.try_get("vault").map_err(|_|AccountPasswordChangeError::StorageUnavailable)?;
                if payload.username!=username || vault!=payload.personal_vault_id.as_bytes() {return Ok(denied());}
                let snapshot_result=$bootstrap(tx,origin,payload.account_id).await;
                let now=$now(tx).await?;
                if now>=expiry {return Ok(Pending::Expired(now));}
                let snapshot_bytes=match snapshot_result {
                    Ok(bytes)=>bytes,
                    Err(AccountBootstrapError::UnsupportedState)=>return Ok(conflict()),
                    Err(_)=>return Err(AccountPasswordChangeError::StorageUnavailable),
                };
                let snapshot=AccountBootstrapSnapshot::from_cbor(snapshot_bytes.as_bytes())
                    .map_err(|_|AccountPasswordChangeError::StorageUnavailable)?;
                let principal_result=load_principal(tx,payload.device_id.into_bytes()).await;
                let principal=match principal_result {
                    Ok(Some(principal))=>principal,
                    Ok(None) | Err(DeviceAuthenticationError::Denied{..})=>return Ok(denied()),
                    Err(_)=>return Err(AccountPasswordChangeError::StorageUnavailable),
                };
                if principal.account_id!=payload.account_id.into_bytes()
                    || !snapshot.certificates.contains(&principal.certificate) {return Ok(denied());}
                if snapshot.credential_generation!=capability.credential_generation()
                    || SecretBytes::new(account_bootstrap_digest(snapshot_bytes.as_bytes()))!=SecretBytes::new(*capability.snapshot_digest()) {
                    // Valid original capability bindings establish stale CAS, not an old-root
                    // signature verification. No Account rate bucket is selected on this branch.
                    return Ok(conflict());
                }
                let Ok(digest)=request.verify_proof(origin,&snapshot.account_signing_public_key,&principal.signing_public_key) else {return Ok(denied());};
                let now=$now(tx).await?;
                if now>=expiry {return Ok(Pending::Expired(now));}
                private.push(charge_account(tx,payload.account_id).await?);
                if payload.validate_for_snapshot(&snapshot,snapshot_bytes.as_bytes(),token).is_err() {return Ok(conflict());}
                let mut next=snapshot.clone();
                next.credential_generation=payload.new_credential_generation;
                next.password_salt=payload.password_salt;
                next.password_ark=payload.password_ark;
                let expected=bounded_snapshot(&next,token)?;
                let result=confirmation(payload,digest);
                let response=result.to_json().map_err(|_|AccountPasswordChangeError::StorageUnavailable)?;
                let keys=account_operation_receipts::device_keys(&principal.certificate)?;
                let mut business=tx.begin().await?;
                let staged=async {
                    let rows=sqlx::query("UPDATE account_password_bootstrap SET credential_generation=$1,password_salt=$2,verifier=$3,password_ark=$4 WHERE account_id=$5 AND credential_generation=$6")
                        .bind(payload.new_credential_generation.to_be_bytes().as_slice()).bind(payload.password_salt.as_slice())
                        .bind(payload.verifier.as_slice()).bind(payload.password_ark.as_slice()).bind(account)
                        .bind(payload.credential_generation.to_be_bytes().as_slice())
                        .execute(&mut *business).await.map_err(|error|business_error(&error))?.rows_affected();
                    if rows!=1 {return Err(AccountPasswordChangeError::AdmissionConflict);}
                    let actual=$bootstrap(&mut business,origin,payload.account_id).await
                        .map_err(|_|AccountPasswordChangeError::StorageUnavailable)?;
                    if actual!=expected {return Err(AccountPasswordChangeError::StorageUnavailable);}
                    let now=$now(&mut business).await?;
                    $receipt(&mut business,&result,&keys,&snapshot.account_signing_public_key,now).await?;
                    Ok::<_,AccountPasswordChangeError>(())
                }.await;
                match staged {
                    Ok(())=>{business.commit().await?;Ok(Pending::Changed(response))}
                    Err(error)=>{business.rollback().await?;if error==AccountPasswordChangeError::AdmissionConflict {
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
    read_sqlite_password_change_receipt,
    append_sqlite_password_change_receipt,
    sqlite_account_entry_now,
    claim_sqlite_account_request_challenge_in_transaction,
    finish_sqlite_account_request_challenge_in_transaction,
    claim_sqlite_account_admission_capability_in_transaction,
    admit_sqlite_account_entry_private_in_transaction,
    sqlite_account_entry_outcome_in_transaction,
    audit_sqlite_account_entry_failure_in_transaction,
    read_sqlite_password_bootstrap_in_transaction,
    load_sqlite_principal
);
admission!(
    postgres,
    PostgresStore,
    Postgres,
    true,
    read_postgres_password_change_receipt,
    append_postgres_password_change_receipt,
    postgres_account_entry_now,
    claim_postgres_account_request_challenge_in_transaction,
    finish_postgres_account_request_challenge_in_transaction,
    claim_postgres_account_admission_capability_in_transaction,
    admit_postgres_account_entry_private_in_transaction,
    postgres_account_entry_outcome_in_transaction,
    audit_postgres_account_entry_failure_in_transaction,
    read_postgres_password_bootstrap_in_transaction,
    load_postgres_password_change_principal
);
