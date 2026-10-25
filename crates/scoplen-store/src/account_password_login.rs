// SPDX-License-Identifier: AGPL-3.0-only
//! Durable password options and login, disclosing secrets only after confirmed commit.

use std::{net::IpAddr, time::Duration};

use scoplen_api::account_admission::{
    AccountPasswordLoginRequest, AccountPasswordLoginResponse, AccountPasswordOptionsRequest,
    AccountPasswordOptionsResponse,
};
use scoplen_crypto::{
    AccountProbeKey as ProbeDerivation, PasswordVerifier, SecretVec, account_bootstrap_digest,
    account_capability_digest, random_key,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    account_admission_capabilities::{ACCOUNT_CAPABILITY_CAPACITY, CAPABILITY_CAPACITY},
    account_bootstrap::{
        AccountBootstrapError, read_postgres_password_bootstrap_in_transaction,
        read_sqlite_password_bootstrap_in_transaction,
    },
    account_entry_admission::{
        AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
        AccountEntryPrivateBucket, AccountEntryStateError, AccountUsernameBucket,
        VerifiedAccountBucket, admit_postgres_account_entry_private_in_transaction,
        admit_sqlite_account_entry_private_in_transaction,
        audit_postgres_account_entry_failure_in_transaction,
        audit_sqlite_account_entry_failure_in_transaction, postgres_account_entry_now,
        postgres_account_entry_outcome_in_transaction, sqlite_account_entry_now,
        sqlite_account_entry_outcome_in_transaction, valid_id,
    },
    account_probe_key::AccountProbeKey,
    kms::KeyManagementService,
};

const ATTEMPT_CAPACITY: i64 = 16_384;
const FAILURE_AUDIT_BUDGET: Duration = Duration::from_secs(5);

/// Content-free public outcomes. Login creates no Account, Device, session or receipt.
#[derive(Debug, Error)]
pub enum AccountPasswordLoginError {
    #[error("invalid Account password request")]
    InvalidRequest,
    #[error("Account authentication is required")]
    AuthenticationRequired,
    #[error("Account admission state conflicts")]
    AdmissionConflict,
    #[error("Account password request is rate limited")]
    RateLimited(u64),
    #[error("Account password storage is unavailable")]
    StorageUnavailable,
}

impl From<sqlx::Error> for AccountPasswordLoginError {
    fn from(_: sqlx::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl From<AccountEntryStateError> for AccountPasswordLoginError {
    fn from(_: AccountEntryStateError) -> Self {
        Self::StorageUnavailable
    }
}

fn attempt_digest(attempt: &[u8; 32]) -> [u8; 32] {
    account_capability_digest(attempt)
}

fn origin_digest(origin: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"spl-account-password-origin-v1");
    hash.update(origin.as_bytes());
    hash.finalize().into()
}

fn checked_count(count: i64, limit: i64) -> Result<bool, AccountPasswordLoginError> {
    if !(0..=limit).contains(&count) {
        return Err(AccountPasswordLoginError::StorageUnavailable);
    }
    Ok(count == limit)
}

fn expiry(now: i64, lifetime: i64) -> Result<i64, AccountPasswordLoginError> {
    now.checked_add(lifetime).ok_or(AccountPasswordLoginError::StorageUnavailable)
}

fn require_live(
    now: i64,
    expires: i64,
    deadline: Instant,
) -> Result<(), AccountPasswordLoginError> {
    if now >= expires || Instant::now() >= deadline {
        return Err(AccountPasswordLoginError::StorageUnavailable);
    }
    Ok(())
}

fn outcome_event(class: u8, account: Option<Uuid>, now: i64) -> Vec<u8> {
    let mut event = b"spl-account-password-outcome-v1".to_vec();
    event.push(class);
    event.extend_from_slice(&now.to_be_bytes());
    if let Some(account) = account {
        event.extend_from_slice(account.as_bytes());
    }
    event
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}

// The timeout owns only preparation. An owned transaction survives cancellation so rollback
// can be acknowledged. COMMIT is deliberately outside every timeout and never cancelled.
macro_rules! password_transaction {
    ($store:expr,$begin:ident,$deadline:expr,$endpoint:expr,$source:expr,$tx:ident,$body:block) => {{
        let Ok(Ok(mut $tx)) = timeout_at($deadline, $begin($store)).await else {
            $store.password_storage_failure_audit($endpoint, $source).await?;
            return Err(AccountPasswordLoginError::StorageUnavailable);
        };
        match timeout_at($deadline, async { $body }).await {
            Ok(Ok(outcome)) => {
                if Instant::now() >= $deadline {
                    $tx.rollback()
                        .await
                        .map_err(|_| AccountPasswordLoginError::StorageUnavailable)?;
                    $store.password_storage_failure_audit($endpoint, $source).await?;
                    return Err(AccountPasswordLoginError::StorageUnavailable);
                }
                $tx.commit().await.map_err(|_| AccountPasswordLoginError::StorageUnavailable)?;
                outcome
            }
            failure => {
                // Wait for explicit rollback before another transaction audits the failure.
                let rolled_back = $tx.rollback().await.is_ok();
                $store.password_storage_failure_audit($endpoint, $source).await?;
                if !rolled_back {
                    return Err(AccountPasswordLoginError::StorageUnavailable);
                }
                match failure {
                    Ok(Err(error)) => Err(error),
                    _ => Err(AccountPasswordLoginError::StorageUnavailable),
                }
            }
        }
    }};
}

macro_rules! password_store {
    ($store:ty,$begin:ident,$now:ident,$admit:ident,$audit:ident,$outcome:ident,$snapshot:ident,$append:path,$length:literal) => {
        impl $store {
            async fn password_storage_failure_audit(&self,endpoint:AccountEntryEndpoint,source:IpAddr)
                -> Result<(),AccountPasswordLoginError> {
                let deadline=Instant::now()+FAILURE_AUDIT_BUDGET;
                let mut tx=timeout_at(deadline,$begin(self)).await
                    .map_err(|_|AccountPasswordLoginError::StorageUnavailable)??;
                if !matches!(timeout_at(deadline,$audit(&mut tx,endpoint,source,
                    AccountEntryFailureReason::StorageUnavailable,&[])).await,Ok(Ok(()))) || Instant::now()>=deadline {
                    tx.rollback().await.map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    return Err(AccountPasswordLoginError::StorageUnavailable);
                }
                tx.commit().await.map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                Ok(())
            }

            async fn password_retained_probe(&self,kms:&dyn KeyManagementService,deadline:Instant,
                endpoint:AccountEntryEndpoint,source:IpAddr) -> Result<AccountProbeKey,AccountPasswordLoginError> {
                match timeout_at(deadline,self.read_account_probe_key(kms)).await {
                    Ok(Ok(key))=>Ok(key),
                    _=>{self.password_storage_failure_audit(endpoint,source).await?;
                        Err(AccountPasswordLoginError::StorageUnavailable)}
                }
            }

            /// Strictly decode and issue profile-one options after HTTP source admission.
            /// Existing and unknown names share durable quotas, capacity and response shape.
            /// Kprobe must already have been initialized at startup.
            /// # Errors
            /// Returns only content-free invalid-input, rate or storage outcomes.
            pub async fn issue_account_password_options(&self,source:IpAddr,origin:&str,
                request_body:&[u8],kms:&dyn KeyManagementService,deadline:Instant)
                ->Result<AccountPasswordOptionsResponse,AccountPasswordLoginError> {
                let endpoint=AccountEntryEndpoint::PasswordOptions;
                let decoded=AccountPasswordOptionsRequest::from_json(request_body);
                let probe=if decoded.is_ok(){Some(self.password_retained_probe(kms,deadline,endpoint,source).await?)}else{None};
                password_transaction!(self,$begin,deadline,endpoint,source,tx,{
                    let _=$now(&mut tx).await?;
                    let Ok(request)=decoded else {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::InvalidRequest,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::InvalidRequest));
                    };
                    let probe=probe.ok_or(AccountPasswordLoginError::StorageUnavailable)?;
                    let username=AccountUsernameBucket::new(&probe,origin,&request.username)?;
                    let decision=$admit(&mut tx,endpoint,AccountEntryPrivateBucket::Username(&username)).await?;
                    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_password_attempts").fetch_one(&mut *tx).await?;
                    let full=checked_count(count,ATTEMPT_CAPACITY)?;
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=decision {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::RateLimited(wait)));
                    }
                    if full {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::RateLimited(1)));
                    }
                    let length=$length;
                    let row=sqlx::query(&format!("SELECT CASE WHEN {length}(b.password_salt)=16 THEN b.password_salt END AS salt,b.password_profile,a.password_owned FROM account_password_bootstrap b JOIN identity_accounts a ON a.account_id=b.account_id WHERE b.username=$1 AND b.origin=$2"))
                        .bind(&request.username).bind(origin).fetch_optional(&mut *tx).await?;
                    let salt=if let Some(row)=row {
                        if !row.try_get::<bool,_>("password_owned")? || row.try_get::<i64,_>("password_profile")?!=1 {
                            return Err(AccountPasswordLoginError::StorageUnavailable);
                        }
                        row.try_get::<Vec<u8>,_>("salt").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?
                            .try_into().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?
                    }else{
                        ProbeDerivation::new(probe.as_bytes()).and_then(|key|key.synthetic_salt(origin,&request.username))
                            .map_err(|_|AccountPasswordLoginError::StorageUnavailable)?
                    };
                    let attempt=random_key().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let now=$now(&mut tx).await?;
                    let expires=expiry(now,120_000)?;
                    let response=AccountPasswordOptionsResponse {attempt_id:attempt,salt,
                        expires_at_ms:u64::try_from(expires).map_err(|_|AccountPasswordLoginError::StorageUnavailable)?};
                    let _encoded=Zeroizing::new(response.to_json().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?);
                    let digest=attempt_digest(response.attempt_id.as_bytes());
                    if sqlx::query("INSERT INTO account_password_attempts (attempt_digest,origin_digest,username,password_profile,password_salt,issued_at_ms,expires_at_ms) VALUES ($1,$2,$3,1,$4,$5,$6)")
                        .bind(digest.as_slice()).bind(origin_digest(origin).as_slice()).bind(&request.username).bind(salt.as_slice())
                        .bind(now).bind(expires).execute(&mut *tx).await?.rows_affected()!=1 {
                        return Err(AccountPasswordLoginError::StorageUnavailable);
                    }
                    require_live($now(&mut tx).await?,expires,deadline)?;
                    Ok(Ok(response))
                })
            }

            /// Verify an owned zeroizing login body and create only an admission capability.
            /// HTTP must first admit the source and bound concurrent proof/bootstrap work.
            /// No raw attempt, `AuthSecret`, snapshot copy or recovery receipt is retained.
            /// # Errors
            /// Missing/used/expired attempts and wrong credentials share one denial. No secret
            /// is returned on preparation timeout, rollback, audit failure or uncertain commit.
            #[allow(clippy::too_many_lines, reason = "Keep preparation, one-use consumption and audit in one transaction")]
            pub async fn execute_account_password_login(&self,source:IpAddr,origin:&str,
                request_body:SecretVec,kms:&dyn KeyManagementService,deadline:Instant)
                ->Result<AccountPasswordLoginResponse,AccountPasswordLoginError> {
                let endpoint=AccountEntryEndpoint::PasswordLogin;
                let decoded=AccountPasswordLoginRequest::from_json(request_body.as_bytes());
                drop(request_body);
                let probe=if decoded.is_ok(){Some(self.password_retained_probe(kms,deadline,endpoint,source).await?)}else{None};
                password_transaction!(self,$begin,deadline,endpoint,source,tx,{
                    let now=$now(&mut tx).await?;
                    let Ok(request)=decoded else {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::InvalidRequest,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::InvalidRequest));
                    };
                    let digest=attempt_digest(request.attempt_id.as_bytes());
                    let length=$length;
                    let row=sqlx::query(&format!("SELECT CASE WHEN {length}(origin_digest)=32 THEN origin_digest END AS origin_digest,CASE WHEN {length}(username)<=64 THEN username END AS username,password_profile,CASE WHEN {length}(password_salt)=16 THEN password_salt END AS password_salt,issued_at_ms,expires_at_ms FROM account_password_attempts WHERE attempt_digest=$1"))
                        .bind(digest.as_slice()).fetch_optional(&mut *tx).await?;
                    let Some(row)=row else {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    };
                    let issued:i64=row.try_get("issued_at_ms")?;
                    let expires:i64=row.try_get("expires_at_ms")?;
                    let retained_origin:[u8;32]=row.try_get::<Vec<u8>,_>("origin_digest").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?.try_into().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let retained_username:String=row.try_get("username").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let salt:[u8;16]=row.try_get::<Vec<u8>,_>("password_salt").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?.try_into().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let profile:i64=row.try_get("password_profile")?;
                    if issued<=0 || now<issued || issued.checked_add(120_000)!=Some(expires) || profile!=1 {
                        return Err(AccountPasswordLoginError::StorageUnavailable);
                    }
                    if retained_origin!=origin_digest(origin) {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    }
                    let probe=probe.ok_or(AccountPasswordLoginError::StorageUnavailable)?;
                    let username=AccountUsernameBucket::new(&probe,origin,&retained_username)?;
                    let private=AccountEntryPrivateBucket::Username(&username);
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=$admit(&mut tx,endpoint,private).await? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::RateLimited(wait)));
                    }
                    if now>=expires {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    }
                    // Holding the shared admission singleton reserves this attempt until commit.
                    // Rate rejection leaves its row intact while retaining earlier admitted debt.
                    let credential=sqlx::query(&format!("SELECT CASE WHEN {length}(b.account_id)=16 THEN b.account_id END AS account_id,b.credential_generation,b.password_profile,CASE WHEN {length}(b.password_salt)=16 THEN b.password_salt END AS salt,CASE WHEN {length}(b.verifier)=32 THEN b.verifier END AS verifier,a.password_owned FROM account_password_bootstrap b JOIN identity_accounts a ON a.account_id=b.account_id WHERE b.origin=$1 AND b.username=$2"))
                        .bind(origin).bind(&retained_username).fetch_optional(&mut *tx).await?;
                    let synthetic=ProbeDerivation::new(probe.as_bytes()).and_then(|key|key.synthetic_verifier(origin,&retained_username))
                        .map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let mut account=None;
                    let mut current_salt=None;
                    let mut generation=0;
                    let verifier=if let Some(row)=credential {
                        if !row.try_get::<bool,_>("password_owned")? {return Err(AccountPasswordLoginError::StorageUnavailable);}
                        let id:Vec<u8>=row.try_get("account_id").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                        let id=Uuid::from_slice(&id).map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                        valid_id(id)?;
                        account=Some(id);
                        generation=row.try_get::<i64,_>("credential_generation")?;
                        if generation<=0 {return Err(AccountPasswordLoginError::StorageUnavailable);}
                        if row.try_get::<i64,_>("password_profile")?==1 {
                            current_salt=Some(row.try_get::<Vec<u8>,_>("salt").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?);
                        }
                        Zeroizing::new(row.try_get::<Vec<u8>,_>("verifier").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?)
                    }else{Zeroizing::new(synthetic.as_ref().to_vec())};
                    let auth_secret=request.auth_secret;
                    drop(request.attempt_id);
                    let valid=PasswordVerifier::from_bytes(&verifier).map_err(|_|AccountPasswordLoginError::StorageUnavailable)?
                        .verify(SecretVec::new(auth_secret.as_ref().to_vec())).is_ok();
                    drop(verifier);
                    let valid=valid && account.is_some() && current_salt.as_deref()==Some(salt.as_slice());
                    if !valid {
                        drop(auth_secret);
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    }
                    let account=account.ok_or(AccountPasswordLoginError::StorageUnavailable)?;
                    let established=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(account)?);
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=$admit(&mut tx,endpoint,established).await? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::RateLimited(wait)));
                    }
                    // This reader acquires the Account/credential locks and validates current roots,
                    // exact signed PUT, certificates/revocations, recipients and Personal bootstrap.
                    let snapshot=match $snapshot(&mut tx,origin,account).await {
                        Ok(snapshot)=>snapshot,
                        Err(AccountBootstrapError::UnsupportedState)=>{
                            sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                            let now=$now(&mut tx).await?;
                            if now>=expires {
                                $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private,established]).await?;
                                return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                            }
                            $append(&mut tx,&outcome_event(2,Some(account),now),now).await.map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                            return Ok(Err(AccountPasswordLoginError::AdmissionConflict));
                        }
                        Err(_)=>return Err(AccountPasswordLoginError::StorageUnavailable),
                    };
                    // The initial lookup is only a proof preflight. The bootstrap reader now
                    // holds the Account and credential locks: verify the current row again so
                    // an old AuthSecret cannot authorize a newly changed credential/snapshot.
                    let locked=sqlx::query(&format!("SELECT b.credential_generation,b.password_profile,CASE WHEN {length}(b.password_salt)=16 THEN b.password_salt END AS salt,CASE WHEN {length}(b.verifier)=32 THEN b.verifier END AS verifier,a.password_owned FROM account_password_bootstrap b JOIN identity_accounts a ON a.account_id=b.account_id WHERE b.account_id=$1 AND b.origin=$2 AND b.username=$3"))
                        .bind(account.as_bytes().as_slice()).bind(origin).bind(&retained_username).fetch_optional(&mut *tx).await?
                        .ok_or(AccountPasswordLoginError::StorageUnavailable)?;
                    let locked_verifier=Zeroizing::new(locked.try_get::<Vec<u8>,_>("verifier").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?);
                    let current_proof=PasswordVerifier::from_bytes(&locked_verifier).map_err(|_|AccountPasswordLoginError::StorageUnavailable)?
                        .verify(SecretVec::new(auth_secret.as_ref().to_vec())).is_ok();
                    drop(auth_secret);
                    drop(locked_verifier);
                    let locked_salt:Vec<u8>=locked.try_get("salt").map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    if !locked.try_get::<bool,_>("password_owned")? {return Err(AccountPasswordLoginError::StorageUnavailable);}
                    if !current_proof || locked.try_get::<i64,_>("credential_generation")?!=generation
                        || locked.try_get::<i64,_>("password_profile")?!=1 || locked_salt.as_slice()!=salt.as_slice() {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private,established]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    }
                    if $now(&mut tx).await?>=expires {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private,established]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    }
                    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_admission_capabilities").fetch_one(&mut *tx).await?;
                    let account_count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_admission_capabilities WHERE account_id=$1")
                        .bind(account.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                    if checked_count(count,CAPABILITY_CAPACITY)? || checked_count(account_count,ACCOUNT_CAPABILITY_CAPACITY)? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountPasswordLoginError::RateLimited(1)));
                    }
                    sqlx::query("SAVEPOINT account_password_capability").execute(&mut *tx).await?;
                    let token=random_key().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let token_digest=account_capability_digest(token.as_bytes());
                    let snapshot_digest=account_bootstrap_digest(snapshot.as_bytes());
                    let now=$now(&mut tx).await?;
                    let capability_expires=expiry(now,300_000)?;
                    let response=AccountPasswordLoginResponse {admission_token:token,snapshot,
                        expires_at_ms:u64::try_from(capability_expires).map_err(|_|AccountPasswordLoginError::StorageUnavailable)?};
                    let _encoded=Zeroizing::new(response.to_json().map_err(|_|AccountPasswordLoginError::StorageUnavailable)?);
                    sqlx::query("INSERT INTO account_admission_capabilities (token_digest,account_id,credential_generation,snapshot_digest,issued_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6)")
                        .bind(token_digest.as_slice()).bind(account.as_bytes().as_slice()).bind(generation)
                        .bind(snapshot_digest.as_slice()).bind(now).bind(capability_expires).execute(&mut *tx).await?;
                    sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                    $outcome(&mut tx,endpoint,source,&[private,established],true).await?;
                    $append(&mut tx,&outcome_event(1,Some(account),now),now).await.map_err(|_|AccountPasswordLoginError::StorageUnavailable)?;
                    let final_now=$now(&mut tx).await?;
                    if final_now>=expires {
                        // Expiry must leave no capability or success event. Preserve only
                        // admitted debt, matching-attempt consumption and mandatory denial.
                        sqlx::query("ROLLBACK TO SAVEPOINT account_password_capability").execute(&mut *tx).await?;
                        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1 WHERE singleton=1")
                            .bind(final_now).execute(&mut *tx).await?;
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private,established]).await?;
                        return Ok(Err(AccountPasswordLoginError::AuthenticationRequired));
                    }
                    require_live(final_now,capability_expires,deadline)?;
                    Ok(Ok(response))
                })
            }
        }
    };
}

password_store!(
    SqliteStore,
    sqlite_begin,
    sqlite_account_entry_now,
    admit_sqlite_account_entry_private_in_transaction,
    audit_sqlite_account_entry_failure_in_transaction,
    sqlite_account_entry_outcome_in_transaction,
    read_sqlite_password_bootstrap_in_transaction,
    crate::append_deployment_audit_event_in_transaction,
    "length"
);
password_store!(
    PostgresStore,
    postgres_begin,
    postgres_account_entry_now,
    admit_postgres_account_entry_private_in_transaction,
    audit_postgres_account_entry_failure_in_transaction,
    postgres_account_entry_outcome_in_transaction,
    read_postgres_password_bootstrap_in_transaction,
    crate::append_deployment_audit_event_in_postgres_transaction,
    "octet_length"
);
