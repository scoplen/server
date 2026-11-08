// SPDX-License-Identifier: AGPL-3.0-only
//! Password Account browser families, independent of enrolled Devices and Operators.

use std::{fmt, net::IpAddr};

use scoplen_api::{
    account_browser::{
        ACCOUNT_BROWSER_ACCESS_SECONDS, ACCOUNT_BROWSER_FAMILY_SECONDS, AccountBrowserAccessToken,
        AccountBrowserCodecError, AccountBrowserPasswordLoginRequest,
        AccountBrowserPasswordLoginResponse, AccountBrowserPasswordOptionsRequest,
        AccountBrowserPasswordOptionsResponse, AccountBrowserRefreshResponse,
        AccountBrowserRefreshToken, INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE,
        account_browser_refresh_cookie,
    },
    auth::BrowserAuthTokenResponse,
};
use scoplen_crypto::{
    AccountProbeKey as ProbeDerivation, DpopProof, DpopTarget, DpopToken, PasswordVerifier,
    SecretVec, random_key,
};
use sqlx::{Row, Transaction};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    account_entry_admission::{
        AccountEntryAdmissionDecision, AccountEntryEndpoint, AccountEntryFailureReason,
        AccountEntryPrivateBucket, AccountEntryStateError, AccountUsernameBucket,
        VerifiedAccountBucket, admit_postgres_account_entry_private_in_transaction,
        admit_sqlite_account_entry_private_in_transaction,
        audit_postgres_account_entry_failure_in_transaction,
        audit_sqlite_account_entry_failure_in_transaction, postgres_account_entry_now,
        postgres_account_entry_outcome_in_transaction, sqlite_account_entry_now,
        sqlite_account_entry_outcome_in_transaction,
    },
    account_password_login::{AccountPasswordLoginError, attempt_digest, origin_digest},
    device_authentication::DeviceAuthenticationError,
    kms::KeyManagementService,
};

/// Fixed errors with no submitted password, credential or database diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum AccountBrowserSessionError {
    #[error("invalid Account browser request")]
    InvalidRequest,
    #[error("Account browser request exceeds its bound")]
    RequestTooLarge,
    #[error("Account browser authentication is required")]
    Denied { changed: bool },
    #[error("Account browser proof is invalid")]
    InvalidDpopProof,
    #[error("Account browser request is rate limited")]
    RateLimited(u64),
    #[error("Account browser storage is unavailable")]
    StorageUnavailable,
    #[error("Account browser commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for AccountBrowserSessionError {
    fn from(_: sqlx::Error) -> Self {
        Self::StorageUnavailable
    }
}
impl From<AccountEntryStateError> for AccountBrowserSessionError {
    fn from(_: AccountEntryStateError) -> Self {
        Self::StorageUnavailable
    }
}
impl From<AccountBrowserCodecError> for AccountBrowserSessionError {
    fn from(error: AccountBrowserCodecError) -> Self {
        match error {
            AccountBrowserCodecError::TooLarge => Self::RequestTooLarge,
            _ => Self::InvalidRequest,
        }
    }
}
impl From<AccountPasswordLoginError> for AccountBrowserSessionError {
    fn from(error: AccountPasswordLoginError) -> Self {
        match error {
            AccountPasswordLoginError::InvalidRequest => Self::InvalidRequest,
            AccountPasswordLoginError::RequestTooLarge => Self::RequestTooLarge,
            AccountPasswordLoginError::AuthenticationRequired => Self::Denied { changed: false },
            AccountPasswordLoginError::RateLimited(wait) => Self::RateLimited(wait),
            _ => Self::StorageUnavailable,
        }
    }
}

/// A durable Account browser identity; never a Device or an enrolled certificate.
#[derive(Clone)]
pub struct CurrentAccountBrowserSession {
    pub account_id: [u8; 16],
    pub family_id: [u8; 16],
    pub jkt: String,
    pub scope: String,
    pub expires_at_ms: i64,
    access_digest: [u8; 32],
    origin: String,
    credential_generation: i64,
}
impl fmt::Debug for CurrentAccountBrowserSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentAccountBrowserSession([REDACTED])")
    }
}

/// Disclosed only after confirmed COMMIT. The refresh credential has no JSON field.
pub struct AccountBrowserSessionResponse {
    pub browser: BrowserAuthTokenResponse,
    pub set_cookie: SecretVec,
}
impl fmt::Debug for AccountBrowserSessionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountBrowserSessionResponse([REDACTED])")
    }
}

struct IssuedSession {
    response: AccountBrowserSessionResponse,
    access_digest: [u8; 32],
    refresh_digest: [u8; 32],
    access_expires: i64,
}

fn issue_session(
    now: i64,
    family_expires: i64,
    initial: bool,
) -> Result<IssuedSession, AccountBrowserSessionError> {
    let access = AccountBrowserAccessToken::from_random_bytes(
        random_key().map_err(|_| AccountBrowserSessionError::StorageUnavailable)?.as_bytes(),
    );
    let refresh = AccountBrowserRefreshToken::from_random_bytes(
        random_key().map_err(|_| AccountBrowserSessionError::StorageUnavailable)?.as_bytes(),
    );
    let remaining = u64::try_from(family_expires.saturating_sub(now) / 1000)
        .map_err(|_| AccountBrowserSessionError::StorageUnavailable)?;
    let browser = BrowserAuthTokenResponse {
        access_token: access.as_str().to_owned(),
        token_type: "DPoP".into(),
        expires_in: ACCOUNT_BROWSER_ACCESS_SECONDS,
        refresh_expires_in: remaining,
    };
    let encoded = if initial {
        AccountBrowserPasswordLoginResponse(browser.clone()).to_json()
    } else {
        AccountBrowserRefreshResponse(browser.clone()).to_json()
    }?;
    drop(Zeroizing::new(encoded));
    Ok(IssuedSession {
        response: AccountBrowserSessionResponse {
            browser,
            set_cookie: account_browser_refresh_cookie(&refresh, remaining)?,
        },
        access_digest: access.digest(),
        refresh_digest: refresh.digest(),
        access_expires: now
            .checked_add(600_000)
            .ok_or(AccountBrowserSessionError::StorageUnavailable)?,
    })
}

fn event(class: u8, account: [u8; 16], family: [u8; 16], now: i64) -> Vec<u8> {
    let mut bytes = b"spl-account-browser-session-v1".to_vec();
    bytes.push(class);
    bytes.extend_from_slice(&account);
    bytes.extend_from_slice(&family);
    bytes.extend_from_slice(&now.to_be_bytes());
    bytes
}

fn now_ms() -> Result<i64, AccountBrowserSessionError> {
    i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(AccountBrowserSessionError::StorageUnavailable)
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
async fn postgres_begin(
    store: &PostgresStore,
) -> Result<Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    store.pool().begin().await
}

// Preparation may be cancelled; COMMIT is always awaited and never discloses uncertain credentials.
macro_rules! browser_transaction {
    ($store:expr,$begin:ident,$deadline:expr,$endpoint:expr,$source:expr,$tx:ident,$body:block) => {{
        let Ok(Ok(mut $tx)) = timeout_at($deadline, $begin($store)).await else {
            $store.password_storage_failure_audit($endpoint, $source).await?;
            return Err(AccountBrowserSessionError::StorageUnavailable);
        };
        match timeout_at($deadline, async { $body }).await {
            Ok(Ok(outcome)) if Instant::now() < $deadline => {
                $tx.commit().await.map_err(|_| AccountBrowserSessionError::CommitOutcomeUnknown)?;
                outcome
            }
            failure => {
                let rolled_back = $tx.rollback().await.is_ok();
                $store.password_storage_failure_audit($endpoint, $source).await?;
                if !rolled_back {
                    return Err(AccountBrowserSessionError::StorageUnavailable);
                }
                match failure {
                    Ok(Err(error)) => Err(error),
                    _ => Err(AccountBrowserSessionError::StorageUnavailable),
                }
            }
        }
    }};
}

macro_rules! browser_store {
    ($store:ty,$db:ty,$begin:ident,$now:ident,$admit:ident,$audit:ident,$outcome:ident,$append:path,$length:literal,$share:literal,$update:literal,$refresh_locks:literal,$current:ident,$require:ident) => {
        pub(crate) async fn $current(tx:&mut Transaction<'_,$db>,digest:&[u8;32],origin:&str,allow_revoked:bool)
            -> Result<Option<CurrentAccountBrowserSession>,AccountBrowserSessionError> {
            let query=concat!("SELECT f.account_id,f.family_id,f.dpop_jkt,f.scope,f.credential_generation,f.trusted_origin,f.created_at_ms,f.expires_at_ms AS family_expires,f.revoked_at_ms,t.issued_at_ms,t.expires_at_ms,b.credential_generation AS current_generation,b.origin AS credential_origin,b.password_profile AS current_profile,a.password_owned FROM account_browser_access_tokens t JOIN account_browser_families f ON f.family_id=t.family_id JOIN account_password_bootstrap b ON b.account_id=f.account_id JOIN identity_accounts a ON a.account_id=f.account_id WHERE t.token_digest=$1",$share);
            let Some(row)=sqlx::query(query).bind(digest.as_slice()).fetch_optional(&mut **tx).await? else {return Ok(None)};
            let now=now_ms()?;
            let generation:i64=row.try_get("credential_generation")?;
            let expires:i64=row.try_get("expires_at_ms")?;
            if row.try_get::<String,_>("trusted_origin")?!=origin
                || row.try_get::<String,_>("credential_origin")?!=origin
                || row.try_get::<i64,_>("current_profile")?!=1
                || row.try_get::<String,_>("scope")?!=INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
                || !row.try_get::<bool,_>("password_owned")?
                || generation<=0 || generation!=row.try_get::<i64,_>("current_generation")?
                || now<row.try_get::<i64,_>("issued_at_ms")? || now>=expires
                || now<row.try_get::<i64,_>("created_at_ms")? || now>=row.try_get::<i64,_>("family_expires")?
                || (!allow_revoked && row.try_get::<Option<i64>,_>("revoked_at_ms")?.is_some()) {
                return Ok(None);
            }
            let account:[u8;16]=row.try_get::<Vec<u8>,_>("account_id")?.try_into().map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
            let family:[u8;16]=row.try_get::<Vec<u8>,_>("family_id")?.try_into().map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
            Ok(Some(CurrentAccountBrowserSession{account_id:account,family_id:family,jkt:row.try_get("dpop_jkt")?,scope:INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE.into(),expires_at_ms:expires,access_digest:*digest,origin:origin.into(),credential_generation:generation}))
        }

        /// Revalidate the real browser family inside the protected business transaction.
        /// # Errors
        /// Rejects expired, revoked or changed Account/family authority and unavailable storage.
        pub async fn $require(tx:&mut Transaction<'_,$db>,expected:&CurrentAccountBrowserSession)
            -> Result<(),AccountBrowserSessionError> {
            let current=$current(tx,&expected.access_digest,&expected.origin,false).await?
                .ok_or(AccountBrowserSessionError::Denied{changed:false})?;
            if current.account_id!=expected.account_id || current.family_id!=expected.family_id
                || current.jkt!=expected.jkt || current.credential_generation!=expected.credential_generation
                || current.expires_at_ms!=expected.expires_at_ms || current.scope!=expected.scope {
                return Err(AccountBrowserSessionError::Denied{changed:false});
            }
            Ok(())
        }

        impl $store {
            /// Issue browser-purpose password options using the native password budgets and salt.
            /// # Errors
            /// Rejects invalid bounded input, unavailable state and shared admission exhaustion.
            pub async fn issue_account_browser_password_options(&self,source:IpAddr,origin:&str,body:&[u8],jkt:&str,kms:&dyn KeyManagementService,deadline:Instant)
                -> Result<AccountBrowserPasswordOptionsResponse,AccountBrowserSessionError> {
                let _=AccountBrowserPasswordOptionsRequest::from_json(body)?;
                Ok(AccountBrowserPasswordOptionsResponse(self.issue_bound_account_password_options(source,origin,body,kms,deadline,Some(jkt)).await?))
            }

            /// Authenticate a password without reading or creating any encrypted bootstrap or Device.
            /// # Errors
            /// Unknown/wrong passwords share one denial; unconfirmed commits return no authority.
            #[allow(clippy::too_many_lines,clippy::too_many_arguments)]
            pub async fn execute_account_browser_password_login(&self,source:IpAddr,origin:&str,body:SecretVec,jkt:&str,kms:&dyn KeyManagementService,deadline:Instant)
                -> Result<AccountBrowserSessionResponse,AccountBrowserSessionError> {
                let decoded=AccountBrowserPasswordLoginRequest::from_json(body.as_bytes());drop(body);
                let probe=if decoded.is_ok(){Some(self.password_retained_probe(kms,deadline,AccountEntryEndpoint::PasswordLogin,source).await?)}else{None};
                let endpoint=AccountEntryEndpoint::PasswordLogin;
                browser_transaction!(self,$begin,deadline,endpoint,source,tx,{
                    let now=$now(&mut tx).await?;
                    let request=match decoded {Ok(request)=>request.0,Err(error)=>{
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::InvalidRequest,&[]).await?;
                        return Ok(Err(error.into()));
                    }};
                    let digest=attempt_digest(request.attempt_id.as_bytes());
                    let row=sqlx::query("SELECT origin_digest,username,password_profile,password_salt,issued_at_ms,expires_at_ms,browser_jkt FROM account_password_attempts WHERE attempt_digest=$1 AND purpose=1")
                        .bind(digest.as_slice()).fetch_optional(&mut *tx).await?;
                    let Some(row)=row else {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    };
                    if row.try_get::<String,_>("browser_jkt")?!=jkt || row.try_get::<Vec<u8>,_>("origin_digest")?.as_slice()!=origin_digest(origin).as_slice() {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::InvalidDpopProof));
                    }
                    let username:String=row.try_get("username")?;
                    let salt:Vec<u8>=row.try_get("password_salt")?;
                    let expires:i64=row.try_get("expires_at_ms")?;
                    let issued:i64=row.try_get("issued_at_ms")?;
                    if issued<=0 || now<issued || issued.checked_add(120_000)!=Some(expires)
                        || row.try_get::<i64,_>("password_profile")?!=1 || salt.len()!=16 {
                        return Err(AccountBrowserSessionError::StorageUnavailable);
                    }
                    let probe=probe.ok_or(AccountBrowserSessionError::StorageUnavailable)?;
                    let username_bucket=AccountUsernameBucket::new(&probe,origin,&username)?;
                    let private=AccountEntryPrivateBucket::Username(&username_bucket);
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=$admit(&mut tx,endpoint,private).await? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::RateLimited(wait)));
                    }
                    if now>=expires {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    }
                    let length=$length;
                    let credential=sqlx::query(&format!("SELECT b.account_id,b.credential_generation,b.password_profile,b.password_salt,CASE WHEN {length}(b.verifier)=32 THEN b.verifier END AS verifier,a.password_owned FROM account_password_bootstrap b JOIN identity_accounts a ON a.account_id=b.account_id WHERE b.origin=$1 AND b.username=$2{}",if $share.is_empty(){""}else{" FOR SHARE OF b,a"}))
                        .bind(origin).bind(&username).fetch_optional(&mut *tx).await?;
                    let synthetic=ProbeDerivation::new(probe.as_bytes()).and_then(|key|key.synthetic_verifier(origin,&username)).map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    let verifier=Zeroizing::new(match &credential {Some(row)=>row.try_get::<Vec<u8>,_>("verifier")?,None=>synthetic.as_ref().to_vec()});
                    let matches=PasswordVerifier::from_bytes(&verifier).map_err(|_|AccountBrowserSessionError::StorageUnavailable)?
                        .verify(SecretVec::new(request.auth_secret.as_ref().to_vec())).is_ok();
                    drop(request);drop(verifier);
                    let valid=credential.as_ref().is_some_and(|row|matches
                        && row.try_get::<bool,_>("password_owned").ok()==Some(true)
                        && row.try_get::<i64,_>("password_profile").ok()==Some(1)
                        && row.try_get::<Vec<u8>,_>("password_salt").ok().as_deref()==Some(salt.as_slice()));
                    if !valid {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    }
                    let row=credential.ok_or(AccountBrowserSessionError::StorageUnavailable)?;
                    let account:[u8;16]=row.try_get::<Vec<u8>,_>("account_id")?.try_into().map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    let generation:i64=row.try_get("credential_generation")?;
                    let established=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(Uuid::from_bytes(account))?);
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=$admit(&mut tx,endpoint,established).await? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::RateLimited(wait)));
                    }
                    let now=$now(&mut tx).await?;
                    if now>=expires {
                        sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private,established]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    }
                    let family=Uuid::now_v7();
                    let family_expires=now.checked_add(i64::try_from(ACCOUNT_BROWSER_FAMILY_SECONDS).map_err(|_|AccountBrowserSessionError::StorageUnavailable)?*1000).ok_or(AccountBrowserSessionError::StorageUnavailable)?;
                    let issued=issue_session(now,family_expires,true)?;
                    sqlx::query("INSERT INTO account_browser_families (family_id,account_id,credential_generation,dpop_jkt,trusted_origin,scope,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
                        .bind(family.as_bytes().as_slice()).bind(account.as_slice()).bind(generation).bind(jkt).bind(origin).bind(INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE).bind(now).bind(family_expires).execute(&mut *tx).await?;
                    Self::insert_account_browser_tokens(&mut tx,family.as_bytes(),now,&issued).await?;
                    sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest=$1").bind(digest.as_slice()).execute(&mut *tx).await?;
                    $outcome(&mut tx,endpoint,source,&[private,established],true).await?;
                    $append(&mut tx,&event(1,account,family.into_bytes(),now),now).await.map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    if $now(&mut tx).await?>=expires {return Err(AccountBrowserSessionError::StorageUnavailable);}
                    Ok(Ok(issued.response))
                })
            }

            async fn insert_account_browser_tokens(tx:&mut Transaction<'_,$db>,family:&[u8;16],now:i64,issued:&IssuedSession)
                -> Result<(),AccountBrowserSessionError> {
                sqlx::query("INSERT INTO account_browser_access_tokens (token_digest,family_id,issued_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4)")
                    .bind(issued.access_digest.as_slice()).bind(family.as_slice()).bind(now).bind(issued.access_expires).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO account_browser_refresh_tokens (token_digest,family_id,issued_at_ms) VALUES ($1,$2,$3)")
                    .bind(issued.refresh_digest.as_slice()).bind(family.as_slice()).bind(now).execute(&mut **tx).await?;
                Ok(())
            }

            /// Look up a current opaque access credential, without accepting cookies as identity.
            /// # Errors
            /// Returns fixed storage errors; unknown, expired or revoked authority returns None.
            pub async fn current_account_browser_session(&self,token:&AccountBrowserAccessToken,origin:&str)
                -> Result<Option<CurrentAccountBrowserSession>,AccountBrowserSessionError> {
                let mut tx=$begin(self).await?;
                let result=$current(&mut tx,&token.digest(),origin,false).await?;
                tx.commit().await?;Ok(result)
            }

            /// Find only eligibility for explicit current-family logout, including a revoked family.
            /// This result is never general current-session authorization.
            /// # Errors
            /// Returns fixed storage errors; expired, changed or unknown credentials return None.
            pub async fn account_browser_logout_eligibility(&self,token:&AccountBrowserAccessToken,origin:&str)
                -> Result<Option<CurrentAccountBrowserSession>,AccountBrowserSessionError> {
                let mut tx=$begin(self).await?;
                let result=$current(&mut tx,&token.digest(),origin,true).await?;
                tx.commit().await?;Ok(result)
            }

            /// Rotate one matching proof-bound refresh credential without extending its family.
            /// # Errors
            /// Matching spent-token reuse revokes only that family; invalid proofs change no family.
            #[allow(clippy::too_many_lines)]
            pub async fn refresh_account_browser_session(&self,source:IpAddr,origin:&str,token:&AccountBrowserRefreshToken,raw_proof:&str,deadline:Instant)
                -> Result<AccountBrowserSessionResponse,AccountBrowserSessionError> {
                let digest=token.digest();
                let preflight=sqlx::query("SELECT f.dpop_jkt FROM account_browser_refresh_tokens t JOIN account_browser_families f ON f.family_id=t.family_id WHERE t.token_digest=$1")
                    .bind(digest.as_slice()).fetch_optional(self.pool()).await?;
                let Some(preflight)=preflight else {
                    self.audit_account_entry_failure(AccountEntryEndpoint::AccountBrowserRefresh,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                    return Err(AccountBrowserSessionError::Denied{changed:false});
                };
                let jkt:String=preflight.try_get("dpop_jkt")?;
                let Ok(proof)=DpopProof::parse(raw_proof) else {
                    self.audit_account_entry_failure(AccountEntryEndpoint::AccountBrowserRefresh,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                    return Err(AccountBrowserSessionError::InvalidDpopProof);
                };
                let target=DpopTarget::new("POST",origin,"/api/v1/auth/accounts/browser/refresh").map_err(|_|AccountBrowserSessionError::InvalidRequest)?;
                if let Err(error)=self.claim_dpop_proof(&proof,&target,DpopToken::Refresh,&jkt,None).await {
                    let (failure,reason)=match error {
                        DeviceAuthenticationError::Denied{..}=>(AccountBrowserSessionError::InvalidDpopProof,AccountEntryFailureReason::AuthenticationDenied),
                        _=>(AccountBrowserSessionError::StorageUnavailable,AccountEntryFailureReason::StorageUnavailable),
                    };
                    self.audit_account_entry_failure(AccountEntryEndpoint::AccountBrowserRefresh,source,reason,&[]).await?;
                    return Err(failure);
                }
                let endpoint=AccountEntryEndpoint::AccountBrowserRefresh;
                browser_transaction!(self,$begin,deadline,endpoint,source,tx,{
                    let _=$now(&mut tx).await?;
                    let row=sqlx::query(concat!("SELECT f.family_id,f.account_id,f.dpop_jkt,f.scope,f.trusted_origin,f.credential_generation,f.created_at_ms,f.expires_at_ms,f.revoked_at_ms,t.spent_at_ms,b.credential_generation AS current_generation,b.origin AS credential_origin,b.password_profile AS current_profile,a.password_owned FROM account_browser_refresh_tokens t JOIN account_browser_families f ON f.family_id=t.family_id JOIN account_password_bootstrap b ON b.account_id=f.account_id JOIN identity_accounts a ON a.account_id=f.account_id WHERE t.token_digest=$1",$refresh_locks))
                        .bind(digest.as_slice()).fetch_optional(&mut *tx).await?;
                    let Some(row)=row else {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    };
                    let now=$now(&mut tx).await?;
                    let account:[u8;16]=row.try_get::<Vec<u8>,_>("account_id")?.try_into().map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    let family:[u8;16]=row.try_get::<Vec<u8>,_>("family_id")?.try_into().map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    let generation:i64=row.try_get("credential_generation")?;
                    let family_expires:i64=row.try_get("expires_at_ms")?;
                    if row.try_get::<String,_>("dpop_jkt")?!=jkt || row.try_get::<String,_>("trusted_origin")?!=origin
                        || row.try_get::<String,_>("credential_origin")?!=origin || row.try_get::<i64,_>("current_profile")?!=1
                        || row.try_get::<String,_>("scope")?!=INITIAL_ACCOUNT_BROWSER_ACCESS_SCOPE
                        || !row.try_get::<bool,_>("password_owned")? || generation<=0 || generation!=row.try_get::<i64,_>("current_generation")?
                        || row.try_get::<Option<i64>,_>("revoked_at_ms")?.is_some()
                        || now<row.try_get::<i64,_>("created_at_ms")? || family_expires.saturating_sub(now)<1000 {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    }
                    let private=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(Uuid::from_bytes(account))?);
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=$admit(&mut tx,endpoint,private).await? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::RateLimited(wait)));
                    }
                    if row.try_get::<Option<i64>,_>("spent_at_ms")?.is_some() {
                        sqlx::query("UPDATE account_browser_families SET revoked_at_ms=$1 WHERE family_id=$2 AND revoked_at_ms IS NULL")
                            .bind(now).bind(family.as_slice()).execute(&mut *tx).await?;
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[private]).await?;
                        $append(&mut tx,&event(3,account,family,now),now).await.map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:true}));
                    }
                    let issued=issue_session(now,family_expires,false)?;
                    if sqlx::query("UPDATE account_browser_refresh_tokens SET spent_at_ms=$1 WHERE token_digest=$2 AND spent_at_ms IS NULL")
                        .bind(now).bind(digest.as_slice()).execute(&mut *tx).await?.rows_affected()!=1 {return Err(AccountBrowserSessionError::StorageUnavailable);}
                    Self::insert_account_browser_tokens(&mut tx,&family,now,&issued).await?;
                    $outcome(&mut tx,endpoint,source,&[private],true).await?;
                    $append(&mut tx,&event(2,account,family,now),now).await.map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    if family_expires.saturating_sub($now(&mut tx).await?)<1000 {return Err(AccountBrowserSessionError::StorageUnavailable);}
                    Ok(Ok(issued.response))
                })
            }

            /// Revoke only the current eligible browser family, or confirm its prior revocation.
            /// HTTP must already have claimed the fresh proof bound to the exact opaque access token.
            /// # Errors
            /// Expired/changed credentials cannot confirm logout; uncertain COMMIT is never success.
            pub async fn logout_account_browser_session(&self,source:IpAddr,expected:&CurrentAccountBrowserSession,deadline:Instant)
                -> Result<(),AccountBrowserSessionError> {
                let endpoint=AccountEntryEndpoint::AccountBrowserLogout;
                browser_transaction!(self,$begin,deadline,endpoint,source,tx,{
                    let now=$now(&mut tx).await?;
                    // Take the exclusive family lock before loading current credential facts.
                    sqlx::query(concat!("SELECT family_id FROM account_browser_families f WHERE family_id=$1",$update))
                        .bind(expected.family_id.as_slice()).fetch_optional(&mut *tx).await?;
                    let current=$current(&mut tx,&expected.access_digest,&expected.origin,true).await?;
                    let Some(current)=current else {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    };
                    if current.family_id!=expected.family_id || current.account_id!=expected.account_id || current.jkt!=expected.jkt
                        || current.credential_generation!=expected.credential_generation {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::AuthenticationDenied,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::Denied{changed:false}));
                    }
                    let private=AccountEntryPrivateBucket::EstablishedAccount(VerifiedAccountBucket::after_authentication(Uuid::from_bytes(current.account_id))?);
                    if let AccountEntryAdmissionDecision::RateLimited(wait)=$admit(&mut tx,endpoint,private).await? {
                        $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                        return Ok(Err(AccountBrowserSessionError::RateLimited(wait)));
                    }
                    let changed=sqlx::query("UPDATE account_browser_families SET revoked_at_ms=$1 WHERE family_id=$2 AND revoked_at_ms IS NULL")
                        .bind(now).bind(expected.family_id.as_slice()).execute(&mut *tx).await?.rows_affected();
                    if changed==1 {
                        $append(&mut tx,&event(4,current.account_id,current.family_id,now),now).await.map_err(|_|AccountBrowserSessionError::StorageUnavailable)?;
                    }
                    if $current(&mut tx,&expected.access_digest,&expected.origin,true).await?.is_none() {return Err(AccountBrowserSessionError::Denied{changed:false});}
                    $outcome(&mut tx,endpoint,source,&[private],true).await?;
                    Ok(Ok(()))
                })
            }
        }
    };
}

browser_store!(
    SqliteStore,
    sqlx::Sqlite,
    sqlite_begin,
    sqlite_account_entry_now,
    admit_sqlite_account_entry_private_in_transaction,
    audit_sqlite_account_entry_failure_in_transaction,
    sqlite_account_entry_outcome_in_transaction,
    crate::append_deployment_audit_event_in_transaction,
    "length",
    "",
    "",
    "",
    load_sqlite_account_browser_session,
    require_sqlite_account_browser_session
);
browser_store!(
    PostgresStore,
    sqlx::Postgres,
    postgres_begin,
    postgres_account_entry_now,
    admit_postgres_account_entry_private_in_transaction,
    audit_postgres_account_entry_failure_in_transaction,
    postgres_account_entry_outcome_in_transaction,
    crate::append_deployment_audit_event_in_postgres_transaction,
    "octet_length",
    " FOR SHARE OF f,b,a",
    " FOR UPDATE OF f",
    " FOR UPDATE OF f FOR SHARE OF b,a",
    load_postgres_account_browser_session,
    require_postgres_account_browser_session
);
