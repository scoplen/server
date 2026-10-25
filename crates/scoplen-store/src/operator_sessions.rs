// SPDX-License-Identifier: AGPL-3.0-only
//! Durable discoverable passkey login and independent Operator browser refresh families.

use std::{
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::auth::{BrowserAuthTokenResponse, INITIAL_OPERATOR_ACCESS_SCOPE};
use scoplen_crypto::{
    DpopProof, DpopTarget, DpopToken, OperatorAccessToken, OperatorAccessTokenClaims,
    TrustedOperatorAccessTokenKeys, VerifiedOperatorAccessToken,
};
use scoplen_identity::operator_passkeys::{
    AssertionArtifacts, OperatorPasskeyVerifier, PasskeyError,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AuditStoreError, PostgresStore, RelationalStore, SqliteStore,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
    operator_admission::{
        OperatorAdmissionDecision, OperatorAdmissionError, OperatorAuthEndpoint,
        OperatorPrivateBucket,
    },
    operator_token_keys::OperatorTokenKeyring,
};

const FAMILY_MS: i64 = 2_592_000_000;

#[derive(Debug, Error)]
pub enum OperatorSessionError {
    #[error("operator authentication input is invalid")]
    InvalidInput,
    #[error("operator authentication proof does not match")]
    InvalidDpopProof,
    /// Every returned denial already includes its required audit and cooldown transaction.
    #[error("operator authentication denied")]
    Denied { changed: bool },
    /// Rate rejection has an audit but consumes no ceremony, credential or family.
    #[error("operator authentication rate limited")]
    RateLimited(u64),
    #[error("operator authentication storage unavailable")]
    Database,
    #[error("operator authentication audit unavailable")]
    Audit,
    #[error("operator authentication stored state is invalid")]
    Integrity,
    #[error("operator authentication clock unavailable")]
    Clock,
    #[error("operator authentication entropy unavailable")]
    Entropy,
    #[error("operator authentication commit outcome unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for OperatorSessionError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}
impl From<AuditStoreError> for OperatorSessionError {
    fn from(_: AuditStoreError) -> Self {
        Self::Audit
    }
}
impl From<OperatorAdmissionError> for OperatorSessionError {
    fn from(error: OperatorAdmissionError) -> Self {
        match error {
            OperatorAdmissionError::InvalidDpopProof => Self::InvalidDpopProof,
            OperatorAdmissionError::InvalidInput => Self::InvalidInput,
            OperatorAdmissionError::Audit => Self::Audit,
            OperatorAdmissionError::Clock => Self::Clock,
            OperatorAdmissionError::Database => Self::Database,
        }
    }
}

pub struct OperatorLoginOptions {
    pub ceremony_id: Uuid,
    pub expires_at_s: i64,
    pub public_key: Value,
}
impl fmt::Debug for OperatorLoginOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorLoginOptions([REDACTED])")
    }
}

/// The caller has already checked Origin, structural bounds and durably claimed the proof.
pub struct OperatorAuthentication<'a> {
    pub source: IpAddr,
    pub ceremony_id: Uuid,
    pub browser_jkt: &'a str,
    pub artifacts: AssertionArtifacts<'a>,
}

/// Returned only after a confirmed commit. The refresh credential has no JSON representation.
pub struct OperatorSessionResponse {
    browser: BrowserAuthTokenResponse,
    set_cookie: Zeroizing<String>,
}
impl fmt::Debug for OperatorSessionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorSessionResponse([REDACTED])")
    }
}
impl OperatorSessionResponse {
    #[must_use]
    pub fn browser(&self) -> &BrowserAuthTokenResponse {
        &self.browser
    }
    #[must_use]
    pub fn set_cookie(&self) -> &str {
        &self.set_cookie
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentOperatorSession {
    pub operator_id: Uuid,
    pub family_id: Uuid,
}

struct Credential {
    operator_id: Uuid,
    state: Vec<u8>,
}
struct Family {
    id: Uuid,
    operator_id: Uuid,
    credential_id: Vec<u8>,
    jkt: String,
    origin: String,
    scope: String,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    spent_at_ms: Option<i64>,
}

fn now_ms() -> Result<i64, OperatorSessionError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OperatorSessionError::Clock)?
            .as_millis(),
    )
    .map_err(|_| OperatorSessionError::Clock)
}
fn jkt_valid(jkt: &str) -> bool {
    jkt.len() == 43
        && URL_SAFE_NO_PAD
            .decode(jkt)
            .is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == jkt)
}
fn identifier(bytes: &[u8]) -> Result<Uuid, OperatorSessionError> {
    let id = Uuid::from_slice(bytes).map_err(|_| OperatorSessionError::Integrity)?;
    if id.get_version_num() != 7 {
        return Err(OperatorSessionError::Integrity);
    }
    Ok(id)
}
fn event(class: u8, now: i64, operator: Option<Uuid>) -> Vec<u8> {
    let mut out = b"spl-operator-session-v1".to_vec();
    out.push(class);
    out.extend_from_slice(&now.to_be_bytes());
    if let Some(id) = operator {
        out.extend_from_slice(id.as_bytes());
    }
    out
}
fn trusted_keys(
    origin: &str,
    keyring: &OperatorTokenKeyring,
) -> Result<TrustedOperatorAccessTokenKeys, OperatorSessionError> {
    let mut trusted = TrustedOperatorAccessTokenKeys::new(origin)
        .map_err(|_| OperatorSessionError::InvalidInput)?;
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).map_err(|_| OperatorSessionError::Integrity)?;
    }
    Ok(trusted)
}
fn sign_response(
    family: &Family,
    keyring: &OperatorTokenKeyring,
    now: i64,
) -> Result<(OperatorSessionResponse, [u8; 32]), OperatorSessionError> {
    if family.scope != INITIAL_OPERATOR_ACCESS_SCOPE {
        return Err(OperatorSessionError::Integrity);
    }
    let remaining = u64::try_from((family.expires_at_ms - now) / 1000)
        .map_err(|_| OperatorSessionError::Clock)?;
    if remaining == 0 {
        return Err(OperatorSessionError::Integrity);
    }
    let iat = u64::try_from(now / 1000).map_err(|_| OperatorSessionError::Clock)?;
    let claims = OperatorAccessTokenClaims {
        iss: family.origin.clone(),
        sub: family.operator_id,
        sid: family.id,
        jti: Uuid::now_v7(),
        cnf_jkt: family.jkt.clone(),
        scope: family.scope.clone(),
        iat,
        exp: iat.checked_add(600).ok_or(OperatorSessionError::Clock)?,
    };
    let trusted = trusted_keys(&family.origin, keyring)?;
    let token = OperatorAccessToken::sign(
        keyring.signing_key(),
        &trusted,
        keyring.signing_key().kid(),
        &claims,
    )
    .map_err(|_| OperatorSessionError::Integrity)?;
    if token.verify(&trusted, iat).map_err(|_| OperatorSessionError::Integrity)?.claims() != &claims
    {
        return Err(OperatorSessionError::Integrity);
    }
    let mut random = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *random).map_err(|_| OperatorSessionError::Entropy)?;
    let refresh = Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice()));
    let digest = Sha256::digest(refresh.as_bytes()).into();
    let mut browser = BrowserAuthTokenResponse::new(token.as_str())
        .map_err(|_| OperatorSessionError::Integrity)?;
    browser.refresh_expires_in = remaining;
    let json = browser.to_json().map_err(|_| OperatorSessionError::Integrity)?;
    if json.len() > 8192
        || BrowserAuthTokenResponse::from_json(&json)
            .map_err(|_| OperatorSessionError::Integrity)?
            != browser
    {
        return Err(OperatorSessionError::Integrity);
    }
    let set_cookie = Zeroizing::new(format!(
        "__Secure-spl-refresh={}; Path=/api/v1/auth/refresh; HttpOnly; Secure; SameSite=Strict; Max-Age={remaining}",
        *refresh
    ));
    if !set_cookie.is_ascii()
        || set_cookie.len() > 4096
        || set_cookie.bytes().any(|b| b == b'\r' || b == b'\n')
    {
        return Err(OperatorSessionError::Integrity);
    }
    Ok((OperatorSessionResponse { browser, set_cookie }, digest))
}

macro_rules! session_store {
    ($store:ty,$db:ty,$begin:ident,$lock:ident,$admission_lock:path,$outcome:path,$admit:path,$claim:path,$credential:ident,$family:ident,$denied:ident,$current:ident,$current_suffix:literal,$append:ident) => {
        impl $store {
            /// Persist fresh discoverable state without looking up or disclosing any operator.
            /// # Errors
            /// Invalid binding, unavailable storage, state generation or mandatory audit fail closed.
            pub async fn operator_login_options(&self,browser_jkt:&str,verifier:&OperatorPasskeyVerifier)->Result<OperatorLoginOptions,OperatorSessionError> {
                if !jkt_valid(browser_jkt) { return Err(OperatorSessionError::InvalidInput); }
                let mut tx=$begin(self).await?;$lock(&mut tx).await?;
                let now=now_ms()?/1000;let expires=now.checked_add(300).ok_or(OperatorSessionError::Clock)?;
                let options=verifier.authentication_options().map_err(|_|OperatorSessionError::Integrity)?;
                let id=Uuid::now_v7();
                sqlx::query::<$db>("DELETE FROM operator_ceremonies WHERE ceremony_id IN (SELECT ceremony_id FROM operator_ceremonies WHERE expires_at_s <= $1 ORDER BY expires_at_s LIMIT 128)").bind(now).execute(&mut *tx).await?;
                sqlx::query::<$db>("INSERT INTO operator_ceremonies (ceremony_id,purpose,browser_jkt,trusted_origin,rp_id,issued_at_s,expires_at_s,state_version,library_state) VALUES ($1,2,$2,$3,$4,$5,$6,1,$7)")
                    .bind(id.as_bytes().as_slice()).bind(browser_jkt).bind(verifier.origin()).bind(verifier.rp_id()).bind(now).bind(expires).bind(options.state).execute(&mut *tx).await?;
                $append(&mut tx,&event(1,now*1000,None),now*1000).await?;
                tx.commit().await?;
                Ok(OperatorLoginOptions {ceremony_id:id,expires_at_s:expires,public_key:options.public_key})
            }

            /// Verify original assertion bytes against the current locked credential, then
            /// atomically consume, update counter/backup state, and create a browser family.
            /// # Errors
            /// Live matching failed assertions consume only their ceremony with denial audit.
            /// An unknown attempted commit returns no cookie or access token.
            #[allow(clippy::too_many_lines)]
            pub async fn finish_operator_login(&self,input:&OperatorAuthentication<'_>,verifier:&OperatorPasskeyVerifier,keyring:&OperatorTokenKeyring)->Result<OperatorSessionResponse,OperatorSessionError> {
                let a=&input.artifacts;
                if input.ceremony_id.get_version_num()!=7 || !jkt_valid(input.browser_jkt)
                    || !(1..=1023).contains(&a.credential_id.len()) || !(1..=4096).contains(&a.client_data.len())
                    || !(37..=4096).contains(&a.authenticator_data.len()) || !(8..=72).contains(&a.signature.len()) { return Err(OperatorSessionError::InvalidInput); }
                let mut tx=$begin(self).await?;$lock(&mut tx).await?;$admission_lock(&mut tx).await?;
                let now=now_ms()?;
                let private=Some(OperatorPrivateBucket::Ceremony(input.ceremony_id));
                let row=sqlx::query::<$db>("SELECT browser_jkt,state_version,library_state FROM operator_ceremonies WHERE ceremony_id=$1 AND purpose=2 AND trusted_origin=$2 AND rp_id=$3 AND expires_at_s>$4 AND consumed_at_s IS NULL")
                    .bind(input.ceremony_id.as_bytes().as_slice()).bind(verifier.origin()).bind(verifier.rp_id()).bind(now/1000).fetch_optional(&mut *tx).await?;
                let Some(row)=row else { return $denied(tx,OperatorAuthEndpoint::LoginFinish,input.source,private,now,false,None).await; };
                if row.try_get::<String,_>("browser_jkt")?!=input.browser_jkt { return Err(OperatorSessionError::InvalidDpopProof); }
                if row.try_get::<i64,_>("state_version")?!=1 { return Err(OperatorSessionError::Integrity); }
                let state:Vec<u8>=row.try_get("library_state")?;
                let credential=$credential(&mut tx,a.credential_id,verifier.origin(),verifier.rp_id()).await?;
                let verified=if let Some(c)=&credential {
                    if c.operator_id.as_bytes()!=a.user_handle { None } else {
                        match verifier.verify_authentication(&state,&c.state,a) {
                            Ok(v)=>Some(v),Err(PasskeyError::Denied)=>None,Err(_)=>return Err(OperatorSessionError::Integrity),
                        }
                    }
                } else { None };
                if let (Some(c),Some(verified))=(credential,verified) {
                    if let OperatorAdmissionDecision::RateLimited(wait)=$admit(&mut tx,OperatorAuthEndpoint::LoginFinish,OperatorPrivateBucket::AuthenticatedOperator(c.operator_id)).await? {
                        $append(&mut tx,&event(5,now,Some(c.operator_id)),now).await?;tx.commit().await?;return Err(OperatorSessionError::RateLimited(wait));
                    }
                    let family=Family {id:Uuid::now_v7(),operator_id:c.operator_id,credential_id:a.credential_id.to_vec(),jkt:input.browser_jkt.to_owned(),origin:verifier.origin().to_owned(),scope:INITIAL_OPERATOR_ACCESS_SCOPE.to_owned(),expires_at_ms:now.checked_add(FAMILY_MS).ok_or(OperatorSessionError::Clock)?,revoked_at_ms:None,spent_at_ms:None};
                    let (response,digest)=sign_response(&family,keyring,now)?;
                    let updated=verified.to_storage(verifier).map_err(|_|OperatorSessionError::Integrity)?;
                    sqlx::query::<$db>("UPDATE operator_credentials SET credential_state=$1 WHERE credential_id=$2").bind(updated).bind(a.credential_id).execute(&mut *tx).await?;
                    sqlx::query::<$db>("UPDATE operator_ceremonies SET consumed_at_s=$1 WHERE ceremony_id=$2").bind(now/1000).bind(input.ceremony_id.as_bytes().as_slice()).execute(&mut *tx).await?;
                    sqlx::query::<$db>("INSERT INTO operator_refresh_families (family_id,principal_kind,operator_id,credential_id,dpop_jkt,trusted_origin,audience,scope,created_at_ms,expires_at_ms) VALUES ($1,'operator',$2,$3,$4,$5,'spl-admin/1',$6,$7,$8)")
                        .bind(family.id.as_bytes().as_slice()).bind(family.operator_id.as_bytes().as_slice()).bind(&family.credential_id).bind(&family.jkt).bind(&family.origin).bind(&family.scope).bind(now).bind(family.expires_at_ms).execute(&mut *tx).await?;
                    sqlx::query::<$db>("INSERT INTO operator_refresh_tokens (token_digest,family_id,issued_at_ms) VALUES ($1,$2,$3)").bind(digest.as_slice()).bind(family.id.as_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                    $outcome(&mut tx,OperatorAuthEndpoint::LoginFinish,input.source,private,true).await?;
                    $outcome(&mut tx,OperatorAuthEndpoint::LoginFinish,input.source,Some(OperatorPrivateBucket::AuthenticatedOperator(c.operator_id)),true).await?;
                    $append(&mut tx,&event(2,now,Some(c.operator_id)),now).await?;
                    tx.commit().await.map_err(|_|OperatorSessionError::CommitOutcomeUnknown)?;
                    Ok(response)
                } else {
                    sqlx::query::<$db>("UPDATE operator_ceremonies SET consumed_at_s=$1 WHERE ceremony_id=$2").bind(now/1000).bind(input.ceremony_id.as_bytes().as_slice()).execute(&mut *tx).await?;
                    $denied(tx,OperatorAuthEndpoint::LoginFinish,input.source,private,now,true,None).await
                }
            }

            /// Rotate a cookie-only Operator refresh credential. The HTTP boundary verifies the
            /// exact empty browser body, cookie carriage and trusted Origin first.
            /// # Errors
            /// Matching spent-token reuse revokes the family atomically with its audit. Invalid
            /// proofs and rate rejections cannot rotate, consume or revoke a family.
            #[allow(clippy::too_many_lines)]
            pub async fn refresh_operator(&self,source:IpAddr,origin:&str,refresh_token:&str,raw_proof:&str,keyring:&OperatorTokenKeyring)->Result<OperatorSessionResponse,OperatorSessionError> {
                if refresh_token.is_empty()||refresh_token.len()>2048 { return Err(OperatorSessionError::InvalidInput); }
                let proof=DpopProof::parse(raw_proof).map_err(|_|OperatorSessionError::InvalidDpopProof)?;
                let target=DpopTarget::new("POST",origin,"/api/v1/auth/refresh").map_err(|_|OperatorSessionError::InvalidInput)?;
                let origin_url=url::Url::parse(origin).map_err(|_|OperatorSessionError::InvalidInput)?;
                let rp_id=origin_url.domain().ok_or(OperatorSessionError::InvalidInput)?;
                let digest:[u8;32]=Sha256::digest(refresh_token.as_bytes()).into();
                let mut tx=$begin(self).await?;$lock(&mut tx).await?;$admission_lock(&mut tx).await?;
                let now=now_ms()?;
                let Some(family)=$family(&mut tx,&digest).await? else { return $denied(tx,OperatorAuthEndpoint::Refresh,source,None,now,false,None).await; };
                $claim(&mut tx,&proof,&target,DpopToken::Refresh,&family.jkt).await?;
                let private=Some(OperatorPrivateBucket::AuthenticatedOperator(family.operator_id));
                if let OperatorAdmissionDecision::RateLimited(wait)=$admit(&mut tx,OperatorAuthEndpoint::Refresh,private.expect("operator bucket")).await? {
                    $append(&mut tx,&event(5,now,Some(family.operator_id)),now).await?;tx.commit().await?;return Err(OperatorSessionError::RateLimited(wait));
                }
                let credential=$credential(&mut tx,&family.credential_id,origin,rp_id).await?;
                if family.origin!=origin || family.revoked_at_ms.is_some() || family.expires_at_ms.saturating_sub(now)<1000 || family.scope!=INITIAL_OPERATOR_ACCESS_SCOPE || !credential.is_some_and(|c|c.operator_id==family.operator_id) {
                    return $denied(tx,OperatorAuthEndpoint::Refresh,source,private,now,false,Some(family.operator_id)).await;
                }
                if family.spent_at_ms.is_some() {
                    sqlx::query::<$db>("UPDATE operator_refresh_families SET revoked_at_ms=$1 WHERE family_id=$2 AND revoked_at_ms IS NULL").bind(now).bind(family.id.as_bytes().as_slice()).execute(&mut *tx).await?;
                    return $denied(tx,OperatorAuthEndpoint::Refresh,source,private,now,true,Some(family.operator_id)).await;
                }
                let (response,next)=sign_response(&family,keyring,now)?;
                let changed=sqlx::query::<$db>("UPDATE operator_refresh_tokens SET spent_at_ms=$1 WHERE token_digest=$2 AND spent_at_ms IS NULL").bind(now).bind(digest.as_slice()).execute(&mut *tx).await?.rows_affected();
                if changed!=1 { return Err(OperatorSessionError::Integrity); }
                sqlx::query::<$db>("INSERT INTO operator_refresh_tokens (token_digest,family_id,issued_at_ms) VALUES ($1,$2,$3)").bind(next.as_slice()).bind(family.id.as_bytes().as_slice()).bind(now).execute(&mut *tx).await?;
                $outcome(&mut tx,OperatorAuthEndpoint::Refresh,source,private,true).await?;
                $append(&mut tx,&event(3,now,Some(family.operator_id)),now).await?;
                tx.commit().await.map_err(|_|OperatorSessionError::CommitOutcomeUnknown)?;
                Ok(response)
            }

            /// Check current independent family, principal and credential after signature
            /// verification. Exact route scope, DPoP/ath and replay checks remain mandatory.
            /// # Errors
            /// Unavailable identity storage fails closed; inactive state returns no principal.
            pub async fn current_operator_session(&self,verified:&VerifiedOperatorAccessToken)->Result<Option<CurrentOperatorSession>,OperatorSessionError> {
                let mut tx=$begin(self).await?;
                let principal=$current(&mut tx,verified).await?;
                tx.commit().await?;
                Ok(principal)
            }

        }

        /// Check current Operator session inside a caller-owned mutation transaction. The
        /// SQLite caller starts `BEGIN IMMEDIATE`; PostgreSQL calls this before any other
        /// business-state or audit lock. The session lock and PostgreSQL family, Operator and
        /// credential row locks remain held until transaction end.
        /// Exact route scope/policy, token signature and durably claimed DPoP/ath precede this.
        /// # Errors
        /// Identity storage failures abort authorization. Inactive or expired state returns none.
        pub async fn $current(tx:&mut sqlx::Transaction<'_,$db>,verified:&VerifiedOperatorAccessToken)->Result<Option<CurrentOperatorSession>,OperatorSessionError> {
            $lock(tx).await?;
            let claims=verified.claims();
            let now=now_ms()?;
            let seconds=u64::try_from(now/1000).map_err(|_|OperatorSessionError::Clock)?;
            if seconds>=claims.exp||claims.iat>seconds {return Ok(None);}
            let row=sqlx::query::<$db>(concat!("SELECT f.scope,f.dpop_jkt,f.trusted_origin,f.expires_at_ms FROM operator_refresh_families f JOIN deployment_operators o ON o.operator_id=f.operator_id JOIN operator_credentials c ON c.credential_id=f.credential_id AND c.operator_id=f.operator_id WHERE f.family_id=$1 AND f.operator_id=$2 AND f.principal_kind='operator' AND f.audience='spl-admin/1' AND f.revoked_at_ms IS NULL AND f.expires_at_ms>$3 AND o.active=1 AND c.active=1 AND c.trusted_origin=f.trusted_origin",$current_suffix))
                .bind(claims.sid.as_bytes().as_slice()).bind(claims.sub.as_bytes().as_slice()).bind(now).fetch_optional(&mut **tx).await?;
            let matches=if let Some(row)=row {
                let locked_now=now_ms()?;
                let locked_seconds=u64::try_from(locked_now/1000).map_err(|_|OperatorSessionError::Clock)?;
                locked_seconds<claims.exp&&claims.iat<=locked_seconds&&row.try_get::<i64,_>("expires_at_ms")?>locked_now&&row.try_get::<String,_>("scope")?==claims.scope&&claims.scope==INITIAL_OPERATOR_ACCESS_SCOPE&&row.try_get::<String,_>("dpop_jkt")?==claims.cnf_jkt&&row.try_get::<String,_>("trusted_origin")?==claims.iss
            }else{false};
            Ok(matches.then_some(CurrentOperatorSession {operator_id:claims.sub,family_id:claims.sid}))
        }

        async fn $credential(tx:&mut sqlx::Transaction<'_,$db>,id:&[u8],origin:&str,rp_id:&str)->Result<Option<Credential>,OperatorSessionError> {
            let row=sqlx::query::<$db>("SELECT c.operator_id,c.user_handle,c.credential_version,c.credential_state FROM operator_credentials c JOIN deployment_operators o ON o.operator_id=c.operator_id WHERE c.credential_id=$1 AND c.active=1 AND o.active=1 AND c.trusted_origin=$2 AND c.rp_id=$3").bind(id).bind(origin).bind(rp_id).fetch_optional(&mut **tx).await?;
            row.map(|r| {let owner:Vec<u8>=r.try_get("operator_id")?; let handle:Vec<u8>=r.try_get("user_handle")?;
                if owner!=handle||r.try_get::<i64,_>("credential_version")?!=1 {return Err(OperatorSessionError::Integrity);}
                Ok(Credential {operator_id:identifier(&owner)?,state:r.try_get("credential_state")?}) }).transpose()
        }

        async fn $family(tx:&mut sqlx::Transaction<'_,$db>,digest:&[u8;32])->Result<Option<Family>,OperatorSessionError> {
            let row=sqlx::query::<$db>("SELECT f.family_id,f.operator_id,f.credential_id,f.dpop_jkt,f.trusted_origin,f.scope,f.expires_at_ms,f.revoked_at_ms,t.spent_at_ms FROM operator_refresh_families f JOIN operator_refresh_tokens t ON t.family_id=f.family_id WHERE t.token_digest=$1 AND f.principal_kind='operator' AND f.audience='spl-admin/1'").bind(digest.as_slice()).fetch_optional(&mut **tx).await?;
            row.map(|r|Ok(Family {id:identifier(&r.try_get::<Vec<u8>,_>("family_id")?)?,operator_id:identifier(&r.try_get::<Vec<u8>,_>("operator_id")?)?,credential_id:r.try_get("credential_id")?,jkt:r.try_get("dpop_jkt")?,origin:r.try_get("trusted_origin")?,scope:r.try_get("scope")?,expires_at_ms:r.try_get("expires_at_ms")?,revoked_at_ms:r.try_get("revoked_at_ms")?,spent_at_ms:r.try_get("spent_at_ms")?})).transpose()
        }

        #[allow(clippy::too_many_arguments)]
        async fn $denied(mut tx:sqlx::Transaction<'_,$db>,endpoint:OperatorAuthEndpoint,source:IpAddr,private:Option<OperatorPrivateBucket<'_>>,now:i64,changed:bool,operator:Option<Uuid>)->Result<OperatorSessionResponse,OperatorSessionError> {
            $outcome(&mut tx,endpoint,source,private,false).await?;
            $append(&mut tx,&event(if changed && endpoint==OperatorAuthEndpoint::Refresh {4} else {6},now,operator),now).await?;
            if changed {tx.commit().await.map_err(|_|OperatorSessionError::CommitOutcomeUnknown)?;}else{tx.commit().await?;}
            Err(OperatorSessionError::Denied {changed})
        }
    }
}

pub(crate) async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
pub(crate) fn sqlite_lock(
    _: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> std::future::Ready<Result<(), sqlx::Error>> {
    std::future::ready(Ok(()))
}
pub(crate) async fn postgres_begin(
    store: &PostgresStore,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    store.pool().begin().await
}
pub(crate) async fn postgres_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048,1397052243)").execute(&mut **tx).await?;
    Ok(())
}
session_store!(
    SqliteStore,
    sqlx::Sqlite,
    sqlite_begin,
    sqlite_lock,
    crate::operator_admission::sqlite_lock,
    crate::operator_admission::sqlite_outcome,
    crate::operator_admission::sqlite_admit_private,
    crate::operator_admission::sqlite_claim_dpop,
    sqlite_credential,
    sqlite_family,
    sqlite_denied,
    verify_operator_session_in_sqlite_transaction,
    "",
    append_deployment_audit_event_in_transaction
);
session_store!(
    PostgresStore,
    sqlx::Postgres,
    postgres_begin,
    postgres_lock,
    crate::operator_admission::postgres_lock,
    crate::operator_admission::postgres_outcome,
    crate::operator_admission::postgres_admit_private,
    crate::operator_admission::postgres_claim_dpop,
    postgres_credential,
    postgres_family,
    postgres_denied,
    verify_operator_session_in_postgres_transaction,
    " FOR SHARE OF f,o,c",
    append_deployment_audit_event_in_postgres_transaction
);
