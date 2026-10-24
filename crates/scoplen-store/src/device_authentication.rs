// SPDX-License-Identifier: AGPL-3.0-only
//! Durable admission, challenges, and single-use refresh credentials for enrolled devices.

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_api::auth::{AuthTokenResponse, DeviceAccessScope, INITIAL_DEVICE_ACCESS_SCOPE};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, DeviceAuthContext, DeviceCertificate, DpopProof,
    DpopTarget, DpopToken, RevocationStatement, TrustedDeviceAccessTokenKeys, VerifiedDpopProof,
    dpop_jwk_thumbprint, p256_verify,
};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row, Sqlite, SqlitePool, Transaction};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AuditStoreError, PostgresStore, RelationalStore, SqliteStore,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
    device_token_keys::DeviceTokenKeyring,
};

const WINDOW_MS: i64 = 60_000;
const CHALLENGE_MS: i64 = 120_000;
const FAMILY_MS: i64 = 2_592_000_000;
const FAILURE_RESET_MS: i64 = 600_000;
const CLEANUP_BATCH: i64 = 16;
const AUDIT_DOMAIN: &[u8] = b"spl-device-auth-audit-v1";

/// Admission buckets are separate for each anonymous authentication endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum DeviceAuthEndpoint {
    Challenge = 1,
    Device = 2,
    Refresh = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAuthAdmission {
    Admitted,
    RateLimited(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeviceAuthFailureReason {
    InvalidRequest = 1,
    OriginDenied = 2,
    AuthenticationDenied = 3,
    RateLimited = 4,
    StorageUnavailable = 5,
}

/// Storage errors contain no nonce, credential, proof, certificate, or key material.
#[derive(Debug, Error)]
pub enum DeviceAuthenticationError {
    #[error("device authentication input is invalid")]
    InvalidInput,
    #[error("device authentication DPoP proof is invalid")]
    InvalidDpopProof,
    #[error("device authentication denied")]
    Denied { changed: bool },
    #[error("device authentication is rate limited")]
    RateLimited(u64),
    #[error("device authentication storage failed")]
    Database,
    #[error("device authentication audit failed")]
    Audit,
    #[error("device authentication clock failed")]
    Clock,
    #[error("device authentication entropy failed")]
    Entropy,
    #[error("device authentication commit outcome is unknown")]
    CommitOutcomeUnknown,
}

impl From<sqlx::Error> for DeviceAuthenticationError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

impl From<AuditStoreError> for DeviceAuthenticationError {
    fn from(_: AuditStoreError) -> Self {
        Self::Audit
    }
}

/// A freshly issued challenge. The database retains only its digest.
pub struct DeviceChallenge {
    nonce: Zeroizing<[u8; 32]>,
    issued_at_ms: i64,
}

impl DeviceChallenge {
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub const fn issued_at_ms(&self) -> i64 {
        self.issued_at_ms
    }
}

impl std::fmt::Debug for DeviceChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceChallenge([REDACTED])")
    }
}

#[derive(Clone)]
struct Bucket {
    window_start_ms: i64,
    attempts: i64,
    failure_streak: i64,
    last_failure_ms: Option<i64>,
    cooldown_until_ms: Option<i64>,
    retain_until_ms: i64,
}

impl Bucket {
    fn fresh(now: i64) -> Self {
        let window_start_ms = now.div_euclid(WINDOW_MS) * WINDOW_MS;
        Self {
            window_start_ms,
            attempts: 0,
            failure_streak: 0,
            last_failure_ms: None,
            cooldown_until_ms: None,
            retain_until_ms: window_start_ms + WINDOW_MS,
        }
    }

    fn from_row<R: Row>(row: &R) -> Result<Self, DeviceAuthenticationError>
    where
        for<'a> &'a str: sqlx::ColumnIndex<R>,
        i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
        Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    {
        let bucket = Self {
            window_start_ms: row.try_get("window_start_ms")?,
            attempts: row.try_get("attempts")?,
            failure_streak: row.try_get("failure_streak")?,
            last_failure_ms: row.try_get("last_failure_ms")?,
            cooldown_until_ms: row.try_get("cooldown_until_ms")?,
            retain_until_ms: row.try_get("retain_until_ms")?,
        };
        if bucket.window_start_ms < 0
            || bucket.attempts < 0
            || bucket.failure_streak < 0
            || bucket.retain_until_ms <= 0
        {
            return Err(DeviceAuthenticationError::Database);
        }
        Ok(bucket)
    }

    fn admit(&mut self, now: i64, limit: i64) -> DeviceAuthAdmission {
        if now >= self.window_start_ms.saturating_add(WINDOW_MS) {
            self.window_start_ms = now.div_euclid(WINDOW_MS) * WINDOW_MS;
            self.attempts = 0;
        }
        if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= FAILURE_RESET_MS) {
            self.failure_streak = 0;
            self.last_failure_ms = None;
            self.cooldown_until_ms = None;
        }
        let quota_until = if self.attempts >= limit { self.window_start_ms + WINDOW_MS } else { 0 };
        let blocked_until = quota_until.max(self.cooldown_until_ms.unwrap_or(0));
        if blocked_until > now {
            self.update_retention();
            return DeviceAuthAdmission::RateLimited(retry_seconds(blocked_until - now));
        }
        self.attempts += 1;
        self.update_retention();
        DeviceAuthAdmission::Admitted
    }

    fn deny(&mut self, now: i64) {
        if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= FAILURE_RESET_MS) {
            self.failure_streak = 0;
        }
        self.failure_streak = self.failure_streak.saturating_add(1).min(10);
        let seconds = (1_i64 << (self.failure_streak - 1)).min(300);
        self.last_failure_ms = Some(now);
        self.cooldown_until_ms = Some(now.saturating_add(seconds * 1_000));
        self.update_retention();
    }

    fn clear_failure(&mut self) {
        self.failure_streak = 0;
        self.last_failure_ms = None;
        self.cooldown_until_ms = None;
        self.update_retention();
    }

    fn update_retention(&mut self) {
        self.retain_until_ms = (self.window_start_ms + WINDOW_MS)
            .max(self.last_failure_ms.map_or(0, |last| last.saturating_add(FAILURE_RESET_MS)))
            .max(self.cooldown_until_ms.unwrap_or(0));
    }
}

fn retry_seconds(remaining_ms: i64) -> u64 {
    u64::try_from((remaining_ms.saturating_add(999) / 1_000).clamp(1, 300)).unwrap_or(300)
}

fn now_ms() -> Result<i64, DeviceAuthenticationError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DeviceAuthenticationError::Clock)?
        .as_millis();
    i64::try_from(millis).map_err(|_| DeviceAuthenticationError::Clock)
}

fn source_key(source: IpAddr) -> Vec<u8> {
    match source {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or_else(|| address.octets().to_vec(), |mapped| mapped.octets().to_vec()),
    }
}

fn audit_event(
    class: u8,
    now: i64,
    ids: &[[u8; 16]],
) -> Result<Vec<u8>, DeviceAuthenticationError> {
    let mut event = Vec::with_capacity(AUDIT_DOMAIN.len() + 11 + ids.len() * 16);
    event.extend_from_slice(AUDIT_DOMAIN);
    event.push(class);
    event.extend_from_slice(
        &u64::try_from(now).map_err(|_| DeviceAuthenticationError::Clock)?.to_be_bytes(),
    );
    for id in ids {
        event.extend_from_slice(id);
    }
    Ok(event)
}

fn failure_event(
    endpoint: DeviceAuthEndpoint,
    reason: DeviceAuthFailureReason,
    now: i64,
    device_id: Option<[u8; 16]>,
    account_id: Option<[u8; 16]>,
) -> Result<Vec<u8>, DeviceAuthenticationError> {
    let mut event = audit_event(1, now, &[])?;
    event.push(endpoint as u8);
    event.push(reason as u8);
    if let Some(device_id) = device_id {
        event.push(1);
        event.extend_from_slice(&device_id);
    }
    if let Some(account_id) = account_id {
        event.push(2);
        event.extend_from_slice(&account_id);
    }
    Ok(event)
}

fn challenge_material(
    device_id: [u8; 16],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), DeviceAuthenticationError> {
    if Uuid::from_bytes(device_id).get_version_num() != 7 {
        return Err(DeviceAuthenticationError::InvalidInput);
    }
    let mut nonce = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *nonce).map_err(|_| DeviceAuthenticationError::Entropy)?;
    let digest = Sha256::digest(*nonce).into();
    Ok((nonce, digest))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Current enrolled device state after certificate publication and revocation checks.
pub struct CurrentPrincipal {
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub signing_public_key: Vec<u8>,
    pub jkt: String,
    pub certificate: Vec<u8>,
}

struct RefreshFamily {
    family_id: [u8; 16],
    account_id: [u8; 16],
    device_id: [u8; 16],
    dpop_jkt: String,
    scope: String,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    spent_at_ms: Option<i64>,
}

fn family_from_row<R: Row>(row: &R) -> Result<RefreshFamily, DeviceAuthenticationError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(RefreshFamily {
        family_id: row
            .try_get::<Vec<u8>, _>("family_id")?
            .try_into()
            .map_err(|_| DeviceAuthenticationError::Database)?,
        account_id: row
            .try_get::<Vec<u8>, _>("account_id")?
            .try_into()
            .map_err(|_| DeviceAuthenticationError::Database)?,
        device_id: row
            .try_get::<Vec<u8>, _>("device_id")?
            .try_into()
            .map_err(|_| DeviceAuthenticationError::Database)?,
        dpop_jkt: row.try_get("dpop_jkt")?,
        scope: row.try_get("scope")?,
        expires_at_ms: row.try_get("expires_at_ms")?,
        revoked_at_ms: row.try_get("revoked_at_ms")?,
        spent_at_ms: row.try_get("spent_at_ms")?,
    })
}

async fn lookup_sqlite_family(
    pool: &SqlitePool,
    digest: &[u8; 32],
) -> Result<Option<RefreshFamily>, DeviceAuthenticationError> {
    let row = sqlx::query(
        "SELECT f.family_id, f.account_id, f.device_id, f.dpop_jkt, f.scope,
                f.expires_at_ms, f.revoked_at_ms, t.spent_at_ms
         FROM device_refresh_tokens AS t
         JOIN device_refresh_families AS f ON f.family_id=t.family_id
         WHERE t.token_digest=?",
    )
    .bind(digest.as_slice())
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(family_from_row).transpose()
}

async fn lookup_postgres_family(
    pool: &PgPool,
    digest: &[u8; 32],
) -> Result<Option<RefreshFamily>, DeviceAuthenticationError> {
    let row = sqlx::query(
        "SELECT f.family_id, f.account_id, f.device_id, f.dpop_jkt, f.scope,
                f.expires_at_ms, f.revoked_at_ms, t.spent_at_ms
         FROM device_refresh_tokens AS t
         JOIN device_refresh_families AS f ON f.family_id=t.family_id
         WHERE t.token_digest=$1",
    )
    .bind(digest.as_slice())
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(family_from_row).transpose()
}

fn verify_refresh_proof(
    raw_proof: &str,
    origin: &str,
    expected_jkt: &str,
) -> Result<(DpopProof, DpopTarget, VerifiedDpopProof), DeviceAuthenticationError> {
    let proof =
        DpopProof::parse(raw_proof).map_err(|_| DeviceAuthenticationError::InvalidDpopProof)?;
    let target = DpopTarget::new("POST", origin, "/api/v1/auth/refresh")
        .map_err(|_| DeviceAuthenticationError::InvalidInput)?;
    let now =
        u64::try_from(now_ms()?.div_euclid(1_000)).map_err(|_| DeviceAuthenticationError::Clock)?;
    let verified = proof
        .verify(&target, DpopToken::Refresh, expected_jkt, now, None)
        .map_err(|_| DeviceAuthenticationError::InvalidDpopProof)?;
    Ok((proof, target, verified))
}

fn validate_refresh_credential(token: &str) -> Result<[u8; 32], DeviceAuthenticationError> {
    if token.is_empty() || token.len() > 2_048 {
        return Err(DeviceAuthenticationError::InvalidInput);
    }
    Ok(Sha256::digest(token.as_bytes()).into())
}

fn verify_current_principal(
    account_id: Vec<u8>,
    device_id: [u8; 16],
    account_signing_public_key: Vec<u8>,
    certificate_bytes: &[u8],
    certificate_published: bool,
    revocations: Vec<Vec<u8>>,
) -> Result<CurrentPrincipal, DeviceAuthenticationError> {
    let account_id: [u8; 16] =
        account_id.try_into().map_err(|_| DeviceAuthenticationError::Database)?;
    let account_signing_public_key: [u8; 32] =
        account_signing_public_key.try_into().map_err(|_| DeviceAuthenticationError::Database)?;
    if !certificate_published {
        return Err(DeviceAuthenticationError::Denied { changed: false });
    }
    let certificate = DeviceCertificate::decode(certificate_bytes)
        .map_err(|_| DeviceAuthenticationError::Database)?;
    certificate
        .verify(&account_signing_public_key)
        .map_err(|_| DeviceAuthenticationError::Database)?;
    if certificate.account_id.into_bytes() != account_id
        || certificate.device_id.into_bytes() != device_id
    {
        return Err(DeviceAuthenticationError::Database);
    }
    for bytes in revocations {
        let statement =
            RevocationStatement::decode(&bytes).map_err(|_| DeviceAuthenticationError::Database)?;
        statement
            .verify(&account_signing_public_key)
            .map_err(|_| DeviceAuthenticationError::Database)?;
        if statement.device_id.into_bytes() == device_id {
            return Err(DeviceAuthenticationError::Denied { changed: false });
        }
    }
    let jkt = dpop_jwk_thumbprint(&certificate.signing_public_key)
        .map_err(|_| DeviceAuthenticationError::Database)?;
    Ok(CurrentPrincipal {
        account_id,
        device_id,
        signing_public_key: certificate.signing_public_key,
        jkt,
        certificate: certificate_bytes.to_vec(),
    })
}

fn verify_device_signature(
    principal: &CurrentPrincipal,
    origin: &str,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), DeviceAuthenticationError> {
    let context =
        DeviceAuthContext::new(origin, &hex(nonce), Uuid::from_bytes(principal.device_id))
            .map_err(|_| DeviceAuthenticationError::InvalidInput)?;
    p256_verify(&principal.signing_public_key, &context.signature_input(), signature)
        .map_err(|_| DeviceAuthenticationError::Denied { changed: false })
}

fn narrowed_scope(original: &str) -> Result<String, DeviceAuthenticationError> {
    let mut previous = None;
    for scope in original.split(' ') {
        if DeviceAccessScope::from_token(scope).is_none()
            || previous.is_some_and(|earlier| earlier >= scope)
        {
            return Err(DeviceAuthenticationError::Denied { changed: false });
        }
        previous = Some(scope);
    }
    Ok(original.to_owned())
}

fn sign_response(
    principal: &CurrentPrincipal,
    origin: &str,
    keyring: &DeviceTokenKeyring,
    scope: &str,
    now: i64,
    refresh_seconds: u64,
) -> Result<(AuthTokenResponse, [u8; 32]), DeviceAuthenticationError> {
    let mut trusted = TrustedDeviceAccessTokenKeys::new(origin)
        .map_err(|_| DeviceAuthenticationError::InvalidInput)?;
    for key in keyring.verification_keys() {
        trusted
            .insert(&key.kid, &key.public_key)
            .map_err(|_| DeviceAuthenticationError::Database)?;
    }
    let iat = u64::try_from(now.div_euclid(1_000)).map_err(|_| DeviceAuthenticationError::Clock)?;
    let claims = DeviceAccessTokenClaims {
        iss: origin.to_owned(),
        sub: Uuid::from_bytes(principal.account_id),
        did: Uuid::from_bytes(principal.device_id),
        jti: Uuid::now_v7(),
        cnf_jkt: principal.jkt.clone(),
        org: vec![],
        scope: scope.to_owned(),
        iat,
        exp: iat.checked_add(600).ok_or(DeviceAuthenticationError::Clock)?,
    };
    let access_token = DeviceAccessToken::sign(
        keyring.signing_key(),
        &trusted,
        keyring.signing_key().kid(),
        &principal.signing_public_key,
        &claims,
    )
    .map_err(|_| DeviceAuthenticationError::Database)?;
    let verified =
        access_token.verify(&trusted, iat).map_err(|_| DeviceAuthenticationError::Database)?;
    if verified.claims() != &claims {
        return Err(DeviceAuthenticationError::Database);
    }
    let mut refresh_bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *refresh_bytes).map_err(|_| DeviceAuthenticationError::Entropy)?;
    let refresh_token = hex(&*refresh_bytes);
    let digest = Sha256::digest(refresh_token.as_bytes()).into();
    let mut response = AuthTokenResponse::new(access_token.as_str(), refresh_token)
        .map_err(|_| DeviceAuthenticationError::Database)?;
    response.refresh_expires_in = refresh_seconds;
    response.to_json().map_err(|_| DeviceAuthenticationError::Database)?;
    Ok((response, digest))
}

pub(crate) async fn load_sqlite_principal(
    tx: &mut Transaction<'_, Sqlite>,
    device_id: [u8; 16],
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    let row = sqlx::query(
        "SELECT d.account_id, d.certificate, a.account_signing_public_key
         FROM identity_devices AS d JOIN identity_accounts AS a ON a.account_id=d.account_id
         WHERE d.device_id=? AND d.active=1",
    )
    .bind(device_id.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let account_id: Vec<u8> = row.try_get("account_id")?;
    let certificate: Vec<u8> = row.try_get("certificate")?;
    let account_signing_public_key: Vec<u8> = row.try_get("account_signing_public_key")?;
    let published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_account_key_certificates WHERE account_id=? AND certificate=?",
    )
    .bind(&account_id)
    .bind(&certificate)
    .fetch_one(&mut **tx)
    .await?;
    let revocations = crate::account_devices::sqlite_statements(
        tx,
        &account_id,
        crate::account_devices::StatementKind::Revocation,
        &mut 0,
    )
    .await?;
    verify_current_principal(
        account_id,
        device_id,
        account_signing_public_key,
        &certificate,
        published == 1,
        revocations,
    )
    .map(Some)
}

pub(crate) async fn load_postgres_principal(
    tx: &mut Transaction<'_, Postgres>,
    device_id: [u8; 16],
    lock_identity: bool,
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    let query = if lock_identity {
        "SELECT d.account_id, d.certificate, a.account_signing_public_key
         FROM identity_devices AS d JOIN identity_accounts AS a ON a.account_id=d.account_id
         WHERE d.device_id=$1 AND d.active=true FOR SHARE OF d, a"
    } else {
        "SELECT d.account_id, d.certificate, a.account_signing_public_key
         FROM identity_devices AS d JOIN identity_accounts AS a ON a.account_id=d.account_id
         WHERE d.device_id=$1 AND d.active=true"
    };
    let row = sqlx::query(query).bind(device_id.as_slice()).fetch_optional(&mut **tx).await?;
    let Some(row) = row else { return Ok(None) };
    let account_id: Vec<u8> = row.try_get("account_id")?;
    let certificate: Vec<u8> = row.try_get("certificate")?;
    let account_signing_public_key: Vec<u8> = row.try_get("account_signing_public_key")?;
    let published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sync_account_key_certificates WHERE account_id=$1 AND certificate=$2",
    )
    .bind(&account_id)
    .bind(&certificate)
    .fetch_one(&mut **tx)
    .await?;
    let revocations = crate::account_devices::postgres_statements(
        tx,
        &account_id,
        crate::account_devices::StatementKind::Revocation,
        &mut 0,
    )
    .await?;
    verify_current_principal(
        account_id,
        device_id,
        account_signing_public_key,
        &certificate,
        published == 1,
        revocations,
    )
    .map(Some)
}

pub(crate) async fn lock_postgres_account_key_state(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &[u8; 16],
) -> Result<(), DeviceAuthenticationError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended(encode($1, 'hex'), 0))")
        .bind(account_id.as_slice())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn bucket_limit(kind: i64) -> i64 {
    match kind {
        2 => 10,
        _ => 30,
    }
}

async fn deny_sqlite_refresh(
    mut tx: Transaction<'_, Sqlite>,
    source: IpAddr,
    principal: &CurrentPrincipal,
    now: i64,
    changed: bool,
) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
    let endpoint = DeviceAuthEndpoint::Refresh;
    deny_sqlite_bucket(&mut tx, endpoint as i64, 1, &source_key(source), now).await?;
    deny_sqlite_bucket(&mut tx, endpoint as i64, 2, &principal.device_id, now).await?;
    deny_sqlite_bucket(&mut tx, endpoint as i64, 3, &principal.account_id, now).await?;
    let event = if changed {
        audit_event(4, now, &[principal.account_id, principal.device_id])?
    } else {
        failure_event(
            endpoint,
            DeviceAuthFailureReason::AuthenticationDenied,
            now,
            Some(principal.device_id),
            Some(principal.account_id),
        )?
    };
    append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
    if changed {
        tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
    } else {
        tx.commit().await?;
    }
    Err(DeviceAuthenticationError::Denied { changed })
}

async fn deny_postgres_refresh(
    mut tx: Transaction<'_, Postgres>,
    source_key: &[u8],
    principal: &CurrentPrincipal,
    mut buckets: [Bucket; 3],
    now: i64,
    changed: bool,
) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
    let endpoint = DeviceAuthEndpoint::Refresh;
    for ((kind, key), bucket) in
        [(1, source_key), (2, principal.device_id.as_slice()), (3, principal.account_id.as_slice())]
            .into_iter()
            .zip(&mut buckets)
    {
        bucket.deny(now);
        update_postgres_bucket(&mut tx, endpoint as i64, kind, key, bucket).await?;
    }
    let event = if changed {
        audit_event(4, now, &[principal.account_id, principal.device_id])?
    } else {
        failure_event(
            endpoint,
            DeviceAuthFailureReason::AuthenticationDenied,
            now,
            Some(principal.device_id),
            Some(principal.account_id),
        )?
    };
    append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now).await?;
    if changed {
        tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
    } else {
        tx.commit().await?;
    }
    Err(DeviceAuthenticationError::Denied { changed })
}

impl SqliteStore {
    /// Load the current enrolled device; a revoked or unpublished certificate is denied.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the current certificate or transaction cannot be read.
    pub async fn current_device_principal(
        &self,
        device_id: [u8; 16],
    ) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
        let mut tx = self.pool().begin().await?;
        let principal = load_sqlite_principal(&mut tx, device_id).await?;
        tx.commit().await?;
        Ok(principal)
    }

    /// Charge a source before parsing an authentication request body.
    ///
    /// # Errors
    ///
    /// Returns a storage or clock error when durable admission cannot be recorded.
    pub async fn admit_device_auth_source(
        &self,
        endpoint: DeviceAuthEndpoint,
        source: IpAddr,
    ) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
        admit_sqlite(self, endpoint as i64, 1, &source_key(source)).await
    }

    /// Charge the decoded device id without testing whether it exists.
    ///
    /// # Errors
    ///
    /// Returns a storage or clock error when durable admission cannot be recorded.
    pub async fn admit_device_auth_device(
        &self,
        endpoint: DeviceAuthEndpoint,
        device_id: [u8; 16],
    ) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
        admit_sqlite(self, endpoint as i64, 2, &device_id).await
    }

    /// Store a random device-bound challenge digest for exactly 120 seconds.
    ///
    /// # Errors
    ///
    /// Returns an input, entropy, clock, or storage error if issuance cannot complete.
    pub async fn issue_device_challenge(
        &self,
        device_id: [u8; 16],
    ) -> Result<DeviceChallenge, DeviceAuthenticationError> {
        let (nonce, digest) = challenge_material(device_id)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let now = now_ms()?;
        sqlx::query("DELETE FROM device_auth_challenges WHERE nonce_digest IN (SELECT nonce_digest FROM device_auth_challenges WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?)")
            .bind(now).bind(CLEANUP_BATCH).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO device_auth_challenges (nonce_digest, device_id, issued_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)")
            .bind(digest.as_slice()).bind(device_id.as_slice()).bind(now).bind(now + CHALLENGE_MS)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(DeviceChallenge { nonce, issued_at_ms: now })
    }

    /// Consume a live challenge and issue a DPoP-bound token and first refresh credential.
    ///
    /// The caller must have charged the source and decoded device id. The current certificate,
    /// revocations, account, signature, token claims, and signer output are rechecked under this
    /// transaction before the nonce, family, and audit commit.
    ///
    /// # Errors
    ///
    /// Returns denial or rate limiting for rejected authentication, and a storage, audit,
    /// signing, or uncertain-commit error if the exchange cannot complete safely.
    #[allow(clippy::too_many_lines)]
    pub async fn authenticate_device(
        &self,
        source: IpAddr,
        trusted_origin: &str,
        device_id: [u8; 16],
        nonce: &[u8; 32],
        signature: &[u8; 64],
        keyring: &DeviceTokenKeyring,
    ) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
        DeviceAuthContext::new(trusted_origin, &hex(nonce), Uuid::from_bytes(device_id))
            .map_err(|_| DeviceAuthenticationError::InvalidInput)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let principal = match load_sqlite_principal(&mut tx, device_id).await {
            Ok(Some(principal))
                if verify_device_signature(&principal, trusted_origin, nonce, signature)
                    .is_ok() =>
            {
                Some(principal)
            }
            Ok(Some(_) | None) | Err(DeviceAuthenticationError::Denied { .. }) => None,
            Err(error) => return Err(error),
        };
        let now = now_ms()?;
        if let Some(principal) = &principal {
            match admit_sqlite_bucket_in_tx(
                &mut tx,
                DeviceAuthEndpoint::Device as i64,
                3,
                &principal.account_id,
                now,
            )
            .await?
            {
                DeviceAuthAdmission::Admitted => {}
                DeviceAuthAdmission::RateLimited(delay) => {
                    let event = failure_event(
                        DeviceAuthEndpoint::Device,
                        DeviceAuthFailureReason::RateLimited,
                        now,
                        Some(device_id),
                        Some(principal.account_id),
                    )?;
                    append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
                    tx.commit().await?;
                    return Err(DeviceAuthenticationError::RateLimited(delay));
                }
            }
        }
        let digest: [u8; 32] = Sha256::digest(nonce).into();
        let claimed = sqlx::query(
            "UPDATE device_auth_challenges SET consumed_at_ms=?
             WHERE nonce_digest=? AND device_id=? AND consumed_at_ms IS NULL AND expires_at_ms>?",
        )
        .bind(now)
        .bind(digest.as_slice())
        .bind(device_id.as_slice())
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if let (true, Some(principal)) = (claimed, principal.as_ref()) {
            let (response, refresh_digest) = sign_response(
                principal,
                trusted_origin,
                keyring,
                INITIAL_DEVICE_ACCESS_SCOPE,
                now,
                2_592_000,
            )?;
            let family_id = Uuid::now_v7().into_bytes();
            sqlx::query(
                "INSERT INTO device_refresh_families
                 (family_id, account_id, device_id, dpop_jkt, audience, scope, created_at_ms, expires_at_ms)
                 VALUES (?, ?, ?, ?, 'spl-api/1', ?, ?, ?)",
            )
            .bind(family_id.as_slice())
            .bind(principal.account_id.as_slice())
            .bind(device_id.as_slice())
            .bind(&principal.jkt)
            .bind(INITIAL_DEVICE_ACCESS_SCOPE)
            .bind(now)
            .bind(now + FAMILY_MS)
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO device_refresh_tokens (token_digest, family_id, issued_at_ms) VALUES (?, ?, ?)")
                .bind(refresh_digest.as_slice()).bind(family_id.as_slice()).bind(now)
                .execute(&mut *tx).await?;
            clear_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Device as i64, 1, &source_key(source))
                .await?;
            clear_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Device as i64, 2, &device_id).await?;
            clear_sqlite_bucket(
                &mut tx,
                DeviceAuthEndpoint::Device as i64,
                3,
                &principal.account_id,
            )
            .await?;
            let event = audit_event(2, now, &[principal.account_id, device_id])?;
            append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
            tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
            return Ok(response);
        }
        deny_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Device as i64, 1, &source_key(source), now)
            .await?;
        deny_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Device as i64, 2, &device_id, now).await?;
        if let Some(principal) = &principal {
            deny_sqlite_bucket(
                &mut tx,
                DeviceAuthEndpoint::Device as i64,
                3,
                &principal.account_id,
                now,
            )
            .await?;
        }
        let event = failure_event(
            DeviceAuthEndpoint::Device,
            DeviceAuthFailureReason::AuthenticationDenied,
            now,
            Some(device_id),
            principal.as_ref().map(|principal| principal.account_id),
        )?;
        append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
        if claimed {
            tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
        } else {
            tx.commit().await?;
        }
        Err(DeviceAuthenticationError::Denied { changed: claimed })
    }

    /// Rotate a device refresh credential, or revoke its family on matching spent-token reuse.
    ///
    /// The source must be admitted before request parsing. Invalid or wrong-key proofs cannot
    /// revoke a family; the complete next response is signed and encoded before commit.
    ///
    /// # Errors
    ///
    /// Returns a proof, denial, or rate-limit error for rejected refreshes, and a storage,
    /// audit, signing, or uncertain-commit error if rotation cannot complete safely.
    #[allow(clippy::too_many_lines)]
    pub async fn refresh_device(
        &self,
        source: IpAddr,
        trusted_origin: &str,
        refresh_token: &str,
        raw_dpop_proof: &str,
        keyring: &DeviceTokenKeyring,
    ) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
        let digest = validate_refresh_credential(refresh_token)?;
        let Some(preflight) = lookup_sqlite_family(self.pool(), &digest).await? else {
            self.audit_device_auth_failure(
                DeviceAuthEndpoint::Refresh,
                DeviceAuthFailureReason::AuthenticationDenied,
                source,
                None,
                None,
            )
            .await?;
            return Err(DeviceAuthenticationError::Denied { changed: false });
        };
        let (proof, target, _) =
            match verify_refresh_proof(raw_dpop_proof, trusted_origin, &preflight.dpop_jkt) {
                Ok(value) => value,
                Err(DeviceAuthenticationError::InvalidDpopProof) => {
                    self.audit_device_auth_failure(
                        DeviceAuthEndpoint::Refresh,
                        DeviceAuthFailureReason::InvalidRequest,
                        source,
                        None,
                        None,
                    )
                    .await?;
                    return Err(DeviceAuthenticationError::InvalidDpopProof);
                }
                Err(error) => return Err(error),
            };
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let principal = match load_sqlite_principal(&mut tx, preflight.device_id).await {
            Ok(value) => value,
            Err(DeviceAuthenticationError::Denied { .. }) => None,
            Err(error) => return Err(error),
        };
        let Some(principal) = principal.filter(|principal| {
            principal.account_id == preflight.account_id && principal.jkt == preflight.dpop_jkt
        }) else {
            drop(tx);
            self.audit_device_auth_failure(
                DeviceAuthEndpoint::Refresh,
                DeviceAuthFailureReason::AuthenticationDenied,
                source,
                None,
                None,
            )
            .await?;
            return Err(DeviceAuthenticationError::Denied { changed: false });
        };
        let now = now_ms()?;
        for (kind, key) in
            [(2, principal.device_id.as_slice()), (3, principal.account_id.as_slice())]
        {
            if let DeviceAuthAdmission::RateLimited(delay) = admit_sqlite_bucket_in_tx(
                &mut tx,
                DeviceAuthEndpoint::Refresh as i64,
                kind,
                key,
                now,
            )
            .await?
            {
                let event = failure_event(
                    DeviceAuthEndpoint::Refresh,
                    DeviceAuthFailureReason::RateLimited,
                    now,
                    Some(principal.device_id),
                    Some(principal.account_id),
                )?;
                append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
                tx.commit().await?;
                return Err(DeviceAuthenticationError::RateLimited(delay));
            }
        }
        let row = sqlx::query(
            "SELECT f.family_id, f.account_id, f.device_id, f.dpop_jkt, f.scope,
                    f.expires_at_ms, f.revoked_at_ms, t.spent_at_ms
             FROM device_refresh_tokens AS t
             JOIN device_refresh_families AS f ON f.family_id=t.family_id
             WHERE t.token_digest=?",
        )
        .bind(digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let family = row.as_ref().map(family_from_row).transpose()?;
        let now = now_ms()?;
        let family = family.filter(|family| {
            family.family_id == preflight.family_id
                && family.account_id == principal.account_id
                && family.device_id == principal.device_id
                && family.dpop_jkt == principal.jkt
        });
        let verified = proof.verify(
            &target,
            DpopToken::Refresh,
            &principal.jkt,
            u64::try_from(now / 1_000).map_err(|_| DeviceAuthenticationError::Clock)?,
            None,
        );
        let Ok(verified) = verified else {
            drop(tx);
            self.audit_device_auth_failure(
                DeviceAuthEndpoint::Refresh,
                DeviceAuthFailureReason::InvalidRequest,
                source,
                None,
                None,
            )
            .await?;
            return Err(DeviceAuthenticationError::InvalidDpopProof);
        };
        match claim_sqlite_dpop(&mut tx, &verified, now).await {
            Ok(()) => {}
            Err(DeviceAuthenticationError::Denied { .. }) => {
                drop(tx);
                self.audit_device_auth_failure(
                    DeviceAuthEndpoint::Refresh,
                    DeviceAuthFailureReason::InvalidRequest,
                    source,
                    None,
                    None,
                )
                .await?;
                return Err(DeviceAuthenticationError::InvalidDpopProof);
            }
            Err(error) => return Err(error),
        }
        let Some(family) = family else {
            return deny_sqlite_refresh(tx, source, &principal, now, false).await;
        };
        if family.revoked_at_ms.is_some() || family.expires_at_ms.saturating_sub(now) < 1_000 {
            return deny_sqlite_refresh(tx, source, &principal, now, false).await;
        }
        if family.spent_at_ms.is_some() {
            sqlx::query("UPDATE device_refresh_families SET revoked_at_ms=? WHERE family_id=? AND revoked_at_ms IS NULL")
                .bind(now).bind(family.family_id.as_slice()).execute(&mut *tx).await?;
            return deny_sqlite_refresh(tx, source, &principal, now, true).await;
        }
        let scope = match narrowed_scope(&family.scope) {
            Ok(scope) => scope,
            Err(DeviceAuthenticationError::Denied { .. }) => {
                return deny_sqlite_refresh(tx, source, &principal, now, false).await;
            }
            Err(error) => return Err(error),
        };
        let remaining_seconds = u64::try_from((family.expires_at_ms - now) / 1_000)
            .map_err(|_| DeviceAuthenticationError::Clock)?;
        let (response, new_digest) =
            sign_response(&principal, trusted_origin, keyring, &scope, now, remaining_seconds)?;
        sqlx::query("UPDATE device_refresh_tokens SET spent_at_ms=? WHERE token_digest=? AND spent_at_ms IS NULL")
            .bind(now).bind(digest.as_slice()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO device_refresh_tokens (token_digest, family_id, issued_at_ms) VALUES (?, ?, ?)")
            .bind(new_digest.as_slice()).bind(family.family_id.as_slice()).bind(now)
            .execute(&mut *tx).await?;
        clear_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Refresh as i64, 1, &source_key(source))
            .await?;
        clear_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Refresh as i64, 2, &principal.device_id)
            .await?;
        clear_sqlite_bucket(&mut tx, DeviceAuthEndpoint::Refresh as i64, 3, &principal.account_id)
            .await?;
        let event = audit_event(3, now, &[principal.account_id, principal.device_id])?;
        append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
        tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
        Ok(response)
    }

    /// Commit a failure audit; only an admitted authentication denial advances cooldown.
    ///
    /// # Errors
    ///
    /// Returns a storage, audit, or clock error if the failure cannot be recorded.
    pub async fn audit_device_auth_failure(
        &self,
        endpoint: DeviceAuthEndpoint,
        reason: DeviceAuthFailureReason,
        source: IpAddr,
        device_id: Option<[u8; 16]>,
        account_id: Option<[u8; 16]>,
    ) -> Result<(), DeviceAuthenticationError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let now = now_ms()?;
        if reason == DeviceAuthFailureReason::AuthenticationDenied {
            deny_sqlite_bucket(&mut tx, endpoint as i64, 1, &source_key(source), now).await?;
            if let Some(device_id) = device_id {
                deny_sqlite_bucket(&mut tx, endpoint as i64, 2, &device_id, now).await?;
            }
            if let Some(account_id) = account_id {
                deny_sqlite_bucket(&mut tx, endpoint as i64, 3, &account_id, now).await?;
            }
        }
        let event = failure_event(endpoint, reason, now, device_id, account_id)?;
        append_deployment_audit_event_in_transaction(&mut tx, &event, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically claim one verified `DPoP` proof for a protected operation.
    ///
    /// The caller still checks the access token and current route authorization. This method
    /// verifies signature, target, token hash, binding, time, and optional nonce before claiming.
    ///
    /// # Errors
    ///
    /// Returns denial for a bad or replayed proof, or a storage or clock error.
    pub async fn claim_dpop_proof(
        &self,
        proof: &DpopProof,
        target: &DpopTarget,
        token: DpopToken<'_>,
        expected_jkt: &str,
        required_nonce: Option<&str>,
    ) -> Result<(), DeviceAuthenticationError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let now = now_ms()?;
        let verified = proof
            .verify(
                target,
                token,
                expected_jkt,
                u64::try_from(now / 1_000).map_err(|_| DeviceAuthenticationError::Clock)?,
                required_nonce,
            )
            .map_err(|_| DeviceAuthenticationError::Denied { changed: false })?;
        claim_sqlite_dpop(&mut tx, &verified, now).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn admit_sqlite_bucket_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    endpoint: i64,
    kind: i64,
    key: &[u8],
    now: i64,
) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM device_auth_admission WHERE endpoint=? AND kind=? AND bucket_key=?")
        .bind(endpoint).bind(kind).bind(key).fetch_optional(&mut **tx).await?;
    let mut bucket =
        row.as_ref().map(Bucket::from_row).transpose()?.unwrap_or_else(|| Bucket::fresh(now));
    let decision = bucket.admit(now, bucket_limit(kind));
    upsert_sqlite_bucket(tx, endpoint, kind, key, &bucket).await?;
    Ok(decision)
}

async fn clear_sqlite_bucket(
    tx: &mut Transaction<'_, Sqlite>,
    endpoint: i64,
    kind: i64,
    key: &[u8],
) -> Result<(), DeviceAuthenticationError> {
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM device_auth_admission WHERE endpoint=? AND kind=? AND bucket_key=?")
        .bind(endpoint).bind(kind).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(row) = row {
        let mut bucket = Bucket::from_row(&row)?;
        bucket.clear_failure();
        upsert_sqlite_bucket(tx, endpoint, kind, key, &bucket).await?;
    }
    Ok(())
}

impl PostgresStore {
    /// Load the current enrolled device; a revoked or unpublished certificate is denied.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the current certificate or transaction cannot be read.
    pub async fn current_device_principal(
        &self,
        device_id: [u8; 16],
    ) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
        let mut tx = self.pool().begin().await?;
        let principal = load_postgres_principal(&mut tx, device_id, false).await?;
        tx.commit().await?;
        Ok(principal)
    }

    /// Charge a source before parsing an authentication request body.
    ///
    /// # Errors
    ///
    /// Returns a storage or clock error when durable admission cannot be recorded.
    pub async fn admit_device_auth_source(
        &self,
        endpoint: DeviceAuthEndpoint,
        source: IpAddr,
    ) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
        admit_postgres(self, endpoint as i64, 1, &source_key(source)).await
    }

    /// Charge the decoded device id without testing whether it exists.
    ///
    /// # Errors
    ///
    /// Returns a storage or clock error when durable admission cannot be recorded.
    pub async fn admit_device_auth_device(
        &self,
        endpoint: DeviceAuthEndpoint,
        device_id: [u8; 16],
    ) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
        admit_postgres(self, endpoint as i64, 2, &device_id).await
    }

    /// Store a random device-bound challenge digest for exactly 120 seconds.
    ///
    /// # Errors
    ///
    /// Returns an input, entropy, clock, or storage error if issuance cannot complete.
    pub async fn issue_device_challenge(
        &self,
        device_id: [u8; 16],
    ) -> Result<DeviceChallenge, DeviceAuthenticationError> {
        let (nonce, digest) = challenge_material(device_id)?;
        let mut tx = self.pool().begin().await?;
        let now = now_ms()?;
        sqlx::query("INSERT INTO device_auth_challenges (nonce_digest, device_id, issued_at_ms, expires_at_ms) VALUES ($1, $2, $3, $4)")
            .bind(digest.as_slice()).bind(device_id.as_slice()).bind(now).bind(now + CHALLENGE_MS)
            .execute(&mut *tx).await?;
        sqlx::query("DELETE FROM device_auth_challenges WHERE nonce_digest IN (SELECT nonce_digest FROM device_auth_challenges WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT $2 FOR UPDATE SKIP LOCKED)")
            .bind(now).bind(CLEANUP_BATCH).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(DeviceChallenge { nonce, issued_at_ms: now })
    }

    /// Consume a live challenge and issue a DPoP-bound token and first refresh credential.
    ///
    /// # Errors
    ///
    /// Returns denial or rate limiting for rejected authentication, and a storage, audit,
    /// signing, or uncertain-commit error if the exchange cannot complete safely.
    #[allow(clippy::too_many_lines)]
    pub async fn authenticate_device(
        &self,
        source: IpAddr,
        trusted_origin: &str,
        device_id: [u8; 16],
        nonce: &[u8; 32],
        signature: &[u8; 64],
        keyring: &DeviceTokenKeyring,
    ) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
        DeviceAuthContext::new(trusted_origin, &hex(nonce), Uuid::from_bytes(device_id))
            .map_err(|_| DeviceAuthenticationError::InvalidInput)?;
        let mut tx = self.pool().begin().await?;
        let source_key = source_key(source);
        let mut source_bucket =
            lock_postgres_bucket(&mut tx, DeviceAuthEndpoint::Device as i64, 1, &source_key)
                .await?;
        let mut device_bucket =
            lock_postgres_bucket(&mut tx, DeviceAuthEndpoint::Device as i64, 2, &device_id).await?;
        let preflight = match load_postgres_principal(&mut tx, device_id, false).await {
            Ok(Some(principal))
                if verify_device_signature(&principal, trusted_origin, nonce, signature)
                    .is_ok() =>
            {
                Some(principal)
            }
            Ok(Some(_) | None) | Err(DeviceAuthenticationError::Denied { .. }) => None,
            Err(error) => return Err(error),
        };
        let mut account_bucket = if let Some(principal) = &preflight {
            Some(
                lock_postgres_bucket(
                    &mut tx,
                    DeviceAuthEndpoint::Device as i64,
                    3,
                    &principal.account_id,
                )
                .await?,
            )
        } else {
            None
        };
        let principal = if let Some(preflight) = &preflight {
            lock_postgres_account_key_state(&mut tx, &preflight.account_id).await?;
            match load_postgres_principal(&mut tx, device_id, true).await {
                Ok(Some(current))
                    if current.account_id == preflight.account_id
                        && verify_device_signature(&current, trusted_origin, nonce, signature)
                            .is_ok() =>
                {
                    Some(current)
                }
                Ok(Some(_) | None) | Err(DeviceAuthenticationError::Denied { .. }) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        if let (Some(principal), Some(bucket)) = (&principal, account_bucket.as_mut()) {
            let now = now_ms()?;
            match bucket.admit(now, 30) {
                DeviceAuthAdmission::Admitted => {
                    update_postgres_bucket(
                        &mut tx,
                        DeviceAuthEndpoint::Device as i64,
                        3,
                        &principal.account_id,
                        bucket,
                    )
                    .await?;
                }
                DeviceAuthAdmission::RateLimited(delay) => {
                    let event = failure_event(
                        DeviceAuthEndpoint::Device,
                        DeviceAuthFailureReason::RateLimited,
                        now,
                        Some(device_id),
                        Some(principal.account_id),
                    )?;
                    append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now)
                        .await?;
                    tx.commit().await?;
                    return Err(DeviceAuthenticationError::RateLimited(delay));
                }
            }
        }
        let digest: [u8; 32] = Sha256::digest(nonce).into();
        let _ = sqlx::query(
            "SELECT nonce_digest FROM device_auth_challenges WHERE nonce_digest=$1 AND device_id=$2 FOR UPDATE",
        )
        .bind(digest.as_slice())
        .bind(device_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let now = now_ms()?;
        let claimed = sqlx::query(
            "UPDATE device_auth_challenges SET consumed_at_ms=$1
             WHERE nonce_digest=$2 AND device_id=$3 AND consumed_at_ms IS NULL AND expires_at_ms>$1",
        )
        .bind(now)
        .bind(digest.as_slice())
        .bind(device_id.as_slice())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if let (true, Some(principal)) = (claimed, principal.as_ref()) {
            let (response, refresh_digest) = sign_response(
                principal,
                trusted_origin,
                keyring,
                INITIAL_DEVICE_ACCESS_SCOPE,
                now,
                2_592_000,
            )?;
            let family_id = Uuid::now_v7().into_bytes();
            sqlx::query(
                "INSERT INTO device_refresh_families
                 (family_id, account_id, device_id, dpop_jkt, audience, scope, created_at_ms, expires_at_ms)
                 VALUES ($1, $2, $3, $4, 'spl-api/1', $5, $6, $7)",
            )
            .bind(family_id.as_slice())
            .bind(principal.account_id.as_slice())
            .bind(device_id.as_slice())
            .bind(&principal.jkt)
            .bind(INITIAL_DEVICE_ACCESS_SCOPE)
            .bind(now)
            .bind(now + FAMILY_MS)
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO device_refresh_tokens (token_digest, family_id, issued_at_ms) VALUES ($1, $2, $3)")
                .bind(refresh_digest.as_slice()).bind(family_id.as_slice()).bind(now)
                .execute(&mut *tx).await?;
            source_bucket.clear_failure();
            device_bucket.clear_failure();
            update_postgres_bucket(
                &mut tx,
                DeviceAuthEndpoint::Device as i64,
                1,
                &source_key,
                &source_bucket,
            )
            .await?;
            update_postgres_bucket(
                &mut tx,
                DeviceAuthEndpoint::Device as i64,
                2,
                &device_id,
                &device_bucket,
            )
            .await?;
            if let Some(bucket) = account_bucket.as_mut() {
                bucket.clear_failure();
                update_postgres_bucket(
                    &mut tx,
                    DeviceAuthEndpoint::Device as i64,
                    3,
                    &principal.account_id,
                    bucket,
                )
                .await?;
            }
            let event = audit_event(2, now, &[principal.account_id, device_id])?;
            append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now).await?;
            tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
            return Ok(response);
        }
        source_bucket.deny(now);
        device_bucket.deny(now);
        update_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Device as i64,
            1,
            &source_key,
            &source_bucket,
        )
        .await?;
        update_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Device as i64,
            2,
            &device_id,
            &device_bucket,
        )
        .await?;
        if let (Some(principal), Some(bucket)) = (&principal, account_bucket.as_mut()) {
            bucket.deny(now);
            update_postgres_bucket(
                &mut tx,
                DeviceAuthEndpoint::Device as i64,
                3,
                &principal.account_id,
                bucket,
            )
            .await?;
        }
        let event = failure_event(
            DeviceAuthEndpoint::Device,
            DeviceAuthFailureReason::AuthenticationDenied,
            now,
            Some(device_id),
            principal.as_ref().map(|principal| principal.account_id),
        )?;
        append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now).await?;
        if claimed {
            tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
        } else {
            tx.commit().await?;
        }
        Err(DeviceAuthenticationError::Denied { changed: claimed })
    }

    /// Rotate a device refresh credential, or revoke its family on matching spent-token reuse.
    ///
    /// # Errors
    ///
    /// Returns a proof, denial, or rate-limit error for rejected refreshes, and a storage,
    /// audit, signing, or uncertain-commit error if rotation cannot complete safely.
    #[allow(clippy::too_many_lines)]
    pub async fn refresh_device(
        &self,
        source: IpAddr,
        trusted_origin: &str,
        refresh_token: &str,
        raw_dpop_proof: &str,
        keyring: &DeviceTokenKeyring,
    ) -> Result<AuthTokenResponse, DeviceAuthenticationError> {
        let digest = validate_refresh_credential(refresh_token)?;
        let Some(preflight) = lookup_postgres_family(self.pool(), &digest).await? else {
            self.audit_device_auth_failure(
                DeviceAuthEndpoint::Refresh,
                DeviceAuthFailureReason::AuthenticationDenied,
                source,
                None,
                None,
            )
            .await?;
            return Err(DeviceAuthenticationError::Denied { changed: false });
        };
        let (proof, target, _) =
            match verify_refresh_proof(raw_dpop_proof, trusted_origin, &preflight.dpop_jkt) {
                Ok(value) => value,
                Err(DeviceAuthenticationError::InvalidDpopProof) => {
                    self.audit_device_auth_failure(
                        DeviceAuthEndpoint::Refresh,
                        DeviceAuthFailureReason::InvalidRequest,
                        source,
                        None,
                        None,
                    )
                    .await?;
                    return Err(DeviceAuthenticationError::InvalidDpopProof);
                }
                Err(error) => return Err(error),
            };
        let mut tx = self.pool().begin().await?;
        let source_key = source_key(source);
        let mut source_bucket =
            lock_postgres_bucket(&mut tx, DeviceAuthEndpoint::Refresh as i64, 1, &source_key)
                .await?;
        let mut device_bucket = lock_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Refresh as i64,
            2,
            &preflight.device_id,
        )
        .await?;
        let principal = match load_postgres_principal(&mut tx, preflight.device_id, false).await {
            Ok(Some(principal))
                if principal.account_id == preflight.account_id
                    && principal.jkt == preflight.dpop_jkt =>
            {
                principal
            }
            Ok(Some(_) | None) | Err(DeviceAuthenticationError::Denied { .. }) => {
                drop(tx);
                self.audit_device_auth_failure(
                    DeviceAuthEndpoint::Refresh,
                    DeviceAuthFailureReason::AuthenticationDenied,
                    source,
                    None,
                    None,
                )
                .await?;
                return Err(DeviceAuthenticationError::Denied { changed: false });
            }
            Err(error) => return Err(error),
        };
        let mut account_bucket = lock_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Refresh as i64,
            3,
            &principal.account_id,
        )
        .await?;
        lock_postgres_account_key_state(&mut tx, &preflight.account_id).await?;
        let principal = match load_postgres_principal(&mut tx, preflight.device_id, true).await {
            Ok(Some(current))
                if current.account_id == preflight.account_id
                    && current.jkt == preflight.dpop_jkt =>
            {
                current
            }
            Ok(Some(_) | None) | Err(DeviceAuthenticationError::Denied { .. }) => {
                drop(tx);
                self.audit_device_auth_failure(
                    DeviceAuthEndpoint::Refresh,
                    DeviceAuthFailureReason::AuthenticationDenied,
                    source,
                    None,
                    None,
                )
                .await?;
                return Err(DeviceAuthenticationError::Denied { changed: false });
            }
            Err(error) => return Err(error),
        };
        let now = now_ms()?;
        for (kind, key, bucket) in [
            (2, principal.device_id.as_slice(), &mut device_bucket),
            (3, principal.account_id.as_slice(), &mut account_bucket),
        ] {
            match bucket.admit(now, bucket_limit(kind)) {
                DeviceAuthAdmission::Admitted => {
                    update_postgres_bucket(
                        &mut tx,
                        DeviceAuthEndpoint::Refresh as i64,
                        kind,
                        key,
                        bucket,
                    )
                    .await?;
                }
                DeviceAuthAdmission::RateLimited(delay) => {
                    let event = failure_event(
                        DeviceAuthEndpoint::Refresh,
                        DeviceAuthFailureReason::RateLimited,
                        now,
                        Some(principal.device_id),
                        Some(principal.account_id),
                    )?;
                    append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now)
                        .await?;
                    tx.commit().await?;
                    return Err(DeviceAuthenticationError::RateLimited(delay));
                }
            }
        }
        let _ = sqlx::query(
            "SELECT family_id FROM device_refresh_families WHERE family_id=$1 FOR UPDATE",
        )
        .bind(preflight.family_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let _ = sqlx::query("SELECT token_digest FROM device_refresh_tokens WHERE token_digest=$1 AND family_id=$2 FOR UPDATE")
            .bind(digest.as_slice()).bind(preflight.family_id.as_slice())
            .fetch_optional(&mut *tx).await?;
        let row = sqlx::query(
            "SELECT f.family_id, f.account_id, f.device_id, f.dpop_jkt, f.scope,
                    f.expires_at_ms, f.revoked_at_ms, t.spent_at_ms
             FROM device_refresh_tokens AS t
             JOIN device_refresh_families AS f ON f.family_id=t.family_id
             WHERE t.token_digest=$1",
        )
        .bind(digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let family = row.as_ref().map(family_from_row).transpose()?;
        let now = now_ms()?;
        let family = family.filter(|family| {
            family.family_id == preflight.family_id
                && family.account_id == principal.account_id
                && family.device_id == principal.device_id
                && family.dpop_jkt == principal.jkt
        });
        let verified = proof.verify(
            &target,
            DpopToken::Refresh,
            &principal.jkt,
            u64::try_from(now / 1_000).map_err(|_| DeviceAuthenticationError::Clock)?,
            None,
        );
        let Ok(verified) = verified else {
            drop(tx);
            self.audit_device_auth_failure(
                DeviceAuthEndpoint::Refresh,
                DeviceAuthFailureReason::InvalidRequest,
                source,
                None,
                None,
            )
            .await?;
            return Err(DeviceAuthenticationError::InvalidDpopProof);
        };
        match claim_postgres_dpop(&mut tx, &verified, now).await {
            Ok(()) => {}
            Err(DeviceAuthenticationError::Denied { .. }) => {
                drop(tx);
                self.audit_device_auth_failure(
                    DeviceAuthEndpoint::Refresh,
                    DeviceAuthFailureReason::InvalidRequest,
                    source,
                    None,
                    None,
                )
                .await?;
                return Err(DeviceAuthenticationError::InvalidDpopProof);
            }
            Err(error) => return Err(error),
        }
        let Some(family) = family else {
            return deny_postgres_refresh(
                tx,
                &source_key,
                &principal,
                [source_bucket, device_bucket, account_bucket],
                now,
                false,
            )
            .await;
        };
        if family.revoked_at_ms.is_some() || family.expires_at_ms.saturating_sub(now) < 1_000 {
            return deny_postgres_refresh(
                tx,
                &source_key,
                &principal,
                [source_bucket, device_bucket, account_bucket],
                now,
                false,
            )
            .await;
        }
        if family.spent_at_ms.is_some() {
            sqlx::query("UPDATE device_refresh_families SET revoked_at_ms=$1 WHERE family_id=$2 AND revoked_at_ms IS NULL")
                .bind(now).bind(family.family_id.as_slice()).execute(&mut *tx).await?;
            return deny_postgres_refresh(
                tx,
                &source_key,
                &principal,
                [source_bucket, device_bucket, account_bucket],
                now,
                true,
            )
            .await;
        }
        let scope = match narrowed_scope(&family.scope) {
            Ok(scope) => scope,
            Err(DeviceAuthenticationError::Denied { .. }) => {
                return deny_postgres_refresh(
                    tx,
                    &source_key,
                    &principal,
                    [source_bucket, device_bucket, account_bucket],
                    now,
                    false,
                )
                .await;
            }
            Err(error) => return Err(error),
        };
        let remaining_seconds = u64::try_from((family.expires_at_ms - now) / 1_000)
            .map_err(|_| DeviceAuthenticationError::Clock)?;
        let (response, new_digest) =
            sign_response(&principal, trusted_origin, keyring, &scope, now, remaining_seconds)?;
        let updated = sqlx::query(
            "UPDATE device_refresh_tokens SET spent_at_ms=$1 WHERE token_digest=$2 AND spent_at_ms IS NULL",
        )
        .bind(now)
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(DeviceAuthenticationError::Database);
        }
        sqlx::query("INSERT INTO device_refresh_tokens (token_digest, family_id, issued_at_ms) VALUES ($1, $2, $3)")
            .bind(new_digest.as_slice()).bind(family.family_id.as_slice()).bind(now)
            .execute(&mut *tx).await?;
        source_bucket.clear_failure();
        device_bucket.clear_failure();
        account_bucket.clear_failure();
        update_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Refresh as i64,
            1,
            &source_key,
            &source_bucket,
        )
        .await?;
        update_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Refresh as i64,
            2,
            &principal.device_id,
            &device_bucket,
        )
        .await?;
        update_postgres_bucket(
            &mut tx,
            DeviceAuthEndpoint::Refresh as i64,
            3,
            &principal.account_id,
            &account_bucket,
        )
        .await?;
        let event = audit_event(3, now, &[principal.account_id, principal.device_id])?;
        append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now).await?;
        tx.commit().await.map_err(|_| DeviceAuthenticationError::CommitOutcomeUnknown)?;
        Ok(response)
    }

    /// Commit a failure audit; only an admitted authentication denial advances cooldown.
    ///
    /// # Errors
    ///
    /// Returns a storage, audit, or clock error if the failure cannot be recorded.
    pub async fn audit_device_auth_failure(
        &self,
        endpoint: DeviceAuthEndpoint,
        reason: DeviceAuthFailureReason,
        source: IpAddr,
        device_id: Option<[u8; 16]>,
        account_id: Option<[u8; 16]>,
    ) -> Result<(), DeviceAuthenticationError> {
        let mut tx = self.pool().begin().await?;
        // Lock order matches device and refresh business transactions.
        let mut source_bucket =
            lock_postgres_bucket(&mut tx, endpoint as i64, 1, &source_key(source)).await?;
        let mut device_bucket = if let Some(device_id) = device_id {
            Some(lock_postgres_bucket(&mut tx, endpoint as i64, 2, &device_id).await?)
        } else {
            None
        };
        let mut account_bucket = if let Some(account_id) = account_id {
            Some(lock_postgres_bucket(&mut tx, endpoint as i64, 3, &account_id).await?)
        } else {
            None
        };
        let now = now_ms()?;
        if reason == DeviceAuthFailureReason::AuthenticationDenied {
            source_bucket.deny(now);
            update_postgres_bucket(
                &mut tx,
                endpoint as i64,
                1,
                &source_key(source),
                &source_bucket,
            )
            .await?;
            if let (Some(device_id), Some(bucket)) = (device_id, device_bucket.as_mut()) {
                bucket.deny(now);
                update_postgres_bucket(&mut tx, endpoint as i64, 2, &device_id, bucket).await?;
            }
            if let (Some(account_id), Some(bucket)) = (account_id, account_bucket.as_mut()) {
                bucket.deny(now);
                update_postgres_bucket(&mut tx, endpoint as i64, 3, &account_id, bucket).await?;
            }
        }
        let event = failure_event(endpoint, reason, now, device_id, account_id)?;
        append_deployment_audit_event_in_postgres_transaction(&mut tx, &event, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically claim one verified `DPoP` proof for a protected operation.
    ///
    /// # Errors
    ///
    /// Returns denial for a bad or replayed proof, or a storage or clock error.
    pub async fn claim_dpop_proof(
        &self,
        proof: &DpopProof,
        target: &DpopTarget,
        token: DpopToken<'_>,
        expected_jkt: &str,
        required_nonce: Option<&str>,
    ) -> Result<(), DeviceAuthenticationError> {
        let mut tx = self.pool().begin().await?;
        let now = now_ms()?;
        let verified = proof
            .verify(
                target,
                token,
                expected_jkt,
                u64::try_from(now / 1_000).map_err(|_| DeviceAuthenticationError::Clock)?,
                required_nonce,
            )
            .map_err(|_| DeviceAuthenticationError::Denied { changed: false })?;
        claim_postgres_dpop(&mut tx, &verified, now).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn deny_sqlite_bucket(
    tx: &mut Transaction<'_, Sqlite>,
    endpoint: i64,
    kind: i64,
    key: &[u8],
    now: i64,
) -> Result<(), DeviceAuthenticationError> {
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM device_auth_admission WHERE endpoint=? AND kind=? AND bucket_key=?")
        .bind(endpoint).bind(kind).bind(key).fetch_optional(&mut **tx).await?;
    let mut bucket =
        row.as_ref().map(Bucket::from_row).transpose()?.unwrap_or_else(|| Bucket::fresh(now));
    bucket.deny(now);
    upsert_sqlite_bucket(tx, endpoint, kind, key, &bucket).await
}

async fn lock_postgres_bucket(
    tx: &mut Transaction<'_, Postgres>,
    endpoint: i64,
    kind: i64,
    key: &[u8],
) -> Result<Bucket, DeviceAuthenticationError> {
    let now = now_ms()?;
    let fresh = Bucket::fresh(now);
    let row = sqlx::query("INSERT INTO device_auth_admission (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak, retain_until_ms) VALUES ($1, $2, $3, $4, 0, 0, $5) ON CONFLICT (endpoint, kind, bucket_key) DO UPDATE SET bucket_key=excluded.bucket_key RETURNING window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms")
        .bind(endpoint).bind(kind).bind(key).bind(fresh.window_start_ms).bind(fresh.retain_until_ms)
        .fetch_one(&mut **tx).await?;
    Bucket::from_row(&row)
}

fn dpop_claim(
    verified: &VerifiedDpopProof,
) -> Result<(String, [u8; 32], i64), DeviceAuthenticationError> {
    let retain_until_ms = i64::try_from(verified.last_accepted_at)
        .map_err(|_| DeviceAuthenticationError::Clock)?
        .checked_add(1)
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(DeviceAuthenticationError::Clock)?;
    Ok((verified.jkt.clone(), Sha256::digest(verified.jti.as_bytes()).into(), retain_until_ms))
}

async fn claim_sqlite_dpop(
    tx: &mut Transaction<'_, Sqlite>,
    verified: &VerifiedDpopProof,
    now: i64,
) -> Result<(), DeviceAuthenticationError> {
    let (jkt, digest, retain_until_ms) = dpop_claim(verified)?;
    sqlx::query("DELETE FROM device_dpop_replays WHERE (dpop_jkt, jti_digest) IN (SELECT dpop_jkt, jti_digest FROM device_dpop_replays WHERE retain_until_ms <= ? ORDER BY retain_until_ms LIMIT ?)")
        .bind(now).bind(CLEANUP_BATCH).execute(&mut **tx).await?;
    let result = sqlx::query(
        "INSERT INTO device_dpop_replays (dpop_jkt, jti_digest, retain_until_ms) VALUES (?, ?, ?)",
    )
    .bind(jkt)
    .bind(digest.as_slice())
    .bind(retain_until_ms)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            Err(DeviceAuthenticationError::Denied { changed: false })
        }
        Err(_) => Err(DeviceAuthenticationError::Database),
    }
}

async fn claim_postgres_dpop(
    tx: &mut Transaction<'_, Postgres>,
    verified: &VerifiedDpopProof,
    now: i64,
) -> Result<(), DeviceAuthenticationError> {
    let (jkt, digest, retain_until_ms) = dpop_claim(verified)?;
    sqlx::query("DELETE FROM device_dpop_replays WHERE (dpop_jkt, jti_digest) IN (SELECT dpop_jkt, jti_digest FROM device_dpop_replays WHERE retain_until_ms <= $1 ORDER BY retain_until_ms LIMIT $2 FOR UPDATE SKIP LOCKED)")
        .bind(now).bind(CLEANUP_BATCH).execute(&mut **tx).await?;
    let result = sqlx::query("INSERT INTO device_dpop_replays (dpop_jkt, jti_digest, retain_until_ms) VALUES ($1, $2, $3)")
        .bind(jkt).bind(digest.as_slice()).bind(retain_until_ms).execute(&mut **tx).await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            Err(DeviceAuthenticationError::Denied { changed: false })
        }
        Err(_) => Err(DeviceAuthenticationError::Database),
    }
}

async fn admit_sqlite(
    store: &SqliteStore,
    endpoint: i64,
    kind: i64,
    key: &[u8],
) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
    let mut tx = store.pool().begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms()?;
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM device_auth_admission WHERE endpoint=? AND kind=? AND bucket_key=?")
        .bind(endpoint).bind(kind).bind(key).fetch_optional(&mut *tx).await?;
    let mut bucket =
        row.as_ref().map(Bucket::from_row).transpose()?.unwrap_or_else(|| Bucket::fresh(now));
    let decision = bucket.admit(now, bucket_limit(kind));
    upsert_sqlite_bucket(&mut tx, endpoint, kind, key, &bucket).await?;
    sqlx::query("DELETE FROM device_auth_admission WHERE (endpoint, kind, bucket_key) IN (SELECT endpoint, kind, bucket_key FROM device_auth_admission WHERE retain_until_ms <= ? ORDER BY retain_until_ms LIMIT ?)")
        .bind(now).bind(CLEANUP_BATCH).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(decision)
}

async fn admit_postgres(
    store: &PostgresStore,
    endpoint: i64,
    kind: i64,
    key: &[u8],
) -> Result<DeviceAuthAdmission, DeviceAuthenticationError> {
    sqlx::query("DELETE FROM device_auth_admission WHERE (endpoint, kind, bucket_key) IN (SELECT endpoint, kind, bucket_key FROM device_auth_admission WHERE retain_until_ms <= $1 ORDER BY retain_until_ms LIMIT $2 FOR UPDATE SKIP LOCKED)")
        .bind(now_ms()?).bind(CLEANUP_BATCH).execute(store.pool()).await?;
    let mut tx = store.pool().begin().await?;
    let now = now_ms()?;
    let fresh = Bucket::fresh(now);
    let row = sqlx::query("INSERT INTO device_auth_admission (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak, retain_until_ms) VALUES ($1, $2, $3, $4, 0, 0, $5) ON CONFLICT (endpoint, kind, bucket_key) DO UPDATE SET bucket_key=excluded.bucket_key RETURNING window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms")
        .bind(endpoint).bind(kind).bind(key).bind(fresh.window_start_ms).bind(fresh.retain_until_ms)
        .fetch_one(&mut *tx).await?;
    let mut bucket = Bucket::from_row(&row)?;
    let decision = bucket.admit(now_ms()?, bucket_limit(kind));
    update_postgres_bucket(&mut tx, endpoint, kind, key, &bucket).await?;
    tx.commit().await?;
    Ok(decision)
}

async fn upsert_sqlite_bucket(
    tx: &mut Transaction<'_, Sqlite>,
    endpoint: i64,
    kind: i64,
    key: &[u8],
    bucket: &Bucket,
) -> Result<(), DeviceAuthenticationError> {
    sqlx::query("INSERT INTO device_auth_admission (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (endpoint, kind, bucket_key) DO UPDATE SET window_start_ms=excluded.window_start_ms, attempts=excluded.attempts, failure_streak=excluded.failure_streak, last_failure_ms=excluded.last_failure_ms, cooldown_until_ms=excluded.cooldown_until_ms, retain_until_ms=excluded.retain_until_ms")
        .bind(endpoint).bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms)
        .execute(&mut **tx).await?;
    Ok(())
}

async fn update_postgres_bucket(
    tx: &mut Transaction<'_, Postgres>,
    endpoint: i64,
    kind: i64,
    key: &[u8],
    bucket: &Bucket,
) -> Result<(), DeviceAuthenticationError> {
    sqlx::query("UPDATE device_auth_admission SET window_start_ms=$4, attempts=$5, failure_streak=$6, last_failure_ms=$7, cooldown_until_ms=$8, retain_until_ms=$9 WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3")
        .bind(endpoint).bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms)
        .execute(&mut **tx).await?;
    Ok(())
}
