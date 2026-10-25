// SPDX-License-Identifier: AGPL-3.0-only
//! Independent, bounded Account-entry admission shared by API replicas.

use std::net::IpAddr;

use scoplen_crypto::{AccountProbeKey as ProbeDerivation, SecretBytes};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{PostgresStore, RelationalStore, SqliteStore, account_probe_key::AccountProbeKey};

const WINDOW_MS: i64 = 60_000;
const IDLE_MS: i64 = 600_000;
const RATE_CAPACITY: i64 = 131_072;

/// Each native Account POST owns independent fixed-window debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum AccountEntryEndpoint {
    RequestChallenge = 1,
    Register = 2,
    PasswordOptions = 3,
    PasswordLogin = 4,
    DeviceAdmission = 5,
}

/// Non-identifying admission result; the delay always uses the common 1..300 range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountEntryAdmissionDecision {
    Admitted,
    RateLimited(u64),
}

/// Fixed failure classes; no transport detail or caller content enters the audit chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccountEntryFailureReason {
    InvalidRequest = 1,
    OriginDenied = 2,
    AuthenticationDenied = 3,
    RateLimited = 4,
    StorageUnavailable = 5,
}

/// A keyed canonical username, derived only with the retained deployment probe key.
pub struct AccountUsernameBucket(SecretBytes<32>);

impl AccountUsernameBucket {
    /// Bind an exact canonical username to the trusted configured origin.
    /// # Errors
    /// Rejects noncanonical identity inputs; neither value is normalized or stored.
    pub fn new(
        probe: &AccountProbeKey,
        trusted_origin: &str,
        username: &str,
    ) -> Result<Self, AccountEntryStateError> {
        let key = ProbeDerivation::new(probe.as_bytes())
            .and_then(|key| key.username_admission_identity(trusted_origin, username))
            .map_err(|_| AccountEntryStateError::InvalidInput)?;
        Ok(Self(key))
    }
}

impl std::fmt::Debug for AccountUsernameBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountUsernameBucket([REDACTED])")
    }
}

/// An Account established by verified credentials, capability or historical receipt.
///
/// This is a trusted application boundary, not a decoder or an authorization check.
#[derive(Clone, Copy)]
pub struct VerifiedAccountBucket(Uuid);

impl VerifiedAccountBucket {
    /// Select a private bucket only after verifying the credential and possession/signatures.
    /// A request-supplied Account id alone must never be passed to this constructor.
    /// # Errors
    /// Rejects an invalid internal identifier.
    pub fn after_authentication(account_id: Uuid) -> Result<Self, AccountEntryStateError> {
        valid_id(account_id)?;
        Ok(Self(account_id))
    }
}

impl std::fmt::Debug for VerifiedAccountBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedAccountBucket([REDACTED])")
    }
}

/// The caller must use the username retained by a login attempt, never a replacement input.
#[derive(Clone, Copy)]
pub enum AccountEntryPrivateBucket<'a> {
    Username(&'a AccountUsernameBucket),
    DecodedDevice(Uuid),
    EstablishedAccount(VerifiedAccountBucket),
}

impl std::fmt::Debug for AccountEntryPrivateBucket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountEntryPrivateBucket([REDACTED])")
    }
}

impl AccountEntryPrivateBucket<'_> {
    fn parts(
        self,
        endpoint: AccountEntryEndpoint,
    ) -> Result<(i64, Vec<u8>), AccountEntryStateError> {
        use AccountEntryEndpoint::{
            DeviceAdmission, PasswordLogin, PasswordOptions, Register, RequestChallenge,
        };
        match self {
            Self::Username(key) if matches!(endpoint, PasswordOptions | PasswordLogin) => {
                Ok((2, key.0.as_ref().to_vec()))
            }
            Self::DecodedDevice(id)
                if matches!(endpoint, RequestChallenge | Register | DeviceAdmission) =>
            {
                valid_id(id)?;
                Ok((3, id.as_bytes().to_vec()))
            }
            Self::EstablishedAccount(id)
                if matches!(endpoint, Register | PasswordLogin | DeviceAdmission) =>
            {
                Ok((4, id.0.as_bytes().to_vec()))
            }
            _ => Err(AccountEntryStateError::InvalidInput),
        }
    }
}

/// Errors contain no submitted identity, SQL diagnostic or secret material.
#[derive(Debug, Error)]
pub enum AccountEntryStateError {
    #[error("Account entry input is invalid")]
    InvalidInput,
    #[error("Account entry state is inconsistent")]
    Integrity,
    #[error("Account entry storage is unavailable")]
    Storage,
    #[error("Account entry audit is unavailable")]
    Audit,
    #[error("Account entry clock is unavailable")]
    Clock,
    #[error("Account entry entropy is unavailable")]
    Entropy,
    #[error("Account entry is rate limited")]
    RateLimited(u64),
    #[error("Account request challenge is no longer live")]
    ChallengeExpired,
}

impl From<sqlx::Error> for AccountEntryStateError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

impl From<crate::AuditStoreError> for AccountEntryStateError {
    fn from(_: crate::AuditStoreError) -> Self {
        Self::Audit
    }
}

pub(crate) fn valid_id(id: Uuid) -> Result<(), AccountEntryStateError> {
    if id.get_version_num() == 7 && id.get_variant() == uuid::Variant::RFC4122 {
        Ok(())
    } else {
        Err(AccountEntryStateError::InvalidInput)
    }
}

fn source_key(source: IpAddr) -> Vec<u8> {
    match source {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map_or_else(|| value.octets().to_vec(), |value| value.octets().to_vec()),
    }
}

struct Bucket {
    window_start_ms: i64,
    attempts: i64,
    failure_streak: i64,
    last_failure_ms: Option<i64>,
    cooldown_until_ms: Option<i64>,
    last_admitted_ms: i64,
    retire_at_ms: i64,
}

impl Bucket {
    fn fresh(now: i64) -> Result<Self, AccountEntryStateError> {
        let mut bucket = Self {
            window_start_ms: now / WINDOW_MS * WINDOW_MS,
            attempts: 0,
            failure_streak: 0,
            last_failure_ms: None,
            cooldown_until_ms: None,
            last_admitted_ms: now,
            retire_at_ms: 0,
        };
        bucket.retain()?;
        Ok(bucket)
    }

    fn from_row<R: Row>(row: &R, now: i64) -> Result<Self, AccountEntryStateError>
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
            last_admitted_ms: row.try_get("last_admitted_ms")?,
            retire_at_ms: row.try_get("retire_at_ms")?,
        };
        if bucket.window_start_ms < 0
            || bucket.window_start_ms % WINDOW_MS != 0
            || bucket.window_start_ms > now
            || !(0..=30).contains(&bucket.attempts)
            || !(0..=10).contains(&bucket.failure_streak)
            || bucket.last_admitted_ms <= 0
            || bucket.last_admitted_ms > now
            || bucket.retire_at_ms <= 0
            || (bucket.failure_streak == 0)
                != (bucket.last_failure_ms.is_none() && bucket.cooldown_until_ms.is_none())
            || (bucket.failure_streak > 0
                && !matches!((bucket.last_failure_ms, bucket.cooldown_until_ms), (Some(last),Some(until)) if last>0 && until>=last))
        {
            return Err(AccountEntryStateError::Integrity);
        }
        if let (Some(last), Some(until)) = (bucket.last_failure_ms, bucket.cooldown_until_ms) {
            let delay = (1_i64 << (bucket.failure_streak - 1)).min(300) * 1000;
            if last > now || last.checked_add(delay) != Some(until) {
                return Err(AccountEntryStateError::Integrity);
            }
        }
        let required = bucket
            .last_admitted_ms
            .checked_add(IDLE_MS)
            .ok_or(AccountEntryStateError::Integrity)?
            .max(
                bucket
                    .window_start_ms
                    .checked_add(WINDOW_MS)
                    .ok_or(AccountEntryStateError::Integrity)?,
            )
            .max(bucket.cooldown_until_ms.unwrap_or(0));
        if bucket.retire_at_ms != required {
            return Err(AccountEntryStateError::Integrity);
        }
        Ok(bucket)
    }

    fn clear(&mut self) {
        self.failure_streak = 0;
        self.last_failure_ms = None;
        self.cooldown_until_ms = None;
    }

    fn retain(&mut self) -> Result<(), AccountEntryStateError> {
        self.retire_at_ms = self
            .last_admitted_ms
            .checked_add(IDLE_MS)
            .ok_or(AccountEntryStateError::Clock)?
            .max(self.window_start_ms.checked_add(WINDOW_MS).ok_or(AccountEntryStateError::Clock)?)
            .max(self.cooldown_until_ms.unwrap_or(0));
        Ok(())
    }

    fn admit(
        &mut self,
        now: i64,
        limit: i64,
    ) -> Result<AccountEntryAdmissionDecision, AccountEntryStateError> {
        if now
            >= self.window_start_ms.checked_add(WINDOW_MS).ok_or(AccountEntryStateError::Clock)?
        {
            self.window_start_ms = now / WINDOW_MS * WINDOW_MS;
            self.attempts = 0;
        }
        if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= IDLE_MS) {
            self.clear();
        }
        let quota_until = if self.attempts >= limit { self.window_start_ms + WINDOW_MS } else { 0 };
        let blocked_until = quota_until.max(self.cooldown_until_ms.unwrap_or(0));
        if blocked_until > now {
            self.retain()?;
            return Ok(AccountEntryAdmissionDecision::RateLimited(
                u64::try_from(((blocked_until - now).saturating_add(999) / 1000).clamp(1, 300))
                    .map_err(|_| AccountEntryStateError::Clock)?,
            ));
        }
        self.attempts += 1;
        self.last_admitted_ms = now;
        self.retain()?;
        Ok(AccountEntryAdmissionDecision::Admitted)
    }

    fn outcome(&mut self, now: i64, success: bool) -> Result<(), AccountEntryStateError> {
        if success {
            self.clear();
        } else if self.cooldown_until_ms.is_none_or(|until| until <= now) {
            if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= IDLE_MS) {
                self.clear();
            }
            self.failure_streak = (self.failure_streak + 1).min(10);
            let delay = (1_i64 << (self.failure_streak - 1)).min(300) * 1000;
            self.last_failure_ms = Some(now);
            self.cooldown_until_ms =
                Some(now.checked_add(delay).ok_or(AccountEntryStateError::Clock)?);
        }
        self.retain()
    }
}

/// Content-free maintenance result. One pass considers at most 100 due rows per table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountEntryCleanup {
    pub admission_rows: u64,
    pub challenge_rows: u64,
    pub password_attempt_rows: u64,
    pub admission_capability_rows: u64,
}

pub(crate) async fn sqlite_account_entry_now(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<i64, AccountEntryStateError> {
    // The caller must use BEGIN IMMEDIATE: read locks must not later upgrade against another writer.
    let high: i64 =
        sqlx::query_scalar("SELECT time_high_water_ms FROM account_entry_state WHERE singleton=1")
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(AccountEntryStateError::Integrity)?;
    let clock: i64 = sqlx::query_scalar("SELECT CAST(strftime('%s','now') AS INTEGER)*1000 + CAST(substr(strftime('%f','now'),4,3) AS INTEGER)")
        .fetch_one(&mut **tx).await?;
    advance_sqlite_clock(tx, high, clock).await
}

async fn advance_sqlite_clock(
    tx: &mut Transaction<'_, Sqlite>,
    high: i64,
    clock: i64,
) -> Result<i64, AccountEntryStateError> {
    let now = high.max(clock);
    if high < 0 || clock <= 0 || now.checked_add(IDLE_MS).is_none() {
        return Err(AccountEntryStateError::Clock);
    }
    if sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1 WHERE singleton=1")
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(AccountEntryStateError::Integrity);
    }
    Ok(now)
}

pub(crate) async fn postgres_account_entry_now(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<i64, AccountEntryStateError> {
    let high: i64 = sqlx::query_scalar(
        "SELECT time_high_water_ms FROM account_entry_state WHERE singleton=1 FOR UPDATE",
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(AccountEntryStateError::Integrity)?;
    let clock: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&mut **tx)
            .await?;
    let now = high.max(clock);
    if high < 0 || clock <= 0 || now.checked_add(IDLE_MS).is_none() {
        return Err(AccountEntryStateError::Clock);
    }
    if sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1 WHERE singleton=1")
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(AccountEntryStateError::Integrity);
    }
    Ok(now)
}

macro_rules! account_admission_store {
    ($store:ty, $db:ty, $begin:expr, $now:ident, $admit:ident, $private:ident, $outcome:ident, $audit:ident, $append:path) => {
        impl $store {
            /// Charge the actual peer before collecting or decoding any request body.
            /// # Errors
            /// Fails closed if durable debt or its confirmed commit is unavailable.
            pub async fn admit_account_entry_source(&self, endpoint: AccountEntryEndpoint, source: IpAddr)
                -> Result<AccountEntryAdmissionDecision, AccountEntryStateError> {
                let mut tx = $begin(self).await?;
                let decision = $admit(&mut tx,endpoint,1,&source_key(source)).await?;
                if matches!(decision,AccountEntryAdmissionDecision::RateLimited(_)) {
                    $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                }
                tx.commit().await?;
                Ok(decision)
            }

            /// Charge decoded Device/username debt before entering a business transaction.
            /// # Errors
            /// Rejects an endpoint/bucket mismatch or unavailable durable state.
            pub async fn admit_account_entry_private(&self, endpoint: AccountEntryEndpoint, source: IpAddr, bucket: AccountEntryPrivateBucket<'_>)
                -> Result<AccountEntryAdmissionDecision, AccountEntryStateError> {
                let mut tx = $begin(self).await?;
                let decision = $private(&mut tx,endpoint,bucket).await?;
                if matches!(decision,AccountEntryAdmissionDecision::RateLimited(_)) {
                    $audit(&mut tx,endpoint,source,AccountEntryFailureReason::RateLimited,&[]).await?;
                }
                tx.commit().await?;
                Ok(decision)
            }

            /// Record a fixed failure, atomically adding cooldown only for authentication denial.
            /// Private entries must already have been admitted by this request; untrusted Account
            /// identifiers cannot select established debt. Audit failure overrides the denial.
            /// # Errors
            /// Fails closed if admission, mandatory audit or its commit is unavailable.
            pub async fn audit_account_entry_failure(&self,endpoint:AccountEntryEndpoint,source:IpAddr,
                reason:AccountEntryFailureReason,private:&[AccountEntryPrivateBucket<'_>])
                ->Result<(),AccountEntryStateError> {
                let mut tx=$begin(self).await?;
                $audit(&mut tx,endpoint,source,reason,private).await?;
                tx.commit().await?;
                Ok(())
            }

            /// Run indexed, bounded retirement at most once per durable second across workers.
            /// # Errors
            /// Missing/corrupt singleton or failed cleanup rolls back the whole pass.
            pub async fn cleanup_account_entry_state(&self) -> Result<AccountEntryCleanup, AccountEntryStateError> {
                let mut tx = $begin(self).await?;
                let now = $now(&mut tx).await?;
                let previous: i64 = sqlx::query_scalar("SELECT last_cleanup_ms FROM account_entry_state WHERE singleton=1")
                    .fetch_one(&mut *tx).await?;
                if previous > now || previous < 0 { return Err(AccountEntryStateError::Integrity); }
                if now-previous<1000 { tx.commit().await?; return Ok(AccountEntryCleanup::default()); }
                let candidates=sqlx::query("SELECT endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms FROM account_entry_admission WHERE retire_at_ms <= $1 ORDER BY retire_at_ms LIMIT 100")
                    .bind(now).fetch_all(&mut *tx).await?;
                let mut admission_rows=0;
                for candidate in candidates {
                    let bucket=Bucket::from_row(&candidate,now)?;
                    let endpoint:i64=candidate.try_get("endpoint")?;
                    let kind:i64=candidate.try_get("kind")?;
                    let key:Vec<u8>=candidate.try_get("bucket_key")?;
                    if bucket.retire_at_ms>now {return Err(AccountEntryStateError::Integrity);}
                    let deleted=sqlx::query("DELETE FROM account_entry_admission WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3 AND retire_at_ms <= $4 AND last_admitted_ms <= $4-600000 AND window_start_ms <= $4-60000 AND (cooldown_until_ms IS NULL OR cooldown_until_ms <= $4)")
                        .bind(endpoint).bind(kind).bind(key).bind(now).execute(&mut *tx).await?.rows_affected();
                    if deleted!=1 {return Err(AccountEntryStateError::Integrity);}
                    admission_rows+=deleted;
                }
                let challenge_rows=sqlx::query("DELETE FROM account_request_challenges WHERE attempt_digest IN (SELECT attempt_digest FROM account_request_challenges WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT 100)")
                    .bind(now).execute(&mut *tx).await?.rows_affected();
                let password_attempt_rows=sqlx::query("DELETE FROM account_password_attempts WHERE attempt_digest IN (SELECT attempt_digest FROM account_password_attempts WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT 100)")
                    .bind(now).execute(&mut *tx).await?.rows_affected();
                let admission_capability_rows=sqlx::query("DELETE FROM account_admission_capabilities WHERE token_digest IN (SELECT token_digest FROM account_admission_capabilities WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT 100)")
                    .bind(now).execute(&mut *tx).await?.rows_affected();
                let updated=sqlx::query("UPDATE account_entry_state SET rate_rows=rate_rows-$1,challenge_rows=challenge_rows-$2,last_cleanup_ms=$3 WHERE singleton=1")
                    .bind(i64::try_from(admission_rows).map_err(|_|AccountEntryStateError::Integrity)?)
                    .bind(i64::try_from(challenge_rows).map_err(|_|AccountEntryStateError::Integrity)?)
                    .bind(now).execute(&mut *tx).await?.rows_affected();
                if updated!=1 { return Err(AccountEntryStateError::Integrity); }
                tx.commit().await?;
                Ok(AccountEntryCleanup { admission_rows, challenge_rows, password_attempt_rows, admission_capability_rows })
            }
        }

        /// Charge an established private identity in the caller's mutation transaction.
        /// Rate denial must roll back a staged challenge claim; earlier admissions stay charged.
        /// # Errors
        /// Fails closed on invalid bucket selection or unavailable durable state.
        pub async fn $private(tx: &mut Transaction<'_,$db>, endpoint: AccountEntryEndpoint, bucket: AccountEntryPrivateBucket<'_>)
            -> Result<AccountEntryAdmissionDecision,AccountEntryStateError> {
            let (kind,key)=bucket.parts(endpoint)?;
            $admit(tx,endpoint,kind,&key).await
        }

        async fn $admit(tx: &mut Transaction<'_,$db>, endpoint: AccountEntryEndpoint, kind: i64, key: &[u8])
            -> Result<AccountEntryAdmissionDecision,AccountEntryStateError> {
            let now=$now(tx).await?;
            let row=sqlx::query("SELECT window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms FROM account_entry_admission WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3")
                .bind(endpoint as i64).bind(kind).bind(key).fetch_optional(&mut **tx).await?;
            let exists=row.is_some();
            if !exists {
                let count:i64=sqlx::query_scalar("SELECT rate_rows FROM account_entry_state WHERE singleton=1").fetch_one(&mut **tx).await?;
                if !(0..=RATE_CAPACITY).contains(&count) { return Err(AccountEntryStateError::Integrity); }
                if count==RATE_CAPACITY { return Ok(AccountEntryAdmissionDecision::RateLimited(1)); }
            }
            let mut bucket=match row {Some(row)=>Bucket::from_row(&row,now)?,None=>Bucket::fresh(now)?};
            let decision=bucket.admit(now,if kind==1 {30} else {10})?;
            let updated=sqlx::query("INSERT INTO account_entry_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (endpoint,kind,bucket_key) DO UPDATE SET window_start_ms=excluded.window_start_ms,attempts=excluded.attempts,failure_streak=excluded.failure_streak,last_failure_ms=excluded.last_failure_ms,cooldown_until_ms=excluded.cooldown_until_ms,last_admitted_ms=excluded.last_admitted_ms,retire_at_ms=excluded.retire_at_ms")
                .bind(endpoint as i64).bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts)
                .bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms)
                .bind(bucket.last_admitted_ms).bind(bucket.retire_at_ms).execute(&mut **tx).await?.rows_affected();
            if updated!=1 {return Err(AccountEntryStateError::Integrity);}
            if !exists && sqlx::query("UPDATE account_entry_state SET rate_rows=rate_rows+1 WHERE singleton=1")
                .execute(&mut **tx).await?.rows_affected()!=1 {return Err(AccountEntryStateError::Integrity);}
            Ok(decision)
        }

        /// Update only already admitted source/private buckets with the authenticated outcome.
        /// The caller must append its mandatory deployment audit and commit in this transaction.
        /// # Errors
        /// Rejects missing admitted debt, duplicate/mismatched buckets, or unavailable storage.
        pub async fn $outcome(tx:&mut Transaction<'_,$db>,endpoint:AccountEntryEndpoint,source:IpAddr,private:&[AccountEntryPrivateBucket<'_>],success:bool)
            -> Result<(),AccountEntryStateError> {
            if private.len()>2 {return Err(AccountEntryStateError::InvalidInput);}
            let now=$now(tx).await?;
            let mut keys=vec![(1,source_key(source))];
            for bucket in private {let parts=bucket.parts(endpoint)?;if keys.contains(&parts){return Err(AccountEntryStateError::InvalidInput);}keys.push(parts);}
            for (kind,key) in keys {
                let row=sqlx::query("SELECT window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms FROM account_entry_admission WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3")
                    .bind(endpoint as i64).bind(kind).bind(&key).fetch_optional(&mut **tx).await?.ok_or(AccountEntryStateError::Integrity)?;
                let mut bucket=Bucket::from_row(&row,now)?;
                bucket.outcome(now,success)?;
                let updated=sqlx::query("UPDATE account_entry_admission SET failure_streak=$4,last_failure_ms=$5,cooldown_until_ms=$6,retire_at_ms=$7 WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3")
                    .bind(endpoint as i64).bind(kind).bind(&key).bind(bucket.failure_streak).bind(bucket.last_failure_ms)
                    .bind(bucket.cooldown_until_ms).bind(bucket.retire_at_ms).execute(&mut **tx).await?.rows_affected();
                if updated!=1 {return Err(AccountEntryStateError::Integrity);}
            }
            Ok(())
        }

        /// Append a mandatory fixed denial event in the caller's transaction.
        /// # Errors
        /// Any admission/audit failure requires the caller to roll back the transaction.
        pub async fn $audit(tx:&mut Transaction<'_,$db>,endpoint:AccountEntryEndpoint,source:IpAddr,
            reason:AccountEntryFailureReason,private:&[AccountEntryPrivateBucket<'_>])
            ->Result<(),AccountEntryStateError> {
            if private.len()>2 {return Err(AccountEntryStateError::InvalidInput);}
            for bucket in private {bucket.parts(endpoint)?;}
            if reason==AccountEntryFailureReason::AuthenticationDenied {
                $outcome(tx,endpoint,source,private,false).await?;
            }
            let now=$now(tx).await?;
            let mut event=b"spl-account-entry-failure-v1".to_vec();
            event.extend_from_slice(&[endpoint as u8,reason as u8]);
            event.extend_from_slice(&now.to_be_bytes());
            $append(tx,&event,now).await?;
            Ok(())
        }
    };
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}

account_admission_store!(
    SqliteStore,
    Sqlite,
    sqlite_begin,
    sqlite_account_entry_now,
    sqlite_admit_bucket,
    admit_sqlite_account_entry_private_in_transaction,
    sqlite_account_entry_outcome_in_transaction,
    audit_sqlite_account_entry_failure_in_transaction,
    crate::append_deployment_audit_event_in_transaction
);
account_admission_store!(
    PostgresStore,
    Postgres,
    postgres_begin,
    postgres_account_entry_now,
    postgres_admit_bucket,
    admit_postgres_account_entry_private_in_transaction,
    postgres_account_entry_outcome_in_transaction,
    audit_postgres_account_entry_failure_in_transaction,
    crate::append_deployment_audit_event_in_postgres_transaction
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_doubles_to_cap_without_extending_rejections_or_refunding_counts() {
        let mut bucket = Bucket::fresh(1).expect("bucket");
        let mut now = 1;
        for delay in [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300] {
            assert_eq!(
                bucket.admit(now, 30).expect("admitted request"),
                AccountEntryAdmissionDecision::Admitted
            );
            bucket.outcome(now, false).expect("admitted denial");
            assert_eq!(bucket.cooldown_until_ms, Some(now + delay * 1000));
            let until = bucket.cooldown_until_ms;
            let streak = bucket.failure_streak;
            assert_eq!(
                bucket.admit(now + 1, 30).expect("bounded wait"),
                AccountEntryAdmissionDecision::RateLimited(u64::try_from(delay).expect("delay"))
            );
            bucket.outcome(now + 1, false).expect("rejection cannot extend cooldown");
            assert_eq!(bucket.cooldown_until_ms, until);
            assert_eq!(bucket.failure_streak, streak);
            now += delay * 1000;
        }
        let attempts = bucket.attempts;
        bucket.outcome(now, true).expect("success");
        assert_eq!(bucket.attempts, attempts);
        assert_eq!(bucket.failure_streak, 0);
    }

    #[test]
    fn fixed_windows_round_waits_up_and_idle_expiry_clears_failure_only() {
        let mut bucket = Bucket::fresh(1).expect("bucket");
        for _ in 0..10 {
            assert_eq!(
                bucket.admit(1, 10).expect("private request"),
                AccountEntryAdmissionDecision::Admitted
            );
        }
        assert_eq!(
            bucket.admit(59_999, 10).expect("one millisecond left"),
            AccountEntryAdmissionDecision::RateLimited(1)
        );
        assert_eq!(
            bucket.admit(60_000, 10).expect("next window"),
            AccountEntryAdmissionDecision::Admitted
        );
        bucket.outcome(60_000, false).expect("denial");
        assert_eq!(bucket.retire_at_ms, 660_000);
        assert_eq!(
            bucket.admit(660_000, 10).expect("idle"),
            AccountEntryAdmissionDecision::Admitted
        );
        assert_eq!(bucket.failure_streak, 0);
        assert_eq!(bucket.attempts, 1);
    }
}
