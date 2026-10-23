// SPDX-License-Identifier: AGPL-3.0-only
//! Durable per-route pairing admission and safe denial audit.

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;

use crate::{
    AuditStoreError, PostgresStore, RelationalStore, SqliteStore,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
};

const WINDOW_MS: i64 = 60_000;
const FAILURE_RESET_MS: i64 = 600_000;
const AUDIT_DOMAIN: &[u8] = b"spl-pairing-failure-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum PairingEndpoint {
    Create = 1,
    Claim = 2,
    Read = 3,
    Message = 4,
    Complete = 5,
    Cancel = 6,
}

impl PairingEndpoint {
    fn limit(self, kind: i64) -> i64 {
        if self == Self::Read { if kind == 2 { 60 } else { 120 } } else { 30 }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingAdmissionDecision {
    Admitted,
    RateLimited(u64),
}

/// Only verified session capabilities or current authenticated accounts may select these keys.
/// The capability value is its SHA-256 digest, never the raw bearer credential.
#[derive(Clone, Copy)]
pub enum PairingPrivateBucket {
    Capability([u8; 32]),
    Account([u8; 16]),
}

impl std::fmt::Debug for PairingPrivateBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingPrivateBucket([REDACTED])")
    }
}

impl PairingPrivateBucket {
    fn parts(self, endpoint: PairingEndpoint) -> Result<(i64, Vec<u8>), PairingAdmissionError> {
        match self {
            Self::Capability(digest)
                if matches!(
                    endpoint,
                    PairingEndpoint::Read | PairingEndpoint::Message | PairingEndpoint::Cancel
                ) =>
            {
                Ok((2, digest.to_vec()))
            }
            Self::Account(id)
                if endpoint != PairingEndpoint::Create
                    && uuid::Uuid::from_bytes(id).get_version_num() == 7 =>
            {
                Ok((3, id.to_vec()))
            }
            _ => Err(PairingAdmissionError::InvalidInput),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PairingFailureReason {
    InvalidRequest = 1,
    OriginDenied = 2,
    PairingDenied = 3,
    RateLimited = 4,
    StorageUnavailable = 5,
    Conflict = 6,
    AuthenticationDenied = 7,
}

#[derive(Debug, Error)]
pub enum PairingAdmissionError {
    #[error("pairing admission input is invalid")]
    InvalidInput,
    #[error("pairing admission storage is unavailable")]
    Database,
    #[error("pairing failure audit is unavailable")]
    Audit,
    #[error("pairing admission clock is unavailable")]
    Clock,
}

impl From<sqlx::Error> for PairingAdmissionError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}
impl From<AuditStoreError> for PairingAdmissionError {
    fn from(_: AuditStoreError) -> Self {
        Self::Audit
    }
}

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
            retain_until_ms: window_start_ms.saturating_add(WINDOW_MS),
        }
    }

    fn from_row<R: Row>(row: &R) -> Result<Self, PairingAdmissionError>
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
            || !(0..=10).contains(&bucket.failure_streak)
            || bucket.retain_until_ms <= 0
            || bucket.last_failure_ms.is_some_and(|n| n < 0)
            || bucket.cooldown_until_ms.is_some_and(|n| n < 0)
        {
            return Err(PairingAdmissionError::Database);
        }
        Ok(bucket)
    }

    fn refresh(&mut self, now: i64) {
        if now >= self.window_start_ms.saturating_add(WINDOW_MS) {
            self.window_start_ms = now.div_euclid(WINDOW_MS) * WINDOW_MS;
            self.attempts = 0;
        }
        if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= FAILURE_RESET_MS) {
            self.clear();
        }
    }

    fn wait(&self, now: i64, limit: i64) -> u64 {
        let quota =
            if self.attempts >= limit { self.window_start_ms.saturating_add(WINDOW_MS) } else { 0 };
        let until = quota.max(self.cooldown_until_ms.unwrap_or(0));
        if until <= now {
            0
        } else {
            u64::try_from((until.saturating_sub(now).saturating_add(999) / 1000).clamp(1, 300))
                .unwrap_or(300)
        }
    }

    fn admit(&mut self, now: i64, limit: i64) -> PairingAdmissionDecision {
        self.refresh(now);
        let wait = self.wait(now, limit);
        if wait > 0 {
            self.retain();
            return PairingAdmissionDecision::RateLimited(wait);
        }
        self.attempts += 1;
        self.retain();
        PairingAdmissionDecision::Admitted
    }

    fn deny(&mut self, now: i64) {
        self.refresh(now);
        // Concurrent admitted requests cannot extend a cooldown another denial already established.
        if self.cooldown_until_ms.is_some_and(|until| until > now) {
            return;
        }
        self.failure_streak = self.failure_streak.saturating_add(1).min(10);
        let seconds = (1_i64 << (self.failure_streak - 1)).min(300);
        self.last_failure_ms = Some(now);
        self.cooldown_until_ms = Some(now.saturating_add(seconds * 1000));
        self.retain();
    }

    fn clear(&mut self) {
        self.failure_streak = 0;
        self.last_failure_ms = None;
        self.cooldown_until_ms = None;
        self.retain();
    }

    fn retain(&mut self) {
        self.retain_until_ms = self
            .window_start_ms
            .saturating_add(WINDOW_MS)
            .max(self.last_failure_ms.map_or(0, |last| last.saturating_add(FAILURE_RESET_MS)))
            .max(self.cooldown_until_ms.unwrap_or(0));
    }
}

fn now_ms() -> Result<i64, PairingAdmissionError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PairingAdmissionError::Clock)?
            .as_millis(),
    )
    .map_err(|_| PairingAdmissionError::Clock)
}

fn source_key(source: IpAddr) -> Vec<u8> {
    match source {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => {
            a.to_ipv4_mapped().map_or_else(|| a.octets().to_vec(), |a| a.octets().to_vec())
        }
    }
}

fn failure_event(
    endpoint: PairingEndpoint,
    reason: PairingFailureReason,
    now: i64,
) -> Result<Vec<u8>, PairingAdmissionError> {
    let mut event = Vec::with_capacity(AUDIT_DOMAIN.len() + 10);
    event.extend_from_slice(AUDIT_DOMAIN);
    event.extend_from_slice(&[endpoint as u8, reason as u8]);
    event.extend_from_slice(
        &u64::try_from(now).map_err(|_| PairingAdmissionError::Clock)?.to_be_bytes(),
    );
    Ok(event)
}

macro_rules! pairing_admission_store {
    ($store:ty,$db:ty,$begin:ident,$lock:ident,$load:ident,$save:ident,$clear:ident,$append:ident) => {
        impl $store {
            /// Charge the actual peer before reading or parsing any request data.
            /// # Errors
            /// Fails closed when durable admission is unavailable.
            pub async fn admit_pairing_source(&self,endpoint:PairingEndpoint,source:IpAddr) -> Result<PairingAdmissionDecision,PairingAdmissionError> {
                self.admit_pairing_bucket(endpoint,source,None).await
            }

            /// Charge a verified role bucket after source admission, without refunding its count.
            /// # Errors
            /// Rejects inappropriate role/endpoint combinations and unavailable storage.
            pub async fn admit_pairing_private(&self,endpoint:PairingEndpoint,source:IpAddr,private:PairingPrivateBucket) -> Result<PairingAdmissionDecision,PairingAdmissionError> {
                self.admit_pairing_bucket(endpoint,source,Some(private)).await
            }

            /// Find the greatest applicable wait after a deployment resource-budget rejection.
            /// This does not charge another attempt or change any failure streak.
            /// # Errors
            /// Rejects invalid minimum waits or roles and unavailable storage.
            pub async fn pairing_retry_after(&self,endpoint:PairingEndpoint,source:IpAddr,private:Option<PairingPrivateBucket>,minimum:u64) -> Result<u64,PairingAdmissionError> {
                if !(1..=300).contains(&minimum) { return Err(PairingAdmissionError::InvalidInput); }
                let private = private.map(|p|p.parts(endpoint)).transpose()?;
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_ms()?;
                let mut keys = vec![(1,source_key(source))];
                keys.extend(private);
                let mut wait = minimum;
                for (kind,key) in keys {
                    let mut bucket = $load(&mut tx,endpoint,kind,&key,now).await?;
                    bucket.refresh(now);
                    wait = wait.max(bucket.wait(now,endpoint.limit(kind)));
                }
                tx.commit().await?;
                Ok(wait)
            }

            async fn admit_pairing_bucket(&self,endpoint:PairingEndpoint,source:IpAddr,private:Option<PairingPrivateBucket>) -> Result<PairingAdmissionDecision,PairingAdmissionError> {
                let (kind,key) = private.map(|p|p.parts(endpoint)).transpose()?.unwrap_or_else(|| (1,source_key(source)));
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_ms()?;
                let mut bucket = $load(&mut tx,endpoint,kind,&key,now).await?;
                let mut decision = bucket.admit(now,endpoint.limit(kind));
                $save(&mut tx,endpoint,kind,&key,&bucket).await?;
                if let PairingAdmissionDecision::RateLimited(wait) = decision {
                    if kind != 1 {
                        let mut source = $load(&mut tx,endpoint,1,&source_key(source),now).await?;
                        source.refresh(now);
                        decision = PairingAdmissionDecision::RateLimited(wait.max(source.wait(now,endpoint.limit(1))));
                    }
                }
                sqlx::query::<$db>("DELETE FROM pairing_admission WHERE (endpoint,kind,bucket_key) IN (SELECT endpoint,kind,bucket_key FROM pairing_admission WHERE retain_until_ms <= $1 ORDER BY retain_until_ms LIMIT 16)")
                    .bind(now).execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(decision)
            }

            /// Audit a safe failure; only pairing denial advances applicable cooldowns.
            /// # Errors
            /// Storage/audit errors roll back the transaction, preserving business state.
            pub async fn audit_pairing_failure(&self,endpoint:PairingEndpoint,reason:PairingFailureReason,source:IpAddr,private:Option<PairingPrivateBucket>) -> Result<(),PairingAdmissionError> {
                let private = private.map(|p|p.parts(endpoint)).transpose()?;
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_ms()?;
                if reason == PairingFailureReason::PairingDenied {
                    let mut keys = vec![(1,source_key(source))];
                    keys.extend(private);
                    for (kind,key) in keys {
                        let mut bucket = $load(&mut tx,endpoint,kind,&key,now).await?;
                        bucket.deny(now);
                        $save(&mut tx,endpoint,kind,&key,&bucket).await?;
                    }
                }
                let event = failure_event(endpoint,reason,now)?;
                $append(&mut tx,&event,now).await?;
                tx.commit().await?;
                Ok(())
            }
        }

        async fn $load(tx:&mut Transaction<'_,$db>,endpoint:PairingEndpoint,kind:i64,key:&[u8],now:i64) -> Result<Bucket,PairingAdmissionError> {
            let row = sqlx::query::<$db>("SELECT window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,retain_until_ms FROM pairing_admission WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3")
                .bind(endpoint as i64).bind(kind).bind(key).fetch_optional(&mut **tx).await?;
            row.as_ref().map(Bucket::from_row).transpose().map(|b| b.unwrap_or_else(|| Bucket::fresh(now)))
        }

        async fn $save(tx:&mut Transaction<'_,$db>,endpoint:PairingEndpoint,kind:i64,key:&[u8],b:&Bucket) -> Result<(),PairingAdmissionError> {
            sqlx::query::<$db>("INSERT INTO pairing_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,retain_until_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(endpoint,kind,bucket_key) DO UPDATE SET window_start_ms=excluded.window_start_ms,attempts=excluded.attempts,failure_streak=excluded.failure_streak,last_failure_ms=excluded.last_failure_ms,cooldown_until_ms=excluded.cooldown_until_ms,retain_until_ms=excluded.retain_until_ms")
                .bind(endpoint as i64).bind(kind).bind(key).bind(b.window_start_ms).bind(b.attempts).bind(b.failure_streak).bind(b.last_failure_ms).bind(b.cooldown_until_ms).bind(b.retain_until_ms)
                .execute(&mut **tx).await?;
            Ok(())
        }

        /// Clear an authenticated success streak inside its business transaction, before audit.
        /// Fixed-window counts remain unchanged, and rollback also rolls back the clear.
        /// # Errors
        /// Rejects an invalid role or unavailable durable admission state.
        pub async fn $clear(tx:&mut Transaction<'_,$db>,source:IpAddr,endpoint:PairingEndpoint,private:PairingPrivateBucket) -> Result<(),PairingAdmissionError> {
            let private = private.parts(endpoint)?;
            $lock(tx).await?;
            let now = now_ms()?;
            for (kind,key) in [(1,source_key(source)),private] {
                let mut bucket = $load(tx,endpoint,kind,&key,now).await?;
                bucket.clear();
                $save(tx,endpoint,kind,&key,&bucket).await?;
            }
            Ok(())
        }
    }
}

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
fn sqlite_lock(_: &mut Transaction<'_, Sqlite>) -> std::future::Ready<Result<(), sqlx::Error>> {
    std::future::ready(Ok(()))
}
async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}
async fn postgres_lock(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    // Admission never takes identity/session locks; business success clears before audit append.
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048,1346455890)").execute(&mut **tx).await?;
    Ok(())
}

pairing_admission_store!(
    SqliteStore,
    Sqlite,
    sqlite_begin,
    sqlite_lock,
    sqlite_load,
    sqlite_save,
    clear_sqlite_pairing_failure_streak,
    append_deployment_audit_event_in_transaction
);
pairing_admission_store!(
    PostgresStore,
    Postgres,
    postgres_begin,
    postgres_lock,
    postgres_load,
    postgres_save,
    clear_postgres_pairing_failure_streak,
    append_deployment_audit_event_in_postgres_transaction
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_windows_rounding_and_success_preserve_counts() {
        let mut b = Bucket::fresh(0);
        assert_eq!(b.admit(1, 30), PairingAdmissionDecision::Admitted);
        b.deny(1);
        assert_eq!(b.admit(2, 30), PairingAdmissionDecision::RateLimited(1));
        b.deny(500);
        assert_eq!(b.cooldown_until_ms, Some(1001));
        b.deny(1001);
        assert_eq!(b.admit(1002, 30), PairingAdmissionDecision::RateLimited(2));
        b.clear();
        assert_eq!(b.attempts, 1);
        b.attempts = 30;
        assert_eq!(b.admit(59_999, 30), PairingAdmissionDecision::RateLimited(1));
        assert_eq!(b.admit(60_000, 30), PairingAdmissionDecision::Admitted);
        b.deny(60_000);
        assert_eq!(b.admit(660_000, 30), PairingAdmissionDecision::Admitted);
        assert_eq!(b.failure_streak, 0);
    }

    #[test]
    fn read_limits_role_validation_and_redaction() {
        assert_eq!(PairingEndpoint::Read.limit(1), 120);
        assert_eq!(PairingEndpoint::Read.limit(2), 60);
        assert_eq!(PairingEndpoint::Read.limit(3), 120);
        assert!(
            PairingPrivateBucket::Capability([7; 32]).parts(PairingEndpoint::Complete).is_err()
        );
        assert!(PairingPrivateBucket::Account([0; 16]).parts(PairingEndpoint::Read).is_err());
        assert_eq!(
            format!("{:?}", PairingPrivateBucket::Capability([7; 32])),
            "PairingPrivateBucket([REDACTED])"
        );
        assert_eq!(
            source_key("192.0.2.1".parse().expect("v4")),
            source_key("::ffff:192.0.2.1".parse().expect("mapped"))
        );
    }

    #[test]
    fn cooldown_caps_at_five_minutes_without_extending_blocked_attempts() {
        let mut b = Bucket::fresh(0);
        let mut now = 1;
        for _ in 0..12 {
            b.deny(now);
            let until = b.cooldown_until_ms.expect("cooldown");
            assert!((1..=300).contains(&b.wait(now, 30)));
            b.deny(now + 1);
            assert_eq!(b.cooldown_until_ms, Some(until));
            now = until;
        }
        assert_eq!(b.failure_streak, 10);
        assert_eq!(b.cooldown_until_ms, b.last_failure_ms.map(|n| n + 300_000));
    }
}
