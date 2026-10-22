// SPDX-License-Identifier: AGPL-3.0-only
//! Independent durable Operator authentication admission, denial audit and `DPoP` replay claims.

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use sha2::{Digest as _, Sha256};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AuditStoreError, PostgresStore, RelationalStore, SqliteStore,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
};

const WINDOW_MS: i64 = 60_000;
const FAILURE_RESET_MS: i64 = 600_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum OperatorAuthEndpoint {
    SetupOptions = 1,
    SetupFinish = 2,
    LoginOptions = 3,
    LoginFinish = 4,
    Refresh = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAdmissionDecision {
    Admitted,
    RateLimited(u64),
}

/// Operator buckets are selected only after assertion or stored refresh-binding verification.
/// A submitted handle or operator id is never sufficient evidence for that variant.
#[derive(Clone, Copy)]
pub enum OperatorPrivateBucket<'a> {
    SetupDigest(&'a [u8; 32]),
    Ceremony(Uuid),
    AuthenticatedOperator(Uuid),
}

impl std::fmt::Debug for OperatorPrivateBucket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorPrivateBucket([REDACTED])")
    }
}

impl OperatorPrivateBucket<'_> {
    fn parts(
        self,
        endpoint: OperatorAuthEndpoint,
    ) -> Result<(i64, Vec<u8>), OperatorAdmissionError> {
        use OperatorAuthEndpoint::{LoginFinish, Refresh, SetupFinish, SetupOptions};
        match self {
            Self::SetupDigest(digest) if matches!(endpoint, SetupOptions | SetupFinish) => {
                Ok((2, digest.to_vec()))
            }
            Self::Ceremony(id) if endpoint == LoginFinish && id.get_version_num() == 7 => {
                Ok((3, id.as_bytes().to_vec()))
            }
            Self::AuthenticatedOperator(id)
                if matches!(endpoint, LoginFinish | Refresh) && id.get_version_num() == 7 =>
            {
                Ok((4, id.as_bytes().to_vec()))
            }
            _ => Err(OperatorAdmissionError::InvalidInput),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperatorAuthFailureReason {
    InvalidRequest = 1,
    OriginDenied = 2,
    InvalidDpopProof = 3,
    AuthenticationDenied = 4,
    RateLimited = 5,
    StorageUnavailable = 6,
}

#[derive(Debug, Error)]
pub enum OperatorAdmissionError {
    #[error("operator authentication admission input is invalid")]
    InvalidInput,
    #[error("operator authentication proof is invalid or replayed")]
    InvalidDpopProof,
    #[error("operator authentication admission storage is unavailable")]
    Database,
    #[error("operator authentication audit is unavailable")]
    Audit,
    #[error("operator authentication admission clock is unavailable")]
    Clock,
}

impl From<sqlx::Error> for OperatorAdmissionError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}
impl From<AuditStoreError> for OperatorAdmissionError {
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
            retain_until_ms: window_start_ms + WINDOW_MS,
        }
    }

    fn from_row<R: Row>(row: &R) -> Result<Self, OperatorAdmissionError>
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
        {
            return Err(OperatorAdmissionError::Database);
        }
        Ok(bucket)
    }

    fn reset_idle(&mut self, now: i64) {
        if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= FAILURE_RESET_MS) {
            self.clear();
        }
    }

    fn admit(&mut self, now: i64, limit: i64) -> OperatorAdmissionDecision {
        if now >= self.window_start_ms.saturating_add(WINDOW_MS) {
            self.window_start_ms = now.div_euclid(WINDOW_MS) * WINDOW_MS;
            self.attempts = 0;
        }
        self.reset_idle(now);
        let quota_until = if self.attempts >= limit { self.window_start_ms + WINDOW_MS } else { 0 };
        let blocked_until = quota_until.max(self.cooldown_until_ms.unwrap_or(0));
        if blocked_until > now {
            self.retain();
            return OperatorAdmissionDecision::RateLimited(
                u64::try_from(((blocked_until - now).saturating_add(999) / 1000).clamp(1, 300))
                    .unwrap_or(300),
            );
        }
        self.attempts += 1;
        self.retain();
        OperatorAdmissionDecision::Admitted
    }

    fn deny(&mut self, now: i64) {
        self.reset_idle(now);
        // A request that was admitted before another request established this cooldown does
        // not extend it after waiting for a database lock.
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

fn now_ms() -> Result<i64, OperatorAdmissionError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OperatorAdmissionError::Clock)?
            .as_millis(),
    )
    .map_err(|_| OperatorAdmissionError::Clock)
}

fn source_key(source: IpAddr) -> Vec<u8> {
    match source {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => {
            a.to_ipv4_mapped().map_or_else(|| a.octets().to_vec(), |a| a.octets().to_vec())
        }
    }
}

macro_rules! admission_store {
    ($store:ty, $db:ty, $begin:ident, $lock:ident, $load:ident, $save:ident, $outcome:ident, $append:ident) => {
        impl $store {
            /// Admit the actual peer before allocating or parsing the body.
            /// # Errors
            /// Fails closed on unavailable admission state.
            pub async fn admit_operator_auth_source(&self, endpoint: OperatorAuthEndpoint, source: IpAddr) -> Result<OperatorAdmissionDecision, OperatorAdmissionError> {
                self.admit_operator_bucket(endpoint, 1, &source_key(source)).await
            }

            /// Charge a structurally decoded private key without an existence lookup.
            /// # Errors
            /// Rejects a bucket that does not belong to this endpoint, or unavailable storage.
            pub async fn admit_operator_auth_private(&self, endpoint: OperatorAuthEndpoint, bucket: OperatorPrivateBucket<'_>) -> Result<OperatorAdmissionDecision, OperatorAdmissionError> {
                let (kind,key) = bucket.parts(endpoint)?;
                self.admit_operator_bucket(endpoint,kind,&key).await
            }

            async fn admit_operator_bucket(&self, endpoint: OperatorAuthEndpoint, kind: i64, key: &[u8]) -> Result<OperatorAdmissionDecision, OperatorAdmissionError> {
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_ms()?;
                let mut bucket = $load(&mut tx, endpoint, kind, key, now).await?;
                let limit = match kind { 1 => 30, 4 => 10, _ => 5 };
                let decision = bucket.admit(now,limit);
                $save(&mut tx,endpoint,kind,key,&bucket).await?;
                sqlx::query::<$db>("DELETE FROM operator_auth_admission WHERE (endpoint, kind, bucket_key) IN (SELECT endpoint, kind, bucket_key FROM operator_auth_admission WHERE retain_until_ms <= $1 ORDER BY retain_until_ms LIMIT 16)").bind(now).execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(decision)
            }

            /// Audit a failure that consumed no ceremony or family. Consuming business paths
            /// record their audit and cooldown inside their own transaction instead.
            /// # Errors
            /// Any audit or admission failure rolls back the entire failure transaction.
            pub async fn audit_operator_auth_failure(&self, endpoint: OperatorAuthEndpoint, reason: OperatorAuthFailureReason, source: IpAddr, private: Option<OperatorPrivateBucket<'_>>) -> Result<(), OperatorAdmissionError> {
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_ms()?;
                if reason == OperatorAuthFailureReason::AuthenticationDenied {
                    $outcome(&mut tx,endpoint,source,private,false).await?;
                } else if let Some(private) = private { private.parts(endpoint)?; }
                let mut event = b"spl-operator-auth-failure-v1".to_vec();
                event.extend_from_slice(&[endpoint as u8, reason as u8]);
                event.extend_from_slice(&now.to_be_bytes());
                $append(&mut tx,&event,now).await?;
                tx.commit().await?;
                Ok(())
            }

            /// Reverify and durably claim an Operator proof across replicas before use.
            /// # Errors
            /// Invalid, expired or replayed proofs fail before any business mutation.
            pub async fn claim_operator_dpop_proof(&self, proof: &DpopProof, target: &DpopTarget, token: DpopToken<'_>, expected_jkt: &str) -> Result<(), OperatorAdmissionError> {
                let mut tx = $begin(self).await?;
                $lock(&mut tx).await?;
                let now = now_ms()?;
                let verified = proof.verify(target, token, expected_jkt, u64::try_from(now/1000).map_err(|_| OperatorAdmissionError::Clock)?, None).map_err(|_| OperatorAdmissionError::InvalidDpopProof)?;
                let until = i64::try_from(verified.last_accepted_at).ok().and_then(|n| n.checked_add(1)).and_then(|n| n.checked_mul(1000)).ok_or(OperatorAdmissionError::Clock)?;
                let digest: [u8;32] = Sha256::digest(verified.jti.as_bytes()).into();
                sqlx::query::<$db>("DELETE FROM operator_dpop_replays WHERE (dpop_jkt, jti_digest) IN (SELECT dpop_jkt, jti_digest FROM operator_dpop_replays WHERE retain_until_ms <= $1 ORDER BY retain_until_ms LIMIT 16)").bind(now).execute(&mut *tx).await?;
                let result = sqlx::query::<$db>("INSERT INTO operator_dpop_replays (dpop_jkt, jti_digest, retain_until_ms) VALUES ($1,$2,$3)").bind(verified.jkt).bind(digest.as_slice()).bind(until).execute(&mut *tx).await;
                match result {
                    Ok(_) => (),
                    Err(sqlx::Error::Database(e)) if e.is_unique_violation() => return Err(OperatorAdmissionError::InvalidDpopProof),
                    Err(_) => return Err(OperatorAdmissionError::Database),
                }
                tx.commit().await?;
                Ok(())
            }
        }

        async fn $load(tx: &mut sqlx::Transaction<'_,$db>, endpoint: OperatorAuthEndpoint, kind: i64, key: &[u8], now: i64) -> Result<Bucket,OperatorAdmissionError> {
            let row = sqlx::query::<$db>("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM operator_auth_admission WHERE endpoint=$1 AND kind=$2 AND bucket_key=$3").bind(endpoint as i64).bind(kind).bind(key).fetch_optional(&mut **tx).await?;
            row.as_ref().map(Bucket::from_row).transpose().map(|b| b.unwrap_or_else(|| Bucket::fresh(now)))
        }

        async fn $save(tx: &mut sqlx::Transaction<'_,$db>, endpoint: OperatorAuthEndpoint, kind: i64, key: &[u8], bucket: &Bucket) -> Result<(),OperatorAdmissionError> {
            sqlx::query::<$db>("INSERT INTO operator_auth_admission (endpoint, kind, bucket_key, window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (endpoint, kind, bucket_key) DO UPDATE SET window_start_ms=excluded.window_start_ms, attempts=excluded.attempts, failure_streak=excluded.failure_streak, last_failure_ms=excluded.last_failure_ms, cooldown_until_ms=excluded.cooldown_until_ms, retain_until_ms=excluded.retain_until_ms")
                .bind(endpoint as i64).bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms).execute(&mut **tx).await?;
            Ok(())
        }

        pub(crate) async fn $outcome(tx: &mut sqlx::Transaction<'_,$db>, endpoint: OperatorAuthEndpoint, source: IpAddr, private: Option<OperatorPrivateBucket<'_>>, success: bool) -> Result<(),OperatorAdmissionError> {
            $lock(tx).await?;
            let now = now_ms()?;
            let mut keys = vec![(1,source_key(source))];
            if let Some(private) = private { keys.push(private.parts(endpoint)?); }
            for (kind,key) in keys {
                let mut bucket = $load(tx,endpoint,kind,&key,now).await?;
                if success { bucket.clear(); } else { bucket.deny(now); }
                $save(tx,endpoint,kind,&key,&bucket).await?;
            }
            Ok(())
        }
    }
}

async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}
pub(crate) fn sqlite_lock(
    _: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> std::future::Ready<Result<(), sqlx::Error>> {
    std::future::ready(Ok(()))
}
async fn postgres_begin(
    store: &PostgresStore,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    store.pool().begin().await
}
pub(crate) async fn postgres_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    // Admission precedes deployment-audit locking, and never acquires a business-state lock.
    sqlx::query("SELECT pg_advisory_xact_lock(1396916048, 1094995277)").execute(&mut **tx).await?;
    Ok(())
}

admission_store!(
    SqliteStore,
    sqlx::Sqlite,
    sqlite_begin,
    sqlite_lock,
    sqlite_load,
    sqlite_save,
    sqlite_outcome,
    append_deployment_audit_event_in_transaction
);
admission_store!(
    PostgresStore,
    sqlx::Postgres,
    postgres_begin,
    postgres_lock,
    postgres_load,
    postgres_save,
    postgres_outcome,
    append_deployment_audit_event_in_postgres_transaction
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cooldown_rounding_idle_reset_and_quota_preservation() {
        let mut b = Bucket::fresh(0);
        assert_eq!(b.admit(1, 5), OperatorAdmissionDecision::Admitted);
        b.deny(1);
        assert_eq!(b.admit(2, 5), OperatorAdmissionDecision::RateLimited(1));
        b.deny(500);
        assert_eq!(b.cooldown_until_ms, Some(1001));
        b.deny(1001);
        assert_eq!(b.cooldown_until_ms, Some(3001));
        assert_eq!(b.admit(1002, 5), OperatorAdmissionDecision::RateLimited(2));
        b.clear();
        assert_eq!(b.attempts, 1);
        b.attempts = 5;
        assert_eq!(b.admit(59_999, 5), OperatorAdmissionDecision::RateLimited(1));
        assert_eq!(b.admit(60_000, 5), OperatorAdmissionDecision::Admitted);
        b.deny(60_000);
        assert_eq!(b.admit(660_000, 5), OperatorAdmissionDecision::Admitted);
        assert_eq!(b.failure_streak, 0);
    }

    #[test]
    fn longest_wait_and_cooldown_cap_are_enforced() {
        let mut b = Bucket::fresh(0);
        b.attempts = 30;
        b.deny(1);
        assert_eq!(b.admit(2, 30), OperatorAdmissionDecision::RateLimited(60));
        for now in (1001..=1_001_001).step_by(100_000) {
            b.cooldown_until_ms = Some(0);
            b.deny(now);
        }
        assert_eq!(b.failure_streak, 10);
        assert_eq!(b.cooldown_until_ms, b.last_failure_ms.map(|n| n + 300_000));
        assert_eq!(b.retain_until_ms, b.last_failure_ms.expect("failure") + 600_000);
    }
}
