// SPDX-License-Identifier: AGPL-3.0-only
//! Durable admission and failure audit for anonymous Personal enrollment.

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
const SOURCE_LIMIT: i64 = 30;
const DIGEST_LIMIT: i64 = 5;
const CLEANUP_BATCH: i64 = 16;
const AUDIT_DOMAIN: &[u8] = b"spl-personal-invitation-audit-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalAdmissionDecision {
    Admitted,
    RateLimited(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersonalEnrollmentFailureReason {
    InvalidRequest = 1,
    OriginDenied = 2,
    EnrollmentDenied = 3,
    RateLimited = 4,
    StorageUnavailable = 5,
}

#[derive(Debug, Error)]
pub enum PersonalAdmissionError {
    #[error("Personal enrollment admission storage failed")]
    Database,
    #[error("Personal enrollment failure audit failed")]
    Audit,
    #[error("system clock cannot represent Personal enrollment admission")]
    Clock,
    #[error("Personal enrollment admission state is invalid")]
    InvalidState,
}

impl From<sqlx::Error> for PersonalAdmissionError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

impl From<AuditStoreError> for PersonalAdmissionError {
    fn from(_: AuditStoreError) -> Self {
        Self::Audit
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

    fn from_row<R: Row>(row: &R) -> Result<Self, PersonalAdmissionError>
    where
        for<'a> &'a str: sqlx::ColumnIndex<R>,
        i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
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
            return Err(PersonalAdmissionError::InvalidState);
        }
        Ok(bucket)
    }

    fn admit(&mut self, now: i64, limit: i64) -> PersonalAdmissionDecision {
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
            self.refresh_retention();
            return PersonalAdmissionDecision::RateLimited(retry_seconds(blocked_until - now));
        }
        self.attempts += 1;
        self.refresh_retention();
        PersonalAdmissionDecision::Admitted
    }

    fn deny(&mut self, now: i64) {
        if self.last_failure_ms.is_some_and(|last| now.saturating_sub(last) >= FAILURE_RESET_MS) {
            self.failure_streak = 0;
        }
        self.failure_streak = self.failure_streak.saturating_add(1).min(10);
        let seconds = (1_i64 << (self.failure_streak - 1)).min(300);
        self.last_failure_ms = Some(now);
        self.cooldown_until_ms = Some(now.saturating_add(seconds * 1_000));
        self.refresh_retention();
    }

    fn clear_failure(&mut self) {
        self.failure_streak = 0;
        self.last_failure_ms = None;
        self.cooldown_until_ms = None;
        self.refresh_retention();
    }

    fn refresh_retention(&mut self) {
        self.retain_until_ms = (self.window_start_ms + WINDOW_MS)
            .max(self.last_failure_ms.map_or(0, |last| last.saturating_add(FAILURE_RESET_MS)))
            .max(self.cooldown_until_ms.unwrap_or(0));
    }
}

fn retry_seconds(remaining_ms: i64) -> u64 {
    u64::try_from((remaining_ms.saturating_add(999) / 1_000).clamp(1, 300)).unwrap_or(300)
}

fn now_ms() -> Result<i64, PersonalAdmissionError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PersonalAdmissionError::Clock)?
        .as_millis();
    i64::try_from(millis).map_err(|_| PersonalAdmissionError::Clock)
}

fn source_key(source: IpAddr) -> Vec<u8> {
    match source {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or_else(|| address.octets().to_vec(), |mapped| mapped.octets().to_vec()),
    }
}

fn failure_event(
    reason: PersonalEnrollmentFailureReason,
    now: i64,
) -> Result<Vec<u8>, PersonalAdmissionError> {
    let now = u64::try_from(now).map_err(|_| PersonalAdmissionError::Clock)?;
    let mut event = Vec::with_capacity(AUDIT_DOMAIN.len() + 11);
    event.extend_from_slice(AUDIT_DOMAIN);
    event.extend_from_slice(&[3, 0, reason as u8]);
    event.extend_from_slice(&now.to_be_bytes());
    Ok(event)
}

impl SqliteStore {
    /// Admit one anonymous enrollment source before reading its body.
    ///
    /// # Errors
    /// Returns an error when durable admission cannot be checked.
    pub async fn admit_personal_enrollment_source(
        &self,
        source: IpAddr,
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        admit_sqlite(self, 1, &source_key(source), SOURCE_LIMIT).await
    }

    /// Admit a decoded invitation digest without looking up invitation existence.
    ///
    /// # Errors
    /// Returns an error when durable admission cannot be checked.
    pub async fn admit_personal_enrollment_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        admit_sqlite(self, 2, digest, DIGEST_LIMIT).await
    }

    /// Append a safe failure event; on an admitted denial, advance both cooldowns atomically.
    ///
    /// # Errors
    /// Failures before commit roll back cooldown and audit changes. A lost commit acknowledgement
    /// can leave their outcome unknown; identity and invitation state are not changed here.
    pub async fn audit_personal_enrollment_failure(
        &self,
        reason: PersonalEnrollmentFailureReason,
        source: IpAddr,
        denied_digest: Option<&[u8; 32]>,
    ) -> Result<(), PersonalAdmissionError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let now = now_ms()?;
        if let Some(digest) = denied_digest {
            deny_sqlite(&mut transaction, 1, &source_key(source), now).await?;
            deny_sqlite(&mut transaction, 2, digest, now).await?;
        }
        let event = failure_event(reason, now)?;
        append_deployment_audit_event_in_transaction(&mut transaction, &event, now).await?;
        transaction.commit().await?;
        Ok(())
    }
}

impl PostgresStore {
    /// Admit one anonymous enrollment source before reading its body.
    ///
    /// # Errors
    /// Returns an error when durable admission cannot be checked.
    pub async fn admit_personal_enrollment_source(
        &self,
        source: IpAddr,
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        admit_postgres(self, 1, &source_key(source), SOURCE_LIMIT).await
    }

    /// Admit a decoded invitation digest without looking up invitation existence.
    ///
    /// # Errors
    /// Returns an error when durable admission cannot be checked.
    pub async fn admit_personal_enrollment_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
        admit_postgres(self, 2, digest, DIGEST_LIMIT).await
    }

    /// Append a safe failure event; on an admitted denial, advance both cooldowns atomically.
    ///
    /// # Errors
    /// Failures before commit roll back cooldown and audit changes. A lost commit acknowledgement
    /// can leave their outcome unknown; identity and invitation state are not changed here.
    pub async fn audit_personal_enrollment_failure(
        &self,
        reason: PersonalEnrollmentFailureReason,
        source: IpAddr,
        denied_digest: Option<&[u8; 32]>,
    ) -> Result<(), PersonalAdmissionError> {
        let mut transaction = self.pool().begin().await?;
        let source_key = source_key(source);
        let buckets = if let Some(digest) = denied_digest {
            Some((
                load_for_deny_postgres(&mut transaction, 1, &source_key).await?,
                load_for_deny_postgres(&mut transaction, 2, digest).await?,
            ))
        } else {
            None
        };
        let now = now_ms()?;
        if let (Some(digest), Some((mut source_bucket, mut digest_bucket))) =
            (denied_digest, buckets)
        {
            source_bucket.deny(now);
            digest_bucket.deny(now);
            update_postgres(&mut transaction, 1, &source_key, &source_bucket).await?;
            update_postgres(&mut transaction, 2, digest, &digest_bucket).await?;
        }
        let event = failure_event(reason, now)?;
        append_deployment_audit_event_in_postgres_transaction(&mut transaction, &event, now)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn admit_sqlite(
    store: &SqliteStore,
    kind: i64,
    key: &[u8],
    limit: i64,
) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
    let mut transaction = store.pool().begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms()?;
    cleanup_sqlite(&mut transaction, now).await?;
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM personal_admission WHERE kind = ? AND bucket_key = ?")
        .bind(kind).bind(key).fetch_optional(&mut *transaction).await?;
    let mut bucket =
        row.as_ref().map(Bucket::from_row).transpose()?.unwrap_or_else(|| Bucket::fresh(now));
    let decision = bucket.admit(now, limit);
    sqlx::query("INSERT INTO personal_admission (kind, bucket_key, window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (kind, bucket_key) DO UPDATE SET window_start_ms=excluded.window_start_ms, attempts=excluded.attempts, failure_streak=excluded.failure_streak, last_failure_ms=excluded.last_failure_ms, cooldown_until_ms=excluded.cooldown_until_ms, retain_until_ms=excluded.retain_until_ms")
        .bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms)
        .execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(decision)
}

async fn admit_postgres(
    store: &PostgresStore,
    kind: i64,
    key: &[u8],
    limit: i64,
) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
    let mut transaction = store.pool().begin().await?;
    let now = now_ms()?;
    let fresh = Bucket::fresh(now);
    let row = sqlx::query("INSERT INTO personal_admission (kind, bucket_key, window_start_ms, attempts, failure_streak, retain_until_ms) VALUES ($1, $2, $3, 0, 0, $4) ON CONFLICT (kind, bucket_key) DO UPDATE SET bucket_key = excluded.bucket_key RETURNING window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms")
        .bind(kind).bind(key).bind(fresh.window_start_ms).bind(fresh.retain_until_ms)
        .fetch_one(&mut *transaction).await?;
    let mut bucket = Bucket::from_row(&row)?;
    let decision = bucket.admit(now_ms()?, limit);
    sqlx::query("UPDATE personal_admission SET window_start_ms=$3, attempts=$4, failure_streak=$5, last_failure_ms=$6, cooldown_until_ms=$7, retain_until_ms=$8 WHERE kind=$1 AND bucket_key=$2")
        .bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms)
        .execute(&mut *transaction).await?;
    cleanup_postgres(&mut transaction, now_ms()?).await?;
    transaction.commit().await?;
    Ok(decision)
}

async fn cleanup_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    now: i64,
) -> Result<(), PersonalAdmissionError> {
    sqlx::query("DELETE FROM personal_admission WHERE (kind, bucket_key) IN (SELECT kind, bucket_key FROM personal_admission WHERE retain_until_ms <= ? ORDER BY retain_until_ms LIMIT ?)")
        .bind(now).bind(CLEANUP_BATCH).execute(&mut **transaction).await?;
    Ok(())
}

async fn cleanup_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    now: i64,
) -> Result<(), PersonalAdmissionError> {
    sqlx::query("DELETE FROM personal_admission WHERE (kind, bucket_key) IN (SELECT kind, bucket_key FROM personal_admission WHERE retain_until_ms <= $1 ORDER BY retain_until_ms LIMIT $2 FOR UPDATE SKIP LOCKED)")
        .bind(now).bind(CLEANUP_BATCH).execute(&mut **transaction).await?;
    Ok(())
}

async fn deny_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    kind: i64,
    key: &[u8],
    now: i64,
) -> Result<(), PersonalAdmissionError> {
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM personal_admission WHERE kind=? AND bucket_key=?")
        .bind(kind).bind(key).fetch_optional(&mut **transaction).await?;
    let mut bucket =
        row.as_ref().map(Bucket::from_row).transpose()?.unwrap_or_else(|| Bucket::fresh(now));
    bucket.deny(now);
    sqlx::query("INSERT INTO personal_admission (kind, bucket_key, window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (kind, bucket_key) DO UPDATE SET window_start_ms=excluded.window_start_ms, attempts=excluded.attempts, failure_streak=excluded.failure_streak, last_failure_ms=excluded.last_failure_ms, cooldown_until_ms=excluded.cooldown_until_ms, retain_until_ms=excluded.retain_until_ms")
        .bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms)
        .execute(&mut **transaction).await?;
    Ok(())
}

async fn load_for_deny_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    kind: i64,
    key: &[u8],
) -> Result<Bucket, PersonalAdmissionError> {
    let now = now_ms()?;
    let fresh = Bucket::fresh(now);
    let row = sqlx::query("INSERT INTO personal_admission (kind, bucket_key, window_start_ms, attempts, failure_streak, retain_until_ms) VALUES ($1, $2, $3, 0, 0, $4) ON CONFLICT (kind, bucket_key) DO UPDATE SET bucket_key = excluded.bucket_key RETURNING window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms")
        .bind(kind).bind(key).bind(fresh.window_start_ms).bind(fresh.retain_until_ms)
        .fetch_one(&mut **transaction).await?;
    Bucket::from_row(&row)
}

async fn update_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    kind: i64,
    key: &[u8],
    bucket: &Bucket,
) -> Result<(), PersonalAdmissionError> {
    sqlx::query("UPDATE personal_admission SET window_start_ms=?, attempts=?, failure_streak=?, last_failure_ms=?, cooldown_until_ms=?, retain_until_ms=? WHERE kind=? AND bucket_key=?")
        .bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms).bind(kind).bind(key)
        .execute(&mut **transaction).await?;
    Ok(())
}

async fn update_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    kind: i64,
    key: &[u8],
    bucket: &Bucket,
) -> Result<(), PersonalAdmissionError> {
    sqlx::query("UPDATE personal_admission SET window_start_ms=$3, attempts=$4, failure_streak=$5, last_failure_ms=$6, cooldown_until_ms=$7, retain_until_ms=$8 WHERE kind=$1 AND bucket_key=$2")
        .bind(kind).bind(key).bind(bucket.window_start_ms).bind(bucket.attempts).bind(bucket.failure_streak).bind(bucket.last_failure_ms).bind(bucket.cooldown_until_ms).bind(bucket.retain_until_ms)
        .execute(&mut **transaction).await?;
    Ok(())
}

pub(crate) async fn clear_sqlite_failure_streak(
    transaction: &mut Transaction<'_, Sqlite>,
    source: IpAddr,
    digest: &[u8; 32],
) -> Result<(), PersonalAdmissionError> {
    clear_sqlite(transaction, 1, &source_key(source)).await?;
    clear_sqlite(transaction, 2, digest).await
}

pub(crate) async fn clear_postgres_failure_streak(
    transaction: &mut Transaction<'_, Postgres>,
    source: IpAddr,
    digest: &[u8; 32],
) -> Result<(), PersonalAdmissionError> {
    clear_postgres(transaction, 1, &source_key(source)).await?;
    clear_postgres(transaction, 2, digest).await
}

async fn clear_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    kind: i64,
    key: &[u8],
) -> Result<(), PersonalAdmissionError> {
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM personal_admission WHERE kind=? AND bucket_key=?")
        .bind(kind).bind(key).fetch_optional(&mut **transaction).await?;
    if let Some(row) = row {
        let mut bucket = Bucket::from_row(&row)?;
        bucket.clear_failure();
        update_sqlite(transaction, kind, key, &bucket).await?;
    }
    Ok(())
}

async fn clear_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    kind: i64,
    key: &[u8],
) -> Result<(), PersonalAdmissionError> {
    let row = sqlx::query("SELECT window_start_ms, attempts, failure_streak, last_failure_ms, cooldown_until_ms, retain_until_ms FROM personal_admission WHERE kind=$1 AND bucket_key=$2 FOR UPDATE")
        .bind(kind).bind(key).fetch_optional(&mut **transaction).await?;
    if let Some(row) = row {
        let mut bucket = Bucket::from_row(&row)?;
        bucket.clear_failure();
        update_postgres(transaction, kind, key, &bucket).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_and_cooldown_do_not_extend_on_rejected_attempts() {
        let mut source = Bucket::fresh(120_000);
        for _ in 0..30 {
            assert_eq!(source.admit(120_000, SOURCE_LIMIT), PersonalAdmissionDecision::Admitted);
        }
        assert_eq!(source.admit(120_001, SOURCE_LIMIT), PersonalAdmissionDecision::RateLimited(60));
        assert_eq!(source.admit(180_000, SOURCE_LIMIT), PersonalAdmissionDecision::Admitted);
        source.deny(180_000);
        assert_eq!(source.admit(180_100, SOURCE_LIMIT), PersonalAdmissionDecision::RateLimited(1));
        assert_eq!(source.admit(181_000, SOURCE_LIMIT), PersonalAdmissionDecision::Admitted);
        source.deny(181_000);
        assert_eq!(source.admit(181_001, SOURCE_LIMIT), PersonalAdmissionDecision::RateLimited(2));
        assert_eq!(source.cooldown_until_ms, Some(183_000));
    }

    #[test]
    fn mapped_ipv6_uses_the_same_source_bucket() {
        let v4: IpAddr = "192.0.2.42".parse().expect("IPv4");
        let mapped: IpAddr = "::ffff:192.0.2.42".parse().expect("mapped IPv6");
        assert_eq!(source_key(v4), source_key(mapped));
    }
}
