// SPDX-License-Identifier: AGPL-3.0-only
//! Durable worker jobs with database-backed leases.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{Row, postgres::PgRow};
use thiserror::Error;

use crate::{PostgresStore, RelationalStore, SqliteStore};

/// Maximum UTF-8 byte length for a job kind.
pub const MAX_JOB_KIND_BYTES: usize = 128;
/// Maximum UTF-8 byte length for a worker lease owner.
pub const MAX_JOB_OWNER_BYTES: usize = 128;
/// Maximum payload size retained in the relational queue.
pub const MAX_JOB_PAYLOAD_BYTES: usize = 1_048_576;
/// Maximum retained failure detail length.
pub const MAX_JOB_ERROR_BYTES: usize = 4_096;
/// Maximum lease duration accepted by the queue.
pub const MAX_JOB_LEASE_MS: i64 = 24 * 60 * 60 * 1_000;

/// Opaque identifier for one queued job.
pub type JobId = [u8; 16];

/// A queued job and its current lease state.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Job {
    /// Stable job identifier.
    pub id: JobId,
    /// Handler key selected by the worker.
    pub kind: String,
    /// Opaque handler payload.
    pub payload: Vec<u8>,
    /// Earliest time at which the job may be claimed.
    pub available_at_ms: i64,
    /// Number of claims, including the current lease when present.
    pub attempts: u64,
    /// Current owner, if the job is leased.
    pub lease_owner: Option<String>,
    /// Lease expiry in Unix milliseconds, if leased.
    pub lease_until_ms: Option<i64>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: i64,
    /// Completion time in Unix milliseconds, if completed.
    pub finished_at_ms: Option<i64>,
    /// Most recent failure detail, if any.
    pub last_error: Option<String>,
}

impl SqliteStore {
    /// Enqueue a job for immediate or future processing.
    ///
    /// The job id is idempotent only at the database boundary: reusing an existing id returns a
    /// constraint error rather than replacing a job. Callers should generate the id before any
    /// external side effect and retry the same enqueue on transient database failures.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid fields or a database constraint error for a reused
    /// id.
    pub async fn enqueue_job(
        &self,
        id: JobId,
        kind: &str,
        payload: &[u8],
        available_at_ms: i64,
    ) -> Result<(), JobQueueError> {
        validate_kind(kind)?;
        validate_payload(payload)?;
        validate_timestamp(available_at_ms)?;
        let created_at_ms = now_ms()?;
        sqlx::query(
            "INSERT INTO jobs (id, kind, payload, available_at_ms, created_at_ms) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.as_slice())
        .bind(kind)
        .bind(payload)
        .bind(available_at_ms)
        .bind(created_at_ms)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(map_write_error)
    }

    /// Enqueue a job unless an unfinished job with the same kind and payload already exists.
    ///
    /// The check and insert share the SQLite write transaction so concurrent worker heartbeats do
    /// not schedule duplicate work for one resource.
    ///
    /// # Errors
    ///
    /// Returns a validation, constraint, or database error when the job cannot be scheduled.
    pub async fn enqueue_job_if_absent(
        &self,
        id: JobId,
        kind: &str,
        payload: &[u8],
        available_at_ms: i64,
    ) -> Result<bool, JobQueueError> {
        validate_kind(kind)?;
        validate_payload(payload)?;
        validate_timestamp(available_at_ms)?;
        let created_at_ms = now_ms()?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM jobs WHERE kind = ? AND payload = ? AND finished_at_ms IS NULL LIMIT 1",
        )
        .bind(kind)
        .bind(payload)
        .fetch_optional(&mut *transaction)
        .await?;
        if existing.is_some() {
            transaction.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO jobs (id, kind, payload, available_at_ms, created_at_ms) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.as_slice())
        .bind(kind)
        .bind(payload)
        .bind(available_at_ms)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_write_error)?;
        transaction.commit().await?;
        Ok(true)
    }

    /// Claim the oldest eligible job under an atomic SQLite write transaction.
    ///
    /// Expired leases are immediately eligible for another worker. A claim increments `attempts`
    /// and sets a bounded lease owned by `owner`; no job is returned when the queue is empty.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid lease parameters or a database error when the claim
    /// cannot be committed.
    pub async fn claim_job(
        &self,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        self.claim_job_filtered(None, owner, now_ms, now_ms, lease_ms).await
    }

    /// Claim the oldest eligible job of one kind under an atomic SQLite write transaction.
    ///
    /// # Errors
    ///
    /// Returns a validation or database error when the claim cannot be committed.
    pub async fn claim_job_kind(
        &self,
        kind: &str,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        self.claim_job_kind_available_through(kind, owner, now_ms, now_ms, lease_ms).await
    }

    /// Claim one kind with a fixed availability cutoff and an independently current lease clock.
    ///
    /// Jobs deferred beyond `available_through_ms` remain for a later sweep even when `now_ms`
    /// advances. Lease expiry and the new lease are evaluated at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns a validation or database error when the claim cannot be committed.
    pub async fn claim_job_kind_available_through(
        &self,
        kind: &str,
        owner: &str,
        available_through_ms: i64,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        validate_kind(kind)?;
        self.claim_job_filtered(Some(kind), owner, available_through_ms, now_ms, lease_ms).await
    }

    async fn claim_job_filtered(
        &self,
        kind: Option<&str>,
        owner: &str,
        available_through_ms: i64,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(available_through_ms)?;
        validate_timestamp(now_ms)?;
        validate_lease(lease_ms)?;
        let lease_until_ms =
            now_ms.checked_add(lease_ms).ok_or(JobQueueError::TimestampOverflow)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let query = if kind.is_some() {
            "SELECT id, kind, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error
             FROM jobs WHERE finished_at_ms IS NULL AND available_at_ms <= ?
               AND (lease_until_ms IS NULL OR lease_until_ms <= ?) AND kind = ?
             ORDER BY available_at_ms ASC, created_at_ms ASC, id ASC LIMIT 1"
        } else {
            "SELECT id, kind, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error
             FROM jobs WHERE finished_at_ms IS NULL AND available_at_ms <= ?
               AND (lease_until_ms IS NULL OR lease_until_ms <= ?)
             ORDER BY available_at_ms ASC, created_at_ms ASC, id ASC LIMIT 1"
        };
        let mut query = sqlx::query(query).bind(available_through_ms).bind(now_ms);
        if let Some(kind) = kind {
            query = query.bind(kind);
        }
        let row = query.fetch_optional(&mut *transaction).await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let id: Vec<u8> = row.try_get("id")?;
        let id = id_from_bytes(&id)?;
        let attempts: i64 = row.try_get("attempts")?;
        let attempts = attempts.checked_add(1).ok_or(JobQueueError::AttemptsOverflow)?;
        sqlx::query(
            "UPDATE jobs SET attempts = ?, lease_owner = ?, lease_until_ms = ? WHERE id = ? AND finished_at_ms IS NULL",
        )
        .bind(attempts)
        .bind(owner)
        .bind(lease_until_ms)
        .bind(id.as_slice())
        .execute(&mut *transaction)
        .await?;
        let mut job = job_from_row(&row)?;
        job.id = id;
        job.attempts =
            u64::try_from(attempts).map_err(|_| JobQueueError::CorruptRow("attempts"))?;
        job.lease_owner = Some(owner.to_owned());
        job.lease_until_ms = Some(lease_until_ms);
        transaction.commit().await?;
        Ok(Some(job))
    }

    /// Extend a live lease owned by `owner`.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::LeaseLost`] if another worker owns the job or its lease expired.
    pub async fn renew_job(
        &self,
        id: JobId,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<(), JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(now_ms)?;
        validate_lease(lease_ms)?;
        let lease_until_ms =
            now_ms.checked_add(lease_ms).ok_or(JobQueueError::TimestampOverflow)?;
        let result = sqlx::query(
            "UPDATE jobs SET lease_until_ms = ?
             WHERE id = ? AND lease_owner = ? AND finished_at_ms IS NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms > ?",
        )
        .bind(lease_until_ms)
        .bind(id.as_slice())
        .bind(owner)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 1 { Ok(()) } else { Err(JobQueueError::LeaseLost) }
    }

    /// Mark a live leased job complete.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::LeaseLost`] if the lease is no longer owned by `owner`.
    pub async fn complete_job(
        &self,
        id: JobId,
        owner: &str,
        now_ms: i64,
    ) -> Result<(), JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(now_ms)?;
        let result = sqlx::query(
            "UPDATE jobs SET finished_at_ms = ?, lease_owner = NULL, lease_until_ms = NULL
             WHERE id = ? AND lease_owner = ? AND finished_at_ms IS NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms > ?",
        )
        .bind(now_ms)
        .bind(id.as_slice())
        .bind(owner)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 1 { Ok(()) } else { Err(JobQueueError::LeaseLost) }
    }

    /// Record a failure and make a job eligible again at `retry_at_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::LeaseLost`] if the lease is no longer owned by `owner`.
    pub async fn fail_job(
        &self,
        id: JobId,
        owner: &str,
        now_ms: i64,
        retry_at_ms: i64,
        error: &str,
    ) -> Result<(), JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(now_ms)?;
        validate_timestamp(retry_at_ms)?;
        validate_error(error)?;
        let result = sqlx::query(
            "UPDATE jobs SET available_at_ms = ?, last_error = ?, lease_owner = NULL, lease_until_ms = NULL
             WHERE id = ? AND lease_owner = ? AND finished_at_ms IS NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms > ?",
        )
        .bind(retry_at_ms)
        .bind(error)
        .bind(id.as_slice())
        .bind(owner)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 1 { Ok(()) } else { Err(JobQueueError::LeaseLost) }
    }

    /// Release all expired leases and return the number of jobs made eligible again.
    ///
    /// # Errors
    ///
    /// Returns a database error when the update cannot be committed.
    pub async fn requeue_expired_jobs(&self, now_ms: i64) -> Result<u64, JobQueueError> {
        validate_timestamp(now_ms)?;
        let result = sqlx::query(
            "UPDATE jobs SET lease_owner = NULL, lease_until_ms = NULL
             WHERE finished_at_ms IS NULL AND lease_until_ms IS NOT NULL AND lease_until_ms <= ?",
        )
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Read one job for diagnostics and worker bookkeeping.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::NotFound`] when the id is absent.
    pub async fn get_job(&self, id: JobId) -> Result<Job, JobQueueError> {
        let row = sqlx::query(
            "SELECT id, kind, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error
             FROM jobs WHERE id = ?",
        )
        .bind(id.as_slice())
        .fetch_optional(self.pool())
        .await?
        .ok_or(JobQueueError::NotFound)?;
        job_from_row(&row)
    }
}

impl PostgresStore {
    /// Enqueue a job for immediate or future processing in PostgreSQL.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid fields or a database constraint error for a reused
    /// id.
    pub async fn enqueue_job(
        &self,
        id: JobId,
        kind: &str,
        payload: &[u8],
        available_at_ms: i64,
    ) -> Result<(), JobQueueError> {
        validate_kind(kind)?;
        validate_payload(payload)?;
        validate_timestamp(available_at_ms)?;
        let created_at_ms = now_ms()?;
        sqlx::query(
            "INSERT INTO jobs (id, kind, payload, available_at_ms, created_at_ms) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id.as_slice())
        .bind(kind)
        .bind(payload)
        .bind(available_at_ms)
        .bind(created_at_ms)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(map_write_error)
    }

    /// Enqueue a job unless an unfinished job with the same kind and payload already exists.
    ///
    /// A transaction-scoped advisory lock serializes the duplicate check for one kind and payload.
    ///
    /// # Errors
    ///
    /// Returns a validation, constraint, or database error when the job cannot be scheduled.
    pub async fn enqueue_job_if_absent(
        &self,
        id: JobId,
        kind: &str,
        payload: &[u8],
        available_at_ms: i64,
    ) -> Result<bool, JobQueueError> {
        validate_kind(kind)?;
        validate_payload(payload)?;
        validate_timestamp(available_at_ms)?;
        let created_at_ms = now_ms()?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || encode($2, 'hex'), 0))")
            .bind(kind)
            .bind(payload)
            .execute(&mut *transaction)
            .await?;
        let existing = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM jobs WHERE kind = $1 AND payload = $2 AND finished_at_ms IS NULL LIMIT 1",
        )
        .bind(kind)
        .bind(payload)
        .fetch_optional(&mut *transaction)
        .await?;
        if existing.is_some() {
            transaction.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO jobs (id, kind, payload, available_at_ms, created_at_ms) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id.as_slice())
        .bind(kind)
        .bind(payload)
        .bind(available_at_ms)
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_write_error)?;
        transaction.commit().await?;
        Ok(true)
    }

    /// Claim the oldest eligible PostgreSQL job with row locking that skips another worker's row.
    ///
    /// # Errors
    ///
    /// Returns a validation error for invalid lease parameters or a database error when the claim
    /// cannot be committed.
    pub async fn claim_job(
        &self,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        self.claim_job_filtered(None, owner, now_ms, now_ms, lease_ms).await
    }

    /// Claim the oldest eligible PostgreSQL job of one kind.
    ///
    /// # Errors
    ///
    /// Returns a validation or database error when the claim cannot be committed.
    pub async fn claim_job_kind(
        &self,
        kind: &str,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        self.claim_job_kind_available_through(kind, owner, now_ms, now_ms, lease_ms).await
    }

    /// Claim one PostgreSQL kind with separate availability and lease clocks.
    ///
    /// Jobs deferred beyond `available_through_ms` remain for a later sweep even when `now_ms`
    /// advances. Lease expiry and the new lease are evaluated at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns a validation or database error when the claim cannot be committed.
    pub async fn claim_job_kind_available_through(
        &self,
        kind: &str,
        owner: &str,
        available_through_ms: i64,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        validate_kind(kind)?;
        self.claim_job_filtered(Some(kind), owner, available_through_ms, now_ms, lease_ms).await
    }

    async fn claim_job_filtered(
        &self,
        kind: Option<&str>,
        owner: &str,
        available_through_ms: i64,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<Job>, JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(available_through_ms)?;
        validate_timestamp(now_ms)?;
        validate_lease(lease_ms)?;
        let lease_until_ms =
            now_ms.checked_add(lease_ms).ok_or(JobQueueError::TimestampOverflow)?;
        let mut transaction = self.pool().begin().await?;
        let query = if kind.is_some() {
            "SELECT id, kind, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error
             FROM jobs WHERE finished_at_ms IS NULL AND available_at_ms <= $1
               AND (lease_until_ms IS NULL OR lease_until_ms <= $2) AND kind = $3
             ORDER BY available_at_ms ASC, created_at_ms ASC, id ASC LIMIT 1 FOR UPDATE SKIP LOCKED"
        } else {
            "SELECT id, kind, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error
             FROM jobs WHERE finished_at_ms IS NULL AND available_at_ms <= $1
               AND (lease_until_ms IS NULL OR lease_until_ms <= $2)
             ORDER BY available_at_ms ASC, created_at_ms ASC, id ASC LIMIT 1 FOR UPDATE SKIP LOCKED"
        };
        let mut query = sqlx::query(query).bind(available_through_ms).bind(now_ms);
        if let Some(kind) = kind {
            query = query.bind(kind);
        }
        let row = query.fetch_optional(&mut *transaction).await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let id: Vec<u8> = row.try_get("id")?;
        let id = id_from_bytes(&id)?;
        let attempts: i64 = row.try_get("attempts")?;
        let attempts = attempts.checked_add(1).ok_or(JobQueueError::AttemptsOverflow)?;
        sqlx::query(
            "UPDATE jobs SET attempts = $1, lease_owner = $2, lease_until_ms = $3 WHERE id = $4 AND finished_at_ms IS NULL",
        )
        .bind(attempts)
        .bind(owner)
        .bind(lease_until_ms)
        .bind(id.as_slice())
        .execute(&mut *transaction)
        .await?;
        let mut job = job_from_postgres_row(&row)?;
        job.id = id;
        job.attempts =
            u64::try_from(attempts).map_err(|_| JobQueueError::CorruptRow("attempts"))?;
        job.lease_owner = Some(owner.to_owned());
        job.lease_until_ms = Some(lease_until_ms);
        transaction.commit().await?;
        Ok(Some(job))
    }

    /// Extend a live PostgreSQL lease owned by `owner`.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::LeaseLost`] if another worker owns the job or its lease expired.
    pub async fn renew_job(
        &self,
        id: JobId,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<(), JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(now_ms)?;
        validate_lease(lease_ms)?;
        let lease_until_ms =
            now_ms.checked_add(lease_ms).ok_or(JobQueueError::TimestampOverflow)?;
        let result = sqlx::query(
            "UPDATE jobs SET lease_until_ms = $1
             WHERE id = $2 AND lease_owner = $3 AND finished_at_ms IS NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms > $4",
        )
        .bind(lease_until_ms)
        .bind(id.as_slice())
        .bind(owner)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 1 { Ok(()) } else { Err(JobQueueError::LeaseLost) }
    }

    /// Mark a live PostgreSQL job complete.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::LeaseLost`] if the lease is no longer owned by `owner`.
    pub async fn complete_job(
        &self,
        id: JobId,
        owner: &str,
        now_ms: i64,
    ) -> Result<(), JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(now_ms)?;
        let result = sqlx::query(
            "UPDATE jobs SET finished_at_ms = $1, lease_owner = NULL, lease_until_ms = NULL
             WHERE id = $2 AND lease_owner = $3 AND finished_at_ms IS NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms > $4",
        )
        .bind(now_ms)
        .bind(id.as_slice())
        .bind(owner)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 1 { Ok(()) } else { Err(JobQueueError::LeaseLost) }
    }

    /// Record a PostgreSQL job failure and make it eligible again at `retry_at_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::LeaseLost`] if the lease is no longer owned by `owner`.
    pub async fn fail_job(
        &self,
        id: JobId,
        owner: &str,
        now_ms: i64,
        retry_at_ms: i64,
        error: &str,
    ) -> Result<(), JobQueueError> {
        validate_owner(owner)?;
        validate_timestamp(now_ms)?;
        validate_timestamp(retry_at_ms)?;
        validate_error(error)?;
        let result = sqlx::query(
            "UPDATE jobs SET available_at_ms = $1, last_error = $2, lease_owner = NULL, lease_until_ms = NULL
             WHERE id = $3 AND lease_owner = $4 AND finished_at_ms IS NULL
               AND lease_until_ms IS NOT NULL AND lease_until_ms > $5",
        )
        .bind(retry_at_ms)
        .bind(error)
        .bind(id.as_slice())
        .bind(owner)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() == 1 { Ok(()) } else { Err(JobQueueError::LeaseLost) }
    }

    /// Release all expired PostgreSQL leases.
    ///
    /// # Errors
    ///
    /// Returns a database error when the update cannot be committed.
    pub async fn requeue_expired_jobs(&self, now_ms: i64) -> Result<u64, JobQueueError> {
        validate_timestamp(now_ms)?;
        let result = sqlx::query(
            "UPDATE jobs SET lease_owner = NULL, lease_until_ms = NULL
             WHERE finished_at_ms IS NULL AND lease_until_ms IS NOT NULL AND lease_until_ms <= $1",
        )
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Read one PostgreSQL job for diagnostics and worker bookkeeping.
    ///
    /// # Errors
    ///
    /// Returns [`JobQueueError::NotFound`] when the id is absent.
    pub async fn get_job(&self, id: JobId) -> Result<Job, JobQueueError> {
        let row = sqlx::query(
            "SELECT id, kind, payload, available_at_ms, attempts, lease_owner, lease_until_ms, created_at_ms, finished_at_ms, last_error
             FROM jobs WHERE id = $1",
        )
        .bind(id.as_slice())
        .fetch_optional(self.pool())
        .await?
        .ok_or(JobQueueError::NotFound)?;
        job_from_postgres_row(&row)
    }
}

fn validate_kind(kind: &str) -> Result<(), JobQueueError> {
    if kind.trim().is_empty() || kind.len() > MAX_JOB_KIND_BYTES {
        return Err(JobQueueError::InvalidKind);
    }
    Ok(())
}

fn validate_owner(owner: &str) -> Result<(), JobQueueError> {
    if owner.trim().is_empty() || owner.len() > MAX_JOB_OWNER_BYTES {
        return Err(JobQueueError::InvalidOwner);
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), JobQueueError> {
    if payload.len() > MAX_JOB_PAYLOAD_BYTES {
        return Err(JobQueueError::PayloadTooLarge);
    }
    Ok(())
}

fn validate_error(error: &str) -> Result<(), JobQueueError> {
    if error.len() > MAX_JOB_ERROR_BYTES {
        return Err(JobQueueError::ErrorTooLarge);
    }
    Ok(())
}

fn validate_timestamp(timestamp: i64) -> Result<(), JobQueueError> {
    if timestamp < 0 { Err(JobQueueError::InvalidTimestamp) } else { Ok(()) }
}

fn validate_lease(lease_ms: i64) -> Result<(), JobQueueError> {
    if (1..=MAX_JOB_LEASE_MS).contains(&lease_ms) {
        Ok(())
    } else {
        Err(JobQueueError::InvalidLease)
    }
}

fn id_from_bytes(id: &[u8]) -> Result<JobId, JobQueueError> {
    id.try_into().map_err(|_| JobQueueError::CorruptRow("id"))
}

fn job_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Job, JobQueueError> {
    let id = id_from_bytes(&row.try_get::<Vec<u8>, _>("id")?)?;
    let attempts = row.try_get::<i64, _>("attempts")?;
    Ok(Job {
        id,
        kind: row.try_get("kind")?,
        payload: row.try_get("payload")?,
        available_at_ms: row.try_get("available_at_ms")?,
        attempts: attempts.try_into().map_err(|_| JobQueueError::CorruptRow("attempts"))?,
        lease_owner: row.try_get("lease_owner")?,
        lease_until_ms: row.try_get("lease_until_ms")?,
        created_at_ms: row.try_get("created_at_ms")?,
        finished_at_ms: row.try_get("finished_at_ms")?,
        last_error: row.try_get("last_error")?,
    })
}

fn job_from_postgres_row(row: &PgRow) -> Result<Job, JobQueueError> {
    let id = id_from_bytes(&row.try_get::<Vec<u8>, _>("id")?)?;
    let attempts = row.try_get::<i64, _>("attempts")?;
    Ok(Job {
        id,
        kind: row.try_get("kind")?,
        payload: row.try_get("payload")?,
        available_at_ms: row.try_get("available_at_ms")?,
        attempts: attempts.try_into().map_err(|_| JobQueueError::CorruptRow("attempts"))?,
        lease_owner: row.try_get("lease_owner")?,
        lease_until_ms: row.try_get("lease_until_ms")?,
        created_at_ms: row.try_get("created_at_ms")?,
        finished_at_ms: row.try_get("finished_at_ms")?,
        last_error: row.try_get("last_error")?,
    })
}

fn map_write_error(error: sqlx::Error) -> JobQueueError {
    match error {
        sqlx::Error::Database(_) => JobQueueError::Constraint(error),
        other => JobQueueError::Database(other),
    }
}

fn now_ms() -> Result<i64, JobQueueError> {
    let millis =
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| JobQueueError::Clock)?.as_millis();
    i64::try_from(millis).map_err(|_| JobQueueError::TimestampOverflow)
}

/// Errors returned by the durable job queue.
#[derive(Debug, Error)]
pub enum JobQueueError {
    /// Job kind is empty or exceeds the bounded identifier length.
    #[error("job kind is empty or too long")]
    InvalidKind,
    /// Lease owner is empty or exceeds the bounded owner length.
    #[error("job lease owner is empty or too long")]
    InvalidOwner,
    /// Job payload exceeds the queue limit.
    #[error("job payload exceeds the {MAX_JOB_PAYLOAD_BYTES}-byte limit")]
    PayloadTooLarge,
    /// Failure detail exceeds the queue limit.
    #[error("job failure detail exceeds the {MAX_JOB_ERROR_BYTES}-byte limit")]
    ErrorTooLarge,
    /// A timestamp is negative.
    #[error("job timestamp must not be negative")]
    InvalidTimestamp,
    /// Lease duration is outside the accepted range.
    #[error("job lease must be between 1 ms and {MAX_JOB_LEASE_MS} ms")]
    InvalidLease,
    /// A timestamp addition exceeded the SQL integer range.
    #[error("job timestamp overflowed")]
    TimestampOverflow,
    /// Attempts exceeded the SQL integer range.
    #[error("job attempts overflowed")]
    AttemptsOverflow,
    /// The requested job is absent.
    #[error("job was not found")]
    NotFound,
    /// The caller no longer owns a live lease.
    #[error("job lease is no longer owned by this worker")]
    LeaseLost,
    /// Stored job data violated an invariant.
    #[error("corrupt job row: {0}")]
    CorruptRow(&'static str),
    /// A job write violated a database constraint.
    #[error("job queue constraint failed: {0}")]
    Constraint(#[source] sqlx::Error),
    /// The database operation failed.
    #[error("job queue database error: {0}")]
    Database(#[from] sqlx::Error),
    /// The system clock could not be read.
    #[error("system clock error")]
    Clock,
}
