// SPDX-License-Identifier: AGPL-3.0-only
//! Durable per-device object-write admission, independent of business-write transactions.

use sqlx::{Postgres, Sqlite, Transaction};
use thiserror::Error;

use crate::{PostgresStore, RelationalStore, SqliteStore, sync::DeviceId};

/// Default authenticated object-write refill rate.
pub const WRITE_REQUESTS_PER_SECOND: u64 = 50;
/// Default authenticated object-write burst.
pub const WRITE_BURST: u64 = 200;
const TOKEN_SCALE: u128 = 1_000_000_000;
const IDLE_GRACE: u128 = 60 * TOKEN_SCALE;

/// Positive per-device object-write token bucket settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteRateLimits {
    requests_per_second: u64,
    burst: u64,
}

impl WriteRateLimits {
    /// Validate the effective limits advertised to clients.
    ///
    /// # Errors
    ///
    /// Returns the invalid setting when either value is zero.
    pub fn new(requests_per_second: u64, burst: u64) -> Result<Self, String> {
        if requests_per_second == 0 {
            return Err("sync.write_requests_per_second must be positive".into());
        }
        if burst == 0 {
            return Err("sync.write_burst must be positive".into());
        }
        Ok(Self { requests_per_second, burst })
    }

    /// Requests added to a device's bucket per second.
    #[must_use]
    pub fn requests_per_second(self) -> u64 {
        self.requests_per_second
    }

    /// Maximum requests spendable without refilling.
    #[must_use]
    pub fn burst(self) -> u64 {
        self.burst
    }

    fn capacity(self) -> u128 {
        u128::from(self.burst) * TOKEN_SCALE
    }
}

impl Default for WriteRateLimits {
    fn default() -> Self {
        Self { requests_per_second: WRITE_REQUESTS_PER_SECOND, burst: WRITE_BURST }
    }
}

/// Result committed before any object body is collected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncWriteAdmissionDecision {
    /// One attempt was charged.
    Admitted,
    /// No whole token is available; wait at least this many seconds.
    RateLimited(u128),
    /// The old policy must refill before this replica's policy can take effect.
    PolicyPending,
}

/// Redacted admission failures. No object mutation has been dispatched.
#[derive(Debug, Error)]
pub enum SyncWriteAdmissionError {
    /// Includes an unconfirmed admission-only commit.
    #[error("sync write admission storage unavailable")]
    Database(#[from] sqlx::Error),
    /// The database clock cannot be represented safely.
    #[error("sync write admission clock unavailable")]
    Clock,
    /// Persisted bucket or retirement-clock state is invalid.
    #[error("invalid sync write admission state")]
    InvalidState,
}

#[derive(Debug, sqlx::FromRow)]
struct StoredBucket {
    device_id: Vec<u8>,
    requests_per_second: Vec<u8>,
    burst: Vec<u8>,
    tokens: Vec<u8>,
    refill_origin_ns: Vec<u8>,
    retire_at_ns: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    limits: WriteRateLimits,
    tokens: u128,
    origin: u128,
}

fn unsigned<const N: usize>(value: &[u8]) -> Result<[u8; N], SyncWriteAdmissionError> {
    value.try_into().map_err(|_| SyncWriteAdmissionError::InvalidState)
}

impl Bucket {
    fn fresh(limits: WriteRateLimits) -> Self {
        Self { limits, tokens: limits.capacity(), origin: 0 }
    }

    fn decode(row: &StoredBucket) -> Result<Self, SyncWriteAdmissionError> {
        let _: DeviceId = unsigned(&row.device_id)?;
        let limits = WriteRateLimits::new(
            u64::from_be_bytes(unsigned(&row.requests_per_second)?),
            u64::from_be_bytes(unsigned(&row.burst)?),
        )
        .map_err(|_| SyncWriteAdmissionError::InvalidState)?;
        let bucket = Self {
            limits,
            tokens: u128::from_be_bytes(unsigned(&row.tokens)?),
            origin: u128::from_be_bytes(unsigned(&row.refill_origin_ns)?),
        };
        if bucket.tokens > limits.capacity()
            || bucket.retire_at()? != u128::from_be_bytes(unsigned(&row.retire_at_ns)?)
        {
            return Err(SyncWriteAdmissionError::InvalidState);
        }
        Ok(bucket)
    }

    fn retire_at(self) -> Result<u128, SyncWriteAdmissionError> {
        self.origin
            .checked_add(
                (self.limits.capacity() - self.tokens)
                    .div_ceil(u128::from(self.limits.requests_per_second)),
            )
            .and_then(|full| full.checked_add(IDLE_GRACE))
            .ok_or(SyncWriteAdmissionError::InvalidState)
    }

    fn admit(
        &mut self,
        limits: WriteRateLimits,
        now: u128,
        watermark: u128,
    ) -> Result<SyncWriteAdmissionDecision, SyncWriteAdmissionError> {
        let elapsed = now.saturating_sub(self.origin);
        let deficit = self.limits.capacity() - self.tokens;
        let rate = u128::from(self.limits.requests_per_second);
        // Check the horizon first: elapsed * rate may overflow even though capacity fits.
        if elapsed >= deficit.div_ceil(rate) {
            self.tokens = self.limits.capacity();
        } else {
            self.tokens += elapsed * rate;
        }
        self.origin = self.origin.max(now).max(watermark);
        let decision = if self.limits != limits && self.tokens != self.limits.capacity() {
            SyncWriteAdmissionDecision::PolicyPending
        } else {
            if self.limits != limits {
                self.limits = limits;
                self.tokens = limits.capacity();
            }
            if self.tokens >= TOKEN_SCALE {
                self.tokens -= TOKEN_SCALE;
                SyncWriteAdmissionDecision::Admitted
            } else {
                let wait = self
                    .origin
                    .saturating_sub(now)
                    .checked_add(
                        (TOKEN_SCALE - self.tokens)
                            .div_ceil(u128::from(limits.requests_per_second)),
                    )
                    .ok_or(SyncWriteAdmissionError::InvalidState)?;
                SyncWriteAdmissionDecision::RateLimited(wait.div_ceil(TOKEN_SCALE).max(1))
            }
        };
        self.retire_at()?;
        Ok(decision)
    }
}

#[derive(Clone, Copy)]
enum Clock {
    Database,
    #[cfg(test)]
    Fixed(u128),
    #[cfg(test)]
    LostCommit(u128),
}

impl Clock {
    fn read(self, database: u128) -> u128 {
        match self {
            Self::Database => database,
            #[cfg(test)]
            Self::Fixed(now) | Self::LostCommit(now) => now,
        }
    }
}

async fn sqlite_now(tx: &mut Transaction<'_, Sqlite>) -> Result<u128, SyncWriteAdmissionError> {
    let (seconds, fraction): (String, String) =
        sqlx::query_as("SELECT strftime('%s','now'), strftime('%f','now')")
            .fetch_one(&mut **tx)
            .await?;
    let seconds: u128 = seconds.parse().map_err(|_| SyncWriteAdmissionError::Clock)?;
    let millis: u128 = fraction
        .get(3..6)
        .ok_or(SyncWriteAdmissionError::Clock)?
        .parse()
        .map_err(|_| SyncWriteAdmissionError::Clock)?;
    seconds
        .checked_mul(TOKEN_SCALE)
        .and_then(|value| value.checked_add(millis * 1_000_000))
        .ok_or(SyncWriteAdmissionError::Clock)
}

async fn postgres_now(tx: &mut Transaction<'_, Postgres>) -> Result<u128, SyncWriteAdmissionError> {
    let now: String = sqlx::query_scalar(
        "SELECT trunc(extract(epoch FROM clock_timestamp()) * 1000000000)::text",
    )
    .fetch_one(&mut **tx)
    .await?;
    now.parse().map_err(|_| SyncWriteAdmissionError::Clock)
}

const LOCK_BUCKET: &str = "INSERT INTO sync_write_admission (device_id, requests_per_second, burst, tokens, refill_origin_ns, retire_at_ns) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (device_id) DO UPDATE SET device_id=excluded.device_id RETURNING device_id, requests_per_second, burst, tokens, refill_origin_ns, retire_at_ns";
const SAVE_BUCKET: &str = "UPDATE sync_write_admission SET requests_per_second=$2,burst=$3,tokens=$4,refill_origin_ns=$5,retire_at_ns=$6 WHERE device_id=$1";
const WATERMARK: &str =
    "SELECT retired_through_ns FROM sync_write_admission_clock WHERE singleton=1";
const ADVANCE_WATERMARK: &str = "UPDATE sync_write_admission_clock SET retired_through_ns=CASE WHEN retired_through_ns < $1 THEN $1 ELSE retired_through_ns END WHERE singleton=1";

async fn sqlite_begin(store: &SqliteStore) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}

async fn postgres_begin(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    store.pool().begin().await
}

macro_rules! admission_store {
    ($store:ty, $begin:ident, $now:ident, $candidates:expr) => {
        impl $store {
            /// Charge one authenticated object POST before collecting its body.
            ///
            /// # Errors
            ///
            /// Fails closed on database, clock or invalid-state errors. An unconfirmed counter
            /// commit may have charged the attempt, but no object write has been dispatched.
            pub async fn admit_sync_write(
                &self,
                device: DeviceId,
                limits: WriteRateLimits,
            ) -> Result<SyncWriteAdmissionDecision, SyncWriteAdmissionError> {
                self.admit_sync_write_with_clock(device, limits, Clock::Database).await
            }

            async fn admit_sync_write_with_clock(
                &self,
                device: DeviceId,
                limits: WriteRateLimits,
                clock: Clock,
            ) -> Result<SyncWriteAdmissionDecision, SyncWriteAdmissionError> {
                let mut tx = $begin(self).await?;
                let fresh = Bucket::fresh(limits);
                // The no-op upsert locks existing rows and serializes competing first inserts.
                let row = sqlx::query_as::<_, StoredBucket>(LOCK_BUCKET)
                    .bind(device.as_slice())
                    .bind(limits.requests_per_second.to_be_bytes().as_slice())
                    .bind(limits.burst.to_be_bytes().as_slice())
                    .bind(fresh.tokens.to_be_bytes().as_slice())
                    .bind(fresh.origin.to_be_bytes().as_slice())
                    .bind(fresh.retire_at()?.to_be_bytes().as_slice())
                    .fetch_one(&mut *tx)
                    .await?;
                let mut bucket = Bucket::decode(&row)?;
                // Non-locking read: cleanup locks candidate devices before writing this row.
                let watermark: Vec<u8> = sqlx::query_scalar(WATERMARK).fetch_one(&mut *tx).await?;
                let watermark = u128::from_be_bytes(unsigned(&watermark)?);
                let now = clock.read($now(&mut tx).await?);
                let decision = bucket.admit(limits, now, watermark)?;
                let saved = sqlx::query(SAVE_BUCKET)
                    .bind(device.as_slice())
                    .bind(bucket.limits.requests_per_second.to_be_bytes().as_slice())
                    .bind(bucket.limits.burst.to_be_bytes().as_slice())
                    .bind(bucket.tokens.to_be_bytes().as_slice())
                    .bind(bucket.origin.to_be_bytes().as_slice())
                    .bind(bucket.retire_at()?.to_be_bytes().as_slice())
                    .execute(&mut *tx)
                    .await?;
                if saved.rows_affected() != 1 {
                    return Err(SyncWriteAdmissionError::InvalidState);
                }
                let candidates = sqlx::query_as::<_, StoredBucket>($candidates)
                    .bind(now.to_be_bytes().as_slice())
                    .fetch_all(&mut *tx)
                    .await?;
                for candidate in &candidates {
                    if Bucket::decode(candidate)?.retire_at()? > now {
                        return Err(SyncWriteAdmissionError::InvalidState);
                    }
                    let deleted =
                        sqlx::query("DELETE FROM sync_write_admission WHERE device_id=$1")
                            .bind(&candidate.device_id)
                            .execute(&mut *tx)
                            .await?;
                    if deleted.rows_affected() != 1 {
                        return Err(SyncWriteAdmissionError::InvalidState);
                    }
                }
                if !candidates.is_empty() {
                    let updated = sqlx::query(ADVANCE_WATERMARK)
                        .bind(now.to_be_bytes().as_slice())
                        .execute(&mut *tx)
                        .await?;
                    if updated.rows_affected() != 1 {
                        return Err(SyncWriteAdmissionError::InvalidState);
                    }
                }
                tx.commit().await?;
                #[cfg(test)]
                if matches!(clock, Clock::LostCommit(_)) {
                    return Err(SyncWriteAdmissionError::Database(sqlx::Error::Io(
                        std::io::Error::other("injected lost admission commit acknowledgement"),
                    )));
                }
                Ok(decision)
            }
        }
    };
}

admission_store!(
    SqliteStore,
    sqlite_begin,
    sqlite_now,
    "SELECT device_id,requests_per_second,burst,tokens,refill_origin_ns,retire_at_ns FROM sync_write_admission WHERE retire_at_ns <= $1 ORDER BY retire_at_ns,device_id LIMIT 16"
);
admission_store!(
    PostgresStore,
    postgres_begin,
    postgres_now,
    "WITH candidates AS MATERIALIZED (SELECT device_id FROM sync_write_admission WHERE retire_at_ns <= $1 ORDER BY retire_at_ns,device_id LIMIT 16) SELECT b.device_id,b.requests_per_second,b.burst,b.tokens,b.refill_origin_ns,b.retire_at_ns FROM sync_write_admission b JOIN candidates c USING(device_id) WHERE b.retire_at_ns <= $1 ORDER BY b.retire_at_ns,b.device_id FOR UPDATE OF b SKIP LOCKED"
);

#[cfg(test)]
#[path = "sync_write_admission/tests.rs"]
mod tests;
