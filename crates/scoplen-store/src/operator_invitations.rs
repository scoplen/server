// SPDX-License-Identifier: AGPL-3.0-only
//! Durable, independent source and authenticated-Operator quotas for invitation issuance.

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use sqlx::Row;
use uuid::Uuid;

use crate::{
    PostgresStore, RelationalStore, SqliteStore,
    deployment_audit::{
        append_deployment_audit_event_in_postgres_transaction,
        append_deployment_audit_event_in_transaction,
    },
    personal_admission::{PersonalAdmissionDecision, PersonalAdmissionError},
};

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum InvitationFailureReason {
    InvalidRequest = 1,
    AuthenticationRequired = 2,
    PolicyDenied = 3,
    OriginDenied = 4,
    RateLimited = 5,
    StorageUnavailable = 6,
}

fn now_ms() -> Result<i64, PersonalAdmissionError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PersonalAdmissionError::Clock)?
            .as_millis(),
    )
    .map_err(|_| PersonalAdmissionError::Clock)
}

fn source_key(source: IpAddr) -> Vec<u8> {
    match source {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped().map_or_else(|| ip.octets().to_vec(), |v4| v4.octets().to_vec())
        }
    }
}

macro_rules! invitation_admission {
    ($store:ty, $db:ty, $begin:expr, $cleanup:literal, $audit:path) => {
        impl $store {
            /// Admit the actual peer before reading the issuance request body.
            ///
            /// # Errors
            /// Returns a safe storage error if the durable quota cannot be checked.
            pub async fn admit_personal_invitation_source(
                &self,
                source: IpAddr,
            ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
                self.admit_personal_invitation_bucket(1, &source_key(source), 30).await
            }

            /// Admit an Operator only after signature, current-session, proof and scope checks.
            ///
            /// # Errors
            /// Rejects invalid identifiers and unavailable durable admission.
            pub async fn admit_personal_invitation_operator(
                &self,
                operator: Uuid,
            ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
                if operator.get_version_num() != 7
                    || operator.get_variant() != uuid::Variant::RFC4122
                {
                    return Err(PersonalAdmissionError::InvalidState);
                }
                self.admit_personal_invitation_bucket(2, operator.as_bytes(), 10).await
            }

            async fn admit_personal_invitation_bucket(
                &self,
                kind: i64,
                key: &[u8],
                limit: i64,
            ) -> Result<PersonalAdmissionDecision, PersonalAdmissionError> {
                let mut tx = self.pool().begin_with($begin).await?;
                let before = now_ms()?;
                let row = sqlx::query::<$db>(
                    "INSERT INTO personal_invitation_admission
                     (kind,bucket_key,window_start_ms,attempts,retain_until_ms)
                     VALUES ($1,$2,$3,0,$4) ON CONFLICT (kind,bucket_key)
                     DO UPDATE SET bucket_key=excluded.bucket_key RETURNING window_start_ms,attempts",
                )
                .bind(kind)
                .bind(key)
                .bind(before.div_euclid(60_000) * 60_000)
                .bind(before.saturating_add(60_000))
                .fetch_one(&mut *tx)
                .await?;
                let now = now_ms()?;
                let mut window: i64 = row.try_get("window_start_ms")?;
                let mut attempts: i64 = row.try_get("attempts")?;
                if now >= window.saturating_add(60_000) {
                    window = now.div_euclid(60_000) * 60_000;
                    attempts = 0;
                }
                let decision = if attempts >= limit {
                    let delay = (window.saturating_add(60_000).saturating_sub(now).saturating_add(999) / 1_000).clamp(1, 300);
                    PersonalAdmissionDecision::RateLimited(
                        u64::try_from(delay).map_err(|_| PersonalAdmissionError::Clock)?,
                    )
                } else {
                    attempts += 1;
                    PersonalAdmissionDecision::Admitted
                };
                sqlx::query::<$db>(
                    "UPDATE personal_invitation_admission
                     SET window_start_ms=$3, attempts=$4, retain_until_ms=$5
                     WHERE kind=$1 AND bucket_key=$2",
                )
                .bind(kind)
                .bind(key)
                .bind(window)
                .bind(attempts)
                .bind(window.saturating_add(60_000))
                .execute(&mut *tx)
                .await?;
                sqlx::query::<$db>($cleanup).bind(now).execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(decision)
            }

            /// Record a safe failure reason without bearer credentials or submitted identifiers.
            ///
            /// # Errors
            /// A failure to commit the mandatory audit must override the original HTTP failure.
            pub async fn audit_personal_invitation_failure(
                &self,
                reason: InvitationFailureReason,
            ) -> Result<(), PersonalAdmissionError> {
                let mut tx = self.pool().begin_with($begin).await?;
                let now = now_ms()?;
                let mut event = b"spl-operator-invitation-failure-v1".to_vec();
                event.push(reason as u8);
                event.extend_from_slice(&now.to_be_bytes());
                $audit(&mut tx, &event, now).await?;
                tx.commit().await?;
                Ok(())
            }
        }
    };
}

invitation_admission!(
    SqliteStore,
    sqlx::Sqlite,
    "BEGIN IMMEDIATE",
    "DELETE FROM personal_invitation_admission WHERE (kind,bucket_key) IN (SELECT kind,bucket_key FROM personal_invitation_admission WHERE retain_until_ms<=$1 ORDER BY retain_until_ms LIMIT 16)",
    append_deployment_audit_event_in_transaction
);
invitation_admission!(
    PostgresStore,
    sqlx::Postgres,
    "BEGIN",
    "DELETE FROM personal_invitation_admission WHERE (kind,bucket_key) IN (SELECT kind,bucket_key FROM personal_invitation_admission WHERE retain_until_ms<=$1 ORDER BY retain_until_ms LIMIT 16 FOR UPDATE SKIP LOCKED)",
    append_deployment_audit_event_in_postgres_transaction
);
