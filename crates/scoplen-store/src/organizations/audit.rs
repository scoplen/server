// SPDX-License-Identifier: AGPL-3.0-only
//! Immutable Organization audit reads under transaction-current tenant authority.

use futures_util::TryStreamExt as _;
use scoplen_api::audit::{
    AuditListQuery, AuditPage, AuditRange, AuditVerification, MAX_AUDIT_VERIFY_EVENT_BYTES,
};
use sqlx::Row as _;
use uuid::Uuid;

use super::{
    OrganizationPrincipal, OrganizationStoreError as Error, PostgresStore, SqliteStore,
    inventory::row_uuid, now_ms, postgres_actor, sqlite_actor,
};

mod projection;
mod verification;

macro_rules! audit_queries {
    ($store:ty, $begin:literal, $actor:ident, $length:literal) => {
        impl $store {
            /// Read a descending live page using only safe recorded metadata.
            ///
            /// # Errors
            /// Rejects invalid queries, stale actors, inaccessible Organizations, denied current
            /// `view_audit`, unavailable storage or unusable mandatory transport metadata.
            pub async fn list_organization_audit(
                &self,
                expected: &impl OrganizationPrincipal,
                expires_at: u64,
                organization: Uuid,
                query: &AuditListQuery,
            ) -> Result<AuditPage, Error> {
                query.validate().map_err(|_| Error::InvalidRequest)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let (current, _, _, _) =
                    Self::inventory_owner(&mut tx, expected, expires_at, organization, false)
                        .await?;
                Self::authorize_organization_action(&mut tx, &current, now_ms()?, "view_audit")
                    .await?;
                let before = query
                    .cursor
                    .map_or(i64::MAX, |value| i64::try_from(value - 1).unwrap_or(i64::MAX));
                let sql = format!(
                    "SELECT organization_id,sequence,previous_hash,event_hash,created_at_ms,\
                     CASE WHEN {}(event_bytes) BETWEEN 1 AND {} THEN event_bytes ELSE NULL END AS event_bytes \
                     FROM audit_events WHERE organization_id=$1 AND sequence<=$2 \
                     ORDER BY sequence DESC",
                    $length,
                    scoplen_audit::MAX_EVENT_BYTES,
                );
                let mut page = AuditPage { items: Vec::new(), next_cursor: None };
                {
                    let mut rows = sqlx::query(&sql)
                        .bind(organization.as_bytes().as_slice())
                        .bind(before)
                        .fetch(&mut *tx);
                    while let Some(row) = rows.try_next().await? {
                        let stored_organization = row_uuid(&row, "organization_id")?;
                        if stored_organization != organization {
                            return Err(Error::StorageUnavailable);
                        }
                        let bytes: Option<Vec<u8>> = row.try_get("event_bytes")?;
                        let event = projection::project(
                            stored_organization,
                            row.try_get("sequence")?,
                            row.try_get("previous_hash")?,
                            row.try_get("event_hash")?,
                            row.try_get("created_at_ms")?,
                            bytes.as_deref(),
                        )?;
                        if !query.filter.matches(&event).map_err(|_| Error::StorageUnavailable)? {
                            continue;
                        }
                        if page.items.len() == usize::from(query.limit) {
                            page.next_cursor = page.items.last().map(|item| item.sequence);
                            break;
                        }
                        page.items.push(event);
                    }
                }
                page.validate_for(organization, query).map_err(|_| Error::StorageUnavailable)?;
                page.to_json().map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, expected, expires_at).await?;
                tx.commit().await?;
                Ok(page)
            }

            /// Verify one bounded contiguous interval against the independent audit trust key.
            ///
            /// # Errors
            /// Rejects out-of-extent or excessive ranges and current-authorization/storage
            /// failures. Determined chain/checkpoint corruption returns an invalid report.
            #[allow(clippy::too_many_lines)]
            pub async fn verify_organization_audit(
                &self,
                expected: &impl OrganizationPrincipal,
                expires_at: u64,
                organization: Uuid,
                range: AuditRange,
                audit_verification_key: &[u8; 32],
            ) -> Result<AuditVerification, Error> {
                range.validate().map_err(|error| match error {
                    scoplen_api::audit::AuditCodecError::TooLarge => Error::AuditTooLarge,
                    _ => Error::InvalidRequest,
                })?;
                let mut tx = self.pool.begin_with($begin).await?;
                let (current, _, _, _) =
                    Self::inventory_owner(&mut tx, expected, expires_at, organization, false)
                        .await?;
                Self::authorize_organization_action(&mut tx, &current, now_ms()?, "view_audit")
                    .await?;
                let event_extent: Option<i64> = sqlx::query_scalar(
                    "SELECT MAX(sequence) FROM audit_events WHERE organization_id=$1",
                ).bind(organization.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                let checkpoint_extent: Option<i64> = sqlx::query_scalar(
                    "SELECT MAX(sequence) FROM audit_checkpoints WHERE organization_id=$1",
                ).bind(organization.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                let extent = event_extent.into_iter().chain(checkpoint_extent).max().unwrap_or(0);
                if range.to_sequence > u64::try_from(extent).map_err(|_| Error::StorageUnavailable)? {
                    return Err(Error::InvalidRequest);
                }
                let from = i64::try_from(range.from_sequence).map_err(|_| Error::InvalidRequest)?;
                let to = i64::try_from(range.to_sequence).map_err(|_| Error::InvalidRequest)?;
                let bytes: Option<i64> = sqlx::query_scalar(&format!(
                    "SELECT SUM({}(event_bytes)) FROM audit_events \
                     WHERE organization_id=$1 AND sequence BETWEEN $2 AND $3", $length,
                )).bind(organization.as_bytes().as_slice()).bind((from-1).max(1)).bind(to)
                    .fetch_one(&mut *tx).await?;
                if u64::try_from(bytes.unwrap_or(0)).map_err(|_| Error::StorageUnavailable)?
                    > MAX_AUDIT_VERIFY_EVENT_BYTES as u64 {
                    return Err(Error::AuditTooLarge);
                }
                let event_sql = format!(
                    "SELECT organization_id,sequence,previous_hash,event_hash,\
                     CASE WHEN {}(event_bytes) BETWEEN 1 AND {} THEN event_bytes ELSE NULL END AS event_bytes \
                     FROM audit_events WHERE organization_id=$1 AND sequence BETWEEN $2 AND $3 \
                     ORDER BY sequence", $length, scoplen_audit::MAX_EVENT_BYTES,
                );
                let result = 'verify: {
                    let mut previous = [0; 32];
                    if from > 1 {
                        let row = sqlx::query(&event_sql)
                            .bind(organization.as_bytes().as_slice()).bind(from-1).bind(from-1)
                            .fetch_optional(&mut *tx).await?;
                        let Some(hash) = row.as_ref()
                            .and_then(verification::event_from_row)
                            .and_then(|event| event.verify(organization, range.from_sequence-1, None))
                        else {
                            break 'verify verification::failure(organization, range, range.from_sequence);
                        };
                        previous = hash;
                    }
                    let first_previous = previous;
                    let checkpoint_rows = sqlx::query(
                        "SELECT organization_id,sequence,head_hash,signature,signed_at_ms \
                         FROM audit_checkpoints WHERE organization_id=$1 \
                         AND sequence BETWEEN $2 AND $3 ORDER BY sequence",
                    ).bind(organization.as_bytes().as_slice()).bind(from).bind(to)
                        .fetch_all(&mut *tx).await?;
                    let mut checkpoints = std::collections::BTreeMap::new();
                    for row in checkpoint_rows {
                        let Some(sequence) = row.try_get::<i64, _>("sequence").ok()
                            .and_then(|value| u64::try_from(value).ok()) else {
                            break 'verify verification::failure(organization, range, range.from_sequence);
                        };
                        checkpoints.insert(sequence, verification::checkpoint_from_row(&row, organization));
                    }
                    let mut sequence = range.from_sequence;
                    let mut checkpoint = None;
                    {
                        let mut rows = sqlx::query(&event_sql)
                            .bind(organization.as_bytes().as_slice()).bind(from).bind(to)
                            .fetch(&mut *tx);
                        while let Some(row) = rows.try_next().await? {
                            let Some(hash) = verification::event_from_row(&row)
                                .and_then(|event| event.verify(organization, sequence, Some(previous)))
                            else {
                                break 'verify verification::failure(organization, range, sequence);
                            };
                            if let Some(evidence) = checkpoints.remove(&sequence) {
                                let Some(evidence) = evidence.filter(|evidence| verification::verify_checkpoint(
                                    evidence, organization, hash, audit_verification_key,
                                )) else {
                                    break 'verify verification::failure(organization, range, sequence);
                                };
                                checkpoint = Some(evidence);
                            }
                            previous = hash;
                            sequence += 1;
                        }
                    }
                    if sequence <= range.to_sequence {
                        break 'verify verification::failure(organization, range, sequence);
                    }
                    verification::success(organization, range, first_previous, previous, checkpoint)
                };
                result.validate_for(organization, range).map_err(|_| Error::StorageUnavailable)?;
                result.to_json().map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, expected, expires_at).await?;
                tx.commit().await?;
                Ok(result)
            }
        }
    };
}

audit_queries!(SqliteStore, "BEGIN IMMEDIATE", sqlite_actor, "length");
audit_queries!(PostgresStore, "BEGIN", postgres_actor, "octet_length");
