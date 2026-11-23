// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit, audit-atomic member confirmation with an original-writer receipt.

use scoplen_api::{
    auth_connection_draft::test_login::DraftLoginStatus, member_link::LinkResponseHeaders,
};
use serde::Deserialize;

use super::{
    Error, LinkMembership, MemberLink, Postgres, PostgresStore, Session, Sqlite, SqliteStore,
    Transaction, Uuid, Writer, append_audit_event_in_postgres_transaction,
    append_audit_event_in_transaction, now_ms, postgres_actor, sqlite_actor, timestamp, valid_id,
};
use crate::organizations::auth_connection::TransitionReceipt;

fn recover(bytes: &[u8], membership: LinkMembership) -> Result<MemberLink, Error> {
    #[derive(Deserialize)]
    struct Tag {
        etag: String,
    }
    let tag: Tag = serde_json::from_slice(bytes).map_err(|_| Error::StorageUnavailable)?;
    MemberLink::from_http_json(
        bytes,
        membership,
        LinkResponseHeaders {
            etag: Some(&tag.etag),
            cache_control: Some("no-store"),
            pragma: Some("no-cache"),
        },
    )
    .map_err(|_| Error::StorageUnavailable)
}

macro_rules! confirm {
    ($store:ty,$db:ty,$begin:literal,$actor:ident,$audit:ident) => {
        impl $store {
            async fn install_verified_link(
                tx: &mut Transaction<'_, $db>,
                writer: Writer,
                id: Uuid,
                revision: Uuid,
                now: i64,
            ) -> Result<(MemberLink, i64), Error> {
                let org = writer.member.organization_id;
                let member = writer.member.membership_id;
                let (attempt, expires) = Self::live_link_attempt(tx, writer, id).await?;
                if attempt.connection_revision != revision {
                    return Err(Error::PreconditionFailed);
                }
                if attempt.status != DraftLoginStatus::Verified {
                    return Err(Error::Conflict);
                }
                let link = MemberLink {
                    id: Uuid::now_v7(),
                    created_at: timestamp(now)?,
                    membership: writer.member,
                };
                let inserted=sqlx::query("INSERT INTO organization_auth_links (id,organization_id,membership_id,subject_comparison,created_at_ms)
                            SELECT $1,organization_id,membership_id,subject_comparison,$2 FROM organization_auth_link_attempts
                            WHERE id=$3 AND phase='verified' AND expires_at_ms>$2 ON CONFLICT DO NOTHING")
                            .bind(link.id.as_bytes().as_slice()).bind(now).bind(id.as_bytes().as_slice()).execute(&mut **tx).await?;
                if inserted.rows_affected() != 1 {
                    return Err(Error::Conflict);
                }
                let advanced=sqlx::query("UPDATE organization_memberships SET auth_link_generation=auth_link_generation+1
                            WHERE organization_id=$1 AND id=$2 AND auth_link_generation=$3 AND status='active'")
                            .bind(org.as_bytes().as_slice()).bind(member.as_bytes().as_slice()).bind(writer.generation).execute(&mut **tx).await?;
                if advanced.rows_affected() != 1 {
                    return Err(Error::NotFound);
                }
                Self::fence_organization_auth_links(tx, org, Some(member), false).await?;
                Ok((link, expires))
            }

            /// Confirm the original member's verified attempt or recover its original public result.
            ///
            /// # Errors
            /// Rejects wrong authority, expired native sign-in, changed revisions, ineligible receipts and identity collisions.
            pub async fn confirm_member_link(
                &self,
                session: &Session,
                org: Uuid,
                id: Uuid,
                revision: Uuid,
                key: Uuid,
                trust: impl FnOnce(&str) -> Option<[u8; 32]> + Send,
            ) -> Result<MemberLink, Error> {
                valid_id(id)?;
                valid_id(key)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let writer = Self::member_link_writer(&mut tx, session, org, None, true).await?;
                let deadline = Self::link_fresh_deadline(&mut tx, writer).await?;
                let active = Self::link_active_revision(&mut tx, org, revision).await?;
                if trust(&active.target.issuer) != Some(active.fingerprint) {
                    return Err(Error::NotFound);
                }
                let path = format!("/api/v1/orgs/{org}/auth-link/attempts/{id}/confirm");
                let mut purpose = b"spl-member-link-confirm\0v1\0".to_vec();
                purpose.extend_from_slice(writer.member.membership_id.as_bytes());
                let receipt =
                    TransitionReceipt::new(session, key, &path, &format!("\"{revision}\""), &purpose);
                if let Some(body) = Self::transition_receipt_bytes(&mut tx, &receipt).await? {
                    let original = recover(&body, writer.member)?;
                    $actor(&mut tx, session, 0).await?;
                    if now_ms()? >= deadline {
                        return Err(Error::PermissionDenied);
                    }
                    tx.commit().await?;
                    return Ok(original);
                }
                let now = now_ms()?;
                let (link, expires) =
                    Self::install_verified_link(&mut tx, writer, id, revision, now).await?;
                let body = link.to_json().map_err(|_| Error::StorageUnavailable)?;
                Self::record_transition_receipt(&mut tx, &receipt, &body, now).await?;
                let event = writer.event(
                    "organization.auth_link_confirmed",
                    Some(revision),
                    Some(id),
                    Some(link.id),
                    None,
                )?;
                $audit(&mut tx, org.into_bytes(), &event, now)
                    .await
                    .map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                let now = now_ms()?;
                if now >= deadline {
                    return Err(Error::PermissionDenied);
                }
                if now >= expires {
                    return Err(Error::NotFound);
                }
                tx.commit().await.map_err(|_| Error::CommitOutcomeUnknown)?;
                Ok(link)
            }
        }
    };
}
confirm!(SqliteStore, Sqlite, "BEGIN IMMEDIATE", sqlite_actor, append_audit_event_in_transaction);
confirm!(
    PostgresStore,
    Postgres,
    "BEGIN",
    postgres_actor,
    append_audit_event_in_postgres_transaction
);
