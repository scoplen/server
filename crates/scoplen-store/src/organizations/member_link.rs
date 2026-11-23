// SPDX-License-Identifier: AGPL-3.0-only
//! Native member-controlled external identity associations.

mod attempt;
mod callback;
mod comparison;
mod confirm;

pub use attempt::LinkStart;
pub use callback::{ClaimedLink, LinkClaim, LinkOutcome};

use scoplen_api::{
    account_browser::AccountBrowserAccessScope as Scope,
    auth_connection::{ConnectionStatus, ConnectionTarget},
    member_link::{LinkConnection, LinkMembership, MemberLink, MemberLinkStatus, SelfLinkStatus},
};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

use super::{
    OrganizationStoreError as Error, PostgresStore, SqliteStore,
    append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    auth_connection::require_fresh, auth_draft_login::DraftLoginProvider, inventory::row_uuid,
    lock_postgres, lock_sqlite, now_ms, postgres_actor, sqlite_actor, timestamp,
};
use crate::account_browser_sessions::CurrentAccountBrowserSession as Session;

#[derive(Clone, Copy)]
struct Writer {
    member: LinkMembership,
    account: Uuid,
    family: Uuid,
    generation: i64,
}

impl Writer {
    fn event(
        self,
        action: &str,
        revision: Option<Uuid>,
        attempt: Option<Uuid>,
        link: Option<Uuid>,
        outcome: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, Error> {
        let mut event = serde_json::json!({
            "action": action, "organization_id": self.member.organization_id, "target_id": self.member.membership_id,
            "account_id": self.account, "browser_family_id": self.family,
        });
        for (field, value) in
            [("connection_revision", revision), ("attempt_id", attempt), ("link_id", link)]
        {
            if let Some(value) = value {
                event[field] = serde_json::json!(value);
            }
        }
        if let Some((result, reason)) = outcome {
            event["outcome"] = result.into();
            event["reason"] = reason.into();
        }
        serde_json::to_vec(&event).map_err(|_| Error::StorageUnavailable)
    }
}

struct ActiveConnection {
    target: ConnectionTarget,
    provider: DraftLoginProvider,
    fingerprint: [u8; 32],
}

fn valid_id(id: Uuid) -> Result<(), Error> {
    scoplen_model::validate_uuid_v7(id).map_err(|_| Error::InvalidRequest)
}

macro_rules! members {
    ($store:ty,$db:ty,$begin:literal,$lock:ident,$actor:ident,$audit:ident,$member_lock:literal) => {
        impl $store {
            async fn active_link_membership(
                tx: &mut Transaction<'_, $db>,
                account: Uuid,
                organization: Uuid,
                family: Uuid,
            ) -> Result<Writer, Error> {
                valid_id(organization)?;
                let row = sqlx::query(concat!("SELECT m.id,m.auth_link_generation FROM organization_memberships m
                            JOIN organizations o ON o.id=m.organization_id WHERE o.id=$1 AND o.dissolved_at_ms IS NULL
                            AND m.account_id=$2 AND m.status='active'", $member_lock))
                            .bind(organization.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
                            .fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                Ok(Writer {
                    member: LinkMembership {
                        organization_id: organization,
                        membership_id: row_uuid(&row, "id")?,
                    },
                    generation: row.try_get("auth_link_generation")?,
                    account,
                    family,
                })
            }

            async fn member_link_writer(
                tx: &mut Transaction<'_, $db>,
                session: &Session,
                organization: Uuid,
                named: Option<Uuid>,
                writing: bool,
            ) -> Result<Writer, Error> {
                $lock(tx, &session.account_id, writing).await?;
                $actor(tx, session, 0).await?;
                let scope = if named.is_some() { Scope::AuthLinksWithdraw } else { Scope::AuthLinksSelf };
                if !scope.is_present_in(&session.scope) {
                    return Err(Error::PermissionDenied);
                }
                let writer = Self::active_link_membership(
                    tx,
                    Uuid::from_bytes(session.account_id),
                    organization,
                    Uuid::from_bytes(session.family_id),
                )
                .await?;
                let Some(target) = named else {
                    return Ok(writer);
                };
                valid_id(target)?;
                let authority = Self::read_organization_in_transaction(
                    tx,
                    &session.account_id,
                    organization.as_bytes(),
                )
                .await?;
                if !authority.membership.roles.iter().any(|role| role == "owner") {
                    return Err(Error::PermissionDenied);
                }
                Self::authorize_organization_action(tx, &authority, now_ms()?, "manage_members").await?;
                let generation = sqlx::query_scalar(
                    "SELECT auth_link_generation FROM organization_memberships
                            WHERE organization_id=$1 AND id=$2 AND status='active'",
                )
                .bind(organization.as_bytes().as_slice())
                .bind(target.as_bytes().as_slice())
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(Error::NotFound)?;
                Ok(Writer {
                    member: LinkMembership { organization_id: organization, membership_id: target },
                    generation,
                    ..writer
                })
            }

            async fn current_member_link(
                tx: &mut Transaction<'_, $db>,
                member: LinkMembership,
            ) -> Result<MemberLinkStatus, Error> {
                let row = sqlx::query("SELECT id,created_at_ms FROM organization_auth_links WHERE organization_id=$1 AND membership_id=$2")
                            .bind(member.organization_id.as_bytes().as_slice()).bind(member.membership_id.as_bytes().as_slice())
                            .fetch_optional(&mut **tx).await?;
                let link = row
                    .map(|row| -> Result<MemberLink, Error> {
                        Ok(MemberLink {
                            id: row_uuid(&row, "id")?,
                            membership: member,
                            created_at: timestamp(row.try_get("created_at_ms")?)?,
                        })
                    })
                    .transpose()?;
                Ok(MemberLinkStatus { membership: member, link })
            }

            async fn link_active_revision(
                tx: &mut Transaction<'_, $db>,
                org: Uuid,
                revision: Uuid,
            ) -> Result<ActiveConnection, Error> {
                valid_id(revision)?;
                let row = sqlx::query("SELECT revision,issuer,client_id,space_id,provider,trust_fingerprint
                            FROM organization_auth_connections WHERE organization_id=$1 AND status='active'")
                            .bind(org.as_bytes().as_slice()).fetch_optional(&mut **tx).await?.ok_or(Error::NotFound)?;
                if row_uuid(&row, "revision")? != revision {
                    return Err(Error::PreconditionFailed);
                }
                let target = ConnectionTarget {
                    issuer: row.try_get("issuer")?,
                    client_id: row.try_get("client_id")?,
                    space_id: row.try_get("space_id")?,
                };
                let provider = serde_json::from_str(row.try_get("provider")?)
                    .map_err(|_| Error::StorageUnavailable)?;
                let fingerprint = row
                    .try_get::<Vec<u8>, _>("trust_fingerprint")?
                    .try_into()
                    .map_err(|_| Error::StorageUnavailable)?;
                Ok(ActiveConnection { target, provider, fingerprint })
            }

            async fn link_fresh_deadline(
                tx: &mut Transaction<'_, $db>,
                writer: Writer,
            ) -> Result<i64, Error> {
                let created_at = sqlx::query_scalar("SELECT created_at_ms FROM account_browser_families WHERE family_id=$1 AND account_id=$2")
                            .bind(writer.family.as_bytes().as_slice()).bind(writer.account.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
                require_fresh(created_at, now_ms()?)
            }

            /// Read the current member's public link and active connection metadata.
            ///
            /// # Errors
            /// Rejects invalid browser authority, missing Membership, or storage failure.
            pub async fn self_member_link_status(
                &self,
                session: &Session,
                org: Uuid,
            ) -> Result<SelfLinkStatus, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let writer = Self::member_link_writer(&mut tx, session, org, None, false).await?;
                let status = Self::current_member_link(&mut tx, writer.member).await?;
                let connection = Self::auth_connection_head(&mut tx, org)
                    .await?
                    .filter(|head| head.status == ConnectionStatus::Active)
                    .map(|head| LinkConnection { id: head.id, target: head.target });
                let result = SelfLinkStatus { status, connection };
                result.to_json().map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                tx.commit().await?;
                Ok(result)
            }

            /// Read one active target Membership under live Owner and Cedar authority.
            ///
            /// # Errors
            /// Rejects inaccessible Memberships, insufficient authority, or storage failure.
            pub async fn named_member_link_status(
                &self,
                session: &Session,
                org: Uuid,
                named: Uuid,
            ) -> Result<MemberLinkStatus, Error> {
                let mut tx = self.pool.begin_with($begin).await?;
                let writer = Self::member_link_writer(&mut tx, session, org, Some(named), false).await?;
                let result = Self::current_member_link(&mut tx, writer.member).await?;
                result.to_json().map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                tx.commit().await?;
                Ok(result)
            }

            /// Withdraw the exact association and fence every attempt from its prior generation.
            ///
            /// # Errors
            /// Rejects absent links, stale revisions, insufficient authority and uncertain commit.
            pub async fn withdraw_member_link(
                &self,
                session: &Session,
                org: Uuid,
                named: Option<Uuid>,
                link_id: Uuid,
            ) -> Result<(), Error> {
                valid_id(link_id)?;
                let mut tx = self.pool.begin_with($begin).await?;
                let writer = Self::member_link_writer(&mut tx, session, org, named, true).await?;
                let link =
                    Self::current_member_link(&mut tx, writer.member).await?.link.ok_or(Error::NotFound)?;
                if link.id != link_id {
                    return Err(Error::PreconditionFailed);
                }
                let revision = Self::auth_connection_head(&mut tx, org).await?.map(|head| head.id);
                Self::fence_organization_auth_links(&mut tx, org, Some(writer.member.membership_id), true)
                    .await?;
                let event = writer.event(
                    "organization.auth_link_withdrawn",
                    revision,
                    None,
                    Some(link_id),
                    None,
                )?;
                $audit(&mut tx, org.into_bytes(), &event, now_ms()?)
                    .await
                    .map_err(|_| Error::StorageUnavailable)?;
                $actor(&mut tx, session, 0).await?;
                tx.commit().await.map_err(|_| Error::UpdateCommitOutcomeUnknown)
            }
        }
    };
}

members!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_actor,
    append_audit_event_in_transaction,
    ""
);
members!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_actor,
    append_audit_event_in_postgres_transaction,
    " FOR UPDATE OF o,m"
);
