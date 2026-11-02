// SPDX-License-Identifier: AGPL-3.0-only
//! Named-recipient invitations and audit-atomic team membership transitions.

use std::fmt::Write as _;

use scoplen_api::{
    organization::{
        OrganizationListQuery, parse_organization_idempotency_key, parse_organization_if_match,
    },
    team::{
        TeamAcceptanceReceipt, TeamDissolutionReceipt, TeamDissolveRequest,
        TeamInvitationAcceptRequest, TeamInvitationCreateRequest, TeamInvitationPage,
        TeamInvitationResource, TeamInvitationStatus, TeamMemberPage, TeamMemberResource,
        TeamMemberStatus, TeamMemberUpdateRequest, TeamRole,
    },
};
use scoplen_crypto::TeamInvitationVerifier;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};

use super::{
    CurrentPrincipal, OrganizationResource, OrganizationStoreError, PostgresStore, SqliteStore,
    Uuid, append_audit_event_in_postgres_transaction, append_audit_event_in_transaction,
    check_identity, lock_postgres, lock_sqlite, now_ms, postgres_principal, sqlite_principal,
    timestamp,
};

const RECEIPT_MS: i64 = 86_400_000;
const INVITATION_SELECT: &str = "SELECT i.id,i.organization_id,o.name AS organization_name,i.recipient_account_id,i.recipient_username,i.issuer_account_id,i.roles_json,i.status,i.membership_id,i.created_at_ms,CASE WHEN i.updated_at_ms>o.updated_at_ms THEN i.updated_at_ms ELSE o.updated_at_ms END AS updated_at_ms,i.expires_at_ms,i.password_verifier,i.wrong_passwords FROM organization_invitations i JOIN organizations o ON o.id=i.organization_id WHERE i.organization_id=$1 AND o.dissolved_at_ms IS NULL";
const MEMBER_SELECT: &str = "SELECT m.id,m.organization_id,m.account_id,b.username,m.roles_json,m.status,m.created_at_ms,m.updated_at_ms FROM organization_memberships m LEFT JOIN account_password_bootstrap b ON b.account_id=m.account_id WHERE m.organization_id=$1";

fn roles(text: &str) -> Result<Vec<TeamRole>, OrganizationStoreError> {
    let values: Vec<String> =
        serde_json::from_str(text).map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    values
        .iter()
        .map(|value| TeamRole::parse(value).map_err(|_| OrganizationStoreError::StorageUnavailable))
        .collect()
}

fn roles_json(values: &[TeamRole]) -> Result<String, OrganizationStoreError> {
    let mut values = values.to_vec();
    values.sort_unstable();
    serde_json::to_string(&values).map_err(|_| OrganizationStoreError::StorageUnavailable)
}

fn owner(value: &OrganizationResource) -> bool {
    value.membership.roles.iter().any(|role| role == "owner")
}

fn role_ceiling(
    actor: &OrganizationResource,
    values: &[TeamRole],
) -> Result<(), OrganizationStoreError> {
    if values.contains(&TeamRole::Owner) && !owner(actor) {
        return Err(OrganizationStoreError::PermissionDenied);
    }
    Ok(())
}

fn digest(method: &str, path: &str, body: &[u8], if_match: Option<&str>) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        b"spl-team-operation-v1".as_slice(),
        method.as_bytes(),
        path.as_bytes(),
        if_match.unwrap_or("").as_bytes(),
    ] {
        hash.update(part);
        hash.update([0]);
    }
    hash.update(body);
    hash.finalize().into()
}

fn etag(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    let mut value = String::from("\"sha256-");
    for byte in hash.finalize() {
        write!(value, "{byte:02x}").expect("String write");
    }
    value.push('"');
    value
}

fn row_id<R: Row>(row: &R, name: &str) -> Result<Uuid, OrganizationStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let bytes: [u8; 16] = row
        .try_get::<Vec<u8>, _>(name)?
        .try_into()
        .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    Ok(Uuid::from_bytes(bytes))
}

fn invitation<R: Row>(row: &R, now: i64) -> Result<TeamInvitationResource, OrganizationStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<Vec<u8>>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let expires: i64 = row.try_get("expires_at_ms")?;
    let state: String = row.try_get("status")?;
    let status = match state.as_str() {
        "pending" | "locked" if now >= expires => TeamInvitationStatus::Expired,
        _ => TeamInvitationStatus::parse(&state)
            .map_err(|_| OrganizationStoreError::StorageUnavailable)?,
    };
    let member: Option<Vec<u8>> = row.try_get("membership_id")?;
    let mut value = TeamInvitationResource {
        id: row_id(row, "id")?,
        etag: "\"pending\"".into(),
        created_at: timestamp(row.try_get("created_at_ms")?)?,
        updated_at: timestamp(row.try_get("updated_at_ms")?)?,
        organization_id: row_id(row, "organization_id")?,
        organization_name: row.try_get("organization_name")?,
        recipient_account_id: row_id(row, "recipient_account_id")?,
        recipient_username: row.try_get("recipient_username")?,
        roles: roles(&row.try_get::<String, _>("roles_json")?)?,
        issuer_account_id: row_id(row, "issuer_account_id")?,
        expires_at: timestamp(expires)?,
        status,
        membership_id: member
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(Uuid::from_bytes)
                    .map_err(|_| OrganizationStoreError::StorageUnavailable)
            })
            .transpose()?,
    };
    value.etag = etag(
        b"spl-team-invitation-resource-v1\0",
        &value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable)?,
    );
    value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    Ok(value)
}

fn member<R: Row>(row: &R) -> Result<TeamMemberResource, OrganizationStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "deprovisioned" => TeamMemberStatus::Removed,
        state => TeamMemberStatus::parse(state)
            .map_err(|_| OrganizationStoreError::StorageUnavailable)?,
    };
    let mut value = TeamMemberResource {
        id: row_id(row, "id")?,
        etag: "\"pending\"".into(),
        created_at: timestamp(row.try_get("created_at_ms")?)?,
        updated_at: timestamp(row.try_get("updated_at_ms")?)?,
        organization_id: row_id(row, "organization_id")?,
        account_id: row_id(row, "account_id")?,
        username: row.try_get("username")?,
        roles: roles(&row.try_get::<String, _>("roles_json")?)?,
        status,
    };
    value.etag = etag(
        b"spl-team-member-resource-v1\0",
        &value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable)?,
    );
    value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    Ok(value)
}

fn valid_id(id: Uuid) -> Result<(), OrganizationStoreError> {
    parse_organization_idempotency_key(&id.to_string())
        .map(|_| ())
        .map_err(|_| OrganizationStoreError::InvalidRequest)
}

macro_rules! teams {
    ($store:ty,$db:ty,$begin:literal,$lock:ident,$principal:ident,$audit:ident,$postgres:literal) => {
        impl $store {
            async fn lock_team_row(tx: &mut Transaction<'_,$db>, organization:Uuid) -> Result<bool,OrganizationStoreError> {
                let suffix=if $postgres {" FOR UPDATE"} else {""};
                let row=sqlx::query(&format!("SELECT dissolved_at_ms FROM organizations WHERE id=$1{suffix}"))
                    .bind(organization.as_bytes().as_slice()).fetch_optional(&mut **tx).await?
                    .ok_or(OrganizationStoreError::NotFound)?;
                Ok(row.try_get::<Option<i64>,_>("dissolved_at_ms")?.is_none())
            }

            async fn lock_team(tx: &mut Transaction<'_,$db>, organization:Uuid) -> Result<(),OrganizationStoreError> {
                if Self::lock_team_row(tx,organization).await? {Ok(())} else {Err(OrganizationStoreError::NotFound)}
            }

            async fn team_actor(tx:&mut Transaction<'_,$db>, expected:&CurrentPrincipal, organization:Uuid, action:&str, now:i64)
                -> Result<OrganizationResource,OrganizationStoreError> {
                let value=Self::read_organization_in_transaction(tx,&expected.account_id,organization.as_bytes()).await?;
                Self::authorize_organization_action(tx,&value,now,action).await?;
                Ok(value)
            }

            pub(super) async fn team_revision(tx:&mut Transaction<'_,$db>, organization:Uuid, now:i64) -> Result<(),OrganizationStoreError> {
                let row=sqlx::query("SELECT view_revision,updated_at_ms FROM organizations WHERE id=$1")
                    .bind(organization.as_bytes().as_slice()).fetch_one(&mut **tx).await?;
                let previous:[u8;8]=row.try_get::<Vec<u8>,_>("view_revision")?.try_into().map_err(|_| OrganizationStoreError::StorageUnavailable)?;
                let next=u64::from_be_bytes(previous).checked_add(1).ok_or(OrganizationStoreError::StorageUnavailable)?.to_be_bytes();
                let previous_time:i64=row.try_get("updated_at_ms")?;
                let updated=now.max(previous_time.checked_add(1).ok_or(OrganizationStoreError::StorageUnavailable)?);
                sqlx::query("UPDATE organizations SET view_revision=$1,updated_at_ms=$2 WHERE id=$3")
                    .bind(next.as_slice()).bind(updated).bind(organization.as_bytes().as_slice()).execute(&mut **tx).await?;
                Self::queue_organization_notification(tx,organization,u64::from_be_bytes(next)).await?;
                Ok(())
            }

            async fn team_audit(tx:&mut Transaction<'_,$db>, expected:&CurrentPrincipal, organization:Uuid, action:&str, target:Uuid, now:i64)
                -> Result<(),OrganizationStoreError> {
                let event=serde_json::to_vec(&serde_json::json!({"action":action,"account_id":Uuid::from_bytes(expected.account_id),
                    "device_id":Uuid::from_bytes(expected.device_id),"organization_id":organization,"target_id":target,"at_ms":now}))
                    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
                $audit(tx,organization.into_bytes(),&event,now).await.map(|_|()).map_err(|_| OrganizationStoreError::StorageUnavailable)
            }

            async fn team_receipt(tx:&mut Transaction<'_,$db>, account:&[u8;16], key:Uuid, expected_digest:&[u8;32], now:i64)
                -> Result<Option<Vec<u8>>,OrganizationStoreError> {
                let row=sqlx::query("SELECT request_digest,response_json FROM organization_operation_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3")
                    .bind(account.as_slice()).bind(key.as_bytes().as_slice()).bind(now).fetch_optional(&mut **tx).await?;
                row.map(|row| {
                    if row.try_get::<Vec<u8>,_>("request_digest")?.as_slice()!=expected_digest.as_slice() {return Err(OrganizationStoreError::Conflict);}
                    Ok(row.try_get("response_json")?)
                }).transpose()
            }

            #[allow(clippy::too_many_arguments)]
            async fn save_team_receipt(tx:&mut Transaction<'_,$db>, account:&[u8;16], organization:Uuid,key:Uuid,operation:i64,
                request_digest:&[u8;32],invitation_id:Option<Uuid>,response:&[u8],now:i64) -> Result<(),OrganizationStoreError> {
                sqlx::query("DELETE FROM organization_operation_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3")
                    .bind(account.as_slice()).bind(key.as_bytes().as_slice()).bind(now).execute(&mut **tx).await?;
                sqlx::query("INSERT INTO organization_operation_receipts (account_id,idempotency_key,organization_id,operation,request_digest,invitation_id,response_json,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                    .bind(account.as_slice()).bind(key.as_bytes().as_slice()).bind(organization.as_bytes().as_slice())
                    .bind(operation).bind(request_digest.as_slice()).bind(invitation_id.map(|id|id.as_bytes().to_vec()))
                    .bind(response).bind(now).bind(now.checked_add(RECEIPT_MS).ok_or(OrganizationStoreError::StorageUnavailable)?)
                    .execute(&mut **tx).await?;
                Ok(())
            }

            async fn invitation_in_tx(tx:&mut Transaction<'_,$db>,organization:Uuid,id:Uuid,now:i64) -> Result<TeamInvitationResource,OrganizationStoreError> {
                let row=sqlx::query(&format!("{INVITATION_SELECT} AND i.id=$2"))
                    .bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
                    .fetch_optional(&mut **tx).await?.ok_or(OrganizationStoreError::NotFound)?;
                invitation(&row,now)
            }

            async fn member_in_tx(tx:&mut Transaction<'_,$db>,organization:Uuid,id:Uuid) -> Result<TeamMemberResource,OrganizationStoreError> {
                let row=sqlx::query(&format!("{MEMBER_SELECT} AND m.id=$2"))
                    .bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
                    .fetch_optional(&mut **tx).await?.ok_or(OrganizationStoreError::NotFound)?;
                member(&row)
            }

            /// Create a fixed-recipient invitation after current Cedar and role-grant checks.
            /// # Errors
            /// Returns bounded authorization, eligibility, conflict, storage or unknown-commit classes.
            #[allow(clippy::too_many_lines)]
            pub async fn create_team_invitation(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,key:Uuid,request:&TeamInvitationCreateRequest)
                -> Result<TeamInvitationResource,OrganizationStoreError> {
                valid_id(organization)?; valid_id(key)?;
                let canonical=request.to_json().map_err(|_| OrganizationStoreError::InvalidRequest)?;
                let request_digest=digest("POST",&format!("/api/v1/orgs/{organization}/invitations"),canonical.as_bytes(),None);
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                let now=now_ms()?;
                let actor=Self::team_actor(&mut tx,expected,organization,"manage_members",now).await?;
                if Self::team_receipt(&mut tx,&expected.account_id,key,&request_digest,now).await?.is_some() {
                    let value=Self::invitation_in_tx(&mut tx,organization,request.invitation_id,now).await?;
                    tx.commit().await?; return Ok(value);
                }
                role_ceiling(&actor,&request.roles)?;
                let recipient=sqlx::query("SELECT b.account_id,m.status FROM account_password_bootstrap b JOIN identity_accounts a ON a.account_id=b.account_id LEFT JOIN organization_memberships m ON m.account_id=b.account_id AND m.organization_id=$1 WHERE b.username=$2")
                    .bind(organization.as_bytes().as_slice()).bind(&request.recipient_username).fetch_optional(&mut *tx).await?
                    .ok_or(OrganizationStoreError::InvitationDenied)?;
                let status:Option<String>=recipient.try_get("status")?;
                if status.is_some_and(|status|status!="deprovisioned") {return Err(OrganizationStoreError::InvitationDenied);}
                let recipient:Vec<u8>=recipient.try_get("account_id")?;
                let exists=sqlx::query("SELECT id FROM organization_invitations WHERE organization_id=$1 AND id=$2")
                    .bind(organization.as_bytes().as_slice()).bind(request.invitation_id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?;
                if exists.is_some() {return Err(OrganizationStoreError::Conflict);}
                sqlx::query("INSERT INTO organization_invitations (organization_id,id,recipient_account_id,recipient_username,issuer_account_id,roles_json,password_verifier,status,created_at_ms,updated_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$8,$9)")
                    .bind(organization.as_bytes().as_slice()).bind(request.invitation_id.as_bytes().as_slice()).bind(recipient)
                    .bind(&request.recipient_username).bind(expected.account_id.as_slice()).bind(roles_json(&request.roles)?)
                    .bind(request.password_verifier.as_bytes().as_slice()).bind(now)
                    .bind(now.checked_add(RECEIPT_MS).ok_or(OrganizationStoreError::StorageUnavailable)?)
                    .execute(&mut *tx).await?;
                Self::team_audit(&mut tx,expected,organization,"organization.invitation_created",request.invitation_id,now).await?;
                Self::save_team_receipt(&mut tx,&expected.account_id,organization,key,1,&request_digest,Some(request.invitation_id),&[],now).await?;
                let value=Self::invitation_in_tx(&mut tx,organization,request.invitation_id,now).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|OrganizationStoreError::CommitOutcomeUnknown)?;
                Ok(value)
            }

            /// Preview only the fixed recipient, or a currently authorized administrator.
            /// `administrative_scope` must come from the verified access token.
            /// # Errors
            /// Foreign recipients and unavailable teams share `NotFound`.
            #[allow(clippy::too_many_arguments)]
            pub async fn read_team_invitation(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,id:Uuid,administrative_scope:bool,recipient_scope:bool)
                -> Result<TeamInvitationResource,OrganizationStoreError> {
                let mut tx=self.pool.begin().await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                let now=now_ms()?;
                let value=Self::invitation_in_tx(&mut tx,organization,id,now).await?;
                if value.recipient_account_id.as_bytes()!=&expected.account_id || !recipient_scope {
                    if !administrative_scope {return Err(OrganizationStoreError::NotFound);}
                    Self::team_actor(&mut tx,expected,organization,"manage_members",now).await?;
                }
                tx.commit().await?; Ok(value)
            }

            /// List a bounded administrative invitation page under current membership.
            /// # Errors
            /// Returns current authentication, Cedar, query or storage failures.
            pub async fn list_team_invitations(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,query:OrganizationListQuery)
                -> Result<TeamInvitationPage,OrganizationStoreError> {
                query.validate().map_err(|_|OrganizationStoreError::InvalidRequest)?;
                let mut tx=self.pool.begin().await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                let now=now_ms()?;
                Self::team_actor(&mut tx,expected,organization,"manage_members",now).await?;
                let cursor=query.cursor.unwrap_or(Uuid::nil());
                let rows=sqlx::query(&format!("{INVITATION_SELECT} AND i.id>$2 ORDER BY i.id LIMIT $3"))
                    .bind(organization.as_bytes().as_slice()).bind(cursor.as_bytes().as_slice()).bind(i64::from(query.limit)+1).fetch_all(&mut *tx).await?;
                let items=rows.iter().take(usize::from(query.limit)).map(|row|invitation(row,now)).collect::<Result<Vec<_>,_>>()?;
                let next_cursor=if rows.len()>usize::from(query.limit) {items.last().map(|value|value.id)} else {None};
                let page=TeamInvitationPage{items,next_cursor}; page.to_json().map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                tx.commit().await?; Ok(page)
            }

            /// Accept once; exact historical confirmation cannot restore removed authority.
            /// # Errors
            /// Returns common foreign-resource, static denial, conflict or storage classes.
            #[allow(clippy::too_many_arguments,clippy::too_many_lines)]
            pub async fn accept_team_invitation(&self,expected:&CurrentPrincipal,expires_at:u64,origin:&str,organization:Uuid,id:Uuid,key:Uuid,request:&TeamInvitationAcceptRequest)
                -> Result<TeamAcceptanceReceipt,OrganizationStoreError> {
                valid_id(organization)?; valid_id(id)?; valid_id(key)?;
                let canonical=request.to_json().map_err(|_|OrganizationStoreError::InvalidRequest)?;
                let request_digest=digest("POST",&format!("/api/v1/orgs/{organization}/invitations/{id}/accept"),canonical.as_bytes(),None);
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                let now=now_ms()?;
                if let Some(response)=Self::team_receipt(&mut tx,&expected.account_id,key,&request_digest,now).await? {
                    let receipt=TeamAcceptanceReceipt::from_json(&response).map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                    tx.commit().await?; return Ok(receipt);
                }
                let active=Self::lock_team_row(&mut tx,organization).await?;
                let now=now_ms()?;
                if let Some(response)=Self::team_receipt(&mut tx,&expected.account_id,key,&request_digest,now).await? {
                    let receipt=TeamAcceptanceReceipt::from_json(&response).map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                    check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                    tx.commit().await?; return Ok(receipt);
                }
                if !active {return Err(OrganizationStoreError::NotFound);}
                let row=sqlx::query(&format!("{INVITATION_SELECT} AND i.id=$2"))
                    .bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await?
                    .ok_or(OrganizationStoreError::NotFound)?;
                let value=invitation(&row,now)?;
                if value.recipient_account_id.as_bytes()!=&expected.account_id {return Err(OrganizationStoreError::NotFound);}
                if value.status!=TeamInvitationStatus::Pending {return Err(OrganizationStoreError::InvitationDenied);}
                let issuer_denied=|error|match error {OrganizationStoreError::PermissionDenied|OrganizationStoreError::NotFound=>OrganizationStoreError::InvitationDenied,other=>other};
                let actor=Self::read_organization_in_transaction(&mut tx,value.issuer_account_id.as_bytes(),organization.as_bytes()).await.map_err(issuer_denied)?;
                Self::authorize_organization_action(&mut tx,&actor,now,"manage_members").await.map_err(issuer_denied)?;
                role_ceiling(&actor,&value.roles).map_err(|_|OrganizationStoreError::InvitationDenied)?;
                let verifier:[u8;32]=row.try_get::<Vec<u8>,_>("password_verifier")?.try_into().map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                let submitted=request.password.verifier(origin,&organization,&id).map_err(|_|OrganizationStoreError::InvalidRequest)?;
                if submitted!=TeamInvitationVerifier::from_bytes(verifier) {
                    let attempts:i64=row.try_get("wrong_passwords")?;
                    let attempts=attempts.checked_add(1).filter(|n|*n<=5).ok_or(OrganizationStoreError::StorageUnavailable)?;
                    sqlx::query("UPDATE organization_invitations SET wrong_passwords=$1,status=$2,updated_at_ms=$3 WHERE organization_id=$4 AND id=$5")
                        .bind(attempts).bind(if attempts==5 {"locked"} else {"pending"}).bind(now)
                        .bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                    check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                    tx.commit().await.map_err(|_|OrganizationStoreError::CommitOutcomeUnknown)?;
                    return Err(OrganizationStoreError::InvitationDenied);
                }
                let previous=sqlx::query("SELECT id,status,updated_at_ms FROM organization_memberships WHERE organization_id=$1 AND account_id=$2")
                    .bind(organization.as_bytes().as_slice()).bind(expected.account_id.as_slice()).fetch_optional(&mut *tx).await?;
                let membership=if let Some(previous)=previous {
                    if previous.try_get::<String,_>("status")?!="deprovisioned" {return Err(OrganizationStoreError::InvitationDenied);}
                    let membership=row_id(&previous,"id")?;
                    let previous_time:i64=previous.try_get("updated_at_ms")?;
                    let updated=now.max(previous_time.checked_add(1).ok_or(OrganizationStoreError::StorageUnavailable)?);
                    sqlx::query("UPDATE organization_memberships SET status='active',roles_json=$1,updated_at_ms=$2 WHERE id=$3")
                        .bind(roles_json(&value.roles)?).bind(updated).bind(membership.as_bytes().as_slice()).execute(&mut *tx).await?;
                    membership
                } else {
                    let membership=Uuid::now_v7();
                    sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active',$4,$5,$5)")
                        .bind(membership.as_bytes().as_slice()).bind(organization.as_bytes().as_slice()).bind(expected.account_id.as_slice())
                        .bind(roles_json(&value.roles)?).bind(now).execute(&mut *tx).await?;
                    membership
                };
                sqlx::query("UPDATE organization_invitations SET status='accepted',membership_id=$1,updated_at_ms=$2 WHERE organization_id=$3 AND id=$4")
                    .bind(membership.as_bytes().as_slice()).bind(now).bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                Self::team_revision(&mut tx,organization,now).await?;
                Self::team_audit(&mut tx,expected,organization,"organization.invitation_accepted",id,now).await?;
                Self::queue_memberships_notification(&mut tx,expected.account_id).await?;
                let receipt=TeamAcceptanceReceipt{invitation_id:id,organization_id:organization,account_id:Uuid::from_bytes(expected.account_id),membership_id:membership,accepted_at:timestamp(now)?};
                let response=receipt.to_json().map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                Self::save_team_receipt(&mut tx,&expected.account_id,organization,key,2,&request_digest,Some(id),&response,now).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|OrganizationStoreError::CommitOutcomeUnknown)?;
                Ok(receipt)
            }

            /// Revoke a pending or locked invitation after exact current preconditions.
            /// # Errors
            /// Returns bounded current authorization, precondition, conflict or storage errors.
            pub async fn revoke_team_invitation(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,id:Uuid,if_match:&str)
                -> Result<(),OrganizationStoreError> {
                parse_organization_if_match(Some(if_match)).map_err(|_|OrganizationStoreError::InvalidRequest)?;
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                let now=now_ms()?;
                Self::team_actor(&mut tx,expected,organization,"manage_members",now).await?;
                let current=Self::invitation_in_tx(&mut tx,organization,id,now).await?;
                if current.etag!=if_match {return Err(OrganizationStoreError::PreconditionFailed);}
                match current.status {
                    TeamInvitationStatus::Revoked=>{tx.commit().await?; return Ok(());},
                    TeamInvitationStatus::Pending|TeamInvitationStatus::Locked=>{},
                    _=>return Err(OrganizationStoreError::Conflict),
                }
                sqlx::query("UPDATE organization_invitations SET status='revoked',updated_at_ms=$1 WHERE organization_id=$2 AND id=$3")
                    .bind(now).bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                Self::team_audit(&mut tx,expected,organization,"organization.invitation_revoked",id,now).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|OrganizationStoreError::UpdateCommitOutcomeUnknown)?; Ok(())
            }

            /// Read one tenant-bound member through current administrative Cedar permission.
            /// # Errors
            /// Returns current authentication, tenant, permission or representation errors.
            pub async fn read_team_member(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,id:Uuid)
                -> Result<TeamMemberResource,OrganizationStoreError> {
                let mut tx=self.pool.begin().await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                Self::team_actor(&mut tx,expected,organization,"manage_members",now_ms()?).await?;
                let value=Self::member_in_tx(&mut tx,organization,id).await?;
                tx.commit().await?; Ok(value)
            }

            /// List one bounded current administrative member page.
            /// # Errors
            /// Returns current authentication, tenant, permission, query or storage errors.
            pub async fn list_team_members(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,query:OrganizationListQuery)
                -> Result<TeamMemberPage,OrganizationStoreError> {
                query.validate().map_err(|_|OrganizationStoreError::InvalidRequest)?;
                let mut tx=self.pool.begin().await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                Self::team_actor(&mut tx,expected,organization,"manage_members",now_ms()?).await?;
                let cursor=query.cursor.unwrap_or(Uuid::nil());
                let rows=sqlx::query(&format!("{MEMBER_SELECT} AND m.id>$2 ORDER BY m.id LIMIT $3"))
                    .bind(organization.as_bytes().as_slice()).bind(cursor.as_bytes().as_slice()).bind(i64::from(query.limit)+1).fetch_all(&mut *tx).await?;
                let items=rows.iter().take(usize::from(query.limit)).map(member).collect::<Result<Vec<_>,_>>()?;
                let next_cursor=if rows.len()>usize::from(query.limit) {items.last().map(|value|value.id)} else {None};
                let page=TeamMemberPage{items,next_cursor}; page.to_json().map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                tx.commit().await?; Ok(page)
            }

            /// Change a member or leave the team, preserving an active Owner and exact `ETags`.
            /// `administrative_scope` must come from the verified access token; `None` removes.
            /// # Errors
            /// Returns current authentication, tenant, role, precondition, conflict or storage errors.
            #[allow(clippy::too_many_arguments,clippy::too_many_lines)]
            pub async fn change_team_member(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,id:Uuid,if_match:&str,
                administrative_scope:bool,recipient_scope:bool,request:Option<&TeamMemberUpdateRequest>) -> Result<Option<TeamMemberResource>,OrganizationStoreError> {
                parse_organization_if_match(Some(if_match)).map_err(|_|OrganizationStoreError::InvalidRequest)?;
                if let Some(request)=request {request.validate().map_err(|_|OrganizationStoreError::InvalidRequest)?;}
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                Self::lock_team(&mut tx,organization).await?;
                let now=now_ms()?;
                let current=Self::member_in_tx(&mut tx,organization,id).await?;
                let self_leave=request.is_none() && recipient_scope && current.account_id.as_bytes()==&expected.account_id;
                let caller=if self_leave && current.status!=TeamMemberStatus::Active {
                    if current.status==TeamMemberStatus::Removed {return Err(OrganizationStoreError::NotFound);}
                    None
                } else {
                    Some(Self::read_organization_in_transaction(&mut tx,&expected.account_id,organization.as_bytes()).await?)
                };
                if !self_leave {
                    if !administrative_scope {return Err(OrganizationStoreError::NotFound);}
                    Self::authorize_organization_action(&mut tx,caller.as_ref().expect("current administrative membership"),now,"manage_members").await?;
                }
                let next_roles=request.map_or(current.roles.as_slice(),|request|request.roles.as_slice());
                if !self_leave && (current.roles.contains(&TeamRole::Owner)||next_roles.contains(&TeamRole::Owner))
                    && !owner(caller.as_ref().expect("current administrative membership")) {
                    return Err(OrganizationStoreError::PermissionDenied);
                }
                if current.etag!=if_match && !(self_leave && caller.as_ref().is_some_and(|value|value.etag==if_match)) {return Err(OrganizationStoreError::PreconditionFailed);}
                let next_status=request.map_or(TeamMemberStatus::Removed,|request|request.status);
                if request.is_some() && current.status==TeamMemberStatus::Removed {return Err(OrganizationStoreError::Conflict);}
                let mut old_roles=current.roles.clone(); old_roles.sort_unstable();
                let mut sorted_next=next_roles.to_vec(); sorted_next.sort_unstable();
                if old_roles==sorted_next && current.status==next_status {
                    tx.commit().await?; return Ok(request.map(|_|current));
                }
                if current.status==TeamMemberStatus::Active && current.roles.contains(&TeamRole::Owner)
                    && (next_status!=TeamMemberStatus::Active || !next_roles.contains(&TeamRole::Owner)) {
                    let rows=sqlx::query("SELECT roles_json FROM organization_memberships WHERE organization_id=$1 AND status='active' AND id<>$2")
                        .bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_all(&mut *tx).await?;
                    let mut another_owner=false;
                    for row in rows {another_owner |= roles(&row.try_get::<String,_>("roles_json")?)?.contains(&TeamRole::Owner);}
                    if !another_owner {return Err(OrganizationStoreError::Conflict);}
                }
                let status=match next_status {TeamMemberStatus::Active=>"active",TeamMemberStatus::Suspended=>"suspended",TeamMemberStatus::Removed=>"deprovisioned"};
                sqlx::query("UPDATE organization_memberships SET status=$1,roles_json=$2,updated_at_ms=CASE WHEN updated_at_ms>=$3 THEN updated_at_ms+1 ELSE $3 END WHERE organization_id=$4 AND id=$5")
                    .bind(status).bind(roles_json(next_roles)?).bind(now).bind(organization.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).execute(&mut *tx).await?;
                if next_status!=TeamMemberStatus::Active {Self::clear_organization_groups(&mut tx,organization,Some(id),now).await?;}
                Self::team_revision(&mut tx,organization,now).await?;
                Self::team_audit(&mut tx,expected,organization,if request.is_some() {"organization.member_updated"} else {"organization.member_removed"},id,now).await?;
                Self::queue_memberships_notification(&mut tx,current.account_id.into_bytes()).await?;
                let result=if request.is_some() {Some(Self::member_in_tx(&mut tx,organization,id).await?)} else {None};
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|OrganizationStoreError::UpdateCommitOutcomeUnknown)?; Ok(result)
            }

            /// Disable a team atomically, retaining Account identities, Personal data and audit.
            /// Exact historical confirmation is checked before the dissolved team's state.
            /// # Errors
            /// Returns bounded current authorization, echo/precondition, receipt or storage errors.
            #[allow(clippy::too_many_arguments)]
            pub async fn dissolve_team(&self,expected:&CurrentPrincipal,expires_at:u64,organization:Uuid,key:Uuid,if_match:&str,request:&TeamDissolveRequest)
                -> Result<TeamDissolutionReceipt,OrganizationStoreError> {
                valid_id(organization)?; valid_id(key)?;
                parse_organization_if_match(Some(if_match)).map_err(|_|OrganizationStoreError::InvalidRequest)?;
                if request.organization_id!=organization {return Err(OrganizationStoreError::InvalidRequest);}
                let canonical=request.to_json().map_err(|_|OrganizationStoreError::InvalidRequest)?;
                let request_digest=digest("POST",&format!("/api/v1/orgs/{organization}/dissolve"),&canonical,Some(if_match));
                let mut tx=self.pool.begin_with($begin).await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                let now=now_ms()?;
                if let Some(response)=Self::team_receipt(&mut tx,&expected.account_id,key,&request_digest,now).await? {
                    let receipt=TeamDissolutionReceipt::from_json(&response).map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                    tx.commit().await?; return Ok(receipt);
                }
                let active=Self::lock_team_row(&mut tx,organization).await?;
                let now=now_ms()?;
                if let Some(response)=Self::team_receipt(&mut tx,&expected.account_id,key,&request_digest,now).await? {
                    let receipt=TeamDissolutionReceipt::from_json(&response).map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                    check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                    tx.commit().await?; return Ok(receipt);
                }
                if !active {return Err(OrganizationStoreError::NotFound);}
                let actor=Self::team_actor(&mut tx,expected,organization,"manage_organization",now).await?;
                if !owner(&actor) {return Err(OrganizationStoreError::PermissionDenied);}
                if actor.etag!=if_match {return Err(OrganizationStoreError::PreconditionFailed);}
                let accounts=sqlx::query_scalar::<_,Vec<u8>>("SELECT account_id FROM organization_memberships WHERE organization_id=$1 AND status='active'")
                    .bind(organization.as_bytes().as_slice()).fetch_all(&mut *tx).await?;
                for account in accounts {Self::queue_memberships_notification(&mut tx,account.try_into().map_err(|_|OrganizationStoreError::StorageUnavailable)?).await?;}
                Self::team_revision(&mut tx,organization,now).await?;
                sqlx::query("UPDATE organizations SET dissolved_at_ms=$1 WHERE id=$2")
                    .bind(now).bind(organization.as_bytes().as_slice()).execute(&mut *tx).await?;
                sqlx::query("UPDATE organization_memberships SET status='deprovisioned',updated_at_ms=CASE WHEN updated_at_ms>=$1 THEN updated_at_ms+1 ELSE $1 END WHERE organization_id=$2 AND status<>'deprovisioned'")
                    .bind(now).bind(organization.as_bytes().as_slice()).execute(&mut *tx).await?;
                Self::clear_organization_groups(&mut tx,organization,None,now).await?;
                sqlx::query("UPDATE organization_invitations SET status='revoked',updated_at_ms=$1 WHERE organization_id=$2 AND status IN ('pending','locked')")
                    .bind(now).bind(organization.as_bytes().as_slice()).execute(&mut *tx).await?;
                Self::team_audit(&mut tx,expected,organization,"organization.dissolved",organization,now).await?;
                let receipt=TeamDissolutionReceipt{organization_id:organization,dissolved_at:timestamp(now)?};
                let response=receipt.to_json().map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                Self::save_team_receipt(&mut tx,&expected.account_id,organization,key,3,&request_digest,None,&response,now).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                tx.commit().await.map_err(|_|OrganizationStoreError::CommitOutcomeUnknown)?; Ok(receipt)
            }
        }
    };
}

teams!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_principal,
    append_audit_event_in_transaction,
    false
);
teams!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_principal,
    append_audit_event_in_postgres_transaction,
    true
);
