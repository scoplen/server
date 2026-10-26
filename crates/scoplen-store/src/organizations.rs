// SPDX-License-Identifier: AGPL-3.0-only
//! Account-owned team discovery and atomic initial-owner creation.

use std::fmt::Write as _;

use scoplen_api::organization::{
    ORGANIZATION_CREATION_RECEIPT_SECONDS, OrganizationCreateRequest, OrganizationListQuery,
    OrganizationMembership, OrganizationPage, OrganizationResource,
};
use scoplen_crypto::{DeviceOrganizationSnapshot, MAX_DEVICE_ACCESS_TOKEN_BYTES};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Sqlite, Transaction};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    PostgresStore, SqliteStore,
    audit::{append_audit_event_in_postgres_transaction, append_audit_event_in_transaction},
    device_authentication::{
        CurrentPrincipal, DeviceAuthenticationError, load_postgres_principal,
        load_sqlite_principal, lock_postgres_account_key_state,
    },
};

mod name;

/// Fixed public classes without submitted names, credentials or database diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrganizationStoreError {
    #[error("invalid organization request")]
    InvalidRequest,
    #[error("current device authentication is required")]
    AuthenticationRequired,
    #[error("organization creation is disabled")]
    CreationDisabled,
    #[error("organization permission denied")]
    PermissionDenied,
    #[error("organization precondition failed")]
    PreconditionFailed,
    #[error("organization not found")]
    NotFound,
    #[error("organization creation conflicts with the original request")]
    Conflict,
    #[error("organization storage is unavailable")]
    StorageUnavailable,
    #[error("organization creation commit outcome is unknown")]
    CommitOutcomeUnknown,
    #[error("organization update commit outcome is unknown")]
    UpdateCommitOutcomeUnknown,
}

impl From<sqlx::Error> for OrganizationStoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl From<DeviceAuthenticationError> for OrganizationStoreError {
    fn from(error: DeviceAuthenticationError) -> Self {
        match error {
            DeviceAuthenticationError::Denied { .. } => Self::AuthenticationRequired,
            _ => Self::StorageUnavailable,
        }
    }
}

fn now_ms() -> Result<i64, OrganizationStoreError> {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .ok()
        .filter(|now| *now > 0)
        .ok_or(OrganizationStoreError::StorageUnavailable)
}

fn check_identity(
    current: Option<CurrentPrincipal>,
    expected: &CurrentPrincipal,
    expires_at: u64,
) -> Result<(), OrganizationStoreError> {
    let current = current.ok_or(OrganizationStoreError::AuthenticationRequired)?;
    let now = u64::try_from(now_ms()?.div_euclid(1_000))
        .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    if current.account_id != expected.account_id
        || current.device_id != expected.device_id
        || current.jkt != expected.jkt
        || now >= expires_at
    {
        return Err(OrganizationStoreError::AuthenticationRequired);
    }
    Ok(())
}

fn timestamp(ms: i64) -> Result<String, OrganizationStoreError> {
    if ms <= 0 {
        return Err(OrganizationStoreError::StorageUnavailable);
    }
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .ok_or(OrganizationStoreError::StorageUnavailable)
}

fn resource<R: Row>(row: &R) -> Result<OrganizationResource, OrganizationStoreError>
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    Vec<u8>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    String: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let id = |name: &str| -> Result<Uuid, OrganizationStoreError> {
        let bytes: [u8; 16] = row
            .try_get::<Vec<u8>, _>(name)?
            .try_into()
            .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
        Ok(Uuid::from_bytes(bytes))
    };
    let roles_json: String = row.try_get("roles_json")?;
    let mut value = OrganizationResource {
        id: id("id")?,
        etag: "\"pending\"".into(),
        created_at: timestamp(row.try_get("created_at_ms")?)?,
        updated_at: timestamp(row.try_get("updated_at_ms")?)?,
        name: row.try_get("name")?,
        membership: OrganizationMembership {
            id: id("membership_id")?,
            account_id: id("account_id")?,
            roles: serde_json::from_str(&roles_json)
                .map_err(|_| OrganizationStoreError::StorageUnavailable)?,
        },
    };
    let mut hash = Sha256::new();
    hash.update(b"spl-organization-resource-v1\0");
    hash.update(value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable)?);
    let mut etag = String::from("\"sha256-");
    for byte in hash.finalize() {
        write!(etag, "{byte:02x}").expect("String write");
    }
    etag.push('"');
    value.etag = etag;
    value.to_json().map_err(|_| OrganizationStoreError::StorageUnavailable)?;
    Ok(value)
}

async fn lock_sqlite(
    _: &mut Transaction<'_, Sqlite>,
    _: &[u8; 16],
    _: bool,
) -> Result<(), OrganizationStoreError> {
    Ok(())
}

async fn lock_postgres(
    tx: &mut Transaction<'_, Postgres>,
    account: &[u8; 16],
    creation: bool,
) -> Result<(), OrganizationStoreError> {
    lock_postgres_account_key_state(tx, account).await?;
    if creation {
        sqlx::query("SELECT account_id FROM identity_accounts WHERE account_id=$1 FOR UPDATE")
            .bind(account.as_slice())
            .fetch_optional(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn sqlite_principal(
    tx: &mut Transaction<'_, Sqlite>,
    device: [u8; 16],
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    load_sqlite_principal(tx, device).await
}

async fn postgres_principal(
    tx: &mut Transaction<'_, Postgres>,
    device: [u8; 16],
) -> Result<Option<CurrentPrincipal>, DeviceAuthenticationError> {
    load_postgres_principal(tx, device, true).await
}

macro_rules! organizations {
    ($store:ty, $db:ty, $begin:literal, $lock:ident, $principal:ident, $audit:ident, $snapshot:ident, $postgres:literal) => {
        impl $store {
            /// Retire at most 100 expired creation receipts without changing team state.
            ///
            /// # Errors
            /// Returns a fixed storage error; a count is disclosed only after confirmed commit.
            pub async fn cleanup_organization_creation_receipts(
                &self,
            ) -> Result<u64, OrganizationStoreError> {
                let mut tx = self.pool.begin_with($begin).await?;
                let now = now_ms()?;
                let removed = sqlx::query("DELETE FROM organization_creation_receipts WHERE (account_id,idempotency_key) IN (SELECT account_id,idempotency_key FROM organization_creation_receipts WHERE expires_at_ms<=$1 ORDER BY expires_at_ms LIMIT 100) AND expires_at_ms<=$1")
                    .bind(now).execute(&mut *tx).await?.rows_affected();
                tx.commit().await?;
                Ok(removed)
            }

            /// Atomically create a team, its sole initial owner, audit and 24-hour receipt.
            /// Exact same-Account confirmation requires current membership and adds no audit.
            ///
            /// # Errors
            /// Returns a fixed authentication, policy, conflict, storage or uncertain-commit class.
            pub async fn create_organization(
                &self,
                expected: &CurrentPrincipal,
                expires_at: u64,
                allow_creation: bool,
                key: Uuid,
                request: &OrganizationCreateRequest,
            ) -> Result<OrganizationResource, OrganizationStoreError> {
                scoplen_api::organization::parse_organization_idempotency_key(&key.to_string())
                    .map_err(|_| OrganizationStoreError::InvalidRequest)?;
                let canonical = request.to_json().map_err(|_| OrganizationStoreError::InvalidRequest)?;
                let mut digest = Sha256::new();
                digest.update(b"spl-organization-create-v1\0POST\0/api/v1/orgs\0");
                digest.update(canonical);
                let digest: [u8; 32] = digest.finalize().into();
                let mut tx = self.pool.begin_with($begin).await?;
                $lock(&mut tx, &expected.account_id, true).await?;
                check_identity($principal(&mut tx, expected.device_id).await?, expected, expires_at)?;
                let now = now_ms()?;
                let receipt = sqlx::query("SELECT organization_id,request_digest FROM organization_creation_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms>$3")
                    .bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(now)
                    .fetch_optional(&mut *tx).await?;
                if let Some(receipt) = receipt {
                    if receipt.try_get::<Vec<u8>,_>("request_digest")?.as_slice()!=digest.as_slice() {
                        return Err(OrganizationStoreError::Conflict);
                    }
                    let organization: Vec<u8> = receipt.try_get("organization_id")?;
                    let value = Self::read_organization_in_transaction(&mut tx, &expected.account_id, &organization).await?;
                    tx.commit().await?;
                    return Ok(value);
                }
                if !allow_creation {
                    return Err(OrganizationStoreError::CreationDisabled);
                }
                sqlx::query("DELETE FROM organization_creation_receipts WHERE account_id=$1 AND idempotency_key=$2 AND expires_at_ms<=$3")
                    .bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice()).bind(now)
                    .execute(&mut *tx).await?;
                let organization=Uuid::now_v7();
                let membership=Uuid::now_v7();
                sqlx::query("INSERT INTO organizations (id,name,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$3)")
                    .bind(organization.as_bytes().as_slice()).bind(&request.name).bind(now)
                    .execute(&mut *tx).await?;
                sqlx::query("INSERT INTO organization_memberships (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,'active','[\"owner\"]',$4,$4)")
                    .bind(membership.as_bytes().as_slice()).bind(organization.as_bytes().as_slice())
                    .bind(expected.account_id.as_slice()).bind(now).execute(&mut *tx).await?;
                let event=serde_json::to_vec(&serde_json::json!({
                    "action":"organization.created", "account_id":Uuid::from_bytes(expected.account_id),
                    "device_id":Uuid::from_bytes(expected.device_id),"organization_id":organization,
                    "membership_id":membership,"created_at_ms":now,
                })).map_err(|_| OrganizationStoreError::StorageUnavailable)?;
                $audit(&mut tx,organization.into_bytes(),&event,now).await
                    .map_err(|_| OrganizationStoreError::StorageUnavailable)?;
                let expires=now.checked_add(i64::try_from(ORGANIZATION_CREATION_RECEIPT_SECONDS)
                    .map_err(|_| OrganizationStoreError::StorageUnavailable)?.checked_mul(1000)
                    .ok_or(OrganizationStoreError::StorageUnavailable)?)
                    .ok_or(OrganizationStoreError::StorageUnavailable)?;
                sqlx::query("INSERT INTO organization_creation_receipts (account_id,idempotency_key,organization_id,request_digest,created_at_ms,expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6)")
                    .bind(expected.account_id.as_slice()).bind(key.as_bytes().as_slice())
                    .bind(organization.as_bytes().as_slice()).bind(digest.as_slice()).bind(now).bind(expires)
                    .execute(&mut *tx).await?;
                let value=Self::read_organization_in_transaction(&mut tx,&expected.account_id,organization.as_bytes()).await?;
                check_identity($principal(&mut tx, expected.device_id).await?, expected, expires_at)?;
                tx.commit().await.map_err(|_| OrganizationStoreError::CommitOutcomeUnknown)?;
                Ok(value)
            }

            async fn read_organization_in_transaction(
                tx:&mut Transaction<'_,$db>, account:&[u8;16], organization:&[u8],
            )->Result<OrganizationResource,OrganizationStoreError>{
                let length=if $postgres {"octet_length(o.name)"}else{"length(CAST(o.name AS BLOB))"};
                let query=format!("SELECT o.id,CASE WHEN {length} BETWEEN 1 AND 128 THEN o.name ELSE NULL END AS name,o.created_at_ms,m.id AS membership_id,m.account_id,m.roles_json,CASE WHEN o.updated_at_ms>m.updated_at_ms THEN o.updated_at_ms ELSE m.updated_at_ms END AS updated_at_ms FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id WHERE o.id=$1 AND m.account_id=$2 AND m.status='active'");
                let row=sqlx::query(&query).bind(organization).bind(account.as_slice())
                    .fetch_optional(&mut **tx).await?.ok_or(OrganizationStoreError::NotFound)?;
                resource(&row)
            }

            /// Read the caller's current team identity without disclosing any other member.
            ///
            /// # Errors
            /// Foreign, absent and inactive memberships return the same `NotFound` class.
            pub async fn read_organization(
                &self, expected:&CurrentPrincipal, expires_at:u64, organization:Uuid,
            )->Result<OrganizationResource,OrganizationStoreError>{
                let mut tx=self.pool.begin().await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                let value=Self::read_organization_in_transaction(&mut tx,&expected.account_id,organization.as_bytes()).await?;
                tx.commit().await?;
                Ok(value)
            }

            /// List only the caller's currently active memberships in ascending team-id order.
            ///
            /// # Errors
            /// Returns authentication, invalid query or bounded storage/representation errors.
            pub async fn list_organizations(
                &self, expected:&CurrentPrincipal, expires_at:u64, query:OrganizationListQuery,
            )->Result<OrganizationPage,OrganizationStoreError>{
                query.validate().map_err(|_|OrganizationStoreError::InvalidRequest)?;
                let mut tx=self.pool.begin().await?;
                $lock(&mut tx,&expected.account_id,false).await?;
                check_identity($principal(&mut tx,expected.device_id).await?,expected,expires_at)?;
                let cursor=query.cursor.unwrap_or(Uuid::nil());
                let length=if $postgres {"octet_length(o.name)"}else{"length(CAST(o.name AS BLOB))"};
                let sql=format!("SELECT o.id,CASE WHEN {length} BETWEEN 1 AND 128 THEN o.name ELSE NULL END AS name,o.created_at_ms,m.id AS membership_id,m.account_id,m.roles_json,CASE WHEN o.updated_at_ms>m.updated_at_ms THEN o.updated_at_ms ELSE m.updated_at_ms END AS updated_at_ms FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.account_id=$1 AND m.status='active' AND o.id>$2 ORDER BY o.id LIMIT $3");
                let rows=sqlx::query(&sql).bind(expected.account_id.as_slice()).bind(cursor.as_bytes().as_slice())
                    .bind(i64::from(query.limit)+1).fetch_all(&mut *tx).await?;
                let more=rows.len()>usize::from(query.limit);
                let items=rows.iter().take(usize::from(query.limit)).map(resource).collect::<Result<Vec<_>,_>>()?;
                let next_cursor=if more {items.last().map(|item|item.id)}else{None};
                let page=OrganizationPage{items,next_cursor};
                page.to_json().map_err(|_|OrganizationStoreError::StorageUnavailable)?;
                tx.commit().await?;
                Ok(page)
            }
        }

        pub(crate) async fn $snapshot(tx:&mut Transaction<'_,$db>, account:&[u8;16])
            ->Result<Vec<DeviceOrganizationSnapshot>,DeviceAuthenticationError>{
            // Even one byte per entry could not fit a larger array in the complete token.
            // Fetch one lookahead and fail rather than issue a truncated discovery snapshot.
            let rows=sqlx::query("SELECT o.id FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id WHERE m.account_id=$1 AND m.status='active' ORDER BY o.id LIMIT $2")
                .bind(account.as_slice()).bind(i64::try_from(MAX_DEVICE_ACCESS_TOKEN_BYTES+1).map_err(|_|DeviceAuthenticationError::Database)?)
                .fetch_all(&mut **tx).await?;
            if rows.len()>MAX_DEVICE_ACCESS_TOKEN_BYTES{return Err(DeviceAuthenticationError::Database);}
            rows.into_iter().map(|row|{
                let bytes:[u8;16]=row.try_get::<Vec<u8>,_>("id")?.try_into().map_err(|_|DeviceAuthenticationError::Database)?;
                Ok(DeviceOrganizationSnapshot{id:Uuid::from_bytes(bytes),sso_authenticated_at:None})
            }).collect()
        }
    };
}

organizations!(
    SqliteStore,
    Sqlite,
    "BEGIN IMMEDIATE",
    lock_sqlite,
    sqlite_principal,
    append_audit_event_in_transaction,
    sqlite_organization_snapshot,
    false
);
organizations!(
    PostgresStore,
    Postgres,
    "BEGIN",
    lock_postgres,
    postgres_principal,
    append_audit_event_in_postgres_transaction,
    postgres_organization_snapshot,
    true
);
