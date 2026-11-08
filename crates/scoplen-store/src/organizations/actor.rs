// SPDX-License-Identifier: AGPL-3.0-only
//! Real Device and Account-browser actors for the finite Organization API surface.

use sqlx::{Postgres, Sqlite, Transaction};
use uuid::Uuid;

use crate::{
    account_browser_sessions::{
        AccountBrowserSessionError, CurrentAccountBrowserSession,
        require_postgres_account_browser_session, require_sqlite_account_browser_session,
    },
    device_authentication::CurrentPrincipal,
};

use super::{OrganizationStoreError, check_identity, postgres_principal, sqlite_principal};

mod sealed {
    pub trait Sealed {}
}

/// Independently authenticated Organization actor; a browser has no enrolled Device.
pub enum OrganizationActor {
    /// The existing certified native Device principal.
    Device(CurrentPrincipal),
    /// A current password Account family, with a server-generated family UUID.
    AccountBrowser(CurrentAccountBrowserSession),
}

/// Borrowed actor facts, used only after authentication and again inside the business transaction.
pub enum OrganizationActorRef<'a> {
    /// The existing native actor, retaining its original receipt bytes.
    Device(&'a CurrentPrincipal),
    /// A browser family, distinct from every Device writer.
    AccountBrowser(&'a CurrentAccountBrowserSession),
}

/// Sealed adapters keep native library callers and actual browser families on one business path.
pub trait OrganizationPrincipal: sealed::Sealed + Sync {
    /// Borrow the original authenticated principal without manufacturing a Device identity.
    fn organization_actor(&self) -> OrganizationActorRef<'_>;

    /// The Account selected by the authenticated actor.
    fn account_id(&self) -> [u8; 16] {
        match self.organization_actor() {
            OrganizationActorRef::Device(value) => value.account_id,
            OrganizationActorRef::AccountBrowser(value) => value.account_id,
        }
    }

    /// The native Device UUID or the server-owned browser-family UUID for K-1 writes.
    fn writer_id(&self) -> [u8; 16] {
        match self.organization_actor() {
            OrganizationActorRef::Device(value) => value.device_id,
            OrganizationActorRef::AccountBrowser(value) => value.family_id,
        }
    }

    /// Distinguish browser receipt context while preserving the exact native writer bytes.
    fn receipt_writer_kind(&self) -> Option<&'static [u8]> {
        match self.organization_actor() {
            OrganizationActorRef::Device(_) => None,
            OrganizationActorRef::AccountBrowser(_) => Some(b"account-browser"),
        }
    }

    /// Whether the actor can use only D-140's explicitly mapped inventory types.
    fn is_account_browser(&self) -> bool {
        matches!(self.organization_actor(), OrganizationActorRef::AccountBrowser(_))
    }
}

impl sealed::Sealed for CurrentPrincipal {}
impl OrganizationPrincipal for CurrentPrincipal {
    fn organization_actor(&self) -> OrganizationActorRef<'_> {
        OrganizationActorRef::Device(self)
    }
}
impl sealed::Sealed for CurrentAccountBrowserSession {}
impl OrganizationPrincipal for CurrentAccountBrowserSession {
    fn organization_actor(&self) -> OrganizationActorRef<'_> {
        OrganizationActorRef::AccountBrowser(self)
    }
}
impl sealed::Sealed for OrganizationActor {}
impl OrganizationPrincipal for OrganizationActor {
    fn organization_actor(&self) -> OrganizationActorRef<'_> {
        match self {
            Self::Device(value) => OrganizationActorRef::Device(value),
            Self::AccountBrowser(value) => OrganizationActorRef::AccountBrowser(value),
        }
    }
}

impl From<AccountBrowserSessionError> for OrganizationStoreError {
    fn from(error: AccountBrowserSessionError) -> Self {
        match error {
            AccountBrowserSessionError::Denied { .. } => Self::AuthenticationRequired,
            _ => Self::StorageUnavailable,
        }
    }
}

pub(crate) async fn sqlite_actor(
    tx: &mut Transaction<'_, Sqlite>,
    expected: &impl OrganizationPrincipal,
    expires_at: u64,
) -> Result<(), OrganizationStoreError> {
    match expected.organization_actor() {
        OrganizationActorRef::Device(value) => {
            check_identity(sqlite_principal(tx, value.device_id).await?, value, expires_at)
        }
        OrganizationActorRef::AccountBrowser(value) => {
            require_sqlite_account_browser_session(tx, value).await.map_err(Into::into)
        }
    }
}

pub(crate) async fn postgres_actor(
    tx: &mut Transaction<'_, Postgres>,
    expected: &impl OrganizationPrincipal,
    expires_at: u64,
) -> Result<(), OrganizationStoreError> {
    match expected.organization_actor() {
        OrganizationActorRef::Device(value) => {
            check_identity(postgres_principal(tx, value.device_id).await?, value, expires_at)
        }
        OrganizationActorRef::AccountBrowser(value) => {
            require_postgres_account_browser_session(tx, value).await.map_err(Into::into)
        }
    }
}

pub(super) fn actor_audit(
    expected: &impl OrganizationPrincipal,
    mut event: serde_json::Value,
) -> Result<Vec<u8>, OrganizationStoreError> {
    let fields = event.as_object_mut().ok_or(OrganizationStoreError::StorageUnavailable)?;
    let (name, id) = match expected.organization_actor() {
        OrganizationActorRef::Device(value) => ("device_id", value.device_id),
        OrganizationActorRef::AccountBrowser(value) => ("browser_family_id", value.family_id),
    };
    fields.insert(name.into(), serde_json::json!(Uuid::from_bytes(id)));
    serde_json::to_vec(&event).map_err(|_| OrganizationStoreError::StorageUnavailable)
}
